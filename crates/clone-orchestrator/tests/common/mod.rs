//! DB setup/teardown + the seed schema for the env-gated (`PG_BUMPERS_IT=1`)
//! real-PG18 integration tests.
//!
//! The measurement backend itself — the baseline `clone.provider: none`
//! [`PgRehearsal`] (SPEC §12) — is **no longer duplicated here**: it was lifted
//! into reusable library code at [`pgb_clone_orchestrator::conn`] (behind the
//! `pg` feature) so the integration tests and `pgb-applyd` share ONE impl. This
//! module re-exports it and keeps only the throwaway-cluster bootstrap, the
//! per-test seeded DB lifecycle, and a few read helpers used by the assertions.
//!
//! `#![allow(dead_code)]`: each integration-test binary links this module and
//! uses a subset of its helpers, so some are unused per-binary.
#![allow(dead_code)]

/// Self-contained throwaway PG18 primary cluster bootstrap (for the
/// clone-governance tests, which need a real on-disk primary to `pg_basebackup`).
pub mod cluster;

use std::collections::BTreeMap;

use postgres::{Client, NoTls};

// The ONE lifted rehearsal backend (and its LSN helper), reused by the tests.
// Re-exported for the test binaries that use it (dry_run_it); other binaries
// link this module without touching these, so suppress the per-binary
// unused-import warning.
#[allow(unused_imports)]
pub use pgb_clone_orchestrator::conn::{PgRehearsal, current_wal_lsn};

/// Env var gating the DB-touching tests (matches the S0 spike convention).
pub const IT_ENV: &str = "PG_BUMPERS_IT";

/// Default libpq URL for the throwaway PG18 cluster on the dedicated port 54341.
/// Overridable via `PG_BUMPERS_PGURL`. **Never** points at the founder's 5432.
pub const DEFAULT_PGURL: &str = "host=127.0.0.1 port=54341 user=postgres dbname=postgres";

/// Whether the IT gate is set.
pub fn it_enabled() -> bool {
    std::env::var(IT_ENV).map(|v| v == "1").unwrap_or(false)
}

/// The base admin connection string (env override or [`DEFAULT_PGURL`]).
pub fn base_pgurl() -> String {
    std::env::var("PG_BUMPERS_PGURL").unwrap_or_else(|_| DEFAULT_PGURL.to_string())
}

/// Connect (sync client).
pub fn connect(url: &str) -> Client {
    Client::connect(url, NoTls).expect("connect to throwaway PG18")
}

/// The deterministic seed schema: FK parent/child (`ON DELETE CASCADE`), an
/// AFTER trigger writing an audit table, a sequence, and a PK-less table for the
/// negative test.
pub const SEED_SQL: &str = r#"
    CREATE TABLE public.accounts (
        id       int    PRIMARY KEY,
        owner    text   NOT NULL,
        balance  bigint NOT NULL
    );

    CREATE TABLE public.entries (
        account_id int  NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
        line_no    int  NOT NULL,
        memo       text NOT NULL,
        amount     bigint NOT NULL,
        PRIMARY KEY (account_id, line_no)
    );

    -- A sequence whose advance is a documented UNRESTORED gap (§10.3).
    CREATE SEQUENCE public.ticket_seq START 1000;

    -- Trigger side-effect / audit table (rows here are an UNRESTORED gap).
    CREATE TABLE public.account_audit (
        audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        account_id int  NOT NULL,
        op       text  NOT NULL
    );

    CREATE FUNCTION public.accounts_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO public.account_audit(account_id, op) VALUES (OLD.id, TG_OP);
            RETURN OLD;
        ELSE
            INSERT INTO public.account_audit(account_id, op) VALUES (NEW.id, TG_OP);
            RETURN NEW;
        END IF;
    END;
    $$;

    CREATE TRIGGER accounts_audit_aud
        AFTER UPDATE OR DELETE ON public.accounts
        FOR EACH ROW EXECUTE FUNCTION public.accounts_audit();

    -- A PK-less / no-replica-identity table for the refusal negative test.
    CREATE TABLE public.event_log (
        kind text NOT NULL,
        note text NOT NULL
    );

    -- Deterministic seed: 8 accounts, each with 2 ledger entries. Non-zero,
    -- distinct balances so a no-WHERE "SET balance = 0" is observable.
    INSERT INTO public.accounts(id, owner, balance)
    SELECT g, 'owner-' || g, (g * 1000)::bigint
    FROM generate_series(1, 8) AS g;

    INSERT INTO public.entries(account_id, line_no, memo, amount)
    SELECT a.id, ln, 'memo-' || a.id || '-' || ln, (a.id * 10 + ln)::bigint
    FROM public.accounts a, generate_series(1, 2) AS ln;

    INSERT INTO public.event_log(kind, note) VALUES ('seed', 'no pk here');
"#;

/// Create a fresh, uniquely-named DB on the server, seed it, and return
/// `(admin_url, dbname, client)`. Dropped in teardown by [`drop_db`].
pub fn create_seeded_db(admin_url: &str, tag: &str) -> (String, String, Client) {
    let mut admin = connect(admin_url);
    let dbname = format!(
        "clone_it_{}",
        tag.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .to_lowercase()
    );
    admin
        .simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))
        .expect("drop stale db");
    admin
        .simple_query(&format!("CREATE DATABASE {dbname}"))
        .expect("create db");
    let url = replace_dbname(admin_url, &dbname);
    let mut client = connect(&url);
    client.batch_execute(SEED_SQL).expect("seed schema");
    (admin_url.to_string(), dbname, client)
}

/// Drop a database created by [`create_seeded_db`] (teardown).
pub fn drop_db(admin_url: &str, dbname: &str) {
    let mut admin = connect(admin_url);
    admin
        .simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))
        .expect("drop db in teardown");
}

fn replace_dbname(url: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

/// Staleness bytes between a captured `snapshot_lsn` and current LSN.
pub fn staleness_lsn_bytes(client: &mut Client, snapshot_lsn: &str) -> Result<u64, String> {
    if !is_valid_lsn(snapshot_lsn) {
        return Err(format!("invalid LSN literal: {snapshot_lsn:?}"));
    }
    let row = client
        .query_one(
            &format!(
                "SELECT GREATEST(pg_wal_lsn_diff(pg_current_wal_lsn(), '{snapshot_lsn}'::pg_lsn), 0)::bigint"
            ),
            &[],
        )
        .map_err(|e| e.to_string())?;
    let bytes: i64 = row.get(0);
    Ok(bytes.max(0) as u64)
}

fn is_valid_lsn(s: &str) -> bool {
    match s.split_once('/') {
        Some((hi, lo)) => {
            !hi.is_empty()
                && !lo.is_empty()
                && hi.chars().all(|c| c.is_ascii_hexdigit())
                && lo.chars().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Helper: read a table's current balances (test assertion of "unchanged").
pub fn account_balances(client: &mut Client) -> BTreeMap<i32, i64> {
    let rows = client
        .query("SELECT id, balance FROM public.accounts ORDER BY id", &[])
        .expect("read balances");
    rows.iter()
        .map(|r| (r.get::<_, i32>(0), r.get::<_, i64>(1)))
        .collect()
}

/// Helper: count rows in a table (for the "primary rows unchanged" assertion).
pub fn row_count(client: &mut Client, relation: &str) -> i64 {
    let row = client
        .query_one(&format!("SELECT count(*) FROM {relation}"), &[])
        .expect("count rows");
    row.get(0)
}
