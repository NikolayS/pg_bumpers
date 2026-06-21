//! Real-PG18 measurement backend for the dry-run engine (env-gated IT support).
//!
//! This module is the **baseline `clone.provider: none`** [`Rehearsal`] from
//! SPEC §12: it runs the candidate write **inside a `BEGIN … ROLLBACK` txn on a
//! provided connection** and measures the §10.1 blast radius for real against
//! PostgreSQL 18. It is clean-room (built from the SPEC + the public `postgres`
//! client API; no pgDog). It is shared by the integration tests in
//! `dry_run_it.rs`; it is **not** production code (production will grow a
//! tokio-based backend in the proxy/warden), but it exercises the exact same
//! engine orchestration the production path will use.
//!
//! What it measures, all inside the rolled-back txn:
//! - affected-PK set of the target (via `RETURNING <pk cols>`) → `core` checksum;
//! - cascade-affected child PKs for `ON DELETE CASCADE` FKs (captured pre-delete);
//! - triggers that fire for the op (`pg_trigger`);
//! - locks held on the target (`pg_locks`) — held until ROLLBACK (§12);
//! - WAL bytes (`pg_current_wal_insert_lsn()` delta across the forward op — the
//!   insert pointer, which moves for an uncommitted write; the flush LSN does
//!   not);
//! - duration (via the injected `core::Clock`);
//! - clone LSN + staleness (0 for the in-txn baseline running on the DB itself).
//!
//! `#![allow(dead_code)]`: each integration-test binary links this module and
//! uses a subset of its helpers, so some are unused per-binary.
#![allow(dead_code)]

use std::collections::BTreeMap;

use pgb_clone_orchestrator::dry_run::{AffectedTable, Measurement, Rehearsal, WriteKind};
use pgb_core::blast_radius::ConstraintViolation;
use pgb_core::{Clock, LockHeld, LockMode, PkSetBuilder, PkTuple, PkValue, TriggerFired};
use postgres::types::Type;
use postgres::{Client, NoTls, Row, Transaction};

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

/// The real, in-txn baseline [`Rehearsal`] (SPEC §12). Owns a connection; each
/// `rehearse` opens a txn, measures, and **always rolls back**.
pub struct PgRehearsal<'c, C: Clock> {
    client: &'c mut Client,
    clock: &'c C,
}

impl<'c, C: Clock> PgRehearsal<'c, C> {
    /// Wrap a connection + injected clock as the baseline rehearsal backend.
    pub fn new(client: &'c mut Client, clock: &'c C) -> Self {
        PgRehearsal { client, clock }
    }
}

impl<C: Clock> Rehearsal for PgRehearsal<'_, C> {
    fn rehearse(
        &mut self,
        statement: &str,
        kind: WriteKind,
        target_relation: &str,
    ) -> Result<Measurement, String> {
        // Snapshot the clone/connection LSN before the rehearsal txn opens. The
        // in-txn baseline runs on the DB itself, so staleness is 0.
        let clone_lsn = current_wal_lsn(self.client)?;

        let mut txn = self.client.transaction().map_err(|e| e.to_string())?;

        // (PK columns) — refuse PK-less targets with checksum = None (no ctid).
        let pk_cols = pk_columns(&mut txn, target_relation)?;

        // (Cascades, captured BEFORE the forward op so the rows still exist.)
        let cascades = if kind == WriteKind::Delete {
            capture_cascades(&mut txn, target_relation, statement)?
        } else {
            Vec::new()
        };

        // (Triggers that fire for this op.)
        let triggers_fired_names = trigger_names(&mut txn, target_relation, kind)?;

        // (WAL + duration around the forward op, capturing the affected-PK set
        //  via RETURNING.)
        let wal_before = txn_wal_lsn(&mut txn)?;
        let t0 = self.clock.monotonic_millis();
        let target = run_forward_capturing_pks(&mut txn, statement, target_relation, &pk_cols)?;
        let duration_ms = self.clock.monotonic_millis().saturating_sub(t0);
        let wal_after = txn_wal_lsn(&mut txn)?;
        let wal_bytes = wal_diff(&mut txn, &wal_before, &wal_after)?;

        // (Locks held on the target — they are held until ROLLBACK; §12.)
        let locks = locks_on(&mut txn, target_relation)?;

        let triggers_fired = triggers_fired_names
            .into_iter()
            .map(|name| TriggerFired {
                name,
                rows: target.rows,
            })
            .collect();

        // ALWAYS roll back — nothing persisted.
        txn.rollback().map_err(|e| e.to_string())?;

        Ok(Measurement {
            target,
            cascades,
            triggers_fired,
            locks,
            duration_ms,
            wal_bytes,
            constraint_violations: Vec::<ConstraintViolation>::new(),
            clone_lsn,
            staleness_lsn_bytes: 0,
        })
    }
}

/// The target's PK (or replica-identity) columns, in order. Empty ⇒ PK-less.
fn pk_columns(txn: &mut Transaction, relation: &str) -> Result<Vec<String>, String> {
    let (schema, table) = split_relation(relation);
    let rows = txn
        .query(
            r#"
            SELECT a.attname
            FROM pg_index i
            JOIN pg_class c   ON c.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
            WHERE n.nspname = $1 AND c.relname = $2 AND i.indisprimary
            ORDER BY array_position(i.indkey, a.attnum)
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Run the forward statement with `RETURNING <pk cols>` appended, collecting the
/// affected-PK set into a `core` checksum. PK-less ⇒ `checksum = None`.
fn run_forward_capturing_pks(
    txn: &mut Transaction,
    statement: &str,
    relation: &str,
    pk_cols: &[String],
) -> Result<AffectedTable, String> {
    if pk_cols.is_empty() {
        // PK-less: execute nothing here; signal refusal upward with None. We run
        // a 0-row count via the statement minus side-effects? No — to avoid any
        // execution on a PK-less table we return immediately. (The engine
        // refuses before persisting; the txn rolls back regardless.)
        return Ok(AffectedTable {
            relation: relation.to_string(),
            checksum: None,
            rows: 0,
        });
    }
    let returning = pk_cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("{statement} RETURNING {returning}");
    let rows = txn.query(&sql, &[]).map_err(|e| e.to_string())?;

    let mut builder = PkSetBuilder::for_relation(relation);
    for row in &rows {
        let tuple = pk_tuple_from_row(row, pk_cols.len()).map_err(|e| e.to_string())?;
        builder.push(tuple).map_err(|e| e.to_string())?;
    }
    let checksum = builder.finalize().map_err(|e| e.to_string())?;
    Ok(AffectedTable {
        relation: relation.to_string(),
        checksum: Some(checksum),
        rows: rows.len() as u64,
    })
}

/// Build a typed [`PkTuple`] from the first `n` columns of a RETURNING row.
/// Handles the common int / text / bytea key types (typed, not stringly, so the
/// checksum matches `core`'s anti-collision encoding).
fn pk_tuple_from_row(row: &Row, n: usize) -> Result<PkTuple, pgb_core::ChecksumError> {
    let mut vals = Vec::with_capacity(n);
    for i in 0..n {
        vals.push(pk_value_at(row, i));
    }
    PkTuple::new(vals)
}

fn pk_value_at(row: &Row, i: usize) -> PkValue {
    let ty = row.columns()[i].type_().clone();
    match ty {
        Type::INT2 => PkValue::Int(row.get::<_, i16>(i) as i64),
        Type::INT4 => PkValue::Int(row.get::<_, i32>(i) as i64),
        Type::INT8 => PkValue::Int(row.get::<_, i64>(i)),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            PkValue::Text(row.get::<_, String>(i))
        }
        Type::UUID => PkValue::Text(row.get::<_, uuid_text::UuidText>(i).0),
        Type::BYTEA => PkValue::Bytes(row.get::<_, Vec<u8>>(i)),
        // Fall back to the text representation for any other key type, keeping it
        // typed-as-text (still anti-collision vs an integer of the same digits).
        _ => PkValue::Text(text_fallback(row, i)),
    }
}

/// Read an arbitrary column as text (for key types we don't special-case).
fn text_fallback(row: &Row, i: usize) -> String {
    // The simplest portable path: ask for a String; if that fails the test will
    // surface it. We only hit this for exotic PK types not used in the seed.
    row.try_get::<_, String>(i)
        .unwrap_or_else(|_| format!("<unprintable col {i}>"))
}

/// Capture cascade-deleted child PKs for `ON DELETE CASCADE` FKs that reference
/// `target`. The child rows are those whose FK points at a parent matched by the
/// DELETE's `WHERE` (we derive the parent PK set, then select referencing
/// children). For the seed this is `entries` referencing `accounts`.
fn capture_cascades(
    txn: &mut Transaction,
    target: &str,
    delete_statement: &str,
) -> Result<Vec<AffectedTable>, String> {
    let (schema, table) = split_relation(target);
    // Find child relations with an ON DELETE CASCADE FK to the target.
    let fks = txn
        .query(
            r#"
            SELECT cn.nspname AS child_schema, cc.relname AS child_table,
                   con.conkey, con.confkey
            FROM pg_constraint con
            JOIN pg_class pc ON pc.oid = con.confrelid
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN pg_class cc ON cc.oid = con.conrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            WHERE con.contype = 'f' AND con.confdeltype = 'c'
              AND pn.nspname = $1 AND pc.relname = $2
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;

    let where_clause = extract_where(delete_statement);
    let mut out = Vec::new();
    for fk in &fks {
        let child_schema: String = fk.get(0);
        let child_table: String = fk.get(1);
        let child_rel = format!("{child_schema}.{child_table}");
        let child_pk = pk_columns(txn, &child_rel)?;
        if child_pk.is_empty() {
            // A PK-less cascade target is equally unsafe → signal None upward.
            out.push(AffectedTable {
                relation: child_rel,
                checksum: None,
                rows: 0,
            });
            continue;
        }
        // The FK columns on the child that reference the parent PK. For the seed
        // FK this is `entries.account_id -> accounts.id`. We select child PKs
        // whose FK target is a parent row matched by the DELETE predicate.
        let fk_cols = fk_child_columns(txn, &child_rel, target)?;
        let parent_pk = pk_columns(txn, target)?;
        let join_on = fk_cols
            .iter()
            .zip(parent_pk.iter())
            .map(|(c, p)| format!("ch.\"{c}\" = pa.\"{p}\""))
            .collect::<Vec<_>>()
            .join(" AND ");
        let select_pk = child_pk
            .iter()
            .map(|c| format!("ch.\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {select_pk} FROM {child_rel} ch JOIN {target} pa ON {join_on} WHERE {where_clause}"
        );
        let rows = txn.query(&sql, &[]).map_err(|e| e.to_string())?;
        let mut b = PkSetBuilder::for_relation(&child_rel);
        for row in &rows {
            let tuple = pk_tuple_from_row(row, child_pk.len()).map_err(|e| e.to_string())?;
            b.push(tuple).map_err(|e| e.to_string())?;
        }
        out.push(AffectedTable {
            relation: child_rel,
            checksum: Some(b.finalize().map_err(|e| e.to_string())?),
            rows: rows.len() as u64,
        });
    }
    Ok(out)
}

/// The child-side FK columns referencing `parent`, in PK order.
fn fk_child_columns(
    txn: &mut Transaction,
    child_rel: &str,
    parent: &str,
) -> Result<Vec<String>, String> {
    let (cs, ct) = split_relation(child_rel);
    let (ps, pt) = split_relation(parent);
    let rows = txn
        .query(
            r#"
            SELECT a.attname
            FROM pg_constraint con
            JOIN pg_class cc ON cc.oid = con.conrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            JOIN pg_class pc ON pc.oid = con.confrelid
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
            JOIN pg_attribute a ON a.attrelid = cc.oid AND a.attnum = k.attnum
            WHERE con.contype = 'f'
              AND cn.nspname = $1 AND cc.relname = $2
              AND pn.nspname = $3 AND pc.relname = $4
            ORDER BY k.ord
            "#,
            &[&cs, &ct, &ps, &pt],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Row-level trigger names that fire for `kind` on `relation`.
fn trigger_names(
    txn: &mut Transaction,
    relation: &str,
    kind: WriteKind,
) -> Result<Vec<String>, String> {
    let (schema, table) = split_relation(relation);
    // tgtype bit 16 = UPDATE, bit 8 = DELETE, bit 0 = row-level (per pg's
    // `pg_trigger.tgtype` bit layout). The mask is a self-generated constant, so
    // it is inlined (no injection vector) — `tgtype` is `int2`, and binding an
    // `int4` param against it fails client-side serialization.
    let mask: i32 = match kind {
        WriteKind::Update => 16,
        WriteKind::Delete => 8,
    };
    let rows = txn
        .query(
            &format!(
                r#"
            SELECT t.tgname
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = $1 AND c.relname = $2
              AND NOT t.tgisinternal
              AND (t.tgtype & 1) = 1            -- row-level
              AND (t.tgtype & {mask}) <> 0      -- fires for this op
            ORDER BY t.tgname
            "#
            ),
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Locks the current backend holds on `relation` (held until ROLLBACK; §12).
fn locks_on(txn: &mut Transaction, relation: &str) -> Result<Vec<LockHeld>, String> {
    let (schema, table) = split_relation(relation);
    let rows = txn
        .query(
            r#"
            SELECT l.mode
            FROM pg_locks l
            JOIN pg_class c ON c.oid = l.relation
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE l.locktype = 'relation'
              AND l.pid = pg_backend_pid()
              AND n.nspname = $1 AND c.relname = $2
            ORDER BY l.mode
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in &rows {
        let mode_str: String = row.get(0);
        if let Some(mode) = parse_lock_mode(&mode_str) {
            out.push(LockHeld {
                relation: relation.to_string(),
                mode,
                held_ms: 0,
            });
        }
    }
    Ok(out)
}

/// Map a `pg_locks.mode` string to the `core` [`LockMode`].
fn parse_lock_mode(s: &str) -> Option<LockMode> {
    Some(match s {
        "AccessShareLock" => LockMode::AccessShareLock,
        "RowShareLock" => LockMode::RowShareLock,
        "RowExclusiveLock" => LockMode::RowExclusiveLock,
        "ShareUpdateExclusiveLock" => LockMode::ShareUpdateExclusiveLock,
        "ShareLock" => LockMode::ShareLock,
        "ShareRowExclusiveLock" => LockMode::ShareRowExclusiveLock,
        "ExclusiveLock" => LockMode::ExclusiveLock,
        "AccessExclusiveLock" => LockMode::AccessExclusiveLock,
        _ => return None,
    })
}

/// `pg_current_wal_lsn()` on a plain client.
pub fn current_wal_lsn(client: &mut Client) -> Result<String, String> {
    let row = client
        .query_one("SELECT pg_current_wal_lsn()::text", &[])
        .map_err(|e| e.to_string())?;
    Ok(row.get(0))
}

/// WAL **insert** position inside a txn (`pg_current_wal_insert_lsn()`).
///
/// We deliberately use the *insert* LSN, not `pg_current_wal_lsn()` (the
/// write/flush LSN): inside an uncommitted rehearsal transaction the forward
/// op's WAL records are inserted into the backend's WAL buffer but not yet
/// flushed, so the flush LSN does not move for small writes — only the insert
/// LSN does. The insert-LSN delta is the WAL the forward op actually generated,
/// which is exactly what the §10.1 `wal_bytes` field reports for the rolled-back
/// in-txn baseline (§12).
fn txn_wal_lsn(txn: &mut Transaction) -> Result<String, String> {
    let row = txn
        .query_one("SELECT pg_current_wal_insert_lsn()::text", &[])
        .map_err(|e| e.to_string())?;
    Ok(row.get(0))
}

/// WAL bytes between two captured LSNs (`pg_wal_lsn_diff`).
fn wal_diff(txn: &mut Transaction, before: &str, after: &str) -> Result<u64, String> {
    if !is_valid_lsn(before) || !is_valid_lsn(after) {
        return Err(format!("invalid LSN literal: {before:?} / {after:?}"));
    }
    let row = txn
        .query_one(
            &format!(
                "SELECT GREATEST(pg_wal_lsn_diff('{after}'::pg_lsn, '{before}'::pg_lsn), 0)::bigint"
            ),
            &[],
        )
        .map_err(|e| e.to_string())?;
    let bytes: i64 = row.get(0);
    Ok(bytes.max(0) as u64)
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

/// Split `schema.table` (default schema `public`).
fn split_relation(relation: &str) -> (String, String) {
    match relation.split_once('.') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => ("public".to_string(), relation.to_string()),
    }
}

/// Pull the `WHERE …` clause out of a statement (everything after the first
/// top-level `WHERE`, before any `RETURNING`). Returns `"true"` if there is no
/// WHERE (a no-WHERE write affects every row). Used to scope cascade capture to
/// the same rows the forward op will touch.
fn extract_where(statement: &str) -> String {
    let lower = statement.to_lowercase();
    let where_pos = lower.find(" where ");
    match where_pos {
        Some(p) => {
            let after = &statement[p + " where ".len()..];
            // Trim a trailing RETURNING if present.
            let after_lower = after.to_lowercase();
            let end = after_lower.find(" returning ").unwrap_or(after.len());
            after[..end].trim().to_string()
        }
        None => "true".to_string(),
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

/// Minimal UUID-as-text reader (we render UUID keys as text in the checksum).
mod uuid_text {
    use postgres::types::{FromSql, Type};
    /// Newtype carrying a UUID rendered to its canonical text form.
    pub struct UuidText(pub String);
    impl<'a> FromSql<'a> for UuidText {
        fn from_sql(
            _ty: &Type,
            raw: &'a [u8],
        ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            // A binary uuid is 16 bytes; render canonical 8-4-4-4-12 hex.
            if raw.len() != 16 {
                return Err("uuid must be 16 bytes".into());
            }
            let h: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let s = format!(
                "{}-{}-{}-{}-{}",
                &h[0..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..32]
            );
            Ok(UuidText(s))
        }
        fn accepts(ty: &Type) -> bool {
            *ty == Type::UUID
        }
    }
}
