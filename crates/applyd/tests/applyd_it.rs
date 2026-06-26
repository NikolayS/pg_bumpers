//! Real-Postgres integration tests for `pgb-applyd` (issue #67, S5). Env-gated behind
//! `PG_BUMPERS_IT=1`; runs against a throwaway Postgres (any supported major, 14-18)
//! on a dedicated high port
//! (⚠️ NEVER 5432). Run:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-applyd --locked -- --test-threads=1
//! ```
//!
//! Two layers are exercised:
//!
//! 1. **the Service over a real `postgres::Client` + seeded Postgres** — the
//!    `propose → dry_run → (operator) approve → apply` lifecycle runs
//!    `guarded_apply_with_grant`, COMMITS a bounded UPDATE, and a REVERT via the
//!    captured typed-inverse **restores the pre-state byte-for-byte** (we assert
//!    the actual rows equal the pre-image — not just `applied:true`). A
//!    destructive drift at apply time **aborts (`BLAST_DRIFT`/`GRANT_REJECTED`)
//!    with NO mutation** (row count unchanged). A no-grant apply →
//!    `APPROVAL_REQUIRED`.
//! 2. **a real Unix-socket round-trip against the built `pgb-applyd` binary** —
//!    a JSON-RPC `propose` over the socket returns a proposal handle, proving the
//!    deployable wire (the full apply path over the socket is covered by the TS IT
//!    which drives the same binary end-to-end).
//!
//! The §4 guards + the grant crypto are REUSED; this asserts the daemon's wiring
//! + the bounded/reversible/fail-closed guarantees end-to-end on the live backend.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use postgres::{Client, NoTls};
use rand_core::OsRng;

use pgb_applyd::{ErrorCode, Service};
use pgb_audit::{InMemorySink, SharedSink};
use pgb_cli::{ApprovalFlow, InMemoryNonceStore, RecordingWebhookSender};
use pgb_clone_orchestrator::{PgApplyConn, PgRehearsal, PgRevertConn, revert};
use pgb_core::{Clock, NoopBarrier, SystemClock};

const FORWARD: &str = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
const DEL_FORWARD: &str = "DELETE FROM public.accounts WHERE id % 2 = 0";

type Svc = Service<RecordingWebhookSender, InMemoryNonceStore, InMemoryNonceStore>;

const SEED_SQL: &str = r#"
    CREATE TABLE public.accounts (
        id       int    PRIMARY KEY,
        owner    text   NOT NULL,
        balance  bigint NOT NULL
    );
    INSERT INTO public.accounts(id, owner, balance)
    SELECT g, 'owner-' || g, (g * 1000)::bigint
    FROM generate_series(1, 8) AS g;
"#;

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn base_pgurl() -> String {
    std::env::var("PG_BUMPERS_PGURL")
        .unwrap_or_else(|_| "host=127.0.0.1 port=54355 user=postgres dbname=postgres".to_string())
}

fn keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    (sk.clone(), sk.verifying_key())
}

/// Create a fresh seeded DB; return `(admin_url, dbname)`.
fn create_seeded_db(tag: &str) -> (String, String) {
    let admin_url = base_pgurl();
    let mut admin = Client::connect(&admin_url, NoTls).expect("admin connect");
    let dbname = format!("applyd_it_{tag}");
    admin
        .simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))
        .unwrap();
    admin
        .simple_query(&format!("CREATE DATABASE {dbname}"))
        .unwrap();
    let url = url_for(&admin_url, &dbname);
    let mut c = Client::connect(&url, NoTls).expect("seed connect");
    c.batch_execute(SEED_SQL).expect("seed");
    (admin_url, dbname)
}

fn drop_db(admin_url: &str, dbname: &str) {
    let mut admin = Client::connect(admin_url, NoTls).expect("admin connect");
    admin
        .simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))
        .unwrap();
}

fn url_for(admin: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = admin
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

fn read_accounts(url: &str) -> BTreeMap<i32, (String, i64)> {
    let mut c = Client::connect(url, NoTls).expect("read connect");
    c.query(
        "SELECT id, owner, balance FROM public.accounts ORDER BY id",
        &[],
    )
    .expect("read accounts")
    .iter()
    .map(|r| {
        (
            r.get::<_, i32>(0),
            (r.get::<_, String>(1), r.get::<_, i64>(2)),
        )
    })
    .collect()
}

/// Dev password for the constrained applier role in these tests.
const APPLIER_PW: &str = "pgb_applier_it_pw";

/// Provision the constrained, DML-only `pgb_applier` role (S5 #77) in the seeded
/// DB, mirroring `deploy/sql/10_hardened_role.sql`. `over_grant=true` deliberately
/// gives it SUPERUSER (the RED lever: a too-powerful applier that CAN DDL) so the
/// DDL-denied assertion fails — proving the test has teeth. `over_grant=false` is
/// the shipped least-privilege shape (NOSUPERUSER, NOCREATEDB/ROLE, no CREATE on
/// public, DML-only on the app table).
fn provision_applier(admin_url: &str, over_grant: bool) {
    let mut c = Client::connect(admin_url, NoTls).expect("provision connect");
    // Recreate cleanly so a prior run's grants/ownership never leak across tests.
    // DROP OWNED first so a role that (e.g. in a RED run) created an object can still
    // be dropped; then DROP ROLE. Both are no-ops when the role is absent.
    if c.query_one(
        "SELECT count(*) FROM pg_roles WHERE rolname='pgb_applier'",
        &[],
    )
    .map(|r| r.get::<_, i64>(0))
    .unwrap_or(0)
        > 0
    {
        c.batch_execute("DROP OWNED BY pgb_applier CASCADE").ok();
        c.batch_execute("DROP ROLE pgb_applier")
            .expect("drop stale pgb_applier");
    }
    let attrs = if over_grant {
        // RED lever: a superuser applier bypasses every grant → CAN DDL.
        "SUPERUSER"
    } else {
        // Shipped shape: cannot DDL, cannot escalate.
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    };
    c.batch_execute(&format!(
        "CREATE ROLE pgb_applier LOGIN PASSWORD '{APPLIER_PW}' {attrs};"
    ))
    .expect("create pgb_applier");
    // DML-only on the app table; USAGE on the schema; NO CREATE on public (the
    // structural DDL denial). Ownership stays with the seeding superuser, so the
    // applier can mutate ROWS but cannot ALTER/DROP the table.
    //
    // VERSION-AGNOSTIC (C1 #102, spec v0.8.1 §0.5 — supported PG 14-18): we MUST
    // also `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, exactly as the production
    // deploy/sql/10_hardened_role.sql does. On **PG 15+** PUBLIC already lacks
    // CREATE on `public` by default, so revoking only the role's direct grant is
    // enough; but on **PG 14** PUBLIC RETAINS CREATE on `public`, so `pgb_applier`
    // would inherit it via PUBLIC and `CREATE TABLE` would SUCCEED — breaking the
    // DML-only DDL-denial assertion below. Re-asserting the PUBLIC revoke makes the
    // role hardening match the real WALL on every supported major (a no-op on 15+,
    // the actual denial on 14).
    c.batch_execute(
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
         REVOKE CREATE ON SCHEMA public FROM pgb_applier;\n\
         GRANT USAGE ON SCHEMA public TO pgb_applier;\n\
         GRANT SELECT, INSERT, UPDATE, DELETE ON public.accounts TO pgb_applier;",
    )
    .expect("grant applier DML");
}

/// Build a libpq URL that connects as `pgb_applier` to the given seeded DB url.
fn applier_url(url: &str) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|kv| !kv.starts_with("user=") && !kv.starts_with("password="))
        .map(|s| s.to_string())
        .collect();
    parts.push("user=pgb_applier".to_string());
    parts.push(format!("password={APPLIER_PW}"));
    parts.join(" ")
}

fn policy() -> pgb_policy::PolicyConfig {
    use pgb_policy::{
        AutonomyLevel, CloneConfig, CloneProvider, PitrConfig as PolicyPitr, PolicyConfig,
        RoleBudget, RolePolicy, WindowBudget,
    };
    let mut roles = BTreeMap::new();
    roles.insert(
        "app_writer".to_string(),
        RolePolicy {
            select_whitelist: vec![],
            budget: RoleBudget {
                max_bytes: 1000,
                max_rows: 100,
                max_plan_cost: 1000.0,
                max_plan_rows: 1000,
                per_window: WindowBudget {
                    window_secs: 60,
                    max_bytes: 10_000,
                    max_rows: 1000,
                },
            },
            autonomy: AutonomyLevel::L1,
        },
    );
    PolicyConfig {
        version: 1,
        roles,
        // No BYO primary target in this applyd IT fixture (SPEC §0.5).
        primary: None,
        replica: Default::default(),
        clone: CloneConfig {
            provider: CloneProvider::None,
        },
        pitr: PolicyPitr { enabled: false },
        approvers: Default::default(),
        audit: Default::default(),
    }
}

fn service(vk: VerifyingKey) -> Svc {
    let sink = SharedSink::new(InMemorySink::new());
    let flow = ApprovalFlow::new(
        sink.clone(),
        RecordingWebhookSender::new(),
        vk,
        InMemoryNonceStore::new(),
    );
    Service::new(flow, sink, InMemoryNonceStore::new(), vk, policy())
}

/// Run propose → dry_run → request_elevation → approve over the live backend, returning
/// `(proposal_id, total_rows, confirm_token)`.
fn approve_through(
    svc: &mut Svc,
    sk: &SigningKey,
    clock: &dyn Clock,
    url: &str,
    statement: &str,
    session: &str,
    nonce: &str,
) -> (String, u64, String) {
    let proposed = svc
        .propose(statement, Some(4), "app_writer", session, clock)
        .expect("propose");
    let dry = {
        let mut read_client = Client::connect(url, NoTls).expect("rehearsal connect");
        let inner = SystemClock::new();
        let mut rehearsal = PgRehearsal::new(&mut read_client, &inner);
        svc.dry_run(&proposed.proposal_id, &mut rehearsal, clock)
            .expect("dry_run")
    };
    let req = svc
        .request_elevation(&proposed.proposal_id, "raise the bound", clock)
        .expect("request_elevation");
    svc.approve(&req.request_id, "operator-1", sk, nonce, 60_000, clock)
        .expect("approve");
    (proposed.proposal_id, dry.total_rows, dry.confirm_token)
}

// ===========================================================================
//  (1) HAPPY PATH — apply COMMITS a bounded UPDATE, then REVERT restores pre-state.
// ===========================================================================

#[test]
fn lifecycle_apply_commits_bounded_update_and_revert_restores_prestate() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the applyd IT");
        return;
    }
    let (admin, dbname) = create_seeded_db("commit_revert");
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let (sk, vk) = keypair();
    // The real wall clock drives the grant TTL; mint with a real-relative expiry.
    let clock = SystemClock::new();
    let mut svc = service(vk);
    let (proposal_id, total_rows, token) = approve_through(
        &mut svc,
        &sk,
        &clock,
        &url,
        FORWARD,
        "sess-prod",
        "nonce-ok",
    );

    // Apply over a real PgApplyConn → guarded_apply_with_grant COMMITS, and we
    // capture the REAL typed-inverse the apply produced (not a reconstruction).
    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let (res, inverse) = {
        let mut conn = PgApplyConn::new(&mut apply_client, FORWARD, "id % 2 = 0");
        svc.apply_returning_inverse(
            &proposal_id,
            total_rows,
            Some(&token),
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .expect("the grant-gated apply must commit on the live backend")
    };
    assert!(res.applied);
    assert_eq!(res.rows_written, 4);
    assert!(res.reversible);

    // The bounded write committed: even accounts zeroed.
    let after_apply = read_accounts(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(
            after_apply[&id].1, 0,
            "even {id} zeroed by the committed write"
        );
    }
    // Odd accounts untouched (bounded).
    for &id in &[1, 3, 5, 7] {
        assert_ne!(after_apply[&id].1, 0, "odd {id} untouched (bounded)");
    }

    // REVERT via the ACTUAL captured typed-inverse the apply produced → the
    // pre-state is restored byte-for-byte. This proves the apply was reversible
    // by construction, using the genuine inverse (not a reconstruction).
    {
        let mut client = Client::connect(&url, NoTls).expect("revert connect");
        let mut rconn = PgRevertConn::new(&mut client);
        let report = revert(&inverse, &mut rconn).expect("revert must succeed");
        assert_eq!(report.total_restored, 4);
    }
    let after_revert = read_accounts(&url);
    assert_eq!(
        before, after_revert,
        "revert restored the pre-apply state byte-for-byte (reversible apply proven)"
    );

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (1b) LEAST-PRIVILEGE APPLIER ROLE (S5 #77) — the guarded apply COMMITS under the
//       constrained, DML-only `pgb_applier` role (reads rows back), AND `pgb_applier`
//       is genuinely DML-ONLY: a DDL attempt as that role is `permission denied`.
//
//  This is the teeth for the #77 hardening: applyd's resident apply connection no
//  longer needs the SUPERUSER. We run the SAME grant-gated apply path as test (1),
//  but the apply `Client` connects as `pgb_applier` (not `postgres`) — proving the
//  write path works under reduced privilege — and we separately attempt CREATE/ALTER/
//  DROP **plus the destructive write-capable vectors TRUNCATE and COPY … FROM/TO
//  PROGRAM** as `pgb_applier` and assert each is rejected (42501), so a bug in the
//  apply path cannot escalate into arbitrary DDL, nuke a table out-of-band, or run a
//  server-side program. TRUNCATE/COPY-PROGRAM matter MOST precisely because this role
//  CAN write rows — they are the high-blast vectors a write role must still be denied.
//
//  RED→GREEN: with `provision_applier(.., over_grant=true)` the role is SUPERUSER and
//  the denied assertions FAIL (a too-powerful applier CAN DDL/TRUNCATE/COPY-PROGRAM —
//  SUPERUSER bypasses every grant + holds pg_execute_server_program implicitly); with
//  the shipped least-privilege shape (`over_grant=false`) every denial PASSES.
// ===========================================================================

#[test]
fn guarded_apply_commits_as_constrained_applier_and_applier_cannot_ddl() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the applier-role IT");
        return;
    }
    let (admin, dbname) = create_seeded_db("applier_role");
    let url = url_for(&admin, &dbname);

    // Shipped least-privilege shape. Flip to `true` to reproduce RED.
    provision_applier(&url, false);
    let applier = applier_url(&url);

    // ---- (a) the guarded write COMMITS under `pgb_applier` ----
    let before = read_accounts(&url);
    let (sk, vk) = keypair();
    let clock = SystemClock::new();
    let mut svc = service(vk);
    let (proposal_id, total_rows, token) = approve_through(
        &mut svc,
        &sk,
        &clock,
        &url,
        FORWARD,
        "sess-applier",
        "nonce-applier",
    );

    // The apply connection is `pgb_applier`, NOT the superuser — exactly what applyd
    // now does by default (PGB_BACKEND_ROLE=pgb_applier).
    let mut apply_client =
        Client::connect(&applier, NoTls).expect("connect apply Client as pgb_applier");
    let res = {
        let mut conn = PgApplyConn::new(&mut apply_client, FORWARD, "id % 2 = 0");
        svc.apply(
            &proposal_id,
            total_rows,
            Some(&token),
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .expect("the grant-gated apply must COMMIT under the constrained pgb_applier role")
    };
    assert!(res.applied, "applied under pgb_applier");
    assert_eq!(res.rows_written, 4, "bounded write committed 4 rows");
    assert!(res.reversible, "reversible apply");

    // Read the committed rows back (the write genuinely landed under reduced privilege).
    let after = read_accounts(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(after[&id].1, 0, "even {id} zeroed by the committed write");
    }
    for &id in &[1, 3, 5, 7] {
        assert_ne!(after[&id].1, 0, "odd {id} untouched (bounded)");
    }
    assert_ne!(before, after, "the apply changed state");

    // ---- (b) `pgb_applier` is genuinely DML-ONLY: every DDL attempt is denied ----
    let mut as_applier =
        Client::connect(&applier, NoTls).expect("second connect as pgb_applier for DDL probes");

    // CREATE TABLE — needs CREATE on schema (revoked) → permission denied.
    let create_err = as_applier
        .batch_execute("CREATE TABLE public.pgb_applier_should_not_exist (x int)")
        .expect_err("CREATE TABLE as pgb_applier MUST be rejected (no CREATE on public)");
    assert_permission_denied("CREATE TABLE", &create_err);

    // DROP TABLE — the applier does not own `accounts` → permission denied.
    let drop_err = as_applier
        .batch_execute("DROP TABLE public.accounts")
        .expect_err("DROP TABLE as pgb_applier MUST be rejected (not the owner)");
    assert_permission_denied("DROP TABLE", &drop_err);

    // ALTER TABLE — likewise an ownership-gated DDL → permission denied.
    let alter_err = as_applier
        .batch_execute("ALTER TABLE public.accounts ADD COLUMN sneaky int")
        .expect_err("ALTER TABLE as pgb_applier MUST be rejected (not the owner)");
    assert_permission_denied("ALTER TABLE", &alter_err);

    // TRUNCATE — the destructive vector that matters MOST for a write-capable role: it
    // empties the whole table in one statement, bypassing the bounded/reversible apply
    // path entirely, and is NOT reversible by our typed-inverse. The applier has only
    // SELECT/INSERT/UPDATE/DELETE (NO TRUNCATE privilege) and does not own `accounts`, so
    // it is `permission denied` (42501). This is the teeth: a write-capable role must
    // still be unable to nuke a table out-of-band.
    let truncate_err = as_applier
        .batch_execute("TRUNCATE public.accounts")
        .expect_err("TRUNCATE as pgb_applier MUST be rejected (no TRUNCATE priv, not owner)");
    assert_permission_denied("TRUNCATE", &truncate_err);

    // COPY … FROM PROGRAM — the server-side command-execution / exfil vector. It is gated
    // on pg_execute_server_program (member-of-nothing → NOT granted) + the superuser bit
    // (NOSUPERUSER), both stripped for pgb_applier, so the attempt is `permission denied`
    // (42501) BEFORE any program runs. (We assert both directions: FROM PROGRAM, the
    // command-injection/ingest vector, and TO PROGRAM, the exfil vector.)
    let copy_from_prog_err = as_applier
        .batch_execute("COPY public.accounts FROM PROGRAM 'echo 1,owner,0'")
        .expect_err("COPY FROM PROGRAM as pgb_applier MUST be rejected (no server-program priv)");
    assert_permission_denied("COPY FROM PROGRAM", &copy_from_prog_err);

    let copy_to_prog_err = as_applier
        .batch_execute("COPY public.accounts TO PROGRAM 'cat > /tmp/pgb_applier_exfil'")
        .expect_err("COPY TO PROGRAM as pgb_applier MUST be rejected (no server-program priv)");
    assert_permission_denied("COPY TO PROGRAM", &copy_to_prog_err);

    // Sanity: the DDL was truly blocked — `accounts` is intact and `sneaky` absent.
    let cols: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='accounts' AND column_name='sneaky'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(cols, 0, "ALTER was blocked — no `sneaky` column added");

    // Sanity: TRUNCATE was truly blocked — the 8 seeded rows are all still present (an
    // empty table would prove the TRUNCATE leaked through despite the 42501).
    let rows: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one("SELECT count(*) FROM public.accounts", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        rows, 8,
        "TRUNCATE was blocked — all seeded rows still present"
    );

    // Teardown: drop the per-DB objects AND the cluster-global `pgb_applier` role so it
    // does not persist after the test. The DML grants lived on objects inside `dbname`
    // (gone with the DROP DATABASE), and the role owns nothing (ownership stayed with the
    // seeding superuser), so DROP ROLE succeeds; `provision_applier` is also idempotent
    // and re-drops defensively, so this is safe either way.
    drop_db(&admin, &dbname);
    {
        let mut c = Client::connect(&admin, NoTls).expect("teardown admin connect");
        // DROP OWNED is a no-op (the role owns nothing) but mirrors provision's defense.
        c.batch_execute("DROP OWNED BY pgb_applier CASCADE").ok();
        c.batch_execute("DROP ROLE IF EXISTS pgb_applier")
            .expect("drop cluster-global pgb_applier role in teardown");
    }
}

/// Assert a `postgres::Error` is an `insufficient_privilege` (SQLSTATE 42501,
/// "permission denied") — the DB-level deny we want, not some other failure.
fn assert_permission_denied(op: &str, err: &postgres::Error) {
    use postgres::error::SqlState;
    let db = err
        .as_db_error()
        .unwrap_or_else(|| panic!("{op}: expected a DB error, got: {err}"));
    assert_eq!(
        *db.code(),
        SqlState::INSUFFICIENT_PRIVILEGE,
        "{op}: expected permission denied (42501), got {}: {}",
        db.code().code(),
        db.message()
    );
}

// ===========================================================================
//  (2) NO-GRANT apply → APPROVAL_REQUIRED, no mutation.
// ===========================================================================

#[test]
fn apply_without_a_grant_is_approval_required_no_mutation() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the applyd IT");
        return;
    }
    let (admin, dbname) = create_seeded_db("no_grant");
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let (_sk, vk) = keypair();
    let clock = SystemClock::new();
    let mut svc = service(vk);
    let proposed = svc
        .propose(FORWARD, Some(4), "app_writer", "sess-prod", &clock)
        .unwrap();
    let dry = {
        let mut read_client = Client::connect(&url, NoTls).unwrap();
        let inner = SystemClock::new();
        let mut rehearsal = PgRehearsal::new(&mut read_client, &inner);
        svc.dry_run(&proposed.proposal_id, &mut rehearsal, &clock)
            .unwrap()
    };

    let mut apply_client = Client::connect(&url, NoTls).unwrap();
    let err = {
        let mut conn = PgApplyConn::new(&mut apply_client, FORWARD, "id % 2 = 0");
        svc.apply(
            &proposed.proposal_id,
            dry.total_rows,
            Some(&dry.confirm_token),
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .unwrap_err()
    };
    assert_eq!(err.data.code, ErrorCode::ApprovalRequired.as_str());
    assert!(err.data.retryable);
    assert_eq!(read_accounts(&url), before, "no mutation without a grant");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3) DRIFT — a destructive DELETE whose MAGNITUDE drifts past the approved cap
//      at apply ABORTS (EPIC #91 PR-B: CapExceeded → BLAST_DRIFT), no mutation.
// ===========================================================================

#[test]
fn destructive_delete_drift_aborts_with_no_mutation() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the applyd IT");
        return;
    }
    let (admin, dbname) = create_seeded_db("drift");
    let url = url_for(&admin, &dbname);

    let (sk, vk) = keypair();
    let clock = SystemClock::new();
    let mut svc = service(vk);
    // Approve a DELETE of the even rows {2,4,6,8}.
    let (proposal_id, total_rows, token) = approve_through(
        &mut svc,
        &sk,
        &clock,
        &url,
        DEL_FORWARD,
        "sess-prod",
        "nonce-del",
    );

    // MAGNITUDE DRIFT (EPIC #91 PR-B): SEVERAL new even rows appear AFTER the grant
    // was signed, so the live `DELETE … WHERE id % 2 = 0` now destroys far more rows
    // (accounts + their cascade entries + audit inserts) than the human approved —
    // the full footprint exceeds the cap (pre-filled from the dry-run + 10%). The cap
    // is the absolute-magnitude anchor that replaced the dropped exact-PK-set checksum.
    Client::connect(&url, NoTls)
        .unwrap()
        .batch_execute(
            "INSERT INTO public.accounts(id, owner, balance) VALUES \
             (10,'d',5),(12,'d',5),(14,'d',5),(16,'d',5),(18,'d',5),(20,'d',5)",
        )
        .unwrap();
    let before_drift = read_accounts(&url);
    let count_before: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one("SELECT count(*) FROM public.accounts", &[])
        .unwrap()
        .get(0);

    let mut apply_client = Client::connect(&url, NoTls).unwrap();
    let err = {
        let mut conn = PgApplyConn::new(&mut apply_client, DEL_FORWARD, "id % 2 = 0");
        svc.apply(
            &proposal_id,
            total_rows,
            Some(&token),
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .unwrap_err()
    };
    // The live DELETE's full footprint exceeds the approved cap → CapExceeded →
    // BLAST_DRIFT, the apply txn rolled back (or the cap/footprint pre-check refused),
    // NO mutation. (The grant itself still verified — statement + cap + nonce match;
    // the magnitude is what the floor caught.)
    assert_eq!(
        err.data.code,
        ErrorCode::BlastDrift.as_str(),
        "expected BLAST_DRIFT (CapExceeded magnitude drift), got {}",
        err.data.code
    );
    let count_after: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one("SELECT count(*) FROM public.accounts", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        count_before, count_after,
        "row count unchanged — no DELETE committed"
    );
    assert_eq!(read_accounts(&url), before_drift, "no mutation on drift");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (4) THE WIRE — a real Unix-socket JSON-RPC round-trip against the binary.
// ===========================================================================

#[test]
fn socket_jsonrpc_propose_round_trip_against_the_binary() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the applyd socket IT");
        return;
    }
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};

    let (admin, dbname) = create_seeded_db("socket");
    let url = url_for(&admin, &dbname);

    // The shared `_meta` audit chain needs its schema (table + writer role +
    // REVOKE) applied to the DB the daemon anchors into. Apply the canonical
    // migration into the seeded DB (it is idempotent) so the binary's AuditBoot
    // can persist + verify the chain — exactly as the proxy expects.
    {
        let mut c = Client::connect(&url, NoTls).expect("meta schema connect");
        let sql = std::fs::read_to_string("../audit/sql/10_audit_meta.sql")
            .expect("read 10_audit_meta.sql");
        // Strip psql meta-commands (\set / \echo) the simple-query protocol rejects.
        let stripped: String = sql
            .lines()
            .filter(|l| !l.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        c.batch_execute(&stripped).expect("apply _meta schema");
    }

    // Approver pubkey (hex) — the apply-time trust root.
    let (_sk, vk) = keypair();
    let pubkey_hex = hex::encode(vk.to_bytes());

    // A throwaway socket + meta DSN (reuse the same seeded DB as `_meta`) + a
    // durable anchor file. Mirror the proxy env wiring.
    let tag = std::process::id();
    let sock_dir = std::env::temp_dir().join(format!("pgb-applyd-it-{tag}"));
    let _ = std::fs::remove_dir_all(&sock_dir);
    let sock = sock_dir.join("applyd.sock");
    let anchor = std::env::temp_dir().join(format!("pgb-applyd-anchor-{tag}.worm"));
    let _ = std::fs::remove_file(&anchor);

    // Parse the seeded DB url into host/port for the backend env.
    let kv: BTreeMap<&str, &str> = url
        .split_whitespace()
        .filter_map(|p| p.split_once('='))
        .collect();
    let host = kv.get("host").copied().unwrap_or("127.0.0.1");
    let port = kv.get("port").copied().unwrap_or("54355");

    // Find the built binary (cargo sets CARGO_BIN_EXE_pgb-applyd for the test).
    let bin = env!("CARGO_BIN_EXE_pgb-applyd");
    let mut child = Command::new(bin)
        .env("PGB_APPLYD_SOCKET", &sock)
        .env("PGB_APPROVER_PUBKEY", &pubkey_hex)
        .env("PGB_POLICY_PATH", "../policy/policy.example.yaml")
        .env("PGB_META_DSN", &url)
        .env("PGB_AUDIT_SIGNING_KEY", "applyd-it-signing-key-000001")
        .env("PGB_ANCHOR_PATH", &anchor)
        .env("PGB_ANCHOR_INTERVAL_MS", "60000")
        .env("PGB_BACKEND_HOST", host)
        .env("PGB_BACKEND_PORT", port)
        .env("PGB_BACKEND_DB", &dbname)
        .env("PGB_BACKEND_ROLE", "postgres")
        .env("PGB_BACKEND_PASSWORD", "unused-trust-auth")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pgb-applyd");

    // Wait for the socket to appear (the binary binds it after the audit boot).
    let mut connected = None;
    for _ in 0..100 {
        if sock.exists()
            && let Ok(s) = UnixStream::connect(&sock)
        {
            connected = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let stream = match connected {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "applyd socket never came up:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    };

    // Send a `propose` JSON-RPC line, read the response line.
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "propose",
        "params": { "sql": FORWARD, "expected_rows": 4, "role": "app_writer", "session_id": "sess-prod" }
    });
    writeln!(writer, "{req}").unwrap();
    writer.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse response");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert!(
        resp["result"]["proposal_id"].as_str().is_some(),
        "propose returned a proposal_id over the socket: {resp}"
    );
    assert!(resp["error"].is_null(), "no error: {resp}");

    // A bad method returns the recoverable error contract over the socket.
    let bad = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "nope", "params": {}});
    writeln!(writer, "{bad}").unwrap();
    writer.flush().unwrap();
    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    let resp2: serde_json::Value = serde_json::from_str(&line2).unwrap();
    assert_eq!(resp2["error"]["data"]["code"], "METHOD_NOT_FOUND");

    // Teardown.
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&sock_dir);
    let _ = std::fs::remove_file(&anchor);
    drop_db(&admin, &dbname);
}
