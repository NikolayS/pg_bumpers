//! Real-PG18 integration tests for `pgb-applyd` (issue #67, S5). Env-gated behind
//! `PG_BUMPERS_IT=1`; runs against a throwaway PG18 on a dedicated high port
//! (⚠️ NEVER 5432). Run:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-applyd --locked -- --test-threads=1
//! ```
//!
//! Two layers are exercised:
//!
//! 1. **the Service over a real `postgres::Client` + seeded PG18** — the
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
//! + the bounded/reversible/fail-closed guarantees end-to-end on real PG18.

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

/// Run propose → dry_run → request_elevation → approve over real PG18, returning
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
        .expect("the grant-gated apply must commit on real PG18")
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
