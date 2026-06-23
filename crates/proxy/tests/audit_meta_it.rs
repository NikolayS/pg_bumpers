//! Env-gated **real PG18** integration test for the S5 shared, persistent,
//! anchored `_meta` audit chain wired into the proxy (issue #64, SPEC §3/§4/§10.9).
//!
//! Runs only when `PG_BUMPERS_IT=1` (CI's fast `cargo test` skips it; the crate
//! still builds/links). Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test audit_meta_it -- --nocapture
//! ```
//!
//! It proves, against a live `_meta` table created from
//! `crates/audit/sql/10_audit_meta.sql`:
//!   1. the proxy `Recorder` — injected with the SAME shared sink the
//!      [`AuditBoot`] wraps — records a real **REJECT** onto the **persistent**
//!      `_meta` chain (one genesis), which then `verify_chain`s;
//!   2. the [`AuditBoot`] anchors that canonical chain (to a DURABLE file-backed
//!      WORM) and the anchored head **matches** the chain head; `verify_then_anchor`
//!      passes;
//!   3. **the real cross-restart hole**: boot1 writes honest records + anchors to a
//!      DURABLE WORM file; the `_meta` rows are then offline-rewritten into a
//!      consistent forged chain; a **fresh boot2** over the SAME durable WORM file
//!      calling the ACTUAL [`AuditBoot::verify_then_anchor`] (verify-BEFORE-anchor)
//!      **REFUSES to start** (`BootError::AnchorHeadMismatch`) — not a test-local
//!      mirror, the real boot path;
//!   4. a positive control: an **untampered** restart over the same durable WORM
//!      verifies and proceeds;
//!   5. the writer DSN is the audit-writer role (never the audited agent).
//!
//! Connection: `PG_BUMPERS_AUDIT_PGURL` (admin/superuser) or the default below —
//! the dedicated PG18 audit cluster on **55432**. NEVER 5432.
//!
//! The proxy always compiles `pgb-audit` with its `pg` feature (the running
//! proxy persists to `_meta`), so this test needs no extra cfg gate.

use std::sync::{Arc, Mutex};

use pgb_audit::{
    AUDIT_SIGNING_KEY_ID, AuditBoot, BootError, Decision, LocalSecretStore, SecretStore, Sink,
    verify_chain,
};
use pgb_core::{Clock, MockClock};
use pgb_proxy::Recorder;
use postgres::{Client, NoTls};

/// A fresh, unique durable WORM anchor file path under the temp dir (modelling
/// the object-lock / transparency-log retention the operator cannot rewrite).
fn fresh_anchor_path(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "pgb_proxy_s5_anchor_{tag}_{}.worm",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

const DEFAULT_ADMIN_PGURL: &str = "host=127.0.0.1 port=55432 user=postgres dbname=postgres";

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn admin_pgurl() -> String {
    std::env::var("PG_BUMPERS_AUDIT_PGURL").unwrap_or_else(|_| DEFAULT_ADMIN_PGURL.to_string())
}

fn connect(url: &str) -> Client {
    Client::connect(url, NoTls).unwrap_or_else(|e| panic!("connect {url}: {e}"))
}

/// Read the audit `_meta` schema SQL, stripping the psql `\set` meta-command.
fn schema_sql() -> String {
    // The schema lives in the audit crate, one level up from this crate.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../audit/sql/10_audit_meta.sql"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    raw.lines()
        .filter(|l| !l.trim_start().starts_with("\\set"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn rewrite_db(dsn: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

fn rewrite_role(dsn: &str, role: &str, password: &str) -> String {
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|kv| !kv.starts_with("user=") && !kv.starts_with("password="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("user={role}"));
    parts.push(format!("password={password}"));
    parts.join(" ")
}

/// Create an isolated fresh DB, apply the audit `_meta` schema, and return
/// `(writer_dsn, admin_client_on_that_db)`.
fn setup_fresh_db(tag: &str) -> (String, Client) {
    let mut admin = connect(&admin_pgurl());
    let dbname = format!(
        "pgb_proxy_s5_it_{tag}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin
        .batch_execute(&format!("CREATE DATABASE \"{dbname}\""))
        .unwrap_or_else(|e| panic!("create db {dbname}: {e}"));
    let db_url = rewrite_db(&admin_pgurl(), &dbname);
    let mut db_admin = connect(&db_url);
    db_admin
        .batch_execute(&schema_sql())
        .expect("apply audit _meta schema");
    let writer_dsn = rewrite_role(&db_url, "pgb_audit_writer", "pgb_audit_writer_dev_pw");
    (writer_dsn, db_admin)
}

fn store_with_key() -> LocalSecretStore {
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"proxy-s5-it-signing-key-000001")
        .unwrap();
    store
}

/// (1)+(2): a real proxy REJECT lands on the persistent `_meta` chain (one
/// genesis), the chain verifies, and the real fail-closed boot sequence
/// (`verify_then_anchor`) anchors it to a DURABLE WORM file and passes.
#[test]
fn proxy_reject_persists_and_anchored_head_matches() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the proxy S5 _meta anchor test");
        return;
    }
    let (writer_dsn, _admin) = setup_fresh_db("anchor");
    let anchor_path = fresh_anchor_path("anchor");
    let clock = MockClock::starting_at(1_700_000_000_000);

    // Build the boot handle over the real `_meta` writer DSN + DURABLE WORM file.
    let mut boot =
        AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 10_000, &anchor_path)
            .expect("audit _meta boot");

    // Inject the SAME shared sink into the proxy Recorder.
    let sink_arc: Arc<Mutex<dyn Sink + Send>> = boot.sink_arc();
    let recorder = Recorder::new(
        sink_arc,
        Arc::new(clock.clone()) as Arc<dyn Clock>,
        "pgb_agent",
    );

    // The marquee hostile statement, BLOCKED → recorded as a REJECT on `_meta`.
    recorder
        .reject(
            "it-sess",
            "COMMIT; DROP SCHEMA public CASCADE",
            "simple_query_rejected",
            Some("extended-protocol-only".to_string()),
        )
        .expect("record reject onto _meta");

    // The persisted chain has the reject at the single genesis (seq 0).
    let records = boot.load_chain().expect("load persisted chain");
    assert_eq!(records.len(), 1, "one persisted record");
    assert_eq!(records[0].payload.seq, 0, "single genesis seq 0");
    assert_eq!(records[0].payload.decision, Decision::Reject);
    assert!(records[0].payload.statement_text.contains("DROP SCHEMA"));
    verify_chain(&records).expect("persisted chain verifies");

    // The REAL fail-closed boot sequence: genesis (empty durable WORM) ⇒ anchor
    // the baseline. Passes on the honest chain.
    boot.verify_then_anchor(clock.monotonic_millis())
        .expect("verify_then_anchor passes on honest chain (genesis baseline)");

    // The durable WORM file now pins the chain head.
    let anchored = boot.worm().latest().expect("baseline anchored to file");
    assert_eq!(
        anchored.head_hash,
        records.last().unwrap().record_hash,
        "anchored head == persisted chain head"
    );
    let _ = std::fs::remove_file(&anchor_path);
    eprintln!("[it] proxy REJECT persisted on `_meta`; durable anchor head matches; boot OK");
}

/// Build the forged `_meta` rows in-process (the SAME audit sealing, so the
/// chain is internally consistent) with the BLOCK at seq 0 flipped to ALLOW, then
/// overwrite every row in the live table. Returns the forged records.
fn forge_meta_rows_in_table(admin: &mut Client) -> Vec<pgb_audit::AuditRecord> {
    use pgb_audit::{InMemorySink, NewEntry, Principal};
    use pgb_policy::IntentTiers;
    let mk = |role: &str, sql: &str, dec: Decision, code: &str| NewEntry {
        statement_text: sql.to_string(),
        decision: dec,
        reason_code: code.to_string(),
        reason: None,
        principal: Principal {
            role: role.to_string(),
            session_id: Some("s".to_string()),
            principal: None,
        },
        intent: IntentTiers::from_statement(role, sql, Some("proxy".to_string())),
        write_safety: Default::default(),
    };
    // Re-derive the ORIGINAL stamps so the forged rows differ only in the flipped
    // decision (the honest rows used the recorder's clock at fixed mock time).
    let c2 = MockClock::starting_at(1_700_000_000_000);
    let mut forged = InMemorySink::new();
    forged
        .append(
            // tampered: was BLOCK/write_on_readonly, now ALLOW/ok
            mk("pgb_agent", "UPDATE t SET x=1", Decision::Allow, "ok"),
            c2.now_unix_millis(),
        )
        .unwrap();
    forged
        .append(
            mk(
                "pgb_agent",
                "COPY t FROM STDIN",
                Decision::Reject,
                "copy_rejected",
            ),
            c2.now_unix_millis(),
        )
        .unwrap();
    let forged_records = forged.load_chain().unwrap();
    verify_chain(&forged_records).expect("forged chain internally consistent (S1 blind)");

    // Disable the append-only trigger (models a privileged operator with direct
    // table access), overwrite every row, re-enable.
    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log DISABLE TRIGGER audit_log_no_mutation")
        .expect("disable trigger for forced rewrite");
    for rec in &forged_records {
        let payload_text = String::from_utf8(rec.payload.canonical_bytes()).unwrap();
        admin
            .execute(
                "UPDATE pgb_audit.audit_log SET prev_hash=$2, record_hash=$3, payload=$4 \
                 WHERE seq=$1",
                &[
                    &(rec.payload.seq as i64),
                    &rec.payload.prev_hash,
                    &rec.record_hash,
                    &payload_text,
                ],
            )
            .expect("rewrite row");
    }
    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log ENABLE TRIGGER audit_log_no_mutation")
        .expect("re-enable trigger");
    forged_records
}

/// (3) THE BLOCKER FIX, proven via the REAL boot path: boot1 writes honest
/// records and anchors to a DURABLE WORM file; the `_meta` rows are offline-
/// rewritten into a consistent forged chain; a **fresh boot2** over the SAME
/// durable WORM file calls the ACTUAL `AuditBoot::verify_then_anchor` (verify-
/// BEFORE-anchor) and must **REFUSE TO START** with `AnchorHeadMismatch`.
#[test]
fn full_chain_rewrite_in_table_is_caught_at_startup() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the proxy S5 full-chain-rewrite test");
        return;
    }
    let (writer_dsn, mut admin) = setup_fresh_db("rewrite");
    let anchor_path = fresh_anchor_path("rewrite");
    let clock = MockClock::starting_at(1_700_000_000_000);

    // --- boot1 (honest run): write a BLOCK + REJECT, anchor to the DURABLE WORM. ---
    {
        let mut boot1 =
            AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 10_000, &anchor_path)
                .expect("audit _meta boot1");
        let sink_arc: Arc<Mutex<dyn Sink + Send>> = boot1.sink_arc();
        let recorder = Recorder::new(
            sink_arc,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            "pgb_agent",
        );
        recorder
            .block("s", "UPDATE t SET x=1", "write_on_readonly", None)
            .unwrap();
        recorder
            .reject("s", "COPY t FROM STDIN", "copy_rejected", None)
            .unwrap();
        // REAL boot sequence: genesis (empty durable WORM) ⇒ verify (nothing to
        // verify against) + anchor the honest head to the file. Persisted on disk.
        boot1
            .verify_then_anchor(clock.monotonic_millis())
            .expect("boot1 anchors honest head to the durable WORM");
        // boot1 process "exits" here — the durable anchor file remains.
    }
    let honest_head = anchor_head_in_file(&anchor_path);

    // --- ATTACK: offline full-chain rewrite of the `_meta` rows (BLOCK→ALLOW). ---
    let forged_records = forge_meta_rows_in_table(&mut admin);
    assert_ne!(
        forged_records.last().unwrap().record_hash,
        honest_head,
        "rewrite changed the head"
    );

    // --- boot2 (the REAL process restart over the SAME durable WORM file). ---
    // It calls the ACTUAL AuditBoot::verify_then_anchor — NOT a test-local mirror.
    // verify-BEFORE-anchor must catch the forged head against the prior durable
    // anchor and REFUSE to start.
    let mut boot2 =
        AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 10_000, &anchor_path)
            .expect("reconnect boot2 over same durable WORM");
    let rewritten = boot2.load_chain().unwrap();
    verify_chain(&rewritten).expect("rewritten chain is internally consistent (S1 blind)");

    let boot_result = boot2.verify_then_anchor(clock.monotonic_millis());
    match boot_result {
        Err(BootError::AnchorHeadMismatch {
            actual_head,
            anchored_head,
            ..
        }) => {
            assert_eq!(actual_head, forged_records.last().unwrap().record_hash);
            assert_eq!(
                anchored_head, honest_head,
                "anchor still pins the honest head"
            );
            eprintln!(
                "[it] REAL boot path REFUSED across restart: full-chain rewrite CAUGHT \
                 (verify-before-anchor → AnchorHeadMismatch)"
            );
        }
        other => panic!(
            "FAIL-CLOSED BROKEN: real boot path must refuse over a forged restart, got {other:?}"
        ),
    }
    let _ = std::fs::remove_file(&anchor_path);
}

/// (4) Positive control: an **untampered** restart over the same durable WORM
/// file verifies and the real boot sequence proceeds (anchors forward).
#[test]
fn untampered_restart_over_durable_anchor_starts() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the proxy S5 untampered-restart test");
        return;
    }
    let (writer_dsn, _admin) = setup_fresh_db("clean_restart");
    let anchor_path = fresh_anchor_path("clean_restart");
    let clock = MockClock::starting_at(1_700_000_000_000);

    // boot1: write honest records, anchor to the durable WORM.
    {
        let mut boot1 =
            AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 10_000, &anchor_path)
                .expect("audit _meta boot1");
        let sink_arc: Arc<Mutex<dyn Sink + Send>> = boot1.sink_arc();
        let recorder = Recorder::new(
            sink_arc,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            "pgb_agent",
        );
        recorder
            .reject("s", "DROP TABLE t", "ddl_rejected", None)
            .unwrap();
        boot1
            .verify_then_anchor(clock.monotonic_millis())
            .expect("boot1 anchors honest head");
    }

    // boot2: fresh process over the SAME durable WORM + the UNtampered `_meta`
    // chain. The real boot sequence must verify cleanly and proceed.
    let mut boot2 =
        AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 10_000, &anchor_path)
            .expect("reconnect boot2");
    boot2
        .verify_then_anchor(clock.monotonic_millis())
        .expect("untampered restart over the durable anchor verifies and starts");
    eprintln!("[it] untampered restart over durable WORM verified and started (positive control)");
    let _ = std::fs::remove_file(&anchor_path);
}

/// Read the latest anchored head hash out of a durable WORM file (the head a
/// prior boot pinned, persisted across the restart).
fn anchor_head_in_file(path: &std::path::Path) -> String {
    pgb_audit::WormAnchor::open_file(path)
        .expect("open durable WORM")
        .latest()
        .expect("a prior boot anchored a head")
        .head_hash
        .clone()
}
