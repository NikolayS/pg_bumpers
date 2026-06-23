//! Env-gated PG18 IT for the **single anchor OWNER** over the one shared chain
//! (S5 #76, item 3). Runs only with `PG_BUMPERS_IT=1`. Run:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-audit --test single_anchor_owner_it -- --test-threads=1
//! ```
//!
//! It proves, against a live `_meta` table + a SHARED durable WORM anchor file +
//! the SAME signing key, the coherent single-owner topology:
//!
//!   1. the OWNER (proxy) boots `verify_then_anchor` and pins the honest baseline;
//!   2. a VERIFY-only binary (applyd) boots over the SAME chain + SAME durable
//!      anchor and VERIFIES — without anchoring (one anchorer over the chain);
//!   3. a concurrent RESTART of BOTH (owner then verify-only, both over the shared
//!      durable head) both verify cleanly — no fail-closed deadlock against each
//!      other's head (the two-uncoordinated-anchorers bug);
//!   4. a VERIFY-only binary booting over a TAMPERED (offline-rewritten) chain
//!      REFUSES and does NOT re-baseline (the WORM is untouched).
//!
//! NEVER points at the founder's 5432 cluster.

#![cfg(feature = "pg")]

use pgb_audit::{
    AUDIT_SIGNING_KEY_ID, AnchorRole, AuditBoot, Decision, LocalSecretStore, NewEntry, Principal,
    SecretStore, SharedSink, Sink,
};
use pgb_core::{Clock, SystemClock};
use pgb_policy::IntentTiers;
use postgres::{Client, NoTls};

const DEFAULT_ADMIN_PGURL: &str = "host=127.0.0.1 port=55432 user=postgres dbname=postgres";
const SHARED_SIGNING_KEY: &[u8] = b"pgb-audit-signing-key-dev-000001";

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

fn schema_sql() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/sql/10_audit_meta.sql");
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

fn setup_fresh_db(tag: &str) -> String {
    let mut admin = connect(&admin_pgurl());
    let dbname = format!(
        "pgb_audit_owner_{tag}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin
        .batch_execute(&format!("CREATE DATABASE \"{dbname}\""))
        .unwrap_or_else(|e| panic!("create db {dbname}: {e}"));
    let mut db_admin = connect(&rewrite_db(&admin_pgurl(), &dbname));
    db_admin
        .batch_execute(&schema_sql())
        .expect("apply audit _meta schema");
    dbname
}

fn writer_pgurl(dbname: &str) -> String {
    let url = rewrite_db(&admin_pgurl(), dbname);
    rewrite_role(&url, "pgb_audit_writer", "pgb_audit_writer_dev_pw")
}

fn store() -> LocalSecretStore {
    let mut s = LocalSecretStore::new();
    s.put(AUDIT_SIGNING_KEY_ID, SHARED_SIGNING_KEY).unwrap();
    s
}

fn entry(role: &str, sql: &str, decision: Decision, code: &str) -> NewEntry {
    NewEntry {
        statement_text: sql.to_string(),
        decision,
        reason_code: code.to_string(),
        reason: None,
        principal: Principal {
            role: role.to_string(),
            session_id: Some("it-sess".to_string()),
            principal: None,
        },
        intent: IntentTiers::from_statement(role, sql, Some("it".to_string())),
        write_safety: Default::default(),
    }
}

/// Boot a fresh PG-backed AuditBoot over `dbname` + the shared durable anchor
/// `anchor_path` (the SAME key for owner + verifier).
fn boot(dbname: &str, anchor_path: &std::path::Path) -> AuditBoot {
    AuditBoot::connect_with_anchor(&writer_pgurl(dbname), &store(), 60_000, anchor_path)
        .expect("AuditBoot connect_with_anchor")
}

#[test]
fn single_owner_anchors_verifier_verifies_concurrent_restart_clean_tamper_refused() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the single-anchor-owner IT");
        return;
    }
    let dbname = setup_fresh_db("topology");
    let anchor = std::env::temp_dir().join(format!("pgb-owner-it-{}.worm", std::process::id()));
    let _ = std::fs::remove_file(&anchor);
    let clock = SystemClock::new();

    // Seed two honest records onto the shared chain via the writer.
    {
        let mut seed = SharedSink::from_arc(boot(&dbname, &anchor).sink_arc());
        seed.append(
            entry("pgb_agent", "UPDATE t SET x=1", Decision::Block, "ro"),
            clock.now_unix_millis(),
        )
        .unwrap();
        seed.append(
            entry("pgb_agent", "COPY t FROM STDIN", Decision::Reject, "copy"),
            clock.now_unix_millis(),
        )
        .unwrap();
    }

    // (1) OWNER boots: verify_then_anchor pins the honest baseline durably.
    {
        let mut owner = boot(&dbname, &anchor);
        owner
            .boot(AnchorRole::Owner, clock.monotonic_millis())
            .expect("owner anchors the honest baseline");
        assert!(
            owner.worm().latest().is_some(),
            "owner published a baseline"
        );
    }
    let anchored_after_owner = pgb_audit::WormAnchor::open_file(&anchor)
        .unwrap()
        .entries()
        .len();
    assert_eq!(
        anchored_after_owner, 1,
        "owner published exactly one anchor"
    );

    // (2) VERIFY-only (applyd) boots over the SAME chain + durable anchor and
    //     VERIFIES — and MUST NOT anchor (one anchorer over the chain).
    {
        let mut verifier = boot(&dbname, &anchor);
        verifier
            .boot(AnchorRole::Verify, clock.monotonic_millis())
            .expect("verify-only verifies against the owner's anchored head");
    }
    let anchored_after_verifier = pgb_audit::WormAnchor::open_file(&anchor)
        .unwrap()
        .entries()
        .len();
    assert_eq!(
        anchored_after_verifier, anchored_after_owner,
        "verify-only did NOT anchor — single owner over the shared chain"
    );

    // (3) CONCURRENT RESTART: both binaries re-boot over the SHARED durable head;
    //     both verify cleanly (no fail-closed deadlock against each other's head —
    //     the two-uncoordinated-anchorers bug this item closes).
    {
        let mut owner2 = boot(&dbname, &anchor);
        owner2
            .boot(AnchorRole::Owner, clock.monotonic_millis())
            .expect("owner restart verifies against the prior durable head");
        let mut verifier2 = boot(&dbname, &anchor);
        verifier2
            .boot(AnchorRole::Verify, clock.monotonic_millis())
            .expect("verify-only restart verifies against the owner's durable head");
    }

    // (4) TAMPER: rewrite the chain offline into a consistent-but-different chain
    //     (BLOCK→ALLOW, re-linked). A VERIFY-only boot over the SAME durable anchor
    //     REFUSES (head mismatch) and does NOT re-baseline.
    forge_chain_block_to_allow(&dbname);
    let entries_before_tamper_boot = pgb_audit::WormAnchor::open_file(&anchor)
        .unwrap()
        .entries()
        .len();
    {
        let mut verifier = boot(&dbname, &anchor);
        let err = verifier
            .boot(AnchorRole::Verify, clock.monotonic_millis())
            .expect_err("verify-only over a tampered chain must FAIL CLOSED");
        assert!(
            matches!(err, pgb_audit::BootError::AnchorHeadMismatch { .. }),
            "expected AnchorHeadMismatch, got {err:?}"
        );
    }
    let entries_after_tamper_boot = pgb_audit::WormAnchor::open_file(&anchor)
        .unwrap()
        .entries()
        .len();
    assert_eq!(
        entries_before_tamper_boot, entries_after_tamper_boot,
        "verify-only did NOT re-baseline the tampered chain (no new anchor)"
    );
    eprintln!(
        "[it] single-owner topology: owner anchored 1 head; verify-only verified \
         (and never anchored) across a concurrent restart; a tampered chain was \
         REFUSED with no re-baseline"
    );

    // Teardown.
    let _ = std::fs::remove_file(&anchor);
    let mut admin = connect(&admin_pgurl());
    let _ = admin.batch_execute(&format!(
        "DROP DATABASE IF EXISTS \"{dbname}\" WITH (FORCE)"
    ));
}

/// Offline-forge: flip the first record's BLOCK→ALLOW and re-link the WHOLE chain
/// so within-chain verify still passes (S1 blind) but the head differs — the
/// full-chain-rewrite the anchor catches. Done as ADMIN with the append-only
/// trigger disabled (a privileged attacker editing the table directly).
fn forge_chain_block_to_allow(dbname: &str) {
    let mut admin = connect(&rewrite_db(&admin_pgurl(), dbname));
    // Rebuild the chain from the existing rows with the decision flipped, re-hashed.
    // The simplest faithful forge: read the rows, recompute via an in-memory chain
    // with the edit, and overwrite the table.
    let rows = admin
        .query(
            "SELECT payload FROM pgb_audit.audit_log ORDER BY seq ASC",
            &[],
        )
        .unwrap();
    let mut forged = pgb_audit::InMemorySink::new();
    for r in &rows {
        let payload_json: String = r.get(0);
        // Flip the first BLOCK to ALLOW in the raw payload before re-sealing.
        let edited = payload_json.replacen("\"BLOCK\"", "\"ALLOW\"", 1);
        let payload: pgb_audit::AuditPayload = serde_json::from_str(&edited).unwrap();
        forged
            .append(
                NewEntry {
                    statement_text: payload.statement_text,
                    decision: payload.decision,
                    reason_code: payload.reason_code,
                    reason: payload.reason,
                    principal: payload.principal,
                    intent: payload.intent,
                    write_safety: payload.write_safety,
                },
                payload.timestamp_unix_millis,
            )
            .unwrap();
    }
    let forged_records = forged.load_chain().unwrap();

    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log DISABLE TRIGGER audit_log_no_mutation")
        .unwrap();
    admin.batch_execute("TRUNCATE pgb_audit.audit_log").unwrap();
    for rec in &forged_records {
        let payload_text =
            String::from_utf8(rec.payload.canonical_bytes()).expect("utf8 canonical payload");
        admin
            .execute(
                "INSERT INTO pgb_audit.audit_log (seq, prev_hash, record_hash, payload) \
                 VALUES ($1, $2, $3, $4)",
                &[
                    &(rec.payload.seq as i64),
                    &rec.payload.prev_hash,
                    &rec.record_hash,
                    &payload_text,
                ],
            )
            .unwrap();
    }
    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log ENABLE TRIGGER audit_log_no_mutation")
        .unwrap();
}
