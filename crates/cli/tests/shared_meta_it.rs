//! Env-gated **real PG18** cross-component integration test (issue #64, S5;
//! SPEC §3/§4/§10.9).
//!
//! THE marquee S5 proof: a **proxy reject** (driven through the real
//! `pgb_proxy::Recorder`) AND a **CLI approve** (driven through the real
//! `pgb_cli::ApprovalFlow`) land on the **same** persistent `_meta` chain — one
//! genesis, hash-chained appends from both components — `verify_chain` passes,
//! and the external-WORM anchored head **matches** the chain head.
//!
//! Runs only when `PG_BUMPERS_IT=1`. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-cli --test shared_meta_it -- --nocapture
//! ```
//!
//! The proxy is a dev-dependency only (no crate cycle: proxy never depends on
//! cli). The `_meta` cluster is the dedicated PG18 on **55432**. NEVER 5432.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use pgb_audit::{
    AUDIT_SIGNING_KEY_ID, AuditBoot, Decision, LocalSecretStore, SecretStore, Sink, verify_chain,
};
use pgb_cli::{
    ApprovalFlow, InMemoryNonceStore, Principal, Proposal, RecordingWebhookSender, RequestId,
};
use pgb_core::{Clock, MockClock, inverse::Operation};
use pgb_proxy::Recorder;
use postgres::{Client, NoTls};

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

fn schema_sql() -> String {
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

fn setup_fresh_db(tag: &str) -> String {
    let mut admin = connect(&admin_pgurl());
    let dbname = format!(
        "pgb_cli_s5_it_{tag}_{}",
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
    rewrite_role(&db_url, "pgb_audit_writer", "pgb_audit_writer_dev_pw")
}

fn store_with_key() -> LocalSecretStore {
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"cli-s5-it-signing-key-000001")
        .unwrap();
    store
}

/// THE S5 ACCEPTANCE: a proxy REJECT and a CLI APPROVE land on the SAME `_meta`
/// chain (one genesis); `verify_chain` passes; the anchored head matches.
#[test]
fn proxy_reject_and_cli_approve_share_one_anchored_meta_chain() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the S5 shared-_meta cross-component test");
        return;
    }
    let writer_dsn = setup_fresh_db("shared");
    let anchor_path = std::env::temp_dir().join(format!(
        "pgb_cli_s5_anchor_shared_{}.worm",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&anchor_path);
    let clock = MockClock::starting_at(1_700_000_000_000);

    // ONE boot handle over the real `_meta` writer DSN + DURABLE WORM → one
    // canonical chain, anchored to a file that survives restarts.
    let mut boot =
        AuditBoot::connect_with_anchor(&writer_dsn, &store_with_key(), 30_000, &anchor_path)
            .expect("audit boot");

    // ---- PROXY side: inject the shared sink into the proxy Recorder ----
    let proxy_arc: Arc<Mutex<dyn Sink + Send>> = boot.sink_arc();
    let recorder = Recorder::new(
        proxy_arc,
        Arc::new(clock.clone()) as Arc<dyn Clock>,
        "pgb_agent",
    );
    recorder
        .reject(
            "proxy-sess",
            "COMMIT; DROP SCHEMA public CASCADE",
            "simple_query_rejected",
            Some("extended-protocol-only".to_string()),
        )
        .expect("proxy reject onto shared _meta");

    // ---- CLI side: run the §14 approval flow over a CLONE of the same sink ----
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let mut flow = ApprovalFlow::new(
        boot.shared_sink(),
        RecordingWebhookSender::new(),
        verifying_key,
        InMemoryNonceStore::new(),
    );
    let proposal = Proposal {
        proposal_id: "p-1".to_string(),
        statement_text: "UPDATE public.orders SET status='fixed' WHERE id=$1".to_string(),
        normalized_params: vec!["42".to_string()],
        role: "app_writer".to_string(),
        session_id: "cli-sess".to_string(),
        dry_run_lsn: "3A/7F00C8".to_string(),
        blast_radius_checksum: "sha256:demo".to_string(),
    };
    let op = Operation::Update {
        has_preimage: true,
        has_pk: true,
    };
    let id = RequestId("req-1".to_string());
    // request_elevation appends a BLOCK (approval_required) to the shared chain.
    flow.request_elevation(id.clone(), proposal, "agent-1", &op, 60_000, &clock)
        .expect("request elevation");
    // approve appends an ALLOW (grant_signed) to the SAME chain.
    let approver = Principal::approver("human-alice");
    flow.approve(&id, &approver, &signing_key, "nonce-1", 30_000, &clock)
        .expect("approve");

    // ---- The persisted chain has BOTH components' events, one genesis ----
    let records = boot.load_chain().expect("load shared _meta chain");
    assert!(
        records.len() >= 3,
        "proxy reject + CLI block + CLI allow on ONE chain (got {})",
        records.len()
    );
    // Single genesis: seqs are 0..n contiguous and the first is the proxy reject.
    assert_eq!(records[0].payload.seq, 0, "single genesis at seq 0");
    assert_eq!(
        records[0].payload.decision,
        Decision::Reject,
        "the proxy reject is the genesis record"
    );
    assert!(records[0].payload.statement_text.contains("DROP SCHEMA"));
    // A CLI grant_signed ALLOW is present, chained AFTER the proxy reject.
    let has_grant = records
        .iter()
        .any(|r| r.payload.decision == Decision::Allow && r.payload.reason_code == "grant_signed");
    assert!(
        has_grant,
        "the CLI approve (grant_signed ALLOW) is on the same chain"
    );
    // Contiguous seqs + intact back-links == one chain, one genesis.
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.payload.seq, i as u64, "contiguous seq (single genesis)");
    }
    verify_chain(&records).expect("the SHARED chain verifies (one genesis, both components)");

    // ---- Anchor the canonical chain to the durable WORM; head matches ----
    // The real fail-closed boot sequence (genesis baseline here): verify (nothing
    // prior) + anchor the current head durably.
    boot.verify_then_anchor(clock.monotonic_millis())
        .expect("fail-closed verify_then_anchor passes on the honest shared chain");
    let anchored = boot.worm().latest().expect("baseline anchored to the file");
    assert_eq!(
        anchored.head_hash,
        records.last().unwrap().record_hash,
        "anchored head == shared chain head"
    );

    eprintln!(
        "[it] proxy REJECT + CLI APPROVE on ONE `_meta` chain ({} records, single genesis); \
         verify_chain OK; durable anchored head matches",
        records.len()
    );
    let _ = std::fs::remove_file(&anchor_path);
}
