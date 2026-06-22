//! Env-gated PG18 IT for **cross-process audit-append serialization** (S5 #76,
//! item 2). Runs only with `PG_BUMPERS_IT=1`. Run:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-audit --test concurrent_append_it -- --test-threads=1
//! ```
//!
//! It proves that two **independent connections** (modelling two separate
//! processes — warden + applyd + proxy — each with its OWN `PgSink`/`Client`)
//! appending CONCURRENTLY to the one hash-chained `_meta` table produce a
//! **contiguous, verifying chain with no lost record and no crash**.
//!
//! Without the fixed `pg_advisory_xact_lock` around the head-read + insert, two
//! appenders can both read head `N`, both compute next-seq `N+1`, and collide on
//! `UNIQUE(seq)` — one append errors (fatal to the live warden) and that record
//! is dropped. With the lock, the read-then-insert is serialized across every
//! appender, so the chain stays gap-free.
//!
//! NEVER points at the founder's 5432 cluster.

#![cfg(feature = "pg")]

use std::sync::{Arc, Barrier};
use std::thread;

use pgb_audit::pg::PgSink;
use pgb_audit::{Decision, NewEntry, Principal, Sink};
use pgb_core::{Clock, MockClock};
use pgb_policy::IntentTiers;
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
        "pgb_audit_concurrent_{tag}_{}",
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
        .expect("apply audit _meta schema into the fresh db");
    dbname
}

fn writer_pgurl(dbname: &str) -> String {
    let url = rewrite_db(&admin_pgurl(), dbname);
    rewrite_role(&url, "pgb_audit_writer", "pgb_audit_writer_dev_pw")
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

/// THE item-2 property: two independent `PgSink`s (two connections = two
/// "processes") hammer the SAME `_meta` chain concurrently. EVERY append must
/// succeed (no `UNIQUE(seq)` crash), and the persisted chain must be contiguous
/// (seq 0..2N, no gap) and VERIFY (no lost record).
#[test]
fn concurrent_appenders_from_two_connections_produce_a_contiguous_verifying_chain() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the concurrent-append serialization IT");
        return;
    }
    let dbname = setup_fresh_db("serialize");

    const PER_WRITER: usize = 40;
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    for w in 0..2 {
        let url = writer_pgurl(&dbname);
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            // Each thread is its OWN connection = its OWN process' PgSink.
            let mut sink = PgSink::new(connect(&url));
            let clock = MockClock::starting_at(1_700_000_000_000);
            // Line both writers up to start at the same instant → maximum
            // head-read/insert interleaving.
            barrier.wait();
            for i in 0..PER_WRITER {
                let sql = format!("UPDATE t SET x={w}_{i}");
                sink.append(
                    entry("pgb_agent", &sql, Decision::Block, "write_on_readonly"),
                    clock.now_unix_millis(),
                )
                .unwrap_or_else(|e| {
                    panic!("writer {w} append #{i} must NOT fail under the advisory lock: {e}")
                });
            }
        }));
    }
    for h in handles {
        h.join()
            .expect("appender thread must not panic (no UNIQUE(seq) crash)");
    }

    // Read the whole chain back from a fresh connection and assert it is
    // contiguous + verifies.
    let mut reader = PgSink::new(connect(&writer_pgurl(&dbname)));
    let chain = reader.load_chain_mut().expect("load chain");
    assert_eq!(
        chain.len(),
        2 * PER_WRITER,
        "every concurrent append landed — no record lost"
    );
    for (i, rec) in chain.iter().enumerate() {
        assert_eq!(
            rec.payload.seq, i as u64,
            "chain is contiguous (seq {i} present, no gap/dup)"
        );
    }
    reader
        .verify_mut()
        .expect("the concurrently-built persisted chain verifies (no fork)");
    eprintln!(
        "[it] {} concurrent cross-connection appends → contiguous chain seq 0..{} VERIFIES; head={}",
        2 * PER_WRITER,
        2 * PER_WRITER - 1,
        chain.last().unwrap().record_hash
    );

    // Teardown.
    let mut admin = connect(&admin_pgurl());
    let _ = admin.batch_execute(&format!(
        "DROP DATABASE IF EXISTS \"{dbname}\" WITH (FORCE)"
    ));
}
