//! Env-gated **real PG18** integration test for the S4 read gates (SPEC §3
//! EXPLAIN-cost gate + cumulative per-window volume budget; §13.4 R4a; issue
//! #53). Runs only when `PG_BUMPERS_IT=1`, so CI's fast `cargo test` skips it
//! (the crate still builds/links).
//!
//! ```sh
//! deploy/local-stack.sh up
//! PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test readgates_it -- --nocapture
//! deploy/local-stack.sh down
//! ```
//!
//! It stands up the proxy in-process (TLS + SCRAM-SHA-256), originating the
//! backend as the WALL role `pgb_agent` against the local-stack primary (54321,
//! **never 5432**), and proves end-to-end against a live server:
//!
//!  * **EXPLAIN-cost gate (advisory, fail-closed):**
//!    - a query whose `EXPLAIN` estimate (cost/rows) exceeds the role ceiling is
//!      **blocked before execution** (no rows stream; the audit reason is the
//!      EXPLAIN gate);
//!    - a cheap query under the ceiling is **allowed**;
//!    - an `EXPLAIN`-failure (a read that doesn't plan) **fails closed** (block).
//!  * **Slow-drip / cumulative per-window budget (R4a, deterministic clock):**
//!    - N small reads whose cumulative bytes exceed the window budget B → the
//!      per-window budget **trips at the deterministic boundary** (session
//!      killed); each individual read is under the single-shot cap, so only the
//!      cumulative gate can stop it;
//!    - a **sub-budget** sequence is allowed;
//!    - after the window **resets** (clock advanced past `window_secs`) a fresh
//!      sub-budget sequence is allowed again.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use pgb_audit::{verify_chain, Decision, InMemorySink, Sink};
use pgb_core::{Clock, MockClock};
use pgb_policy::{RoleBudget, WindowBudget};
use pgb_proxy::config::{BackendTarget, ProxyConfig, TlsConfig};
use pgb_proxy::{serve_connection, Recorder};
use tokio::net::TcpListener;

const AGENT_USER: &str = "pgb_agent";
const AGENT_PASSWORD: &str = "pgb_agent_dev_pw";

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn db_msg(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

fn admin_dsn() -> String {
    std::env::var("PG_BUMPERS_PROXY_PGURL")
        .unwrap_or_else(|_| "host=127.0.0.1 port=54321 user=postgres dbname=postgres".to_string())
}

fn backend_host_port_db() -> (String, u16, String) {
    let dsn = admin_dsn();
    let mut host = "127.0.0.1".to_string();
    let mut port = 54321u16;
    let mut db = "postgres".to_string();
    for kv in dsn.split_whitespace() {
        if let Some(v) = kv.strip_prefix("host=") {
            host = v.to_string();
        } else if let Some(v) = kv.strip_prefix("port=") {
            port = v.parse().unwrap_or(54321);
        } else if let Some(v) = kv.strip_prefix("dbname=") {
            db = v.to_string();
        }
    }
    (host, port, db)
}

/// Fixtures for the read-gate tests: a small cheap table (low EXPLAIN cost) and
/// a large wide table (high EXPLAIN cost + many small rows for the slow-drip
/// drip), both SELECT-granted to the WALL role.
fn setup_fixtures() {
    use postgres::{Client, NoTls};
    let mut admin = Client::connect(&admin_dsn(), NoTls).expect("admin connect");
    admin
        .batch_execute(
            "BEGIN;
             SELECT pg_advisory_xact_lock(7067626669780053);

             CREATE TABLE IF NOT EXISTS public.rg_cheap (id int PRIMARY KEY, note text);
             INSERT INTO public.rg_cheap VALUES (1,'a'),(2,'b'),(3,'c')
               ON CONFLICT (id) DO NOTHING;
             ANALYZE public.rg_cheap;
             GRANT SELECT ON public.rg_cheap TO pgb_agent;

             DROP TABLE IF EXISTS public.rg_big;
             CREATE TABLE public.rg_big AS
               SELECT g AS id, repeat('y', 100) AS payload FROM generate_series(1, 20000) g;
             ANALYZE public.rg_big;
             GRANT SELECT ON public.rg_big TO pgb_agent;

             COMMIT;",
        )
        .expect("apply fixtures");
}

fn make_tls() -> (TlsConfig, Vec<u8>, tempdir::TempPaths) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let der = cert.cert.der().to_vec();

    let dir = std::env::temp_dir().join(format!("pgb-readgates-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (
        TlsConfig {
            cert_pem: cert_path,
            key_pem: key_path,
        },
        der,
        tempdir::TempPaths { dir },
    )
}

mod tempdir {
    pub struct TempPaths {
        pub dir: std::path::PathBuf,
    }
    impl Drop for TempPaths {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Spawn the proxy on an ephemeral port with the given budget. Returns the bound
/// address, the audit sink, the client trust DER, and the **MockClock handle**
/// (shared with the proxy) so the slow-drip test can advance time deterministically
/// to cross the window boundary.
async fn spawn_proxy(
    budget: RoleBudget,
    statement_timeout_ms: u64,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<InMemorySink>>,
    Vec<u8>,
    MockClock,
    tempdir::TempPaths,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (tls_cfg, cert_der, paths) = make_tls();
    let (host, port, db) = backend_host_port_db();

    let cfg = Arc::new(ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(tls_cfg.clone()),
        require_tls: true,
        backend: BackendTarget {
            host,
            port,
            database: db,
            role: AGENT_USER.to_string(),
            password: AGENT_PASSWORD.to_string(),
        },
        agent_user: AGENT_USER.to_string(),
        agent_password: AGENT_PASSWORD.to_string(),
        policy_role: "analytics".to_string(),
        budget,
        statement_timeout_ms,
        search_path: ProxyConfig::DEFAULT_SEARCH_PATH.to_string(),
    });

    let sink_inner = Arc::new(Mutex::new(InMemorySink::new()));
    let sink: Arc<Mutex<dyn Sink + Send>> = sink_inner.clone();
    // The SAME MockClock drives the audit stamps AND the per-window meter, so the
    // test can advance it to deterministically cross the window boundary.
    let mock = MockClock::starting_at(1_700_000_000_000);
    let clock: Arc<dyn Clock> = Arc::new(mock.clone());
    let recorder = Recorder::new(sink, clock, AGENT_USER);

    let listener = TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(
        pgb_proxy::tls::server_config(&tls_cfg).unwrap(),
    ));

    let mut id = 0u64;
    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            id += 1;
            let cfg = cfg.clone();
            let acceptor = Some(acceptor.clone());
            let recorder = recorder.clone();
            let sid = format!("rg-conn-{id}");
            tokio::spawn(async move {
                let _ = serve_connection(tcp, cfg, acceptor, recorder, sid).await;
            });
        }
    });

    (addr, sink_inner, cert_der, mock, paths)
}

async fn connect_client(addr: std::net::SocketAddr, cert_der: &[u8]) -> tokio_postgres::Client {
    use tokio_rustls::rustls;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))
        .unwrap();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);

    let conn_str = format!(
        "host=localhost port={} user={} password={} dbname=postgres sslmode=require",
        addr.port(),
        AGENT_USER,
        AGENT_PASSWORD,
    );
    let (client, connection) = tokio_postgres::connect(&conn_str, tls)
        .await
        .expect("client connect through proxy");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// **EXPLAIN-cost gate** against live PG18 (advisory + fail-closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_cost_gate_blocks_before_execution() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BUMPERS_IT=1 (+ deploy/local-stack.sh up) for the EXPLAIN-gate IT"
        );
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    // A tight EXPLAIN ceiling: max_plan_cost = 100 cost units, max_plan_rows = 100.
    // After ANALYZE the cheap 3-row table plans at cost≈1.06/rows=3 (allowed);
    // the big 20k-row table seq-scans at cost≈584/rows=20000 (blocked on BOTH
    // the cost AND the row dimension). Single-shot byte/row caps + window are
    // generous so the advisory EXPLAIN gate is what trips here.
    let budget = RoleBudget {
        max_bytes: 100_000_000,
        max_rows: 1_000_000,
        max_plan_cost: 100.0,
        max_plan_rows: 100,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 1_000_000_000,
            max_rows: 1_000_000_000,
        },
    };
    let (addr, sink, cert_der, _clock, _paths) = spawn_proxy(budget, 30_000).await;
    let client = connect_client(addr, &cert_der).await;

    // ---- (a) Cheap query UNDER the ceiling is ALLOWED ----
    let rows = client
        .query("SELECT id, note FROM public.rg_cheap ORDER BY id", &[])
        .await
        .expect("cheap read under the EXPLAIN ceiling must be allowed");
    assert_eq!(rows.len(), 3, "cheap read returned wrong row count");
    eprintln!(
        "[ok] cheap read under EXPLAIN ceiling allowed ({} rows)",
        rows.len()
    );

    // ---- (b) Heavy query OVER the ceiling is BLOCKED before execution ----
    let heavy = client
        .query("SELECT id, payload FROM public.rg_big", &[])
        .await;
    let err = heavy.expect_err("heavy read over the EXPLAIN ceiling must be BLOCKED");
    let msg = db_msg(&err);
    eprintln!("[ok] heavy read blocked by EXPLAIN gate: {msg}");
    assert!(
        msg.contains("EXPLAIN-cost gate") || msg.contains("before execution"),
        "EXPLAIN-gate block should explain itself: {msg}"
    );

    // ---- (c) EXPLAIN-failure FAILS CLOSED (a read that cannot plan) ----
    // A read of a non-existent relation: it classifies as a read (SELECT), so it
    // passes the read-only gate, but EXPLAIN errors on the backend → fail-closed.
    let bad = client
        .query("SELECT * FROM public.rg_does_not_exist", &[])
        .await;
    let berr = bad.expect_err("EXPLAIN failure must fail closed (block)");
    eprintln!("[ok] EXPLAIN-failure fails closed: {}", db_msg(&berr));

    // The session survives all the recoverable blocks.
    let alive = client
        .query_one("SELECT 7::int", &[])
        .await
        .expect("session must survive EXPLAIN-gate blocks");
    let v: i32 = alive.get(0);
    assert_eq!(v, 7);
    eprintln!("[ok] session survives EXPLAIN-gate blocks (SELECT 7 → 7)");

    // The blocks were audited with the EXPLAIN gate reason codes.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let chain = sink.lock().unwrap().chain().records().to_vec();
    verify_chain(&chain).expect("audit chain must verify");
    let explain_blocks = chain
        .iter()
        .filter(|r| {
            r.payload.decision == Decision::Block && (r.payload.reason_code.starts_with("explain_"))
        })
        .count();
    assert!(
        explain_blocks >= 2,
        "must have audited the EXPLAIN cost block + the fail-closed block (got {explain_blocks})"
    );
    eprintln!("[ok] audit chain has {explain_blocks} EXPLAIN-gate blocks; verify_chain OK");
}

/// **Slow-drip / cumulative per-window volume budget** (R4a) against live PG18,
/// deterministic via the injected MockClock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_drip_cumulative_window_budget_trips_and_resets() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 (+ deploy/local-stack.sh up) for the slow-drip IT");
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    // Each read below returns ~5 rows of ~100-byte payload. Set the per-window
    // budget so a handful of these small reads fit but the cumulative total
    // trips: window B = 2500 bytes / 60s. The single-shot cap and EXPLAIN ceiling
    // are generous so ONLY the cumulative window gate can stop the drip.
    let budget = RoleBudget {
        max_bytes: 100_000_000,
        max_rows: 1_000_000,
        max_plan_cost: 1_000_000_000.0,
        max_plan_rows: 1_000_000_000,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 2_500,
            max_rows: 1_000_000,
        },
    };
    let (addr, sink, cert_der, clock, _paths) = spawn_proxy(budget, 30_000).await;
    let client = connect_client(addr, &cert_der).await;

    // Each small read: 5 rows of ~100-byte payload. On the wire a DataRow is
    // payload + framing, so ~5 rows ≈ 500-600 bytes streamed per read.
    let small_read = "SELECT id, payload FROM public.rg_big WHERE id <= 5 ORDER BY id";

    // ---- Window 1: drip small reads until the cumulative budget trips ----
    let mut tripped = false;
    let mut allowed_reads = 0;
    for i in 1..=20 {
        // Advance the clock a little between reads, but stay inside the 60s window
        // (well under 60_000ms) so the window does NOT reset — this is the
        // slow-drip: many small reads spread over time, same window.
        clock.advance(1_000);
        match client.query(small_read, &[]).await {
            Ok(rows) => {
                allowed_reads += 1;
                assert_eq!(rows.len(), 5, "each small read returns 5 rows");
                eprintln!("[ok] drip read #{i} allowed ({} rows)", rows.len());
            }
            Err(e) => {
                let msg = db_msg(&e);
                eprintln!("[ok] drip read #{i} KILLED by cumulative window budget: {msg}");
                assert!(
                    msg.contains("per-window") || msg.contains("slow-drip"),
                    "kill should cite the cumulative per-window budget: {msg}"
                );
                tripped = true;
                break;
            }
        }
    }
    assert!(
        tripped,
        "the cumulative per-window budget MUST trip on the slow drip"
    );
    assert!(
        (1..20).contains(&allowed_reads),
        "some sub-budget reads allowed, then the budget tripped (allowed={allowed_reads})"
    );
    eprintln!("[ok] slow-drip tripped after {allowed_reads} sub-budget reads (≤ B then killed)");

    // The window kill is fail-closed: it terminates the session (the backend was
    // torn down). Reconnect for the window-reset check.
    let client2 = connect_client(addr, &cert_der).await;

    // ---- Window RESET: advance the clock PAST window_secs → a fresh window ----
    // The first read's charge anchored window 1; advancing > 60_000ms rolls it.
    clock.advance(120_000);
    let after_reset = client2
        .query(small_read, &[])
        .await
        .expect("after the window resets, a fresh sub-budget read must be allowed again");
    assert_eq!(after_reset.len(), 5);
    eprintln!(
        "[ok] window reset: a fresh sub-budget read is allowed again ({} rows)",
        after_reset.len()
    );

    // Audit: the cumulative-window kill was recorded with the window reason code.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let chain = sink.lock().unwrap().chain().records().to_vec();
    verify_chain(&chain).expect("audit chain must verify");
    let window_blocks = chain
        .iter()
        .filter(|r| {
            r.payload.decision == Decision::Block && r.payload.reason_code.starts_with("window_")
        })
        .count();
    assert!(
        window_blocks >= 1,
        "the cumulative per-window kill must be audited (got {window_blocks})"
    );
    eprintln!("[ok] audit chain recorded the cumulative-window kill; verify_chain OK");
}
