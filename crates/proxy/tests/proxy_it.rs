//! Env-gated **real PG18** integration test for the proxy (SPEC §5 acceptance,
//! §7 S1; issue #22). Runs only when `PG_BUMPERS_IT=1`, so CI's fast
//! `cargo test` skips it (the crate still builds/links).
//!
//! ```sh
//! deploy/local-stack.sh up
//! PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test proxy_it -- --nocapture
//! deploy/local-stack.sh down
//! ```
//!
//! It stands up the proxy in-process (bound to an ephemeral port), terminating
//! agent connections over **TLS + SCRAM-SHA-256**, originating the backend
//! session as the WALL role `pgb_agent` against the local-stack primary (54321,
//! **never 5432**), and proves end-to-end against a live server:
//!
//!  * a read-only RCA `SELECT` succeeds within budget;
//!  * a large `SELECT` is **cut off** at the byte/row budget (bytes/rows ≤ B);
//!  * **MARQUEE:** `COMMIT; DROP SCHEMA public CASCADE` over simple-query is
//!    **BLOCKED** (extended-protocol-only — statement-stacking defense);
//!  * `UPDATE`/`DELETE`/DDL are **blocked** (read-only gate; the WALL role is
//!    the backstop) and `COPY` is rejected;
//!  * `statement_timeout` **fires** on `pg_sleep` (the classifier blind spot);
//!  * a parse failure **fails closed** (blocked);
//!  * the **audit chain** records allow + blocks/rejects and `verify_chain()`
//!    holds.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use pgb_audit::{Decision, InMemorySink, Sink, verify_chain};
use pgb_core::{Clock, MockClock};
use pgb_policy::{RoleBudget, WindowBudget};
use pgb_proxy::config::{BackendTarget, ProxyConfig, TlsConfig};
use pgb_proxy::{Recorder, serve_connection};
use tokio::net::TcpListener;

const AGENT_USER: &str = "pgb_agent";
const AGENT_PASSWORD: &str = "pgb_agent_dev_pw";

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Extract the server-side message text from a tokio-postgres error (the outer
/// `Display` only says "db error"; the real `ErrorResponse` message is on the
/// `DbError`).
fn db_msg(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

/// Admin DSN (keyword/value) for the local-stack primary. Never 5432.
fn admin_dsn() -> String {
    std::env::var("PG_BUMPERS_PROXY_PGURL")
        .unwrap_or_else(|_| "host=127.0.0.1 port=54321 user=postgres dbname=postgres".to_string())
}

fn backend_host_port_db() -> (String, u16, String) {
    // Parse the admin DSN for host/port/db so the proxy points at the same DB.
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

/// Apply test fixtures as admin: a small whitelisted table + a wide table for
/// the cutoff test, both SELECT-granted to the WALL role.
///
/// Wraps the fixture block in `pg_advisory_xact_lock` with a fixed key so that
/// when the two `#[tokio::test]` cases call this concurrently (parallel test
/// runner) they serialize on the lock rather than racing on
/// `pg_type_typname_nsp_index` (SQLSTATE 23505) during `CREATE TABLE IF NOT
/// EXISTS`. The lock is automatically released at transaction end.
fn setup_fixtures() {
    use postgres::{Client, NoTls};
    let mut admin = Client::connect(&admin_dsn(), NoTls).expect("admin connect");
    // A stable arbitrary advisory-lock key scoped to this fixture.
    // pg_advisory_xact_lock auto-releases when the transaction ends.
    admin
        .batch_execute(
            "BEGIN;
             SELECT pg_advisory_xact_lock(7067626669780000);

             CREATE TABLE IF NOT EXISTS public.rca_read (id int PRIMARY KEY, note text);
             INSERT INTO public.rca_read VALUES (1,'incident-1'),(2,'incident-2'),(3,'incident-3')
               ON CONFLICT (id) DO NOTHING;
             GRANT SELECT ON public.rca_read TO pgb_agent;

             DROP TABLE IF EXISTS public.proxy_wide_read;
             CREATE TABLE public.proxy_wide_read AS
               SELECT g AS id, repeat('x', 200) AS payload FROM generate_series(1, 5000) g;
             GRANT SELECT ON public.proxy_wide_read TO pgb_agent;

             COMMIT;",
        )
        .expect("apply fixtures");
}

/// Generate a self-signed cert/key for the proxy listener; write them to temp
/// PEM files and return their paths plus the cert DER for the client's trust
/// store.
fn make_tls() -> (TlsConfig, Vec<u8>, tempdir::TempPaths) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let der = cert.cert.der().to_vec();

    let dir = std::env::temp_dir().join(format!("pgb-proxy-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (
        TlsConfig {
            cert_pem: cert_path.clone(),
            key_pem: key_path.clone(),
        },
        der,
        tempdir::TempPaths { dir },
    )
}

/// Minimal RAII temp-dir cleanup (avoids an extra dependency).
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

/// Spawn the proxy on an ephemeral port with the given budget + timeout, return
/// the bound address, the shared audit sink, and the client's cert trust DER.
/// Uses the default pinned `search_path`.
async fn spawn_proxy(
    budget: RoleBudget,
    statement_timeout_ms: u64,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<InMemorySink>>,
    Vec<u8>,
    tempdir::TempPaths,
) {
    spawn_proxy_with_search_path(
        budget,
        statement_timeout_ms,
        ProxyConfig::DEFAULT_SEARCH_PATH.to_string(),
    )
    .await
}

/// As [`spawn_proxy`] but lets a test pick the pinned `search_path` (so the
/// search_path-pin IT can assert an explicit, non-default value is enforced).
async fn spawn_proxy_with_search_path(
    budget: RoleBudget,
    statement_timeout_ms: u64,
    search_path: String,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<InMemorySink>>,
    Vec<u8>,
    tempdir::TempPaths,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (tls_cfg, cert_der, paths) = make_tls();
    let (host, port, db) = backend_host_port_db();

    let cfg = Arc::new(ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(tls_cfg.clone()),
        // TLS configured ⇒ TLS REQUIRED (no silent cleartext downgrade).
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
        search_path,
    });

    let sink_inner = Arc::new(Mutex::new(InMemorySink::new()));
    let sink: Arc<Mutex<dyn Sink + Send>> = sink_inner.clone();
    // A MockClock so the audit timestamps are deterministic; the chain order is
    // seq + hash links, not time.
    let clock: Arc<dyn Clock> = Arc::new(MockClock::starting_at(1_700_000_000_000));
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
            let sid = format!("it-conn-{id}");
            tokio::spawn(async move {
                let _ = serve_connection(tcp, cfg, acceptor, recorder, sid).await;
            });
        }
    });

    (addr, sink_inner, cert_der, paths)
}

/// Connect a `tokio-postgres` client to the proxy over TLS (trusting the
/// proxy's self-signed cert) + SCRAM.
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

    // Connect by hostname `localhost` so rustls validates against the cert's
    // `localhost` SAN; the proxy is bound on 127.0.0.1 (loopback resolves there).
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_enforcement_end_to_end_against_pg18() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BUMPERS_IT=1 (+ deploy/local-stack.sh up) to run the PG18 proxy IT"
        );
        return;
    }
    // The synchronous `postgres` admin client cannot run inside the tokio
    // runtime, so set up fixtures on a dedicated OS thread.
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    // A budget tight enough to force a mid-stream cutoff on the wide table:
    // 100 rows OR ~50 KiB. The wide table has 5000 rows of ~200 bytes.
    let budget = RoleBudget {
        max_bytes: 50_000,
        max_rows: 100,
        // Generous EXPLAIN ceiling (cost AND rows): the existing end-to-end cases
        // gate on the byte/row mid-stream cutoff + read-only + timeout, NOT the
        // advisory EXPLAIN gate (which has its own dedicated IT in readgates_it).
        // Critically, max_plan_rows must NOT be coupled to the single-shot
        // max_rows cutoff, or the planner's default estimate for an un-analyzed
        // table would pre-empt the cutoff this test exercises.
        max_plan_cost: 1_000_000_000.0,
        max_plan_rows: 1_000_000_000,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 50_000_000,
            max_rows: 1_000_000,
        },
    };
    // A short statement_timeout so pg_sleep(5) trips it fast.
    let (addr, sink, cert_der, _paths) = spawn_proxy(budget, 1_000).await;

    let client = connect_client(addr, &cert_der).await;

    // ---- 1. Read-only RCA SELECT succeeds (extended protocol) ----
    let rows = client
        .query("SELECT id, note FROM public.rca_read ORDER BY id", &[])
        .await
        .expect("read-only RCA select must succeed");
    assert_eq!(rows.len(), 3, "RCA select returned wrong row count");
    let first: i32 = rows[0].get(0);
    assert_eq!(first, 1);
    eprintln!("[ok] read-only RCA SELECT returned {} rows", rows.len());

    // ---- 2. Large SELECT cut off at the byte/row budget ----
    let big = client
        .query(
            "SELECT id, payload FROM public.proxy_wide_read ORDER BY id",
            &[],
        )
        .await;
    match big {
        Err(e) => {
            // The proxy injects an ErrorResponse mid-stream → the driver errors.
            // The server-message text is on the DbError, not the outer Display.
            let server_msg = e
                .as_db_error()
                .map(|d| d.message().to_string())
                .unwrap_or_else(|| e.to_string());
            eprintln!("[ok] large SELECT cut off: {server_msg}");
            assert!(
                server_msg.contains("cut off") || server_msg.contains("budget"),
                "cutoff error should mention budget: {server_msg}"
            );
        }
        Ok(rows) => {
            // If the driver surfaced the partial rows instead of the error, the
            // count must still be bounded by the row budget.
            assert!(
                rows.len() <= 100,
                "cutoff failed: got {} rows, budget was 100",
                rows.len()
            );
            eprintln!("[ok] large SELECT bounded to {} rows (≤100)", rows.len());
        }
    }

    // ---- 3. MARQUEE: COMMIT; DROP SCHEMA public CASCADE via simple-query BLOCKED ----
    // `batch_execute` sends a simple `Query` ('Q') frame — the statement-stacking
    // vector. The proxy must reject it (extended-protocol-only).
    let marquee = client
        .batch_execute("COMMIT; DROP SCHEMA public CASCADE")
        .await;
    let err = marquee.expect_err("COMMIT; DROP SCHEMA must be BLOCKED");
    let marquee_msg = db_msg(&err);
    eprintln!("[ok] MARQUEE blocked: {marquee_msg}");
    assert!(
        marquee_msg.contains("simple query")
            || marquee_msg.contains("extended")
            || marquee_msg.contains("not permitted"),
        "marquee rejection should explain extended-only: {marquee_msg}"
    );
    // The schema must still exist — prove the DROP never reached the backend.
    let still_there = client
        .query_one(
            "SELECT count(*)::int FROM information_schema.schemata WHERE schema_name = 'public'",
            &[],
        )
        .await
        .expect("schema check select");
    let n: i32 = still_there.get(0);
    assert_eq!(n, 1, "public schema must still exist (DROP was blocked)");
    eprintln!("[ok] public schema intact after blocked DROP");

    // ---- 4. UPDATE / DELETE / DDL blocked; COPY rejected ----
    for sql in [
        "UPDATE public.rca_read SET note = 'x' WHERE id = 1",
        "DELETE FROM public.rca_read WHERE id = 1",
        "CREATE TABLE public.should_not_exist (id int)",
        "DROP TABLE public.rca_read",
    ] {
        let e = client
            .execute(sql, &[])
            .await
            .expect_err(&format!("{sql} must be blocked"));
        eprintln!("[ok] blocked write/DDL `{sql}`: {}", db_msg(&e));
    }
    // COPY (extended-protocol Parse of a COPY statement → classifier blocks it).
    let copy_err = client
        .execute("COPY public.rca_read TO STDOUT", &[])
        .await
        .expect_err("COPY must be rejected/blocked");
    eprintln!("[ok] COPY blocked: {}", db_msg(&copy_err));

    // ---- 5. statement_timeout fires on pg_sleep (classifier blind spot) ----
    let sleep = client.query("SELECT pg_sleep(5)", &[]).await;
    let serr = sleep.expect_err("pg_sleep must hit statement_timeout");
    let smsg = db_msg(&serr);
    eprintln!("[ok] statement_timeout fired on pg_sleep: {smsg}");
    assert!(
        smsg.contains("timeout") || smsg.contains("canceling") || smsg.contains("statement"),
        "expected a timeout cancel: {smsg}"
    );

    // ---- 6. Fail-closed on a parse failure ----
    let bad = client.query("SELEKT * FRM nonsense !!!", &[]).await;
    let berr = bad.expect_err("unparseable SQL must be blocked (fail-closed)");
    eprintln!("[ok] fail-closed on parse failure: {}", db_msg(&berr));

    // The session must still be usable after all the recoverable blocks.
    let alive = client
        .query_one("SELECT 42::int", &[])
        .await
        .expect("session must survive recoverable blocks");
    let v: i32 = alive.get(0);
    assert_eq!(v, 42);
    eprintln!("[ok] session survives recoverable blocks (SELECT 42 → 42)");

    // ---- 7. Audit chain records allow + blocks/rejects and verifies ----
    // Give the proxy a moment to flush the final audit appends.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let chain = sink.lock().unwrap().chain().records().to_vec();
    verify_chain(&chain).expect("audit chain must verify");
    let allows = chain
        .iter()
        .filter(|r| r.payload.decision == Decision::Allow)
        .count();
    let blocks = chain
        .iter()
        .filter(|r| r.payload.decision == Decision::Block)
        .count();
    let rejects = chain
        .iter()
        .filter(|r| r.payload.decision == Decision::Reject)
        .count();
    eprintln!(
        "[ok] audit chain: {} records (allow={allows} block={blocks} reject={rejects}); verify_chain OK",
        chain.len()
    );
    assert!(allows >= 1, "must have recorded at least one ALLOW");
    assert!(blocks >= 1, "must have recorded BLOCKs (read-only/cutoff)");
    assert!(rejects >= 1, "must have recorded the simple-query REJECT");
    // The marquee statement is captured verbatim in the chain.
    assert!(
        chain
            .iter()
            .any(|r| r.payload.statement_text.contains("DROP SCHEMA")),
        "the marquee COMMIT; DROP SCHEMA must be captured in the audit chain"
    );
    eprintln!("[ok] MARQUEE COMMIT; DROP SCHEMA captured verbatim in the audit chain");
}

/// TLS is **required** when configured (no silent cleartext downgrade — review
/// item 1). Proven end-to-end against the live proxy:
///   * `sslmode=disable` (a direct plaintext StartupMessage, no SSLRequest) is
///     **REJECTED** — it never reaches auth/queries;
///   * `sslmode=require` (SSLRequest → TLS upgrade) **works** — a real SELECT
///     succeeds over the encrypted socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_is_required_when_configured() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BUMPERS_IT=1 (+ deploy/local-stack.sh up) for the TLS-required IT"
        );
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    let budget = RoleBudget {
        max_bytes: 50_000,
        max_rows: 100,
        // Generous EXPLAIN ceiling (cost AND rows): the existing end-to-end cases
        // gate on the byte/row mid-stream cutoff + read-only + timeout, NOT the
        // advisory EXPLAIN gate (which has its own dedicated IT in readgates_it).
        // Critically, max_plan_rows must NOT be coupled to the single-shot
        // max_rows cutoff, or the planner's default estimate for an un-analyzed
        // table would pre-empt the cutoff this test exercises.
        max_plan_cost: 1_000_000_000.0,
        max_plan_rows: 1_000_000_000,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 50_000_000,
            max_rows: 1_000_000,
        },
    };
    // The proxy is spawned with TLS configured ⇒ require_tls = true.
    let (addr, _sink, cert_der, _paths) = spawn_proxy(budget, 30_000).await;

    // ---- (a) sslmode=disable is REJECTED (cleartext refused) ----
    // `NoTls` + sslmode=disable ⇒ the driver sends a direct StartupMessage with
    // no SSLRequest; the proxy must refuse it (no cleartext auth path).
    let disable_dsn = format!(
        "host=127.0.0.1 port={} user={} password={} dbname=postgres sslmode=disable",
        addr.port(),
        AGENT_USER,
        AGENT_PASSWORD,
    );
    let disabled = tokio_postgres::connect(&disable_dsn, tokio_postgres::NoTls).await;
    // The Ok variant's Connection isn't Debug, so match rather than expect_err.
    let err = match disabled {
        Ok(_) => panic!("sslmode=disable MUST be rejected when TLS is required"),
        Err(e) => e,
    };
    eprintln!("[ok] sslmode=disable REJECTED (TLS required): {err}");

    // ---- (b) sslmode=require works (TLS upgrade + SCRAM + a real SELECT) ----
    let client = connect_client(addr, &cert_der).await;
    let rows = client
        .query("SELECT id, note FROM public.rca_read ORDER BY id", &[])
        .await
        .expect("sslmode=require must succeed over TLS");
    assert_eq!(rows.len(), 3, "TLS SELECT returned wrong row count");
    eprintln!(
        "[ok] sslmode=require works over TLS: SELECT returned {} rows",
        rows.len()
    );
}

/// A generous budget that never trips the cutoff/EXPLAIN gates — for tests that
/// gate on something other than the budget (e.g. the search_path pin).
fn generous_budget() -> RoleBudget {
    RoleBudget {
        max_bytes: 50_000,
        max_rows: 100,
        max_plan_cost: 1_000_000_000.0,
        max_plan_rows: 1_000_000_000,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 50_000_000,
            max_rows: 1_000_000,
        },
    }
}

/// **search_path PIN (SPEC §3 layer-1 WALL: "search_path pinned"; issue #80
/// gap 1).** The proxy is the AUTHORITATIVE per-session `search_path` pin, set on
/// every brokered backend session BEFORE any agent statement. Proven end-to-end
/// against live PG18:
///
///   * a brokered session's active `search_path` (read via the read-only
///     `current_setting('search_path')` — `SHOW`/`SET` are utility statements the
///     proxy's read-only gate blocks) equals the configured pinned value (the
///     proxy set it — not the agent, not the role-level default);
///   * the agent's own `SET search_path = 'evil'` is itself **blocked** by the
///     read-only gate (it cannot even mutate the session path through the proxy),
///     and — belt to that suspender — a brand-NEW brokered session is re-pinned to
///     the configured value regardless (terminate-and-originate: every brokered
///     backend session is a fresh origination the proxy re-pins).
///
/// RED (no pin wired): `current_setting('search_path')` returns the role-level
/// default `pg_catalog, "public"`, NOT the configured pin → the first assertion
/// fails. GREEN: it equals the pin.
///
/// The pinned value here (`pg_catalog, public, pg_temp`) is deliberately DISTINCT
/// from the role-level pin in `deploy/sql/10_hardened_role.sql`
/// (`pg_catalog, "public"`), so a pass proves the **proxy** pinned it (the
/// role-level GUC alone would yield the two-element value).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_pins_search_path_on_every_brokered_session() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BUMPERS_IT=1 (+ deploy/local-stack.sh up) for the search_path-pin IT"
        );
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    // A pin distinct from the role-level pin so a pass proves the PROXY set it.
    let pinned = "pg_catalog, public, pg_temp".to_string();
    let (addr, _sink, cert_der, _paths) =
        spawn_proxy_with_search_path(generous_budget(), 30_000, pinned.clone()).await;

    // ---- 1. A brokered session's active search_path equals the pinned value ----
    // `current_setting('search_path')` is a plain read-only SELECT (allowed),
    // whereas `SHOW search_path` is a utility statement the read-only gate blocks.
    let client = connect_client(addr, &cert_der).await;
    let observed: String = client
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .expect("current_setting('search_path') must succeed")
        .get(0);
    eprintln!("[search_path] brokered session 1 search_path = {observed:?} (pin {pinned:?})");
    assert_eq!(
        observed, pinned,
        "the brokered session's search_path must equal the proxy pin (got {observed:?}, \
         expected {pinned:?}) — the proxy is the authoritative per-session pin"
    );
    eprintln!("[ok] brokered session search_path is pinned by the proxy");

    // ---- 2a. The agent's own SET search_path='evil' is BLOCKED ----
    // The agent cannot even mutate its session path through the proxy: a
    // `batch_execute` SET goes over the simple-query protocol, which the proxy
    // rejects outright (extended-protocol-only, the statement-stacking defense),
    // and a SET is in any case a non-read utility the read-only gate would block.
    // Either way the agent's `SET` never takes hold — a stronger property than
    // "it doesn't persist".
    let set_err = client
        .batch_execute("SET search_path = 'evil_schema_that_should_not_persist'")
        .await
        .expect_err("agent SET search_path must be blocked by the proxy");
    eprintln!(
        "[ok] agent `SET search_path='evil'` blocked: {}",
        db_msg(&set_err)
    );
    // The session survives the recoverable block and is still on the pin.
    let still_pinned: String = client
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .expect("session survives the blocked SET")
        .get(0);
    assert_eq!(
        still_pinned, pinned,
        "after the blocked SET the session's search_path is unchanged (still the pin)"
    );

    // ---- 2b. A brand-NEW brokered session is re-pinned regardless ----
    // Open a fresh connection through the proxy: a new brokered backend session.
    // It must be re-pinned to the configured value — no agent-chosen path survives.
    let client2 = connect_client(addr, &cert_der).await;
    let after: String = client2
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .expect("current_setting on the fresh brokered session")
        .get(0);
    eprintln!("[search_path] fresh brokered session 2 search_path = {after:?}");
    assert_eq!(
        after, pinned,
        "a fresh brokered session must be re-pinned to {pinned:?} (got {after:?}) — the \
         proxy re-pins every brokered session"
    );
    assert!(
        !after.contains("evil_schema_that_should_not_persist"),
        "the agent's chosen path must NEVER appear in a fresh brokered session"
    );
    eprintln!(
        "[ok] every fresh brokered session is re-pinned by the proxy (no agent path survives)"
    );
}
