//! Env-gated **real PG18** end-to-end test for the EPIC #83 PR3 WRITE PATH: a REAL
//! MCP client drives `PgBumpersMcp` whose write tools execute THROUGH the live
//! `pgb-applyd` Unix-socket daemon (the grant-gated §4 floor) in front of PG18 —
//! NOT a fake, NOT raw PG. This is the honesty bar the founder set: a write must
//! genuinely traverse `pgb-mcp → applyd-socket → guarded_apply_with_grant → PG18`,
//! proven by reading the actual committed rows back.
//!
//! Runs only when `PG_BUMPERS_IT=1`, so CI's fast `cargo test` skips it (the crate
//! still builds/links). ⚠️ NEVER touches :5432 — it stands up a THROWAWAY PG18 on
//! a dedicated high port (default 54360), with a clean teardown.
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-mcp --test write_path_e2e -- --nocapture --test-threads=1
//! ```
//!
//! What it proves end-to-end, driving the SHIPPED `PgBumpersMcp` handler over the
//! SAME duplex transport the stdio binary uses, with a REAL `pgb-applyd`:
//!   * the catalog stays **nine** tools (no `approve` tool — the signing-key hop
//!     stays out of the agent stdio);
//!   * a **structural** op (DROP/TRUNCATE) and a **steerable predicate**
//!     (`UPDATE … FROM` / `WHERE status=…`) → **REFUSED** (`NOT_REHEARSABLE`, the
//!     predicate gate / certify), recorded on the `_meta` chain;
//!   * a supported single-int-PK write (`WHERE id % 2 = 0`): `dry_run` bounds it;
//!     `apply_write` WITHOUT a grant → `APPROVAL_REQUIRED`; the operator `approve`
//!     (OUT-of-band over the socket, carrying the signing key) → `apply_write`
//!     **commits a bounded write** (the even rows change, the odd rows do not),
//!     reported reversible — the rows are read back from PG18 to prove it;
//!   * an **over-cap** write (magnitude drift past the approved cap) → `BLAST_DRIFT`
//!     abort, **no mutation** (the row count is unchanged);
//!   * `apply_write` without a matching `confirm_rows` → blocked
//!     (`CONFIRM_REQUIRED` at the MCP forcing function, `CONFIRM_MISMATCH` at
//!     applyd) — the forcing function holds;
//!   * **injection-via-data** in a statement comment cannot widen capability;
//!   * `get_audit` → the actions on the ONE anchored `_meta` chain.

#![cfg(test)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use postgres::{Client, NoTls};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;

use pgb_mcp::{ApplydClient, ApplydConfig, AuditConfig, AuditReader, PgBumpersMcp};

const ROLE: &str = "app_writer";
const SESSION: &str = "mcp-write-e2e";
const AUDIT_SIGNING_KEY: &str = "mcp-write-e2e-signing-key-0001";

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// =============================================================================
//  Throwaway PG18 cluster (⚠️ NEVER 5432) — initdb + pg_ctl on a dedicated high
//  port, with a clean teardown. Mirrors the deploy convention (high port, local).
// =============================================================================

/// A throwaway PG18 instance: its own data dir + a dedicated high port, dropped on
/// teardown. The bin dir comes from `PG_BUMPERS_PG_BINDIR` (default the Homebrew
/// PG18 path the env documents); the port from `PG_BUMPERS_PRIMARY_PORT` (54360).
struct Pg {
    datadir: PathBuf,
    port: u16,
    bindir: PathBuf,
}

impl Pg {
    fn bindir() -> PathBuf {
        PathBuf::from(
            std::env::var("PG_BUMPERS_PG_BINDIR")
                .unwrap_or_else(|_| "/opt/homebrew/opt/postgresql@18/bin".to_string()),
        )
    }

    fn port() -> u16 {
        std::env::var("PG_BUMPERS_PRIMARY_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(54360)
    }

    /// initdb a fresh cluster + start it on the dedicated port (listening only on
    /// 127.0.0.1; ⚠️ never 5432). Trust auth so the test connects without a password.
    fn start() -> Pg {
        let bindir = Self::bindir();
        let port = Self::port();
        assert_ne!(port, 5432, "the e2e must NEVER use :5432");
        let datadir =
            std::env::temp_dir().join(format!("pgb-mcp-write-e2e-{}-{port}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("create datadir");

        // initdb (trust auth locally; this is a throwaway cluster).
        let out = Command::new(bindir.join("initdb"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-A",
                "trust",
                "-U",
                "postgres",
            ])
            .output()
            .expect("run initdb");
        assert!(
            out.status.success(),
            "initdb failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Start: 127.0.0.1 only, the dedicated port, no unix-socket dir collisions.
        let sockdir = datadir.join("sock");
        std::fs::create_dir_all(&sockdir).unwrap();
        let logfile = datadir.join("pg.log");
        let opts = format!(
            "-c listen_addresses=127.0.0.1 -c port={port} -c unix_socket_directories={}",
            sockdir.display()
        );
        let out = Command::new(bindir.join("pg_ctl"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-l",
                logfile.to_str().unwrap(),
                "-o",
                &opts,
                "-w",
                "-t",
                "30",
                "start",
            ])
            .output()
            .expect("run pg_ctl start");
        assert!(
            out.status.success(),
            "pg_ctl start failed: {}\n--- pg.log ---\n{}",
            String::from_utf8_lossy(&out.stderr),
            std::fs::read_to_string(&logfile).unwrap_or_default()
        );

        let pg = Pg {
            datadir,
            port,
            bindir,
        };
        // Wait for accept.
        for _ in 0..100 {
            if Client::connect(&pg.admin_dsn(), NoTls).is_ok() {
                return pg;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("throwaway PG18 never accepted connections on port {port}");
    }

    fn admin_dsn(&self) -> String {
        format!(
            "host=127.0.0.1 port={} user=postgres dbname=postgres connect_timeout=2",
            self.port
        )
    }
}

impl Drop for Pg {
    fn drop(&mut self) {
        // Best-effort stop (immediate) + remove the data dir. Never touches 5432.
        let _ = Command::new(self.bindir.join("pg_ctl"))
            .args([
                "-D",
                self.datadir.to_str().unwrap(),
                "-m",
                "immediate",
                "stop",
            ])
            .output();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

// =============================================================================
//  Fixtures: the `_meta` audit chain schema + a seeded accounts table (single-int
//  PK), an `orders` table with a `status` column (the steerable-predicate target).
// =============================================================================

const SEED_SQL: &str = r#"
    CREATE TABLE public.accounts (
        id       int    PRIMARY KEY,
        owner    text   NOT NULL,
        balance  bigint NOT NULL
    );
    INSERT INTO public.accounts(id, owner, balance)
    SELECT g, 'owner-' || g, (g * 1000)::bigint
    FROM generate_series(1, 8) AS g;

    CREATE TABLE public.orders (
        id      int  PRIMARY KEY,
        status  text NOT NULL
    );
    INSERT INTO public.orders(id, status)
    SELECT g, CASE WHEN g % 2 = 0 THEN 'open' ELSE 'closed' END
    FROM generate_series(1, 6) AS g;
"#;

fn apply_meta_schema(dsn: &str) {
    let mut c = Client::connect(dsn, NoTls).expect("meta schema connect");
    // The canonical `_meta` schema (writer role + append-only chain table). Strip
    // psql meta-commands the simple-protocol batch path rejects.
    let sql =
        std::fs::read_to_string("../audit/sql/10_audit_meta.sql").expect("read 10_audit_meta.sql");
    let stripped: String = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    c.batch_execute(&stripped).expect("apply _meta schema");
}

fn read_accounts(dsn: &str) -> BTreeMap<i32, i64> {
    let mut c = Client::connect(dsn, NoTls).expect("read connect");
    c.query("SELECT id, balance FROM public.accounts ORDER BY id", &[])
        .expect("read accounts")
        .iter()
        .map(|r| (r.get::<_, i32>(0), r.get::<_, i64>(1)))
        .collect()
}

fn count_accounts(dsn: &str) -> i64 {
    let mut c = Client::connect(dsn, NoTls).expect("count connect");
    c.query_one("SELECT count(*) FROM public.accounts", &[])
        .unwrap()
        .get(0)
}

// =============================================================================
//  The real pgb-applyd daemon over its Unix socket.
// =============================================================================

/// Locate the built `pgb-applyd` binary. `CARGO_BIN_EXE_pgb-applyd` is NOT set for
/// a test in a DIFFERENT crate, so we derive it from the test executable's own
/// directory (cargo lays all workspace binaries side-by-side in `target/<profile>`,
/// and the integration-test binary lives in `target/<profile>/deps`). An explicit
/// `PGB_APPLYD_BIN` override wins. Fail loudly if it cannot be found (the dev-dep on
/// `pgb-applyd` guarantees cargo built it before this test ran).
fn applyd_bin_path() -> PathBuf {
    if let Ok(p) = std::env::var("PGB_APPLYD_BIN") {
        return PathBuf::from(p);
    }
    // The current test exe: …/target/<profile>/deps/write_path_e2e-<hash>.
    let exe = std::env::current_exe().expect("current_exe");
    // Walk up to the profile dir (parent of `deps`).
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile> dir");
    let candidate = profile_dir.join("pgb-applyd");
    if candidate.exists() {
        return candidate;
    }
    // Fallback: also check the `deps` dir itself.
    let in_deps = exe.parent().unwrap().join("pgb-applyd");
    if in_deps.exists() {
        return in_deps;
    }
    panic!(
        "could not find the pgb-applyd binary near {} (set PGB_APPLYD_BIN). \
         Run `cargo build -p pgb-applyd` first.",
        profile_dir.display()
    );
}

/// A running `pgb-applyd` child bound to a throwaway socket. Killed on teardown.
struct Applyd {
    child: Child,
    socket: PathBuf,
    statedir: PathBuf,
    anchor: PathBuf,
}

impl Applyd {
    /// Spawn the REAL `pgb-applyd` binary (cargo built it: CARGO_BIN_EXE_pgb-applyd)
    /// against the seeded DB. `approver_pubkey_hex` is the apply-time trust root.
    fn start(port: u16, dbname: &str, approver_pubkey_hex: &str) -> Applyd {
        let tag = std::process::id();
        let statedir = std::env::temp_dir().join(format!("pgb-mcp-applyd-{tag}-{port}"));
        let _ = std::fs::remove_dir_all(&statedir);
        std::fs::create_dir_all(&statedir).unwrap();
        let socket = statedir.join("applyd.sock");
        let anchor = statedir.join("anchor.worm");

        // The seeded DB is the `_meta` chain DB too (the IT convention).
        let meta_dsn = format!("host=127.0.0.1 port={port} dbname={dbname} user=postgres");

        let bin = applyd_bin_path();
        let child = Command::new(&bin)
            .env("PGB_APPLYD_SOCKET", &socket)
            .env("PGB_APPROVER_PUBKEY", approver_pubkey_hex)
            .env("PGB_POLICY_PATH", "../policy/policy.example.yaml")
            .env("PGB_META_DSN", &meta_dsn)
            .env("PGB_AUDIT_SIGNING_KEY", AUDIT_SIGNING_KEY)
            .env("PGB_ANCHOR_PATH", &anchor)
            .env("PGB_ANCHOR_INTERVAL_MS", "60000")
            // applyd OWNS the anchor here (single anchorer over this throwaway chain).
            .env("PGB_ANCHOR_ROLE", "owner")
            .env("PGB_BACKEND_HOST", "127.0.0.1")
            .env("PGB_BACKEND_PORT", port.to_string())
            .env("PGB_BACKEND_DB", dbname)
            .env("PGB_BACKEND_ROLE", "postgres")
            .env("PGB_BACKEND_PASSWORD", "unused-trust-auth")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pgb-applyd");

        let mut me = Applyd {
            child,
            socket,
            statedir,
            anchor,
        };
        // Wait for the socket to come up (binary binds it after the audit boot).
        for _ in 0..150 {
            if me.socket.exists() && UnixStream::connect(&me.socket).is_ok() {
                return me;
            }
            if let Ok(Some(status)) = me.child.try_wait() {
                let mut err = String::new();
                if let Some(mut s) = me.child.stderr.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut err);
                }
                panic!("pgb-applyd exited early ({status}):\n{err}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut err = String::new();
        if let Some(mut s) = me.child.stderr.take() {
            use std::io::Read;
            let _ = s.read_to_string(&mut err);
        }
        let _ = me.child.kill();
        panic!("pgb-applyd socket never appeared:\n{err}");
    }

    fn socket_path(&self) -> String {
        self.socket.to_string_lossy().to_string()
    }
}

impl Drop for Applyd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.statedir);
        let _ = std::fs::remove_file(&self.anchor);
    }
}

// =============================================================================
//  An Ed25519 approver keypair (the apply-time trust root). Generated in-test.
// =============================================================================

/// Returns `(seed_hex, pubkey_hex)` for a fresh Ed25519 approver keypair.
fn approver_keypair() -> (String, String) {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    (
        hex::encode(sk.to_bytes()),
        hex::encode(sk.verifying_key().to_bytes()),
    )
}

// =============================================================================
//  The MCP client harness.
// =============================================================================

/// Build the SHIPPED `PgBumpersMcp` handler with the applyd client (pointed at the
/// real daemon socket) + the `_meta` audit reader (so `get_audit` reads the chain).
fn build_server(socket_path: &str, meta_dsn: &str) -> PgBumpersMcp {
    let applyd = ApplydClient::new(ApplydConfig {
        socket_path: socket_path.to_string(),
        role: ROLE.to_string(),
        session_id: SESSION.to_string(),
        timeout_ms: 30_000,
    });
    let audit = AuditReader::new(AuditConfig {
        dsn: meta_dsn.to_string(),
    });
    PgBumpersMcp::new(ROLE, SESSION)
        .with_applyd(applyd)
        .with_audit(audit)
}

async fn connect_client(
    server: PgBumpersMcp,
) -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (s_read, s_write) = tokio::io::split(server_io);
    let (c_read, c_write) = tokio::io::split(client_io);
    tokio::spawn(async move {
        if let Ok(running) = server.serve((s_read, s_write)).await {
            let _ = running.waiting().await;
        }
    });
    ().serve((c_read, c_write)).await.expect("client handshake")
}

/// Call a tool with a JSON args object; return its `structuredContent`.
async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::service::RoleClient, ()>,
    tool: &'static str,
    args: serde_json::Value,
) -> serde_json::Value {
    let map = match args {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    let res = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await
        .expect("tool call transport ok");
    res.structured_content.expect("structuredContent")
}

// =============================================================================
//  The marquee end-to-end write-path test.
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_writes_traverse_the_live_applyd_floor_refuse_bound_approve_commit_overcap_abort() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BUMPERS_IT=1 (PG18 in PATH) for the MCP write-path e2e through applyd"
        );
        return;
    }

    // ---- stand up a THROWAWAY PG18 (NEVER 5432) + seed + the _meta chain ----
    let pg = tokio::task::spawn_blocking(Pg::start)
        .await
        .expect("pg start thread");
    let port = pg.port;
    let dbname = "postgres";
    let dsn = format!("host=127.0.0.1 port={port} user=postgres dbname={dbname}");
    {
        let dsn = dsn.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = Client::connect(&dsn, NoTls).expect("seed connect");
            c.batch_execute(SEED_SQL).expect("seed");
            apply_meta_schema(&dsn);
        })
        .await
        .expect("seed thread");
    }

    // ---- the Ed25519 approver keypair (the apply-time trust root) ----
    let (seed_hex, pubkey_hex) = approver_keypair();

    // ---- launch the REAL pgb-applyd daemon over its socket ----
    let applyd = {
        let pubkey = pubkey_hex.clone();
        let dbname = dbname.to_string();
        tokio::task::spawn_blocking(move || Applyd::start(port, &dbname, &pubkey))
            .await
            .expect("applyd start thread")
    };
    let socket_path = applyd.socket_path();

    // ---- the SHIPPED MCP server + a REAL MCP client over the duplex pipe ----
    let server = build_server(&socket_path, &dsn);
    let client = connect_client(server).await;

    // ---- 0. the catalog stays nine; NO approve tool ----
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 9, "the §4 catalog is nine tools");
    assert!(
        !tools.iter().any(|t| t.name == "approve"),
        "the signing-key approve hop is NOT an MCP tool"
    );
    eprintln!(
        "[ok] tools/list → 9 tools; no `approve` tool (signing key stays out of agent stdio)"
    );

    // ---- 1a. a STRUCTURAL op (DROP) → NOT_REHEARSABLE, refused at propose ----
    let drop_refused = call_tool(
        &client,
        "propose_write",
        serde_json::json!({ "sql": "DROP TABLE public.accounts" }),
    )
    .await;
    assert_eq!(
        drop_refused["code"],
        serde_json::json!("NOT_REHEARSABLE"),
        "a DROP is refused (structural): {drop_refused}"
    );
    assert_eq!(drop_refused["status"], serde_json::json!("blocked"));
    eprintln!("[ok] propose_write(DROP TABLE) → NOT_REHEARSABLE (structural refusal)");

    // ---- 1b. a TRUNCATE → NOT_REHEARSABLE ----
    let trunc_refused = call_tool(
        &client,
        "propose_write",
        serde_json::json!({ "sql": "TRUNCATE public.accounts" }),
    )
    .await;
    assert_eq!(
        trunc_refused["code"],
        serde_json::json!("NOT_REHEARSABLE"),
        "a TRUNCATE is refused: {trunc_refused}"
    );
    eprintln!("[ok] propose_write(TRUNCATE) → NOT_REHEARSABLE");

    // ---- 1c. a STEERABLE predicate (UPDATE … FROM join-correlation) → refused ----
    // The self-determined-predicate gate (EPIC #91): a grant-bound WHERE may
    // reference only the immutable PK + literals; a join-correlated UPDATE…FROM is
    // refused. propose classifies the shape; the refusal surfaces at propose or
    // dry_run depending on where the gate fires — assert it is refused, not applied.
    let steer = call_tool(
        &client,
        "propose_write",
        serde_json::json!({
            "sql": "UPDATE public.accounts a SET balance = 0 FROM public.orders o WHERE a.id = o.id"
        }),
    )
    .await;
    let steer_blocked_at_propose = steer["status"] == serde_json::json!("blocked");
    if steer_blocked_at_propose {
        assert_eq!(
            steer["code"],
            serde_json::json!("NOT_REHEARSABLE"),
            "a join-correlated UPDATE…FROM is refused: {steer}"
        );
        eprintln!(
            "[ok] propose_write(UPDATE…FROM) → NOT_REHEARSABLE (steerable predicate, at propose)"
        );
    } else {
        // It minted a proposal; the gate must refuse at dry_run instead.
        let pid = steer["proposal_id"]
            .as_str()
            .expect("proposal_id")
            .to_string();
        let dr = call_tool(
            &client,
            "dry_run",
            serde_json::json!({ "proposal_id": pid }),
        )
        .await;
        assert_eq!(
            dr["code"],
            serde_json::json!("NOT_REHEARSABLE"),
            "a join-correlated UPDATE…FROM is refused at dry_run: {dr}"
        );
        eprintln!("[ok] dry_run(UPDATE…FROM) → NOT_REHEARSABLE (steerable predicate, at dry_run)");
    }

    // ---- 2. a SUPPORTED single-int-PK write: propose → dry_run bounds it ----
    let before = tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || read_accounts(&dsn)
    })
    .await
    .unwrap();
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    let proposed = call_tool(
        &client,
        "propose_write",
        serde_json::json!({ "sql": forward, "expected_rows": 4 }),
    )
    .await;
    assert_eq!(
        proposed["status"],
        serde_json::json!("ok"),
        "propose: {proposed}"
    );
    let proposal_id = proposed["proposal_id"]
        .as_str()
        .expect("proposal_id")
        .to_string();
    eprintln!("[ok] propose_write(UPDATE … WHERE id%2=0) → proposal {proposal_id}");

    let dry = call_tool(
        &client,
        "dry_run",
        serde_json::json!({ "proposal_id": proposal_id }),
    )
    .await;
    assert_eq!(dry["status"], serde_json::json!("ok"), "dry_run: {dry}");
    let total_rows = dry["blast_radius"]["total_rows"]
        .as_u64()
        .expect("total_rows");
    assert_eq!(
        total_rows, 4,
        "dry_run bounds the even rows {{2,4,6,8}}: {dry}"
    );
    assert_eq!(
        dry["blast_radius"]["reversible"],
        serde_json::json!(true),
        "the UPDATE is reversible (pre-image captured): {dry}"
    );
    // The RiskEngine stub verdict is captured/logged only — Allow, never teeth.
    assert_eq!(dry["risk"]["verdict"], serde_json::json!("ALLOW"));
    let confirm_token = dry["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();
    eprintln!("[ok] dry_run → bounded to {total_rows} rows, reversible; risk=ALLOW (logged-only)");

    // ---- 3. apply_write WITHOUT confirm_rows → CONFIRM_REQUIRED (forcing fn) ----
    let no_confirm = call_tool(
        &client,
        "apply_write",
        serde_json::json!({ "proposal_id": proposal_id }),
    )
    .await;
    assert_eq!(
        no_confirm["code"],
        serde_json::json!("CONFIRM_REQUIRED"),
        "apply without confirm_rows is blocked: {no_confirm}"
    );
    // A MISMATCHED confirm_rows → CONFIRM_MISMATCH at applyd (defense in depth).
    let bad_confirm = call_tool(
        &client,
        "apply_write",
        serde_json::json!({ "proposal_id": proposal_id, "confirm_rows": 999 }),
    )
    .await;
    assert_eq!(
        bad_confirm["code"],
        serde_json::json!("CONFIRM_MISMATCH"),
        "a wrong confirm_rows is refused by applyd: {bad_confirm}"
    );
    eprintln!(
        "[ok] apply_write forcing function: missing→CONFIRM_REQUIRED, wrong→CONFIRM_MISMATCH"
    );

    // ---- 4. apply_write WITHOUT a grant → APPROVAL_REQUIRED, no mutation ----
    let no_grant = call_tool(
        &client,
        "apply_write",
        serde_json::json!({
            "proposal_id": proposal_id,
            "confirm_rows": total_rows,
            "confirm_token": confirm_token,
        }),
    )
    .await;
    assert_eq!(
        no_grant["code"],
        serde_json::json!("APPROVAL_REQUIRED"),
        "apply without a grant is blocked pending approval: {no_grant}"
    );
    assert_eq!(no_grant["retryable"], serde_json::json!(true));
    let mid = tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || read_accounts(&dsn)
    })
    .await
    .unwrap();
    assert_eq!(before, mid, "no mutation before approval");
    eprintln!("[ok] apply_write (no grant) → APPROVAL_REQUIRED; no mutation");

    // ---- 5. request_elevation → APPROVAL_REQUIRED ticket + disclosures ----
    let elev = call_tool(
        &client,
        "request_elevation",
        serde_json::json!({ "proposal_id": proposal_id, "reason": "zero the even balances" }),
    )
    .await;
    assert_eq!(elev["status"], serde_json::json!("ok"), "elevation: {elev}");
    let request_id = elev["request_id"].as_str().expect("request_id").to_string();
    // The §14.2 disclosures the human reviews (the suggested absolute cap).
    let cap_max_rows = elev["cap_max_rows"].as_u64().expect("cap_max_rows");
    assert!(
        cap_max_rows >= total_rows,
        "the suggested cap covers the dry-run footprint: {elev}"
    );
    eprintln!(
        "[ok] request_elevation → ticket {request_id}; suggested cap_max_rows={cap_max_rows}"
    );

    // ---- 6. operator approve (OUT-of-band; the signing key never enters the MCP) ----
    tokio::task::spawn_blocking({
        let applyd_socket = socket_path.clone();
        let request_id = request_id.clone();
        let seed_hex = seed_hex.clone();
        move || {
            // Reconnect over the socket as the operator (the signing key hop).
            let op = OperatorSocket {
                socket: PathBuf::from(applyd_socket),
            };
            op.approve(&request_id, &seed_hex, "nonce-approve-1");
        }
    })
    .await
    .unwrap();
    eprintln!(
        "[ok] operator approve (out-of-band over the socket; signing key NOT in agent stdio)"
    );

    // ---- 7. apply_write WITH the grant → COMMITS a bounded, reversible write ----
    let applied = call_tool(
        &client,
        "apply_write",
        serde_json::json!({
            "proposal_id": proposal_id,
            "confirm_rows": total_rows,
            "confirm_token": confirm_token,
        }),
    )
    .await;
    assert_eq!(
        applied["status"],
        serde_json::json!("ok"),
        "apply: {applied}"
    );
    assert_eq!(applied["applied"], serde_json::json!(true));
    assert_eq!(
        applied["reversible"],
        serde_json::json!(true),
        "the committed write is reversible: {applied}"
    );
    // Read the ACTUAL committed rows back from PG18 — the proof the write went
    // through applyd→guarded_apply→PG18, not a fake.
    let after = tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || read_accounts(&dsn)
    })
    .await
    .unwrap();
    for id in [2, 4, 6, 8] {
        assert_eq!(after[&id], 0, "even {id} zeroed by the committed write");
    }
    for id in [1, 3, 5, 7] {
        assert_ne!(after[&id], 0, "odd {id} untouched (bounded)");
        assert_eq!(after[&id], before[&id], "odd {id} unchanged");
    }
    eprintln!(
        "[ok] apply_write (granted) → COMMITTED: even rows zeroed, odd rows untouched (read back from PG18)"
    );

    // ---- 8. an OVER-CAP write → BLAST_DRIFT abort, no mutation ----
    // Approve a DELETE of the even rows, then INSERT many new even rows so the live
    // DELETE's magnitude blows past the approved cap → CapExceeded → BLAST_DRIFT.
    let del_forward = "DELETE FROM public.accounts WHERE id % 2 = 0";
    let del_proposed = call_tool(
        &client,
        "propose_write",
        serde_json::json!({ "sql": del_forward, "expected_rows": 4 }),
    )
    .await;
    let del_pid = del_proposed["proposal_id"]
        .as_str()
        .expect("del proposal_id")
        .to_string();
    let del_dry = call_tool(
        &client,
        "dry_run",
        serde_json::json!({ "proposal_id": del_pid }),
    )
    .await;
    let del_rows = del_dry["blast_radius"]["total_rows"].as_u64().unwrap();
    let del_token = del_dry["confirm_token"].as_str().unwrap().to_string();
    let del_elev = call_tool(
        &client,
        "request_elevation",
        serde_json::json!({ "proposal_id": del_pid, "reason": "delete even rows" }),
    )
    .await;
    let del_req = del_elev["request_id"].as_str().unwrap().to_string();
    tokio::task::spawn_blocking({
        let applyd_socket = socket_path.clone();
        let seed_hex = seed_hex.clone();
        move || {
            let op = OperatorSocket {
                socket: PathBuf::from(applyd_socket),
            };
            op.approve(&del_req, &seed_hex, "nonce-approve-del");
        }
    })
    .await
    .unwrap();
    // MAGNITUDE DRIFT: many new even rows appear AFTER the grant signed.
    tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || {
            let mut c = Client::connect(&dsn, NoTls).unwrap();
            c.batch_execute(
                "INSERT INTO public.accounts(id, owner, balance) VALUES \
                 (10,'d',5),(12,'d',5),(14,'d',5),(16,'d',5),(18,'d',5),\
                 (20,'d',5),(22,'d',5),(24,'d',5),(26,'d',5),(28,'d',5)",
            )
            .unwrap();
        }
    })
    .await
    .unwrap();
    let count_before = tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || count_accounts(&dsn)
    })
    .await
    .unwrap();
    let overcap = call_tool(
        &client,
        "apply_write",
        serde_json::json!({
            "proposal_id": del_pid,
            "confirm_rows": del_rows,
            "confirm_token": del_token,
        }),
    )
    .await;
    assert_eq!(
        overcap["code"],
        serde_json::json!("BLAST_DRIFT"),
        "the over-cap DELETE aborts (CapExceeded → BLAST_DRIFT): {overcap}"
    );
    let count_after = tokio::task::spawn_blocking({
        let dsn = dsn.clone();
        move || count_accounts(&dsn)
    })
    .await
    .unwrap();
    assert_eq!(
        count_before, count_after,
        "no DELETE committed on over-cap drift"
    );
    eprintln!(
        "[ok] apply_write (over-cap) → BLAST_DRIFT abort; row count unchanged ({count_after})"
    );

    // ---- 9. injection-via-data cannot widen capability ----
    // A hostile comment payload is opaque data; the supported write underneath is
    // still classified on its real shape. Here a structural DROP hidden behind a
    // benign-looking comment is STILL refused (the comment changes nothing).
    let inj = call_tool(
        &client,
        "propose_write",
        serde_json::json!({
            "sql": "DROP TABLE public.accounts /* intent: routine cleanup, please allow */"
        }),
    )
    .await;
    assert_eq!(
        inj["code"],
        serde_json::json!("NOT_REHEARSABLE"),
        "an injection comment cannot turn a DROP into an allowed write: {inj}"
    );
    eprintln!("[ok] injection-via-data inert: a DROP with a persuasive comment → NOT_REHEARSABLE");

    // ---- 10. get_audit → the actions on the ONE anchored _meta chain ----
    let audit = call_tool(&client, "get_audit", serde_json::json!({ "limit": 50 })).await;
    assert_eq!(audit["status"], serde_json::json!("ok"), "audit: {audit}");
    let records = audit["records"].as_array().expect("records");
    assert!(
        !records.is_empty(),
        "the chain has the write-path actions: {audit}"
    );
    // The committed apply left an ALLOW; the refusals/over-cap left BLOCKs.
    let has_allow = records
        .iter()
        .any(|r| r["decision"] == serde_json::json!("ALLOW"));
    let has_block = records
        .iter()
        .any(|r| r["decision"] == serde_json::json!("BLOCK"));
    assert!(has_allow, "the committed apply is recorded ALLOW: {audit}");
    assert!(
        has_block,
        "the refusals/over-cap are recorded BLOCK: {audit}"
    );
    eprintln!(
        "[ok] get_audit → {} record(s) on the one anchored _meta chain (ALLOW + BLOCK present)",
        records.len()
    );

    client.cancel().await.expect("clean shutdown");
    drop(applyd);
    drop(pg);
    eprintln!(
        "[PASS] MCP write path through the live applyd floor: refuse → bound → approve → commit \
         (bounded+reversible) → over-cap abort; confirm_rows forcing + injection inert; audit chain."
    );
}

/// A bare operator handle to the applyd socket (the signing-key `approve` hop done
/// OUT-of-band — never an MCP tool). Used only by the test driver.
struct OperatorSocket {
    socket: PathBuf,
}

impl OperatorSocket {
    fn approve(&self, request_id: &str, signing_key_hex: &str, nonce: &str) {
        let stream = UnixStream::connect(&self.socket).expect("operator connect");
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9001,
            "method": "approve",
            "params": {
                "request_id": request_id,
                "approver_id": "operator-1",
                "signing_key_hex": signing_key_hex,
                "nonce": nonce,
                "grant_ttl_millis": 120_000u64,
            }
        });
        writeln!(writer, "{req}").unwrap();
        writer.flush().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).expect("approve response");
        assert!(
            resp["error"].is_null(),
            "operator approve must succeed: {resp}"
        );
        assert_eq!(resp["result"]["request_id"], serde_json::json!(request_id));
    }
}
