//! Env-gated **real PG18** integration test for the warden (SPEC §3 layer 2,
//! §4, §10.9; issues #52, #65). Runs only when `PG_BUMPERS_IT=1`, so CI's fast
//! `cargo test` skips it (the crate still builds/links).
//!
//! ```sh
//! # stand up a dedicated throwaway PG18 cluster on a high port (NEVER 5432):
//! PG_BUMPERS_IT=1 cargo test -p pgb-warden --test warden_it -- --nocapture
//! ```
//!
//! By default the test **stands up its own throwaway cluster** on port `54362`
//! (initdb + start + teardown, all under a temp dir) so it is hermetic and
//! never touches the developer's 5432. Override with `PG_BUMPERS_WARDEN_PGURL`
//! to point at an already-running local-stack primary.
//!
//! It proves, against a live server, that the **running, audited** watchdog
//! (#65) — the *same* `PgActivitySource` / `PgKiller` the binary wires, driving
//! the proven `WardenLoop` via `tick_and_audit` against a `PgSink`-backed `_meta`
//! audit chain:
//!
//!  * **detects + terminates** a real agent-tagged runaway (a backend running
//!    `pg_sleep` with the proxy `application_name`) via `pg_terminate_backend`,
//!    and the backend actually disappears;
//!  * **spares** a non-agent backend running the same long `pg_sleep` (no
//!    false-positive kill) — it is still present afterwards;
//!  * **alarms** on a replication slot created against the cluster;
//!  * **trips** the authenticated breaker on the slot/WAL condition; and
//!  * lands **each** of those actions as a record on the `_meta` audit chain
//!    (`WARDEN_TERMINATE` / `SLOT_ALARM` / `BREAKER_TRIP`), which then
//!    **`verify_chain`s** read back from the table — the audited-watchdog
//!    guarantee.

// The whole IT needs the live PG seams + the `_meta` sink, both behind the
// default-on `pg` feature; under `--no-default-features` it compiles to nothing
// (exactly like `pgb-audit`'s `pg_meta_it.rs`).
#![cfg(all(test, feature = "pg"))]

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};

use pgb_audit::pg::PgSink;
use pgb_audit::verify_chain;
// `sink.load_chain_mut()` / `sink.verify_mut()` below are now `Sink` trait
// methods (the audit read-method API moved into the trait); bring `Sink` into
// scope so they resolve on the concrete `PgSink` value.
use pgb_audit::Sink;
use pgb_core::MockClock;
use pgb_warden::{
    PgActivitySource, PgKiller, REASON_BREAKER_TRIP, REASON_SLOT_ALARM, REASON_WARDEN_TERMINATE,
    WardenLoop, WardenThresholds, tick_and_audit,
};

const AGENT_APP_NAME: &str = "pgb_proxy"; // the warden tag (PROXY_APP_NAME)

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn pgbin() -> String {
    std::env::var("PG_BUMPERS_PGBIN")
        .unwrap_or_else(|_| "/opt/homebrew/opt/postgresql@18/bin".to_string())
}

// --------------------------------------------------------------------------
// Throwaway cluster harness — a dedicated high port; NEVER 5432.
// --------------------------------------------------------------------------

struct ThrowawayCluster {
    datadir: std::path::PathBuf,
    port: u16,
    owns: bool, // true if we initdb'd + started it (so we tear it down)
}

impl ThrowawayCluster {
    /// Stand up (or attach to an override) a throwaway PG18 cluster.
    fn up() -> (Self, String) {
        if let Ok(dsn) = std::env::var("PG_BUMPERS_WARDEN_PGURL") {
            // Attach mode: an external local-stack primary. We don't own it.
            return (
                ThrowawayCluster {
                    datadir: std::path::PathBuf::new(),
                    port: 0,
                    owns: false,
                },
                dsn,
            );
        }
        let port: u16 = 54362; // dedicated warden IT port (never 5432)
        let datadir = std::env::temp_dir().join(format!("pgb-warden-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).unwrap();

        let bin = pgbin();
        // initdb (trust auth on loopback so the test connects without a
        // password). The datadir must be empty for initdb, so write nothing
        // into it beforehand.
        let status = Command::new(format!("{bin}/initdb"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-U",
                "postgres",
                "--auth=trust",
                "--no-sync",
            ])
            .status()
            .expect("run initdb");
        assert!(status.success(), "initdb failed");

        // Start the postmaster on the dedicated port, loopback only, with
        // logical replication enabled (so we can create a logical slot).
        let status = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-o",
                &format!(
                    "-p {port} -c listen_addresses=127.0.0.1 -c wal_level=logical \
                     -c max_replication_slots=8 -c max_wal_senders=8 -c unix_socket_directories=''"
                ),
                "-w",
                "-l",
                datadir.join("server.log").to_str().unwrap(),
                "start",
            ])
            .status()
            .expect("run pg_ctl start");
        assert!(status.success(), "pg_ctl start failed");

        let dsn = format!("host=127.0.0.1 port={port} user=postgres dbname=postgres");
        (
            ThrowawayCluster {
                datadir,
                port,
                owns: true,
            },
            dsn,
        )
    }
}

impl Drop for ThrowawayCluster {
    fn drop(&mut self) {
        if !self.owns {
            return;
        }
        let bin = pgbin();
        let _ = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                self.datadir.to_str().unwrap(),
                "-m",
                "immediate",
                "-w",
                "stop",
            ])
            .status();
        let _ = std::fs::remove_dir_all(&self.datadir);
        eprintln!(
            "[warden-it] torn down throwaway cluster on port {} (NEVER touched 5432)",
            self.port
        );
    }
}

/// Apply the canonical audit `_meta` schema (the SAME SQL the rest of the system
/// uses) into the cluster, stripping the psql `\set` meta-command the wire
/// protocol doesn't understand. After this the audit-writer role + the
/// append-only `pgb_audit.audit_log` table exist, and the warden writes its
/// enforcement chain there.
fn apply_audit_schema(admin: &mut Client) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../audit/sql/10_audit_meta.sql"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let sql = raw
        .lines()
        .filter(|l| !l.trim_start().starts_with("\\set"))
        .collect::<Vec<_>>()
        .join("\n");
    admin.batch_execute(&sql).expect("apply audit _meta schema");
}

/// Swap the `user=` (+ add a password) in a keyword/value DSN.
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

/// Spawn a backend that runs a long `pg_sleep` with a given role + app_name,
/// returning its pid (read from a side channel) so the test can assert on it.
fn spawn_sleeper(dsn: &str, app_name: &str, label: &str) -> (thread::JoinHandle<()>, i32) {
    let pid = Arc::new(Mutex::new(0i32));
    let pid_w = Arc::clone(&pid);
    let dsn_app = format!("{dsn} application_name={app_name}");
    let handle = thread::spawn(move || {
        let mut c = match Client::connect(&dsn_app, NoTls) {
            Ok(c) => c,
            Err(_) => return,
        };
        let row = c.query_one("SELECT pg_backend_pid()", &[]).unwrap();
        *pid_w.lock().unwrap() = row.get::<_, i32>(0);
        // Long sleep; the warden should terminate the agent-tagged one. The
        // terminate aborts this query (it returns an error) — that's expected.
        let _ = c.batch_execute("SELECT pg_sleep(60)");
    });
    // Wait for the backend to register its pid.
    let start = Instant::now();
    loop {
        {
            let p = *pid.lock().unwrap();
            if p != 0 {
                eprintln!("[warden-it] spawned {label} backend pid={p} app={app_name}");
                return (handle, p);
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{label} sleeper never registered a pid"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Wait until the backend's running query has accrued at least `min_ms`
/// runtime, so the warden's runtime ceiling can be set below it deterministically.
fn wait_for_runtime(admin: &mut Client, pid: i32, min_ms: u64) {
    let start = Instant::now();
    loop {
        let rows = admin
            .query(
                "SELECT coalesce(
                          (extract(epoch FROM (now() - query_start)) * 1000)::bigint, 0)
                   FROM pg_stat_activity WHERE pid = $1 AND state = 'active'",
                &[&pid],
            )
            .unwrap();
        if let Some(r) = rows.first() {
            let ms: i64 = r.get(0);
            if ms as u64 >= min_ms {
                return;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "backend {pid} never reached {min_ms}ms runtime"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn backend_present(admin: &mut Client, pid: i32) -> bool {
    let rows = admin
        .query("SELECT 1 FROM pg_stat_activity WHERE pid = $1", &[&pid])
        .unwrap();
    !rows.is_empty()
}

/// The headline #65 acceptance: the **running, audited** watchdog detects +
/// terminates an agent-tagged runaway, SPAREs a shared session, ALARMs on a
/// replication slot, TRIPs the breaker — and **each** action lands as a record
/// on the `_meta` audit chain, which verifies on read-back.
#[test]
fn warden_terminates_spares_alarms_and_audits_each_action_to_meta() {
    if !it_enabled() {
        eprintln!("[skip] warden_it: set PG_BUMPERS_IT=1 to run against live PG18");
        return;
    }

    let (cluster, dsn) = ThrowawayCluster::up();

    // The warden's admin connections carry `application_name=pgb_warden_admin`
    // so the source excludes them and never targets itself.
    let admin_app_dsn = format!("{dsn} application_name=pgb_warden_admin");
    let mut test_admin = Client::connect(&admin_app_dsn, NoTls).expect("test admin connect");

    // Install the canonical audit `_meta` schema (writer role + append-only
    // table) so the warden can write its enforcement chain to the SAME table the
    // rest of the system uses (#64's unifying anchor will cover these rows).
    apply_audit_schema(&mut test_admin);

    // --- Fixture: a logical replication slot (the slot-exfil / WAL-DoS watch).
    test_admin
        .batch_execute(
            "SELECT pg_create_logical_replication_slot('agent_exfil_slot', 'test_decoding')",
        )
        .expect("create logical slot");

    // --- Spawn two real runaways: one AGENT-TAGGED, one SHARED (non-agent).
    // Both connect as `postgres` (the throwaway cluster has no WALL role); the
    // warden keys on the proxy `application_name` tag, which the agent-tagged
    // one carries and the shared one does not. (In the live system the
    // un-strippable anchor is additionally the `pgb_agent` role.)
    let (agent_handle, agent_pid) = spawn_sleeper(&dsn, AGENT_APP_NAME, "agent-tagged");
    let (shared_handle, shared_pid) = spawn_sleeper(&dsn, "some_shared_app", "shared");

    // Let both queries accrue runtime so a low ceiling classifies them runaway.
    wait_for_runtime(&mut test_admin, agent_pid, 500);
    wait_for_runtime(&mut test_admin, shared_pid, 500);

    // --- Build the SAME live seams the binary wires, the proven WardenLoop, and
    //     a PgSink-backed `_meta` audit chain (appended as the WRITER role —
    //     never the audited principal).
    let source = PgActivitySource::connect(&admin_app_dsn).expect("warden source connect");
    let killer = PgKiller::connect(&admin_app_dsn).expect("warden killer connect");

    // Ceiling 200ms: both runaways exceed it; only the agent-tagged is killed.
    // slot_alarm=1 so ANY retained WAL alarms; lag_trip=1 with the slot present
    // means the slot/WAL ceiling trips the breaker this tick.
    let thresholds = WardenThresholds {
        poll_interval_millis: 1_000,
        max_query_runtime_millis: 200,
        slot_retained_wal_alarm_bytes: 1,
        breaker_lag_trip_bytes: 1_000_000_000, // lag is 0 here; don't trip on lag
        breaker_runaway_trip_count: 99,        // don't trip on volume here
        breaker_cooldown_millis: 5_000,
    };

    let writer_dsn = rewrite_role(&dsn, "pgb_audit_writer", "pgb_audit_writer_dev_pw");
    let mut sink = PgSink::new(Client::connect(&writer_dsn, NoTls).expect("writer connect"));

    let mut wl = WardenLoop::new(source, killer, thresholds);
    // A MockClock for the audit stamp — the cadence + breaker timing read it; the
    // IT exercises one tick, so wall-clock-free stamping is fine and deterministic.
    let clock = MockClock::starting_at(1_700_000_000_000);

    // Drive ONE audited tick: observe → assess → terminate agent-tagged → trip
    // breaker → append every action to `_meta`. (Re-driving tick_and_audit is
    // exactly what `run_loop` does each cadence; the IT runs a single tick.)
    let outcome = tick_and_audit(&mut wl, &mut sink, &clock, "warden-it")
        .expect("tick + audit append to _meta");
    eprintln!(
        "[warden-it] tick outcome: terminated={:?} spared={:?} slot_alarms={:?} breaker_open={}",
        outcome.terminated_pids,
        outcome.spared_non_agent_pids,
        outcome.slot_alarms,
        outcome.breaker_open,
    );

    // --- The deterministic decisions (#52 semantics, unchanged):
    assert!(
        outcome.terminated_pids.contains(&agent_pid),
        "agent-tagged runaway {agent_pid} must be terminated; got {:?}",
        outcome.terminated_pids
    );
    assert!(
        !outcome.terminated_pids.contains(&shared_pid),
        "shared runaway {shared_pid} must NOT be terminated (no false-positive kill)"
    );
    assert!(
        outcome.spared_non_agent_pids.contains(&shared_pid),
        "shared runaway {shared_pid} must be recorded as spared"
    );
    assert!(
        outcome
            .slot_alarms
            .iter()
            .any(|(name, _)| name == "agent_exfil_slot"),
        "replication slot must be detected + alarmed; got {:?}",
        outcome.slot_alarms
    );
    assert!(
        outcome.breaker_open,
        "slot/WAL ceiling must trip the breaker"
    );

    // --- The audited-watchdog guarantee: EACH action landed on the `_meta`
    //     chain, and the persisted chain VERIFIES on read-back.
    let chain = sink.load_chain_mut().expect("load _meta chain");
    let codes: Vec<&str> = chain
        .iter()
        .map(|r| r.payload.reason_code.as_str())
        .collect();
    eprintln!("[warden-it] _meta audit reason codes: {codes:?}");
    assert!(
        codes.contains(&REASON_WARDEN_TERMINATE),
        "the termination must be audited to _meta; got {codes:?}"
    );
    assert!(
        codes.contains(&REASON_SLOT_ALARM),
        "the slot alarm must be audited to _meta; got {codes:?}"
    );
    assert!(
        codes.contains(&REASON_BREAKER_TRIP),
        "the breaker trip must be audited to _meta; got {codes:?}"
    );
    // The terminated agent pid is named in the WARDEN_TERMINATE record.
    assert!(
        chain
            .iter()
            .any(|r| r.payload.reason_code == REASON_WARDEN_TERMINATE
                && r.payload.statement_text.contains(&agent_pid.to_string())),
        "the audited termination must name the agent pid {agent_pid}"
    );
    // The spared shared pid must NOT appear as an action anywhere (a non-event).
    assert!(
        !chain
            .iter()
            .any(|r| r.payload.statement_text.contains(&shared_pid.to_string())),
        "the spared shared pid {shared_pid} must NOT appear in any audit action"
    );
    verify_chain(&chain).expect("the persisted _meta warden chain must verify");
    sink.verify_mut()
        .expect("PgSink read-back verify of _meta chain");
    eprintln!(
        "[warden-it] all {} warden actions audited to _meta; chain VERIFIES",
        chain.len()
    );

    // --- Prove the agent backend is gone and the shared backend survives.
    let start = Instant::now();
    while backend_present(&mut test_admin, agent_pid) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "agent backend {agent_pid} was not terminated"
        );
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("[warden-it] agent backend {agent_pid} terminated ✓");
    assert!(
        backend_present(&mut test_admin, shared_pid),
        "shared backend {shared_pid} must STILL be present (left alone) ✓"
    );
    eprintln!("[warden-it] shared backend {shared_pid} left alone ✓");

    // --- Teardown: terminate the shared sleeper, drop the slot, join threads.
    let _ = test_admin.query("SELECT pg_terminate_backend($1)", &[&shared_pid]);
    let _ = test_admin.batch_execute("SELECT pg_drop_replication_slot('agent_exfil_slot')");
    let _ = agent_handle.join();
    let _ = shared_handle.join();
    drop(cluster); // explicit teardown of the throwaway cluster

    eprintln!(
        "[warden-it] PASS — agent-tagged killed, shared spared, slot alarmed, breaker tripped, \
         each AUDITED to _meta + chain verifies, 5432 untouched"
    );
}
