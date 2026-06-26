//! pg_bumpers warden binary (SPEC §3 layer 2, §4, §10.9) — a **running, audited**
//! out-of-band watchdog.
//!
//! The warden runs out-of-band from the inline proxy: it polls
//! `pg_stat_activity` / `pg_replication_slots` / replication lag on a
//! [`SystemClock`](pgb_core::SystemClock) cadence (poll 1–5s, SPEC §4), **only**
//! terminates agent-tagged sessions (never shared roles — avoid false-positive
//! outages), owns the authenticated circuit breaker, and **audits every
//! enforcement action** (`WARDEN_TERMINATE` / `BREAKER_TRIP` / `SLOT_ALARM`) to
//! the same `_meta` hash-chained audit log the rest of the system writes
//! (SPEC §3/§4/§10.9).
//!
//! The gating *logic* lives in the `pgb_warden` library — targeting / slot-WAL
//! alarms / the non-forgeable breaker are exhaustively unit-tested on a
//! [`MockClock`](pgb_core::MockClock); the live `PgActivitySource` / `PgKiller` +
//! the `_meta` audit append are proven against real PG18 in the env-gated
//! integration test (`tests/warden_it.rs`). The config assembly + DSN building +
//! fail-closed policy load are unit-tested in the library
//! ([`WardenSettings::resolve`](pgb_warden::WardenSettings),
//! [`load_thresholds_fail_closed`](pgb_warden::load_thresholds_fail_closed)).
//! This `main()` is the thin shell that opens the live connections and drives
//! the loop.
//!
//! ## Configuration (12-factor; fail-closed)
//! - `PGB_POLICY_PATH` — path to `policy.yaml` (the `warden:` section is parsed +
//!   validated; a **present-but-invalid** section makes the binary refuse to
//!   start with a non-zero exit — fail-closed, SPEC §4). The same document's
//!   `primary:` BYO target (SPEC §0.5) supplies the watched host/port/db when the
//!   `PGB_BACKEND_*` env overrides are unset. **Required.**
//! - `PGB_BACKEND_HOST` / `PGB_BACKEND_PORT` / `PGB_BACKEND_DB` — the BYO primary
//!   (SPEC §0.5) to watch. **Overrides** over the `policy.yaml` `primary:` target;
//!   precedence is **env override > policy.yaml `primary:` target > FAIL-CLOSED**.
//!   There is **no** throwaway-cluster default — with neither source the warden
//!   refuses to start (no silent `54321`). **Never** 5432 unless that is the
//!   user's own database.
//! - `PGB_WARDEN_ADMIN_ROLE` / `PGB_WARDEN_ADMIN_PASSWORD` — the admin role the
//!   warden polls + terminates as (password **required**, no literal default).
//! - `PGB_AUDIT_DB` — the `_meta` database holding the audit chain
//!   (default `postgres`).
//! - `PGB_AUDIT_WRITER_ROLE` / `PGB_AUDIT_WRITER_PASSWORD` — the audit-writer role
//!   the warden appends the chain as (NEVER the audited agent role; password
//!   **required**). "The audited cannot write audit" (SPEC §3/§4/§10.9).

// The live watchdog needs the PG seams + the `_meta` sink, both behind the
// default-on `pg` feature. The shipped binary always has it; a
// `--no-default-features` build (the CI feature-matrix) compiles a stub `main`
// that refuses to run a live loop, mirroring `pgb-audit`'s feature gating.
#[cfg(feature = "pg")]
use std::sync::Arc;

#[cfg(feature = "pg")]
use pgb_audit::Sink;
#[cfg(feature = "pg")]
use pgb_audit::pg::PgSink;
#[cfg(feature = "pg")]
use pgb_core::{Clock, SystemClock};
#[cfg(feature = "pg")]
use pgb_policy::PolicyConfig;
#[cfg(feature = "pg")]
use pgb_warden::{
    PgActivitySource, PgKiller, WardenLoop, WardenSettings, load_thresholds_fail_closed, run_loop,
};

#[cfg(feature = "pg")]
fn run() -> Result<(), String> {
    // 1. Fail-closed config load: a missing/unreadable policy file or a
    //    present-but-invalid `warden:` section makes the warden REFUSE to start.
    let policy_path = std::env::var("PGB_POLICY_PATH").map_err(|_| {
        "PGB_POLICY_PATH is required (path to policy.yaml; the `warden:` section is \
         validated fail-closed)"
            .to_string()
    })?;
    let thresholds = load_thresholds_fail_closed(&policy_path)?;

    // The same policy.yaml carries the BYO `primary:` target (SPEC §0.5): the
    // watched host/port/db when the `PGB_BACKEND_*` env overrides are unset. Load
    // the full PolicyConfig (fail-closed) so the warden watches the user's DB, not
    // a throwaway-cluster default.
    let policy = PolicyConfig::load_from_yaml(
        &std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("cannot read policy.yaml `{policy_path}` (fail-closed): {e}"))?,
    )
    .map_err(|e| format!("invalid policy.yaml `{policy_path}` (fail-closed): {e}"))?;

    // 2. Resolve connection settings: env override > policy.yaml `primary:` target >
    //    FAIL-CLOSED (no throwaway-cluster `54321` default), plus the two required
    //    secrets. Then open the live admin + writer connections.
    let settings = WardenSettings::resolve(policy.primary.as_ref(), |k| std::env::var(k).ok())?;
    let source = PgActivitySource::connect(&settings.observe_dsn())?;
    let killer = PgKiller::connect(&settings.observe_dsn())?;

    // The `_meta` audit chain is appended as the audit-WRITER role, never the
    // audited agent role ("the audited cannot write audit", SPEC §10.9).
    let client = postgres::Client::connect(&settings.writer_dsn(), postgres::NoTls)
        .map_err(|e| e.to_string())?;
    let sink: Box<dyn Sink> = Box::new(PgSink::new(client));

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let session_id = format!("warden-{}", std::process::id());

    eprintln!(
        "pgb-warden: live watchdog (SPEC §3/§4/§10.9) — watching {h}:{p}/{bdb} as `{ar}`, \
         auditing to {h}:{p}/{adb} as `{wr}`. poll_interval={}ms runaway_kill={}ms \
         slot_alarm={}B lag_trip={}B runaway_trip={} breaker_cooldown={}ms. Terminating ONLY \
         agent-tagged sessions; shared roles spared. (NEVER 5432.)",
        thresholds.poll_interval_millis,
        thresholds.max_query_runtime_millis,
        thresholds.slot_retained_wal_alarm_bytes,
        thresholds.breaker_lag_trip_bytes,
        thresholds.breaker_runaway_trip_count,
        thresholds.breaker_cooldown_millis,
        h = settings.host,
        p = settings.port,
        bdb = settings.backend_db,
        adb = settings.audit_db,
        ar = settings.admin_role,
        wr = settings.writer_role,
    );

    // 3. Drive the proven WardenLoop over the live seams on the SystemClock
    //    cadence, auditing every action. Never returns Ok under normal operation
    //    (the success type is uninhabited); only a fatal audit/DB error escapes.
    let wl = WardenLoop::new(source, killer, thresholds.clone());
    match run_loop(wl, sink, &thresholds, clock.as_ref(), &session_id) {
        Ok(never) => match never {},
        Err(e) => Err(e),
    }
}

#[cfg(feature = "pg")]
fn main() {
    if let Err(e) = run() {
        eprintln!("pgb-warden: fatal: {e}");
        std::process::exit(1);
    }
}

/// `--no-default-features` stub: without the `pg` feature there is no Postgres
/// client to open a live connection, so the watchdog cannot run. Refuse loudly
/// (fail-closed) rather than pretend to watch.
#[cfg(not(feature = "pg"))]
fn main() {
    eprintln!(
        "pgb-warden: built WITHOUT the `pg` feature — the live watchdog needs the \
         Postgres seams. Rebuild with default features (the shipped binary has them)."
    );
    std::process::exit(1);
}
