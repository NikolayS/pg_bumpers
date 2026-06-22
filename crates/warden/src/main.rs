//! pg_bumpers warden binary (SPEC §3 layer 2, §4, §10.9).
//!
//! The warden runs out-of-band: it polls `pg_stat_activity` /
//! `pg_stat_statements` / replication lag / `pg_replication_slots`, **only**
//! cancels/terminates agent-tagged / agent-role sessions (never shared roles —
//! avoid false-positive outages), and owns the authenticated circuit breaker.
//!
//! The gating *logic* lives in the `pgb_warden` library (and is exhaustively
//! unit-tested with a [`MockClock`](pgb_core::MockClock) and scripted
//! observation/kill seams, plus an env-gated real-PG18 integration test).
//!
//! **Status (S4 — not yet a live watchdog).** This binary's `main()` currently
//! prints and **validates** the conservative threshold config (so a bad
//! `policy.yaml` fails closed) and documents the loop shape; it does **not** run
//! a live polling loop. The live `ActivitySource` (the `pg_stat_activity` /
//! `pg_replication_slots` query) and `Killer` (`pg_terminate_backend`) are
//! implemented and proven against real PG18 only in the env-gated integration
//! test (`tests/warden_it.rs`) — the `postgres` client is a **dev-dependency**,
//! so the shipped binary cannot open a backend connection. Wiring `main()` to
//! drive a real [`WardenLoop`](pgb_warden::WardenLoop) over a `PgActivitySource`
//! / `PgKiller` on a [`SystemClock`](pgb_core::SystemClock) cadence is **deferred
//! to S5** (tracking: #65, the runnable+audited warden; S0/S3 carry-forwards
//! #18). See `docs/spec/SPEC.amendments.md` §S4. Do **not** read this `main` as
//! evidence of a running watchdog.

use pgb_core::{Clock, SystemClock};
use pgb_warden::WardenThresholds;

fn main() {
    // In production the thresholds come from `policy.yaml`; here we surface the
    // conservative defaults + validate them so a bad config fails closed.
    let thresholds = WardenThresholds::default();
    thresholds
        .validate()
        .expect("default warden thresholds must validate");

    let clock = SystemClock::new();
    let _now = clock.monotonic_millis(); // the cadence anchor (read via Clock)

    println!(
        "pgb-warden: out-of-band watchdog (SPEC §3/§4/§10.9) — config validated, \
         live loop NOT running (S4). \
         poll_interval={}ms, runaway_kill={}ms, slot_alarm={}B, lag_trip={}B, \
         runaway_trip={}, breaker_cooldown={}ms. \
         When wired (S5, #65) it will kill agent-tagged/agent-role sessions only \
         and own the authenticated (non-forgeable) circuit breaker; today this \
         binary only validates config. The live ActivitySource/Killer are proven \
         against PG18 in the env-gated integration test, not driven here; gating \
         logic is in the pgb_warden lib (unit + PG18 IT).",
        thresholds.poll_interval_millis,
        thresholds.max_query_runtime_millis,
        thresholds.slot_retained_wal_alarm_bytes,
        thresholds.breaker_lag_trip_bytes,
        thresholds.breaker_runaway_trip_count,
        thresholds.breaker_cooldown_millis,
    );
}
