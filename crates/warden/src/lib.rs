//! pg_bumpers **warden** — the out-of-band watchdog (SPEC §3 layer 2, §4, §10.9).
//!
//! The warden runs *out of band* from the inline proxy: it is the no-app-SPOF
//! backstop that catches what the proxy can't see — slow-drip through the DB,
//! replication-slot exfil / WAL-DoS, and runaway agent sessions. It:
//!
//! 1. **polls** `pg_stat_activity` / `pg_stat_statements` / replication lag /
//!    `pg_replication_slots` on a cadence read from the injected
//!    [`Clock`](pgb_core::Clock) (**mockable** — no wall-clock in tests);
//! 2. **kills only agent-tagged / agent-role sessions** (`pg_cancel_backend` /
//!    `pg_terminate_backend`) — *never* shared-role backends, so it can't cause
//!    a false-positive outage; the agent **cannot strip its warden tag** because
//!    the un-strippable anchor is the DB **role identity**, not a mutable
//!    `application_name`;
//! 3. owns the **authenticated circuit breaker** (warden→proxy, modelled on the
//!    mTLS channel of SPEC §10.9): its state is **not forgeable** by the agent /
//!    operator principal, it trips on a `policy.yaml` threshold (lag / slot-WAL /
//!    runaway volume), and it has a clock-driven recovery path.
//!
//! ## Module map
//! - [`model`] — DB-free observation types ([`Backend`], [`ReplicationSlot`],
//!   [`Observation`]) + the targeting predicate / tag-strip invariant.
//! - [`thresholds`] — the `warden:` section of `policy.yaml`
//!   ([`WardenThresholds`]): kill criteria, slot/WAL ceilings, breaker trips.
//! - [`breaker`] — the authenticated, non-forgeable [`CircuitBreaker`].
//! - [`poller`] — the pure [`assess`](poller::assess) decision + the
//!   clock-driven [`WardenLoop`] over the [`ActivitySource`](poller::ActivitySource)
//!   / [`Killer`](poller::Killer) seams.
//!
//! As of S5 (#65) the binary **runs**: [`run::run_loop`] drives this loop over a
//! live [`PgActivitySource`](run::PgActivitySource) / [`PgKiller`](run::PgKiller)
//! on a [`SystemClock`](pgb_core::SystemClock) cadence and **audits** every
//! action (`WARDEN_TERMINATE` / `BREAKER_TRIP` / `SLOT_ALARM`) to the `_meta`
//! chain (see [`run`] and `docs/spec/SPEC.amendments.md` §S5).
//!
//! ## Recovery runbook (SPEC §10.9, breaker recovery)
//! When the breaker is **Open**, the proxy is *intended* to shed agent traffic.
//! The warden now *trips and audits* the breaker (S5, #65), but the **proxy-side
//! wiring that consumes this state to actually shed traffic is still deferred**
//! (#52 authorized the deferral; no running proxy reads it yet — see
//! `docs/spec/SPEC.amendments.md` §S5). After `breaker_cooldown_millis` the
//! warden moves it to **HalfOpen** and probes recovery; a healthy probe
//! **Closes** it, a failed one re-**Opens** it with a fresh cooldown. Only the
//! warden principal (holding the unforgeable
//! [`WardenCredential`](breaker::WardenCredential)) can drive these transitions —
//! an operator cannot manually force the authenticated state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod breaker;
pub mod model;
pub mod poller;
pub mod run;
pub mod thresholds;

pub use breaker::{
    BreakerState, CircuitBreaker, ForgeryRejected, Principal, TripReason, WardenCredential,
};
pub use model::{
    AGENT_ROLE, Backend, Observation, PROXY_APP_NAME, ReplicationSlot, tag_is_strippable_for,
};
pub use poller::{ActivitySource, Assessment, Killer, TickOutcome, WardenLoop, assess};
#[cfg(feature = "pg")]
pub use run::{PgActivitySource, PgKiller};
pub use run::{
    REASON_BREAKER_TRIP, REASON_SLOT_ALARM, REASON_WARDEN_TERMINATE, WARDEN_AUDIT_ROLE,
    WardenSettings, action_count, audit_entries_for, format_tick_log, kv_dsn,
    load_thresholds_fail_closed, run_loop, tick_and_audit,
};
pub use thresholds::{ThresholdError, WardenThresholds};
