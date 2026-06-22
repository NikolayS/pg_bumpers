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
//! ## Recovery runbook (SPEC §10.9, breaker recovery)
//! When the breaker is **Open**, the proxy is *intended* to shed agent traffic
//! (the proxy-side wiring that consumes this breaker state is **deferred** —
//! #52 authorized the deferral; the breaker is a warden-side state machine only
//! in S4, see `docs/spec/SPEC.amendments.md` §S4). After
//! `breaker_cooldown_millis` the warden moves it to **HalfOpen** and probes
//! recovery; a healthy probe **Closes** it, a failed one re-**Opens** it with a
//! fresh cooldown. Only the warden principal (holding the unforgeable
//! [`WardenCredential`](breaker::WardenCredential)) can drive these transitions —
//! an operator cannot manually force the authenticated state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod breaker;
pub mod model;
pub mod poller;
pub mod thresholds;

pub use breaker::{
    BreakerState, CircuitBreaker, ForgeryRejected, Principal, TripReason, WardenCredential,
};
pub use model::{
    tag_is_strippable_for, Backend, Observation, ReplicationSlot, AGENT_ROLE, PROXY_APP_NAME,
};
pub use poller::{assess, ActivitySource, Assessment, Killer, TickOutcome, WardenLoop};
pub use thresholds::{ThresholdError, WardenThresholds};
