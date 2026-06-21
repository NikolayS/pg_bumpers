//! # THROWAWAY S0 fidelity-spike harness (issue #8 — 🚦 THE GATE)
//!
//! **This crate is a throwaway spike, NOT production code** (`publish = false`).
//! Its sole job is to red-test, against **real PostgreSQL 18**, the two riskiest
//! assumptions of the whole product *in week 2, not week 10* (SPEC §5, §10.5):
//!
//! 1. **clone↔prod prediction fidelity** — the dry-run's predicted affected-PK
//!    set / total rows equals the actual apply effect, **and any drift is caught**
//!    by the [`pgb_core`] PK-set checksum recomputed inside the apply txn.
//! 2. **typed-inverse restore** — the captured pre-image inverse restores a
//!    **golden prod state** byte-for-byte for the certified op set, with the
//!    documented honest gaps (sequences / trigger side-effects / NOTIFY are *not*
//!    restored).
//!
//! It consumes the **real merged `pgb_core` seams** — [`pgb_core::ApplyBarrier`]
//! ([`pgb_core::ClosureBarrier`] to inject drift between dry-run and apply),
//! [`pgb_core::Clock`]/[`pgb_core::MockClock`] (deterministic staleness/timing),
//! the affected-PK-set checksum
//! ([`pgb_core::PkSetBuilder`]/[`pgb_core::PkChecksum`], composite + PK-less
//! refused), the typed-inverse format
//! ([`pgb_core::InverseKind`]/[`pgb_core::InversePlan`]), and the default-deny
//! certified action set ([`pgb_core::certify`]).
//!
//! ## §10.5 binary pass criteria (the gate)
//! - **(a)** no-drift apply: dry-run `pk_set_checksum` **==** apply-time checksum
//!   (exact); predicted `total_rows` **==** actual (delta 0).
//! - **(b)** typed-inverse restores the golden prod state byte-for-byte for the
//!   certified op set; sequences / trigger-side-effects / NOTIFY are **asserted
//!   NOT restored** (the documented gaps).
//! - **(c)** reject any clone whose `staleness_lsn_bytes` exceeds a configured
//!   ceiling.
//!
//! The DB-touching logic lives in [`harness`]; the **independent** golden-state
//! differ lives in [`differ`] and shares no code with the inverse-under-test
//! (avoids circularity — SPEC §10.6). The env-gated integration tests in
//! `tests/` orchestrate the spike flow and assert (a)(b)(c) + the five drift
//! tests.

#![forbid(unsafe_code)]

pub mod differ;
pub mod harness;

/// Environment variable that gates the DB-touching integration tests.
///
/// CI's fast `cargo test` job runs with this **unset**, so the integration
/// tests skip (and the crate still compiles). Set `PG_BUMPERS_IT=1` to run the
/// spike against a live PG18 cluster.
pub const IT_ENV: &str = "PG_BUMPERS_IT";

/// Default libpq connection string for the throwaway PG18 cluster on port 55431.
///
/// Overridable via the `PG_BUMPERS_PGURL` env var. **Never** points at the
/// founder's 5432 cluster.
pub const DEFAULT_PGURL: &str = "host=127.0.0.1 port=55431 user=postgres dbname=postgres";

/// Whether the env gate is set; integration tests early-return when this is
/// `false` so the default `cargo test` stays fast and DB-free.
pub fn it_enabled() -> bool {
    std::env::var(IT_ENV).map(|v| v == "1").unwrap_or(false)
}

/// The base connection string (env override or [`DEFAULT_PGURL`]).
pub fn base_pgurl() -> String {
    std::env::var("PG_BUMPERS_PGURL").unwrap_or_else(|_| DEFAULT_PGURL.to_string())
}
