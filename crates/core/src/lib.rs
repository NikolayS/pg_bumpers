//! Core domain types and one-way-door seams shared across pg_bumpers.
//!
//! This crate is intentionally dependency-light and **DB-free**: it holds the
//! contracts every other crate builds on (see `docs/spec/SPEC.md` §3 and the S0
//! core-seams work item #6). The proxy, clone-orchestrator, guarded-apply,
//! warden and policy all build on these seams, so they are designed to be
//! deterministic and test-injectable — these are §15.3 one-way doors,
//! expensive to retrofit.
//!
//! # Modules
//! - [`clock`] — the [`Clock`] trait + an advanceable [`MockClock`]; no
//!   wall-clock reads ever leak into gating logic (SPEC §10.4).
//! - [`barrier`] — the [`ApplyBarrier`] seam: a deterministic `pause_point()`
//!   hook between dry-run and apply (SPEC §10.4).
//! - [`session`] — [`SessionState`]/[`TrustLevel`] plus the **pure**
//!   [`trust_transition`] function, which is *tighten-only* (SPEC §10.4,
//!   §11.1).
//! - [`blast_radius`] — the [`BlastRadius`] dry-run record (SPEC §10.1).
//! - [`pk_checksum`] — the affected-PK-set checksum that is the guard's basis;
//!   it catches row-identity drift that a row count cannot (SPEC §10.2).
//! - [`inverse`] — the typed-inverse capture format and the refused-op
//!   default-deny certified action set (SPEC §10.3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod barrier;
pub mod blast_radius;
pub mod clock;
pub mod inverse;
pub mod pk_checksum;
pub mod session;

pub use barrier::{ApplyBarrier, ClosureBarrier, NoopBarrier};
pub use blast_radius::{BlastRadius, LockHeld, LockMode, OpCounts, TriggerFired};
pub use clock::{Clock, MockClock, SystemClock};
pub use inverse::{CertifiedAction, InverseKind, InversePlan, InverseRow, NotRestored, RefusedOp};
pub use pk_checksum::{ChecksumError, PkChecksum, PkSetBuilder, PkTuple, PkValue};
pub use session::{SessionState, TrustEvent, TrustLevel, trust_transition};
