//! `dbsafe-bench` — the **deterministic FP/FN floor gate** (SPEC §3 "Separate:
//! dbsafe-bench", §13.5 CI-gating plane, §10.6 golden file). This is the §13.5
//! *floor plane* that **gates CI**: *0 catastrophic FN by construction + minimal
//! FP*, gated on **0 diffs vs a golden expected-outcome file**.
//!
//! # What this is (and is not)
//!
//! - It is the **deterministic floor plane** — every dangerous scenario must be
//!   bounded / blocked / reverted / refused by the *real merged floor*, and every
//!   adversarial-legit scenario must be allowed. Reproducible: pinned PG (scripted
//!   `ApplyConn` + env-gated PG18 IT), fixed ids, frozen clock (`MockClock`).
//! - It is **NOT** the LLM-detection FP/FN plane (SPEC §13.5 detection plane) —
//!   that is statistical, non-CI-gating, and a fast-follow. The deterministic
//!   floor is the real guarantee; "0 catastrophic FN" here is an **empirical**
//!   statement over this frozen distribution (SPEC §13.8), backstopped by the
//!   structural floor (writes bounded+reversible by construction; reads bounded to
//!   ≤ B). KNOWN_BYPASSES entries ([`verdict::KnownBypassLedger`]) count against
//!   the headline; the MVP ledger is empty (breadth + the MCP-bypass repro are S5).
//!
//! # Layout
//! - [`verdict`] — the golden vocabulary (verdict/class/vector/layer) + golden
//!   record + KNOWN_BYPASSES ledger.
//! - [`floor`] — the real-floor probes (proxy gate, byte cutoff, guarded-apply,
//!   certify, WALL bypass) — the *same public APIs the product ships*.
//! - [`mod@corpus`] — the frozen labeled corpus (dangerous + adversarial-legit).
//! - [`runner`] — runs each scenario through the floor + the per-scenario pass
//!   predicate → a [`runner::GateReport`].
//! - [`golden`] — golden-file I/O + the 0-diff comparison.
//!
//! # The gate
//! The CI gate lives in `tests/gate.rs` (fast, pure-logic — classifier, certify,
//! guarded-apply via the scripted conn, byte cutoff) and `tests/gate_it.rs`
//! (env-gated `PG_BUMPERS_IT=1` — WALL role denial + proxy end-to-end against real
//! PG18). Both assert: **0 diffs vs golden + 0 catastrophic FN + 0 FP regression**.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod corpus;
pub mod floor;
pub mod golden;
pub mod runner;
pub mod verdict;

pub use corpus::{Probe, Scenario, corpus};
pub use runner::{GateReport, ScenarioResult, assert_coverage_floor};
pub use verdict::{
    Class, DefenseLayer, GoldenRecord, KnownBypass, KnownBypassLedger, Vector, Verdict,
};
