//! Policy model + contracts seam for pg_bumpers (S0, issue #7).
//!
//! This crate pins the **one-way-door** contracts (SPEC §15.3) the rest of the
//! system builds on, even though the engines behind them are fast-follow:
//!
//! - [`config`] — the single **`policy.yaml`** model + validation: per-role
//!   SELECT whitelist, byte/row budgets (single-shot + per-window cumulative),
//!   autonomy **L0–L2** (§15.1), plus the §12.2 component config and the §14.3
//!   approver / §10.9 audit-anchor placeholders. The shipped
//!   `policy.example.yaml` loads and validates; over-permissive configs
//!   (autonomy L3, negative/zero budgets) are **rejected**.
//! - [`verdict`] — the risk-plane [`Verdict`] with the total order
//!   `ALLOW < ESCALATE < HOLD < BLOCK` (§13.4 R2), the basis of *tighten-only*.
//! - [`risk`] — the [`RiskEngine`] trait (`{sql, schema, measured_stats,
//!   intent_tiers}` → `{verdict, reason, confidence}`), with the MVP
//!   [`AllowStub`] that **always returns `Allow`** (§11.5) and a seam-level
//!   tighten-only clamp.
//! - [`intent`] — the **T0–T2 intent-capture** schema (§11.2), captured/logged
//!   only in MVP, including the `/* intent: ticket: actor: */` annotation
//!   parser.
//! - [`grant`] — the §14.3 signed, single-use, time-boxed, **proposal-bound**
//!   grant token: the canonical binding hash, Ed25519 sign/verify, and the
//!   re-verify-at-apply helper that defeats SQL-swap / param-swap /
//!   cross-session-replay / nonce-replay / expiry (the five T-grant-* tests).
//!
//! The safety guarantee in v1 is the **deterministic floor**, never this crate's
//! risk plane — the [`RiskEngine`] is a stub and the intent tiers are logged
//! only (CLAUDE.md §2, SPEC §11.1/§11.5).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod grant;
pub mod intent;
pub mod risk;
pub mod verdict;

pub use config::{
    ApproverSet, AuditAnchorConfig, AutonomyLevel, CloneConfig, CloneProvider, DsnTarget,
    PitrConfig, PolicyConfig, PolicyError, ReplicaConfig, ResolvedTarget, RoleBudget, RolePolicy,
    TargetResolutionError, TargetResolver, WindowBudget,
};
pub use grant::{GrantBinding, GrantError, GrantToken, InMemoryNonceStore, NonceStore};
pub use intent::{
    IntentAnnotation, IntentTiers, ObservedStep, TierT0, TierT1, TierT2, parse_intent_annotation,
    statement_class,
};
pub use risk::{AllowStub, MeasuredStats, RiskEngine, RiskInput, RiskVerdict, StubRiskEngine};
pub use verdict::Verdict;
