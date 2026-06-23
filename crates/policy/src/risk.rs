//! The [`RiskEngine`] seam (SPEC §10.10, §11.1, §11.5, §15.3).
//!
//! This is a **one-way door**: the trait signature is pinned now so the rest of
//! the system can depend on it, even though the real LLM gating engine is
//! fast-follow (§15.2). In the MVP the only implementation is [`AllowStub`],
//! which **always returns `Allow`** (§11.5) — the deterministic floor, not this
//! engine, is the safety guarantee in v1.
//!
//! # Tighten-only contract (§11.1)
//!
//! The risk engine may only push an action in the *tightening* direction. Given
//! the deterministic-floor verdict `floor`, a conforming engine must return a
//! verdict `>= floor` (using the [`Verdict`] order `ALLOW < ESCALATE < HOLD <
//! BLOCK`). It can **never loosen** below the floor or grant access. The
//! consequence (the "risk asymmetry" of §11.1): an engine error is at worst a
//! false-positive (a blocked legitimate action), never a breach.
//!
//! Callers combine the floor and the engine with [`RiskVerdict::clamp_to_floor`],
//! which enforces tighten-only *at the seam* — even a buggy or adversarially
//! prompt-injected engine cannot loosen the outcome.

use serde::{Deserialize, Serialize};

use crate::intent::IntentTiers;
use crate::verdict::Verdict;

/// Measured effects of a proposed action (filled from the dry-run /
/// blast-radius record + EXPLAIN). Deliberately a thin, extensible bag: the MVP
/// stub ignores it, but the real engine reads it (§11.6 axes).
///
/// All counts are `Option` so "not measured" is distinct from "measured zero" —
/// absence of signal means least privilege (fail-closed, CLAUDE.md §2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeasuredStats {
    /// Rows the action would touch (target + cascade), if measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,
    /// Bytes the action would read or return, if measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// EXPLAIN total cost estimate, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<f64>,
    /// WAL volume the apply would generate, if measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wal_bytes: Option<u64>,
}

/// The input to a risk assessment (SPEC §10.10 / §15.3 signature:
/// `{sql, schema, measured_stats, intent_tiers}`).
///
/// Per §11.4, the `sql` handed to a *hosted* engine should have literals
/// stripped/parameterized so embedded PII never egresses; that redaction happens
/// upstream — this struct just carries whatever the caller decided to pass.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RiskInput {
    /// The statement under assessment (literals redacted upstream for hosted
    /// engines — §11.4).
    pub sql: String,
    /// A description of the relevant schema (tables/columns/types). Opaque to
    /// the stub; the real engine uses it for context-aware tuning (§11.6).
    #[serde(default)]
    pub schema: String,
    /// Measured effects from the dry-run / EXPLAIN.
    #[serde(default)]
    pub measured_stats: MeasuredStats,
    /// Captured intent across tiers T0–T2 (logged-only in MVP — §11.5).
    #[serde(default)]
    pub intent_tiers: IntentTiers,
}

/// The output of a risk assessment (SPEC §10.10: `{verdict, reason,
/// confidence}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskVerdict {
    /// The tighten-only verdict.
    pub verdict: Verdict,
    /// Human-readable rationale (shown to the approver — §14.2).
    pub reason: String,
    /// Engine confidence in `[0.0, 1.0]`. Drives the calibration thresholds
    /// (block on high / escalate on medium / allow on low — §11.1).
    pub confidence: f64,
}

impl RiskVerdict {
    /// An `Allow` verdict with the given rationale and full confidence.
    pub fn allow(reason: impl Into<String>) -> Self {
        RiskVerdict {
            verdict: Verdict::Allow,
            reason: reason.into(),
            confidence: 1.0,
        }
    }

    /// Enforce the **tighten-only** contract (§11.1) at the seam.
    ///
    /// Returns a verdict that is the *tighter* of this engine output and the
    /// deterministic-floor verdict, so a buggy or prompt-injected engine can
    /// never loosen below the floor. If the engine tried to loosen (returned a
    /// verdict below `floor`), the floor wins and the original (loosening)
    /// reason is replaced with a contract-violation note.
    pub fn clamp_to_floor(self, floor: Verdict) -> RiskVerdict {
        if self.verdict >= floor {
            self
        } else {
            RiskVerdict {
                verdict: floor,
                reason: format!(
                    "risk engine attempted to loosen below floor ({:?} < {:?}); clamped to floor",
                    self.verdict, floor
                ),
                confidence: self.confidence,
            }
        }
    }
}

/// The risk-engine seam (SPEC §10.10 / §15.3 one-way door).
///
/// Implementations assess how dangerous an action looks and return a
/// **tighten-only** verdict. The trait is object-safe so the engine can be
/// swapped behind a `&dyn RiskEngine` / `Box<dyn RiskEngine>` without touching
/// call sites when the real engine lands.
pub trait RiskEngine: Send + Sync {
    /// Assess an action. The returned verdict must satisfy the tighten-only
    /// contract relative to the deterministic floor (callers enforce it via
    /// [`RiskVerdict::clamp_to_floor`]).
    fn assess(&self, input: &RiskInput) -> RiskVerdict;
}

/// The MVP risk engine: **always returns `Allow`** (SPEC §11.5).
///
/// The deterministic floor — not this engine — is the safety guarantee in v1.
/// Intent tiers T0–T2 in the input are captured/logged only, not acted on.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowStub;

impl RiskEngine for AllowStub {
    fn assess(&self, _input: &RiskInput) -> RiskVerdict {
        RiskVerdict::allow(
            "MVP stub: risk engine returns Allow; the deterministic floor enforces safety (SPEC §11.5)",
        )
    }
}

impl AllowStub {
    /// Convenience: the bare [`Verdict`] the stub returns (always `Allow`).
    ///
    /// A thin accessor for callers (and the S0 smoke-test binaries) that only
    /// need the verdict vocabulary, not the full [`RiskVerdict`]. Equivalent to
    /// `self.assess(&RiskInput::default()).verdict`.
    pub fn evaluate(&self) -> Verdict {
        Verdict::Allow
    }
}

/// Backwards-compatible alias for [`AllowStub`] (the S0 foundation seam name).
///
/// The canonical name is [`AllowStub`]; re-exporting the unit struct under its
/// original name (carrying both the type and the value namespace) keeps the
/// foundation-PR smoke-test binaries compiling without reaching into other
/// crates. `StubRiskEngine.evaluate()` therefore still resolves.
pub use AllowStub as StubRiskEngine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_allow() {
        let stub = AllowStub;
        let input = RiskInput {
            sql: "DELETE FROM orders".to_string(),
            ..Default::default()
        };
        let out = stub.assess(&input);
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.confidence, 1.0);
    }

    #[test]
    fn stub_allows_even_a_scary_input() {
        // The stub is unconditional — even a wide, high-volume DELETE allows.
        let stub = AllowStub;
        let input = RiskInput {
            sql: "DELETE FROM orders /* no where */".to_string(),
            measured_stats: MeasuredStats {
                rows_affected: Some(4_800_000),
                bytes: Some(1 << 30),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(stub.assess(&input).verdict, Verdict::Allow);
    }

    #[test]
    fn usable_as_a_trait_object() {
        // The seam must be object-safe so the real engine swaps in later.
        let engine: Box<dyn RiskEngine> = Box::new(AllowStub);
        let input = RiskInput::default();
        assert_eq!(engine.assess(&input).verdict, Verdict::Allow);

        let by_ref: &dyn RiskEngine = &AllowStub;
        assert_eq!(by_ref.assess(&input).verdict, Verdict::Allow);
    }

    #[test]
    fn clamp_to_floor_lets_a_tighter_verdict_pass() {
        let v = RiskVerdict {
            verdict: Verdict::Block,
            reason: "looks malicious".into(),
            confidence: 0.9,
        };
        let clamped = v.clone().clamp_to_floor(Verdict::Hold);
        assert_eq!(clamped.verdict, Verdict::Block);
        assert_eq!(clamped.reason, v.reason);
    }

    #[test]
    fn clamp_to_floor_rejects_a_loosening_engine() {
        // A misbehaving engine that tries to ALLOW below a HOLD floor must be
        // clamped up to the floor — tighten-only enforced at the seam.
        let rogue = RiskVerdict {
            verdict: Verdict::Allow,
            reason: "trust me".into(),
            confidence: 0.99,
        };
        let clamped = rogue.clamp_to_floor(Verdict::Hold);
        assert_eq!(clamped.verdict, Verdict::Hold);
        assert!(clamped.reason.contains("clamped to floor"));
    }

    #[test]
    fn risk_verdict_round_trips_through_serde() {
        let v = RiskVerdict {
            verdict: Verdict::Escalate,
            reason: "intent↔action mismatch".into(),
            confidence: 0.5,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: RiskVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
