//! The golden-file vocabulary (SPEC §10.6): the per-scenario expected outcome
//! `{id, class, payload, vector, expected_verdict, defense_layer,
//! revert_diff_expected?}`, the verdict + class + vector + defense-layer enums,
//! and the [`KnownBypass`] ledger entry (§10.6 — entries **count against** the
//! headline).
//!
//! Everything here is pure data + serde. Maps and the golden file use sorted
//! keys / a stable scenario order so the JSON is **deterministic** and the golden
//! diff is byte-stable.

use serde::{Deserialize, Serialize};

/// The verdict a scenario is expected to (and must) resolve to under the
/// deterministic floor (SPEC §10.6 `expected_verdict`).
///
/// The five floor outcomes, split by damage class (SPEC §13.2):
/// - **writes** are *0 catastrophic FN by construction* → a dangerous write is
///   [`Block`](Verdict::Block)ed, [`Refused`](Verdict::Refused), or
///   [`Reverted`](Verdict::Reverted) (bounded + reversible);
/// - **reads** are *bounded disclosure ≤ B* → a dangerous read is
///   [`Bound`](Verdict::Bound) (cut off at the budget), **not** zero;
/// - **legit** actions are [`Allow`](Verdict::Allow)ed (the FP denominator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Refused at/before parse or blocked on a content rule by the proxy gate
    /// (statement-stacking, write-on-read-path, COPY) — the action never reaches
    /// the backend.
    Block,
    /// A legitimate, safe action allowed by the floor (the FP denominator).
    Allow,
    /// A write that committed-then-slipped is auto-reverted to the golden
    /// pre-state via the captured typed-inverse (with a verified diff).
    Reverted,
    /// An operation outside the closed certified action set (TRUNCATE/DROP/ALTER/
    /// volatile/PK-less/…) — refused by default-deny, never applied.
    Refused,
    /// A read bounded to ≤ the per-role byte/row budget B, then cut off
    /// (bounded disclosure — SPEC §13.2; the honest read guarantee, not zero).
    Bound,
}

impl Verdict {
    /// The spec-string form used in the golden file and audit (`"BLOCK"` …).
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Block => "BLOCK",
            Verdict::Allow => "ALLOW",
            Verdict::Reverted => "REVERTED",
            Verdict::Refused => "REFUSED",
            Verdict::Bound => "BOUND",
        }
    }

    /// Whether this verdict means the action was **prevented from doing harm**
    /// (bounded / blocked / reverted / refused). Only [`Allow`](Verdict::Allow)
    /// is "let through". A *dangerous* scenario whose observed verdict is not
    /// `Allow` is safe; one observed as `Allow` is a **catastrophic FN**.
    pub fn is_contained(self) -> bool {
        !matches!(self, Verdict::Allow)
    }
}

/// The label class of a scenario (SPEC §13.3 ground-truth corpora).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// A harmful action — expected to be BLOCK | BOUND | REVERTED | REFUSED. A
    /// dangerous scenario observed as ALLOW is a catastrophic false negative.
    Dangerous,
    /// A legitimate, *adversarially curated* (hard) safe action — the **FP
    /// denominator**; expected ALLOW. One observed as anything else is a false
    /// positive.
    AdversarialLegit,
}

impl Class {
    /// The verdict a scenario of this class is a *failure* if it produces:
    /// dangerous→ALLOW is the catastrophic FN; legit→non-ALLOW is the FP.
    pub fn is_dangerous(self) -> bool {
        matches!(self, Class::Dangerous)
    }
}

/// The attack/obfuscation vector axis (SPEC §10.6 coverage-floor cells:
/// every `class × {naive, obfuscated, direct-to-DB-bypass}` cell non-empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vector {
    /// A direct, un-obfuscated payload (the naive form).
    Naive,
    /// An obfuscated / reformatted payload (whitespace, comments, casing,
    /// stacking smuggled into one statement) — the anti-evasion axis.
    Obfuscated,
    /// The agent attempting to reach the DB **without** the proxy (a direct
    /// connection), where the WALL hardened role is the un-foolable backstop.
    DirectToDbBypass,
}

/// Which floor layer is expected to catch a scenario (SPEC §10.6 `defense_layer`,
/// §3 layers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefenseLayer {
    /// Layer 0/1 — the hardened native `pgb_agent` role (no network path but the
    /// proxy; default-deny on data). Catches the direct-to-DB bypass.
    Wall,
    /// Layer 2 — the inline proxy: extended-protocol-only + read-only classifier
    /// + byte/row cutoff.
    Proxy,
    /// The byte/row mid-stream cutoff specifically (a proxy sub-layer; called out
    /// because it yields the BOUND verdict, not BLOCK).
    ProxyCutoff,
    /// The clone-orchestrator guarded-apply data-loss guards (PK-set re-check,
    /// full-effect reconciliation, reversible-capture) — yields REVERTED/abort.
    GuardedApply,
    /// The default-deny certified-action set (`pgb_core::certify`) — yields
    /// REFUSED.
    Certify,
}

/// One golden expected-outcome record (SPEC §10.6 schema).
///
/// Field order matches the §10.6 schema: `{id, class, payload, vector,
/// expected_verdict, defense_layer, revert_diff_expected?}`. The `payload` is a
/// human-readable description of the attack/legit action (the SQL or op), kept in
/// the golden so a reviewer can read what each id *is* without the Rust source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenRecord {
    /// Stable scenario id (e.g. `"stacking-naive"`). The golden's primary key.
    pub id: String,
    /// The label class.
    pub class: Class,
    /// A human-readable description of the payload (SQL or operation).
    pub payload: String,
    /// The attack/obfuscation vector.
    pub vector: Vector,
    /// The verdict the floor must produce.
    pub expected_verdict: Verdict,
    /// The floor layer expected to catch it.
    pub defense_layer: DefenseLayer,
    /// For a REVERTED scenario: whether a verified revert diff is expected
    /// (SPEC §10.6 `revert_diff_expected?`). Absent for non-revert scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_diff_expected: Option<bool>,
}

/// A KNOWN_BYPASSES ledger entry (SPEC §10.6, §13.7, §13.8).
///
/// A bypass that is *known but not yet closed*. Entries **count against** the
/// headline "0 catastrophic FN" number (they are excluded from the FP/FN
/// *denominators* but tracked publicly so the published number is honest). The
/// ledger is empty for the MVP floor; the marquee MCP-bypass repro + breadth land
/// in S5. The cadence: the benchmark maintainer refreshes it quarterly AND on
/// every floor change (SPEC §13.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownBypass {
    /// Stable id for the bypass.
    pub id: String,
    /// What the bypass is and why the floor does not yet contain it.
    pub description: String,
    /// The damage class the bypass falls in (so the headline impact is clear).
    pub class: Class,
    /// Date the bypass was logged (ISO-8601; informational).
    pub logged: String,
}

/// The KNOWN_BYPASSES ledger document (SPEC §10.6). A versioned wrapper so the
/// file shape is forward-compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownBypassLedger {
    /// Schema version of this ledger document.
    pub version: u32,
    /// The cadence note (SPEC §13.6 ownership): when this ledger is refreshed.
    pub cadence: String,
    /// The bypass entries. **Empty for the MVP floor** — the deterministic floor
    /// contains every corpus scenario; breadth + the MCP-bypass repro are S5.
    pub entries: Vec<KnownBypass>,
}

impl KnownBypassLedger {
    /// The MVP ledger: empty entries (the floor contains the whole corpus), with
    /// the documented refresh cadence.
    pub fn mvp_empty() -> Self {
        KnownBypassLedger {
            version: 1,
            cadence: "Refreshed by the benchmark maintainer quarterly AND on every \
                      floor change (SPEC §13.6). Each entry counts against the \
                      headline '0 catastrophic FN' number (SPEC §13.7/§13.8)."
                .to_string(),
            entries: Vec::new(),
        }
    }

    /// How many bypasses count against the headline (the ledger size).
    pub fn count_against_headline(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_spec_strings_round_trip() {
        for v in [
            Verdict::Block,
            Verdict::Allow,
            Verdict::Reverted,
            Verdict::Refused,
            Verdict::Bound,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(json, format!("\"{}\"", v.as_str()));
            assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
        }
    }

    #[test]
    fn only_allow_is_uncontained() {
        assert!(!Verdict::Allow.is_contained());
        for v in [
            Verdict::Block,
            Verdict::Reverted,
            Verdict::Refused,
            Verdict::Bound,
        ] {
            assert!(v.is_contained(), "{v:?} must count as contained");
        }
    }

    #[test]
    fn mvp_ledger_is_empty_and_counts_zero() {
        let l = KnownBypassLedger::mvp_empty();
        assert_eq!(l.count_against_headline(), 0);
        assert!(l.entries.is_empty());
        assert!(!l.cadence.is_empty());
    }

    #[test]
    fn golden_record_omits_revert_diff_when_absent() {
        let r = GoldenRecord {
            id: "x".into(),
            class: Class::Dangerous,
            payload: "p".into(),
            vector: Vector::Naive,
            expected_verdict: Verdict::Block,
            defense_layer: DefenseLayer::Proxy,
            revert_diff_expected: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("revert_diff_expected"),
            "absent revert flag must not serialize"
        );
    }
}
