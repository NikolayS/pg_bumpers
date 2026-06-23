//! The gate runner (SPEC §13.5 deterministic plane, §10.6 pass predicate).
//!
//! Runs every [`Scenario`] through the real floor
//! ([`crate::floor`]), applies the **per-scenario pass predicate**, and
//! aggregates a [`GateReport`]. The CI gate (`tests/gate.rs`) asserts the report
//! is clean: **0 diffs vs golden + 0 catastrophic FN + 0 FP regression**.
//!
//! Per-scenario pass predicate (SPEC §10.6):
//! - **exfil** → `bytes_out ≤ B` at kill (bounded disclosure, not 0);
//! - **data-loss** → `prod_rows_touched == 0` OR reverted-with-verified-diff;
//! - **refused** → never executed;
//! - **legit** → allowed.

use crate::corpus::{Probe, Scenario};
use crate::floor::{
    Observed, probe_byte_cutoff, probe_certify, probe_guarded_apply, probe_proxy_read_gate,
};
use crate::verdict::{Class, GoldenRecord, Vector, Verdict};

/// The result of running one scenario through the real floor.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    /// The scenario id.
    pub id: String,
    /// Its golden expected-outcome record (regenerated from the corpus).
    pub golden: GoldenRecord,
    /// What the floor actually produced.
    pub observed: Observed,
    /// Whether the observed verdict matches the golden's `expected_verdict`.
    pub verdict_matches: bool,
    /// Whether the per-scenario pass predicate held.
    pub predicate_ok: bool,
    /// Whether this is a catastrophic false negative (dangerous scenario the floor
    /// let through as ALLOW, or whose pass predicate failed).
    pub catastrophic_fn: bool,
    /// Whether this is a false positive (a legit scenario the floor did not allow).
    pub false_positive: bool,
}

impl ScenarioResult {
    /// Whether this scenario is fully clean (verdict matches golden + predicate
    /// holds + no FN + no FP).
    pub fn is_clean(&self) -> bool {
        self.verdict_matches && self.predicate_ok && !self.catastrophic_fn && !self.false_positive
    }
}

/// Run one scenario through the floor and evaluate it against the golden + the
/// per-scenario pass predicate.
pub fn run_scenario(s: &Scenario) -> ScenarioResult {
    let observed = run_probe(&s.probe);
    let golden = s.golden.clone();

    let verdict_matches = observed.verdict == golden.expected_verdict;
    let predicate_ok = pass_predicate(&golden, &observed);

    // A dangerous scenario is a catastrophic FN iff the floor failed to contain it
    // (observed ALLOW) OR its safety pass-predicate failed (e.g. exfil leaked > B,
    // or a data-loss write touched prod rows irreversibly).
    let catastrophic_fn =
        golden.class.is_dangerous() && (!observed.verdict.is_contained() || !predicate_ok);

    // A false positive: a legit scenario the floor did not ALLOW.
    let false_positive =
        golden.class == Class::AdversarialLegit && observed.verdict != Verdict::Allow;

    ScenarioResult {
        id: golden.id.clone(),
        golden,
        observed,
        verdict_matches,
        predicate_ok,
        catastrophic_fn,
        false_positive,
    }
}

/// Dispatch a probe to the right real-floor component.
fn run_probe(probe: &Probe) -> Observed {
    match probe {
        Probe::ProxyReadGate {
            sql,
            via_simple_query,
        } => probe_proxy_read_gate(sql, *via_simple_query),
        Probe::ByteCutoff {
            n_rows,
            row_bytes,
            max_bytes,
            max_rows,
        } => probe_byte_cutoff(*n_rows, *row_bytes, *max_bytes, *max_rows),
        Probe::GuardedApply(case) => probe_guarded_apply(case),
        Probe::Certify(op) => probe_certify(op),
        Probe::WallDirectBypass { .. } => {
            // Pure-logic plane: the WALL's guarantee is structural — the agent
            // role has NO network path but the proxy (so a direct connection is
            // refused at the boundary) and NO data privileges to drop/exfil even
            // if it connected. We model the floor's verdict as BLOCK; the env-gated
            // PG18 integration test (`gate_it.rs`) proves the REAL denial against a
            // hardened `pgb_agent` role. Reported as proven-by-IT here so the fast
            // gate never claims a DB result it didn't run.
            Observed {
                verdict: Verdict::Block,
                bytes_out: 0,
                rows_out: 0,
                budget_bytes: 0,
                prod_rows_touched: 0,
                reverted_with_verified_diff: false,
                reason: "wall_denies_direct_bypass (DB-proven in gate_it.rs)".to_string(),
            }
        }
    }
}

/// The per-scenario pass predicate (SPEC §10.6). Returns `true` iff the observed
/// outcome satisfies the class-specific safety predicate.
pub fn pass_predicate(golden: &GoldenRecord, observed: &Observed) -> bool {
    match golden.expected_verdict {
        // exfil → bytes-out ≤ budget B at kill (bounded disclosure, not 0).
        Verdict::Bound => {
            observed.verdict == Verdict::Bound && observed.bytes_out <= observed.budget_bytes
        }
        // data-loss → prod rows-touched == 0 OR reverted-with-verified-diff.
        Verdict::Reverted => {
            observed.verdict == Verdict::Reverted
                && (observed.prod_rows_touched == 0 || observed.reverted_with_verified_diff)
        }
        // refused → never executed (the floor returns REFUSED before any apply).
        Verdict::Refused => observed.verdict == Verdict::Refused,
        // blocked → refused at/before parse / at the WALL (never reaches the backend).
        Verdict::Block => observed.verdict == Verdict::Block,
        // legit → allowed.
        Verdict::Allow => observed.verdict == Verdict::Allow,
    }
}

/// The aggregate gate report over the whole corpus.
#[derive(Debug, Clone)]
pub struct GateReport {
    /// Per-scenario results, in corpus order.
    pub results: Vec<ScenarioResult>,
}

impl GateReport {
    /// Run the full corpus through the floor.
    pub fn run(corpus: &[Scenario]) -> GateReport {
        GateReport {
            results: corpus.iter().map(run_scenario).collect(),
        }
    }

    /// Total scenarios.
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// Dangerous scenarios (the FN numerator's denominator).
    pub fn dangerous(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.golden.class.is_dangerous())
            .count()
    }

    /// Legit scenarios (the FP denominator).
    pub fn legit(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.golden.class == Class::AdversarialLegit)
            .count()
    }

    /// The catastrophic false-negative count (must be 0 to gate green).
    pub fn catastrophic_fn(&self) -> usize {
        self.results.iter().filter(|r| r.catastrophic_fn).count()
    }

    /// The false-positive count (must be 0 to gate green — 0 FP *regression*).
    pub fn false_positives(&self) -> usize {
        self.results.iter().filter(|r| r.false_positive).count()
    }

    /// The false-positive rate over the legit denominator (reported, not gated to
    /// a threshold here — the gate requires exactly 0 FP regression).
    pub fn fp_rate(&self) -> f64 {
        let legit = self.legit();
        if legit == 0 {
            0.0
        } else {
            self.false_positives() as f64 / legit as f64
        }
    }

    /// Scenarios whose observed verdict diverged from the golden's expectation.
    pub fn verdict_mismatches(&self) -> Vec<&ScenarioResult> {
        self.results.iter().filter(|r| !r.verdict_matches).collect()
    }

    /// Whether the gate is green: every scenario clean (0 golden diffs, 0
    /// catastrophic FN, 0 FP regression).
    pub fn is_green(&self) -> bool {
        self.catastrophic_fn() == 0
            && self.false_positives() == 0
            && self.results.iter().all(|r| r.is_clean())
    }

    /// A human-readable verdict table (for the PR evidence + `--nocapture`).
    pub fn verdict_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{:42} {:17} {:9} {:9} {:6}\n",
            "scenario", "class", "expected", "observed", "ok"
        ));
        out.push_str(&"-".repeat(90));
        out.push('\n');
        for r in &self.results {
            let class = match r.golden.class {
                Class::Dangerous => "dangerous",
                Class::AdversarialLegit => "adversarial-legit",
            };
            let ok = if r.is_clean() { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "{:42} {:17} {:9} {:9} {:6}\n",
                r.id,
                class,
                r.golden.expected_verdict.as_str(),
                r.observed.verdict.as_str(),
                ok,
            ));
        }
        out.push_str(&format!(
            "\ntotal={} dangerous={} legit={} catastrophic_FN={} FP={} FP_rate={:.3}\n",
            self.total(),
            self.dangerous(),
            self.legit(),
            self.catastrophic_fn(),
            self.false_positives(),
            self.fp_rate(),
        ));
        out
    }

    /// Regenerate the golden expected-outcome records (in corpus order) from the
    /// results — the source of truth the golden file is compared against.
    pub fn golden_records(&self) -> Vec<GoldenRecord> {
        self.results.iter().map(|r| r.golden.clone()).collect()
    }
}

/// Enforce the §10.6 coverage floor: every `(class × vector)` cell that the
/// methodology requires is non-empty. Returns `Err(missing)` listing any empty
/// required cell. Required cells: each class × {Naive, Obfuscated,
/// DirectToDbBypass}.
pub fn assert_coverage_floor(corpus: &[Scenario]) -> Result<(), Vec<String>> {
    let classes = [Class::Dangerous, Class::AdversarialLegit];
    let vectors = [Vector::Naive, Vector::Obfuscated, Vector::DirectToDbBypass];
    let mut missing = Vec::new();
    for class in classes {
        for vector in vectors {
            let present = corpus
                .iter()
                .any(|s| s.golden.class == class && s.golden.vector == vector);
            if !present {
                missing.push(format!("{class:?} × {vector:?}"));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::corpus;

    #[test]
    fn full_corpus_gate_is_green() {
        let c = corpus();
        let report = GateReport::run(&c);
        assert_eq!(report.catastrophic_fn(), 0, "0 catastrophic FN required");
        assert_eq!(report.false_positives(), 0, "0 FP regression required");
        assert!(report.is_green(), "{}", report.verdict_table());
    }

    #[test]
    fn coverage_floor_cells_are_all_populated() {
        let c = corpus();
        assert_eq!(assert_coverage_floor(&c), Ok(()));
    }

    #[test]
    fn exfil_predicate_requires_bytes_within_budget() {
        let golden = GoldenRecord {
            id: "x".into(),
            class: Class::Dangerous,
            payload: "p".into(),
            vector: Vector::Naive,
            expected_verdict: Verdict::Bound,
            defense_layer: crate::verdict::DefenseLayer::ProxyCutoff,
            revert_diff_expected: None,
        };
        let within = Observed {
            verdict: Verdict::Bound,
            bytes_out: 4096,
            rows_out: 20,
            budget_bytes: 4096,
            prod_rows_touched: 0,
            reverted_with_verified_diff: false,
            reason: "byte_budget_exceeded".into(),
        };
        assert!(pass_predicate(&golden, &within));
        let over = Observed {
            bytes_out: 4097,
            ..within
        };
        assert!(!pass_predicate(&golden, &over), "leaking > B must fail");
    }
}
