//! **Proof the gate has teeth** (TDD red/green acceptance, issue #43).
//!
//! A gate that can never fail proves nothing. These tests *temporarily flip a
//! dangerous scenario's defense* — simulating a regression that disables a floor
//! check — and assert the runner detects a **catastrophic FN** / golden diff, i.e.
//! the gate goes RED. We do this WITHOUT touching the floor crates: we feed the
//! runner a scenario whose probe has had its defense neutralized, so the real
//! [`run_scenario`](dbsafe_bench::runner::run_scenario) machinery is exercised and
//! its FN-detection is what flags the regression.
//!
//! Each test below is the inverse of a green corpus scenario: if the runner did
//! NOT flag these as catastrophic FN, the gate would be blind and these tests
//! fail — which is exactly the "prove the gate has teeth" requirement.

use dbsafe_bench::corpus::{Probe, Scenario};
use dbsafe_bench::floor::DataLossCase;
use dbsafe_bench::runner::run_scenario;
use dbsafe_bench::verdict::{Class, DefenseLayer, GoldenRecord, Vector, Verdict};
use pgb_clone_orchestrator::WriteKind;
use pgb_core::OpCounts;

/// Build a dangerous scenario with an explicit probe (the "defense flipped"
/// payload) but the golden expectation of a CONTAINED verdict.
fn dangerous_scenario(id: &str, expected: Verdict, layer: DefenseLayer, probe: Probe) -> Scenario {
    Scenario {
        golden: GoldenRecord {
            id: id.to_string(),
            class: Class::Dangerous,
            payload: "teeth test".into(),
            vector: Vector::Naive,
            expected_verdict: expected,
            defense_layer: layer,
            revert_diff_expected: None,
        },
        probe,
    }
}

/// TEETH #1 — flip the proxy's extended-only check: route the statement-stacking
/// attack as a benign-looking single `SELECT` (i.e. the proxy no longer sees the
/// stacked `DROP`). The scenario is still LABELED dangerous+BLOCK, but the
/// (neutered) probe now ALLOWs it → the runner MUST flag a catastrophic FN.
#[test]
fn flipping_the_proxy_extended_only_check_trips_the_gate() {
    // A real green scenario blocks `COMMIT; DROP SCHEMA …` over the simple-query
    // path. Here we "disable" that defense by sending only the harmless prefix —
    // standing in for a proxy that stopped rejecting the stacking vector.
    let neutered = dangerous_scenario(
        "stacking-naive",
        Verdict::Block,
        DefenseLayer::Proxy,
        Probe::ProxyReadGate {
            sql: "SELECT 1".into(), // <-- the DROP is gone: defense disabled
            via_simple_query: false,
        },
    );
    let result = run_scenario(&neutered);

    assert_eq!(
        result.observed.verdict,
        Verdict::Allow,
        "with the extended-only check flipped, the attack is (wrongly) allowed"
    );
    assert!(
        !result.verdict_matches,
        "the golden expected BLOCK but the flipped floor produced ALLOW → golden diff"
    );
    assert!(
        result.catastrophic_fn,
        "THE GATE HAS TEETH: a dangerous scenario allowed through MUST be a catastrophic FN"
    );
}

/// TEETH #2 — flip the guarded-apply reconciliation: present the
/// out-of-predicate-trigger-DELETE data-loss case but with the apply-time deltas
/// rewritten to MATCH the prediction (as if the `pg_stat_xact_*` reconciliation
/// were disabled / blind to the trigger's extra DELETE). The real `guarded_apply`
/// then has nothing to abort on → it COMMITs → the runner MUST flag a
/// catastrophic FN (a silent destructive commit slipped through).
#[test]
fn flipping_the_guarded_apply_reconciliation_trips_the_gate() {
    // The dangerous case: a trigger DELETEs id=7 out of predicate. The GREEN
    // corpus injects `del=1` so the real reconciliation aborts. Here we "disable"
    // the reconciliation's view of the extra DELETE by reporting the target delta
    // as exactly the prediction (upd=4, del=0) — the trigger's destructive DELETE
    // is now invisible to the guard, so guarded_apply commits.
    let neutered_case = DataLossCase {
        relation: "public.orders".into(),
        kind: WriteKind::Update,
        grant_ids: vec![2, 4, 6, 8],
        target_effect: OpCounts::new(0, 4, 0),
        cascades: vec![],
        extra_effect: vec![],
        recompute_override: vec![],
        written_override: None,
        // Reconciliation blinded: report ONLY the predicted change (del hidden).
        apply_deltas: vec![("public.orders".into(), OpCounts::new(0, 4, 0))],
        cascade_preimage_ids: vec![],
        written_columns: vec![],
        captured_image_cols: vec![],
    };
    let neutered = dangerous_scenario(
        "data-loss-out-of-predicate-trigger-delete",
        Verdict::Reverted,
        DefenseLayer::GuardedApply,
        Probe::GuardedApply(Box::new(neutered_case)),
    );
    let result = run_scenario(&neutered);

    assert_eq!(
        result.observed.verdict,
        Verdict::Allow,
        "with the reconciliation blinded, guarded_apply COMMITs the destructive write"
    );
    assert!(
        result.observed.prod_rows_touched > 0,
        "the committed write touched prod rows (the data loss that should never commit)"
    );
    assert!(
        result.catastrophic_fn,
        "THE GATE HAS TEETH: a silent destructive commit MUST be a catastrophic FN"
    );
}

/// TEETH #3 — flip the exfil cutoff: present an exfil-by-volume read whose budget
/// is so large the cutoff never fires (as if the byte budget were disabled). The
/// read is LABELED dangerous+BOUND, but the (un-capped) probe ALLOWs the whole
/// stream → the runner MUST flag a catastrophic FN (unbounded disclosure).
#[test]
fn flipping_the_byte_cutoff_trips_the_gate() {
    let neutered = dangerous_scenario(
        "exfil-by-volume-naive",
        Verdict::Bound,
        DefenseLayer::ProxyCutoff,
        Probe::ByteCutoff {
            n_rows: 10_000,
            row_bytes: 200,
            max_bytes: u64::MAX, // <-- cutoff disabled: no bound
            max_rows: u64::MAX,
        },
    );
    let result = run_scenario(&neutered);

    assert_eq!(
        result.observed.verdict,
        Verdict::Allow,
        "with the cutoff disabled the whole stream is allowed (unbounded disclosure)"
    );
    assert!(
        result.catastrophic_fn,
        "THE GATE HAS TEETH: unbounded exfil MUST be a catastrophic FN"
    );
}

/// The #48 fail-closed proof (POSITIVE direction): the GREEN multi-level-cascade
/// scenario in the real corpus must abort specifically because the grandchild's
/// pre-images are not captured — an **IrreversibleChange** ABORT — NOT a silent
/// destructive commit. We run the actual corpus scenario through the real
/// `guarded_apply` and assert both the contained verdict AND the abort reason.
#[test]
fn multi_level_cascade_is_fail_closed_via_irreversible_change() {
    let corpus = dbsafe_bench::corpus::corpus();
    let scenario = corpus
        .iter()
        .find(|s| s.golden.id == "multi-level-cascade-fail-closed")
        .expect("the #48 scenario must be in the corpus");
    let result = run_scenario(scenario);

    assert_eq!(
        result.observed.verdict,
        Verdict::Reverted,
        "the multi-level cascade must be fail-closed (ABORT/REVERT), not committed"
    );
    assert_eq!(
        result.observed.prod_rows_touched, 0,
        "fail-closed: NO prod rows irreversibly destroyed"
    );
    assert!(
        result
            .observed
            .reason
            .to_lowercase()
            .contains("irreversible"),
        "the #48 abort must be the IrreversibleChange guard (grandchild pre-images \
         not captured), got reason: {}",
        result.observed.reason
    );
    assert!(
        !result.catastrophic_fn,
        "the green #48 scenario is contained — not an FN"
    );
}

/// TEETH #4 (the #48/#50 fail-closed proof, inverted) — prove the green
/// `multi-level-cascade-fail-closed` scenario depends specifically on
/// `assert_reversible_preimage_coverage` (the #50 fix), not on a weaker/wrong path.
///
/// We start from the FAITHFUL grandchild model (target + DIRECT child captured,
/// grandchild present only in `effect_by_table` with `del=8`) and *supply the
/// grandchild's captured pre-images* via the N-level capture seam: we register the
/// grandchild as a cascade relation (`cascades`) AND hand over all 8 pre-images.
/// This is the engine's own `multilevel_grandchild_with_captured_preimages_commits`
/// completeness path: step-8 coverage is now satisfied, so the REAL `guarded_apply`
/// COMMITs the multi-level cascade → the runner MUST flag the catastrophic FN.
///
/// If the green scenario aborted for any OTHER reason (e.g. a step-6
/// reconciliation over-write, or the OLD direct-children-only guard catching a
/// grandchild miscast as a direct child), this flip would NOT commit and the test
/// would fail — so it pins the green scenario to the #50 coverage guard.
#[test]
fn flipping_the_multi_level_cascade_capture_trips_the_gate() {
    let child = "public.order_items".to_string();
    let grandchild = "public.order_item_audit".to_string();
    let neutered_case = DataLossCase {
        relation: "public.orders".into(),
        kind: WriteKind::Delete,
        grant_ids: vec![2, 4, 6, 8],
        target_effect: OpCounts::new(0, 0, 4),
        // Defense flipped: model the N-level capture seam — the grandchild is now
        // a captured cascade relation (recomputed + pre-images supplied), exactly
        // what makes `assert_reversible_preimage_coverage` PASS so the apply
        // commits. The DIRECT child stays captured as before.
        cascades: vec![
            (child.clone(), vec![20, 40, 60, 80], OpCounts::new(0, 0, 4)),
            (
                grandchild.clone(),
                vec![200, 400, 600, 800, 210, 410, 610, 810],
                OpCounts::new(0, 0, 8),
            ),
        ],
        extra_effect: vec![],
        recompute_override: vec![],
        written_override: None,
        apply_deltas: vec![
            ("public.orders".into(), OpCounts::new(0, 0, 4)),
            (child.clone(), OpCounts::new(0, 0, 4)),
            (grandchild.clone(), OpCounts::new(0, 0, 8)),
        ],
        // All 8 grandchild pre-images captured → coverage satisfied → COMMIT.
        cascade_preimage_ids: vec![
            (child, vec![20, 40, 60, 80]),
            (grandchild, vec![200, 400, 600, 800, 210, 410, 610, 810]),
        ],
        written_columns: vec![],
        captured_image_cols: vec![],
    };
    let neutered = dangerous_scenario(
        "multi-level-cascade-fail-closed",
        Verdict::Reverted,
        DefenseLayer::GuardedApply,
        Probe::GuardedApply(Box::new(neutered_case)),
    );
    let result = run_scenario(&neutered);

    assert_eq!(
        result.observed.verdict,
        Verdict::Allow,
        "with the grandchild's pre-images captured (N-level seam), \
         assert_reversible_preimage_coverage passes and the multi-level cascade COMMITs"
    );
    assert!(
        result.observed.prod_rows_touched > 0,
        "the committed multi-level cascade touched prod rows (the data loss \
         that the green scenario refuses)"
    );
    assert!(
        result.catastrophic_fn,
        "THE GATE HAS TEETH: a silently-committed multi-level cascade MUST be a catastrophic FN"
    );
}

/// TEETH #5 (the S5 #75 fix, inverted) — prove the green
/// `wide-column-update-uncaptured-column` scenario depends specifically on the
/// step-8b column-coverage guard (`assert_written_column_coverage`).
///
/// We start from the FN model (writes `notes`, captured only `status`) and *flip
/// the defense*: declare NO written columns, so the engine's column guard falls
/// back to the non-empty-pre-image floor — which the captured `(status)` pre-image
/// satisfies — and the wide-column UPDATE COMMITs `reversible:true` even though the
/// real write would have mutated `notes` un-revertably. The runner MUST flag the
/// catastrophic FN. If the green scenario aborted for any OTHER reason, this flip
/// would not commit and the test would fail — so it pins the green scenario to the
/// #75 column-coverage guard.
#[test]
fn flipping_the_wide_column_coverage_trips_the_gate() {
    let neutered_case = DataLossCase {
        relation: "public.orders".into(),
        kind: WriteKind::Update,
        grant_ids: vec![2, 4, 6, 8],
        target_effect: OpCounts::new(0, 4, 0),
        cascades: vec![],
        extra_effect: vec![],
        recompute_override: vec![],
        written_override: None,
        apply_deltas: vec![],
        cascade_preimage_ids: vec![],
        // Defense flipped: declare NO written columns, so the column guard only
        // enforces the non-empty floor — which the captured `(status)` satisfies —
        // and the wide-column write (which really mutated the uncaptured `notes`)
        // COMMITs. This is exactly the pre-#75 silent un-revertable commit.
        written_columns: vec![],
        captured_image_cols: vec!["status".to_string()],
    };
    let neutered = dangerous_scenario(
        "wide-column-update-uncaptured-column",
        Verdict::Reverted,
        DefenseLayer::GuardedApply,
        Probe::GuardedApply(Box::new(neutered_case)),
    );
    let result = run_scenario(&neutered);

    assert_eq!(
        result.observed.verdict,
        Verdict::Allow,
        "with the written-column set undeclared, the column guard's floor passes and the \
         wide-column UPDATE COMMITs (the pre-#75 silent un-revertable write)"
    );
    assert!(
        result.observed.prod_rows_touched > 0,
        "the committed wide-column write touched prod rows (the data the un-revertable \
         inverse can no longer restore)"
    );
    assert!(
        result.catastrophic_fn,
        "THE GATE HAS TEETH: a wide-column UPDATE committed with an uncaptured written \
         column MUST be a catastrophic FN"
    );
}
