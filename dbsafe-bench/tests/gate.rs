//! The **deterministic FP/FN CI gate** (SPEC §13.5 floor plane, §10.6).
//!
//! This is the test that gates CI. It runs every corpus scenario through the
//! REAL merged floor and asserts:
//!
//! 1. **0 diffs vs the golden** expected-outcome file (§10.6);
//! 2. **0 catastrophic FN** — every dangerous scenario is bounded / blocked /
//!    reverted / refused (never silently allowed; its pass predicate holds);
//! 3. **0 FP regression** — every adversarial-legit scenario is allowed;
//! 4. the **coverage floor** — every `(class × {naive, obfuscated,
//!    direct-to-DB-bypass})` cell is non-empty;
//! 5. the **KNOWN_BYPASSES ledger** loads and (for the MVP floor) is empty.
//!
//! The pure-logic scenarios (classifier, certify, guarded-apply via the scripted
//! `ApplyConn`, byte cutoff) run here in the **fast cargo job**. The DB-backed
//! scenarios (WALL role denial, proxy end-to-end against real PG18) are in
//! `gate_it.rs`, env-gated `PG_BUMPERS_IT=1`.
//!
//! To (intentionally) re-bless the golden after a deliberate corpus change, run
//! with `DBSAFE_BENCH_BLESS=1` — it rewrites the golden file from the live corpus
//! and the ledger, then the assertions below re-verify 0 diffs.

use dbsafe_bench::corpus::corpus;
use dbsafe_bench::golden::{
    diff_golden, golden_path, known_bypasses_path, load_golden, load_known_bypasses,
    serialize_golden,
};
use dbsafe_bench::runner::{GateReport, assert_coverage_floor};
use dbsafe_bench::verdict::KnownBypassLedger;

/// Re-bless the golden + ledger from the live corpus when `DBSAFE_BENCH_BLESS=1`.
fn maybe_bless(report: &GateReport) {
    if std::env::var("DBSAFE_BENCH_BLESS").as_deref() != Ok("1") {
        return;
    }
    let golden = serialize_golden(&report.golden_records());
    std::fs::write(golden_path(), golden).expect("write golden");
    let ledger = KnownBypassLedger::mvp_empty();
    let mut json = serde_json::to_string_pretty(&ledger).expect("serialize ledger");
    json.push('\n');
    std::fs::write(known_bypasses_path(), json).expect("write ledger");
    eprintln!("[bless] golden + KNOWN_BYPASSES rewritten from the live corpus");
}

#[test]
fn the_gate_is_green_zero_diffs_zero_fn_zero_fp() {
    let scenarios = corpus();
    let report = GateReport::run(&scenarios);

    // Always print the verdict table (PR evidence / `--nocapture`).
    eprintln!("\n{}", report.verdict_table());

    maybe_bless(&report);

    // (4) Coverage floor: every required (class × vector) cell is populated.
    assert_eq!(
        assert_coverage_floor(&scenarios),
        Ok(()),
        "coverage floor: a (class × vector) cell is empty"
    );

    // (2) 0 catastrophic FN — every dangerous scenario contained + predicate held.
    assert_eq!(
        report.catastrophic_fn(),
        0,
        "CATASTROPHIC FN: a dangerous scenario was not bounded/blocked/reverted/refused:\n{}",
        report.verdict_table()
    );

    // (3) 0 FP regression — every legit scenario allowed.
    assert_eq!(
        report.false_positives(),
        0,
        "FP REGRESSION: a legit scenario was not allowed:\n{}",
        report.verdict_table()
    );

    // (1) 0 diffs vs the golden file on disk.
    let golden = load_golden(&golden_path()).unwrap_or_else(|e| {
        panic!(
            "could not load the golden file ({e}).\n\
             If this is the first run, bless it with DBSAFE_BENCH_BLESS=1."
        )
    });
    let diffs = diff_golden(&golden, &report.golden_records());
    assert!(
        diffs.is_empty(),
        "GOLDEN DIFF ({} mismatch(es)) — the floor's behavior drifted from the frozen golden:\n{:#?}",
        diffs.len(),
        diffs
    );

    // The whole report is green (belt-and-suspenders over the above).
    assert!(report.is_green(), "{}", report.verdict_table());
}

#[test]
fn known_bypasses_ledger_loads_and_is_empty_for_the_mvp_floor() {
    // SPEC §10.6/§13.7: KNOWN_BYPASSES entries count against the headline. The MVP
    // deterministic floor contains the whole corpus, so the ledger is empty;
    // breadth + the marquee MCP-bypass repro are S5. We still assert the file
    // exists, parses, and is empty so a future non-empty ledger is a deliberate,
    // reviewed change (and visibly dents the headline).
    let ledger = load_known_bypasses(&known_bypasses_path())
        .expect("KNOWN_BYPASSES ledger must exist + parse");
    assert_eq!(
        ledger.count_against_headline(),
        0,
        "MVP floor: KNOWN_BYPASSES must be empty (entries count against '0 catastrophic FN')"
    );
    assert!(
        !ledger.cadence.is_empty(),
        "the refresh cadence must be documented"
    );
}

#[test]
fn golden_file_is_byte_stable_when_reserialized() {
    // The on-disk golden must be exactly what serialize_golden produces from the
    // records it contains (sorted/pretty/trailing-newline), so a no-op churn
    // never produces a spurious diff and `git status` stays clean.
    let golden = load_golden(&golden_path()).expect("load golden");
    let reserialized = serialize_golden(&golden);
    let on_disk = std::fs::read_to_string(golden_path()).expect("read golden");
    assert_eq!(
        on_disk, reserialized,
        "golden file is not in canonical form — re-bless with DBSAFE_BENCH_BLESS=1"
    );
}
