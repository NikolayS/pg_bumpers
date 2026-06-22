//! Golden expected-outcome file I/O + diff (SPEC §10.6).
//!
//! The golden file `golden/expected_outcomes.json` is the frozen
//! `{id, class, payload, vector, expected_verdict, defense_layer,
//! revert_diff_expected?}` per scenario. The CI gate asserts **0 diffs** between
//! the golden file on disk and the records the corpus produces — a drift in the
//! corpus, a changed verdict, or a removed scenario all surface as a diff and
//! fail CI. The golden is regenerated (only on purpose) via
//! [`serialize_golden`] + the `bless` test helper.

use std::path::{Path, PathBuf};

use crate::verdict::{GoldenRecord, KnownBypassLedger};

/// The golden file path, relative to the crate root (`dbsafe-bench/`).
pub const GOLDEN_RELATIVE: &str = "golden/expected_outcomes.json";

/// The KNOWN_BYPASSES ledger path, relative to the crate root.
pub const KNOWN_BYPASSES_RELATIVE: &str = "golden/known_bypasses.json";

/// Absolute path to the golden file (resolved from `CARGO_MANIFEST_DIR` so it
/// works under `cargo test` regardless of cwd).
pub fn golden_path() -> PathBuf {
    manifest_dir().join(GOLDEN_RELATIVE)
}

/// Absolute path to the KNOWN_BYPASSES ledger.
pub fn known_bypasses_path() -> PathBuf {
    manifest_dir().join(KNOWN_BYPASSES_RELATIVE)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Serialize golden records to pretty JSON (sorted/stable; trailing newline) so
/// the file is human-diffable and the on-disk form is byte-stable.
pub fn serialize_golden(records: &[GoldenRecord]) -> String {
    let mut s = serde_json::to_string_pretty(records).expect("serialize golden");
    s.push('\n');
    s
}

/// Load the golden records from disk.
pub fn load_golden(path: &Path) -> Result<Vec<GoldenRecord>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading golden {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parsing golden {}: {e}", path.display()))
}

/// Load the KNOWN_BYPASSES ledger from disk.
pub fn load_known_bypasses(path: &Path) -> Result<KnownBypassLedger, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading ledger {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parsing ledger {}: {e}", path.display()))
}

/// A single golden diff line (a mismatch between the expected golden on disk and
/// the records the corpus produced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoldenDiff {
    /// A scenario id present on disk but missing from the live corpus.
    OnlyInGolden(String),
    /// A scenario id present in the live corpus but missing from the golden file.
    OnlyInLive(String),
    /// A scenario whose record changed (verdict, layer, payload, vector, …).
    Changed {
        /// The scenario id.
        id: String,
        /// The golden (on-disk) record.
        golden: Box<GoldenRecord>,
        /// The live (corpus-produced) record.
        live: Box<GoldenRecord>,
    },
}

/// Compute the diff between the on-disk golden and the live corpus records
/// (SPEC §10.6: the gate requires this to be empty). Order-independent: matches
/// records by `id`.
pub fn diff_golden(golden: &[GoldenRecord], live: &[GoldenRecord]) -> Vec<GoldenDiff> {
    use std::collections::BTreeMap;
    let golden_by_id: BTreeMap<&str, &GoldenRecord> =
        golden.iter().map(|r| (r.id.as_str(), r)).collect();
    let live_by_id: BTreeMap<&str, &GoldenRecord> =
        live.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut diffs = Vec::new();
    for (id, g) in &golden_by_id {
        match live_by_id.get(id) {
            None => diffs.push(GoldenDiff::OnlyInGolden(id.to_string())),
            Some(l) if l != g => diffs.push(GoldenDiff::Changed {
                id: id.to_string(),
                golden: Box::new((*g).clone()),
                live: Box::new((**l).clone()),
            }),
            Some(_) => {}
        }
    }
    for id in live_by_id.keys() {
        if !golden_by_id.contains_key(id) {
            diffs.push(GoldenDiff::OnlyInLive(id.to_string()));
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Class, DefenseLayer, Vector, Verdict};

    fn rec(id: &str, v: Verdict) -> GoldenRecord {
        GoldenRecord {
            id: id.into(),
            class: Class::Dangerous,
            payload: "p".into(),
            vector: Vector::Naive,
            expected_verdict: v,
            defense_layer: DefenseLayer::Proxy,
            revert_diff_expected: None,
        }
    }

    #[test]
    fn identical_sets_have_no_diff() {
        let a = vec![rec("x", Verdict::Block), rec("y", Verdict::Allow)];
        let b = vec![rec("y", Verdict::Allow), rec("x", Verdict::Block)];
        assert!(diff_golden(&a, &b).is_empty(), "order-independent, equal");
    }

    #[test]
    fn changed_verdict_is_a_diff() {
        let a = vec![rec("x", Verdict::Block)];
        let b = vec![rec("x", Verdict::Allow)];
        let d = diff_golden(&a, &b);
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0], GoldenDiff::Changed { .. }));
    }

    #[test]
    fn added_and_removed_scenarios_are_diffs() {
        let golden = vec![rec("x", Verdict::Block)];
        let live = vec![rec("y", Verdict::Block)];
        let d = diff_golden(&golden, &live);
        assert!(d.contains(&GoldenDiff::OnlyInGolden("x".into())));
        assert!(d.contains(&GoldenDiff::OnlyInLive("y".into())));
    }

    #[test]
    fn serialize_round_trips() {
        let recs = vec![rec("x", Verdict::Block)];
        let json = serialize_golden(&recs);
        assert!(json.ends_with('\n'));
        let back: Vec<GoldenRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, recs);
    }
}
