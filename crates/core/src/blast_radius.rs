//! The blast-radius record — the dry-run output (SPEC §10.1).
//!
//! A guarded write first runs as a **dry-run on a clone**, producing this
//! record: exactly which rows it would touch (by table, plus cascades), the
//! [`PkChecksum`](crate::pk_checksum::PkChecksum) of the affected PK set, locks,
//! WAL volume, predicted duration, whether it is reversible and by what inverse,
//! and the clone's LSN / staleness. The guard, the risk engine, and the human
//! reviewer all read this record before the apply phase.
//!
//! This module is **pure data + serde**: the JSON it (de)serializes mirrors the
//! §10.1 sample byte-for-byte, so the wire contract is pinned by a round-trip
//! test. The field layout (a nested `affected` object) matches the spec exactly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::inverse::InverseKind;

/// The set of rows a proposed write would affect (SPEC §10.1 `affected`).
///
/// `by_table` and `cascade_by_table` are keyed by `schema.table` and use a
/// [`BTreeMap`] so serialization is **deterministic** (sorted keys) — important
/// for golden-file comparisons. `pk_set_checksum` is keyed the same way and
/// carries the per-table `sha256:` checksum (see [`crate::pk_checksum`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affected {
    /// Rows directly affected, per `schema.table`.
    pub by_table: BTreeMap<String, u64>,
    /// Rows affected by `ON DELETE/UPDATE CASCADE`, per `schema.table`.
    pub cascade_by_table: BTreeMap<String, u64>,
    /// Per-table affected-PK-set checksum (`"sha256:…"`); see SPEC §10.2.
    pub pk_set_checksum: BTreeMap<String, String>,
    /// The **full** per-relation in-txn change footprint the dry-run measured via
    /// `pg_stat_xact_n_tup_{ins,upd,del}` deltas (SPEC §4) — the target, every
    /// cascade child, **and every relation a fired trigger wrote to** (e.g. an
    /// audit table). This is the symmetric prediction the guarded apply reconciles
    /// its own `pg_stat_xact_*` deltas against: a write to a relation **not** in
    /// this map, or **more** changes than recorded here, is drift and aborts. It is
    /// the apply-time "0 catastrophic data-loss FN by construction" mechanism.
    ///
    /// `#[serde(default)]` keeps the §10.1 wire contract backward-compatible: an
    /// older record without this field deserializes to an empty map (a guarded
    /// apply then has no predicted footprint to reconcile and must refuse — a
    /// stale grant cannot authorize a write, fail-closed).
    #[serde(default)]
    pub effect_by_table: BTreeMap<String, u64>,
    /// Total rows affected across target + cascade.
    pub total_rows: u64,
}

/// A trigger that the proposed write would fire, and how many rows it touches
/// (SPEC §10.1 `triggers_fired`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerFired {
    /// Trigger name.
    pub name: String,
    /// Rows the trigger would process.
    pub rows: u64,
}

/// A lock the proposed write would take (SPEC §10.1 `locks`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHeld {
    /// `schema.table` the lock is on.
    pub relation: String,
    /// Lock mode (see [`LockMode`]).
    pub mode: LockMode,
    /// Predicted hold time, in milliseconds.
    pub held_ms: u64,
}

/// Postgres lock modes, weakest → strongest (SPEC §10.1 `max_lock_mode`).
///
/// Ordered so `max()` yields the strongest mode acquired. Serializes to the
/// exact Postgres mode names (e.g. `"RowExclusiveLock"`) so the JSON matches
/// `pg_locks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LockMode {
    /// `ACCESS SHARE` — weakest; taken by `SELECT`.
    AccessShareLock,
    /// `ROW SHARE` — taken by `SELECT … FOR UPDATE/SHARE`.
    RowShareLock,
    /// `ROW EXCLUSIVE` — taken by `INSERT`/`UPDATE`/`DELETE`.
    RowExclusiveLock,
    /// `SHARE UPDATE EXCLUSIVE` — `VACUUM`, some `ALTER`/`CREATE INDEX`.
    ShareUpdateExclusiveLock,
    /// `SHARE` — `CREATE INDEX` (non-concurrent).
    ShareLock,
    /// `SHARE ROW EXCLUSIVE`.
    ShareRowExclusiveLock,
    /// `EXCLUSIVE`.
    ExclusiveLock,
    /// `ACCESS EXCLUSIVE` — strongest; `DROP`/`TRUNCATE`/most `ALTER`.
    AccessExclusiveLock,
}

/// A constraint the proposed write would violate (SPEC §10.1
/// `constraint_violations`).
///
/// Empty in the §10.1 sample; modeled as a struct so future fields (constraint
/// name, offending PK) extend without changing the wire shape of an empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintViolation {
    /// `schema.table` whose constraint is violated.
    pub relation: String,
    /// Constraint name.
    pub constraint: String,
}

/// The blast-radius record produced by a dry-run (SPEC §10.1).
///
/// Field order and names mirror the §10.1 sample JSON exactly; a round-trip test
/// pins the contract. `Option<…>` is used only where the spec field is logically
/// optional, and skipped on serialize when absent so the JSON stays minimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Caller-assigned proposal id this dry-run belongs to.
    pub proposal_id: String,
    /// LSN of the clone the dry-run ran against (e.g. `"3A/7F00C8"`).
    pub clone_lsn: String,
    /// How far behind prod the clone is, in WAL bytes. The staleness gate
    /// rejects clones above a configured ceiling (SPEC §10.5c).
    pub staleness_lsn_bytes: u64,
    /// The rows this write would affect (see [`Affected`]).
    pub affected: Affected,
    /// Triggers the write would fire.
    pub triggers_fired: Vec<TriggerFired>,
    /// Locks the write would take.
    pub locks: Vec<LockHeld>,
    /// The strongest lock mode acquired across all `locks`.
    pub max_lock_mode: LockMode,
    /// Predicted wall-clock duration of the apply, in milliseconds.
    pub duration_ms: u64,
    /// Predicted WAL volume of the apply, in bytes.
    pub wal_bytes: u64,
    /// Constraints the write would violate (empty ⇒ none).
    pub constraint_violations: Vec<ConstraintViolation>,
    /// Whether the write is reversible by the captured typed-inverse.
    pub reversible: bool,
    /// The kind of inverse captured (see [`InverseKind`]).
    pub inverse_kind: InverseKind,
    /// Whether the write's predicate is volatile (e.g. references `now()` /
    /// `random()`), which makes dry-run/apply equivalence unsafe.
    pub predicate_volatile: bool,
}

impl BlastRadius {
    /// The strongest lock mode across the record's `locks`, or `None` if it
    /// takes no locks. Useful for keeping [`max_lock_mode`](Self::max_lock_mode)
    /// consistent with [`locks`](Self::locks).
    pub fn computed_max_lock_mode(&self) -> Option<LockMode> {
        self.locks.iter().map(|l| l.mode).max()
    }

    /// Total rows affected, recomputed from the per-table maps (target +
    /// cascade) — a cross-check against [`Affected::total_rows`].
    pub fn computed_total_rows(&self) -> u64 {
        let direct: u64 = self.affected.by_table.values().copied().sum();
        let cascade: u64 = self.affected.cascade_by_table.values().copied().sum();
        direct.saturating_add(cascade)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §10.1 sample, transcribed (comments stripped, since the record is
    /// strict JSON). The round-trip test deserializes this and re-serializes,
    /// asserting structural equality both ways.
    const SAMPLE_JSON: &str = r#"{
        "proposal_id": "p-001",
        "clone_lsn": "3A/7F00C8",
        "staleness_lsn_bytes": 4194304,
        "affected": {
            "by_table": { "public.orders": 4800000 },
            "cascade_by_table": { "public.order_items": 0 },
            "pk_set_checksum": { "public.orders": "sha256:abc123" },
            "total_rows": 4800000
        },
        "triggers_fired": [ { "name": "orders_audit_ai", "rows": 4800000 } ],
        "locks": [ { "relation": "public.orders", "mode": "RowExclusiveLock", "held_ms": 88400 } ],
        "max_lock_mode": "RowExclusiveLock",
        "duration_ms": 88421,
        "wal_bytes": 1503289344,
        "constraint_violations": [],
        "reversible": true,
        "inverse_kind": "PREIMAGE_UPSERT",
        "predicate_volatile": false
    }"#;

    #[test]
    fn deserializes_the_spec_10_1_sample() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        assert_eq!(br.proposal_id, "p-001");
        assert_eq!(br.clone_lsn, "3A/7F00C8");
        assert_eq!(br.staleness_lsn_bytes, 4_194_304);
        assert_eq!(br.affected.total_rows, 4_800_000);
        assert_eq!(br.affected.by_table["public.orders"], 4_800_000);
        assert_eq!(br.affected.cascade_by_table["public.order_items"], 0);
        assert_eq!(
            br.affected.pk_set_checksum["public.orders"],
            "sha256:abc123"
        );
        assert_eq!(br.triggers_fired[0].name, "orders_audit_ai");
        assert_eq!(br.locks[0].mode, LockMode::RowExclusiveLock);
        assert_eq!(br.max_lock_mode, LockMode::RowExclusiveLock);
        assert_eq!(br.duration_ms, 88_421);
        assert_eq!(br.wal_bytes, 1_503_289_344);
        assert!(br.constraint_violations.is_empty());
        assert!(br.reversible);
        assert_eq!(br.inverse_kind, InverseKind::PreimageUpsert);
        assert!(!br.predicate_volatile);
    }

    #[test]
    fn round_trips_through_serde_without_loss() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        let serialized = serde_json::to_string(&br).expect("must serialize");
        let reparsed: BlastRadius = serde_json::from_str(&serialized).expect("must re-parse");
        assert_eq!(br, reparsed, "blast-radius record must round-trip exactly");
    }

    #[test]
    fn serialized_field_names_match_the_spec() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        let value: serde_json::Value = serde_json::to_value(&br).expect("to_value");
        let obj = value.as_object().expect("object");
        for key in [
            "proposal_id",
            "clone_lsn",
            "staleness_lsn_bytes",
            "affected",
            "triggers_fired",
            "locks",
            "max_lock_mode",
            "duration_ms",
            "wal_bytes",
            "constraint_violations",
            "reversible",
            "inverse_kind",
            "predicate_volatile",
        ] {
            assert!(obj.contains_key(key), "missing spec field `{key}`");
        }
        let affected = obj["affected"].as_object().expect("affected object");
        for key in [
            "by_table",
            "cascade_by_table",
            "pk_set_checksum",
            "effect_by_table",
            "total_rows",
        ] {
            assert!(
                affected.contains_key(key),
                "missing affected.{key} spec field"
            );
        }
    }

    /// The new `effect_by_table` field is backward-compatible: an older §10.1
    /// record without it deserializes to an empty map (and a guarded apply then
    /// refuses the stale grant, fail-closed).
    #[test]
    fn effect_by_table_defaults_to_empty_for_a_legacy_record() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        assert!(
            br.affected.effect_by_table.is_empty(),
            "a record without effect_by_table deserializes to an empty footprint"
        );
    }

    #[test]
    fn lock_modes_are_ordered_weakest_to_strongest() {
        assert!(LockMode::AccessShareLock < LockMode::RowExclusiveLock);
        assert!(LockMode::RowExclusiveLock < LockMode::AccessExclusiveLock);
    }

    #[test]
    fn computed_helpers_agree_with_the_sample() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        assert_eq!(
            br.computed_max_lock_mode(),
            Some(LockMode::RowExclusiveLock)
        );
        assert_eq!(br.computed_total_rows(), br.affected.total_rows);
    }
}
