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

/// One relation's per-op-type in-txn change footprint, measured from the
/// `pg_stat_xact_n_tup_{ins,upd,del}` deltas (SPEC §4).
///
/// The guarded apply reconciles its own deltas against this **per op-type**, not
/// against a collapsed total: a relation the dry-run predicted to only `ins` that
/// the apply sees `del`/`upd` is the **data-loss direction** and must abort —
/// even when the *total* matches (an INSERT-of-N prediction satisfied by a DELETE
/// of N pre-existing rows). Collapsing to a single total discards op-type and is
/// the exact catastrophic false-negative this struct exists to close.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpCounts {
    /// Rows inserted in the relation within the txn (`pg_stat_xact_n_tup_ins`).
    #[serde(default)]
    pub ins: u64,
    /// Rows updated in the relation within the txn (`pg_stat_xact_n_tup_upd`).
    #[serde(default)]
    pub upd: u64,
    /// Rows deleted in the relation within the txn (`pg_stat_xact_n_tup_del`).
    #[serde(default)]
    pub del: u64,
}

impl OpCounts {
    /// Construct from the three op-type counts.
    pub const fn new(ins: u64, upd: u64, del: u64) -> Self {
        OpCounts { ins, upd, del }
    }

    /// Total tuples changed across all op types (`ins + upd + del`) — a display /
    /// cross-check helper. The **guard does not use this**: reconciliation is
    /// per-op-type so an op-type substitution (same total, different op) aborts.
    pub fn total(&self) -> u64 {
        self.ins.saturating_add(self.upd).saturating_add(self.del)
    }

    /// Whether this footprint records no change at all.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

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
    /// The **full** per-relation, **per-op-type** in-txn change footprint the
    /// dry-run measured via `pg_stat_xact_n_tup_{ins,upd,del}` deltas (SPEC §4) —
    /// the target, every cascade child, **and every relation a fired trigger wrote
    /// to** (e.g. an audit table). This is the symmetric prediction the guarded
    /// apply reconciles its own `pg_stat_xact_*` deltas against, **per op channel**
    /// ([`OpCounts`]): a write to a relation **not** in this map, **more** changes
    /// of any op type than recorded here, or **any** op type the prediction did not
    /// have (e.g. a `del` on an `ins`-only relation), is drift and aborts. It is the
    /// apply-time "0 catastrophic data-loss FN by construction" mechanism — and it
    /// is op-type-aware so an INSERT-of-N prediction can NOT be silently satisfied
    /// by a DELETE of N pre-existing rows (same total, opposite, destructive op).
    ///
    /// `#[serde(default)]` keeps the §10.1 wire contract backward-compatible: an
    /// older record without this field deserializes to an empty map (a guarded
    /// apply then has no predicted footprint to reconcile and must refuse — a
    /// stale grant cannot authorize a write, fail-closed).
    #[serde(default)]
    pub effect_by_table: BTreeMap<String, OpCounts>,
    /// Total rows affected across target + cascade.
    pub total_rows: u64,
}

/// The **absolute apply-time cap** a human approves for a guarded write (EPIC #91
/// PR-B). This is the **absolute-magnitude anchor** on an approved write that
/// replaced the exact-PK-set checksum (founder decision): the checksum pinned the
/// exact row *identity* set, but reconciliation is *relative* to the dry-run
/// prediction, `statement_timeout` is wall-clock, and the read-path `RoleBudget`
/// does not touch the write path — so without an absolute cap, nothing pinned the
/// absolute *magnitude* of an approved write once the checksum was dropped.
///
/// The cap is enforced **inside the apply txn** ([`crate::ApplyError`]-style abort
/// in `pgb_clone_orchestrator`): if the live write's actual magnitude (rows changed,
/// from `pg_stat_xact_*`, or WAL bytes generated) exceeds the approved cap, the
/// apply ABORTs (`CapExceeded`) with no mutation. Together with the
/// self-determined-predicate gate (identity), the `pg_stat_xact_*` reconciliation
/// (relative effect), and the pre-image coverage (reversibility), the cap carries
/// the deterministic floor without the exact-set checksum.
///
/// The cap is part of the signed §14.3 grant binding (a bound field), so a swapped
/// or absent cap fails the binding-hash check closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteCap {
    /// The maximum number of rows the approved write may change **across its full
    /// footprint** (target + cascades + trigger-written tables), measured from the
    /// apply txn's `pg_stat_xact_n_tup_{ins,upd,del}` deltas. An apply whose summed
    /// tuple changes exceed this aborts before commit.
    pub max_rows: u64,
    /// The maximum WAL bytes the approved write's apply txn may generate
    /// (`pg_current_wal_insert_lsn()` delta across the forward op, the same measure
    /// the dry-run records). An apply that generates more WAL than this aborts.
    pub max_wal_bytes: u64,
}

impl WriteCap {
    /// Construct a cap from explicit row + WAL-byte ceilings.
    pub const fn new(max_rows: u64, max_wal_bytes: u64) -> Self {
        WriteCap {
            max_rows,
            max_wal_bytes,
        }
    }
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
    /// How far behind prod the clone is, in WAL bytes. Captured and propagated for
    /// audit; the SPEC §10.5(c) staleness-ceiling reject is the **S0 fidelity-spike
    /// binary's** pass criterion, not a `clone-orchestrator` gate (no ceiling
    /// enforcement exists here — the field is informational on this path).
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

    /// The **full predicted footprint magnitude** the apply reconciles against:
    /// the sum of every relation's `pg_stat_xact_*` op counts in
    /// [`Affected::effect_by_table`] (target + cascades + trigger-written tables),
    /// across all three op channels. This is the dry-run's measured **absolute
    /// magnitude** — the basis for the suggested cap. Falls back to
    /// [`computed_total_rows`](Self::computed_total_rows) when the backend recorded
    /// no `effect_by_table` (an older record), so the suggestion is never zero for a
    /// write that touched rows.
    pub fn predicted_total_tuples(&self) -> u64 {
        let measured: u64 = self
            .affected
            .effect_by_table
            .values()
            .map(|c| c.total())
            .fold(0u64, |a, b| a.saturating_add(b));
        if measured == 0 {
            self.computed_total_rows()
        } else {
            measured
        }
    }

    /// A **suggested absolute cap** (EPIC #91 PR-B) the CLI pre-fills the approval
    /// with, sized from the dry-run's measured magnitude plus `headroom` (a fraction
    /// such as `0.10` for +10%). The human may then tighten it (a smaller bound) or
    /// raise it per §14.2 — the suggestion is a starting point, not a ceiling on the
    /// approver.
    ///
    /// - `max_rows` = `ceil(predicted_total_tuples × (1 + headroom))`, with a floor of
    ///   the predicted total itself (so a 0% headroom still admits the predicted
    ///   write) and a floor of 1 for a measured-but-rounding-to-zero footprint;
    /// - `max_wal_bytes` = `ceil(wal_bytes × (1 + headroom))`, floored at the measured
    ///   `wal_bytes` (and at 0 when the dry-run generated no WAL — the apply then
    ///   commits only if it likewise generates none).
    ///
    /// Saturating throughout so a pathological prediction cannot overflow the cap.
    pub fn suggested_cap(&self, headroom: f64) -> WriteCap {
        let headroom = if headroom.is_finite() && headroom >= 0.0 {
            headroom
        } else {
            0.0
        };
        let with_headroom = |base: u64| -> u64 {
            // base + ceil(base * headroom), saturating, never below `base`. We add
            // the headroom as a separate ceil'd term (rather than `base * (1 +
            // headroom)`) so binary-float drift cannot inflate the result by a whole
            // unit (e.g. `100 * 1.10 == 110.0000000001` ceil'ing to 111). A tiny
            // epsilon absorbs the residual float error in the extra term itself.
            let extra = (base as f64) * headroom;
            if !extra.is_finite() {
                return u64::MAX;
            }
            let extra_ceiled = (extra - 1e-9).ceil().max(0.0);
            if extra_ceiled >= (u64::MAX as f64) {
                return u64::MAX;
            }
            base.saturating_add(extra_ceiled as u64)
        };
        let rows_base = self.predicted_total_tuples().max(1);
        WriteCap {
            max_rows: with_headroom(rows_base),
            max_wal_bytes: with_headroom(self.wal_bytes),
        }
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

    /// `effect_by_table` carries the per-op-type counts ([`OpCounts`]) and
    /// round-trips through serde. This is what lets the guarded apply reconcile each
    /// op channel independently (and so refuse an op-type substitution).
    #[test]
    fn effect_by_table_carries_per_op_type_counts_and_round_trips() {
        const J: &str = r#"{
            "proposal_id": "p-op",
            "clone_lsn": "0/0",
            "staleness_lsn_bytes": 0,
            "affected": {
                "by_table": { "public.accounts": 4 },
                "cascade_by_table": {},
                "pk_set_checksum": { "public.accounts": "sha256:x" },
                "effect_by_table": {
                    "public.accounts": { "ins": 0, "upd": 4, "del": 0 },
                    "public.account_audit": { "ins": 4, "upd": 0, "del": 0 }
                },
                "total_rows": 4
            },
            "triggers_fired": [],
            "locks": [],
            "max_lock_mode": "RowExclusiveLock",
            "duration_ms": 1,
            "wal_bytes": 0,
            "constraint_violations": [],
            "reversible": true,
            "inverse_kind": "PREIMAGE_UPSERT",
            "predicate_volatile": false
        }"#;
        let br: BlastRadius = serde_json::from_str(J).expect("per-op record must parse");
        let audit = br.affected.effect_by_table["public.account_audit"];
        assert_eq!(audit.ins, 4);
        assert_eq!(audit.del, 0);
        assert_eq!(audit.total(), 4);
        let acct = br.affected.effect_by_table["public.accounts"];
        assert_eq!(acct.upd, 4);
        // Round-trips without loss.
        let s = serde_json::to_string(&br).expect("serialize");
        let back: BlastRadius = serde_json::from_str(&s).expect("re-parse");
        assert_eq!(br, back);
    }

    /// A partial `OpCounts` (some op fields omitted) defaults the missing channels
    /// to 0 — fail-closed, never inferring a write that was not measured.
    #[test]
    fn op_counts_missing_channels_default_to_zero() {
        let c: OpCounts = serde_json::from_str(r#"{ "del": 3 }"#).expect("partial OpCounts");
        assert_eq!(c, OpCounts::new(0, 0, 3));
        assert_eq!(c.total(), 3);
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

    // ---- WriteCap + suggested_cap (EPIC #91 PR-B absolute magnitude anchor) ----

    #[test]
    fn write_cap_round_trips_through_serde() {
        let cap = WriteCap::new(42, 4096);
        let json = serde_json::to_string(&cap).expect("serialize cap");
        let back: WriteCap = serde_json::from_str(&json).expect("re-parse cap");
        assert_eq!(cap, back);
        assert_eq!(back.max_rows, 42);
        assert_eq!(back.max_wal_bytes, 4096);
    }

    /// `predicted_total_tuples` sums the FULL measured footprint across all op
    /// channels (target + cascade + trigger-written tables), not a single relation.
    #[test]
    fn predicted_total_tuples_sums_the_full_effect_footprint() {
        let mut effect = BTreeMap::new();
        effect.insert("public.orders".to_string(), OpCounts::new(0, 4, 0));
        effect.insert("public.order_items".to_string(), OpCounts::new(0, 0, 6));
        effect.insert("public.orders_audit".to_string(), OpCounts::new(4, 0, 0));
        let br = BlastRadius {
            proposal_id: "p".into(),
            clone_lsn: "0/0".into(),
            staleness_lsn_bytes: 0,
            affected: Affected {
                by_table: BTreeMap::new(),
                cascade_by_table: BTreeMap::new(),
                pk_set_checksum: BTreeMap::new(),
                effect_by_table: effect,
                total_rows: 10,
            },
            triggers_fired: vec![],
            locks: vec![],
            max_lock_mode: LockMode::RowExclusiveLock,
            duration_ms: 5,
            wal_bytes: 1000,
            constraint_violations: vec![],
            reversible: true,
            inverse_kind: InverseKind::PreimageUpsert,
            predicate_volatile: false,
        };
        // 4 + 6 + 4 = 14 tuples across the full footprint.
        assert_eq!(br.predicted_total_tuples(), 14);
    }

    /// `suggested_cap(0.10)` sizes both ceilings at +10% (ceiled), never below the
    /// measured base — so the predicted write always fits the suggestion.
    #[test]
    fn suggested_cap_adds_headroom_and_never_under_predicts() {
        let mut effect = BTreeMap::new();
        effect.insert("public.orders".to_string(), OpCounts::new(0, 100, 0));
        let br = BlastRadius {
            proposal_id: "p".into(),
            clone_lsn: "0/0".into(),
            staleness_lsn_bytes: 0,
            affected: Affected {
                by_table: BTreeMap::new(),
                cascade_by_table: BTreeMap::new(),
                pk_set_checksum: BTreeMap::new(),
                effect_by_table: effect,
                total_rows: 100,
            },
            triggers_fired: vec![],
            locks: vec![],
            max_lock_mode: LockMode::RowExclusiveLock,
            duration_ms: 5,
            wal_bytes: 2000,
            constraint_violations: vec![],
            reversible: true,
            inverse_kind: InverseKind::PreimageUpsert,
            predicate_volatile: false,
        };
        let cap = br.suggested_cap(0.10);
        assert_eq!(cap.max_rows, 110, "100 rows +10% = 110");
        assert_eq!(cap.max_wal_bytes, 2200, "2000 WAL bytes +10% = 2200");
        // Zero headroom still admits the predicted write exactly.
        let tight = br.suggested_cap(0.0);
        assert_eq!(tight.max_rows, 100);
        assert_eq!(tight.max_wal_bytes, 2000);
        // A negative / non-finite headroom is clamped to 0 (fail-safe, never < base).
        let clamped = br.suggested_cap(-1.0);
        assert_eq!(clamped.max_rows, 100);
        let nan = br.suggested_cap(f64::NAN);
        assert_eq!(nan.max_rows, 100);
    }

    /// With no measured `effect_by_table` (a legacy record) the suggestion falls
    /// back to `computed_total_rows` so it is never zero for a write that touched
    /// rows, and `max_rows` is floored at 1.
    #[test]
    fn suggested_cap_falls_back_when_no_effect_measured() {
        let br: BlastRadius = serde_json::from_str(SAMPLE_JSON).expect("sample must parse");
        // SAMPLE has empty effect_by_table → falls back to computed_total_rows.
        assert!(br.affected.effect_by_table.is_empty());
        let cap = br.suggested_cap(0.0);
        assert_eq!(cap.max_rows, br.computed_total_rows().max(1));
    }
}
