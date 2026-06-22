//! The **real-floor probes** (SPEC §13.5 deterministic plane): each runs a
//! payload through an actual merged enforcement component and reports the
//! observed [`Observed`] outcome. The runner ([`crate::runner`]) maps that onto a
//! [`Verdict`](crate::verdict::Verdict) and the per-scenario pass predicate.
//!
//! These are the **same** public APIs the product ships — `pgb_proxy`'s
//! frontend-frame gate + read-only classifier, `pgb_proxy::Budget`'s byte/row
//! cutoff, `pgb_core::certify`'s default-deny set, and `pgb_clone_orchestrator`'s
//! `guarded_apply` data-loss guards — driven deterministically (pinned PG via the
//! scripted `ApplyConn`, no wall-clock via `MockClock`). No re-implementation of
//! the floor lives here; the gate exercises the floor itself.

use std::collections::BTreeMap;

use pgb_clone_orchestrator::{
    guarded_apply, ApplyConn, ApplyError, CapturedRow, ForwardResult, PitrConfig, RelationChange,
    WriteKind,
};
use pgb_core::blast_radius::Affected;
use pgb_core::{
    BlastRadius, InverseKind, LockMode, MockClock, NoopBarrier, OpCounts, PkChecksum, PkSetBuilder,
    PkTuple, PkValue,
};
use pgb_policy::{RoleBudget, WindowBudget};
use pgb_proxy::{Budget, BudgetOutcome, Enforcement, GateDecision};

/// What a floor probe observed: the floor outcome plus the quantities the
/// per-scenario pass predicate checks (SPEC §10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The floor's verdict for the payload.
    pub verdict: crate::verdict::Verdict,
    /// Bytes streamed before the cutoff fired (exfil pass predicate: ≤ B).
    pub bytes_out: u64,
    /// Rows streamed before the cutoff fired.
    pub rows_out: u64,
    /// The single-shot byte budget B in force (so the runner can assert
    /// `bytes_out ≤ B`).
    pub budget_bytes: u64,
    /// Prod rows IRREVERSIBLY destroyed by the action (data-loss pass predicate:
    /// must be 0, OR `reverted_with_verified_diff`).
    pub prod_rows_touched: u64,
    /// Whether a committed-then-slipped write was reverted to the golden
    /// pre-state with a verified diff.
    pub reverted_with_verified_diff: bool,
    /// A short machine reason (the floor's code / the abort kind) — for diagnostics.
    pub reason: String,
}

// --- Proxy frontend-frame gate (statement-stacking, write-on-read, COPY) ------

/// Run a payload through the proxy's read-path gate exactly as the proxy does:
/// the simple-query (`'Q'`) statement-stacking path is **rejected**, COPY is
/// rejected, and an extended-protocol `Parse` is classified read-only. Returns
/// the observed verdict (BLOCK on any refusal/block, ALLOW for a provable read).
pub fn probe_proxy_read_gate(sql: &str, via_simple_query: bool) -> Observed {
    let gate = Enforcement::new();
    let msg = if via_simple_query {
        // The statement-stacking vector arrives over the simple-query protocol.
        pgb_pgwire::FrontendMessage::Query {
            sql: sql.to_string(),
        }
    } else {
        pgb_pgwire::FrontendMessage::Parse {
            statement: String::new(),
            sql: sql.to_string(),
            param_types: vec![],
        }
    };
    let (verdict, reason) = match gate.gate(&msg) {
        GateDecision::Allow { .. } => (crate::verdict::Verdict::Allow, "allow".to_string()),
        GateDecision::Reject { code, .. } => (crate::verdict::Verdict::Block, code.to_string()),
        GateDecision::Block { code, .. } => (crate::verdict::Verdict::Block, code.to_string()),
    };
    Observed {
        verdict,
        bytes_out: 0,
        rows_out: 0,
        budget_bytes: 0,
        prod_rows_touched: 0,
        reverted_with_verified_diff: false,
        reason,
    }
}

// --- Proxy byte/row mid-stream cutoff (exfil-by-volume → BOUND) ---------------

/// A single-shot role budget with the given byte/row caps (the per-window cap is
/// set generously high so the single-shot cutoff is what trips in this probe).
fn role_budget(max_bytes: u64, max_rows: u64) -> RoleBudget {
    RoleBudget {
        max_bytes,
        max_rows,
        max_plan_cost: RoleBudget::DEFAULT_MAX_PLAN_COST,
        max_plan_rows: RoleBudget::DEFAULT_MAX_PLAN_ROWS,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: max_bytes.saturating_mul(1000),
            max_rows: max_rows.saturating_mul(1000),
        },
    }
}

/// Stream `n_rows` of `row_bytes` each through the proxy's single-shot byte/row
/// cutoff under a role budget of `(max_bytes, max_rows)`. Models an
/// exfil-by-volume read: the floor forwards rows until forwarding the next would
/// breach the budget, then cuts off. The observed `bytes_out`/`rows_out` are what
/// leaked *before* the cutoff — the bounded-disclosure quantity (SPEC §13.2). The
/// verdict is BOUND iff the cutoff fired, ALLOW iff the whole read fit.
pub fn probe_byte_cutoff(n_rows: u64, row_bytes: u64, max_bytes: u64, max_rows: u64) -> Observed {
    let mut budget = Budget::for_role(&role_budget(max_bytes, max_rows));
    let mut last_bytes = 0u64;
    let mut last_rows = 0u64;
    let mut cut = false;
    let mut reason = "within_budget".to_string();
    for _ in 0..n_rows {
        match budget.charge_row(row_bytes) {
            BudgetOutcome::Within { bytes, rows } => {
                last_bytes = bytes;
                last_rows = rows;
            }
            BudgetOutcome::Exceeded { cap, bytes, rows } => {
                last_bytes = bytes;
                last_rows = rows;
                cut = true;
                reason = cap.code().to_string();
                break;
            }
        }
    }
    Observed {
        verdict: if cut {
            crate::verdict::Verdict::Bound
        } else {
            crate::verdict::Verdict::Allow
        },
        bytes_out: last_bytes,
        rows_out: last_rows,
        budget_bytes: max_bytes,
        prod_rows_touched: 0,
        reverted_with_verified_diff: false,
        reason,
    }
}

// --- Guarded-apply data-loss guards (drift / cascade / op-sub → abort) --------

/// A scripted `ApplyConn` that drives the REAL `guarded_apply` engine
/// deterministically (the same scripted-connection seam the engine's own unit
/// tests + the env-gated PG18 IT use). A scenario describes the apply-time world
/// (drift, trigger writes, cascade over-deletes) and `guarded_apply` decides.
struct ScriptedConn {
    /// Per-relation PK set the apply-time recompute returns (drift injection).
    recompute_ids: BTreeMap<String, Vec<i64>>,
    /// PK set the forward op writes (target) via RETURNING.
    written_ids: Vec<i64>,
    /// Per-relation in-txn `pg_stat_xact_*` tuple deltas (full-effect recon).
    tuple_deltas: Vec<RelationChange>,
    /// Per-cascade-relation captured pre-image ids (for the reversible-capture check).
    cascade_preimage_ids: BTreeMap<String, Vec<i64>>,
    committed: bool,
    rolled_back: bool,
}

fn checksum_of(rel: &str, ids: &[i64]) -> PkChecksum {
    let mut b = PkSetBuilder::for_relation(rel);
    for &id in ids {
        b.push(PkTuple::single(PkValue::Int(id))).unwrap();
    }
    b.finalize().unwrap()
}

fn captured(ids: &[i64]) -> Vec<CapturedRow> {
    ids.iter()
        .map(|&id| CapturedRow {
            pk: PkTuple::single(PkValue::Int(id)),
            before_image: vec![("status".into(), PkValue::Text("open".into()))],
        })
        .collect()
}

impl ApplyConn for ScriptedConn {
    fn create_restore_point(&mut self, _label: &str) -> Result<String, ApplyError> {
        Ok("0/0".into())
    }
    fn begin(&mut self, _timeout_ms: u64) -> Result<(), ApplyError> {
        Ok(())
    }
    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
        let ids = self
            .recompute_ids
            .get(relation)
            .cloned()
            .unwrap_or_default();
        Ok(checksum_of(relation, &ids))
    }
    fn apply_forward(
        &mut self,
        _kind: WriteKind,
        _relation: &str,
        cascade_relations: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        let mut cascade_preimages = BTreeMap::new();
        for rel in cascade_relations {
            let ids = self
                .cascade_preimage_ids
                .get(rel)
                .cloned()
                .unwrap_or_default();
            cascade_preimages.insert(rel.clone(), captured(&ids));
        }
        Ok(ForwardResult {
            written: captured(&self.written_ids),
            cascade_preimages,
        })
    }
    fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
        Ok(self.tuple_deltas.clone())
    }
    fn commit(&mut self) -> Result<(), ApplyError> {
        self.committed = true;
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), ApplyError> {
        self.rolled_back = true;
        Ok(())
    }
}

/// A guarded-apply data-loss scenario the gate runs through the REAL engine.
///
/// The fields describe the dry-run grant (the predicted blast radius) and the
/// drifted apply-time world; `guarded_apply` reconciles them and the gate asserts
/// it aborts/reverts (never a silent destructive commit). This is the
/// pure-logic, deterministic form of the §13.2 write-side `T-FN-write` test.
pub struct DataLossCase {
    /// `schema.table` of the target.
    pub relation: String,
    /// The forward op kind.
    pub kind: WriteKind,
    /// The PK set the dry-run grant pinned for the target.
    pub grant_ids: Vec<i64>,
    /// The target's predicted per-op-type footprint.
    pub target_effect: OpCounts,
    /// Cascade relations: `(relation, grant_ids, predicted_effect)`.
    pub cascades: Vec<(String, Vec<i64>, OpCounts)>,
    /// Extra predicted-footprint relations beyond target+cascades (e.g. an audit
    /// table a trigger writes): `(relation, predicted_effect)`.
    pub extra_effect: Vec<(String, OpCounts)>,
    /// Apply-time PK recompute overrides (drift): `(relation, ids)`. Defaults to
    /// the grant ids when absent.
    pub recompute_override: Vec<(String, Vec<i64>)>,
    /// The PK set the forward op actually writes for the target (defaults to grant).
    pub written_override: Option<Vec<i64>>,
    /// The apply-time `pg_stat_xact_*` deltas (the drifted full effect).
    pub apply_deltas: Vec<(String, OpCounts)>,
    /// Per-cascade captured pre-image ids (for the reversible-capture check).
    pub cascade_preimage_ids: Vec<(String, Vec<i64>)>,
}

/// Run a [`DataLossCase`] through the real `guarded_apply`. Returns the observed
/// verdict: REVERTED (the guard aborted before commit → prod is byte-for-byte
/// unchanged, i.e. 0 prod rows touched, reverted with the verified
/// no-op/pre-state diff) or ALLOW (it committed — a catastrophic FN if the
/// scenario was dangerous).
pub fn probe_guarded_apply(case: &DataLossCase) -> Observed {
    let proposal_id = "gate";
    // Assemble the dry-run grant (predicted blast radius).
    let mut pk_set_checksum = BTreeMap::new();
    pk_set_checksum.insert(
        case.relation.clone(),
        checksum_of(&case.relation, &case.grant_ids).as_prefixed(),
    );
    let mut by_table = BTreeMap::new();
    by_table.insert(case.relation.clone(), case.grant_ids.len() as u64);
    let mut cascade_by_table = BTreeMap::new();
    let mut effect_by_table = BTreeMap::new();
    effect_by_table.insert(case.relation.clone(), case.target_effect);
    for (rel, ids, eff) in &case.cascades {
        cascade_by_table.insert(rel.clone(), ids.len() as u64);
        pk_set_checksum.insert(rel.clone(), checksum_of(rel, ids).as_prefixed());
        effect_by_table.insert(rel.clone(), *eff);
    }
    for (rel, eff) in &case.extra_effect {
        effect_by_table.insert(rel.clone(), *eff);
    }
    let total_rows = case.grant_ids.len() as u64
        + case
            .cascades
            .iter()
            .map(|(_, ids, _)| ids.len() as u64)
            .sum::<u64>();
    let inverse_kind = match case.kind {
        WriteKind::Update => InverseKind::PreimageUpsert,
        WriteKind::Delete => InverseKind::Insert,
    };
    let grant = BlastRadius {
        proposal_id: proposal_id.to_string(),
        clone_lsn: "0/0".into(),
        staleness_lsn_bytes: 0,
        affected: Affected {
            by_table,
            cascade_by_table,
            pk_set_checksum,
            effect_by_table,
            total_rows,
        },
        triggers_fired: vec![],
        locks: vec![],
        max_lock_mode: LockMode::RowExclusiveLock,
        duration_ms: 5,
        wal_bytes: 0,
        constraint_violations: vec![],
        reversible: true,
        inverse_kind,
        predicate_volatile: false,
    };

    // Build the scripted apply-time world.
    let mut recompute_ids = BTreeMap::new();
    recompute_ids.insert(case.relation.clone(), case.grant_ids.clone());
    for (rel, ids, _) in &case.cascades {
        recompute_ids.insert(rel.clone(), ids.clone());
    }
    for (rel, ids) in &case.recompute_override {
        recompute_ids.insert(rel.clone(), ids.clone());
    }
    let written_ids = case
        .written_override
        .clone()
        .unwrap_or_else(|| case.grant_ids.clone());
    let tuple_deltas: Vec<RelationChange> = if case.apply_deltas.is_empty() {
        // Default: the target changed exactly its grant footprint (clean reconcile).
        vec![RelationChange {
            relation: case.relation.clone(),
            ins: case.target_effect.ins,
            upd: case.target_effect.upd,
            del: case.target_effect.del,
        }]
    } else {
        case.apply_deltas
            .iter()
            .map(|(rel, e)| RelationChange {
                relation: rel.clone(),
                ins: e.ins,
                upd: e.upd,
                del: e.del,
            })
            .collect()
    };
    let cascade_preimage_ids: BTreeMap<String, Vec<i64>> =
        case.cascade_preimage_ids.iter().cloned().collect();

    let mut conn = ScriptedConn {
        recompute_ids,
        written_ids,
        tuple_deltas,
        cascade_preimage_ids,
        committed: false,
        rolled_back: false,
    };

    let result = guarded_apply(
        proposal_id,
        case.kind,
        &case.relation,
        &grant,
        PitrConfig::disabled(),
        &mut conn,
        &NoopBarrier::new(),
        &MockClock::new(),
    );

    match result {
        Ok(_applied) => Observed {
            // The apply COMMITTED. For a dangerous data-loss case this is the
            // catastrophic FN the gate must catch.
            verdict: crate::verdict::Verdict::Allow,
            bytes_out: 0,
            rows_out: 0,
            budget_bytes: 0,
            prod_rows_touched: total_rows,
            reverted_with_verified_diff: false,
            reason: "committed".to_string(),
        },
        Err(e) => Observed {
            // A guard fired → ROLLBACK. Nothing committed: prod is byte-for-byte
            // unchanged (0 rows irreversibly touched), i.e. reverted to the
            // golden pre-state with the verified (no-op) diff (SPEC §13.2
            // T-FN-write: rows-touched == 0 OR reverted-with-verified-diff).
            verdict: crate::verdict::Verdict::Reverted,
            bytes_out: 0,
            rows_out: 0,
            budget_bytes: 0,
            prod_rows_touched: 0,
            reverted_with_verified_diff: true,
            reason: format!("{e}"),
        },
    }
}

// --- Default-deny certified-action set (TRUNCATE/DROP/ALTER/volatile → REFUSED) -

/// Run an [`Operation`](pgb_core::inverse::Operation) through the REAL default-deny
/// `certify` choke point. Returns REFUSED iff `certify` rejects it (never
/// executed), ALLOW iff it is in the closed certified set.
pub fn probe_certify(op: &pgb_core::inverse::Operation) -> Observed {
    match pgb_core::inverse::certify(op) {
        Ok(_action) => Observed {
            verdict: crate::verdict::Verdict::Allow,
            bytes_out: 0,
            rows_out: 0,
            budget_bytes: 0,
            prod_rows_touched: 0,
            reverted_with_verified_diff: false,
            reason: "certified".to_string(),
        },
        Err(refused) => Observed {
            verdict: crate::verdict::Verdict::Refused,
            bytes_out: 0,
            rows_out: 0,
            budget_bytes: 0,
            prod_rows_touched: 0,
            reverted_with_verified_diff: false,
            reason: format!("{refused}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::inverse::Operation;

    #[test]
    fn stacking_over_simple_query_is_blocked() {
        let o = probe_proxy_read_gate("COMMIT; DROP SCHEMA public CASCADE", true);
        assert_eq!(o.verdict, crate::verdict::Verdict::Block);
        assert_eq!(o.reason, "simple_query_rejected");
    }

    #[test]
    fn legit_select_is_allowed() {
        let o = probe_proxy_read_gate("SELECT id FROM public.orders WHERE id = 1", false);
        assert_eq!(o.verdict, crate::verdict::Verdict::Allow);
    }

    #[test]
    fn exfil_by_volume_is_bounded_at_budget() {
        // 1000 rows of 100 bytes each, but the byte budget is 1000 → cutoff.
        let o = probe_byte_cutoff(1000, 100, 1000, 1_000_000);
        assert_eq!(o.verdict, crate::verdict::Verdict::Bound);
        assert!(o.bytes_out <= o.budget_bytes, "bounded disclosure ≤ B");
    }

    #[test]
    fn truncate_is_refused() {
        let o = probe_certify(&Operation::Truncate);
        assert_eq!(o.verdict, crate::verdict::Verdict::Refused);
    }

    #[test]
    fn out_of_predicate_trigger_delete_is_reverted() {
        // UPDATE id%2=0 RETURNING={2,4,6,8}, predicted upd=4 del=0; but a trigger
        // DELETEs id=7 (out of predicate) → del=1 → the real guard aborts.
        let case = DataLossCase {
            relation: "public.orders".into(),
            kind: WriteKind::Update,
            grant_ids: vec![2, 4, 6, 8],
            target_effect: OpCounts::new(0, 4, 0),
            cascades: vec![],
            extra_effect: vec![],
            recompute_override: vec![],
            written_override: None,
            apply_deltas: vec![("public.orders".into(), OpCounts::new(0, 4, 1))],
            cascade_preimage_ids: vec![],
        };
        let o = probe_guarded_apply(&case);
        assert_eq!(o.verdict, crate::verdict::Verdict::Reverted);
        assert_eq!(o.prod_rows_touched, 0);
        assert!(o.reverted_with_verified_diff);
    }
}
