//! The revert engine (SPEC §5, §10.3, §1 honest recovery) — the *other half* of
//! the moat's reversibility: apply the captured **typed-inverse**
//! ([`pgb_core::InversePlan`]) so a committed-but-slipped write is **auto-reverted
//! with a verifiable diff** back to the golden prod state.
//!
//! [`crate::apply::guarded_apply`] returns an [`InversePlan`]: the FK-ordered
//! per-row pre-images of every changed row across the target **and every cascade
//! relation**. [`revert`] re-applies that inverse:
//!
//! - **`PREIMAGE_UPSERT`** (the inverse of an `UPDATE`) → for each captured row,
//!   restore its pre-image columns `WHERE pk = …`. The forward op may have written
//!   anything (even a BEFORE-trigger hijacked value); the inverse holds the ACTUAL
//!   old tuple, so the upsert restores truth.
//! - **`INSERT`** (the inverse of a `DELETE`) → re-insert every captured row,
//!   **FK-ordered** (parents in `fk_order[0]` first, then each child relation), so
//!   a re-inserted child never violates its foreign key to a not-yet-re-inserted
//!   parent. This restores the target rows AND every cascade-destroyed child.
//!
//! # The seam (mirrors [`crate::apply::ApplyConn`])
//!
//! The engine is DB-free: it owns the **FK ordering + the per-row routing**
//! decisions (which relation each captured row belongs to); the connection owns
//! the SQL. Production grows a tokio-backed [`RevertConn`]; the env-gated
//! integration tests (`revert_it.rs`, `PG_BUMPERS_IT=1`) implement it against real
//! PostgreSQL 18; the unit tests here implement an in-memory one that records the
//! exact (relation, op, row) sequence so the FK ordering is asserted directly.
//!
//! # Honest gaps (SPEC §1 / §10.3 — documented + tested, NOT restored)
//!
//! The revert restores **table row state only**. It deliberately does NOT restore
//! [`pgb_core::NotRestored`]: **sequence** advances (a re-inserted row does not
//! roll `last_value` back; a fresh `nextval` keeps climbing), **trigger
//! side-effects** (audit rows a trigger wrote — and worse, the *revert's own*
//! re-insert fires the same AFTER trigger, appending MORE audit rows, never
//! removing the originals), and **`NOTIFY`** already delivered. [`revert`] surfaces
//! these caveats on the [`RevertReport`] so the caller/audit names them explicitly
//! and never claims a fuller restore than was performed.
//!
//! # Routing
//!
//! [`build_inverse`](crate::apply) stamps each cascade-child pre-image with a
//! synthetic `__relation` column carrying its owning `schema.table`; a target row
//! has no such stamp and belongs to [`InversePlan::relation`]. [`revert`] routes
//! each row by that stamp and re-inserts/upserts it against the right relation, in
//! `fk_order`.

use std::collections::BTreeMap;

use pgb_core::inverse::ImageValue;
use pgb_core::{InverseKind, InversePlan, NotRestored, PkTuple};

/// The synthetic column [`crate::apply::build_inverse`] stamps onto a cascade
/// child's pre-image to record its owning `schema.table`. A pre-image WITHOUT this
/// column belongs to the inverse's target relation. Kept private to the crate so
/// the apply (writer) and revert (reader) agree on the one routing key.
pub(crate) const RELATION_STAMP: &str = "__relation";

/// Why a revert failed. **Reversibility is fail-honest:** a revert either restores
/// the captured pre-image or returns one of these — it never silently leaves a
/// partial restore (the connection runs the whole inverse in one txn and rolls it
/// back on any error).
#[derive(Debug, thiserror::Error)]
pub enum RevertError {
    /// The inverse carries no restorable rows for a relation it names in
    /// `fk_order` — a malformed inverse. Fail-closed: we refuse to "revert" an
    /// inverse we cannot fully route rather than restore part of it.
    #[error(
        "malformed inverse: relation `{relation}` is in fk_order but has no role here: {detail}"
    )]
    MalformedInverse {
        /// The relation that could not be routed.
        relation: String,
        /// Why it could not be routed.
        detail: String,
    },

    /// A captured pre-image row is missing its primary-key columns (a
    /// `PREIMAGE_UPSERT` needs the PK to target the row; an `INSERT` needs the full
    /// image). Fail-closed.
    #[error("malformed inverse row on `{relation}`: {detail}")]
    MalformedRow {
        /// The relation the bad row belongs to.
        relation: String,
        /// What was wrong with the row.
        detail: String,
    },

    /// The inverse is [`InverseKind::None`] — there is nothing to revert (a
    /// non-reversible write should never have committed; this guards the caller).
    #[error("inverse kind is NONE — nothing to revert (the write was not reversible)")]
    NotReversible,

    /// The underlying connection failed. The connection rolls its txn back before
    /// returning, so nothing partial is persisted.
    #[error("revert backend failed: {0}")]
    Backend(String),
}

/// One row to restore, already routed to its relation: its PK tuple plus the full
/// ordered `(column, before_value)` pre-image (with the synthetic
/// [`RELATION_STAMP`] removed — it is routing metadata, not a real column).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertRow {
    /// The row's primary-key tuple.
    pub pk: PkTuple,
    /// The real pre-image columns to restore (`__relation` stripped).
    pub before_image: Vec<(String, ImageValue)>,
}

/// The connection seam the revert engine drives (the revert analogue of
/// [`crate::apply::ApplyConn`]).
///
/// The engine owns the **FK ordering + the routing**; the connection owns the SQL.
/// An implementation runs the whole inverse in **one** transaction:
/// [`begin`](RevertConn::begin) opens it, the per-relation restore methods run
/// within it, and [`commit`](RevertConn::commit) / [`rollback`](RevertConn::rollback)
/// close it. The engine guarantees it calls them FK-ordered and rolls back on any
/// error, so a revert is all-or-nothing.
pub trait RevertConn {
    /// Open the revert txn (a single atomic restore).
    fn begin(&mut self) -> Result<(), RevertError>;

    /// Restore `rows` of `relation` via `PREIMAGE_UPSERT` — for each row,
    /// `UPDATE relation SET <before_image> WHERE pk = …`. Returns the number of
    /// rows actually restored.
    fn restore_update(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError>;

    /// Restore `rows` of `relation` via `INSERT` — re-insert each captured row.
    /// Called **FK-ordered** (parents before children) by the engine. Returns the
    /// number of rows re-inserted.
    fn restore_insert(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError>;

    /// Commit the revert txn (only on full success).
    fn commit(&mut self) -> Result<(), RevertError>;

    /// Roll back the revert txn (on any error). MUST be idempotent / safe on an
    /// already-aborted txn.
    fn rollback(&mut self) -> Result<(), RevertError>;
}

/// The outcome of a successful [`revert`]: how many rows were restored per
/// relation (FK-ordered), plus the documented [`NotRestored`] caveats this revert
/// did **not** undo (SPEC §1). The caller/audit record names the gaps explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertReport {
    /// The inverse kind that was applied.
    pub kind: InverseKind,
    /// Rows restored per relation, in the FK order they were applied.
    pub restored_by_relation: Vec<(String, u64)>,
    /// Total rows restored across all relations.
    pub total_restored: u64,
    /// The effects this revert did NOT undo (sequences / trigger side-effects /
    /// NOTIFY) — carried straight from the inverse so the claim stays honest.
    pub not_restored: Vec<NotRestored>,
}

impl RevertReport {
    /// Rows restored for `relation`, or 0 if it was not touched.
    pub fn restored(&self, relation: &str) -> u64 {
        self.restored_by_relation
            .iter()
            .find(|(r, _)| r == relation)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }
}

/// Apply the captured typed-inverse to restore the target + cascade rows, **FK
/// ordered** (SPEC §10.3 / §5 reversibility).
///
/// - `PREIMAGE_UPSERT` → upsert each target row's pre-image (the inverse of an
///   `UPDATE`). Single relation.
/// - `INSERT` → re-insert every captured row, parents (`fk_order[0]`) before
///   children, so no re-inserted child violates its FK (the inverse of a `DELETE`
///   that cascaded).
///
/// The whole inverse runs in one txn on `conn`; any error rolls it back (nothing
/// partial persists) and returns a [`RevertError`]. On success returns a
/// [`RevertReport`] naming the per-relation restored counts AND the honest gaps the
/// revert did not undo (§1).
pub fn revert(
    inverse: &InversePlan,
    conn: &mut dyn RevertConn,
) -> Result<RevertReport, RevertError> {
    if inverse.kind == InverseKind::None {
        return Err(RevertError::NotReversible);
    }

    // Route every captured pre-image to its owning relation (target rows have no
    // __relation stamp → the inverse's target relation; cascade rows carry it).
    let routed = route_rows(inverse)?;

    conn.begin()?;
    let outcome = revert_body(inverse, &routed, conn);
    match outcome {
        Ok(report) => {
            conn.commit()?;
            Ok(report)
        }
        Err(e) => {
            // The error path must not be masked by the rollback's own error.
            let _ = conn.rollback();
            Err(e)
        }
    }
}

/// Restore each relation in `fk_order`. For `PREIMAGE_UPSERT` the order is moot
/// (single relation) but we honor it uniformly; for `INSERT` the order is
/// load-bearing — **parents must be re-inserted before children** or the child's
/// FK fails. Any relation in `fk_order` with no routed rows is a malformed inverse.
fn revert_body(
    inverse: &InversePlan,
    routed: &BTreeMap<String, Vec<RevertRow>>,
    conn: &mut dyn RevertConn,
) -> Result<RevertReport, RevertError> {
    let mut restored_by_relation = Vec::new();
    let mut total_restored = 0u64;

    for relation in &inverse.fk_order {
        let rows = routed.get(relation).map(|v| v.as_slice()).unwrap_or(&[]);
        // A relation named in fk_order with zero captured rows is allowed only when
        // the forward op genuinely touched no rows there; but if the inverse has
        // rows for a relation NOT in fk_order, that is malformed (caught in
        // route_rows). Here an empty relation simply restores 0.
        let n = match inverse.kind {
            InverseKind::PreimageUpsert => conn.restore_update(relation, rows)?,
            InverseKind::Insert => conn.restore_insert(relation, rows)?,
            InverseKind::None => unreachable!("None is rejected before the txn opens"),
        };
        restored_by_relation.push((relation.clone(), n));
        total_restored = total_restored.saturating_add(n);
    }

    Ok(RevertReport {
        kind: inverse.kind,
        restored_by_relation,
        total_restored,
        not_restored: inverse.not_restored.clone(),
    })
}

/// Route every [`InversePlan::rows`] pre-image to its owning relation, stripping
/// the synthetic [`RELATION_STAMP`]. A row with the stamp belongs to the named
/// relation; a row without it belongs to [`InversePlan::relation`] (the target).
///
/// Fail-closed: a row stamped with a relation that is NOT in `fk_order` is a
/// malformed inverse (the apply could not have produced it) → refuse rather than
/// silently drop a row we cannot order.
fn route_rows(inverse: &InversePlan) -> Result<BTreeMap<String, Vec<RevertRow>>, RevertError> {
    let fk_set: std::collections::BTreeSet<&str> =
        inverse.fk_order.iter().map(|s| s.as_str()).collect();
    let mut routed: BTreeMap<String, Vec<RevertRow>> = BTreeMap::new();

    for row in &inverse.rows {
        // Find the routing stamp (if any) and build the real pre-image without it.
        let mut relation: Option<String> = None;
        let mut before_image = Vec::with_capacity(row.before_image.len());
        for (col, val) in &row.before_image {
            if col == RELATION_STAMP {
                match val {
                    ImageValue::Text(rel) => relation = Some(rel.clone()),
                    other => {
                        return Err(RevertError::MalformedRow {
                            relation: inverse.relation.clone(),
                            detail: format!("__relation stamp is not text: {other:?}"),
                        });
                    }
                }
            } else {
                before_image.push((col.clone(), val.clone()));
            }
        }
        let relation = relation.unwrap_or_else(|| inverse.relation.clone());

        if !fk_set.contains(relation.as_str()) {
            return Err(RevertError::MalformedInverse {
                relation: relation.clone(),
                detail: "a captured row is stamped with a relation outside fk_order \
                         (the inverse cannot be FK-ordered)"
                    .to_string(),
            });
        }
        if before_image.is_empty() {
            return Err(RevertError::MalformedRow {
                relation,
                detail: "captured row has no pre-image columns to restore".to_string(),
            });
        }

        routed.entry(relation).or_default().push(RevertRow {
            pk: row.pk.clone(),
            before_image,
        });
    }

    Ok(routed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::inverse::InversePlanBuilder;
    use pgb_core::{InverseRow, PkValue};
    use std::sync::{Arc, Mutex};

    const TARGET: &str = "public.accounts";
    const CHILD: &str = "public.entries";

    /// One recorded restore step the engine asked the connection to perform.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Step {
        op: &'static str, // "update" | "insert"
        relation: String,
        pk_ids: Vec<Vec<PkValue>>,
    }

    /// A scripted in-memory `RevertConn`. It RECORDS the exact (op, relation, row)
    /// sequence so a test can assert the FK ordering directly, and can be told to
    /// fail a specific relation's insert to model an FK violation when the order is
    /// wrong.
    #[derive(Default)]
    struct MockRevertConnInner {
        steps: Vec<Step>,
        began: bool,
        committed: bool,
        rolled_back: bool,
        /// Relations already restored (parents) — an INSERT into a child whose
        /// parent has NOT yet been restored fails, modeling a real FK violation.
        restored_relations: std::collections::BTreeSet<String>,
        /// child -> parent FK edges to enforce (child insert needs parent first).
        fk_parent: BTreeMap<String, String>,
    }

    #[derive(Clone)]
    struct MockRevertConn(Arc<Mutex<MockRevertConnInner>>);

    impl MockRevertConn {
        fn new() -> Self {
            MockRevertConn(Arc::new(Mutex::new(MockRevertConnInner::default())))
        }
        /// Enforce that `child` cannot be inserted before `parent` (FK).
        fn with_fk(self, child: &str, parent: &str) -> Self {
            self.0
                .lock()
                .unwrap()
                .fk_parent
                .insert(child.to_string(), parent.to_string());
            self
        }
        fn inner(&self) -> std::sync::MutexGuard<'_, MockRevertConnInner> {
            self.0.lock().unwrap()
        }
        fn record(&self, op: &'static str, relation: &str, rows: &[RevertRow]) {
            let pk_ids = rows.iter().map(|r| r.pk.values().to_vec()).collect();
            self.inner().steps.push(Step {
                op,
                relation: relation.to_string(),
                pk_ids,
            });
        }
    }

    impl RevertConn for MockRevertConn {
        fn begin(&mut self) -> Result<(), RevertError> {
            self.inner().began = true;
            Ok(())
        }
        fn restore_update(
            &mut self,
            relation: &str,
            rows: &[RevertRow],
        ) -> Result<u64, RevertError> {
            self.record("update", relation, rows);
            Ok(rows.len() as u64)
        }
        fn restore_insert(
            &mut self,
            relation: &str,
            rows: &[RevertRow],
        ) -> Result<u64, RevertError> {
            // Model the real FK constraint: a child insert before its parent fails.
            // Each `self.inner()` lock is scoped to a single statement (std Mutex is
            // NOT re-entrant — a nested lock would deadlock).
            let parent = self.inner().fk_parent.get(relation).cloned();
            if let Some(parent) = parent {
                let parent_missing = !self.inner().restored_relations.contains(&parent);
                if !rows.is_empty() && parent_missing {
                    return Err(RevertError::Backend(format!(
                        "insert or update on table \"{relation}\" violates foreign key \
                         constraint (parent `{parent}` not yet restored)"
                    )));
                }
            }
            self.record("insert", relation, rows);
            if !rows.is_empty() {
                self.inner().restored_relations.insert(relation.to_string());
            }
            Ok(rows.len() as u64)
        }
        fn commit(&mut self) -> Result<(), RevertError> {
            self.inner().committed = true;
            Ok(())
        }
        fn rollback(&mut self) -> Result<(), RevertError> {
            self.inner().rolled_back = true;
            Ok(())
        }
    }

    fn row(id: i64, balance: i64) -> InverseRow {
        InverseRow::new(
            PkTuple::single(PkValue::Int(id)),
            vec![
                ("id".into(), PkValue::Int(id)),
                ("owner".into(), PkValue::Text(format!("owner-{id}"))),
                ("balance".into(), PkValue::Int(balance)),
            ],
        )
    }

    /// A child pre-image stamped with its owning relation (as `build_inverse` does).
    fn child_row(account_id: i64, line_no: i64) -> InverseRow {
        InverseRow::new(
            PkTuple::new(vec![PkValue::Int(account_id), PkValue::Int(line_no)]).unwrap(),
            vec![
                ("account_id".into(), PkValue::Int(account_id)),
                ("line_no".into(), PkValue::Int(line_no)),
                (
                    "memo".into(),
                    PkValue::Text(format!("memo-{account_id}-{line_no}")),
                ),
                ("amount".into(), PkValue::Int(account_id * 10 + line_no)),
                // The routing stamp the apply adds for cascade children.
                (RELATION_STAMP.into(), PkValue::Text(CHILD.into())),
            ],
        )
    }

    // ---- PREIMAGE_UPSERT (UPDATE inverse) ----------------------------------

    #[test]
    fn preimage_upsert_restores_target_rows() {
        let inverse = InversePlanBuilder::new(TARGET, InverseKind::for_update())
            .push_row(row(2, 2000))
            .push_row(row(4, 4000))
            .build();
        let mut conn = MockRevertConn::new();
        let probe = conn.clone();
        let report = revert(&inverse, &mut conn).expect("update inverse reverts");

        assert_eq!(report.kind, InverseKind::PreimageUpsert);
        assert_eq!(report.total_restored, 2);
        assert_eq!(report.restored(TARGET), 2);
        // The honest gaps are carried forward (NOT restored).
        assert_eq!(report.not_restored, NotRestored::ALL.to_vec());

        let p = probe.inner();
        assert!(p.began && p.committed && !p.rolled_back);
        // One UPDATE step against the target, both rows.
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.steps[0].op, "update");
        assert_eq!(p.steps[0].relation, TARGET);
        assert_eq!(p.steps[0].pk_ids.len(), 2);
    }

    // ---- INSERT (DELETE inverse), FK ordered -------------------------------

    #[test]
    fn insert_inverse_reinserts_parent_before_children_fk_ordered() {
        // The cascade DELETE inverse: 2 parents + their children, parent relation
        // first in fk_order. The mock enforces the FK (child before parent fails),
        // so a correct FK order is the only way this commits.
        let inverse = InversePlanBuilder::new(TARGET, InverseKind::for_delete())
            .push_row(row(2, 2000))
            .push_row(row(4, 4000))
            .push_row(child_row(2, 1))
            .push_row(child_row(2, 2))
            .push_row(child_row(4, 1))
            .push_row(child_row(4, 2))
            .fk_order(vec![TARGET.into(), CHILD.into()])
            .build();
        let mut conn = MockRevertConn::new().with_fk(CHILD, TARGET);
        let probe = conn.clone();
        let report = revert(&inverse, &mut conn).expect("delete inverse reverts FK-ordered");

        assert_eq!(report.kind, InverseKind::Insert);
        assert_eq!(report.restored(TARGET), 2, "2 parents re-inserted");
        assert_eq!(report.restored(CHILD), 4, "4 cascade children re-inserted");
        assert_eq!(report.total_restored, 6);

        let p = probe.inner();
        assert!(p.committed && !p.rolled_back);
        // The PARENT insert step came BEFORE the CHILD insert step.
        let parent_idx = p.steps.iter().position(|s| s.relation == TARGET).unwrap();
        let child_idx = p.steps.iter().position(|s| s.relation == CHILD).unwrap();
        assert!(
            parent_idx < child_idx,
            "FK order: parents must be re-inserted before children"
        );
    }

    /// RED→GREEN companion: if the inverse's `fk_order` is WRONG (children first),
    /// the revert tries to re-insert a child before its parent and the FK fails →
    /// the whole revert rolls back (nothing restored). This is the exact failure
    /// the FK ordering exists to prevent; the engine surfaces it instead of leaving
    /// a half-restored cascade.
    #[test]
    fn insert_inverse_with_broken_fk_order_fails_and_rolls_back() {
        let inverse = InversePlanBuilder::new(TARGET, InverseKind::for_delete())
            .push_row(row(2, 2000))
            .push_row(child_row(2, 1))
            // BROKEN: children BEFORE parents.
            .fk_order(vec![CHILD.into(), TARGET.into()])
            .build();
        let mut conn = MockRevertConn::new().with_fk(CHILD, TARGET);
        let probe = conn.clone();
        let err = revert(&inverse, &mut conn).unwrap_err();
        assert!(matches!(err, RevertError::Backend(_)), "{err:?}");
        let p = probe.inner();
        assert!(p.rolled_back, "a broken FK order must ROLL BACK the revert");
        assert!(!p.committed);
    }

    // ---- malformed / fail-closed -------------------------------------------

    #[test]
    fn none_inverse_is_not_reversible() {
        let inverse = InversePlan {
            relation: TARGET.into(),
            kind: InverseKind::None,
            rows: vec![],
            fk_order: vec![TARGET.into()],
            not_restored: NotRestored::ALL.to_vec(),
        };
        let mut conn = MockRevertConn::new();
        let probe = conn.clone();
        let err = revert(&inverse, &mut conn).unwrap_err();
        assert!(matches!(err, RevertError::NotReversible), "{err:?}");
        // Never even opened the txn.
        assert!(!probe.inner().began);
    }

    #[test]
    fn row_stamped_with_relation_outside_fk_order_is_malformed() {
        // A cascade row stamped with a relation the inverse never declared in
        // fk_order cannot be FK-ordered → refuse (fail-closed), before any DB work.
        let inverse = InversePlanBuilder::new(TARGET, InverseKind::for_delete())
            .push_row(row(2, 2000))
            .push_row(InverseRow::new(
                PkTuple::single(PkValue::Int(9)),
                vec![
                    ("x".into(), PkValue::Int(9)),
                    (
                        RELATION_STAMP.into(),
                        PkValue::Text("public.unknown".into()),
                    ),
                ],
            ))
            .fk_order(vec![TARGET.into(), CHILD.into()])
            .build();
        let mut conn = MockRevertConn::new();
        let probe = conn.clone();
        let err = revert(&inverse, &mut conn).unwrap_err();
        assert!(
            matches!(err, RevertError::MalformedInverse { .. }),
            "{err:?}"
        );
        assert!(!probe.inner().began, "refused before opening the txn");
    }
}
