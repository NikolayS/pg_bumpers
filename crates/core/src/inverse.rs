//! Typed-inverse capture + the refused-op **default-deny** certified action set
//! (SPEC §10.3).
//!
//! Reversibility is achieved by capturing a **typed inverse** during the
//! dry-run: per affected row we store `{pk, before_image}` (the full pre-image
//! column values for `UPDATE`/`DELETE`). The inverse is then:
//!
//! - `UPDATE … FROM (VALUES …) WHERE pk = …` for an `UPDATE` →
//!   [`InverseKind::PreimageUpsert`], and
//! - `INSERT …` for a `DELETE` → [`InverseKind::Insert`],
//!
//! applied in **FK order** so re-inserts don't violate foreign keys.
//!
//! # What is explicitly NOT restored (documented + tested)
//!
//! The inverse restores **table row state only**. It deliberately does **not**
//! restore (SPEC §10.3): **sequence** advances (`nextval` gaps stay),
//! **trigger side-effects** (e.g. audit rows a trigger wrote), and **`NOTIFY`**
//! messages already delivered. [`NotRestored`] enumerates these so callers and
//! the audit record name them explicitly; a test asserts the set.
//!
//! # Default-deny certified action set
//!
//! The set of operations that may ever be auto-applied is a **closed allow-list**
//! ([`CertifiedAction`]). Everything outside it — `TRUNCATE`, `DROP`, `ALTER`,
//! `INSERT` with a volatile default, a `DELETE` with no pre-image or on a
//! PK-less table, anything unknown — is [`RefusedOp`]. [`certify`] is the single
//! choke point; its default arm refuses, so **adding a new op is refused until
//! it is explicitly certified** (fail-closed). A property test sweeps the op
//! space and asserts everything outside the set is refused.

use serde::{Deserialize, Serialize};

use crate::pk_checksum::PkTuple;

/// The kind of inverse captured for a reversible write (SPEC §10.1 / §10.3).
///
/// Serializes to the exact spec strings so it round-trips with the
/// blast-radius record's `inverse_kind` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InverseKind {
    /// Inverse of an `UPDATE`: re-apply the captured pre-image via
    /// `UPDATE … FROM (VALUES …) WHERE pk = …`. Spec string `PREIMAGE_UPSERT`.
    #[serde(rename = "PREIMAGE_UPSERT")]
    PreimageUpsert,
    /// Inverse of a `DELETE`: re-insert the captured rows. Spec string `INSERT`.
    #[serde(rename = "INSERT")]
    Insert,
    /// The write has no captured inverse (e.g. a pure no-op, or a refused op
    /// recorded for audit). Marks the write **not reversible**. Spec string
    /// `NONE`.
    #[serde(rename = "NONE")]
    None,
}

impl InverseKind {
    /// The inverse kind for a forward operation, if one can be captured.
    ///
    /// `UPDATE` → [`PreimageUpsert`](Self::PreimageUpsert), `DELETE` →
    /// [`Insert`](Self::Insert). Forward `INSERT` has no captured *row* inverse
    /// here (its inverse is a delete, handled by the apply txn's own rollback
    /// scope), so this returns [`None`](Self::None) for it.
    pub const fn for_update() -> Self {
        InverseKind::PreimageUpsert
    }

    /// The inverse kind for a `DELETE`.
    pub const fn for_delete() -> Self {
        InverseKind::Insert
    }
}

/// One column of a captured pre-image (the "before" value of a key/column).
///
/// Reuses the typed PK value vocabulary so the before-image is typed, not
/// stringly — the same anti-collision reasoning as the PK checksum.
pub type ImageValue = crate::pk_checksum::PkValue;

/// The captured pre-image of one affected row: its PK plus the full set of
/// `(column, before_value)` pairs (SPEC §10.3 `{pk, before_image}`).
///
/// Column order is preserved (a `Vec`, not a map) so the generated
/// `VALUES`/`INSERT` column list is stable and matches the dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InverseRow {
    /// The row's primary-key tuple (how the inverse targets it).
    pub pk: PkTuple,
    /// The full pre-image: ordered `(column_name, before_value)` pairs.
    pub before_image: Vec<(String, ImageValue)>,
}

impl InverseRow {
    /// Capture one row's pre-image.
    pub fn new(pk: PkTuple, before_image: Vec<(String, ImageValue)>) -> Self {
        InverseRow { pk, before_image }
    }
}

/// State that the typed inverse **does not restore** (SPEC §10.3, documented +
/// tested).
///
/// The inverse restores table row state only. These three are out of scope by
/// design; the variant exists so the audit record can name *which* unrestored
/// effect occurred rather than leaving it implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotRestored {
    /// Sequence advances are permanent: `nextval` gaps remain after revert.
    SequenceAdvance,
    /// Side effects a trigger performed (e.g. audit rows it wrote) are not
    /// undone by reverting the triggering table's rows.
    TriggerSideEffect,
    /// `NOTIFY` messages already delivered cannot be recalled.
    NotifyDelivered,
}

impl NotRestored {
    /// The complete set of effects the inverse never restores. The order is the
    /// canonical documentation order (SPEC §10.3 lists sequences, trigger
    /// side-effects, NOTIFY).
    pub const ALL: [NotRestored; 3] = [
        NotRestored::SequenceAdvance,
        NotRestored::TriggerSideEffect,
        NotRestored::NotifyDelivered,
    ];
}

/// A captured plan to reverse a guarded write (SPEC §10.3).
///
/// Holds the per-row pre-images, the [`InverseKind`], and the **FK order** in
/// which target relations must be touched so re-inserts and updates don't
/// violate foreign keys (parents before children for inserts). It also carries
/// the documented [`NotRestored`] caveats that apply to this write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InversePlan {
    /// `schema.table` this inverse targets.
    pub relation: String,
    /// How the inverse is applied.
    pub kind: InverseKind,
    /// Captured pre-images, one per affected row.
    pub rows: Vec<InverseRow>,
    /// Relations in the order the inverse must apply them to respect foreign
    /// keys (the FK-order field). For a single relation this is just
    /// `[relation]`; the field is explicit so multi-relation inverses are
    /// ordered deterministically.
    pub fk_order: Vec<String>,
    /// Effects this revert will *not* undo (always non-empty in practice; see
    /// [`NotRestored::ALL`]).
    pub not_restored: Vec<NotRestored>,
}

/// Builder for an [`InversePlan`] (SPEC §10.3 capture).
pub struct InversePlanBuilder {
    relation: String,
    kind: InverseKind,
    rows: Vec<InverseRow>,
    fk_order: Vec<String>,
}

impl InversePlanBuilder {
    /// Begin capturing an inverse of `kind` for `relation`.
    pub fn new(relation: impl Into<String>, kind: InverseKind) -> Self {
        let relation = relation.into();
        InversePlanBuilder {
            fk_order: vec![relation.clone()],
            relation,
            kind,
            rows: Vec::new(),
        }
    }

    /// Capture one affected row's pre-image.
    pub fn push_row(mut self, row: InverseRow) -> Self {
        self.rows.push(row);
        self
    }

    /// Set the FK-ordered relation list (parents before children).
    pub fn fk_order(mut self, order: Vec<String>) -> Self {
        self.fk_order = order;
        self
    }

    /// Finish, attaching the full documented [`NotRestored`] caveat set.
    pub fn build(self) -> InversePlan {
        InversePlan {
            relation: self.relation,
            kind: self.kind,
            rows: self.rows,
            fk_order: self.fk_order,
            not_restored: NotRestored::ALL.to_vec(),
        }
    }
}

/// The **closed certified action set**: the only operations that may ever be
/// auto-applied (SPEC §10.3 default-deny).
///
/// Each variant is an op we have certified as *bounded + reversible*. The set is
/// closed: an operation that is not one of these is [`RefusedOp`]. Membership is
/// checked by [`certify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertifiedAction {
    /// A bounded `UPDATE` with a captured pre-image and a usable PK.
    BoundedUpdate,
    /// A bounded `DELETE` with a captured pre-image and a usable PK
    /// (re-insertable).
    BoundedDelete,
    /// An `INSERT` whose column defaults are all **non-volatile** (so the
    /// dry-run and apply produce the same rows).
    NonVolatileInsert,
}

/// An operation outside the certified set — **refused** (SPEC §10.3).
///
/// The variants name the canonical refused categories so the audit log records
/// *why* an op was refused, not just that it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefusedOp {
    /// `TRUNCATE` — unbounded, non-row-reversible.
    #[error("refused: TRUNCATE is outside the certified action set")]
    Truncate,
    /// `DROP …` (DDL) — irreversible structural change.
    #[error("refused: DROP is outside the certified action set")]
    Drop,
    /// `ALTER …` (DDL) — structural change.
    #[error("refused: ALTER is outside the certified action set")]
    Alter,
    /// `INSERT` with a volatile default (e.g. `DEFAULT now()`/`random()`/a
    /// sequence) — dry-run/apply rows can differ.
    #[error("refused: INSERT with a volatile default is outside the certified action set")]
    VolatileDefaultInsert,
    /// `DELETE` with no captured pre-image — not reversible.
    #[error("refused: DELETE without a captured pre-image cannot be reversed")]
    DeleteWithoutPreimage,
    /// Any write to a PK-less / no-replica-identity table.
    #[error("refused: write to a PK-less / no-replica-identity table")]
    PkLessTable,
    /// Anything else — the catch-all that makes the policy **default-deny**.
    #[error("refused: operation `{0}` is not in the certified action set (default-deny)")]
    NotCertified(String),
}

/// A described operation presented to [`certify`].
///
/// This is a coarse, DB-free description (the proxy/warden fill it in from the
/// parsed statement + measured dry-run facts). It is intentionally *more*
/// expressive than the certified set so that [`certify`] has to actively
/// allow-list — the default arm refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// An `UPDATE`; `has_preimage`/`has_pk` come from the dry-run capture.
    Update {
        /// Whether a full pre-image was captured for every affected row.
        has_preimage: bool,
        /// Whether the target relation has a usable PK / replica identity.
        has_pk: bool,
    },
    /// A `DELETE`.
    Delete {
        /// Whether a full pre-image was captured.
        has_preimage: bool,
        /// Whether the target relation has a usable PK / replica identity.
        has_pk: bool,
    },
    /// An `INSERT`.
    Insert {
        /// Whether any column default is volatile (`now()`/`random()`/sequence).
        volatile_default: bool,
        /// Whether the target relation has a usable PK / replica identity.
        has_pk: bool,
    },
    /// `TRUNCATE`.
    Truncate,
    /// `DROP` (DDL).
    Drop,
    /// `ALTER` (DDL).
    Alter,
    /// Anything the parser couldn't map to a known op — must be refused.
    Unknown(String),
}

/// The single default-deny choke point (SPEC §10.3).
///
/// Returns the [`CertifiedAction`] for an op **iff** it is bounded + reversible
/// and in the closed set; otherwise [`RefusedOp`]. The match's final arm — and
/// the [`Operation::Unknown`] arm — refuse, so any op not *explicitly* certified
/// here is denied. New ops are refused until someone adds an allow arm with a
/// test.
pub fn certify(op: &Operation) -> Result<CertifiedAction, RefusedOp> {
    match op {
        // --- Allow-list: bounded + reversible, with a usable PK -------------
        Operation::Update {
            has_preimage: true,
            has_pk: true,
        } => Ok(CertifiedAction::BoundedUpdate),

        Operation::Delete {
            has_preimage: true,
            has_pk: true,
        } => Ok(CertifiedAction::BoundedDelete),

        Operation::Insert {
            volatile_default: false,
            has_pk: true,
        } => Ok(CertifiedAction::NonVolatileInsert),

        // --- Default-deny: everything below is refused ----------------------
        Operation::Update { has_pk: false, .. } | Operation::Delete { has_pk: false, .. } => {
            Err(RefusedOp::PkLessTable)
        }
        Operation::Insert { has_pk: false, .. } => Err(RefusedOp::PkLessTable),
        Operation::Delete {
            has_preimage: false,
            ..
        } => Err(RefusedOp::DeleteWithoutPreimage),
        // An UPDATE without a pre-image cannot be reversed → not certified.
        Operation::Update {
            has_preimage: false,
            ..
        } => Err(RefusedOp::NotCertified("UPDATE without pre-image".into())),
        Operation::Insert {
            volatile_default: true,
            ..
        } => Err(RefusedOp::VolatileDefaultInsert),
        Operation::Truncate => Err(RefusedOp::Truncate),
        Operation::Drop => Err(RefusedOp::Drop),
        Operation::Alter => Err(RefusedOp::Alter),
        Operation::Unknown(name) => Err(RefusedOp::NotCertified(name.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pk_checksum::PkValue;

    #[test]
    fn inverse_kind_serializes_to_spec_strings() {
        assert_eq!(
            serde_json::to_string(&InverseKind::PreimageUpsert).unwrap(),
            "\"PREIMAGE_UPSERT\""
        );
        assert_eq!(
            serde_json::to_string(&InverseKind::Insert).unwrap(),
            "\"INSERT\""
        );
        assert_eq!(
            serde_json::from_str::<InverseKind>("\"PREIMAGE_UPSERT\"").unwrap(),
            InverseKind::PreimageUpsert
        );
    }

    #[test]
    fn update_maps_to_preimage_upsert_and_delete_to_insert() {
        assert_eq!(InverseKind::for_update(), InverseKind::PreimageUpsert);
        assert_eq!(InverseKind::for_delete(), InverseKind::Insert);
    }

    #[test]
    fn inverse_plan_captures_pk_before_image_and_fk_order() {
        let row = InverseRow::new(
            PkTuple::single(PkValue::Int(42)),
            vec![
                ("status".into(), PkValue::Text("shipped".into())),
                ("qty".into(), PkValue::Int(3)),
            ],
        );
        let plan = InversePlanBuilder::new("public.orders", InverseKind::for_update())
            .push_row(row.clone())
            .fk_order(vec!["public.orders".into(), "public.order_items".into()])
            .build();

        assert_eq!(plan.kind, InverseKind::PreimageUpsert);
        assert_eq!(plan.rows, vec![row]);
        assert_eq!(
            plan.fk_order,
            vec![
                "public.orders".to_string(),
                "public.order_items".to_string()
            ]
        );
    }

    /// Documented + asserted: the inverse never restores sequences, trigger
    /// side-effects, or NOTIFY.
    #[test]
    fn inverse_plan_documents_what_is_not_restored() {
        let plan = InversePlanBuilder::new("public.orders", InverseKind::for_delete()).build();
        assert!(plan.not_restored.contains(&NotRestored::SequenceAdvance));
        assert!(plan.not_restored.contains(&NotRestored::TriggerSideEffect));
        assert!(plan.not_restored.contains(&NotRestored::NotifyDelivered));
        assert_eq!(plan.not_restored.len(), 3);
        assert_eq!(plan.not_restored, NotRestored::ALL.to_vec());
    }

    #[test]
    fn certified_ops_are_allowed() {
        assert_eq!(
            certify(&Operation::Update {
                has_preimage: true,
                has_pk: true
            }),
            Ok(CertifiedAction::BoundedUpdate)
        );
        assert_eq!(
            certify(&Operation::Delete {
                has_preimage: true,
                has_pk: true
            }),
            Ok(CertifiedAction::BoundedDelete)
        );
        assert_eq!(
            certify(&Operation::Insert {
                volatile_default: false,
                has_pk: true
            }),
            Ok(CertifiedAction::NonVolatileInsert)
        );
    }

    #[test]
    fn named_dangerous_ops_are_refused() {
        assert_eq!(certify(&Operation::Truncate), Err(RefusedOp::Truncate));
        assert_eq!(certify(&Operation::Drop), Err(RefusedOp::Drop));
        assert_eq!(certify(&Operation::Alter), Err(RefusedOp::Alter));
        assert_eq!(
            certify(&Operation::Insert {
                volatile_default: true,
                has_pk: true
            }),
            Err(RefusedOp::VolatileDefaultInsert)
        );
        assert_eq!(
            certify(&Operation::Delete {
                has_preimage: false,
                has_pk: true
            }),
            Err(RefusedOp::DeleteWithoutPreimage)
        );
        assert_eq!(
            certify(&Operation::Delete {
                has_preimage: true,
                has_pk: false
            }),
            Err(RefusedOp::PkLessTable)
        );
    }

    /// DEFAULT-DENY PROPERTY: sweep the op space (all flag combinations + the
    /// named DDL/unknown ops). Every op that is **not** one of the three
    /// certified shapes must be `Err`, and every certified shape must be `Ok` —
    /// i.e. the allow-list is exactly closed.
    #[test]
    fn default_deny_any_op_outside_the_certified_set_is_refused() {
        let mut ops: Vec<Operation> = Vec::new();
        for &preimage in &[true, false] {
            for &pk in &[true, false] {
                ops.push(Operation::Update {
                    has_preimage: preimage,
                    has_pk: pk,
                });
                ops.push(Operation::Delete {
                    has_preimage: preimage,
                    has_pk: pk,
                });
            }
        }
        for &vol in &[true, false] {
            for &pk in &[true, false] {
                ops.push(Operation::Insert {
                    volatile_default: vol,
                    has_pk: pk,
                });
            }
        }
        ops.push(Operation::Truncate);
        ops.push(Operation::Drop);
        ops.push(Operation::Alter);
        ops.push(Operation::Unknown("MERGE".into()));
        ops.push(Operation::Unknown("COPY ... FROM PROGRAM".into()));
        ops.push(Operation::Unknown("GRANT".into()));

        // The exact closed allow-list, by shape.
        let is_certified = |op: &Operation| {
            matches!(
                op,
                Operation::Update {
                    has_preimage: true,
                    has_pk: true
                } | Operation::Delete {
                    has_preimage: true,
                    has_pk: true
                } | Operation::Insert {
                    volatile_default: false,
                    has_pk: true
                }
            )
        };

        let mut allowed = 0;
        for op in &ops {
            let result = certify(op);
            if is_certified(op) {
                assert!(result.is_ok(), "certified op {op:?} must be allowed");
                allowed += 1;
            } else {
                assert!(
                    result.is_err(),
                    "default-deny violated: op {op:?} outside the certified set was allowed"
                );
            }
        }
        // Exactly the three certified shapes were allowed.
        assert_eq!(allowed, 3, "exactly the three certified shapes are allowed");
    }
}
