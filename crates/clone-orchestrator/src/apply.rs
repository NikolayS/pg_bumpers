//! The guarded-apply engine (SPEC §4, §10.2, §10.3, §10.4, §1 honest recovery).
//!
//! This is the *reversible half of the moat*: once a [`Proposal`] has passed the
//! dry-run ([`crate::dry_run`]) and yielded a [`BlastRadius`], [`guarded_apply`]
//! applies it on the **primary** under a closed set of guards, and returns the
//! typed-inverse ([`pgb_core::InversePlan`]) the revert (#37) will use. Nothing
//! is committed unless every guard passes.
//!
//! # The guarded-apply contract (SPEC §4, in order)
//!
//! 1. **PITR fence** — `pg_create_restore_point(label)` when `pitr.enabled`. When
//!    PITR is *not* enabled we do **not** fabricate a fence; the typed-inverse is
//!    the documented undo (SPEC §1 honest-recovery: the typed-inverse is cheap +
//!    fast; PITR is a last-resort that requires the customer to run continuous WAL
//!    archiving + a tested restore). We never market both as cheap.
//! 2. **`BEGIN`** a single apply txn and `SET LOCAL statement_timeout` ≈ **3× the
//!    dry-run `duration_ms`** (so a slow apply aborts with **no partial commit**,
//!    SPEC §3 deterministic floor) — clamped to a sane floor so a sub-millisecond
//!    dry-run still leaves a usable budget.
//! 3. **[`ApplyBarrier::pause_point`]** between prepare and apply — production is a
//!    no-op; the drift tests inject through this seam (SPEC §10.4).
//! 4. **Apply with `RETURNING`** — capture both the **pre-image** (for the
//!    typed-inverse, §10.3 `{pk, before_image}`) and the **actual affected-PK
//!    set** the forward op wrote.
//! 5. **Full-blast-radius apply-time PK-set re-check (0-tolerance destructive)** —
//!    recompute the affected-PK-set checksum *inside the apply txn* on the same
//!    predicate, for the **target AND every `cascade_by_table` relation the
//!    dry-run recorded**, and compare each to the dry-run/grant checksum. Any
//!    mismatch → **ABORT (ROLLBACK)**. The guard is the PK-set checksum, **not**
//!    the row count, so it catches row-identity drift (same count, different PKs)
//!    — on the target *and* on cascade children (post-snapshot child rows).
//! 6. **Symmetric full-effect reconciliation (`pg_stat_xact_*` tuple deltas)** —
//!    the dry-run measures the FULL blast radius (cascades + trigger effects) via
//!    per-relation `pg_stat_xact_n_tup_{ins,upd,del}` deltas; the apply measures
//!    the **same** deltas inside the apply txn and reconciles them against the
//!    prediction. **ABORT** if ANY relation **not** in the predicted blast radius
//!    shows a change (the AFTER-trigger `DELETE id=7` out of predicate, or a
//!    trigger wiping a separate `mirror` table — both invisible to the target's
//!    `RETURNING`), OR any predicted relation changed **more** than predicted (an
//!    unguarded cascade that destroyed post-snapshot child rows). This is the
//!    "0 catastrophic data-loss FN by construction" mechanism: a drifted write can
//!    no longer commit.
//! 7. **`RETURNING` written-set check (gate carry-forward)** — verify the rows the
//!    forward op *actually wrote* in the target (`RETURNING`) match the predicted
//!    set (defense in depth, kept for same-relation drift).
//! 8. **Full reversible pre-image capture** — the typed-inverse must cover **every
//!    changed row across ALL affected tables** (target + cascades), FK-ordered, so
//!    the revert (#37) fully restores. If any committed change cannot be captured
//!    as a reversible pre-image → **ABORT** (fail-closed: we never commit a change
//!    we cannot certifiably undo). The pre-image is read from the ACTUAL row
//!    values (so a BEFORE-trigger value rewrite cannot desync the inverse).
//! 9. **`COMMIT`** only if every check passes; else **`ROLLBACK`**.
//! 10. **Refused-op default-deny** — anything outside the closed certified action
//!     set ([`pgb_core::certify`]) is refused and **never applied**.
//!
//! # The seam
//!
//! Like [`crate::dry_run`] is DB-free and drives a [`crate::Rehearsal`], this
//! engine is DB-free and drives an [`ApplyConn`]: the engine owns the *ordering
//! and the guard decisions*; the connection owns the SQL. Production grows a
//! tokio-backed `ApplyConn`; the env-gated integration tests
//! (`apply_it.rs`, `PG_BUMPERS_IT=1`) implement it against real PostgreSQL 18, and
//! the unit tests here implement an in-memory one that can inject every drift +
//! the `statement_timeout` fire deterministically. The barrier seam
//! ([`ApplyBarrier`]) is crossed at the §10.4 point in both.

use std::collections::{BTreeMap, BTreeSet};

use pgb_core::inverse::{certify, InversePlanBuilder, Operation};
use pgb_core::{
    ApplyBarrier, BlastRadius, Clock, InverseKind, InversePlan, InverseRow, OpCounts, PkChecksum,
    PkSetBuilder, PkTuple, RefusedOp,
};

use crate::dry_run::WriteKind;

/// The default floor for the apply txn's `statement_timeout`, in milliseconds.
///
/// `statement_timeout` ≈ 3× the dry-run `duration_ms` (SPEC §4), but a fast
/// dry-run (a few ms, or even 0 on a tiny table) would otherwise produce a
/// timeout so small the apply could not finish even with no drift. We clamp the
/// budget up to this floor so the multiplier only ever *raises* the budget for a
/// genuinely slow apply; it never starves a legitimate fast one.
pub const MIN_STATEMENT_TIMEOUT_MS: u64 = 1_000;

/// The multiplier applied to the dry-run `duration_ms` to size the apply txn's
/// `statement_timeout` (SPEC §4 "`statement_timeout ≈ 3× dry-run`").
pub const STATEMENT_TIMEOUT_MULTIPLIER: u64 = 3;

/// Compute the apply txn's `statement_timeout` from the dry-run `duration_ms`:
/// `max(3 × duration_ms, MIN_STATEMENT_TIMEOUT_MS)` (SPEC §4).
///
/// Saturating so a pathological `duration_ms` cannot overflow the budget.
pub fn statement_timeout_ms(dry_run_duration_ms: u64) -> u64 {
    dry_run_duration_ms
        .saturating_mul(STATEMENT_TIMEOUT_MULTIPLIER)
        .max(MIN_STATEMENT_TIMEOUT_MS)
}

/// Why a guarded apply aborted or was refused. **Every variant means nothing was
/// committed** — the apply path is fail-closed, so on any of these the primary is
/// byte-for-byte unchanged (the txn was rolled back, or never opened).
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The proposal's operation is outside the closed certified action set
    /// (default-deny, §10.3) — **refused, never applied**. Carries the typed
    /// [`RefusedOp`] reason for the audit record.
    #[error("REFUSED: {0}")]
    Refused(#[from] RefusedOp),

    /// **Apply-time PK-set drift** (step 5): the affected-PK-set checksum
    /// recomputed inside the apply txn differs from the dry-run/grant checksum.
    /// 0-tolerance → ROLLBACK. This is the guard *firing* — the expected outcome
    /// of every drift test (insert / delete-shrink / predicate-flip /
    /// trigger-amplification).
    #[error("GUARD ABORT (apply-time PK-set drift on `{relation}`): dry_run={dry_run} apply_time={apply_time}")]
    PkSetDrift {
        /// The relation whose affected-PK set drifted.
        relation: String,
        /// The dry-run/grant checksum.
        dry_run: String,
        /// The checksum recomputed inside the apply txn (before the forward op).
        apply_time: String,
    },

    /// **`RETURNING` written-set mismatch** (step 7, the gate carry-forward): the
    /// rows the forward op actually wrote (its `RETURNING` PK set) differ from the
    /// predicted set. Catches a post-snapshot trigger writing rows OUTSIDE the
    /// predicate that the pre-op recompute (step 5) cannot see. → ROLLBACK.
    #[error("GUARD ABORT (RETURNING written-set mismatch on `{relation}`): predicted={predicted} written={written}")]
    WrittenSetMismatch {
        /// The relation whose written set diverged from the prediction.
        relation: String,
        /// The predicted (dry-run) affected-PK-set checksum.
        predicted: String,
        /// The checksum of the rows the forward op actually wrote (`RETURNING`).
        written: String,
    },

    /// **Write to an UNPREDICTED relation** (step 6, the symmetric `pg_stat_xact_*`
    /// reconciliation): the apply txn changed rows in a relation that was **not**
    /// in the dry-run blast radius (target + cascades). This is the catastrophic,
    /// `RETURNING`-invisible case — an AFTER trigger that `DELETE`s a row OUTSIDE
    /// the predicate (e.g. `DELETE FROM accounts WHERE id=7`) or wipes a separate
    /// `mirror` table — and it is **irreversible** under the captured inverse. The
    /// guard fails closed: a write that touches an unpredicted relation can never
    /// commit. → ROLLBACK.
    #[error("GUARD ABORT (unpredicted-relation write on `{relation}`): {changed} tuples changed (ins={ins} upd={upd} del={del}) but the relation is not in the dry-run blast radius")]
    UnpredictedRelationWrite {
        /// The relation the apply txn changed that the dry-run never predicted.
        relation: String,
        /// Total tuples changed in that relation (ins+upd+del).
        changed: u64,
        /// In-txn `pg_stat_xact_n_tup_ins` for the relation.
        ins: u64,
        /// In-txn `pg_stat_xact_n_tup_upd` for the relation.
        upd: u64,
        /// In-txn `pg_stat_xact_n_tup_del` for the relation.
        del: u64,
    },

    /// **A predicted relation changed MORE than predicted on some op channel**
    /// (step 6, the symmetric **per-op-type** reconciliation): a relation in the
    /// dry-run blast radius shows more in-txn tuples changed on at least one of the
    /// `ins` / `upd` / `del` channels than the dry-run measured for that channel.
    /// Catches an out-of-predicate write to the *target* table (an AFTER trigger
    /// `DELETE`/`UPDATE` of a same-table row the `RETURNING` set happens to still
    /// match), **cascade drift** (post-snapshot child rows that swelled the cascade
    /// beyond the prediction), AND — critically — an **op-type substitution**: a
    /// relation predicted to only `ins` that the apply `del`s/`upd`s instead (same
    /// *total*, opposite destructive op). Those excess/substituted rows have no
    /// pre-image in the inverse → irreversible. The reconciliation compares each op
    /// channel **independently** (never a collapsed total). → ROLLBACK.
    #[error("GUARD ABORT (relation `{relation}` changed more than predicted on the `{channel}` channel): predicted=(ins={p_ins} upd={p_upd} del={p_del}) actual=(ins={a_ins} upd={a_upd} del={a_del})")]
    RelationOverWrite {
        /// The predicted relation whose actual change exceeded the prediction.
        relation: String,
        /// The op channel that drifted (`"ins"`, `"upd"`, or `"del"`) — the first
        /// channel found to exceed its prediction.
        channel: &'static str,
        /// Predicted `pg_stat_xact_n_tup_ins` for the relation.
        p_ins: u64,
        /// Predicted `pg_stat_xact_n_tup_upd` for the relation.
        p_upd: u64,
        /// Predicted `pg_stat_xact_n_tup_del` for the relation.
        p_del: u64,
        /// Actual in-txn `pg_stat_xact_n_tup_ins`.
        a_ins: u64,
        /// Actual in-txn `pg_stat_xact_n_tup_upd`.
        a_upd: u64,
        /// Actual in-txn `pg_stat_xact_n_tup_del`.
        a_del: u64,
    },

    /// **A committed change could not be captured as a reversible pre-image**
    /// (step 8): the inverse must cover every changed row across all affected
    /// tables, but a row in `relation` was changed without a captured pre-image.
    /// Committing would leave an unrevertable change → fail-closed ABORT. → ROLLBACK.
    #[error("GUARD ABORT (irreversible change on `{relation}`): {detail}")]
    IrreversibleChange {
        /// The relation whose change could not be reversibly captured.
        relation: String,
        /// Why the change is not certifiably reversible.
        detail: String,
    },

    /// **A written COLUMN has no captured pre-image** (step 8, column coverage,
    /// S5 #75): an `UPDATE`-written row mutated a column whose OLD value the
    /// typed-inverse never captured, so the revert cannot restore it. This is the
    /// catastrophic, silent un-revertable write the apply-time column guard closes —
    /// a write must NEVER commit `reversible:true` with an incomplete inverse. The
    /// guard fails closed: any written row missing a pre-image for any written column
    /// aborts before commit (no mutation). → ROLLBACK.
    #[error("GUARD ABORT (uncaptured written column on `{relation}` pk={pk}): the write mutated column(s) {missing:?} but the typed-inverse captured no pre-image for them — the change is not reversible")]
    UncapturedColumn {
        /// The relation whose written column was not captured.
        relation: String,
        /// The PK of the written row missing a column pre-image (for diagnostics).
        pk: String,
        /// The written column(s) with no captured pre-image.
        missing: Vec<String>,
    },

    /// The apply txn exceeded its `statement_timeout` (step 2) and was aborted by
    /// the server — **no partial commit**. Surfaced distinctly so the caller can
    /// tell a timeout abort from a drift abort.
    #[error("APPLY TIMEOUT: apply exceeded statement_timeout of {timeout_ms}ms — aborted, nothing committed")]
    Timeout {
        /// The `statement_timeout` budget that was exceeded.
        timeout_ms: u64,
    },

    /// The blast-radius record this apply was handed does not match the proposal
    /// (defensive cross-check) or is missing the target's checksum.
    #[error("INVALID GRANT: {0}")]
    InvalidGrant(String),

    /// The underlying connection failed (DB error etc.). Surfaced as a string so
    /// the engine stays DB-free; the txn is always rolled back before this is
    /// returned.
    #[error("apply backend failed: {0}")]
    Backend(String),
}

/// A pre-image row captured by the forward op's `RETURNING`: its typed PK tuple
/// plus the full ordered `(column, before_value)` pre-image (SPEC §10.3
/// `{pk, before_image}`).
///
/// The connection produces these from `RETURNING` (an `UPDATE` returns the *old*
/// values via `RETURNING <cols>` of the pre-update row image captured at snapshot
/// time; a `DELETE` returns the deleted row). The engine folds them into the
/// [`InversePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRow {
    /// The affected row's typed PK tuple.
    pub pk: PkTuple,
    /// The full ordered pre-image `(column_name, before_value)` pairs.
    pub before_image: Vec<(String, pgb_core::inverse::ImageValue)>,
}

/// What the forward op produced: the rows it actually wrote (from `RETURNING`),
/// each with its captured pre-image. Used to build both the §10.3 typed-inverse
/// and the §10.5(a) written-set checksum.
#[derive(Debug, Clone)]
pub struct ForwardResult {
    /// The **target** rows the forward op actually wrote, in `RETURNING` order
    /// (with the actual pre-image — post-BEFORE-trigger old values).
    pub written: Vec<CapturedRow>,
    /// The **cascade** pre-images, keyed by `schema.table`, captured (for a
    /// `DELETE`) BEFORE the forward op deleted the children — so the typed-inverse
    /// can re-insert every cascade-destroyed row, FK-ordered. Empty for a plain
    /// `UPDATE` with no cascades. The connection populates this symmetrically with
    /// what the dry-run measured in `cascade_by_table`.
    pub cascade_preimages: BTreeMap<String, Vec<CapturedRow>>,
    /// The **columns the forward op mutated on the target** (the UPDATE SET-clause
    /// targets, S5 #75). The connection fills this so the engine's step-8 coverage
    /// guard can verify — defense-in-depth, even if the dry-run column gate were
    /// bypassed — that **every written column has a captured pre-image** in each
    /// `written` row before commit. Empty ⇒ the connection declared no specific
    /// written-column set (a `DELETE`, whose full-row re-insert is row-covered, or a
    /// legacy/scripted conn); the column guard then only enforces the
    /// non-empty-pre-image floor.
    pub written_columns: Vec<String>,
}

impl ForwardResult {
    /// Convenience constructor for a target-only forward result (no cascades, no
    /// declared written-column set — the column guard then enforces only the
    /// non-empty-pre-image floor).
    pub fn new(written: Vec<CapturedRow>) -> Self {
        ForwardResult {
            written,
            cascade_preimages: BTreeMap::new(),
            written_columns: Vec::new(),
        }
    }

    /// Declare the columns the forward op mutated on the target (S5 #75). The
    /// engine's step-8 coverage guard verifies each written row's pre-image covers
    /// all of these before commit.
    pub fn with_written_columns(mut self, cols: Vec<String>) -> Self {
        self.written_columns = cols;
        self
    }

    /// The checksum of the **written** PK set (the target rows the forward op
    /// actually touched, per `RETURNING`). Compared against the prediction in
    /// step 7.
    fn written_checksum(&self, relation: &str) -> Result<PkChecksum, ApplyError> {
        let mut b = PkSetBuilder::for_relation(relation);
        for row in &self.written {
            b.push(row.pk.clone())
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }
}

/// One relation's in-txn tuple deltas, read from `pg_stat_xact_user_tables`
/// **inside the apply txn** (SPEC §4 `pg_stat_xact_*` deltas). This is the
/// symmetric apply-side of the FULL blast radius the dry-run measured: it surfaces
/// every relation the txn changed — including rows a trigger wrote in another
/// statement or another table, which `RETURNING` can never report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationChange {
    /// `schema.table`.
    pub relation: String,
    /// Rows inserted in this relation within the apply txn.
    pub ins: u64,
    /// Rows updated in this relation within the apply txn.
    pub upd: u64,
    /// Rows deleted in this relation within the apply txn.
    pub del: u64,
}

impl RelationChange {
    /// Total tuples changed in the relation within the txn (`ins + upd + del`).
    /// Display / cross-check only — the guard reconciles **per op type** (see
    /// [`as_op_counts`](RelationChange::as_op_counts)), so a substitution that
    /// keeps the total but flips the op (an INSERT prediction met by a DELETE)
    /// still aborts.
    pub fn total(&self) -> u64 {
        self.ins.saturating_add(self.upd).saturating_add(self.del)
    }

    /// This relation's measured deltas as a typed [`OpCounts`], for per-channel
    /// reconciliation against the prediction.
    pub fn as_op_counts(&self) -> OpCounts {
        OpCounts::new(self.ins, self.upd, self.del)
    }
}

/// The connection seam the guarded-apply engine drives (the apply analogue of
/// [`crate::Rehearsal`]).
///
/// The engine owns the **ordering and the guard decisions**; the connection owns
/// the SQL. An implementation runs everything against **one** apply transaction:
/// [`begin`](ApplyConn::begin) opens it and sets `statement_timeout`, the
/// recompute / forward / commit / rollback methods run within it. The engine
/// guarantees it calls them in the §4 order and rolls back on any guard failure.
///
/// Production grows a tokio-backed impl; the env-gated integration tests
/// implement it against real PG18; the unit tests use an in-memory one.
pub trait ApplyConn {
    /// **Step 1 — PITR fence.** Create a named restore point
    /// (`pg_create_restore_point(label)`) and return its LSN. Only called when
    /// `pitr.enabled` (SPEC §4 / §1). MUST run **outside** the apply txn (a
    /// restore point is a WAL record that must be durable regardless of the
    /// apply's outcome).
    fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError>;

    /// **Step 2 — open the apply txn** and `SET LOCAL statement_timeout = timeout_ms`.
    /// All subsequent steps run inside this txn until [`commit`](ApplyConn::commit)
    /// or [`rollback`](ApplyConn::rollback).
    fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError>;

    /// **Step 5 — recompute the affected-PK-set checksum** for `relation` on the
    /// same predicate, *inside the apply txn, before the forward op*. This is the
    /// 0-tolerance drift check's apply-time side. Called for the target **and for
    /// every cascade relation** the dry-run recorded, so cascade-child drift
    /// (post-snapshot rows) is caught symmetrically with the target.
    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError>;

    /// **Step 4 — run the forward op with `RETURNING`**, capturing each written
    /// row's PK + full pre-image, **and the pre-images of every cascade-affected
    /// child row** (captured before the forward op deletes them, so the inverse can
    /// re-insert them). Returns the [`ForwardResult`].
    ///
    /// `cascade_relations` is the set of `cascade_by_table` relations the dry-run
    /// recorded; the connection captures each one's pre-image FK-ordered so the
    /// typed-inverse fully restores. The pre-image MUST be read from the ACTUAL row
    /// values (so a BEFORE-trigger value rewrite cannot desync the inverse).
    ///
    /// If the server aborts the statement for exceeding `statement_timeout`, this
    /// MUST return [`ApplyError::Timeout`] (and leave the txn aborted; the engine
    /// rolls back).
    fn apply_forward(
        &mut self,
        kind: WriteKind,
        relation: &str,
        cascade_relations: &[String],
    ) -> Result<ForwardResult, ApplyError>;

    /// **Step 6 — read the per-relation in-txn tuple deltas** from
    /// `pg_stat_xact_user_tables` (SPEC §4 `pg_stat_xact_*`). Returns one
    /// [`RelationChange`] per user relation the apply txn changed — including rows
    /// a trigger wrote in another statement or another table, which `RETURNING`
    /// never reports. This is the apply-side of the FULL blast-radius measurement
    /// the dry-run made; the engine reconciles it against the prediction and aborts
    /// on any unpredicted or excess change. Relations with no change MAY be omitted.
    fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError>;

    /// **Step 7a — commit** the apply txn (only called when both guards pass).
    fn commit(&mut self) -> Result<(), ApplyError>;

    /// **Step 7b — roll back** the apply txn (called on any guard failure or
    /// timeout). MUST be idempotent / safe to call on an already-aborted txn.
    fn rollback(&mut self) -> Result<(), ApplyError>;
}

/// PITR configuration for the apply (SPEC §4 `pitr.enabled` / §1 honest recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitrConfig {
    /// Whether the customer runs continuous WAL archiving so a restore point is
    /// meaningful. When `false`, the apply does **not** fabricate a fence: the
    /// typed-inverse is the documented undo (SPEC §1).
    pub enabled: bool,
}

impl PitrConfig {
    /// PITR enabled (a restore-point fence is created before the apply txn).
    pub const fn enabled() -> Self {
        PitrConfig { enabled: true }
    }
    /// PITR disabled — the typed-inverse is the undo (SPEC §1 honest recovery).
    pub const fn disabled() -> Self {
        PitrConfig { enabled: false }
    }
}

/// The honest-recovery posture of a committed apply (SPEC §1).
///
/// Names *which* undo mechanism is available so the audit record and the caller
/// never conflate the cheap typed-inverse with the last-resort PITR fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryFence {
    /// PITR was enabled: a restore point was created before the apply. The
    /// **typed-inverse is still the default, cheap undo**; the restore point is
    /// the last-resort fence (SPEC §1).
    PitrRestorePoint {
        /// The restore point label.
        label: String,
        /// The LSN the restore point was created at.
        lsn: String,
    },
    /// PITR was not enabled: the **typed-inverse is the only undo** (SPEC §1).
    /// Documented explicitly so the caller cannot assume a PITR safety net exists.
    TypedInverseOnly,
}

/// A committed guarded apply (SPEC §4): the rows it actually wrote, the captured
/// **typed-inverse** for the revert (#37), and the honest-recovery posture.
#[derive(Debug, Clone)]
pub struct AppliedWrite {
    /// The proposal id this apply belongs to.
    pub proposal_id: String,
    /// How many rows the forward op actually wrote (per `RETURNING`).
    pub rows_written: u64,
    /// The apply-time affected-PK-set checksum (equal to the dry-run checksum —
    /// the guard passed) for audit.
    pub apply_checksum: PkChecksum,
    /// The captured **typed-inverse** (FK-ordered pre-image) for the revert.
    pub inverse: InversePlan,
    /// The recovery posture (typed-inverse only, or + PITR restore point).
    pub fence: RecoveryFence,
    /// The `statement_timeout` (ms) the apply txn ran under.
    pub statement_timeout_ms: u64,
}

/// The forward operation described to [`certify`] from the dry-run record. Maps
/// the [`WriteKind`] + the §10.1 facts (reversible, PK-bearing) onto the
/// certified-action vocabulary so the default-deny gate (§10.3) is the *single*
/// choke point.
fn operation_from_dry_run(kind: WriteKind, dry_run: &BlastRadius) -> Operation {
    // Reaching guarded_apply means the dry-run assembled a record (it refuses
    // PK-less + volatile up front), so `reversible` reflects a captured pre-image
    // + usable PK. We still route through `certify` so the closed allow-list is
    // re-affirmed at apply time (defense in depth / fail-closed).
    let has_preimage = dry_run.reversible;
    let has_pk = true; // a record with a `pk_set_checksum` had a usable PK.
    match kind {
        WriteKind::Update => Operation::Update {
            has_preimage,
            has_pk,
        },
        WriteKind::Delete => Operation::Delete {
            has_preimage,
            has_pk,
        },
    }
}

/// Apply a dry-run-validated proposal on the primary under the §4 guards.
///
/// `proposal_id` ties the apply to its proposal; `kind` + `relation` name the
/// certified write; `dry_run` is the §10.1 grant the apply re-checks against;
/// `pitr` decides the §1 fence; `conn` is the DB seam; `barrier` is the §10.4
/// drift-injection seam; `clock` stamps the restore-point label.
///
/// On success returns an [`AppliedWrite`] carrying the captured **typed-inverse**
/// (for the revert, #37). On any guard failure / refusal / timeout returns an
/// [`ApplyError`] and **nothing is committed** (the txn is rolled back, or never
/// opened for a refusal).
#[allow(clippy::too_many_arguments)]
pub fn guarded_apply(
    proposal_id: &str,
    kind: WriteKind,
    relation: &str,
    dry_run: &BlastRadius,
    pitr: PitrConfig,
    conn: &mut dyn ApplyConn,
    barrier: &dyn ApplyBarrier,
    clock: &dyn Clock,
) -> Result<AppliedWrite, ApplyError> {
    // (0) Cross-check the grant + assemble the FULL predicted blast radius
    //     (target + every cascade relation) the apply will measure against.
    if dry_run.proposal_id != proposal_id {
        return Err(ApplyError::InvalidGrant(format!(
            "blast-radius proposal_id `{}` does not match proposal `{}`",
            dry_run.proposal_id, proposal_id
        )));
    }
    let predicted = PredictedBlastRadius::from_grant(dry_run, relation)?;

    // (10) Refused-op default-deny — BEFORE touching the DB. Anything outside the
    //      closed certified action set is refused and never applied (§10.3).
    let op = operation_from_dry_run(kind, dry_run);
    certify(&op)?; // Err(RefusedOp) → ApplyError::Refused, no txn opened.

    // (1) PITR fence — only when enabled; else the typed-inverse is the undo (§1).
    let fence = if pitr.enabled {
        let label = restore_point_label(proposal_id, clock);
        let lsn = conn.create_restore_point(&label)?;
        RecoveryFence::PitrRestorePoint { label, lsn }
    } else {
        RecoveryFence::TypedInverseOnly
    };

    // (2) BEGIN + SET LOCAL statement_timeout ≈ 3× dry-run duration.
    let timeout_ms = statement_timeout_ms(dry_run.duration_ms);
    conn.begin(timeout_ms)?;

    // From here on, every early return MUST roll back. We funnel the guarded body
    // through a helper so a single match handles rollback-on-error.
    let outcome = guarded_body(kind, relation, &predicted, conn, barrier);

    match outcome {
        Ok(forward) => {
            // (9) Every guard passed → COMMIT.
            conn.commit()?;
            let inverse = build_inverse(kind, relation, &predicted, &forward);
            let apply_checksum = forward.written_checksum(relation)?;
            Ok(AppliedWrite {
                proposal_id: proposal_id.to_string(),
                rows_written: forward.written.len() as u64,
                apply_checksum,
                inverse,
                fence,
                statement_timeout_ms: timeout_ms,
            })
        }
        Err(e) => {
            // (9b) Any guard failure / timeout → ROLLBACK, nothing committed.
            // The rollback's own error must not mask the guard error.
            let _ = conn.rollback();
            Err(e)
        }
    }
}

/// The FULL predicted blast radius the apply re-checks against (SPEC §10.1, §4) —
/// the target, every `cascade_by_table` relation (each with its dry-run PK-set
/// checksum), and the **complete per-relation `pg_stat_xact_*` change footprint**
/// (`effect_by_table`) the dry-run measured: target + cascades + every relation a
/// fired trigger wrote to (e.g. an audit table). This is what makes the apply-time
/// re-check **symmetric** with the dry-run's full-blast-radius measurement.
struct PredictedBlastRadius {
    /// The target's dry-run affected-PK-set checksum (prefixed `sha256:…`).
    target_checksum: String,
    /// Cascade relations (`cascade_by_table`), each with its dry-run checksum. The
    /// apply re-checks the PK-set of each AND captures their pre-images for the
    /// full inverse.
    cascades: Vec<(String, String)>,
    /// The FULL per-relation, **per-op-type** predicted change footprint
    /// (`effect_by_table`): every relation the dry-run's `pg_stat_xact_*` measured,
    /// mapped to its predicted in-txn [`OpCounts`]. The apply reconciles its own
    /// deltas against this **per op channel** (0-tolerance over-write on any of
    /// `ins`/`upd`/`del`; any relation outside it is unpredicted). Per-op-type is
    /// load-bearing: a predicted INSERT footprint can NOT be satisfied by an
    /// apply-time DELETE of the same total.
    effect_by_table: BTreeMap<String, OpCounts>,
}

impl PredictedBlastRadius {
    /// Assemble the predicted blast radius from the §10.1 grant for `target`.
    /// Every cascade relation must carry a recorded PK-set checksum (the dry-run
    /// refuses a PK-less cascade), else the grant is rejected. The grant MUST carry
    /// a non-empty `effect_by_table` (the dry-run's measured `pg_stat_xact_*`
    /// footprint) — a stale grant without it cannot authorize a write (fail-closed:
    /// with no predicted footprint, the apply has nothing to reconcile against and
    /// any write would be "unpredicted").
    fn from_grant(dry_run: &BlastRadius, target: &str) -> Result<Self, ApplyError> {
        let affected = &dry_run.affected;
        let target_checksum = affected
            .pk_set_checksum
            .get(target)
            .cloned()
            .ok_or_else(|| {
                ApplyError::InvalidGrant(format!(
                    "blast-radius has no pk_set_checksum for target `{target}`"
                ))
            })?;

        if affected.effect_by_table.is_empty() {
            return Err(ApplyError::InvalidGrant(format!(
                "blast-radius for `{target}` has no measured effect_by_table footprint \
                 (stale/incomplete grant — cannot reconcile the apply's full effect, refusing)"
            )));
        }
        // The target MUST be in the measured footprint (the dry-run wrote it).
        if !affected.effect_by_table.contains_key(target) {
            return Err(ApplyError::InvalidGrant(format!(
                "blast-radius effect_by_table is missing the target `{target}`"
            )));
        }

        let mut cascades = Vec::new();
        for rel in affected.cascade_by_table.keys() {
            if rel == target {
                continue;
            }
            let cs = affected.pk_set_checksum.get(rel).cloned().ok_or_else(|| {
                ApplyError::InvalidGrant(format!(
                    "blast-radius has no pk_set_checksum for cascade `{rel}`"
                ))
            })?;
            cascades.push((rel.clone(), cs));
        }

        Ok(PredictedBlastRadius {
            target_checksum,
            cascades,
            effect_by_table: affected.effect_by_table.clone(),
        })
    }

    /// The set of relations in the predicted blast radius — the FULL measured
    /// footprint (target + cascades + trigger-written tables).
    fn relations(&self) -> BTreeSet<&str> {
        self.effect_by_table.keys().map(|s| s.as_str()).collect()
    }
}

/// Steps 3–8 inside the open apply txn. Returns the forward result on success;
/// any `Err` here means the caller must roll back.
fn guarded_body(
    kind: WriteKind,
    relation: &str,
    predicted: &PredictedBlastRadius,
    conn: &mut dyn ApplyConn,
    barrier: &dyn ApplyBarrier,
) -> Result<ForwardResult, ApplyError> {
    // (3) The §10.4 seam: cross the barrier between prepare and apply. Production
    //     is a no-op; the drift tests mutate world state here.
    barrier.pause_point("between dry_run and apply");

    // (5) FULL-blast-radius apply-time PK-set re-check (0-tolerance destructive).
    //     Recompute the affected-PK-set checksum INSIDE the txn (before the forward
    //     op) for the TARGET *and every cascade relation* and compare each to its
    //     dry-run checksum. The guard is the checksum, not the count — it catches a
    //     predicate-flip (same count, different PKs) on the target AND cascade-child
    //     drift (post-snapshot child rows that swelled the cascade set).
    let apply_time = conn.recompute_pk_checksum(relation)?;
    if apply_time.as_prefixed() != predicted.target_checksum {
        return Err(ApplyError::PkSetDrift {
            relation: relation.to_string(),
            dry_run: predicted.target_checksum.clone(),
            apply_time: apply_time.as_prefixed(),
        });
    }
    for (cascade_rel, cascade_checksum) in &predicted.cascades {
        let cs = conn.recompute_pk_checksum(cascade_rel)?;
        if cs.as_prefixed() != *cascade_checksum {
            return Err(ApplyError::PkSetDrift {
                relation: cascade_rel.clone(),
                dry_run: cascade_checksum.clone(),
                apply_time: cs.as_prefixed(),
            });
        }
    }

    // (4) Forward op with RETURNING — capture the target's pre-image + actual
    //     written-PK set, AND the cascade children's pre-images (captured before
    //     the forward op deletes them) so the inverse can fully restore them. A
    //     statement_timeout overrun surfaces as ApplyError::Timeout here.
    let cascade_relations: Vec<String> =
        predicted.cascades.iter().map(|(r, _)| r.clone()).collect();
    let forward = conn.apply_forward(kind, relation, &cascade_relations)?;

    // (6) SYMMETRIC full-effect reconciliation (`pg_stat_xact_*` tuple deltas).
    //     Read the per-relation in-txn tuple deltas — the SAME measure the dry-run
    //     made — and reconcile against the prediction. This is the data-loss
    //     mechanism: it sees rows a trigger wrote in another statement / table that
    //     `RETURNING` can NEVER report.
    let deltas = conn.xact_tuple_deltas()?;
    reconcile_full_effect(predicted, &deltas)?;

    // (7) RETURNING written-set check (gate carry-forward, defense in depth). The
    //     target rows the forward op ACTUALLY wrote must match the prediction.
    let written = forward.written_checksum(relation)?;
    if written.as_prefixed() != predicted.target_checksum {
        return Err(ApplyError::WrittenSetMismatch {
            relation: relation.to_string(),
            predicted: predicted.target_checksum.clone(),
            written: written.as_prefixed(),
        });
    }

    // (8) Full reversible pre-image capture check (fail-closed). The typed-inverse
    //     must hold a pre-image for EVERY destructively-changed row across ALL
    //     relations the apply ACTUALLY touched (`deltas`) — not just the direct
    //     `predicted.cascades` children. This is the structural "0 catastrophic
    //     data-loss FN by construction" guard: a relation that lost rows but whose
    //     pre-image is not captured cannot be reverted, so we ABORT rather than
    //     commit an unrevertable change (#48 multi-level-cascade fail-closed).
    assert_reversible_preimage_coverage(relation, &deltas, &forward)?;

    // (8b) COLUMN coverage (S5 #75). The row guard above proves every changed ROW
    //      has a pre-image, but NOT that the pre-image covers every changed COLUMN.
    //      An UPDATE that mutates a column whose OLD value was never captured commits
    //      `reversible:true` with an inverse that silently cannot restore it — a
    //      catastrophic FN. Verify every target written row's pre-image covers the
    //      written columns (the conn declares them; with none declared we enforce the
    //      non-empty-pre-image floor). Defense-in-depth: even if the dry-run column
    //      gate were bypassed, the apply aborts here BEFORE commit (no mutation).
    assert_written_column_coverage(kind, relation, &forward)?;

    Ok(forward)
}

/// Step 8b — **fail-closed written-COLUMN coverage** (S5 #75).
///
/// The row-level [`assert_reversible_preimage_coverage`] proves every changed *row*
/// has a captured pre-image, but a typed-inverse `PREIMAGE_UPSERT` only restores the
/// *columns* present in each row's `before_image`. If an `UPDATE` mutated a column
/// whose OLD value the conn never captured (the S5 #75 bug: a hardcoded
/// `(owner, balance)` capture against a `SET notes = …` write), the inverse would
/// restore the wrong/no value for that column — a silent un-revertable write that
/// nonetheless committed `reversible:true`.
///
/// This guard closes that hole for the **target** of an `UPDATE`:
/// - if the conn declared the written columns ([`ForwardResult::written_columns`]),
///   every target written row's `before_image` MUST contain a pre-image for each of
///   them (excluding the PK `id`, which keys the row and is not "restored");
/// - if the conn declared none (a legacy/scripted conn), we still enforce the
///   **non-empty-pre-image floor**: a written row whose `before_image` carries only
///   the PK (or nothing) has nothing for the inverse to restore → abort.
///
/// A `DELETE`'s inverse is a whole-row re-insert (row-covered by step 8), so no
/// per-column gate applies. Any miss aborts BEFORE commit → ROLLBACK, no mutation.
fn assert_written_column_coverage(
    kind: WriteKind,
    relation: &str,
    forward: &ForwardResult,
) -> Result<(), ApplyError> {
    if kind != WriteKind::Update {
        return Ok(());
    }
    // The columns the inverse must be able to restore (the written columns minus the
    // PK, which is never re-restored — it only keys the upsert).
    let required: BTreeSet<&str> = forward
        .written_columns
        .iter()
        .map(|c| c.as_str())
        .filter(|c| *c != "id")
        .collect();

    for row in &forward.written {
        let captured: BTreeSet<&str> = row
            .before_image
            .iter()
            .map(|(c, _)| c.as_str())
            .filter(|c| *c != "id")
            .collect();

        if required.is_empty() {
            // Floor: with no declared written-column set, a pre-image that carries
            // no non-PK column cannot restore anything an UPDATE changed.
            if captured.is_empty() {
                return Err(ApplyError::UncapturedColumn {
                    relation: relation.to_string(),
                    pk: format!("{:?}", row.pk.values()),
                    missing: vec!["<any written column>".to_string()],
                });
            }
        } else {
            let missing: Vec<String> = required
                .iter()
                .filter(|c| !captured.contains(*c))
                .map(|c| c.to_string())
                .collect();
            if !missing.is_empty() {
                return Err(ApplyError::UncapturedColumn {
                    relation: relation.to_string(),
                    pk: format!("{:?}", row.pk.values()),
                    missing,
                });
            }
        }
    }
    Ok(())
}

/// Step 8 — **fail-closed reversible pre-image coverage** across the FULL actual
/// footprint (SPEC §4 step 8, #48).
///
/// The typed-inverse [`build_inverse`] captures pre-images for exactly two sources:
/// the **target** rows (from `RETURNING`, in [`ForwardResult::written`]) and each
/// **direct** `cascade_by_table` child (in [`ForwardResult::cascade_preimages`]).
/// The reconciliation footprint, however, is the FULL `pg_stat_xact_*` measure —
/// it includes **grandchildren** of a `parent → child → grandchild ON DELETE
/// CASCADE` and any other relation a fired trigger destroyed. Those rows are real
/// data loss, but [`build_inverse`] captures **no** pre-image for them and
/// [`build_inverse`]'s `fk_order` never lists them, so the revert cannot restore
/// them.
///
/// This guard closes that asymmetry. For **every** relation in the ACTUAL deltas
/// that destroyed rows on a channel the inverse must be able to undo, the captured
/// inverse must cover at least that many rows:
///
/// - **`del` (any kind)** — a deleted row is reversible only by re-inserting its
///   captured pre-image. Every relation with `del > 0` MUST be covered:
///   - the **target** is covered by `forward.written`;
///   - a **direct cascade** is covered by `forward.cascade_preimages[rel]`;
///   - **anything else** (a grandchild present in `effect_by_table` but NOT in
///     `predicted.cascades`, a trigger-deleted side relation) has **no** captured
///     pre-image → its destruction is uncapturable → **ABORT**.
/// - **`upd` on a relation that is not the target** — an identity/value change to a
///   relation outside the target also needs a captured pre-image to revert; the
///   inverse only captures the target's own `upd` pre-image, so any other relation
///   showing `upd > 0` is likewise uncapturable → **ABORT**.
///
/// (The target's own `upd` is exactly what `RETURNING` captured into
/// `forward.written`; the step-7 written-set check already pins it. A relation that
/// changed *less* than the inverse captured cannot under-restore. This is the
/// minimum bar #48 requires: **refuse** the un-capturable multi-level case. Full
/// N-level pre-image *capture* (so such cascades can be applied + reverted rather
/// than refused) stays deferred under #48.)
fn assert_reversible_preimage_coverage(
    target: &str,
    deltas: &[RelationChange],
    forward: &ForwardResult,
) -> Result<(), ApplyError> {
    // How many pre-image rows the inverse holds for each relation it can revert.
    let target_captured = forward.written.len() as u64;
    for change in deltas {
        if change.total() == 0 {
            continue;
        }
        let is_target = change.relation == target;
        let captured = if is_target {
            target_captured
        } else {
            forward
                .cascade_preimages
                .get(&change.relation)
                .map(|v| v.len() as u64)
                .unwrap_or(0)
        };

        // The `del` channel always needs a re-insert pre-image to be reversible.
        if change.del > 0 && captured < change.del {
            return Err(ApplyError::IrreversibleChange {
                relation: change.relation.clone(),
                detail: format!(
                    "{} destroyed {} row(s) but only {} pre-image(s) were captured — \
                     the typed-inverse cannot restore them (relation outside the \
                     captured target/direct-cascade set, e.g. a multi-level \
                     grandchild cascade; #48). Fail-closed: refusing to commit an \
                     unrevertable change",
                    change.relation, change.del, captured,
                ),
            });
        }

        // An identity/value-changing `upd` on any relation OTHER than the target is
        // not captured by the inverse (only the target's `upd` pre-image is). For a
        // DELETE-kind apply, a non-target `upd` is doubly unexpected. Either way it
        // is uncapturable → fail-closed.
        if !is_target && change.upd > 0 && captured < change.upd {
            return Err(ApplyError::IrreversibleChange {
                relation: change.relation.clone(),
                detail: format!(
                    "{} updated {} row(s) outside the target with only {} captured \
                     pre-image(s) — the typed-inverse cannot restore the prior values \
                     (relation outside the captured target/direct-cascade set; #48). \
                     Fail-closed: refusing to commit an unrevertable change",
                    change.relation, change.upd, captured,
                ),
            });
        }
    }
    Ok(())
}

/// Reconcile the apply txn's per-relation `pg_stat_xact_*` tuple deltas against
/// the predicted full blast radius (SPEC §4), **per op type** (`ins`/`upd`/`del`
/// reconciled independently — never a collapsed total). Fail-closed:
///
/// - ANY relation with a non-zero in-txn change that is **not** in the predicted
///   blast radius → [`ApplyError::UnpredictedRelationWrite`] (the AFTER-trigger
///   out-of-predicate `DELETE`, or the separate-table `mirror` wipe — both
///   invisible to `RETURNING`).
/// - ANY predicted relation whose actual change **on any op channel exceeds** the
///   prediction for that channel → [`ApplyError::RelationOverWrite`]. This catches
///   an out-of-predicate write to the target table, cascade drift on a child, AND
///   the **op-type substitution** the collapsed-total guard missed: a relation
///   predicted to only `ins` (e.g. an audit table) that the apply `del`s/`upd`s
///   instead trips the `del`/`upd` channel even though the *total* is unchanged —
///   the silent irreversible destructive write is now refused.
///
/// (A predicted relation changing *less* than predicted on a channel cannot
/// under-destroy data, and the PK-set re-check + RETURNING check already pin the
/// exact target set; the per-channel over-write is the data-loss direction this
/// guards. Checking each channel — rather than the sum — is what makes a
/// destructive op substituted for a predicted-only-insert op impossible to commit.)
fn reconcile_full_effect(
    predicted: &PredictedBlastRadius,
    deltas: &[RelationChange],
) -> Result<(), ApplyError> {
    let in_radius = predicted.relations();
    for change in deltas {
        if change.total() == 0 {
            continue;
        }
        if !in_radius.contains(change.relation.as_str()) {
            return Err(ApplyError::UnpredictedRelationWrite {
                relation: change.relation.clone(),
                changed: change.total(),
                ins: change.ins,
                upd: change.upd,
                del: change.del,
            });
        }
        let p = predicted
            .effect_by_table
            .get(&change.relation)
            .copied()
            .unwrap_or_default();
        let a = change.as_op_counts();
        // Compare each op channel INDEPENDENTLY. The first channel that exceeds its
        // prediction aborts — including the data-loss direction where the predicted
        // channel was 0 (e.g. an `ins`-only relation showing any `del`).
        let channel = if a.ins > p.ins {
            Some("ins")
        } else if a.upd > p.upd {
            Some("upd")
        } else if a.del > p.del {
            Some("del")
        } else {
            None
        };
        if let Some(channel) = channel {
            return Err(ApplyError::RelationOverWrite {
                relation: change.relation.clone(),
                channel,
                p_ins: p.ins,
                p_upd: p.upd,
                p_del: p.del,
                a_ins: a.ins,
                a_upd: a.upd,
                a_del: a.del,
            });
        }
    }
    Ok(())
}

/// Build the typed-inverse (§10.3) from the captured pre-image rows, covering the
/// **target AND every cascade relation** so the revert (#37) fully restores.
///
/// `UPDATE` → [`InverseKind::PreimageUpsert`] on the target. `DELETE` →
/// [`InverseKind::Insert`], re-inserting the target rows and **every
/// cascade-destroyed child row**; `fk_order` lists parents before children so the
/// revert re-inserts in FK order. The per-relation child pre-images are carried in
/// [`InversePlan::rows`] (target + cascades), each row stamped with its relation
/// via the `__relation` synthetic column so the revert can route it.
fn build_inverse(
    kind: WriteKind,
    relation: &str,
    predicted: &PredictedBlastRadius,
    forward: &ForwardResult,
) -> InversePlan {
    let inverse_kind = match kind {
        WriteKind::Update => InverseKind::for_update(),
        WriteKind::Delete => InverseKind::for_delete(),
    };
    let mut b = InversePlanBuilder::new(relation, inverse_kind);
    // Target rows first.
    for row in &forward.written {
        b = b.push_row(InverseRow::new(row.pk.clone(), row.before_image.clone()));
    }
    // Then every cascade child's pre-image (DELETE only). FK order = parent first,
    // children after, matching the order the revert re-inserts.
    let mut fk_order = vec![relation.to_string()];
    for (cascade_rel, _) in &predicted.cascades {
        if let Some(rows) = forward.cascade_preimages.get(cascade_rel) {
            for row in rows {
                let mut image = row.before_image.clone();
                // Stamp the owning relation so a multi-relation inverse is routable
                // by the revert (#37), which consumes per-relation pre-images. The
                // stamp column name is shared with the revert engine so writer and
                // reader agree on the one routing key.
                image.push((
                    crate::revert::RELATION_STAMP.to_string(),
                    pgb_core::inverse::ImageValue::Text(cascade_rel.clone()),
                ));
                b = b.push_row(InverseRow::new(row.pk.clone(), image));
            }
        }
        fk_order.push(cascade_rel.clone());
    }
    b.fk_order(fk_order).build()
}

/// A deterministic restore-point label for a proposal, stamped against the
/// injected clock (SPEC §10.4 — no wall-clock read in gating; the stamp is
/// human-facing only). Postgres restore-point names are truncated to 64 bytes, so
/// this stays well under that.
fn restore_point_label(proposal_id: &str, clock: &dyn Clock) -> String {
    format!("pgb_{}_{}", proposal_id, clock.now_unix_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::{ClosureBarrier, MockClock, NoopBarrier, PkValue};
    use std::sync::{Arc, Mutex};

    // ---- test fixtures -----------------------------------------------------

    fn checksum_of(rel: &str, ids: &[i64]) -> PkChecksum {
        let mut b = PkSetBuilder::for_relation(rel);
        for &id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().unwrap()
    }

    /// A blast-radius grant for `rel` over the integer PK set `ids`.
    fn grant_for(proposal_id: &str, rel: &str, ids: &[i64], duration_ms: u64) -> BlastRadius {
        use pgb_core::blast_radius::Affected;
        use pgb_core::LockMode;
        let mut pk_set_checksum = std::collections::BTreeMap::new();
        pk_set_checksum.insert(rel.to_string(), checksum_of(rel, ids).as_prefixed());
        let mut by_table = std::collections::BTreeMap::new();
        by_table.insert(rel.to_string(), ids.len() as u64);
        // The measured full footprint: by default just the target changed exactly
        // its affected-row count, as an UPDATE (`upd`) — matching the MockConn's
        // default `tuple_deltas`. (No cascades / trigger side-effects in the base
        // grant; DELETE tests use `grant_with_cascade`, which rewrites the channel
        // to `del`; trigger tests set the deltas directly.)
        let mut effect_by_table = std::collections::BTreeMap::new();
        effect_by_table.insert(rel.to_string(), OpCounts::new(0, ids.len() as u64, 0));
        BlastRadius {
            proposal_id: proposal_id.to_string(),
            clone_lsn: "0/0".into(),
            staleness_lsn_bytes: 0,
            affected: Affected {
                by_table,
                cascade_by_table: std::collections::BTreeMap::new(),
                pk_set_checksum,
                effect_by_table,
                total_rows: ids.len() as u64,
            },
            triggers_fired: vec![],
            locks: vec![],
            max_lock_mode: LockMode::RowExclusiveLock,
            duration_ms,
            wal_bytes: 0,
            constraint_violations: vec![],
            reversible: true,
            inverse_kind: InverseKind::PreimageUpsert,
            predicate_volatile: false,
        }
    }

    fn captured(ids: &[i64]) -> Vec<CapturedRow> {
        captured_with_cols(ids, &["status"])
    }

    /// Capture `ids` with a scripted set of pre-image columns (each a text `"x"`),
    /// so a test can model a pre-image that does (or does NOT) cover a declared
    /// written column — the S5 #75 column-coverage guard.
    fn captured_with_cols(ids: &[i64], cols: &[&str]) -> Vec<CapturedRow> {
        ids.iter()
            .map(|&id| CapturedRow {
                pk: PkTuple::single(PkValue::Int(id)),
                before_image: cols
                    .iter()
                    .map(|c| ((*c).to_string(), PkValue::Text("x".into())))
                    .collect(),
            })
            .collect()
    }

    /// A scripted in-memory `ApplyConn`. The script lets a test set: the PK set
    /// the apply-time recompute sees per relation (drift, incl. cascades), the rows
    /// the forward op writes (written-set drift / trigger-outside-predicate), the
    /// per-relation `pg_stat_xact_*` tuple deltas (the FULL-effect reconciliation —
    /// trigger writes to other rows/tables + cascade drift), the cascade
    /// pre-images, and a forced timeout.
    #[derive(Default)]
    struct MockConnInner {
        /// Per-relation PK set the apply-time recompute returns. The target
        /// defaults to `target`; cascades are added by the test.
        recompute_ids: BTreeMap<String, Vec<i64>>,
        /// PK set the forward op writes via RETURNING for the target (defaults to
        /// `target`).
        written_ids: Vec<i64>,
        /// Per-relation in-txn tuple deltas the apply reconciles (the symmetric
        /// `pg_stat_xact_*` measure). If unset, defaults to "target changed exactly
        /// its written rows" so the happy path reconciles cleanly.
        tuple_deltas: Option<Vec<RelationChange>>,
        /// Per-cascade-relation captured pre-image PK ids (for the full inverse).
        cascade_preimage_ids: BTreeMap<String, Vec<i64>>,
        /// If set, `apply_forward` returns Timeout.
        timeout_at_forward: Option<u64>,
        /// S5 #75: the columns the forward op declares it wrote on the target
        /// (`ForwardResult::written_columns`). Empty ⇒ none declared.
        written_columns: Vec<String>,
        /// S5 #75: override the captured target `before_image` columns (the
        /// `(col, "x")` text image each written row carries). `None` ⇒ the default
        /// `[("status", "open")]` — so a test can model a pre-image that does NOT
        /// cover a declared written column (the column-coverage abort).
        written_image_cols: Option<Vec<String>>,
        // observability
        restore_points: Vec<String>,
        began_with_timeout: Option<u64>,
        committed: bool,
        rolled_back: bool,
        forward_ran: bool,
    }

    #[derive(Clone)]
    struct MockConn(Arc<Mutex<MockConnInner>>);

    impl MockConn {
        fn new(rel: &str, target: &[i64]) -> Self {
            let mut recompute_ids = BTreeMap::new();
            recompute_ids.insert(rel.to_string(), target.to_vec());
            MockConn(Arc::new(Mutex::new(MockConnInner {
                recompute_ids,
                written_ids: target.to_vec(),
                ..Default::default()
            })))
        }
        fn inner(&self) -> std::sync::MutexGuard<'_, MockConnInner> {
            self.0.lock().expect("mock conn mutex poisoned")
        }
    }

    impl ApplyConn for MockConn {
        fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError> {
            self.inner().restore_points.push(label.to_string());
            Ok("0/16B6358".to_string())
        }
        fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError> {
            self.inner().began_with_timeout = Some(timeout_ms);
            Ok(())
        }
        fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
            let ids = self
                .inner()
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
            self.inner().forward_ran = true;
            if let Some(t) = self.inner().timeout_at_forward {
                return Err(ApplyError::Timeout { timeout_ms: t });
            }
            let ids = self.inner().written_ids.clone();
            let image_cols = self.inner().written_image_cols.clone();
            let written_columns = self.inner().written_columns.clone();
            let written = match &image_cols {
                Some(cols) => {
                    let refs: Vec<&str> = cols.iter().map(|s| s.as_str()).collect();
                    captured_with_cols(&ids, &refs)
                }
                None => captured(&ids),
            };
            let mut cascade_preimages = BTreeMap::new();
            for rel in cascade_relations {
                let cids = self
                    .inner()
                    .cascade_preimage_ids
                    .get(rel)
                    .cloned()
                    .unwrap_or_default();
                cascade_preimages.insert(rel.clone(), captured(&cids));
            }
            Ok(ForwardResult {
                written,
                cascade_preimages,
                written_columns,
            })
        }
        fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
            if let Some(d) = self.inner().tuple_deltas.clone() {
                return Ok(d);
            }
            // Default: the target changed exactly the rows it wrote (so the happy
            // path reconciles), as an UPDATE (upd) — counts are what matters.
            let n = self.inner().written_ids.len() as u64;
            Ok(vec![RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: n,
                del: 0,
            }])
        }
        fn commit(&mut self) -> Result<(), ApplyError> {
            self.inner().committed = true;
            Ok(())
        }
        fn rollback(&mut self) -> Result<(), ApplyError> {
            self.inner().rolled_back = true;
            Ok(())
        }
    }

    const REL: &str = "public.orders";

    // ---- statement_timeout sizing -----------------------------------------

    #[test]
    fn statement_timeout_is_three_x_dry_run_with_a_floor() {
        // 3× a slow dry-run dominates.
        assert_eq!(statement_timeout_ms(5_000), 15_000);
        // A fast dry-run is clamped up to the floor so the apply can finish.
        assert_eq!(statement_timeout_ms(10), MIN_STATEMENT_TIMEOUT_MS);
        assert_eq!(statement_timeout_ms(0), MIN_STATEMENT_TIMEOUT_MS);
        // No overflow on a pathological duration.
        assert_eq!(
            statement_timeout_ms(u64::MAX),
            u64::MAX.saturating_mul(3).max(MIN_STATEMENT_TIMEOUT_MS)
        );
    }

    // ---- happy path: commits + captures the typed-inverse ------------------

    #[test]
    fn no_drift_commits_and_captures_typed_inverse() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let grant = grant_for("p-1", REL, &[2, 4, 6, 8, 10], 7);
        let applied = guarded_apply(
            "p-1",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("no-drift apply must commit");

        assert_eq!(applied.rows_written, 5);
        // Typed-inverse captured + matches the changed rows (PreimageUpsert).
        assert_eq!(applied.inverse.kind, InverseKind::PreimageUpsert);
        assert_eq!(applied.inverse.rows.len(), 5);
        assert_eq!(applied.inverse.relation, REL);
        // FK order for a single relation is just [relation].
        assert_eq!(applied.inverse.fk_order, vec![REL.to_string()]);
        // PITR disabled → the typed-inverse is the documented undo (§1).
        assert_eq!(applied.fence, RecoveryFence::TypedInverseOnly);
        // The txn committed (and was NOT rolled back).
        let p = probe.inner();
        assert!(p.committed, "no-drift apply must COMMIT");
        assert!(!p.rolled_back);
        assert!(p.restore_points.is_empty(), "no fence when PITR disabled");
        assert_eq!(p.began_with_timeout, Some(MIN_STATEMENT_TIMEOUT_MS));
    }

    #[test]
    fn pitr_enabled_creates_restore_point_fence_before_apply() {
        let mut conn = MockConn::new(REL, &[1, 2, 3]);
        let probe = conn.clone();
        let grant = grant_for("p-pitr", REL, &[1, 2, 3], 1_000);
        let applied = guarded_apply(
            "p-pitr",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::enabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::starting_at(42),
        )
        .expect("apply commits");

        // DELETE → INSERT inverse.
        assert_eq!(applied.inverse.kind, InverseKind::Insert);
        match &applied.fence {
            RecoveryFence::PitrRestorePoint { label, lsn } => {
                assert!(label.starts_with("pgb_p-pitr_"));
                assert_eq!(lsn, "0/16B6358");
            }
            other => panic!("expected a PITR fence, got {other:?}"),
        }
        let p = probe.inner();
        assert_eq!(p.restore_points.len(), 1, "exactly one restore point");
        // 3× 1000ms dominates the floor.
        assert_eq!(p.began_with_timeout, Some(3_000));
        assert!(p.committed);
    }

    // ---- drift: apply-time PK-set re-check (0-tolerance) -------------------

    #[test]
    fn drift_insert_over_count_aborts() {
        // Apply-time recompute sees an extra matching row (101) → drift → ABORT.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        // Inject the drift through the barrier (as production tests do).
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            conn_for_barrier
                .inner()
                .recompute_ids
                .insert(REL.to_string(), vec![2, 4, 6, 8, 10, 101]);
        });
        let grant = grant_for("p-2", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-2",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::PkSetDrift { .. }), "{err:?}");
        let p = probe.inner();
        assert!(p.rolled_back, "drift must ROLLBACK");
        assert!(!p.committed);
        assert!(
            !p.forward_ran,
            "the forward op must NOT run after pre-op drift is caught"
        );
    }

    #[test]
    fn drift_delete_shrink_under_count_aborts() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            // one matching row vanished post-snapshot.
            conn_for_barrier
                .inner()
                .recompute_ids
                .insert(REL.to_string(), vec![2, 4, 6, 8]);
        });
        let grant = grant_for("p-3", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-3",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::PkSetDrift { .. }), "{err:?}");
        assert!(probe.inner().rolled_back);
    }

    #[test]
    fn drift_predicate_flip_same_count_different_pks_aborts() {
        // HEADLINE: same cardinality, different PKs. A row-count guard PASSES
        // here; only the PK-set checksum catches it.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            // 10 flipped OUT, 1 flipped IN — count is still 5.
            conn_for_barrier
                .inner()
                .recompute_ids
                .insert(REL.to_string(), vec![1, 2, 4, 6, 8]);
        });
        let grant = grant_for("p-4", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-4",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::PkSetDrift {
                dry_run,
                apply_time,
                ..
            } => assert_ne!(dry_run, apply_time),
            other => panic!("expected PkSetDrift, got {other:?}"),
        }
        assert!(probe.inner().rolled_back);
    }

    // ---- RETURNING written-set check (the carry-forward) -------------------

    #[test]
    fn returning_written_set_mismatch_aborts() {
        // The pre-op recompute MATCHES the grant (so step 5 passes) and the txn
        // changed exactly the predicted COUNT of target rows (so the stat-delta
        // reconciliation passes), but the forward op WROTE a different *set* of the
        // same cardinality (id=999 in place of id=10). Only the RETURNING
        // written-set checksum (step 7) catches this same-relation, same-count
        // identity drift.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        // recompute matches grant; written set swaps id=10 for an out-of-set 999
        // (same cardinality 5 → stat-delta count matches predicted 5).
        conn.inner().written_ids = vec![2, 4, 6, 8, 999];
        let probe = conn.clone();
        let grant = grant_for("p-5", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-5",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::WrittenSetMismatch { .. }),
            "{err:?}"
        );
        let p = probe.inner();
        assert!(
            p.forward_ran,
            "the forward op ran (then we caught the drift)"
        );
        assert!(p.rolled_back, "written-set mismatch must ROLLBACK");
        assert!(!p.committed);
    }

    // ---- FULL-effect reconciliation (the data-loss mechanism) --------------

    /// A grant for `rel` over `ids` PLUS a cascade relation `cascade_rel` over
    /// `cascade_ids` (recorded in `cascade_by_table` + `pk_set_checksum`).
    fn grant_with_cascade(
        proposal_id: &str,
        rel: &str,
        ids: &[i64],
        cascade_rel: &str,
        cascade_ids: &[i64],
        duration_ms: u64,
    ) -> BlastRadius {
        let mut g = grant_for(proposal_id, rel, ids, duration_ms);
        g.affected
            .cascade_by_table
            .insert(cascade_rel.to_string(), cascade_ids.len() as u64);
        g.affected.pk_set_checksum.insert(
            cascade_rel.to_string(),
            checksum_of(cascade_rel, cascade_ids).as_prefixed(),
        );
        // This is a DELETE-with-cascade grant: the target and the cascade child are
        // both DELETEs in the measured footprint (the base `grant_for` typed the
        // target as `upd`; rewrite it to `del` so the per-op-type reconciliation
        // matches the DELETE deltas these tests inject).
        g.affected
            .effect_by_table
            .insert(rel.to_string(), OpCounts::new(0, 0, ids.len() as u64));
        g.affected.effect_by_table.insert(
            cascade_rel.to_string(),
            OpCounts::new(0, 0, cascade_ids.len() as u64),
        );
        g.affected.total_rows = ids.len() as u64 + cascade_ids.len() as u64;
        g.inverse_kind = InverseKind::Insert;
        g
    }

    #[test]
    fn unpredicted_relation_write_aborts_the_trigger_other_table_case() {
        // BLOCKER 1 (other-table): the target's RETURNING matches the grant, but an
        // AFTER trigger wiped a SEPARATE relation (`public.mirror`) that is NOT in
        // the blast radius. RETURNING can never see it; the pg_stat_xact delta does.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        // target changed exactly as predicted, but `mirror` shows a delete the
        // prediction never had.
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 4,
                del: 0,
            },
            RelationChange {
                relation: "public.mirror".to_string(),
                ins: 0,
                upd: 0,
                del: 3,
            },
        ]);
        let probe = conn.clone();
        let grant = grant_for("p-mirror", REL, &[2, 4, 6, 8], 5);
        let err = guarded_apply(
            "p-mirror",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::UnpredictedRelationWrite { relation, del, .. } => {
                assert_eq!(relation, "public.mirror");
                assert_eq!(del, 3);
            }
            other => panic!("expected UnpredictedRelationWrite, got {other:?}"),
        }
        let p = probe.inner();
        assert!(p.rolled_back, "unpredicted-relation write must ROLLBACK");
        assert!(!p.committed);
    }

    #[test]
    fn out_of_predicate_trigger_write_to_target_aborts_via_overwrite() {
        // BLOCKER 1 (same-table out-of-predicate): UPDATE id%2=0 RETURNING={2,4,6,8}
        // == grant, but an AFTER trigger also DELETEs id=7 (odd → out of predicate).
        // RETURNING never surfaces id=7. The target's predicted footprint is upd=4,
        // del=0; the apply's delta is upd=4, del=1 → the `del` channel (actual 1 >
        // predicted 0) ABORTs (id=7 would be irreversible).
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().tuple_deltas = Some(vec![RelationChange {
            relation: REL.to_string(),
            ins: 0,
            upd: 4,
            del: 1, // the trigger's out-of-predicate DELETE id=7
        }]);
        let probe = conn.clone();
        let grant = grant_for("p-kill7", REL, &[2, 4, 6, 8], 5);
        let err = guarded_apply(
            "p-kill7",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::RelationOverWrite {
                relation,
                channel,
                p_del,
                a_del,
                ..
            } => {
                assert_eq!(relation, REL);
                assert_eq!(
                    channel, "del",
                    "the out-of-predicate DELETE tripped the del channel"
                );
                assert_eq!(p_del, 0);
                assert_eq!(a_del, 1);
            }
            other => panic!("expected RelationOverWrite, got {other:?}"),
        }
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    #[test]
    fn cascade_drift_more_children_than_predicted_aborts() {
        // BLOCKER 2: +N child rows added post-snapshot under an in-predicate parent.
        // The parent PK set is unchanged ({2,4,6,8}), the parent RETURNING matches,
        // but the DELETE cascade destroyed MORE children than predicted. The
        // cascade delta (54) > predicted (8) → RelationOverWrite ABORT.
        let cascade = "public.entries";
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().recompute_ids.insert(
            cascade.to_string(),
            // cascade PK-set recompute UNCHANGED (the +50 rows are NEW children the
            // dry-run grant's PK-set doesn't include — but the parent set is what
            // the grant pinned; here we model the cascade checksum drifting too).
            vec![20, 40, 60, 80],
        );
        // Predicted cascade = {20,40,60,80} (4 rows recorded), but at apply time the
        // cascade destroyed 54.
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 0,
                del: 4,
            },
            RelationChange {
                relation: cascade.to_string(),
                ins: 0,
                upd: 0,
                del: 54,
            },
        ]);
        conn.inner()
            .cascade_preimage_ids
            .insert(cascade.to_string(), vec![20, 40, 60, 80]);
        let probe = conn.clone();
        let grant = grant_with_cascade(
            "p-cascade",
            REL,
            &[2, 4, 6, 8],
            cascade,
            &[20, 40, 60, 80],
            5,
        );
        let err = guarded_apply(
            "p-cascade",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::RelationOverWrite {
                relation,
                channel,
                p_del,
                a_del,
                ..
            } => {
                assert_eq!(relation, cascade);
                assert_eq!(channel, "del");
                assert_eq!(p_del, 4);
                assert_eq!(a_del, 54);
            }
            other => panic!("expected cascade RelationOverWrite, got {other:?}"),
        }
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    // ---- op-type substitution (THE third BLOCKER) --------------------------

    /// THE BLOCKER: a predicted **INSERT** footprint of N into a side / trigger-
    /// written relation, but the post-snapshot trigger actually **DELETEs** N
    /// pre-existing rows of that same relation. The *total* is identical (N), so a
    /// collapsed-total guard would PASS and commit an irreversible destructive
    /// write. The per-op-type reconciliation sees `del=N > predicted del=0` on that
    /// relation → ABORT.
    #[test]
    fn op_type_substitution_predicted_insert_actual_delete_aborts() {
        let audit = "public.account_audit";
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        // target changed exactly as predicted (upd=4). The audit relation was
        // predicted to INSERT 4 rows; at apply time the swapped trigger DELETEd 4
        // PRE-EXISTING audit rows instead — same total (4), opposite op.
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 4,
                del: 0,
            },
            RelationChange {
                relation: audit.to_string(),
                ins: 0,
                upd: 0,
                del: 4, // destructive DELETE substituted for the predicted INSERT
            },
        ]);
        let probe = conn.clone();
        // Grant predicts: target upd=4, audit INSERT 4 (ins=4, del=0).
        let mut grant = grant_for("p-opsub", REL, &[2, 4, 6, 8], 5);
        grant
            .affected
            .effect_by_table
            .insert(audit.to_string(), OpCounts::new(4, 0, 0));
        let err = guarded_apply(
            "p-opsub",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::RelationOverWrite {
                relation,
                channel,
                p_ins,
                p_del,
                a_del,
                ..
            } => {
                assert_eq!(relation, audit);
                assert_eq!(channel, "del", "the substituted DELETE tripped the del channel");
                assert_eq!(p_ins, 4, "the prediction was an INSERT of 4");
                assert_eq!(p_del, 0, "the prediction had NO deletes");
                assert_eq!(a_del, 4, "the apply DELETEd 4 pre-existing rows");
            }
            other => panic!(
                "op-type substitution (predicted ins, actual del, same total) MUST abort, got {other:?}"
            ),
        }
        let p = probe.inner();
        assert!(
            p.rolled_back,
            "the destructive op substitution must ROLLBACK"
        );
        assert!(
            !p.committed,
            "it must NOT commit — the 4 audit rows are intact"
        );
    }

    /// The upd-for-ins substitution: a relation predicted to only INSERT that the
    /// apply UPDATEs instead (same total). Caught on the `upd` channel → ABORT.
    #[test]
    fn op_type_substitution_predicted_insert_actual_update_aborts() {
        let side = "public.side_table";
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 4,
                del: 0,
            },
            RelationChange {
                relation: side.to_string(),
                ins: 0,
                upd: 3, // UPDATE substituted for the predicted INSERT
                del: 0,
            },
        ]);
        let probe = conn.clone();
        let mut grant = grant_for("p-updsub", REL, &[2, 4, 6, 8], 5);
        grant
            .affected
            .effect_by_table
            .insert(side.to_string(), OpCounts::new(3, 0, 0));
        let err = guarded_apply(
            "p-updsub",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::RelationOverWrite {
                relation, channel, ..
            } => {
                assert_eq!(relation, side);
                assert_eq!(channel, "upd");
            }
            other => panic!("expected RelationOverWrite on the upd channel, got {other:?}"),
        }
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    /// A relation predicted to INSERT N that the apply INSERTs N of → no drift, the
    /// same-op-type happy path still commits (the guard does not over-fire).
    #[test]
    fn predicted_insert_matched_by_insert_commits() {
        let audit = "public.account_audit";
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 4,
                del: 0,
            },
            RelationChange {
                relation: audit.to_string(),
                ins: 4, // matches the predicted INSERT
                upd: 0,
                del: 0,
            },
        ]);
        let probe = conn.clone();
        let mut grant = grant_for("p-okins", REL, &[2, 4, 6, 8], 5);
        grant
            .affected
            .effect_by_table
            .insert(audit.to_string(), OpCounts::new(4, 0, 0));
        guarded_apply(
            "p-okins",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("a predicted INSERT met by an INSERT of the same count must COMMIT");
        assert!(probe.inner().committed);
        assert!(!probe.inner().rolled_back);
    }

    /// The stale-grant unit test the reviewer flagged: a grant whose
    /// `effect_by_table` is empty (a legacy §10.1 record, or a measurement that
    /// recorded no footprint) cannot authorize a write — there is no predicted
    /// footprint to reconcile against → `InvalidGrant`, fail-closed, BEFORE any DB
    /// work (no txn opened).
    #[test]
    fn stale_grant_with_empty_effect_by_table_is_refused() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        let probe = conn.clone();
        let mut grant = grant_for("p-stale", REL, &[2, 4, 6, 8], 5);
        grant.affected.effect_by_table.clear(); // models a legacy / unmeasured grant
        let err = guarded_apply(
            "p-stale",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::InvalidGrant(_)), "{err:?}");
        let p = probe.inner();
        assert!(
            p.began_with_timeout.is_none(),
            "a stale grant must be refused before the apply txn opens"
        );
        assert!(!p.forward_ran && !p.committed && !p.rolled_back);
    }

    #[test]
    fn cascade_delete_commits_and_captures_full_fk_ordered_inverse() {
        // The LEGIT cascade case: a DELETE on the parent that cascades to children,
        // no drift. It must COMMIT and the inverse must hold the parent rows AND
        // every cascade-child pre-image, FK-ordered (parent before children).
        let cascade = "public.entries";
        let mut conn = MockConn::new(REL, &[2, 4]);
        conn.inner()
            .recompute_ids
            .insert(cascade.to_string(), vec![20, 21, 40, 41]);
        conn.inner()
            .cascade_preimage_ids
            .insert(cascade.to_string(), vec![20, 21, 40, 41]);
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 0,
                del: 2,
            },
            RelationChange {
                relation: cascade.to_string(),
                ins: 0,
                upd: 0,
                del: 4,
            },
        ]);
        let probe = conn.clone();
        let grant = grant_with_cascade("p-okcasc", REL, &[2, 4], cascade, &[20, 21, 40, 41], 5);
        let applied = guarded_apply(
            "p-okcasc",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("legit cascade delete must COMMIT");

        assert!(probe.inner().committed);
        // INSERT inverse, FK-ordered parent → child.
        assert_eq!(applied.inverse.kind, InverseKind::Insert);
        assert_eq!(
            applied.inverse.fk_order,
            vec![REL.to_string(), cascade.to_string()]
        );
        // Inverse covers the 2 parent rows + 4 child pre-images = 6 rows.
        assert_eq!(applied.inverse.rows.len(), 6);
        // The child rows carry the __relation stamp so the revert can route them.
        let child_rows = applied
            .inverse
            .rows
            .iter()
            .filter(|r| {
                r.before_image
                    .iter()
                    .any(|(c, v)| c == "__relation" && *v == PkValue::Text(cascade.into()))
            })
            .count();
        assert_eq!(child_rows, 4, "every cascade child pre-image is captured");
    }

    #[test]
    fn cascade_without_captured_preimages_aborts_fail_closed() {
        // Fail-closed reversibility: the cascade destroyed children but NO
        // pre-images were captured → the change is not certifiably reversible →
        // ABORT (never commit an unrevertable change).
        let cascade = "public.entries";
        let mut conn = MockConn::new(REL, &[2, 4]);
        conn.inner()
            .recompute_ids
            .insert(cascade.to_string(), vec![20, 21, 40, 41]);
        // NOTE: cascade_preimage_ids is intentionally empty (none captured).
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 0,
                del: 2,
            },
            RelationChange {
                relation: cascade.to_string(),
                ins: 0,
                upd: 0,
                del: 4,
            },
        ]);
        let probe = conn.clone();
        let grant = grant_with_cascade("p-nocap", REL, &[2, 4], cascade, &[20, 21, 40, 41], 5);
        let err = guarded_apply(
            "p-nocap",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::IrreversibleChange { .. }),
            "{err:?}"
        );
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    // ---- THE S3 BLOCKER: multi-level (grandchild) cascade is fail-closed ----

    /// A `parent → child → grandchild ON DELETE CASCADE` grant (#48). The dry-run's
    /// FULL `pg_stat_xact_*` measure (`full_effect`) records the grandchild's `del`
    /// into `effect_by_table`, but `cascade_by_table` walks **direct children only**
    /// — so the grandchild is present in `effect_by_table` and ABSENT from
    /// `cascade_by_table` (and therefore from `predicted.cascades`). This is the
    /// exact asymmetry the S3 sprint review flagged.
    #[allow(clippy::too_many_arguments)]
    fn grant_three_level_cascade(
        proposal_id: &str,
        parent: &str,
        parent_ids: &[i64],
        child: &str,
        child_ids: &[i64],
        grandchild: &str,
        grandchild_ids: &[i64],
        duration_ms: u64,
    ) -> BlastRadius {
        // Start from a normal parent→child (DIRECT) cascade grant.
        let mut g = grant_with_cascade(
            proposal_id,
            parent,
            parent_ids,
            child,
            child_ids,
            duration_ms,
        );
        // The grandchild is in the MEASURED full footprint (`effect_by_table`, via
        // the dry-run's `full_effect`) as a DELETE — but NOT in `cascade_by_table`,
        // because apply discovery walks DIRECT children only (#48). We deliberately
        // do NOT add it to `cascade_by_table`/`pk_set_checksum`.
        g.affected.effect_by_table.insert(
            grandchild.to_string(),
            OpCounts::new(0, 0, grandchild_ids.len() as u64),
        );
        g.affected.total_rows = g
            .affected
            .total_rows
            .saturating_add(grandchild_ids.len() as u64);
        g
    }

    #[test]
    fn multilevel_grandchild_cascade_delete_aborts_fail_closed() {
        // THE BLOCKER (#48): parent → child → grandchild ON DELETE CASCADE.
        //
        // - parent `public.orders` deletes {2,4}                  (target, captured)
        // - child  `public.entries` deletes {20,21,40,41}   (DIRECT cascade, captured)
        // - grandchild `public.entry_lines` deletes 8 rows  (in effect_by_table ONLY,
        //                                                     NOT in cascade_by_table)
        //
        // Reconciliation passes for the grandchild (it IS in effect_by_table and
        // actual == predicted), the grandchild PK-set is never recomputed, and
        // `build_inverse` captures NO pre-image for it. Step 8 MUST notice that the
        // grandchild destroyed 8 rows with 0 captured pre-images → IrreversibleChange
        // ABORT. Before the fix this COMMITTED → 8 grandchild rows silently lost on
        // revert.
        let child = "public.entries";
        let grandchild = "public.entry_lines";
        let mut conn = MockConn::new(REL, &[2, 4]);
        // Step-5 recompute matches for target + DIRECT child (the only relations the
        // engine rechecks — the grandchild is never recomputed, per #48).
        conn.inner()
            .recompute_ids
            .insert(child.to_string(), vec![20, 21, 40, 41]);
        // The DIRECT child's pre-images ARE captured (1-level capture works).
        conn.inner()
            .cascade_preimage_ids
            .insert(child.to_string(), vec![20, 21, 40, 41]);
        // The ACTUAL apply footprint: target del=2, child del=4, AND grandchild
        // del=8 — exactly what the dry-run measured into effect_by_table, so the
        // per-op-type reconciliation (step 6) PASSES for every relation.
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 0,
                del: 2,
            },
            RelationChange {
                relation: child.to_string(),
                ins: 0,
                upd: 0,
                del: 4,
            },
            RelationChange {
                relation: grandchild.to_string(),
                ins: 0,
                upd: 0,
                del: 8, // 8 grandchildren destroyed, ZERO pre-images captured
            },
        ]);
        let probe = conn.clone();
        let grant = grant_three_level_cascade(
            "p-grandchild",
            REL,
            &[2, 4],
            child,
            &[20, 21, 40, 41],
            grandchild,
            &[100, 101, 102, 103, 104, 105, 106, 107],
            5,
        );
        let err = guarded_apply(
            "p-grandchild",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        // The grandchild's destruction has no captured pre-image → fail-closed ABORT.
        match err {
            ApplyError::IrreversibleChange { relation, .. } => {
                assert_eq!(
                    relation, grandchild,
                    "the UNCAPTURED grandchild cascade must be the relation that aborts"
                );
            }
            other => panic!(
                "a multi-level grandchild cascade with no captured pre-image MUST \
                 ABORT (IrreversibleChange), got {other:?}"
            ),
        }
        let p = probe.inner();
        assert!(
            p.rolled_back,
            "the un-revertable multi-level cascade must ROLLBACK"
        );
        assert!(
            !p.committed,
            "it must NOT commit — the 8 grandchild rows are intact, primary unchanged"
        );
    }

    #[test]
    fn multilevel_grandchild_with_captured_preimages_commits() {
        // No-regression / completeness: if the grandchild's pre-images WERE captured
        // (i.e. a future N-level capture supplies them via cascade_preimages, even
        // though it is not in `cascade_by_table`), step 8 is satisfied and the apply
        // commits. This proves the guard keys on CAPTURED COVERAGE, not merely on
        // membership in `predicted.cascades` — so it does not over-fire.
        let child = "public.entries";
        let grandchild = "public.entry_lines";
        let mut conn = MockConn::new(REL, &[2, 4]);
        conn.inner()
            .recompute_ids
            .insert(child.to_string(), vec![20, 21, 40, 41]);
        conn.inner()
            .cascade_preimage_ids
            .insert(child.to_string(), vec![20, 21, 40, 41]);
        // Supply the grandchild's pre-images too (8 rows) — full coverage.
        conn.inner().cascade_preimage_ids.insert(
            grandchild.to_string(),
            vec![100, 101, 102, 103, 104, 105, 106, 107],
        );
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 0,
                del: 2,
            },
            RelationChange {
                relation: child.to_string(),
                ins: 0,
                upd: 0,
                del: 4,
            },
            RelationChange {
                relation: grandchild.to_string(),
                ins: 0,
                upd: 0,
                del: 8,
            },
        ]);
        let probe = conn.clone();
        let mut grant = grant_three_level_cascade(
            "p-gc-ok",
            REL,
            &[2, 4],
            child,
            &[20, 21, 40, 41],
            grandchild,
            &[100, 101, 102, 103, 104, 105, 106, 107],
            5,
        );
        // For the forward op to capture the grandchild's pre-images, the engine must
        // hand it to `apply_forward` as a cascade relation. Model the N-level capture
        // seam: register the grandchild in cascade_by_table + pk_set_checksum so it
        // is in `predicted.cascades` and the MockConn captures it.
        grant
            .affected
            .cascade_by_table
            .insert(grandchild.to_string(), 8);
        grant.affected.pk_set_checksum.insert(
            grandchild.to_string(),
            checksum_of(grandchild, &[100, 101, 102, 103, 104, 105, 106, 107]).as_prefixed(),
        );
        conn.inner().recompute_ids.insert(
            grandchild.to_string(),
            vec![100, 101, 102, 103, 104, 105, 106, 107],
        );
        guarded_apply(
            "p-gc-ok",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("a fully-captured multi-level cascade may COMMIT");
        assert!(probe.inner().committed);
        assert!(!probe.inner().rolled_back);
    }

    /// A trigger that DELETEs rows in a relation present in `effect_by_table` (so it
    /// is in-radius and reconciles) but is **not** the target and not a captured
    /// cascade — same structural hole as the grandchild, reached via a trigger
    /// rather than a declarative cascade. Must ABORT fail-closed.
    #[test]
    fn trigger_deleted_inradius_relation_without_preimage_aborts() {
        let side = "public.audit_shadow";
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().tuple_deltas = Some(vec![
            RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: 4,
                del: 0,
            },
            RelationChange {
                relation: side.to_string(),
                ins: 0,
                upd: 0,
                del: 3, // trigger destroyed 3 rows; predicted del=3 so reconcile PASSES
            },
        ]);
        let probe = conn.clone();
        let mut grant = grant_for("p-shadow", REL, &[2, 4, 6, 8], 5);
        // The side relation is in the measured footprint as a DELETE of 3 (so the
        // per-op-type reconciliation passes) but is NOT a captured cascade.
        grant
            .affected
            .effect_by_table
            .insert(side.to_string(), OpCounts::new(0, 0, 3));
        let err = guarded_apply(
            "p-shadow",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::IrreversibleChange { relation, .. } => assert_eq!(relation, side),
            other => {
                panic!("expected IrreversibleChange on the uncaptured side relation, got {other:?}")
            }
        }
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    // ---- S5 #75: written-COLUMN coverage (apply-time, defense-in-depth) -----

    /// THE S5 #75 BLOCKER at the engine layer: an UPDATE that DECLARES it wrote the
    /// `notes` column but whose captured pre-image holds only `status` (the old
    /// hardcoded shape never captured `notes`). Step 8b column-coverage MUST abort
    /// with `UncapturedColumn` BEFORE commit — even though every ROW has a pre-image
    /// (step 8 passes) — because the inverse cannot restore the written `notes`. A
    /// write must NEVER commit `reversible:true` with an incomplete inverse.
    #[test]
    fn uncaptured_written_column_aborts_before_commit() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        // The forward op declares it wrote `notes`, but the captured pre-image only
        // holds `status` — `notes` is uncaptured (the silent un-revertable write).
        conn.inner().written_columns = vec!["notes".to_string()];
        conn.inner().written_image_cols = Some(vec!["status".to_string()]);
        let probe = conn.clone();
        let grant = grant_for("p-col", REL, &[2, 4, 6, 8], 5);
        let err = guarded_apply(
            "p-col",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::UncapturedColumn {
                relation, missing, ..
            } => {
                assert_eq!(relation, REL);
                assert_eq!(missing, vec!["notes".to_string()]);
            }
            other => panic!(
                "a written column with no captured pre-image MUST abort \
                 (UncapturedColumn), got {other:?}"
            ),
        }
        let p = probe.inner();
        assert!(
            p.rolled_back,
            "an uncaptured written column must ROLLBACK (no silent un-revertable commit)"
        );
        assert!(
            !p.committed,
            "it must NOT commit reversible:true with an incomplete inverse"
        );
    }

    /// The positive companion: an UPDATE that declares `notes` written AND captured
    /// its pre-image commits normally (the guard does not over-fire).
    #[test]
    fn captured_written_column_commits() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        conn.inner().written_columns = vec!["notes".to_string()];
        conn.inner().written_image_cols = Some(vec!["notes".to_string()]);
        let probe = conn.clone();
        let grant = grant_for("p-col-ok", REL, &[2, 4, 6, 8], 5);
        guarded_apply(
            "p-col-ok",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("a fully-captured written column must COMMIT");
        assert!(probe.inner().committed);
        assert!(!probe.inner().rolled_back);
    }

    /// The non-empty-pre-image FLOOR (no declared written columns): a written row
    /// whose captured pre-image carries ONLY the PK has nothing for the inverse to
    /// restore → abort, even without a declared written-column set.
    #[test]
    fn empty_preimage_floor_aborts_when_no_columns_declared() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        // No declared written columns; captured pre-image holds only the PK `id`.
        conn.inner().written_image_cols = Some(vec!["id".to_string()]);
        let probe = conn.clone();
        let grant = grant_for("p-floor", REL, &[2, 4, 6, 8], 5);
        let err = guarded_apply(
            "p-floor",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::UncapturedColumn { .. }),
            "{err:?}"
        );
        assert!(probe.inner().rolled_back);
        assert!(!probe.inner().committed);
    }

    // ---- statement_timeout fires → no partial commit -----------------------

    #[test]
    fn statement_timeout_aborts_with_no_partial_commit() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        conn.inner().timeout_at_forward = Some(15);
        let probe = conn.clone();
        let grant = grant_for("p-6", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-6",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Timeout { .. }), "{err:?}");
        let p = probe.inner();
        assert!(p.rolled_back, "a timeout must ROLLBACK (no partial commit)");
        assert!(!p.committed);
    }

    // ---- refused-op default-deny → never applied ---------------------------

    #[test]
    fn refused_op_is_never_applied() {
        // A non-reversible UPDATE (no captured pre-image) is outside the certified
        // set → REFUSED, and the connection is NEVER touched (no begin/forward).
        let mut conn = MockConn::new(REL, &[1]);
        let probe = conn.clone();
        let mut grant = grant_for("p-7", REL, &[1], 5);
        grant.reversible = false; // models "no pre-image captured"
        let err = guarded_apply(
            "p-7",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Refused(_)), "{err:?}");
        let p = probe.inner();
        assert!(
            p.began_with_timeout.is_none(),
            "a refused op must not even open the apply txn"
        );
        assert!(!p.forward_ran && !p.committed && !p.rolled_back);
    }

    #[test]
    fn grant_mismatch_is_rejected_before_any_db_work() {
        let mut conn = MockConn::new(REL, &[1]);
        let probe = conn.clone();
        let grant = grant_for("p-OTHER", REL, &[1], 5);
        let err = guarded_apply(
            "p-8", // does not match grant.proposal_id
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::InvalidGrant(_)), "{err:?}");
        assert!(probe.inner().began_with_timeout.is_none());
    }

    #[test]
    fn barrier_is_crossed_exactly_once_on_the_apply_path() {
        let mut conn = MockConn::new(REL, &[1, 2, 3]);
        let crossings = Arc::new(Mutex::new(0u32));
        let c2 = Arc::clone(&crossings);
        let barrier = ClosureBarrier::new(move |_| *c2.lock().unwrap() += 1);
        let grant = grant_for("p-9", REL, &[1, 2, 3], 5);
        guarded_apply(
            "p-9",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap();
        assert_eq!(
            *crossings.lock().unwrap(),
            1,
            "barrier crossed exactly once"
        );
    }
}
