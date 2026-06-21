//! The dry-run blast-radius engine (SPEC §4, §10.1, §12 baseline in-txn).
//!
//! [`dry_run`] is the demo core: it takes a [`Proposal`] and a measurement
//! [`Rehearsal`] backend, runs the candidate statement **inside a transaction it
//! always rolls back**, and folds the measured facts into a [`pgb_core::BlastRadius`]
//! record (§10.1). Nothing is persisted — the rehearsal's only output is the
//! record.
//!
//! ## Baseline = in-txn dry-run (`clone.provider: none`, SPEC §12)
//!
//! The baseline provider runs the rehearsal **in a `BEGIN … ROLLBACK` on a
//! provided connection** (the founder's real DB, or a clone if one is wired in
//! later). Per SPEC §12 this baseline **holds the write's locks for the duration
//! of the rehearsal** — the dry-run takes the same `RowExclusiveLock` (etc.) the
//! apply would, and keeps them until the `ROLLBACK`. That cost is the explicit
//! tradeoff of the no-clone baseline; the DBLab clone provider (next issue)
//! removes it by rehearsing on an isolated clone. The orchestration here is
//! provider-agnostic; the [`Rehearsal`] trait is the seam a clone provider
//! implements.
//!
//! ## Refusals (fail-closed, never executed)
//!
//! Two classes are refused **before any forward execution**:
//!
//! - **Volatile/non-deterministic predicate** (`now()`/`random()`/
//!   `clock_timestamp()` …, SPEC §4): the dry-run/apply equivalence is unsafe,
//!   so the statement is [`DryRunError::Volatile`] and never run.
//! - **PK-less / no-replica-identity target** (SPEC §10.2): affected rows cannot
//!   be safely identified across the dry-run/apply boundary, so the write is
//!   [`DryRunError::PkLess`] — **no `ctid` fallback**.
//!
//! The orchestration (parse → refuse → measure → assemble → rollback) is
//! DB-free and unit-tested against a mock [`Rehearsal`]; the real PG18 backend
//! lives in the integration tests behind `PG_BUMPERS_IT=1`.

use std::collections::BTreeMap;

use pgb_core::blast_radius::{Affected, ConstraintViolation};
use pgb_core::{BlastRadius, Clock, InverseKind, LockHeld, LockMode, PkChecksum, TriggerFired};

use crate::predicate::{volatile_reason, VolatileReason};
use crate::proposal::Proposal;

/// The statement class the dry-run engine recognizes (advisory parse, SPEC §4).
///
/// Only the bounded + reversible certified shapes (`UPDATE`/`DELETE`) are
/// rehearsed by the baseline engine; everything else is refused up front so the
/// engine never executes an op outside the certified action set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    /// `UPDATE …` — inverse is a pre-image upsert (§10.3).
    Update,
    /// `DELETE …` — inverse is a re-insert (§10.3).
    Delete,
}

impl WriteKind {
    /// The typed-inverse kind that reverses this write (SPEC §10.1/§10.3).
    pub const fn inverse_kind(self) -> InverseKind {
        match self {
            WriteKind::Update => InverseKind::for_update(),
            WriteKind::Delete => InverseKind::for_delete(),
        }
    }
}

/// Why a dry-run refused or failed (all fail-closed; the statement is never
/// committed under any of these).
#[derive(Debug, thiserror::Error)]
pub enum DryRunError {
    /// The proposed statement references a volatile / non-deterministic function
    /// — **REFUSED, never executed** (SPEC §4).
    #[error("REFUSED: volatile/non-deterministic predicate — {0}")]
    Volatile(VolatileReason),

    /// The proposed statement is not a certified, rehearsable shape
    /// (`UPDATE`/`DELETE`). DDL / `TRUNCATE` / unknown ops are refused here
    /// rather than executed (default-deny, §10.3).
    #[error("REFUSED: statement is not a rehearsable certified write ({0})")]
    NotRehearsable(String),

    /// The target relation has no usable primary key / replica identity, so the
    /// affected-PK set cannot be computed — **REFUSED, no `ctid` fallback**
    /// (SPEC §10.2).
    #[error(
        "REFUSED: target relation `{0}` is PK-less / has no replica identity (no ctid fallback)"
    )]
    PkLess(String),

    /// The proposal has outlived its TTL; re-propose before rehearsing.
    #[error("REFUSED: proposal `{0}` has expired (TTL elapsed)")]
    Expired(String),

    /// The measurement backend failed (DB error etc.). Surfaced as a string so
    /// the DB-free core stays dependency-light.
    #[error("dry-run measurement failed: {0}")]
    Backend(String),
}

/// The per-relation affected-PK set measured by the rehearsal: the typed
/// [`PkChecksum`] plus the row count, for the target and (separately) cascades.
#[derive(Debug, Clone)]
pub struct AffectedTable {
    /// `schema.table`.
    pub relation: String,
    /// Affected-PK-set checksum (core `sha256:…`). `None` ⇒ the relation is
    /// PK-less / has no replica identity → the engine refuses.
    pub checksum: Option<PkChecksum>,
    /// Number of affected rows in this relation.
    pub rows: u64,
}

/// Everything the rehearsal measured for one proposed write, before the engine
/// folds it into a [`BlastRadius`]. The backend produces this **inside the
/// rolled-back txn**; the engine adds no DB facts of its own.
#[derive(Debug, Clone)]
pub struct Measurement {
    /// The target relation's affected-PK set (the directly-written rows).
    pub target: AffectedTable,
    /// Cascade-affected relations (`ON DELETE/UPDATE CASCADE`), each with its
    /// own affected-PK set.
    pub cascades: Vec<AffectedTable>,
    /// Triggers the write fired, with per-trigger row counts.
    pub triggers_fired: Vec<TriggerFired>,
    /// Locks the write took (from `pg_locks`, held during the rehearsal).
    pub locks: Vec<LockHeld>,
    /// Predicted apply duration in ms (measured by the backend via [`Clock`]).
    pub duration_ms: u64,
    /// WAL volume the forward op generated, from a `pg_current_wal_lsn()` delta.
    pub wal_bytes: u64,
    /// Constraints the write would violate (empty ⇒ none).
    pub constraint_violations: Vec<ConstraintViolation>,
    /// The clone/connection LSN the rehearsal ran against.
    pub clone_lsn: String,
    /// How far behind prod the clone is, in WAL bytes (0 for the in-txn baseline
    /// running on prod itself).
    pub staleness_lsn_bytes: u64,
}

/// The measurement backend seam (the clone-provider seam, SPEC §12).
///
/// An implementor runs the candidate `statement` **inside a transaction it will
/// roll back**, captures the pre-image / `RETURNING` affected-PK set, and
/// measures locks / WAL / triggers / duration. The baseline in-txn provider
/// (`clone.provider: none`) implements this against a provided connection; a
/// DBLab clone provider (next issue) implements it against an isolated clone.
///
/// The engine guarantees it only ever calls [`rehearse`](Rehearsal::rehearse)
/// with a statement it has already classified as a certified, non-volatile
/// write — but the backend is still responsible for the `BEGIN`/`ROLLBACK`
/// bracket so that the "always rolled back, nothing persisted" property is
/// enforced where the DB connection actually lives.
pub trait Rehearsal {
    /// Rehearse `statement` (a certified `kind` write on `target_relation`) in a
    /// rolled-back transaction and return the [`Measurement`].
    ///
    /// MUST `BEGIN`, execute, measure, then `ROLLBACK` — no committed change.
    /// MUST return [`AffectedTable::checksum`] `= None` for any PK-less target
    /// so the engine can refuse (no `ctid` fallback).
    fn rehearse(
        &mut self,
        statement: &str,
        kind: WriteKind,
        target_relation: &str,
    ) -> Result<Measurement, String>;
}

/// Classify the proposed statement (advisory `sqlparser` parse, §4): is it a
/// rehearsable certified write, and on what relation?
///
/// Returns `(kind, schema.table)`. DDL / `TRUNCATE` / multi-statement / unknown
/// shapes are [`DryRunError::NotRehearsable`] (default-deny). The relation is
/// returned `schema.table`-qualified (defaulting the schema to `public`).
pub fn classify(statement: &str) -> Result<(WriteKind, String), DryRunError> {
    use sqlparser::ast::{FromTable, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let dialect = PostgreSqlDialect {};
    let parsed = Parser::parse_sql(&dialect, statement)
        .map_err(|e| DryRunError::NotRehearsable(format!("parse error: {e}")))?;
    if parsed.len() != 1 {
        return Err(DryRunError::NotRehearsable(format!(
            "expected exactly one statement, got {}",
            parsed.len()
        )));
    }
    match &parsed[0] {
        Statement::Update(update) => {
            let rel = relation_of_table_factor(&update.table.relation).ok_or_else(|| {
                DryRunError::NotRehearsable("UPDATE target is not a plain table".into())
            })?;
            Ok((WriteKind::Update, rel))
        }
        Statement::Delete(delete) => {
            let names = match &delete.from {
                FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
            };
            let first = names
                .first()
                .ok_or_else(|| DryRunError::NotRehearsable("DELETE has no target table".into()))?;
            let rel = relation_of_table_factor(&first.relation).ok_or_else(|| {
                DryRunError::NotRehearsable("DELETE target is not a plain table".into())
            })?;
            Ok((WriteKind::Delete, rel))
        }
        other => Err(DryRunError::NotRehearsable(format!(
            "statement kind `{}` is not a certified rehearsable write",
            stmt_label(other)
        ))),
    }
}

/// Extract a `schema.table` from a `sqlparser` table factor, defaulting the
/// schema to `public`. Returns `None` for non-table factors (subqueries etc.).
fn relation_of_table_factor(factor: &sqlparser::ast::TableFactor) -> Option<String> {
    use sqlparser::ast::TableFactor;
    match factor {
        TableFactor::Table { name, .. } => {
            let parts: Vec<String> = name.0.iter().map(|p| p.to_string()).collect();
            match parts.len() {
                1 => Some(format!("public.{}", parts[0])),
                _ => Some(parts.join(".")),
            }
        }
        _ => None,
    }
}

/// A short label for an unsupported statement kind (for the refusal message).
fn stmt_label(stmt: &sqlparser::ast::Statement) -> &'static str {
    use sqlparser::ast::Statement;
    match stmt {
        Statement::Insert(_) => "INSERT",
        Statement::Truncate { .. } => "TRUNCATE",
        Statement::Drop { .. } => "DROP",
        Statement::AlterTable { .. } => "ALTER",
        Statement::CreateTable(_) => "CREATE TABLE",
        Statement::Query(_) => "SELECT",
        Statement::Merge { .. } => "MERGE",
        _ => "unsupported",
    }
}

/// Run the dry-run blast-radius rehearsal for `proposal` against `rehearsal`.
///
/// Pipeline (all fail-closed):
/// 1. **TTL** — refuse an expired proposal.
/// 2. **Volatile predicate** — refuse `now()`/`random()`/… *before* executing.
/// 3. **Classify** — refuse non-certified shapes (DDL/TRUNCATE/unknown).
/// 4. **Rehearse** — the backend runs the statement in a rolled-back txn and
///    measures the blast radius (PK set + cascades + triggers + locks + WAL +
///    duration + LSN/staleness).
/// 5. **PK-less guard** — refuse if the target (or any cascade) has no usable PK
///    (no `ctid` fallback).
/// 6. **Assemble** — fold the measurement into the §10.1 [`BlastRadius`] record.
///
/// On success the returned record reflects a write that was rehearsed and then
/// **rolled back** — no row was persisted.
pub fn dry_run(
    proposal: &Proposal,
    rehearsal: &mut dyn Rehearsal,
    clock: &dyn Clock,
) -> Result<BlastRadius, DryRunError> {
    // (1) TTL — an expired preview must be re-proposed.
    if proposal.is_expired(clock) {
        return Err(DryRunError::Expired(proposal.id.clone()));
    }

    // (2) Volatile/non-deterministic predicate — REFUSED, never executed (§4).
    if let Some(reason) = volatile_reason(&proposal.statement) {
        return Err(DryRunError::Volatile(reason));
    }

    // (3) Classify the certified write shape + target relation (advisory parse).
    let (kind, target_relation) = classify(&proposal.statement)?;

    // (4) Rehearse in a rolled-back txn (the backend owns BEGIN/ROLLBACK).
    let measurement = rehearsal
        .rehearse(&proposal.statement, kind, &target_relation)
        .map_err(DryRunError::Backend)?;

    // (5) PK-less guard: refuse if the target or any cascade has no usable PK
    //     (no ctid fallback — §10.2).
    assemble(proposal, kind, measurement)
}

/// Fold a [`Measurement`] into the §10.1 [`BlastRadius`] record, enforcing the
/// PK-less refusal (step 5) along the way.
fn assemble(
    proposal: &Proposal,
    kind: WriteKind,
    m: Measurement,
) -> Result<BlastRadius, DryRunError> {
    // Target must have a usable PK.
    let target_checksum = m
        .target
        .checksum
        .as_ref()
        .ok_or_else(|| DryRunError::PkLess(m.target.relation.clone()))?
        .as_prefixed();

    let mut by_table: BTreeMap<String, u64> = BTreeMap::new();
    let mut cascade_by_table: BTreeMap<String, u64> = BTreeMap::new();
    let mut pk_set_checksum: BTreeMap<String, String> = BTreeMap::new();

    by_table.insert(m.target.relation.clone(), m.target.rows);
    pk_set_checksum.insert(m.target.relation.clone(), target_checksum);

    let mut total_rows = m.target.rows;
    for cascade in &m.cascades {
        // Cascades to a PK-less relation are equally unsafe → refuse.
        let cs = cascade
            .checksum
            .as_ref()
            .ok_or_else(|| DryRunError::PkLess(cascade.relation.clone()))?
            .as_prefixed();
        cascade_by_table.insert(cascade.relation.clone(), cascade.rows);
        pk_set_checksum.insert(cascade.relation.clone(), cs);
        total_rows = total_rows.saturating_add(cascade.rows);
    }

    let affected = Affected {
        by_table,
        cascade_by_table,
        pk_set_checksum,
        total_rows,
    };

    let max_lock_mode = m
        .locks
        .iter()
        .map(|l| l.mode)
        .max()
        // A certified write always takes at least RowExclusiveLock; default to it
        // so the field is never under-reported if the backend returned no rows.
        .unwrap_or(LockMode::RowExclusiveLock);

    Ok(BlastRadius {
        proposal_id: proposal.id.clone(),
        clone_lsn: m.clone_lsn,
        staleness_lsn_bytes: m.staleness_lsn_bytes,
        affected,
        triggers_fired: m.triggers_fired,
        locks: m.locks,
        max_lock_mode,
        duration_ms: m.duration_ms,
        wal_bytes: m.wal_bytes,
        constraint_violations: m.constraint_violations,
        // A certified UPDATE/DELETE with a captured pre-image + usable PK is
        // reversible by its typed inverse (§10.3). The pre-image capture itself
        // happens in the backend; reaching here means the PK set is computable.
        reversible: true,
        inverse_kind: kind.inverse_kind(),
        // We only reach assembly for a non-volatile statement (step 2 refused
        // otherwise), so the recorded predicate is deterministic.
        predicate_volatile: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposal::{propose, propose_with_ttl};
    use pgb_core::{MockClock, PkSetBuilder, PkTuple, PkValue};

    /// A deterministic in-memory rehearsal backend for unit tests. It does not
    /// touch a DB; it returns a fixed [`Measurement`] so the engine's
    /// orchestration (refusals, assembly) is tested in isolation. The real PG18
    /// backend is exercised by the env-gated integration tests.
    struct MockRehearsal {
        measurement: Measurement,
        /// Records the statement the engine asked us to rehearse (to assert the
        /// engine refuses *before* calling us on the volatile path).
        rehearsed: Option<String>,
    }

    fn checksum_of(rel: &str, ids: &[i64]) -> PkChecksum {
        let mut b = PkSetBuilder::for_relation(rel);
        for &id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().unwrap()
    }

    impl MockRehearsal {
        fn with_target(rel: &str, ids: &[i64]) -> Self {
            MockRehearsal {
                measurement: Measurement {
                    target: AffectedTable {
                        relation: rel.into(),
                        checksum: Some(checksum_of(rel, ids)),
                        rows: ids.len() as u64,
                    },
                    cascades: vec![],
                    triggers_fired: vec![TriggerFired {
                        name: "orders_audit_ai".into(),
                        rows: ids.len() as u64,
                    }],
                    locks: vec![LockHeld {
                        relation: rel.into(),
                        mode: LockMode::RowExclusiveLock,
                        held_ms: 12,
                    }],
                    duration_ms: 13,
                    wal_bytes: 4096,
                    constraint_violations: vec![],
                    clone_lsn: "0/1A2B3C".into(),
                    staleness_lsn_bytes: 0,
                },
                rehearsed: None,
            }
        }

        fn pk_less_target(rel: &str) -> Self {
            let mut m = Self::with_target(rel, &[1, 2, 3]);
            m.measurement.target.checksum = None;
            m
        }
    }

    impl Rehearsal for MockRehearsal {
        fn rehearse(
            &mut self,
            statement: &str,
            _kind: WriteKind,
            _target_relation: &str,
        ) -> Result<Measurement, String> {
            self.rehearsed = Some(statement.to_string());
            Ok(self.measurement.clone())
        }
    }

    #[test]
    fn classify_recognizes_update_and_delete() {
        assert_eq!(
            classify("UPDATE public.orders SET balance = 0").unwrap(),
            (WriteKind::Update, "public.orders".to_string())
        );
        assert_eq!(
            classify("DELETE FROM orders WHERE id = 1").unwrap(),
            (WriteKind::Delete, "public.orders".to_string())
        );
    }

    #[test]
    fn classify_refuses_ddl_and_truncate_and_insert() {
        assert!(matches!(
            classify("TRUNCATE public.orders"),
            Err(DryRunError::NotRehearsable(_))
        ));
        assert!(matches!(
            classify("DROP TABLE public.orders"),
            Err(DryRunError::NotRehearsable(_))
        ));
        assert!(matches!(
            classify("INSERT INTO public.orders(id) VALUES (1)"),
            Err(DryRunError::NotRehearsable(_))
        ));
        assert!(matches!(
            classify("SELECT 1"),
            Err(DryRunError::NotRehearsable(_))
        ));
    }

    #[test]
    fn marquee_no_where_update_assembles_blast_radius() {
        let clock = MockClock::new();
        let p = propose("UPDATE public.orders SET balance = 0", Some(5), &clock);
        let mut backend = MockRehearsal::with_target("public.orders", &[1, 2, 3, 4, 5]);
        let br = dry_run(&p, &mut backend, &clock).expect("dry-run should succeed");

        assert_eq!(br.proposal_id, p.id);
        assert_eq!(br.affected.by_table["public.orders"], 5);
        assert_eq!(br.affected.total_rows, 5);
        assert_eq!(br.affected.pk_set_checksum["public.orders"].len(), 71); // "sha256:" + 64
        assert!(br.affected.pk_set_checksum["public.orders"].starts_with("sha256:"));
        assert_eq!(br.inverse_kind, InverseKind::PreimageUpsert);
        assert!(br.reversible);
        assert!(!br.predicate_volatile);
        assert_eq!(br.max_lock_mode, LockMode::RowExclusiveLock);
        // The record round-trips through serde (the §10.1 wire contract).
        let json = serde_json::to_string(&br).unwrap();
        let back: BlastRadius = serde_json::from_str(&json).unwrap();
        assert_eq!(br, back);
    }

    #[test]
    fn volatile_predicate_is_refused_before_rehearsal() {
        let clock = MockClock::new();
        let p = propose(
            "UPDATE public.orders SET balance = 0 WHERE created > now()",
            None,
            &clock,
        );
        let mut backend = MockRehearsal::with_target("public.orders", &[1, 2, 3]);
        let err = dry_run(&p, &mut backend, &clock).unwrap_err();
        assert!(matches!(err, DryRunError::Volatile(_)));
        // The backend was NEVER asked to execute the volatile statement.
        assert!(
            backend.rehearsed.is_none(),
            "volatile statement must not reach the rehearsal backend"
        );
    }

    #[test]
    fn pk_less_target_is_refused_no_ctid_fallback() {
        let clock = MockClock::new();
        let p = propose("DELETE FROM public.event_log WHERE 1=1", None, &clock);
        let mut backend = MockRehearsal::pk_less_target("public.event_log");
        let err = dry_run(&p, &mut backend, &clock).unwrap_err();
        match err {
            DryRunError::PkLess(rel) => assert_eq!(rel, "public.event_log"),
            other => panic!("expected PkLess, got {other:?}"),
        }
    }

    #[test]
    fn expired_proposal_is_refused() {
        let clock = MockClock::starting_at(0);
        let p = propose_with_ttl("UPDATE public.orders SET x = 1", None, 100, &clock);
        clock.advance(100);
        let mut backend = MockRehearsal::with_target("public.orders", &[1]);
        assert!(matches!(
            dry_run(&p, &mut backend, &clock),
            Err(DryRunError::Expired(_))
        ));
    }

    #[test]
    fn cascade_rows_are_included_in_total_and_checksum_map() {
        let clock = MockClock::new();
        let p = propose(
            "DELETE FROM public.orders WHERE status = 'open'",
            None,
            &clock,
        );
        let mut backend = MockRehearsal::with_target("public.orders", &[2, 4]);
        backend.measurement.cascades = vec![AffectedTable {
            relation: "public.order_items".into(),
            checksum: Some(checksum_of("public.order_items", &[20, 21, 40, 41])),
            rows: 4,
        }];
        let br = dry_run(&p, &mut backend, &clock).unwrap();
        assert_eq!(br.affected.by_table["public.orders"], 2);
        assert_eq!(br.affected.cascade_by_table["public.order_items"], 4);
        assert_eq!(br.affected.total_rows, 6);
        assert!(br
            .affected
            .pk_set_checksum
            .contains_key("public.order_items"));
    }
}
