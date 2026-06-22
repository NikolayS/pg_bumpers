//! Real-PG18 connection seams for the dry-run + guarded-apply engines (SPEC §4,
//! §10.1, §12). **Behind the `pg` feature.**
//!
//! The engines ([`crate::dry_run`], [`crate::apply`], [`crate::revert`]) are
//! DB-free: they own the *ordering and the guard decisions* and drive a
//! connection trait ([`Rehearsal`], [`ApplyConn`], [`RevertConn`]) that owns the
//! SQL. This module is the **one** production-grade implementation of those
//! traits against real PostgreSQL 18 — lifted verbatim from the former
//! `tests/common/mod.rs` ([`PgRehearsal`]) and `tests/apply_grant_it.rs`
//! ([`PgApplyConn`] / [`PgRevertConn`]) so the integration tests and
//! `pgb-applyd` share a single impl (no second, unproven copy that could mis-read
//! a PK or skip a pre-image column — that would silently break reversibility
//! while looking green).
//!
//! # MVP scope (the #1 risk — honored here)
//! [`PgApplyConn`] / [`PgRevertConn`] are constrained to the **single-`int4`-PK
//! `UPDATE`/`DELETE`** shape. The PK *width/cardinality* is the coverage limit; the
//! *columns* are NOT (S5 #75). For an `UPDATE`, the apply captures the pre-image of
//! **exactly the SET-clause columns** the write mutates (parsed from the forward
//! SQL) and the revert restores exactly those — so a write to ANY column is
//! genuinely reversible, not a silent un-revertable commit. For a `DELETE`, the
//! full row image is captured (whole-row re-insert). A wider/composite PK
//! (`int8`/`text`/`uuid`/multi-col) or a column type the capture cannot restore
//! losslessly is gated out **cleanly at dry-run** by
//! [`PgRehearsal::certify_apply_shape`] (`NOT_REHEARSABLE`, no panic);
//! defense-in-depth, the guarded-apply step-8b column-coverage guard aborts an
//! uncaptured written column before commit. [`PgRehearsal`] is generic (it measures
//! whatever the rehearsal touches); only the *apply* conn is shape-constrained.

use std::collections::BTreeMap;

use postgres::error::SqlState;
use postgres::types::Type;
use postgres::{Client, Row, Transaction};

use pgb_core::blast_radius::{ConstraintViolation, OpCounts};
use pgb_core::inverse::ImageValue;
use pgb_core::{Clock, LockHeld, LockMode, PkSetBuilder, PkTuple, PkValue, TriggerFired};

use crate::apply::{ApplyConn, ApplyError, CapturedRow, ForwardResult, RelationChange};
use crate::dry_run::{AffectedTable, Measurement, Rehearsal, RelationEffect, WriteKind};
use crate::revert::{RevertConn, RevertError, RevertRow};
use crate::Volatility;

/// The primary-key shape of a target relation, for the S5 #75 apply-shape gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PkShape {
    /// No primary key — left to the §10.2 `PkLess` refusal (a distinct message).
    NoPk,
    /// Exactly one `int4` PK column — the supported MVP reversible-apply shape.
    SingleInt4,
    /// A composite PK, or a single PK of a wider type (`int8`/`text`/`uuid`/…) the
    /// MVP apply path cannot reversibly carry — refused `NOT_REHEARSABLE`.
    Other,
}

// ===========================================================================
//  PgRehearsal — the §12 baseline in-txn rehearsal (clone.provider: none).
// ===========================================================================

/// The real, in-txn baseline [`Rehearsal`] (SPEC §12). Owns a connection; each
/// `rehearse` opens a txn, measures the §10.1 blast radius, and **always rolls
/// back** so nothing is persisted.
///
/// What it measures, all inside the rolled-back txn:
/// - affected-PK set of the target (via `RETURNING <pk cols>`) → `core` checksum;
/// - cascade-affected child PKs for `ON DELETE CASCADE` FKs (captured pre-delete);
/// - triggers that fire for the op (`pg_trigger`);
/// - locks held on the target (`pg_locks`) — held until ROLLBACK (§12);
/// - WAL bytes (`pg_current_wal_insert_lsn()` delta across the forward op);
/// - duration (via the injected `core::Clock`);
/// - clone LSN + staleness (0 for the in-txn baseline running on prod itself).
pub struct PgRehearsal<'c, C: Clock> {
    client: &'c mut Client,
    clock: &'c C,
}

impl<'c, C: Clock> PgRehearsal<'c, C> {
    /// Wrap a connection + injected clock as the baseline rehearsal backend.
    pub fn new(client: &'c mut Client, clock: &'c C) -> Self {
        PgRehearsal { client, clock }
    }

    /// Look up `pg_proc.provolatile` for `name`, folding overloads to the most
    /// volatile class. Reads `pg_proc` only (never executes the candidate).
    fn resolve_provolatile(&mut self, name: &str) -> Result<Volatility, String> {
        let (schema, proc_name) = match name.rsplit_once('.') {
            Some((s, p)) => (Some(s.to_string()), p.to_string()),
            None => (None, name.to_string()),
        };

        let sql = r#"
            SELECT
                bool_or(p.provolatile = 'v') AS any_volatile,
                count(*)                      AS n
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.proname = $1
              AND ( $2::text IS NULL AND pg_function_is_visible(p.oid)
                    OR n.nspname = $2::text )
        "#;
        let row = self
            .client
            .query_one(sql, &[&proc_name, &schema])
            .map_err(|e| e.to_string())?;
        let n: i64 = row.get("n");
        if n == 0 {
            return Ok(Volatility::Unknown);
        }
        let any_volatile: bool = row.get("any_volatile");
        if any_volatile {
            Ok(Volatility::Volatile)
        } else {
            Ok(Volatility::Stable)
        }
    }

    /// Classify `relation`'s primary-key shape for the MVP reversible-apply gate
    /// (S5 #75). Reads `pg_index`/`pg_attribute`/`pg_type` only; never executes the
    /// candidate.
    ///
    /// - [`PkShape::NoPk`] — no primary key (left to the §10.2 `PkLess` refusal);
    /// - [`PkShape::SingleInt4`] — exactly one `int4` PK column (the supported shape);
    /// - [`PkShape::Other`] — a composite PK, or a single PK of a wider type
    ///   (`int8`/`text`/`uuid`/…) the apply path cannot reversibly carry.
    fn target_pk_int4_shape(&mut self, relation: &str) -> Result<PkShape, String> {
        let (schema, table) = split_relation(relation);
        let rows = self
            .client
            .query(
                r#"
                SELECT t.typname
                FROM pg_index i
                JOIN pg_class c   ON c.oid = i.indrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
                JOIN pg_type t ON t.oid = a.atttypid
                WHERE n.nspname = $1 AND c.relname = $2 AND i.indisprimary
                ORDER BY array_position(i.indkey, a.attnum)
                "#,
                &[&schema, &table],
            )
            .map_err(|e| e.to_string())?;
        match rows.len() {
            0 => Ok(PkShape::NoPk),
            1 if rows[0].get::<_, String>(0) == "int4" => Ok(PkShape::SingleInt4),
            _ => Ok(PkShape::Other),
        }
    }

    /// Of `columns`, those on `relation` whose type the MVP reversible-capture does
    /// **not** support losslessly (S5 #75). A column not found in `pg_attribute` is
    /// also returned (refuse rather than guess). Supported: `int2/4/8`,
    /// `text/varchar/bpchar/name`, `bytea`.
    fn uncapturable_columns(
        &mut self,
        relation: &str,
        columns: &[String],
    ) -> Result<Vec<String>, String> {
        let (schema, table) = split_relation(relation);
        let mut bad = Vec::new();
        for col in columns {
            let rows = self
                .client
                .query(
                    r#"
                    SELECT t.typname
                    FROM pg_attribute a
                    JOIN pg_class c ON c.oid = a.attrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_type t ON t.oid = a.atttypid
                    WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3
                      AND a.attnum > 0 AND NOT a.attisdropped
                    "#,
                    &[&schema, &table, col],
                )
                .map_err(|e| e.to_string())?;
            let supported = match rows.first() {
                Some(r) => matches!(
                    r.get::<_, String>(0).as_str(),
                    "int2" | "int4" | "int8" | "text" | "varchar" | "bpchar" | "name" | "bytea"
                ),
                None => false, // unknown column → refuse
            };
            if !supported {
                bad.push(col.clone());
            }
        }
        Ok(bad)
    }
}

impl<C: Clock> Rehearsal for PgRehearsal<'_, C> {
    fn volatility_of(&mut self, name: &str) -> Volatility {
        match self.resolve_provolatile(name) {
            Ok(v) => v,
            Err(_) => Volatility::Unknown,
        }
    }

    fn certify_apply_shape(
        &mut self,
        statement: &str,
        kind: WriteKind,
        target_relation: &str,
    ) -> Option<String> {
        // (a) PK must be exactly ONE column of type `int4` (the MVP shape the
        //     PgApplyConn/PgRevertConn prove). A wider PK type / composite PK is
        //     refused cleanly here rather than surfacing as an apply-time backend
        //     error. A genuinely PK-LESS target is left to the existing §10.2
        //     `PkLess` refusal (a distinct, more specific message), so we do NOT
        //     refuse it here. A `pg_index`/`pg_attribute` read only — never the
        //     candidate.
        match self.target_pk_int4_shape(target_relation) {
            Ok(PkShape::SingleInt4) | Ok(PkShape::NoPk) => {}
            Ok(PkShape::Other) => {
                return Some(format!(
                    "target relation `{target_relation}` does not have a single `int4` \
                     primary key — the MVP reversible apply path is constrained to a \
                     single-`int4`-PK `UPDATE`/`DELETE` (a wider/composite PK is DEFERRED, \
                     fail-closed)"
                ));
            }
            Err(e) => {
                return Some(format!(
                    "could not resolve PK shape of `{target_relation}`: {e}"
                ))
            }
        }

        // (b) For an UPDATE, every SET-clause column must be losslessly capturable
        //     (so the typed-inverse can restore it byte-for-byte). A non-plain SET
        //     target or an unsupported column type is refused here, fail-closed.
        if kind == WriteKind::Update {
            let set_cols = match update_set_columns(statement) {
                Ok(c) => c,
                Err(e) => {
                    return Some(format!(
                        "cannot determine the UPDATE SET-clause columns (so reversibility \
                         cannot be certified): {e}"
                    ));
                }
            };
            match self.uncapturable_columns(target_relation, &set_cols) {
                Ok(bad) if !bad.is_empty() => {
                    return Some(format!(
                        "UPDATE writes column(s) {bad:?} on `{target_relation}` whose type the \
                         MVP reversible-capture does not support losslessly — refusing rather \
                         than commit an unrevertable write (S5 #75, fail-closed)"
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    return Some(format!(
                        "could not resolve SET-column types on `{target_relation}`: {e}"
                    ));
                }
            }
        }
        None
    }

    fn rehearse(
        &mut self,
        statement: &str,
        kind: WriteKind,
        target_relation: &str,
    ) -> Result<Measurement, String> {
        let clone_lsn = current_wal_lsn(self.client)?;

        let mut txn = self.client.transaction().map_err(|e| e.to_string())?;

        let xact_baseline = xact_raw(&mut txn)?;
        let pk_cols = pk_columns(&mut txn, target_relation)?;

        let cascades = if kind == WriteKind::Delete {
            capture_cascades(&mut txn, target_relation, statement)?
        } else {
            Vec::new()
        };

        let triggers_fired_names = trigger_names(&mut txn, target_relation, kind)?;

        let wal_before = txn_wal_lsn(&mut txn)?;
        let t0 = self.clock.monotonic_millis();
        let target = run_forward_capturing_pks(&mut txn, statement, target_relation, &pk_cols)?;
        let duration_ms = self.clock.monotonic_millis().saturating_sub(t0);
        let wal_after = txn_wal_lsn(&mut txn)?;
        let wal_bytes = wal_diff(&mut txn, &wal_before, &wal_after)?;

        let locks = locks_on(&mut txn, target_relation)?;
        let full_effect = xact_full_effect(&mut txn, &xact_baseline)?;

        let triggers_fired = triggers_fired_names
            .into_iter()
            .map(|name| TriggerFired {
                name,
                rows: target.rows,
            })
            .collect();

        // ALWAYS roll back — nothing persisted.
        txn.rollback().map_err(|e| e.to_string())?;

        Ok(Measurement {
            target,
            cascades,
            full_effect,
            triggers_fired,
            locks,
            duration_ms,
            wal_bytes,
            constraint_violations: Vec::<ConstraintViolation>::new(),
            clone_lsn,
            staleness_lsn_bytes: 0,
        })
    }
}

// ===========================================================================
//  PgApplyConn — the focused single-int-PK UPDATE/DELETE apply conn (#66 MVP).
// ===========================================================================

/// The real-PG18 [`ApplyConn`] for the guarded-apply engine, constrained to the
/// **single-integer-PK `UPDATE`/`DELETE`** shape (the MVP scope #66 already proves
/// end-to-end). The engine owns the §4 ordering + guard decisions; this conn owns
/// the SQL run inside ONE apply txn.
///
/// # Column-coverage (S5 #75)
/// The typed-inverse must restore **every column the write actually mutates**. For
/// an `UPDATE` this conn parses the **SET-clause target columns** out of
/// `forward_sql` and captures the pre-image of exactly those columns (+ the PK) by
/// name — so a `SET notes = …` is genuinely reversible, not a silent FN that
/// captured only a hardcoded `(owner, balance)`. For a `DELETE` it captures the
/// **full row image** (every column from `pg_attribute`) so the re-insert restores
/// the whole row. If the SET targets cannot be parsed (a non-plain-column
/// assignment, e.g. `SET (a,b)=(…)` or a sub-select tuple), the apply **fails
/// closed** ([`ApplyError::Backend`]) rather than commit an incompletely-captured
/// write.
///
/// `forward_sql` is the exact write (e.g. `UPDATE … SET balance = 0 WHERE
/// id % 2 = 0`); `where_sql` is its predicate, used to recompute the affected-PK
/// set inside the txn (the apply-time drift re-check) and to capture pre-images.
pub struct PgApplyConn<'a> {
    client: &'a mut Client,
    forward_sql: String,
    where_sql: String,
    xact_baseline: BTreeMap<String, (i64, i64, i64)>,
    in_txn: bool,
    statement_timeout_ms: u64,
}

impl<'a> PgApplyConn<'a> {
    /// Build the apply conn for `forward_sql` over predicate `where_sql`.
    pub fn new(client: &'a mut Client, forward_sql: &str, where_sql: &str) -> Self {
        PgApplyConn {
            client,
            forward_sql: forward_sql.to_string(),
            where_sql: where_sql.to_string(),
            xact_baseline: BTreeMap::new(),
            in_txn: false,
            statement_timeout_ms: 0,
        }
    }

    /// The full ordered column list of `relation` from `pg_attribute` (live,
    /// dropped/system columns excluded). Used to capture a DELETE's full-row
    /// pre-image so the re-insert restores every column.
    fn all_columns(&mut self, relation: &str) -> Result<Vec<String>, ApplyError> {
        let (schema, table) = split_relation(relation);
        let rows = self
            .client
            .query(
                r#"
                SELECT a.attname
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = $1 AND c.relname = $2
                  AND a.attnum > 0 AND NOT a.attisdropped
                ORDER BY a.attnum
                "#,
                &[&schema, &table],
            )
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    fn read_xact_raw(&mut self) -> Result<BTreeMap<String, (i64, i64, i64)>, ApplyError> {
        let rows = self
            .client
            .query(
                "SELECT schemaname || '.' || relname AS rel, \
                        n_tup_ins, n_tup_upd, n_tup_del \
                 FROM pg_stat_xact_user_tables",
                &[],
            )
            .map_err(|e| classify_apply(&e, self.statement_timeout_ms))?;
        let mut out = BTreeMap::new();
        for row in &rows {
            out.insert(
                row.get::<_, String>(0),
                (
                    row.get::<_, i64>(1),
                    row.get::<_, i64>(2),
                    row.get::<_, i64>(3),
                ),
            );
        }
        Ok(out)
    }
}

impl ApplyConn for PgApplyConn<'_> {
    fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError> {
        let row = self
            .client
            .query_one("SELECT pg_create_restore_point($1)::text", &[&label])
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        Ok(row.get(0))
    }

    fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError> {
        self.client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL statement_timeout = {timeout_ms};"
            ))
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        self.in_txn = true;
        self.statement_timeout_ms = timeout_ms;
        self.xact_baseline = self.read_xact_raw()?;
        Ok(())
    }

    fn recompute_pk_checksum(
        &mut self,
        relation: &str,
    ) -> Result<pgb_core::PkChecksum, ApplyError> {
        let rows = self
            .client
            .query(
                &format!(
                    "SELECT id FROM {relation} WHERE {} ORDER BY id",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        let mut b = PkSetBuilder::for_relation(relation);
        for row in &rows {
            // Fail-closed on a non-int4 PK rather than panic: a wider PK type is
            // gated at dry_run (NOT_REHEARSABLE); if one ever reaches here, surface
            // a typed Backend error so the apply aborts cleanly (no poisoned conn).
            let id: i32 = row
                .try_get(0)
                .map_err(|e| ApplyError::Backend(format!("non-int4 PK on `{relation}`: {e}")))?;
            b.push(PkTuple::single(PkValue::Int(id as i64)))
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }

    fn apply_forward(
        &mut self,
        kind: WriteKind,
        relation: &str,
        _cascade: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        // The pre-image columns the typed-inverse must restore (S5 #75 column
        // coverage). For an UPDATE: exactly the SET-clause target columns the write
        // mutates (parsed from `forward_sql`), so the inverse restores precisely what
        // changed regardless of which columns. For a DELETE: every column (full-row
        // re-insert). The PK column `id` is always captured (the inverse keys on it).
        let image_cols: Vec<String> = match kind {
            WriteKind::Update => update_set_columns(&self.forward_sql).map_err(|e| {
                ApplyError::Backend(format!(
                    "cannot determine the UPDATE SET-clause columns to capture a \
                     reversible pre-image (fail-closed; S5 #75): {e}"
                ))
            })?,
            WriteKind::Delete => self.all_columns(relation)?,
        };
        // The select list is `id` (the PK) + each written column, de-duplicated and
        // quoted. `id` first so the PK read is positional + cheap.
        let mut select_cols: Vec<String> = vec!["id".to_string()];
        for c in &image_cols {
            if c != "id" && !select_cols.contains(c) {
                select_cols.push(c.clone());
            }
        }
        let select_list = select_cols
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");

        let preimage_rows = self
            .client
            .query(
                &format!(
                    "SELECT {select_list} FROM {relation} WHERE {} ORDER BY id FOR UPDATE",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| classify_apply(&e, self.statement_timeout_ms))?;
        let mut preimage: BTreeMap<i64, Vec<(String, ImageValue)>> = BTreeMap::new();
        for row in &preimage_rows {
            let id: i32 = row
                .try_get(0)
                .map_err(|e| ApplyError::Backend(format!("non-int4 PK on `{relation}`: {e}")))?;
            let mut image: Vec<(String, ImageValue)> = Vec::with_capacity(select_cols.len());
            for (i, col) in select_cols.iter().enumerate() {
                image.push((col.clone(), image_value_at(row, i)?));
            }
            preimage.insert(id as i64, image);
        }
        let sql = format!("{} RETURNING id", self.forward_sql);
        let returned = self
            .client
            .query(&sql, &[])
            .map_err(|e| classify_apply(&e, self.statement_timeout_ms))?;
        let mut written = Vec::with_capacity(returned.len());
        for row in &returned {
            let id: i32 = row
                .try_get(0)
                .map_err(|e| ApplyError::Backend(format!("non-int4 PK on `{relation}`: {e}")))?;
            let before_image = preimage
                .get(&(id as i64))
                .cloned()
                .unwrap_or_else(|| vec![("id".into(), PkValue::Int(id as i64))]);
            written.push(CapturedRow {
                pk: PkTuple::single(PkValue::Int(id as i64)),
                before_image,
            });
        }
        // Declare the written-column set so the engine's step-8b column-coverage
        // guard can verify every written column has a captured pre-image (S5 #75).
        // For an UPDATE this is the SET-clause targets; a DELETE re-inserts the whole
        // row (row-covered), so it declares none.
        let result = match kind {
            WriteKind::Update => ForwardResult::new(written).with_written_columns(image_cols),
            WriteKind::Delete => ForwardResult::new(written),
        };
        Ok(result)
    }

    fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
        let after = self.read_xact_raw()?;
        let mut out = Vec::new();
        for (rel, (ins, upd, del)) in &after {
            let (b_ins, b_upd, b_del) = self.xact_baseline.get(rel).copied().unwrap_or((0, 0, 0));
            let d_ins = (ins - b_ins).max(0) as u64;
            let d_upd = (upd - b_upd).max(0) as u64;
            let d_del = (del - b_del).max(0) as u64;
            if d_ins + d_upd + d_del == 0 {
                continue;
            }
            out.push(RelationChange {
                relation: rel.clone(),
                ins: d_ins,
                upd: d_upd,
                del: d_del,
            });
        }
        out.sort_by(|a, b| a.relation.cmp(&b.relation));
        Ok(out)
    }

    fn commit(&mut self) -> Result<(), ApplyError> {
        self.client
            .batch_execute("COMMIT")
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        self.in_txn = false;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), ApplyError> {
        if self.in_txn {
            let _ = self.client.batch_execute("ROLLBACK");
            self.in_txn = false;
        }
        Ok(())
    }
}

/// Map a `postgres::Error` to the engine's [`ApplyError`], surfacing a
/// `statement_timeout` cancel distinctly so a timeout abort is not conflated with
/// a drift abort.
fn classify_apply(e: &postgres::Error, timeout_ms: u64) -> ApplyError {
    if e.code() == Some(&SqlState::QUERY_CANCELED) {
        ApplyError::Timeout { timeout_ms }
    } else {
        ApplyError::Backend(e.to_string())
    }
}

// ===========================================================================
//  PgRevertConn — the UPDATE pre-image upsert + DELETE re-insert revert conn.
// ===========================================================================

/// The real-PG18 [`RevertConn`] for the typed-inverse revert (#37), generic over
/// the **captured pre-image columns** (S5 #75). An `UPDATE` inverse re-applies the
/// captured OLD values of exactly the columns the forward op wrote (`PreimageUpsert`,
/// keyed on the single-int PK); a `DELETE` inverse re-inserts the captured full-row
/// image. The columns are read from each [`RevertRow::before_image`] — NOT
/// hardcoded — so any single-int-PK write is restored regardless of which columns it
/// touched.
pub struct PgRevertConn<'a> {
    client: &'a mut Client,
    in_txn: bool,
}

impl<'a> PgRevertConn<'a> {
    /// Wrap a connection as the revert conn.
    pub fn new(client: &'a mut Client) -> Self {
        PgRevertConn {
            client,
            in_txn: false,
        }
    }
}

impl RevertConn for PgRevertConn<'_> {
    fn begin(&mut self) -> Result<(), RevertError> {
        self.client
            .batch_execute("BEGIN")
            .map_err(|e| RevertError::Backend(e.to_string()))?;
        self.in_txn = true;
        Ok(())
    }

    fn restore_update(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError> {
        let mut n = 0u64;
        for row in rows {
            let id = pk_int(row)?;
            // Restore EXACTLY the captured columns (the SET-clause columns the
            // forward op wrote), excluding the PK `id` (it keys the row, never
            // changes). Empty ⇒ a malformed inverse with no columns to restore.
            let cols: Vec<&(String, ImageValue)> =
                row.before_image.iter().filter(|(c, _)| c != "id").collect();
            if cols.is_empty() {
                return Err(RevertError::Backend(format!(
                    "inverse row for `{relation}` id={id} has no non-PK pre-image columns \
                     to restore (S5 #75: a reversible UPDATE must capture every written column)"
                )));
            }
            let mut bind = BindBuilder::new();
            let mut set_list = Vec::with_capacity(cols.len());
            for (col, val) in cols.iter().map(|p| (&p.0, &p.1)) {
                let ph = bind.push(val.into());
                set_list.push(format!("\"{col}\" = {ph}"));
            }
            let id_ph = bind.push(SqlVal::Int(id).into());
            let sql = format!(
                "UPDATE {relation} SET {} WHERE id = {id_ph}",
                set_list.join(", ")
            );
            let updated = self
                .client
                .execute(&sql, &bind.params())
                .map_err(|e| RevertError::Backend(e.to_string()))?;
            n += updated;
        }
        Ok(n)
    }

    fn restore_insert(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError> {
        let mut n = 0u64;
        for row in rows {
            // Re-insert EXACTLY the captured columns (the full-row image a DELETE
            // captured). Must be non-empty (the PK `id` is always present).
            if row.before_image.is_empty() {
                return Err(RevertError::Backend(format!(
                    "inverse row for `{relation}` has no pre-image columns to re-insert"
                )));
            }
            let mut bind = BindBuilder::new();
            let mut cols = Vec::with_capacity(row.before_image.len());
            let mut placeholders = Vec::with_capacity(row.before_image.len());
            for (col, val) in &row.before_image {
                placeholders.push(bind.push(val.into()));
                cols.push(format!("\"{col}\""));
            }
            let sql = format!(
                "INSERT INTO {relation}({}) VALUES ({})",
                cols.join(", "),
                placeholders.join(", ")
            );
            let inserted = self
                .client
                .execute(&sql, &bind.params())
                .map_err(|e| RevertError::Backend(e.to_string()))?;
            n += inserted;
        }
        Ok(n)
    }

    fn commit(&mut self) -> Result<(), RevertError> {
        self.client
            .batch_execute("COMMIT")
            .map_err(|e| RevertError::Backend(e.to_string()))?;
        self.in_txn = false;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), RevertError> {
        if self.in_txn {
            let _ = self.client.batch_execute("ROLLBACK");
            self.in_txn = false;
        }
        Ok(())
    }
}

/// A typed pre-image value owned for the duration of a revert statement, bound as
/// a libpq parameter. Reuses the typed [`ImageValue`] vocabulary (no stringly
/// re-encoding) so the restored value is byte-identical to the captured OLD tuple.
enum SqlVal {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
}

impl SqlVal {
    /// Convert a captured non-NULL [`ImageValue`] into an owned, bindable parameter.
    /// A NULL is handled by [`BindBuilder::push`] as a SQL literal (not a param), so
    /// this is only reached for the three concrete kinds.
    fn from_concrete(v: &ImageValue) -> SqlVal {
        match v {
            PkValue::Int(i) => SqlVal::Int(*i),
            PkValue::Text(s) => SqlVal::Text(s.clone()),
            PkValue::Bytes(b) => SqlVal::Bytes(b.clone()),
            PkValue::Null => unreachable!("NULL is rendered as a literal, never a SqlVal"),
        }
    }

    /// Borrow as a `ToSql` parameter.
    fn as_sql(&self) -> &(dyn postgres::types::ToSql + Sync) {
        match self {
            SqlVal::Int(i) => i,
            SqlVal::Text(s) => s,
            SqlVal::Bytes(b) => b,
        }
    }
}

/// Accumulates the owned bound parameters of one revert statement and renders each
/// captured value's SQL placeholder, keeping parameter numbering and the owned
/// `Vec<SqlVal>` in lock-step. A NULL is emitted as the literal `NULL` (a constant,
/// no value binding) so it assigns to a column of any type; a concrete value is
/// bound as `$n`, with integers cast `$n::int8` so the server infers an `int8`
/// parameter type (which `i64` serializes to) and then assignment-casts it down to
/// the column's own width — without the cast, `i64` is rejected against the `int4`
/// parameter type the server would infer from an `int4` column.
struct BindBuilder {
    owned: Vec<SqlVal>,
}

impl BindBuilder {
    fn new() -> Self {
        BindBuilder { owned: Vec::new() }
    }

    /// Push a captured value, returning its SQL placeholder fragment.
    fn push(&mut self, v: ImageValueOrOwned) -> String {
        match v.into_image_or_sqlval() {
            None => "NULL".to_string(),
            Some(sql_val) => {
                let is_int = matches!(sql_val, SqlVal::Int(_));
                self.owned.push(sql_val);
                let n = self.owned.len();
                if is_int {
                    format!("${n}::int8")
                } else {
                    format!("${n}")
                }
            }
        }
    }

    /// The borrowed parameter slice for `Client::execute`.
    fn params(&self) -> Vec<&(dyn postgres::types::ToSql + Sync)> {
        self.owned.iter().map(|v| v.as_sql()).collect()
    }
}

/// Either a captured [`ImageValue`] reference or a directly-built [`SqlVal`] (the PK
/// `id`), accepted by [`BindBuilder::push`] so a NULL image becomes a literal while
/// concrete values are bound.
enum ImageValueOrOwned<'a> {
    Image(&'a ImageValue),
    Owned(SqlVal),
}

impl ImageValueOrOwned<'_> {
    fn into_image_or_sqlval(self) -> Option<SqlVal> {
        match self {
            ImageValueOrOwned::Image(PkValue::Null) => None,
            ImageValueOrOwned::Image(v) => Some(SqlVal::from_concrete(v)),
            ImageValueOrOwned::Owned(v) => Some(v),
        }
    }
}

impl<'a> From<&'a ImageValue> for ImageValueOrOwned<'a> {
    fn from(v: &'a ImageValue) -> Self {
        ImageValueOrOwned::Image(v)
    }
}

impl From<SqlVal> for ImageValueOrOwned<'_> {
    fn from(v: SqlVal) -> Self {
        ImageValueOrOwned::Owned(v)
    }
}

/// Extract the single integer PK value from a revert row (fail-closed on a
/// non-int / multi-col PK — outside the MVP shape).
fn pk_int(row: &RevertRow) -> Result<i64, RevertError> {
    match &row.pk.values()[0] {
        PkValue::Int(i) => Ok(*i),
        other => Err(RevertError::Backend(format!("bad pk {other:?}"))),
    }
}

// ===========================================================================
//  Shared catalog/measure helpers (used by PgRehearsal).
// ===========================================================================

/// The target's PK columns, in order. Empty ⇒ PK-less.
fn pk_columns(txn: &mut Transaction, relation: &str) -> Result<Vec<String>, String> {
    let (schema, table) = split_relation(relation);
    let rows = txn
        .query(
            r#"
            SELECT a.attname
            FROM pg_index i
            JOIN pg_class c   ON c.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
            WHERE n.nspname = $1 AND c.relname = $2 AND i.indisprimary
            ORDER BY array_position(i.indkey, a.attnum)
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Run the forward statement with `RETURNING <pk cols>` appended, collecting the
/// affected-PK set into a `core` checksum. PK-less ⇒ `checksum = None`.
fn run_forward_capturing_pks(
    txn: &mut Transaction,
    statement: &str,
    relation: &str,
    pk_cols: &[String],
) -> Result<AffectedTable, String> {
    if pk_cols.is_empty() {
        return Ok(AffectedTable {
            relation: relation.to_string(),
            checksum: None,
            rows: 0,
        });
    }
    let returning = pk_cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("{statement} RETURNING {returning}");
    let rows = txn.query(&sql, &[]).map_err(|e| e.to_string())?;

    let mut builder = PkSetBuilder::for_relation(relation);
    for row in &rows {
        let tuple = pk_tuple_from_row(row, pk_cols.len()).map_err(|e| e.to_string())?;
        builder.push(tuple).map_err(|e| e.to_string())?;
    }
    let checksum = builder.finalize().map_err(|e| e.to_string())?;
    Ok(AffectedTable {
        relation: relation.to_string(),
        checksum: Some(checksum),
        rows: rows.len() as u64,
    })
}

fn pk_tuple_from_row(row: &Row, n: usize) -> Result<PkTuple, pgb_core::ChecksumError> {
    let mut vals = Vec::with_capacity(n);
    for i in 0..n {
        vals.push(pk_value_at(row, i));
    }
    PkTuple::new(vals)
}

fn pk_value_at(row: &Row, i: usize) -> PkValue {
    let ty = row.columns()[i].type_().clone();
    match ty {
        Type::INT2 => PkValue::Int(row.get::<_, i16>(i) as i64),
        Type::INT4 => PkValue::Int(row.get::<_, i32>(i) as i64),
        Type::INT8 => PkValue::Int(row.get::<_, i64>(i)),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            PkValue::Text(row.get::<_, String>(i))
        }
        Type::BYTEA => PkValue::Bytes(row.get::<_, Vec<u8>>(i)),
        _ => PkValue::Text(text_fallback(row, i)),
    }
}

fn text_fallback(row: &Row, i: usize) -> String {
    row.try_get::<_, String>(i)
        .unwrap_or_else(|_| format!("<unprintable col {i}>"))
}

/// Capture column `i`'s value as a **lossless** typed [`ImageValue`] for the
/// reversible pre-image (S5 #75). Unlike [`pk_value_at`] (which is only ever used
/// for the PK and may text-fold an exotic key type for the checksum), a pre-image
/// value will be **written back** by the revert, so a lossy capture would silently
/// corrupt the restore. We therefore capture only types we can restore exactly
/// (`int2/4/8`, `text/varchar/bpchar/name`, `bytea`) and **fail closed**
/// ([`ApplyError::Backend`]) on anything else — refusing to commit a write whose
/// pre-image we cannot certifiably restore. A SQL `NULL` is captured faithfully as
/// [`PkValue::Null`] (the revert writes NULL back). (Widening the captured type set
/// is a separate, tested change — fail-closed until then.)
fn image_value_at(row: &Row, i: usize) -> Result<ImageValue, ApplyError> {
    let col = &row.columns()[i];
    let ty = col.type_().clone();
    let name = col.name().to_string();
    let v = match ty {
        Type::INT2 => row
            .try_get::<_, Option<i16>>(i)
            .map(|o| o.map(|x| PkValue::Int(x as i64)).unwrap_or(PkValue::Null)),
        Type::INT4 => row
            .try_get::<_, Option<i32>>(i)
            .map(|o| o.map(|x| PkValue::Int(x as i64)).unwrap_or(PkValue::Null)),
        Type::INT8 => row
            .try_get::<_, Option<i64>>(i)
            .map(|o| o.map(PkValue::Int).unwrap_or(PkValue::Null)),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => row
            .try_get::<_, Option<String>>(i)
            .map(|o| o.map(PkValue::Text).unwrap_or(PkValue::Null)),
        Type::BYTEA => row
            .try_get::<_, Option<Vec<u8>>>(i)
            .map(|o| o.map(PkValue::Bytes).unwrap_or(PkValue::Null)),
        other => {
            return Err(ApplyError::Backend(format!(
                "column `{name}` has type `{other}` which the MVP reversible-capture \
                 does not support losslessly — fail-closed (S5 #75): refusing to commit a \
                 write whose pre-image cannot be certifiably restored"
            )));
        }
    };
    v.map_err(|e| ApplyError::Backend(format!("reading pre-image column `{name}`: {e}")))
}

/// Parse the **SET-clause target columns** of an `UPDATE` from `forward_sql`
/// (S5 #75 column coverage). Returns the column names the write mutates, so the
/// apply captures the pre-image of exactly those columns.
///
/// Fail-closed: a non-plain-column assignment target (a `SET (a,b) = (…)` tuple or
/// a sub-select form we cannot map to discrete columns), a parse failure, or a
/// non-UPDATE statement all return `Err` so the caller refuses to commit a write
/// whose written columns it cannot enumerate. AST-derived (not a text slice) so a
/// `SET` inside a string literal / sub-query cannot fool it.
fn update_set_columns(forward_sql: &str) -> Result<Vec<String>, String> {
    use sqlparser::ast::{AssignmentTarget, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let dialect = PostgreSqlDialect {};
    let parsed =
        Parser::parse_sql(&dialect, forward_sql).map_err(|e| format!("parse error: {e}"))?;
    let update = match parsed.first() {
        Some(Statement::Update(u)) => u,
        _ => return Err("forward statement is not a plain UPDATE".to_string()),
    };
    if update.assignments.is_empty() {
        return Err("UPDATE has no SET assignments".to_string());
    }
    let mut cols = Vec::with_capacity(update.assignments.len());
    for a in &update.assignments {
        match &a.target {
            AssignmentTarget::ColumnName(name) => {
                // `schema.col` / `col` — the last identifier is the column.
                let col = name
                    .0
                    .last()
                    .map(|p| p.to_string())
                    .ok_or_else(|| "empty SET column name".to_string())?;
                // sqlparser renders an unquoted identifier bare and a quoted one with
                // quotes; strip surrounding quotes so the name matches pg_attribute.
                cols.push(col.trim_matches('"').to_string());
            }
            AssignmentTarget::Tuple(_) => {
                return Err(
                    "tuple SET target `(a, b) = (…)` is not supported by the MVP \
                     reversible-capture (fail-closed)"
                        .to_string(),
                );
            }
        }
    }
    Ok(cols)
}

/// Capture cascade-deleted child PKs for `ON DELETE CASCADE` FKs referencing
/// `target`, scoped to the DELETE's predicate.
fn capture_cascades(
    txn: &mut Transaction,
    target: &str,
    delete_statement: &str,
) -> Result<Vec<AffectedTable>, String> {
    let (schema, table) = split_relation(target);
    let fks = txn
        .query(
            r#"
            SELECT cn.nspname AS child_schema, cc.relname AS child_table,
                   con.conkey, con.confkey
            FROM pg_constraint con
            JOIN pg_class pc ON pc.oid = con.confrelid
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN pg_class cc ON cc.oid = con.conrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            WHERE con.contype = 'f' AND con.confdeltype = 'c'
              AND pn.nspname = $1 AND pc.relname = $2
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;

    let where_clause = extract_where(delete_statement);
    let mut out = Vec::new();
    for fk in &fks {
        let child_schema: String = fk.get(0);
        let child_table: String = fk.get(1);
        let child_rel = format!("{child_schema}.{child_table}");
        let child_pk = pk_columns(txn, &child_rel)?;
        if child_pk.is_empty() {
            out.push(AffectedTable {
                relation: child_rel,
                checksum: None,
                rows: 0,
            });
            continue;
        }
        let fk_cols = fk_child_columns(txn, &child_rel, target)?;
        let parent_pk = pk_columns(txn, target)?;
        let join_on = fk_cols
            .iter()
            .zip(parent_pk.iter())
            .map(|(c, p)| format!("ch.\"{c}\" = pa.\"{p}\""))
            .collect::<Vec<_>>()
            .join(" AND ");
        let select_pk = child_pk
            .iter()
            .map(|c| format!("ch.\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {select_pk} FROM {child_rel} ch JOIN {target} pa ON {join_on} WHERE {where_clause}"
        );
        let rows = txn.query(&sql, &[]).map_err(|e| e.to_string())?;
        let mut b = PkSetBuilder::for_relation(&child_rel);
        for row in &rows {
            let tuple = pk_tuple_from_row(row, child_pk.len()).map_err(|e| e.to_string())?;
            b.push(tuple).map_err(|e| e.to_string())?;
        }
        out.push(AffectedTable {
            relation: child_rel,
            checksum: Some(b.finalize().map_err(|e| e.to_string())?),
            rows: rows.len() as u64,
        });
    }
    Ok(out)
}

/// The child-side FK columns referencing `parent`, in PK order.
fn fk_child_columns(
    txn: &mut Transaction,
    child_rel: &str,
    parent: &str,
) -> Result<Vec<String>, String> {
    let (cs, ct) = split_relation(child_rel);
    let (ps, pt) = split_relation(parent);
    let rows = txn
        .query(
            r#"
            SELECT a.attname
            FROM pg_constraint con
            JOIN pg_class cc ON cc.oid = con.conrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            JOIN pg_class pc ON pc.oid = con.confrelid
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
            JOIN pg_attribute a ON a.attrelid = cc.oid AND a.attnum = k.attnum
            WHERE con.contype = 'f'
              AND cn.nspname = $1 AND cc.relname = $2
              AND pn.nspname = $3 AND pc.relname = $4
            ORDER BY k.ord
            "#,
            &[&cs, &ct, &ps, &pt],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Row-level trigger names that fire for `kind` on `relation`.
fn trigger_names(
    txn: &mut Transaction,
    relation: &str,
    kind: WriteKind,
) -> Result<Vec<String>, String> {
    let (schema, table) = split_relation(relation);
    let mask: i32 = match kind {
        WriteKind::Update => 16,
        WriteKind::Delete => 8,
    };
    let rows = txn
        .query(
            &format!(
                r#"
            SELECT t.tgname
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = $1 AND c.relname = $2
              AND NOT t.tgisinternal
              AND (t.tgtype & 1) = 1
              AND (t.tgtype & {mask}) <> 0
            ORDER BY t.tgname
            "#
            ),
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Locks the current backend holds on `relation` (held until ROLLBACK; §12).
fn locks_on(txn: &mut Transaction, relation: &str) -> Result<Vec<LockHeld>, String> {
    let (schema, table) = split_relation(relation);
    let rows = txn
        .query(
            r#"
            SELECT l.mode
            FROM pg_locks l
            JOIN pg_class c ON c.oid = l.relation
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE l.locktype = 'relation'
              AND l.pid = pg_backend_pid()
              AND n.nspname = $1 AND c.relname = $2
            ORDER BY l.mode
            "#,
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in &rows {
        let mode_str: String = row.get(0);
        if let Some(mode) = parse_lock_mode(&mode_str) {
            out.push(LockHeld {
                relation: relation.to_string(),
                mode,
                held_ms: 0,
            });
        }
    }
    Ok(out)
}

/// Raw per-relation `(n_tup_ins, n_tup_upd, n_tup_del)` from
/// `pg_stat_xact_user_tables` (cumulative within the session).
fn xact_raw(txn: &mut Transaction) -> Result<BTreeMap<String, (i64, i64, i64)>, String> {
    let rows = txn
        .query(
            "SELECT schemaname || '.' || relname AS rel, \
                    n_tup_ins, n_tup_upd, n_tup_del \
             FROM pg_stat_xact_user_tables",
            &[],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                (r.get::<_, i64>(1), r.get::<_, i64>(2), r.get::<_, i64>(3)),
            )
        })
        .collect())
}

/// The FULL per-relation, per-op-type in-txn change footprint as the DELTA
/// against `baseline` (SPEC §4 `pg_stat_xact_*`).
fn xact_full_effect(
    txn: &mut Transaction,
    baseline: &BTreeMap<String, (i64, i64, i64)>,
) -> Result<Vec<RelationEffect>, String> {
    let after = xact_raw(txn)?;
    let mut out = Vec::new();
    for (rel, (ins, upd, del)) in &after {
        let (b_ins, b_upd, b_del) = baseline.get(rel).copied().unwrap_or((0, 0, 0));
        let d_ins = (ins - b_ins).max(0) as u64;
        let d_upd = (upd - b_upd).max(0) as u64;
        let d_del = (del - b_del).max(0) as u64;
        if d_ins + d_upd + d_del > 0 {
            out.push(RelationEffect {
                relation: rel.clone(),
                counts: OpCounts::new(d_ins, d_upd, d_del),
            });
        }
    }
    out.sort_by(|a, b| a.relation.cmp(&b.relation));
    Ok(out)
}

fn parse_lock_mode(s: &str) -> Option<LockMode> {
    Some(match s {
        "AccessShareLock" => LockMode::AccessShareLock,
        "RowShareLock" => LockMode::RowShareLock,
        "RowExclusiveLock" => LockMode::RowExclusiveLock,
        "ShareUpdateExclusiveLock" => LockMode::ShareUpdateExclusiveLock,
        "ShareLock" => LockMode::ShareLock,
        "ShareRowExclusiveLock" => LockMode::ShareRowExclusiveLock,
        "ExclusiveLock" => LockMode::ExclusiveLock,
        "AccessExclusiveLock" => LockMode::AccessExclusiveLock,
        _ => return None,
    })
}

/// `pg_current_wal_lsn()` on a plain client.
pub fn current_wal_lsn(client: &mut Client) -> Result<String, String> {
    let row = client
        .query_one("SELECT pg_current_wal_lsn()::text", &[])
        .map_err(|e| e.to_string())?;
    Ok(row.get(0))
}

/// WAL **insert** position inside a txn (`pg_current_wal_insert_lsn()`).
fn txn_wal_lsn(txn: &mut Transaction) -> Result<String, String> {
    let row = txn
        .query_one("SELECT pg_current_wal_insert_lsn()::text", &[])
        .map_err(|e| e.to_string())?;
    Ok(row.get(0))
}

/// WAL bytes between two captured LSNs (`pg_wal_lsn_diff`).
fn wal_diff(txn: &mut Transaction, before: &str, after: &str) -> Result<u64, String> {
    if !is_valid_lsn(before) || !is_valid_lsn(after) {
        return Err(format!("invalid LSN literal: {before:?} / {after:?}"));
    }
    let row = txn
        .query_one(
            &format!(
                "SELECT GREATEST(pg_wal_lsn_diff('{after}'::pg_lsn, '{before}'::pg_lsn), 0)::bigint"
            ),
            &[],
        )
        .map_err(|e| e.to_string())?;
    let bytes: i64 = row.get(0);
    Ok(bytes.max(0) as u64)
}

fn is_valid_lsn(s: &str) -> bool {
    match s.split_once('/') {
        Some((hi, lo)) => {
            !hi.is_empty()
                && !lo.is_empty()
                && hi.chars().all(|c| c.is_ascii_hexdigit())
                && lo.chars().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Split `schema.table` (default schema `public`).
fn split_relation(relation: &str) -> (String, String) {
    match relation.split_once('.') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => ("public".to_string(), relation.to_string()),
    }
}

/// Extract the top-level `WHERE` predicate of a `DELETE`/`UPDATE` from its parsed
/// AST and render it back to SQL. Returns `"true"` when there is no `WHERE`.
fn extract_where(statement: &str) -> String {
    use sqlparser::ast::{SetExpr, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let dialect = PostgreSqlDialect {};
    let Ok(parsed) = Parser::parse_sql(&dialect, statement) else {
        return "true".to_string();
    };
    let selection = match parsed.first() {
        Some(Statement::Delete(d)) => d.selection.as_ref(),
        Some(Statement::Update(u)) => u.selection.as_ref(),
        Some(Statement::Query(q)) => match q.body.as_ref() {
            SetExpr::Select(s) => s.selection.as_ref(),
            _ => None,
        },
        _ => None,
    };
    match selection {
        Some(expr) => expr.to_string(),
        None => "true".to_string(),
    }
}
