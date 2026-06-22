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
//! [`PgApplyConn`] / [`PgRevertConn`] are constrained to the **single-integer-PK
//! `UPDATE`/`DELETE`** shape on a table whose pre-image is `(id, owner, balance)`
//! — exactly the shape the IT already proves end-to-end (commit + revert restores
//! the pre-state). A generic-schema apply that could mis-read the PK or skip a
//! pre-image column is **DEFERRED** (it would break reversibility invisibly).
//! Anything wider is gated out by the dry-run's existing PK-less / volatile /
//! irreversible REFUSALS (fail-closed). [`PgRehearsal`] is generic (it measures
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
}

impl<C: Clock> Rehearsal for PgRehearsal<'_, C> {
    fn volatility_of(&mut self, name: &str) -> Volatility {
        match self.resolve_provolatile(name) {
            Ok(v) => v,
            Err(_) => Volatility::Unknown,
        }
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
/// **single-integer-PK `UPDATE`/`DELETE`** shape on a `(id, owner, balance)`
/// table (the MVP scope #66 already proves end-to-end). The engine owns the §4
/// ordering + guard decisions; this conn owns the SQL run inside ONE apply txn.
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
            let id: i32 = row.get(0);
            b.push(PkTuple::single(PkValue::Int(id as i64)))
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }

    fn apply_forward(
        &mut self,
        _kind: WriteKind,
        relation: &str,
        _cascade: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        let preimage_rows = self
            .client
            .query(
                &format!(
                    "SELECT id, owner, balance FROM {relation} WHERE {} ORDER BY id FOR UPDATE",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| classify_apply(&e, self.statement_timeout_ms))?;
        let mut preimage: BTreeMap<i64, Vec<(String, ImageValue)>> = BTreeMap::new();
        for row in &preimage_rows {
            let id: i32 = row.get(0);
            let owner: String = row.get(1);
            let balance: i64 = row.get(2);
            preimage.insert(
                id as i64,
                vec![
                    ("id".into(), PkValue::Int(id as i64)),
                    ("owner".into(), PkValue::Text(owner)),
                    ("balance".into(), PkValue::Int(balance)),
                ],
            );
        }
        let sql = format!("{} RETURNING id", self.forward_sql);
        let returned = self
            .client
            .query(&sql, &[])
            .map_err(|e| classify_apply(&e, self.statement_timeout_ms))?;
        let mut written = Vec::with_capacity(returned.len());
        for row in &returned {
            let id: i32 = row.get(0);
            let before_image = preimage
                .get(&(id as i64))
                .cloned()
                .unwrap_or_else(|| vec![("id".into(), PkValue::Int(id as i64))]);
            written.push(CapturedRow {
                pk: PkTuple::single(PkValue::Int(id as i64)),
                before_image,
            });
        }
        Ok(ForwardResult::new(written))
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

/// The real-PG18 [`RevertConn`] for the typed-inverse revert (#37), constrained
/// to the same `(id, owner, balance)` MVP shape. An `UPDATE` inverse
/// re-applies the captured OLD `(owner, balance)` per PK (PreimageUpsert); a
/// `DELETE` inverse re-inserts the captured `(id, owner, balance)` rows.
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
            let (owner, balance) = owner_balance(row)?;
            let updated = self
                .client
                .execute(
                    &format!("UPDATE {relation} SET owner = $1, balance = $2 WHERE id = $3"),
                    &[&owner, &balance, &(id as i32)],
                )
                .map_err(|e| RevertError::Backend(e.to_string()))?;
            n += updated;
        }
        Ok(n)
    }

    fn restore_insert(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError> {
        let mut n = 0u64;
        for row in rows {
            let id = pk_int(row)?;
            let (owner, balance) = owner_balance(row)?;
            let inserted = self
                .client
                .execute(
                    &format!("INSERT INTO {relation}(id, owner, balance) VALUES ($1, $2, $3)"),
                    &[&(id as i32), &owner, &balance],
                )
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

/// Extract the single integer PK value from a revert row (fail-closed on a
/// non-int / multi-col PK — outside the MVP shape).
fn pk_int(row: &RevertRow) -> Result<i64, RevertError> {
    match &row.pk.values()[0] {
        PkValue::Int(i) => Ok(*i),
        other => Err(RevertError::Backend(format!("bad pk {other:?}"))),
    }
}

/// Extract the captured `(owner, balance)` pre-image (fail-closed on a missing
/// column — outside the MVP shape).
fn owner_balance(row: &RevertRow) -> Result<(String, i64), RevertError> {
    let owner = row
        .before_image
        .iter()
        .find(|(c, _)| c == "owner")
        .and_then(|(_, v)| match v {
            PkValue::Text(s) => Some(s.clone()),
            _ => None,
        });
    let balance = row
        .before_image
        .iter()
        .find(|(c, _)| c == "balance")
        .and_then(|(_, v)| match v {
            PkValue::Int(i) => Some(*i),
            _ => None,
        });
    match (owner, balance) {
        (Some(owner), Some(balance)) => Ok((owner, balance)),
        _ => Err(RevertError::Backend("missing pre-image cols".into())),
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
