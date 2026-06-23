//! Real-PG18 integration tests for the **revert engine** (SPEC §5, §10.3, §10.5(b),
//! §10.6, §1). Env-gated behind `PG_BUMPERS_IT=1`. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test revert_it -- --nocapture
//! ```
//!
//! This is the **"auto-reverted with a verifiable diff" half of the moat**. It
//! proves reversibility *against a GOLDEN PROD STATE* (not just a clone):
//!
//! 1. seed a deterministic schema (FK parent/child `ON DELETE CASCADE`, a
//!    trigger-side-effect audit table, a sequence);
//! 2. checksum the **golden prod state** with an **INDEPENDENT differ** — a
//!    Postgres-side `md5(string_agg(row::text ORDER BY pk))` per table + the
//!    sequence `last_value` + the audit-table rows — that shares **NO code** with
//!    the inverse-under-test (SPEC §10.6, avoid circularity);
//! 3. `guarded_apply` the write (the moat's forward half, already merged);
//! 4. `revert` the captured typed-inverse (the engine under test);
//! 5. assert the **target + cascade rows are byte-for-byte == golden** (independent
//!    differ confirms);
//! 6. assert the documented honest gaps are **NOT restored** (SPEC §1): the
//!    sequence `last_value` stays advanced, the trigger-audit rows are NOT removed
//!    (the revert's own re-insert even appends MORE), NOTIFY is not recalled.
//!
//! The **MARQUEE** is `t_marquee_no_where_update_balance_zero_auto_reverts`: the
//! slipped no-`WHERE` `UPDATE accounts SET balance = 0` → applied → auto-reverted →
//! prod (target + cascade) byte-for-byte == golden.

mod common;

use std::collections::BTreeMap;

use common::{base_pgurl, create_seeded_db, drop_db, it_enabled};
use pgb_clone_orchestrator::apply::{
    ApplyConn, ApplyError, CapturedRow, ForwardResult, RelationChange,
};
use pgb_clone_orchestrator::revert::{RevertConn, RevertError, RevertRow, revert};
use pgb_clone_orchestrator::{PitrConfig, WriteKind, guarded_apply};
use pgb_core::inverse::{ImageValue, Operation, certify};
use pgb_core::{
    BlastRadius, InverseKind, NoopBarrier, NotRestored, OpCounts, PkChecksum, PkSetBuilder,
    PkTuple, PkValue, RefusedOp, SystemClock, WriteCap,
};
use postgres::{Client, NoTls};

/// Skip-guard: returns `None` (printing why) when the IT gate is unset.
fn setup(tag: &str) -> Option<(String, String)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed revert test");
        return None;
    }
    let (admin, dbname, _client) = create_seeded_db(&base_pgurl(), tag);
    Some((admin, dbname))
}

const EVEN_WHERE: &str = "id % 2 = 0";

fn url_for(admin: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = admin
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

// ===========================================================================
//  THE INDEPENDENT REVERT-DIFFER (SPEC §10.6) — shares NO code with the inverse.
//
//  This is a *Postgres-side* checksum: `md5(string_agg(t::text, ',' ORDER BY pk))`.
//  It never touches PkSetBuilder / PkChecksum / InversePlan / the apply or revert
//  engine — it reads the live table with raw SQL and hashes the rendered rows in
//  the server. So "golden == post-revert" being asserted by THIS differ cannot be
//  an artifact of the same code that produced the inverse (avoid circularity).
// ===========================================================================

/// An independent, Postgres-computed fingerprint of the golden prod state. Each
/// field is a server-side `md5(string_agg(...))` or a raw count / `last_value` —
/// no Rust checksum code, no shared path with the inverse-under-test.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GoldenFingerprint {
    /// `md5` of every `accounts` row rendered to text, ordered by `id`.
    accounts_md5: String,
    /// `md5` of every `entries` row rendered to text, ordered by `(account_id,line_no)`.
    entries_md5: String,
    /// `md5` of every `account_audit` row (the trigger-side-effect table).
    audit_md5: String,
    /// Number of audit rows (the trigger side-effect count).
    audit_rows: i64,
    /// The sequence's `last_value` (a documented UNRESTORED gap — §1).
    seq_last_value: i64,
}

/// Compute the independent fingerprint from `url` via raw server-side SQL only.
fn independent_fingerprint(url: &str) -> GoldenFingerprint {
    let mut c = Client::connect(url, NoTls).expect("differ connect");
    // Per-table md5 of the rendered rows in a deterministic order. `t::text` is the
    // full row image; string_agg + md5 collapses it to one independent digest.
    let accounts_md5: String = c
        .query_one(
            "SELECT coalesce(md5(string_agg(t::text, ',' ORDER BY t.id)), 'empty') \
             FROM public.accounts t",
            &[],
        )
        .unwrap()
        .get(0);
    let entries_md5: String = c
        .query_one(
            "SELECT coalesce(md5(string_agg(t::text, ',' ORDER BY t.account_id, t.line_no)), 'empty') \
             FROM public.entries t",
            &[],
        )
        .unwrap()
        .get(0);
    let audit_md5: String = c
        .query_one(
            "SELECT coalesce(md5(string_agg(t::text, ',' ORDER BY t.audit_id)), 'empty') \
             FROM public.account_audit t",
            &[],
        )
        .unwrap()
        .get(0);
    let audit_rows: i64 = c
        .query_one("SELECT count(*) FROM public.account_audit", &[])
        .unwrap()
        .get(0);
    let seq_last_value: i64 = c
        .query_one("SELECT last_value FROM public.ticket_seq", &[])
        .unwrap()
        .get(0);
    GoldenFingerprint {
        accounts_md5,
        entries_md5,
        audit_md5,
        audit_rows,
        seq_last_value,
    }
}

// ===========================================================================
//  A real-PG18 RevertConn for the seed (accounts target + entries cascade).
//
//  PREIMAGE_UPSERT → UPDATE accounts SET owner=$, balance=$ WHERE id=$.
//  INSERT          → INSERT INTO <relation> (cols...) VALUES (...).
//  The engine calls these FK-ordered; this conn just emits the SQL per relation.
// ===========================================================================

struct PgRevertConn<'a> {
    client: &'a mut Client,
    in_txn: bool,
}

impl<'a> PgRevertConn<'a> {
    fn new(client: &'a mut Client) -> Self {
        PgRevertConn {
            client,
            in_txn: false,
        }
    }
}

/// Render an [`ImageValue`] to a SQL literal (typed; ints bare, text quoted).
fn lit(v: &ImageValue) -> String {
    match v {
        PkValue::Int(i) => i.to_string(),
        PkValue::Text(s) => format!("'{}'", s.replace('\'', "''")),
        PkValue::Bytes(b) => format!(
            "'\\x{}'::bytea",
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        ),
        PkValue::Null => "NULL".to_string(),
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
        for r in rows {
            // The pre-image's non-PK columns are the SET list; the PK targets the row.
            let id = match &r.pk.values()[0] {
                PkValue::Int(i) => *i,
                other => return Err(RevertError::Backend(format!("non-int pk {other:?}"))),
            };
            // Restore owner + balance from the captured pre-image.
            let owner = r
                .before_image
                .iter()
                .find(|(c, _)| c == "owner")
                .map(|(_, v)| lit(v))
                .ok_or_else(|| RevertError::MalformedRow {
                    relation: relation.to_string(),
                    detail: "missing owner".into(),
                })?;
            let balance = r
                .before_image
                .iter()
                .find(|(c, _)| c == "balance")
                .map(|(_, v)| lit(v))
                .ok_or_else(|| RevertError::MalformedRow {
                    relation: relation.to_string(),
                    detail: "missing balance".into(),
                })?;
            let sql = format!(
                "UPDATE {relation} SET owner = {owner}, balance = {balance} WHERE id = {id}"
            );
            let affected = self
                .client
                .execute(&sql, &[])
                .map_err(|e| RevertError::Backend(e.to_string()))?;
            n += affected;
        }
        Ok(n)
    }

    fn restore_insert(&mut self, relation: &str, rows: &[RevertRow]) -> Result<u64, RevertError> {
        let mut n = 0u64;
        for r in rows {
            let cols: Vec<String> = r.before_image.iter().map(|(c, _)| c.clone()).collect();
            let vals: Vec<String> = r.before_image.iter().map(|(_, v)| lit(v)).collect();
            let sql = format!(
                "INSERT INTO {relation} ({}) VALUES ({})",
                cols.join(", "),
                vals.join(", ")
            );
            let affected = self
                .client
                .execute(&sql, &[])
                .map_err(|e| RevertError::Backend(e.to_string()))?;
            n += affected;
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

// ===========================================================================
//  A real-PG18 ApplyConn for the seed (reused, focused). This is the SAME seam
//  apply_it.rs exercises; we keep a lean copy here so the revert test is
//  self-contained (the apply engine itself is already merged + tested).
// ===========================================================================

struct PgApplyConn<'a> {
    client: &'a mut Client,
    forward_sql: String,
    where_sql: String,
    cascade: Option<CascadeSelect>,
    xact_baseline: BTreeMap<String, (i64, i64, i64)>,
    in_txn: bool,
}

#[derive(Clone)]
struct CascadeSelect {
    relation: String,
    where_sql: String,
}

impl<'a> PgApplyConn<'a> {
    fn new(client: &'a mut Client, forward_sql: &str, where_sql: &str) -> Self {
        PgApplyConn {
            client,
            forward_sql: forward_sql.to_string(),
            where_sql: where_sql.to_string(),
            cascade: None,
            xact_baseline: BTreeMap::new(),
            in_txn: false,
        }
    }
    fn with_cascade(mut self, where_sql: &str) -> Self {
        self.cascade = Some(CascadeSelect {
            relation: "public.entries".into(),
            where_sql: format!("account_id IN (SELECT id FROM public.accounts WHERE {where_sql})"),
        });
        self
    }
    fn read_xact_raw(&mut self) -> Result<BTreeMap<String, (i64, i64, i64)>, ApplyError> {
        let rows = self
            .client
            .query(
                "SELECT schemaname || '.' || relname, n_tup_ins, n_tup_upd, n_tup_del \
                 FROM pg_stat_xact_user_tables",
                &[],
            )
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
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
        self.xact_baseline = self.read_xact_raw()?;
        Ok(())
    }
    fn apply_forward(
        &mut self,
        _kind: WriteKind,
        relation: &str,
        cascade_relations: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        let mut cascade_preimages: BTreeMap<String, Vec<CapturedRow>> = BTreeMap::new();
        for rel in cascade_relations {
            if let Some(c) = self.cascade.clone()
                && &c.relation == rel
            {
                let rows = self
                    .client
                    .query(
                        &format!(
                            "SELECT account_id, line_no, memo, amount FROM {} WHERE {} \
                             ORDER BY account_id, line_no FOR UPDATE",
                            c.relation, c.where_sql
                        ),
                        &[],
                    )
                    .map_err(|e| ApplyError::Backend(e.to_string()))?;
                let mut captured = Vec::with_capacity(rows.len());
                for row in &rows {
                    let a: i32 = row.get(0);
                    let l: i32 = row.get(1);
                    let memo: String = row.get(2);
                    let amount: i64 = row.get(3);
                    captured.push(CapturedRow {
                        pk: PkTuple::new(vec![PkValue::Int(a as i64), PkValue::Int(l as i64)])
                            .unwrap(),
                        before_image: vec![
                            ("account_id".into(), PkValue::Int(a as i64)),
                            ("line_no".into(), PkValue::Int(l as i64)),
                            ("memo".into(), PkValue::Text(memo)),
                            ("amount".into(), PkValue::Int(amount)),
                        ],
                    });
                }
                cascade_preimages.insert(rel.clone(), captured);
            }
        }
        let preimage_rows = self
            .client
            .query(
                &format!(
                    "SELECT id, owner, balance FROM {relation} WHERE {} ORDER BY id FOR UPDATE",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
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
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
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
        Ok(ForwardResult {
            written,
            cascade_preimages,
            written_columns: vec![],
        })
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

// ---- grant building (measures the full footprint by a rolled-back rehearsal) ----

fn grant_checksum(url: &str, where_sql: &str) -> PkChecksum {
    let mut c = Client::connect(url, NoTls).expect("grant connect");
    let rows = c
        .query(
            &format!("SELECT id FROM public.accounts WHERE {where_sql} ORDER BY id"),
            &[],
        )
        .unwrap();
    let mut b = PkSetBuilder::for_relation("public.accounts");
    for row in &rows {
        let id: i32 = row.get(0);
        b.push(PkTuple::single(PkValue::Int(id as i64))).unwrap();
    }
    b.finalize().unwrap()
}

fn measure_full_effect(url: &str, forward_sql: &str) -> BTreeMap<String, OpCounts> {
    let read_raw = |txn: &mut postgres::Transaction| -> BTreeMap<String, (i64, i64, i64)> {
        txn.query(
            "SELECT schemaname || '.' || relname, n_tup_ins, n_tup_upd, n_tup_del \
             FROM pg_stat_xact_user_tables",
            &[],
        )
        .unwrap()
        .iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                (r.get::<_, i64>(1), r.get::<_, i64>(2), r.get::<_, i64>(3)),
            )
        })
        .collect()
    };
    let mut c = Client::connect(url, NoTls).unwrap();
    let mut txn = c.transaction().unwrap();
    let baseline = read_raw(&mut txn);
    txn.batch_execute(forward_sql).unwrap();
    let after = read_raw(&mut txn);
    txn.rollback().unwrap();
    let mut out = BTreeMap::new();
    for (rel, (ins, upd, del)) in after {
        let (b_ins, b_upd, b_del) = baseline.get(&rel).copied().unwrap_or((0, 0, 0));
        let d_ins = (ins - b_ins).max(0) as u64;
        let d_upd = (upd - b_upd).max(0) as u64;
        let d_del = (del - b_del).max(0) as u64;
        if d_ins + d_upd + d_del > 0 {
            out.insert(rel, OpCounts::new(d_ins, d_upd, d_del));
        }
    }
    out
}

fn grant_for_forward(
    proposal_id: &str,
    url: &str,
    where_sql: &str,
    forward_sql: &str,
    kind: WriteKind,
    duration_ms: u64,
) -> BlastRadius {
    use pgb_core::LockMode;
    use pgb_core::blast_radius::Affected;

    let target_cs = grant_checksum(url, where_sql);
    let mut c = Client::connect(url, NoTls).unwrap();
    let n: i64 = c
        .query_one(
            &format!("SELECT count(*) FROM public.accounts WHERE {where_sql}"),
            &[],
        )
        .unwrap()
        .get(0);
    let n = n as u64;

    let mut pk_set_checksum = BTreeMap::new();
    pk_set_checksum.insert("public.accounts".to_string(), target_cs.as_prefixed());
    let mut by_table = BTreeMap::new();
    by_table.insert("public.accounts".to_string(), n);
    let mut cascade_by_table: BTreeMap<String, u64> = BTreeMap::new();

    if kind == WriteKind::Delete {
        let child_rows = c
            .query(
                &format!(
                    "SELECT account_id, line_no FROM public.entries \
                     WHERE account_id IN (SELECT id FROM public.accounts WHERE {where_sql}) \
                     ORDER BY account_id, line_no"
                ),
                &[],
            )
            .unwrap();
        let mut b = PkSetBuilder::for_relation("public.entries");
        for r in &child_rows {
            let a: i32 = r.get(0);
            let l: i32 = r.get(1);
            b.push(PkTuple::new(vec![PkValue::Int(a as i64), PkValue::Int(l as i64)]).unwrap())
                .unwrap();
        }
        let child_cs = b.finalize().unwrap();
        cascade_by_table.insert("public.entries".to_string(), child_rows.len() as u64);
        pk_set_checksum.insert("public.entries".to_string(), child_cs.as_prefixed());
    }

    let effect_by_table = measure_full_effect(url, forward_sql);
    let total_rows = by_table.values().sum::<u64>() + cascade_by_table.values().sum::<u64>();

    BlastRadius {
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
        duration_ms,
        wal_bytes: 0,
        constraint_violations: vec![],
        reversible: true,
        inverse_kind: kind.inverse_kind(),
        predicate_volatile: false,
    }
}

// ===========================================================================
//  (1) THE MARQUEE — slipped no-WHERE UPDATE accounts SET balance=0 →
//      applied → auto-reverted with a verifiable diff → prod == golden.
// ===========================================================================

#[test]
fn t_marquee_no_where_update_balance_zero_auto_reverts_to_golden() {
    let Some((admin, dbname)) = setup("marquee_revert") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    // (1) GOLDEN: the independent differ fingerprints the prod state BEFORE.
    let golden = independent_fingerprint(&url);
    eprintln!("[marquee] golden fingerprint: {golden:?}");

    // The slipped write: a no-WHERE UPDATE that zeroes EVERY balance. (We use a
    // tautological WHERE so the same machinery applies; this is the killer demo's
    // "SET balance = 0" with no real predicate.)
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id = id";
    let where_sql = "id = id";
    let grant = grant_for_forward("p-marquee", &url, where_sql, forward, WriteKind::Update, 50);

    // (2) APPLY (the merged forward half).
    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut apply_client, forward, where_sql);
        guarded_apply(
            "p-marquee",
            WriteKind::Update,
            "public.accounts",
            &grant,
            WriteCap::new(u64::MAX, u64::MAX),
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("the slipped no-WHERE UPDATE applies under the guards")
    };
    assert_eq!(applied.rows_written, 8, "all 8 balances were zeroed");
    // The damage is real: every balance is now 0 (the independent differ sees a
    // DIFFERENT accounts md5).
    let damaged = independent_fingerprint(&url);
    assert_ne!(
        damaged.accounts_md5, golden.accounts_md5,
        "the slipped write actually changed prod (the differ proves the damage)"
    );
    let zeroed: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one(
            "SELECT count(*) FROM public.accounts WHERE balance = 0",
            &[],
        )
        .unwrap()
        .get(0)
    };
    assert_eq!(zeroed, 8, "all balances zeroed by the slipped write");

    // (3) REVERT the captured typed-inverse (the engine under test).
    let mut revert_client = Client::connect(&url, NoTls).expect("revert connect");
    let report = {
        let mut conn = PgRevertConn::new(&mut revert_client);
        revert(&applied.inverse, &mut conn).expect("auto-revert must restore the golden state")
    };
    eprintln!(
        "[marquee] reverted {} rows: {:?}",
        report.total_restored, report.restored_by_relation
    );
    assert_eq!(report.kind, InverseKind::PreimageUpsert);
    assert_eq!(report.restored("public.accounts"), 8);

    // (4) THE VERIFIABLE DIFF — the INDEPENDENT differ confirms target+cascade rows
    //     are byte-for-byte == golden (no shared code with the inverse).
    let after = independent_fingerprint(&url);
    assert_eq!(
        after.accounts_md5, golden.accounts_md5,
        "MARQUEE: accounts byte-for-byte == golden after auto-revert (independent differ)"
    );
    assert_eq!(
        after.entries_md5, golden.entries_md5,
        "cascade rows (entries) unchanged == golden"
    );

    // (5) THE HONEST GAPS (§1): the revert names them, and they are observably NOT
    //     restored. The audit table has MORE rows than golden (the forward UPDATE
    //     fired the AFTER trigger 8×, and the revert's own UPDATE fired it 8× more);
    //     none were removed. The sequence is documented unrestored.
    assert_eq!(report.not_restored, NotRestored::ALL.to_vec());
    assert!(
        report
            .not_restored
            .contains(&NotRestored::TriggerSideEffect),
        "revert documents trigger side-effects are NOT restored"
    );
    assert!(
        after.audit_rows > golden.audit_rows,
        "trigger-audit rows are NOT restored: golden had {}, now {} (revert appended, never removed)",
        golden.audit_rows,
        after.audit_rows
    );
    assert_ne!(
        after.audit_md5, golden.audit_md5,
        "the audit table is NOT byte-for-byte golden (trigger side-effects persist) — honest gap"
    );
    eprintln!(
        "[marquee] PASS: accounts+entries == golden (independent differ); audit {}->{} NOT restored (honest gap)",
        golden.audit_rows, after.audit_rows
    );

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (2) GOLDEN ROUND-TRIP for a DELETE that CASCADES — revert re-inserts the
//      target AND every cascade-destroyed child, FK-ordered → == golden.
// ===========================================================================

#[test]
fn t_delete_cascade_revert_restores_target_and_cascade_to_golden() {
    let Some((admin, dbname)) = setup("delete_cascade_revert") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    // Advance the sequence first, so we can later prove it is NOT rolled back.
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute("SELECT nextval('public.ticket_seq')")
            .unwrap();
    }
    let golden = independent_fingerprint(&url);

    let forward = "DELETE FROM public.accounts WHERE id % 2 = 0";
    let grant = grant_for_forward("p-delrev", &url, EVEN_WHERE, forward, WriteKind::Delete, 50);

    // APPLY the cascade DELETE.
    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn =
            PgApplyConn::new(&mut apply_client, forward, EVEN_WHERE).with_cascade(EVEN_WHERE);
        guarded_apply(
            "p-delrev",
            WriteKind::Delete,
            "public.accounts",
            &grant,
            WriteCap::new(u64::MAX, u64::MAX),
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("cascade DELETE applies")
    };
    assert_eq!(applied.inverse.kind, InverseKind::Insert);
    assert_eq!(
        applied.inverse.fk_order,
        vec!["public.accounts".to_string(), "public.entries".to_string()],
        "the inverse is FK-ordered: parents before children"
    );
    // The damage: even accounts + their entries are gone.
    let damaged = independent_fingerprint(&url);
    assert_ne!(damaged.accounts_md5, golden.accounts_md5);
    assert_ne!(damaged.entries_md5, golden.entries_md5);

    // REVERT — re-insert the parents (fk_order[0]) THEN the children, FK-ordered.
    let mut revert_client = Client::connect(&url, NoTls).expect("revert connect");
    let report = {
        let mut conn = PgRevertConn::new(&mut revert_client);
        revert(&applied.inverse, &mut conn).expect("cascade revert restores golden")
    };
    eprintln!(
        "[delete-revert] restored {:?} (kind={:?})",
        report.restored_by_relation, report.kind
    );
    assert_eq!(
        report.restored("public.accounts"),
        4,
        "4 parents re-inserted"
    );
    assert_eq!(
        report.restored("public.entries"),
        8,
        "8 cascade children re-inserted"
    );

    // THE INDEPENDENT DIFF — target + cascade byte-for-byte == golden.
    let after = independent_fingerprint(&url);
    assert_eq!(
        after.accounts_md5, golden.accounts_md5,
        "DELETE round-trip: accounts == golden (independent differ)"
    );
    assert_eq!(
        after.entries_md5, golden.entries_md5,
        "DELETE round-trip: cascade entries == golden (independent differ)"
    );

    // HONEST GAP: the sequence is NOT rolled back (a re-insert does not restore a
    // sequence). last_value stays where the golden state had it OR higher — never
    // restored DOWN to an earlier point by the revert.
    assert!(
        after.seq_last_value >= golden.seq_last_value,
        "sequence last_value is NOT restored downward by revert (§1 honest gap)"
    );
    assert!(report.not_restored.contains(&NotRestored::SequenceAdvance));
    eprintln!("[delete-revert] PASS: target+cascade == golden; sequence NOT restored (honest gap)");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3) NEGATIVE TEST PER REFUSED OP — each refused op is REFUSED (never applied),
//      so there is nothing to revert. Default-deny at the certify() choke point.
// ===========================================================================

/// Each named refused op + the shape that triggers it, asserted REFUSED so it is
/// never applied (and thus never needs reverting). This is the §10.3 refused-op
/// list: TRUNCATE / DROP / ALTER / volatile-default INSERT / no-pre-image DELETE /
/// PK-less write.
#[test]
fn t_negative_per_refused_op_is_refused_never_applied() {
    if !it_enabled() {
        eprintln!("[skip] negative refused-op: PG_BUMPERS_IT=1");
        return;
    }
    // certify() is the single default-deny choke point the apply path routes
    // through; assert each refused op category is Err(RefusedOp::…). (These ops can
    // never reach the DB, so there is nothing to revert — the strongest guarantee.)
    let cases: Vec<(Operation, RefusedOp)> = vec![
        (Operation::Truncate, RefusedOp::Truncate),
        (Operation::Drop, RefusedOp::Drop),
        (Operation::Alter, RefusedOp::Alter),
        (
            Operation::Insert {
                volatile_default: true,
                has_pk: true,
            },
            RefusedOp::VolatileDefaultInsert,
        ),
        (
            Operation::Delete {
                has_preimage: false,
                has_pk: true,
            },
            RefusedOp::DeleteWithoutPreimage,
        ),
        (
            Operation::Delete {
                has_preimage: true,
                has_pk: false,
            },
            RefusedOp::PkLessTable,
        ),
    ];
    for (op, expected) in cases {
        let got = certify(&op).expect_err("refused op must be Err");
        assert_eq!(got, expected, "op {op:?} must be refused as {expected:?}");
        eprintln!("[refused] {op:?} → REFUSED ({got}) — never applied, nothing to revert");
    }
    eprintln!("[refused] PASS: every refused op category is denied at the certify() choke point");
}

// ===========================================================================
//  (4) DEFAULT-DENY PROPERTY — a generated op OUTSIDE the certified set is refused.
// ===========================================================================

#[test]
fn t_default_deny_any_op_outside_certified_set_is_refused() {
    if !it_enabled() {
        eprintln!("[skip] default-deny property: PG_BUMPERS_IT=1");
        return;
    }
    // Sweep the whole op space (every flag combo + named DDL/unknown). Everything
    // that is NOT one of the three certified shapes must be refused, and exactly the
    // three certified shapes are allowed. (The closed allow-list is exactly closed.)
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
    assert_eq!(allowed, 3, "exactly the three certified shapes are allowed");
    eprintln!(
        "[default-deny] PASS: {} ops swept; only the 3 certified shapes allowed, all else refused",
        ops.len()
    );
}

// ===========================================================================
//  (5) CARDINALITY INVARIANT (gate carry-forward) — the round-trip holds the
//      table cardinality constant (UPDATE) / restores it exactly (DELETE).
// ===========================================================================

#[test]
fn t_cardinality_invariant_held_across_revert_round_trip() {
    let Some((admin, dbname)) = setup("cardinality_invariant") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    let count = |rel: &str| -> i64 {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one(&format!("SELECT count(*) FROM {rel}"), &[])
            .unwrap()
            .get(0)
    };
    let golden_accounts = count("public.accounts");
    let golden_entries = count("public.entries");

    // A DELETE round-trip: cardinality drops on apply, then is restored EXACTLY.
    let forward = "DELETE FROM public.accounts WHERE id % 2 = 0";
    let grant = grant_for_forward("p-card", &url, EVEN_WHERE, forward, WriteKind::Delete, 50);
    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn =
            PgApplyConn::new(&mut apply_client, forward, EVEN_WHERE).with_cascade(EVEN_WHERE);
        guarded_apply(
            "p-card",
            WriteKind::Delete,
            "public.accounts",
            &grant,
            WriteCap::new(u64::MAX, u64::MAX),
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("cascade DELETE applies")
    };
    // Cardinality dropped (the invariant is NOT held while damaged).
    assert_eq!(count("public.accounts"), golden_accounts - 4);
    assert_eq!(count("public.entries"), golden_entries - 8);

    let mut revert_client = Client::connect(&url, NoTls).expect("revert connect");
    {
        let mut conn = PgRevertConn::new(&mut revert_client);
        revert(&applied.inverse, &mut conn).expect("revert restores");
    }
    // INVARIANT (asserted, not printed): cardinality is restored EXACTLY to golden.
    assert_eq!(
        count("public.accounts"),
        golden_accounts,
        "cardinality invariant: accounts count restored exactly to golden"
    );
    assert_eq!(
        count("public.entries"),
        golden_entries,
        "cardinality invariant: entries (cascade) count restored exactly to golden"
    );
    eprintln!(
        "[cardinality] PASS: accounts {golden_accounts}->{}->{golden_accounts}, entries {golden_entries}->{}->{golden_entries} (invariant asserted)",
        golden_accounts - 4,
        golden_entries - 8
    );

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (6) THE INDEPENDENT DIFFER IS REALLY INDEPENDENT — it detects a change the
//      inverse path never touched (a manual row edit), proving it is not a
//      no-op / circular check.
// ===========================================================================

#[test]
fn t_independent_differ_detects_a_change_outside_the_inverse_path() {
    let Some((admin, dbname)) = setup("differ_sanity") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let golden = independent_fingerprint(&url);

    // Mutate a single row by hand (NOTHING from the inverse/apply path involved).
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute("UPDATE public.accounts SET balance = balance + 1 WHERE id = 1")
            .unwrap();
    }
    let changed = independent_fingerprint(&url);
    assert_ne!(
        changed.accounts_md5, golden.accounts_md5,
        "the independent differ MUST detect a real change (it is not a no-op)"
    );
    // Undo by hand → fingerprint returns to golden.
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute("UPDATE public.accounts SET balance = balance - 1 WHERE id = 1")
            .unwrap();
    }
    let restored = independent_fingerprint(&url);
    assert_eq!(
        restored.accounts_md5, golden.accounts_md5,
        "the independent differ confirms a true byte-for-byte restore"
    );
    eprintln!("[differ] PASS: the independent differ detects a change AND confirms a restore");

    drop_db(&admin, &dbname);
}
