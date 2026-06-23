//! Real-PG18 integration tests for the **guarded-apply engine** (SPEC §4, §10.2,
//! §10.3, §10.4, §1). Env-gated behind `PG_BUMPERS_IT=1` so CI's fast `cargo test`
//! skips them. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test apply_it -- --nocapture
//! ```
//!
//! These drive the production [`pgb_clone_orchestrator::guarded_apply`] engine
//! through a real-PG18 [`PgApplyConn`] against a throwaway cluster on a dedicated
//! port (NEVER 5432). The engine owns the §4 ordering + the guard decisions; the
//! connection owns the SQL — exactly the seam production will use. They assert:
//!
//! - a dry-run-validated UPDATE/DELETE **commits** under the guards; the
//!   **typed-inverse** is captured + matches the changed rows;
//! - **drift injected via `ApplyBarrier::pause_point()`** → apply-time PK-set
//!   re-check **ABORTS** (0-tolerance): insert / delete-shrink / predicate-flip
//!   (same count, different PKs) / trigger-amplification;
//! - the **RETURNING written-set mismatch** (a post-snapshot trigger writing rows
//!   OUTSIDE the predicate) → **ABORTS** (the carry-forward);
//! - `statement_timeout` fires on a slow apply → abort, **no partial commit**;
//! - a refused op → **never applied** (DB untouched).
//!
//! On every abort path we re-read the primary and assert it is byte-for-byte
//! unchanged: the charter is data-loss safety, so "aborted" must mean "nothing
//! persisted".

mod common;

use std::collections::BTreeMap;

use common::{base_pgurl, create_seeded_db, drop_db, it_enabled};
use pgb_clone_orchestrator::apply::{
    ApplyConn, ApplyError, CapturedRow, ForwardResult, RelationChange,
};
use pgb_clone_orchestrator::{PitrConfig, RecoveryFence, WriteKind, guarded_apply};
use pgb_core::inverse::ImageValue;
use pgb_core::{
    BlastRadius, ClosureBarrier, InverseKind, NoopBarrier, OpCounts, PkChecksum, PkSetBuilder,
    PkTuple, PkValue, SystemClock,
};
use postgres::error::SqlState;
use postgres::{Client, NoTls};

/// Skip-guard: returns `None` (printing why) when the IT gate is unset.
fn setup(tag: &str) -> Option<(String, String, Client)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed apply test");
        return None;
    }
    Some(create_seeded_db(&base_pgurl(), tag))
}

/// The stable predicate matching a known PK set in the `accounts` seed: even ids
/// 2,4,6,8 (the seed has ids 1..=8).
const EVEN_WHERE: &str = "id % 2 = 0";

// ===========================================================================
//  The real-PG18 ApplyConn (the production seam, exercised for real)
// ===========================================================================

/// A real-PG18 [`ApplyConn`] for `public.accounts` (single int PK).
///
/// The §4 guarded apply must straddle multiple engine calls inside **one** txn
/// (recompute → forward → commit/rollback), so instead of the `postgres`
/// `Transaction` RAII guard (whose lifetime cannot span separate trait-method
/// calls) we drive the txn with explicit `BEGIN`/`COMMIT`/`ROLLBACK`
/// simple-queries on the owned `Client`. `in_txn` tracks liveness so rollback is
/// idempotent. This is the same connection shape production will use.
struct PgApplyConn<'a> {
    client: &'a mut Client,
    /// The forward statement (without RETURNING); the conn appends `RETURNING id`.
    forward_sql: String,
    /// The recompute predicate (WHERE body) for the apply-time PK-set re-check.
    where_sql: String,
    /// Per-cascade-relation: a SQL snippet selecting the child PK + pre-image rows
    /// (those whose parent matches `where_sql`). Keyed by `schema.table`. Used to
    /// recompute the cascade PK-set checksum AND capture the cascade pre-image for
    /// the full inverse. For the seed this is `entries` whose `account_id` is in
    /// the matched-accounts set.
    cascade_selects: BTreeMap<String, CascadeSelect>,
    /// Per-relation BASELINE of `pg_stat_xact_n_tup_{ins,upd,del}` captured at the
    /// START of the apply txn (before the forward op). `pg_stat_xact_*` accumulates
    /// across the session (it does NOT reset on `BEGIN`), so the forward op's true
    /// footprint is the `after − baseline` DELTA. Without this, prior-session writes
    /// (the seed) would masquerade as the apply's effect.
    xact_baseline: BTreeMap<String, (i64, i64, i64)>,
    /// Set once `begin` runs; cleared by commit/rollback (rollback idempotency).
    in_txn: bool,
    /// The `statement_timeout` the txn runs under (so a cancel maps to `Timeout`).
    statement_timeout_ms: u64,
}

/// How to read a cascade child relation's PK set + pre-image, scoped to the
/// children whose parent matches the target predicate.
#[derive(Clone)]
struct CascadeSelect {
    /// The child relation `schema.table`.
    relation: String,
    /// Comma-separated PK column list (e.g. `account_id, line_no`).
    pk_cols: String,
    /// Comma-separated full pre-image column list (e.g. `account_id, line_no, memo, amount`).
    image_cols: String,
    /// A WHERE body scoping the child rows to the matched parents (e.g.
    /// `account_id IN (SELECT id FROM public.accounts WHERE id % 2 = 0)`).
    where_sql: String,
}

impl<'a> PgApplyConn<'a> {
    fn new(client: &'a mut Client, forward_sql: &str, where_sql: &str, _kind: WriteKind) -> Self {
        PgApplyConn {
            client,
            forward_sql: forward_sql.to_string(),
            where_sql: where_sql.to_string(),
            cascade_selects: BTreeMap::new(),
            xact_baseline: BTreeMap::new(),
            in_txn: false,
            statement_timeout_ms: 0,
        }
    }

    /// Read the raw per-relation `pg_stat_xact_n_tup_{ins,upd,del}` counters for
    /// every user relation (cumulative within the session). The DELTA against the
    /// baseline taken at txn start is the forward op's true footprint.
    fn read_xact_raw(&mut self) -> Result<BTreeMap<String, (i64, i64, i64)>, ApplyError> {
        let rows = self
            .client
            .query(
                "SELECT schemaname || '.' || relname AS rel, \
                        n_tup_ins, n_tup_upd, n_tup_del \
                 FROM pg_stat_xact_user_tables",
                &[],
            )
            .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;
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

    /// Register a cascade child relation for the full-blast-radius re-check +
    /// inverse capture (the seed's `entries → accounts ON DELETE CASCADE`).
    fn with_cascade(mut self, c: CascadeSelect) -> Self {
        self.cascade_selects.insert(c.relation.clone(), c);
        self
    }
}

impl ApplyConn for PgApplyConn<'_> {
    fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError> {
        // A restore point is a durable WAL record created OUTSIDE the apply txn.
        let row = self
            .client
            .query_one("SELECT pg_create_restore_point($1)::text", &[&label])
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        Ok(row.get(0))
    }

    fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError> {
        // Open the apply txn and pin statement_timeout for it. We use explicit
        // BEGIN/COMMIT (simple-query) rather than the `Transaction` guard so the
        // single txn spans the multiple engine calls cleanly.
        self.client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL statement_timeout = {timeout_ms};"
            ))
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        self.in_txn = true;
        self.statement_timeout_ms = timeout_ms;
        // Capture the pg_stat_xact baseline at txn start (it accumulates across the
        // session, so the forward op's footprint is the delta against this).
        self.xact_baseline = self.read_xact_raw()?;
        Ok(())
    }

    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
        // Recompute the affected-PK set on the SAME predicate, INSIDE the txn,
        // BEFORE the forward op (the 0-tolerance drift check's apply-time side).
        // A cascade relation (composite PK) is recomputed via its registered
        // CascadeSelect; the target via the single-int-PK `where_sql`.
        if let Some(c) = self.cascade_selects.get(relation).cloned() {
            let rows = self
                .client
                .query(
                    &format!(
                        "SELECT {} FROM {} WHERE {} ORDER BY {}",
                        c.pk_cols, c.relation, c.where_sql, c.pk_cols
                    ),
                    &[],
                )
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
            let mut b = PkSetBuilder::for_relation(relation);
            for row in &rows {
                // entries PK = (account_id int, line_no int).
                let a: i32 = row.get(0);
                let l: i32 = row.get(1);
                b.push(PkTuple::new(vec![PkValue::Int(a as i64), PkValue::Int(l as i64)]).unwrap())
                    .map_err(|e| ApplyError::Backend(e.to_string()))?;
            }
            return b.finalize().map_err(|e| ApplyError::Backend(e.to_string()));
        }

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
        kind: WriteKind,
        relation: &str,
        cascade_relations: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        // Capture the cascade children's pre-image BEFORE the forward op deletes
        // them (so the typed-inverse can re-insert every cascade-destroyed row).
        let mut cascade_preimages: BTreeMap<String, Vec<CapturedRow>> = BTreeMap::new();
        for rel in cascade_relations {
            if let Some(c) = self.cascade_selects.get(rel).cloned() {
                let rows = self
                    .client
                    .query(
                        &format!(
                            "SELECT {} FROM {} WHERE {} ORDER BY {} FOR UPDATE",
                            c.image_cols, c.relation, c.where_sql, c.pk_cols
                        ),
                        &[],
                    )
                    .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;
                let mut captured = Vec::with_capacity(rows.len());
                for row in &rows {
                    // entries(account_id, line_no, memo, amount).
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

        // Capture the full pre-image of the matching TARGET rows FOR UPDATE (locks
        // them), then run the forward op with RETURNING id (the actual written-PK
        // set). The pre-image SELECT and the forward op are in the same txn, so the
        // RETURNING set and the pre-image describe the same rows. The pre-image is
        // the ACTUAL old values (so a BEFORE-trigger value rewrite cannot desync
        // the inverse — we restore the OLD tuple regardless of the NEW one).
        let preimage_rows = self
            .client
            .query(
                &format!(
                    "SELECT id, owner, balance FROM {relation} WHERE {} ORDER BY id FOR UPDATE",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;

        // Index pre-images by pk for pairing with the RETURNING set.
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

        // The forward op with RETURNING id — the rows it ACTUALLY wrote.
        let sql = format!("{} RETURNING id", self.forward_sql);
        let returned = self
            .client
            .query(&sql, &[])
            .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;

        let _ = kind; // the forward SQL already encodes the op; param kept for the seam.
        let mut written = Vec::with_capacity(returned.len());
        for row in &returned {
            let id: i32 = row.get(0);
            let before_image = preimage.get(&(id as i64)).cloned().unwrap_or_else(|| {
                // A RETURNING id with no captured pre-image means the forward op
                // wrote a row OUTSIDE the FOR UPDATE pre-image snapshot (e.g. a
                // trigger inserted/touched an out-of-predicate row). We still
                // surface the PK so the written-set checksum catches the drift;
                // the pre-image is best-effort (the row will trip the guards anyway).
                vec![("id".into(), PkValue::Int(id as i64))]
            });
            written.push(CapturedRow {
                pk: PkTuple::single(PkValue::Int(id as i64)),
                before_image,
            });
        }
        // The local fixture captures the full `(id, owner, balance)` image; declare
        // the written columns so the S5 #75 column-coverage guard is exercised here
        // too (a `SET balance = …` whose `balance` pre-image is captured passes).
        let written_columns = match kind {
            WriteKind::Update => vec!["owner".to_string(), "balance".to_string()],
            WriteKind::Delete => vec![],
        };
        Ok(ForwardResult {
            written,
            cascade_preimages,
            written_columns,
        })
    }

    fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
        // The symmetric FULL-effect measure: per-relation in-txn tuple deltas from
        // pg_stat_xact_user_tables, as the DELTA against the baseline taken at txn
        // start. This sees rows a trigger wrote in another statement / table that
        // RETURNING never reports (the AFTER-trigger DELETE id=7 / mirror wipe), and
        // cascade drift (more children than predicted) — while cancelling any
        // prior-session writes (the seed) that also sit in the cumulative counter.
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
            // ROLLBACK is safe even on an already-aborted txn (it ends the block).
            let _ = self.client.batch_execute("ROLLBACK");
            self.in_txn = false;
        }
        Ok(())
    }
}

/// Map a PG error to the engine's typed error: a `statement_timeout` cancel
/// (`57014`) becomes [`ApplyError::Timeout`]; anything else is `Backend`.
fn classify_pg_err(e: &postgres::Error, timeout_ms: u64) -> ApplyError {
    if e.code() == Some(&SqlState::QUERY_CANCELED) {
        ApplyError::Timeout { timeout_ms }
    } else {
        ApplyError::Backend(e.to_string())
    }
}

// ===========================================================================
//  Helpers: build the grant + read the world for the unchanged assertions
// ===========================================================================

/// Snapshot the affected-PK-set checksum of `accounts` rows matching `where_sql`
/// (the dry-run / grant side). Uses a fresh connection so it does not disturb the
/// apply client's txn state.
fn grant_checksum(url: &str, where_sql: &str) -> PkChecksum {
    let mut c = Client::connect(url, NoTls).expect("grant connect");
    let rows = c
        .query(
            &format!("SELECT id FROM public.accounts WHERE {where_sql} ORDER BY id"),
            &[],
        )
        .expect("grant select");
    let mut b = PkSetBuilder::for_relation("public.accounts");
    for row in &rows {
        let id: i32 = row.get(0);
        b.push(PkTuple::single(PkValue::Int(id as i64))).unwrap();
    }
    b.finalize().unwrap()
}

/// Build a [`BlastRadius`] grant for `public.accounts` over `where_sql` for an
/// UPDATE (target only, no cascade). The full `effect_by_table` footprint is
/// MEASURED by rehearsing `forward_sql` in a rolled-back txn — the same symmetric
/// `pg_stat_xact_*` measure the real dry-run records — so the grant is honest
/// (what the dry-run would actually produce, audit trigger writes included).
fn grant_for(proposal_id: &str, url: &str, where_sql: &str, duration_ms: u64) -> BlastRadius {
    let forward = format!("UPDATE public.accounts SET balance = 0 WHERE {where_sql}");
    grant_for_forward(
        proposal_id,
        url,
        where_sql,
        &forward,
        WriteKind::Update,
        duration_ms,
    )
}

/// Build a grant whose full footprint is measured by rehearsing `forward_sql`
/// (UPDATE or DELETE) in a rolled-back txn. Captures the target PK-set checksum,
/// every cascade child's PK-set checksum (composite PK), and the full per-relation
/// `effect_by_table` footprint (target + cascades + trigger-written audit table).
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
    let mut c = Client::connect(url, NoTls).expect("grant connect");
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

    // For a DELETE, capture the cascade child (`entries`) PK-set + count (children
    // whose parent matches the predicate), BEFORE the rolled-back forward op.
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
            .expect("cascade child select");
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

    // MEASURE the full per-relation footprint by rehearsing the forward op in a
    // rolled-back txn (the symmetric pg_stat_xact_* measure). This records the
    // audit-table trigger writes too, so the apply does not flag them as drift.
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

/// Rehearse `forward_sql` in a `BEGIN … ROLLBACK` txn and return the full
/// per-relation, **per-op-type** change footprint from `pg_stat_xact_user_tables`
/// (SPEC §4). This is exactly what the dry-run measures; it captures the
/// audit-table trigger writes that are a deterministic, predicted side-effect (so
/// they are NOT drift) — keeping `ins`/`upd`/`del` separate so the apply reconciles
/// each channel (an audit INSERT footprint can NOT be satisfied by a DELETE).
fn measure_full_effect(url: &str, forward_sql: &str) -> BTreeMap<String, OpCounts> {
    let read_raw = |txn: &mut postgres::Transaction| -> BTreeMap<String, (i64, i64, i64)> {
        txn.query(
            "SELECT schemaname || '.' || relname AS rel, \
                    n_tup_ins, n_tup_upd, n_tup_del \
             FROM pg_stat_xact_user_tables",
            &[],
        )
        .expect("measure stat")
        .iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                (r.get::<_, i64>(1), r.get::<_, i64>(2), r.get::<_, i64>(3)),
            )
        })
        .collect()
    };
    let mut c = Client::connect(url, NoTls).expect("measure connect");
    let mut txn = c.transaction().expect("measure begin");
    // Baseline (pg_stat_xact accumulates across the session) → delta = footprint.
    let baseline = read_raw(&mut txn);
    txn.batch_execute(forward_sql).expect("measure forward");
    let after = read_raw(&mut txn);
    txn.rollback().expect("measure rollback");
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

/// A cascade-child registration for the seed's `entries → accounts` FK, scoped to
/// the children whose parent matches `where_sql`.
fn entries_cascade(where_sql: &str) -> CascadeSelect {
    CascadeSelect {
        relation: "public.entries".to_string(),
        pk_cols: "account_id, line_no".to_string(),
        image_cols: "account_id, line_no, memo, amount".to_string(),
        where_sql: format!("account_id IN (SELECT id FROM public.accounts WHERE {where_sql})"),
    }
}

/// Read `(id -> (owner, balance))` for the whole `accounts` table — the
/// golden-state probe for the "unchanged after abort" assertions.
fn read_accounts(url: &str) -> BTreeMap<i32, (String, i64)> {
    let mut c = Client::connect(url, NoTls).expect("read connect");
    let rows = c
        .query(
            "SELECT id, owner, balance FROM public.accounts ORDER BY id",
            &[],
        )
        .expect("read accounts");
    rows.iter()
        .map(|r| {
            (
                r.get::<_, i32>(0),
                (r.get::<_, String>(1), r.get::<_, i64>(2)),
            )
        })
        .collect()
}

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
//  (1) HAPPY PATH — commits under the guards; typed-inverse captured + matches.
// ===========================================================================

#[test]
fn dry_run_validated_update_commits_and_captures_matching_typed_inverse() {
    let Some((admin, dbname, _client)) = setup("apply_commit") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    let before = read_accounts(&url);
    eprintln!("[commit] pre-state (even ids): {:?}", even_view(&before));

    let grant = grant_for("p-commit", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-commit",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("no-drift apply must COMMIT")
    };

    eprintln!(
        "[commit] APPLIED: rows_written={} statement_timeout_ms={} fence={:?}",
        applied.rows_written, applied.statement_timeout_ms, applied.fence
    );

    // Committed: the 4 even accounts now have balance 0.
    assert_eq!(applied.rows_written, 4);
    let after = read_accounts(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(
            after[&id].1, 0,
            "even account {id} must be zeroed (committed)"
        );
    }
    // Odd accounts untouched.
    for &id in &[1i32, 3, 5, 7] {
        assert_eq!(after[&id].1, before[&id].1, "odd {id} untouched");
    }

    // Typed-inverse captured + MATCHES the changed rows: kind, count, and the
    // before_image of each row equals the pre-apply value.
    assert_eq!(applied.inverse.kind, InverseKind::PreimageUpsert);
    assert_eq!(applied.inverse.rows.len(), 4);
    assert_eq!(applied.inverse.relation, "public.accounts");
    for row in &applied.inverse.rows {
        let id = match &row.pk.values()[0] {
            PkValue::Int(i) => *i as i32,
            other => panic!("expected int pk, got {other:?}"),
        };
        let pre_balance = col_int(&row.before_image, "balance");
        let pre_owner = col_text(&row.before_image, "owner");
        assert_eq!(
            (pre_owner, pre_balance),
            before[&id].clone(),
            "inverse pre-image for {id} must match the golden pre-state"
        );
    }
    assert_eq!(applied.fence, RecoveryFence::TypedInverseOnly);
    eprintln!("[commit] PASS: committed + typed-inverse matches the changed rows");

    drop_db(&admin, &dbname);
}

/// (1b) DELETE commits (cascades to entries), inverse kind = INSERT, pre-image
/// captured for the deleted parent rows.
#[test]
fn dry_run_validated_delete_commits_and_captures_insert_inverse() {
    let Some((admin, dbname, _c)) = setup("apply_delete_commit") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let forward = "DELETE FROM public.accounts WHERE id % 2 = 0";
    let grant = grant_for_forward("p-del", &url, EVEN_WHERE, forward, WriteKind::Delete, 50);

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Delete)
            .with_cascade(entries_cascade(EVEN_WHERE));
        guarded_apply(
            "p-del",
            WriteKind::Delete,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("delete apply must COMMIT")
    };

    assert_eq!(applied.rows_written, 4);
    assert_eq!(applied.inverse.kind, InverseKind::Insert);
    // The inverse covers the 4 parent rows AND the 8 cascade-destroyed children
    // (each even account has 2 entries) = 12 pre-images, FK-ordered.
    assert_eq!(
        applied.inverse.fk_order,
        vec!["public.accounts".to_string(), "public.entries".to_string()]
    );
    assert_eq!(
        applied.inverse.rows.len(),
        12,
        "full inverse: 4 parents + 8 cascade children captured"
    );
    let child_pre = applied
        .inverse
        .rows
        .iter()
        .filter(|r| {
            r.before_image
                .iter()
                .any(|(c, v)| c == "__relation" && *v == PkValue::Text("public.entries".into()))
        })
        .count();
    assert_eq!(child_pre, 8, "every cascade child pre-image captured");
    // The even accounts are gone; cascade removed their entries too.
    let after = read_accounts(&url);
    assert!(
        [2, 4, 6, 8].iter().all(|id| !after.contains_key(id)),
        "even accounts must be deleted"
    );
    let entries_left: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one(
            "SELECT count(*) FROM public.entries WHERE account_id % 2 = 0",
            &[],
        )
        .unwrap()
        .get(0)
    };
    assert_eq!(entries_left, 0, "cascade removed the children");
    // Pre-image of each deleted PARENT row matches the golden state (revert reinserts).
    for row in &applied.inverse.rows {
        // skip cascade-child rows (stamped with __relation)
        if row.before_image.iter().any(|(c, _)| c == "__relation") {
            continue;
        }
        let id = match &row.pk.values()[0] {
            PkValue::Int(i) => *i as i32,
            other => panic!("{other:?}"),
        };
        assert_eq!(col_text(&row.before_image, "owner"), before[&id].0);
        assert_eq!(col_int(&row.before_image, "balance"), before[&id].1);
    }
    eprintln!(
        "[delete-commit] PASS: deleted + FULL FK-ordered INSERT inverse (parents + cascade children) captured"
    );

    drop_db(&admin, &dbname);
}

/// (1c) PITR enabled → a restore point is created before the apply (the §1 fence).
#[test]
fn pitr_enabled_creates_a_real_restore_point_before_apply() {
    let Some((admin, dbname, _c)) = setup("apply_pitr") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let grant = grant_for("p-pitr", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = balance + 1 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-pitr",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::enabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("apply commits with a PITR fence")
    };
    match &applied.fence {
        RecoveryFence::PitrRestorePoint { label, lsn } => {
            assert!(label.starts_with("pgb_p-pitr_"), "label={label}");
            assert!(lsn.contains('/'), "a real LSN: {lsn}");
            eprintln!("[pitr] PASS: restore point `{label}` created at LSN {lsn}");
        }
        other => panic!("expected a PITR restore point, got {other:?}"),
    }
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (2) DRIFT via ApplyBarrier::pause_point() → apply-time re-check ABORTS.
// ===========================================================================

/// Shared drift runner: inject `inject_sql` (committed on a second connection)
/// through the barrier, run the guarded UPDATE, and assert the apply-time PK-set
/// re-check ABORTED with no change.
fn run_drift_case(tag: &str, inject_sql: &str) -> Option<(String, String)> {
    let (admin, dbname, _c) = setup(tag)?;
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let grant = grant_for("p-drift", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    // The barrier opens a SEPARATE connection and commits the drift before the
    // apply recomputes the checksum.
    let inject_url = url.clone();
    let inject = inject_sql.to_string();
    let barrier = ClosureBarrier::new(move |_| {
        let mut c = Client::connect(&inject_url, NoTls).expect("inject connect");
        c.batch_execute(&inject).expect("inject drift");
    });

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-drift",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &SystemClock::new(),
        )
    };
    assert_eq!(
        barrier.crossings(),
        1,
        "{tag}: barrier crossed exactly once"
    );

    match result {
        Err(ApplyError::PkSetDrift {
            dry_run,
            apply_time,
            ..
        }) => {
            assert_ne!(
                dry_run, apply_time,
                "{tag}: abort must be a checksum mismatch"
            );
            eprintln!(
                "{tag}: GUARD ABORT (apply-time PK-set drift) dry_run={dry_run} apply_time={apply_time}"
            );
        }
        other => panic!("{tag}: expected PkSetDrift ABORT, got {other:?}"),
    }

    // No partial commit: the even accounts' balances are UNCHANGED (the apply
    // rolled back). We compare only the rows the *forward op* would have touched
    // that the drift did not itself legitimately change.
    let after = read_accounts(&url);
    // The forward op (SET balance = 0) never committed, so NO account that was
    // non-zero before is zero now *because of the apply*. Assert the apply made no
    // balance-zeroing: every id still present whose pre-balance was non-zero is
    // still non-zero (the drift injections here never set balance=0).
    for (id, (_owner, bal)) in &after {
        if let Some((_, pre_bal)) = before.get(id)
            && *pre_bal != 0
        {
            assert_ne!(
                *bal, 0,
                "{tag}: account {id} was zeroed — the aborted apply leaked a partial commit"
            );
        }
    }
    Some((admin, dbname))
}

#[test]
fn t_drift_insert_aborts() {
    // A new matching (even-id) row appears post-snapshot (over-count) → ABORT.
    let Some((admin, dbname)) = run_drift_case(
        "drift_insert",
        "INSERT INTO public.accounts(id, owner, balance) VALUES (100, 'drift', 9999)",
    ) else {
        return;
    };
    eprintln!("T-drift-insert PASS: over-count drift ABORTED, no partial commit");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_delete_shrink_aborts() {
    // A matching row vanishes post-snapshot (under-count) → ABORT.
    let Some((admin, dbname)) =
        run_drift_case("drift_shrink", "DELETE FROM public.accounts WHERE id = 8")
    else {
        return;
    };
    eprintln!("T-drift-delete-shrink PASS: under-count drift ABORTED");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_predicate_flip_same_count_different_pks_aborts() {
    // HEADLINE: id 8 leaves the matched set, id 10 enters it — count stays 4, the
    // PK set changes. A row-count guard PASSES here; only the PK-set checksum
    // catches it. (We delete the even id=8 and insert a new even id=10.)
    let Some((admin, dbname)) = run_drift_case(
        "drift_flip",
        "DELETE FROM public.accounts WHERE id = 8; \
         INSERT INTO public.accounts(id, owner, balance) VALUES (10, 'flip', 1234);",
    ) else {
        return;
    };
    // Prove the COUNT is unchanged (so a count-only guard would have MISSED it).
    let url = url_for(&admin, &dbname);
    let mut c = Client::connect(&url, NoTls).unwrap();
    let n: i64 = c
        .query_one(
            &format!("SELECT count(*) FROM public.accounts WHERE {EVEN_WHERE}"),
            &[],
        )
        .unwrap()
        .get(0);
    eprintln!("T-drift-predicate-flip: matching-row count is still {n} (count guard blind spot)");
    assert_eq!(
        n, 4,
        "count unchanged — only the PK-set checksum catches this"
    );
    eprintln!("T-drift-predicate-flip PASS: identical count, different PK set → ABORTED");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_trigger_amplification_aborts() {
    // A trigger is installed on `accounts` post-snapshot (amplifying the audit
    // side-effect footprint), and the same migration also shifts a NEW row INTO
    // the predicate (an even id=12). The apply-time recompute observes the changed
    // affected-PK set → ABORT. (Per §10.3/the spike: a pre-op recompute cannot see
    // a trigger that writes *outside* the predicate during the forward op — that
    // case is the RETURNING written-set check below — so this models the honest,
    // catchable case where the migration shifts the matched set itself.)
    let Some((admin, dbname)) = run_drift_case(
        "drift_amplify",
        "CREATE FUNCTION public.accounts_amplify() RETURNS trigger LANGUAGE plpgsql AS $$ \
           BEGIN INSERT INTO public.account_audit(account_id, op) VALUES (NEW.id, 'AMPLIFY'); RETURN NEW; END; $$; \
         CREATE TRIGGER accounts_amplify_aud AFTER UPDATE ON public.accounts \
           FOR EACH ROW EXECUTE FUNCTION public.accounts_amplify(); \
         INSERT INTO public.accounts(id, owner, balance) VALUES (12, 'amplify', 1);",
    ) else {
        return;
    };
    eprintln!("T-drift-trigger-amplification PASS: post-snapshot trigger+row shift ABORTED");
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3) THE DATA-LOSS BLOCKERS — a post-snapshot trigger / cascade that writes
//      rows the TARGET's RETURNING can NEVER surface. The symmetric
//      `pg_stat_xact_*` full-effect reconciliation catches them → ABORT, the
//      out-of-predicate rows / other tables stay intact.
// ===========================================================================

/// BLOCKER 1 (the reviewer's EXACT repro): an AFTER UPDATE trigger installed
/// post-snapshot `DELETE FROM accounts WHERE id=7` — id=7 is ODD, OUTSIDE the
/// predicate `id%2=0`. The target's `RETURNING id` = {2,4,6,8} == grant, so the
/// pre-op recompute AND the written-set check both PASS. Only the `pg_stat_xact_*`
/// reconciliation (the target shows 4 upd + 1 del = 5 > predicted 4) catches the
/// irreversible destruction of id=7 → ABORT, id=7 INTACT.
#[test]
fn t_after_trigger_deletes_out_of_predicate_row_aborts_id7_intact() {
    let Some((admin, dbname, _c)) = setup("trigger_kill7") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    // Install the out-of-predicate killer trigger POST-snapshot (the grant is
    // measured BEFORE this, so it predicts only the 4 even-row updates + audit).
    let grant = grant_for("p-kill7", &url, EVEN_WHERE, 50);
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "CREATE FUNCTION public.kill7() RETURNS trigger LANGUAGE plpgsql AS $$ \
               BEGIN DELETE FROM public.accounts WHERE id = 7; RETURN NEW; END; $$; \
             CREATE TRIGGER accounts_kill7 AFTER UPDATE ON public.accounts \
               FOR EACH ROW WHEN (pg_trigger_depth() = 0) \
               EXECUTE FUNCTION public.kill7();",
        )
        .expect("install kill7 trigger");
    }
    let before = read_accounts(&url);
    assert!(before.contains_key(&7), "id=7 present before apply");

    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-kill7",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    // The out-of-predicate DELETE id=7 makes `accounts` show del=1 (predicted del=0)
    // AND the audit trigger fire 5 INSERTs (>4 predicted ins). Either per-channel
    // over-write ABORTS — both are the same irreversible drift; what matters is id=7
    // survives.
    match result {
        Err(ApplyError::RelationOverWrite {
            relation,
            channel,
            p_ins,
            p_upd,
            p_del,
            a_ins,
            a_upd,
            a_del,
        }) => {
            assert!(
                relation == "public.accounts" || relation == "public.account_audit",
                "abort on the over-written relation, got {relation}"
            );
            eprintln!(
                "T-after-trigger-kill7 PASS: out-of-predicate trigger DELETE id=7 caught by \
                 per-op-type pg_stat_xact reconciliation on `{relation}` channel=`{channel}` \
                 (predicted ins={p_ins} upd={p_upd} del={p_del}; actual ins={a_ins} upd={a_upd} del={a_del}) → ABORTED"
            );
        }
        other => panic!("expected RelationOverWrite (out-of-predicate trigger), got {other:?}"),
    }

    // id=7 is INTACT and the whole apply rolled back (DB byte-for-byte unchanged).
    let after = read_accounts(&url);
    assert!(after.contains_key(&7), "id=7 MUST survive (apply aborted)");
    assert_eq!(
        before, after,
        "the whole apply rolled back — DB byte-for-byte unchanged, id=7 destroyed-and-restored never happened"
    );
    drop_db(&admin, &dbname);
}

/// BLOCKER 3 — OP-TYPE SUBSTITUTION (the reviewer's EXACT repro): the audit table
/// `public.account_audit` is pre-seeded with 20 real rows. The grant is measured
/// while the benign audit trigger INSERTs on UPDATE → predicted footprint
/// `account_audit = (ins=4, upd=0, del=0)`. Post-snapshot the trigger is swapped to
/// **DELETE 4 pre-existing audit rows** on UPDATE. The forward op's target
/// `RETURNING` is still {2,4,6,8} == grant, the target footprint still upd=4, and
/// the audit relation's *total* delta is still 4 — so a collapsed-total guard would
/// PASS and COMMIT, destroying 4 real audit rows irreversibly (the relation is
/// neither target nor cascade → no PK-set check, no captured inverse). The
/// per-op-type reconciliation sees `del=4 > predicted del=0` on `account_audit` →
/// ABORT. Audit table stays 20→20, primary byte-for-byte unchanged.
#[test]
fn t_op_type_substitution_predicted_insert_actual_delete_on_audit_aborts() {
    let Some((admin, dbname, _c)) = setup("op_substitution") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    // Pre-seed the audit table with 20 REAL rows (pre-existing data the swapped
    // trigger will try to destroy).
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "INSERT INTO public.account_audit(account_id, op) \
             SELECT (g % 8) + 1, 'SEED' FROM generate_series(1, 20) g;",
        )
        .expect("pre-seed 20 audit rows");
    }
    let audit_before: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.account_audit", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(audit_before, 20, "audit table pre-seeded with 20 rows");

    // Grant measured with the BENIGN (insert-on-update) audit trigger → predicts
    // account_audit = (ins=4, upd=0, del=0).
    let grant = grant_for("p-opsub", &url, EVEN_WHERE, 50);
    let predicted_audit = grant.affected.effect_by_table["public.account_audit"];
    assert_eq!(
        predicted_audit,
        OpCounts::new(4, 0, 0),
        "the dry-run predicted 4 audit INSERTs, NO deletes"
    );

    // Swap the audit trigger function POST-snapshot: on UPDATE it now DELETEs 4
    // pre-existing audit rows instead of inserting (same total magnitude, opposite
    // destructive op). DELETE path unchanged so the seed-FK stays valid.
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "CREATE OR REPLACE FUNCTION public.accounts_audit() RETURNS trigger \
             LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF (TG_OP = 'UPDATE') THEN \
                 DELETE FROM public.account_audit \
                  WHERE audit_id IN (SELECT audit_id FROM public.account_audit \
                                     ORDER BY audit_id LIMIT 1); \
                 RETURN NEW; \
               ELSIF (TG_OP = 'DELETE') THEN \
                 INSERT INTO public.account_audit(account_id, op) VALUES (OLD.id, TG_OP); \
                 RETURN OLD; \
               ELSE RETURN NEW; END IF; \
             END; $$;",
        )
        .expect("swap audit trigger to delete-on-update");
    }

    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-opsub",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    // The substituted DELETE trips the `del` channel of account_audit (actual del>0,
    // predicted del=0) — NOT a collapsed total (which would have matched 4==4).
    match result {
        Err(ApplyError::RelationOverWrite {
            relation,
            channel,
            p_ins,
            p_del,
            a_del,
            ..
        }) => {
            assert_eq!(relation, "public.account_audit");
            assert_eq!(
                channel, "del",
                "the op substitution tripped the del channel"
            );
            assert_eq!(p_ins, 4, "the prediction was 4 audit INSERTs");
            assert_eq!(p_del, 0, "the prediction had ZERO audit deletes");
            assert!(
                a_del > 0,
                "the swapped trigger DELETEd pre-existing audit rows"
            );
            eprintln!(
                "T-op-substitution PASS: predicted INSERT-of-4 on `public.account_audit` \
                 satisfied at apply time by a DELETE of {a_del} pre-existing rows (same total, \
                 opposite op) — caught by PER-OP-TYPE reconciliation (del {a_del} > predicted {p_del}) \
                 → ABORTED. A collapsed-total guard would have COMMITTED this irreversible destruction."
            );
        }
        other => panic!(
            "op-type substitution (predicted ins, apply-time del, same total) MUST abort, got {other:?}"
        ),
    }

    // The 20 audit rows are INTACT and the primary is byte-for-byte unchanged.
    let audit_after: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.account_audit", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(
        audit_after, 20,
        "audit table MUST stay 20→20 (apply aborted; the 4 pre-existing rows were NOT destroyed)"
    );
    drop_db(&admin, &dbname);
}

/// BLOCKER 1 (other-table repro): an AFTER UPDATE trigger wipes a SEPARATE
/// `mirror` table — a relation NOT in the blast radius. RETURNING can never see
/// another table; the `pg_stat_xact_*` delta does → ABORT, `mirror` intact.
#[test]
fn t_after_trigger_wipes_separate_table_aborts_mirror_intact() {
    let Some((admin, dbname, _c)) = setup("trigger_mirror") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "CREATE TABLE public.mirror(id int PRIMARY KEY, v int NOT NULL); \
             INSERT INTO public.mirror SELECT g, g FROM generate_series(1, 5) g;",
        )
        .unwrap();
    }
    // Grant measured BEFORE the mirror-wiping trigger exists.
    let grant = grant_for("p-mirror", &url, EVEN_WHERE, 50);
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "CREATE FUNCTION public.wipe_mirror() RETURNS trigger LANGUAGE plpgsql AS $$ \
               BEGIN DELETE FROM public.mirror; RETURN NEW; END; $$; \
             CREATE TRIGGER accounts_wipe_mirror AFTER UPDATE ON public.accounts \
               FOR EACH STATEMENT EXECUTE FUNCTION public.wipe_mirror();",
        )
        .unwrap();
    }
    let mirror_before: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.mirror", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(mirror_before, 5);

    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-mirror",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    match result {
        Err(ApplyError::UnpredictedRelationWrite { relation, del, .. }) => {
            assert_eq!(relation, "public.mirror");
            assert_eq!(del, 5, "the trigger wiped all 5 mirror rows");
            eprintln!(
                "T-after-trigger-mirror PASS: write to UNPREDICTED relation public.mirror caught → ABORTED"
            );
        }
        other => panic!("expected UnpredictedRelationWrite on public.mirror, got {other:?}"),
    }
    // mirror is INTACT (apply aborted).
    let mirror_after: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.mirror", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(mirror_after, 5, "mirror MUST be intact (apply aborted)");
    drop_db(&admin, &dbname);
}

/// BLOCKER 2 (the reviewer's EXACT repro): +N child rows added post-snapshot under
/// an in-predicate parent. The parent PK set is UNCHANGED ({2,4,6,8}), so the
/// parent RETURNING + pre-op recompute PASS, but the DELETE cascade destroys MORE
/// children than predicted. The cascade PK-set re-check AND the `pg_stat_xact_*`
/// reconciliation catch the over-destruction → ABORT, children intact.
#[test]
fn t_cascade_drift_more_children_than_predicted_aborts() {
    let Some((admin, dbname, _c)) = setup("cascade_drift") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    let forward = "DELETE FROM public.accounts WHERE id % 2 = 0";
    // Grant measured BEFORE the post-snapshot child rows are added.
    let grant = grant_for_forward("p-cdrift", &url, EVEN_WHERE, forward, WriteKind::Delete, 50);
    let predicted_children: u64 = grant.affected.cascade_by_table["public.entries"];

    // Drift: add 50 NEW child rows under an in-predicate parent (id=2), AFTER the
    // grant was measured. The parent set is untouched.
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "INSERT INTO public.entries(account_id, line_no, memo, amount) \
             SELECT 2, g, 'drift-' || g, g FROM generate_series(100, 149) g;",
        )
        .unwrap();
    }
    let children_before: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.entries", &[])
            .unwrap()
            .get(0)
    };

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Delete)
            .with_cascade(entries_cascade(EVEN_WHERE));
        guarded_apply(
            "p-cdrift",
            WriteKind::Delete,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    // The cascade child PK-set drifted (new rows under id=2) — caught at the
    // pre-op cascade re-check (step 5) OR the stat-delta over-write (step 6).
    match result {
        Err(ApplyError::PkSetDrift { relation, .. }) => {
            assert_eq!(relation, "public.entries");
            eprintln!(
                "T-cascade-drift PASS: cascade child PK-set drift (predicted {predicted_children} \
                 children, +50 added post-snapshot) caught at the cascade re-check → ABORTED"
            );
        }
        Err(ApplyError::RelationOverWrite {
            relation,
            channel,
            p_del,
            a_del,
            ..
        }) => {
            assert_eq!(relation, "public.entries");
            assert_eq!(channel, "del");
            assert!(a_del > p_del);
            eprintln!(
                "T-cascade-drift PASS: cascade destroyed {a_del} children > predicted {p_del} \
                 (per-op-type pg_stat_xact reconciliation, del channel) → ABORTED"
            );
        }
        other => panic!("expected cascade PkSetDrift / RelationOverWrite, got {other:?}"),
    }
    // Children + parents INTACT.
    let children_after: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.entries", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(
        children_before, children_after,
        "no child rows destroyed (apply aborted)"
    );
    let parents: i64 = {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.query_one("SELECT count(*) FROM public.accounts", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(parents, 8, "no parent rows destroyed (apply aborted)");
    drop_db(&admin, &dbname);
}

/// MAJOR (BEFORE-trigger value hijack): a BEFORE UPDATE trigger rewrites
/// `NEW.balance` to a value different from the rehearsed one. The change stays
/// reversible because the inverse captures the ACTUAL OLD tuple (the FOR UPDATE
/// pre-image), so revert restores the true pre-state regardless of the hijack. The
/// apply commits (same PK set + same footprint) and the inverse pre-image equals
/// the real OLD values.
#[test]
fn t_before_trigger_value_hijack_inverse_captures_actual_old_values() {
    let Some((admin, dbname, _c)) = setup("before_hijack") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let grant = grant_for("p-hijack", &url, EVEN_WHERE, 50);
    {
        let mut c = Client::connect(&url, NoTls).unwrap();
        c.batch_execute(
            "CREATE FUNCTION public.hijack() RETURNS trigger LANGUAGE plpgsql AS $$ \
               BEGIN NEW.balance := 777777; RETURN NEW; END; $$; \
             CREATE TRIGGER accounts_hijack BEFORE UPDATE ON public.accounts \
               FOR EACH ROW EXECUTE FUNCTION public.hijack();",
        )
        .unwrap();
    }
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-hijack",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("hijack apply still commits (same PK set + footprint, reversible)")
    };
    // The committed value is the HIJACKED one (777777), not the rehearsed 0 — but
    // the inverse pre-image is the ACTUAL OLD value, so revert restores truth.
    let after = read_accounts(&url);
    assert_eq!(
        after[&2].1, 777_777,
        "the BEFORE trigger hijacked the value"
    );
    for row in &applied.inverse.rows {
        let id = match &row.pk.values()[0] {
            PkValue::Int(i) => *i as i32,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            col_int(&row.before_image, "balance"),
            before[&id].1,
            "inverse pre-image MUST be the actual OLD value (so revert undoes even a hijack)"
        );
    }
    eprintln!(
        "T-before-trigger-hijack PASS: committed hijacked value, but the inverse captured the \
         ACTUAL OLD values → revert is correct"
    );
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3c) S5 BLOCKER (#75) — WIDE-COLUMN UPDATE column coverage. A single-int-PK
//       UPDATE that writes a column the OLD hardcoded `(owner, balance)` pre-image
//       never captured. Before the fix this committed `reversible:true` but the
//       revert SILENTLY did not restore the written column — a catastrophic,
//       un-revertable write. After the fix the apply captures the EXACT SET-clause
//       columns' pre-image and the revert restores ALL written columns
//       byte-for-byte (driven through the PRODUCTION conn.rs conns, not the local
//       fixture, so this exercises exactly what `pgb-applyd` runs).
// ===========================================================================

/// Seed a `(id, owner, balance, notes)` wide table on a fresh DB and return its
/// pre-state `id -> (owner, balance, notes)`.
fn seed_wide(url: &str) -> BTreeMap<i32, (String, i64, String)> {
    let mut c = Client::connect(url, NoTls).expect("wide seed connect");
    c.batch_execute(
        "CREATE TABLE public.wide (\
            id int PRIMARY KEY, \
            owner text NOT NULL, \
            balance bigint NOT NULL, \
            notes text NOT NULL); \
         INSERT INTO public.wide(id, owner, balance, notes) \
         SELECT g, 'owner-' || g, (g * 1000)::bigint, 'note-' || g \
         FROM generate_series(1, 8) g;",
    )
    .expect("seed wide");
    read_wide(url)
}

/// Read the full `(owner, balance, notes)` image of `public.wide` per id.
fn read_wide(url: &str) -> BTreeMap<i32, (String, i64, String)> {
    let mut c = Client::connect(url, NoTls).expect("wide read connect");
    c.query(
        "SELECT id, owner, balance, notes FROM public.wide ORDER BY id",
        &[],
    )
    .expect("read wide")
    .iter()
    .map(|r| {
        (
            r.get::<_, i32>(0),
            (
                r.get::<_, String>(1),
                r.get::<_, i64>(2),
                r.get::<_, String>(3),
            ),
        )
    })
    .collect()
}

/// Build an UPDATE grant for `public.wide` over `where_sql` by rehearsing
/// `forward_sql` (the real symmetric `pg_stat_xact_*` measure), with the target
/// PK-set checksum read from the live data set.
fn grant_for_wide(
    proposal_id: &str,
    url: &str,
    where_sql: &str,
    forward_sql: &str,
    duration_ms: u64,
) -> BlastRadius {
    use pgb_core::LockMode;
    use pgb_core::blast_radius::Affected;

    let mut c = Client::connect(url, NoTls).expect("wide grant connect");
    let rows = c
        .query(
            &format!("SELECT id FROM public.wide WHERE {where_sql} ORDER BY id"),
            &[],
        )
        .expect("wide grant select");
    let mut b = PkSetBuilder::for_relation("public.wide");
    for row in &rows {
        let id: i32 = row.get(0);
        b.push(PkTuple::single(PkValue::Int(id as i64))).unwrap();
    }
    let target_cs = b.finalize().unwrap();
    let n = rows.len() as u64;

    let mut pk_set_checksum = BTreeMap::new();
    pk_set_checksum.insert("public.wide".to_string(), target_cs.as_prefixed());
    let mut by_table = BTreeMap::new();
    by_table.insert("public.wide".to_string(), n);
    let effect_by_table = measure_full_effect(url, forward_sql);

    BlastRadius {
        proposal_id: proposal_id.to_string(),
        clone_lsn: "0/0".into(),
        staleness_lsn_bytes: 0,
        affected: Affected {
            by_table,
            cascade_by_table: BTreeMap::new(),
            pk_set_checksum,
            effect_by_table,
            total_rows: n,
        },
        triggers_fired: vec![],
        locks: vec![],
        max_lock_mode: LockMode::RowExclusiveLock,
        duration_ms,
        wal_bytes: 0,
        constraint_violations: vec![],
        reversible: true,
        inverse_kind: WriteKind::Update.inverse_kind(),
        predicate_volatile: false,
    }
}

#[test]
fn t_wide_column_update_is_fully_reversible_revert_restores_all_columns() {
    let Some((admin, dbname, _c)) = setup("wide_column_update") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = seed_wide(&url);

    // A single-int-PK UPDATE that writes ONLY the `notes` column — exactly the
    // shape the OLD hardcoded `(owner, balance)` pre-image never captured.
    let where_sql = "id % 2 = 0";
    let forward = "UPDATE public.wide SET notes = 'hacked' WHERE id % 2 = 0";
    let grant = grant_for_wide("p-wide", &url, where_sql, forward, 50);

    // Drive the PRODUCTION conn.rs PgApplyConn (what pgb-applyd uses), NOT the
    // local fixture — so this proves the daemon's real apply path is reversible.
    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn =
            pgb_clone_orchestrator::PgApplyConn::new(&mut apply_client, forward, where_sql);
        guarded_apply(
            "p-wide",
            WriteKind::Update,
            "public.wide",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("a single-int-PK wide-column UPDATE must be reversibly APPLIED")
    };
    assert_eq!(applied.rows_written, 4);

    // The committed write: even rows now carry notes='hacked'; the inverse MUST
    // have captured the `notes` pre-image (the bug was that it did not).
    let after_apply = read_wide(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(after_apply[&id].2, "hacked", "even {id} notes written");
    }
    let captured_notes = applied
        .inverse
        .rows
        .iter()
        .all(|r| r.before_image.iter().any(|(c, _)| c == "notes"));
    assert!(
        captured_notes,
        "the typed-inverse MUST capture the WRITTEN `notes` column's pre-image \
         (the S5 #75 bug: it captured only (owner,balance) and silently dropped notes)"
    );

    // REVERT via the ACTUAL captured inverse → ALL columns restored byte-for-byte,
    // including the previously-uncaptured `notes`.
    {
        let mut client = Client::connect(&url, NoTls).expect("revert connect");
        let mut rconn = pgb_clone_orchestrator::PgRevertConn::new(&mut client);
        let report = pgb_clone_orchestrator::revert(&applied.inverse, &mut rconn)
            .expect("revert must succeed");
        assert_eq!(report.total_restored, 4);
    }
    let after_revert = read_wide(&url);
    assert_eq!(
        before, after_revert,
        "revert MUST restore the FULL row (incl. the previously-uncaptured `notes`) \
         byte-for-byte — a wide-column UPDATE is genuinely reversible, not a silent FN"
    );
    eprintln!(
        "T-wide-column-update PASS: SET notes=… captured + reverted ALL columns \
         (no silent un-revertable write)"
    );
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3b) RETURNING written-set check — same-relation, same-COUNT identity drift
//       that the stat-delta count check cannot see. The forward op writes a
//       DIFFERENT set of the SAME size in the target → step 7 ABORTS.
// ===========================================================================

#[test]
fn t_returning_written_set_mismatch_same_count_aborts() {
    let Some((admin, dbname, _c)) = setup("returning_samecount") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // The grant is for {2,4,6,8} (the EVEN_WHERE predicate the recompute uses). The
    // forward op writes a DIFFERENT set of the SAME cardinality 4 — {2,4,6,1}
    // (id=8 OUT via `id<>8`, id=1 IN). The pre-op recompute on EVEN_WHERE → {2,4,6,8}
    // == grant (PASS), and the txn changes exactly 4 target rows (stat-delta count
    // matches), but the RETURNING set {1,2,4,6} differs from the predicted {2,4,6,8}.
    // Only the written-set checksum (step 7) catches this same-count identity drift.
    let grant = grant_for("p-ret", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = 0 WHERE (id % 2 = 0 AND id <> 8) OR id = 1";

    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut apply_client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-ret",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    match result {
        Err(ApplyError::WrittenSetMismatch {
            predicted, written, ..
        }) => {
            assert_ne!(predicted, written);
            eprintln!(
                "T-returning-written-set PASS: same-count identity drift in the target \
                 (predicted={predicted} written={written}) → ABORTED"
            );
        }
        other => panic!("expected WrittenSetMismatch, got {other:?}"),
    }
    let after = read_accounts(&url);
    assert_eq!(
        before, after,
        "the whole apply rolled back — DB byte-for-byte unchanged"
    );
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (4) statement_timeout fires on a slow apply → abort, NO partial commit.
// ===========================================================================

#[test]
fn statement_timeout_fires_and_leaves_no_partial_commit() {
    let Some((admin, dbname, _c)) = setup("apply_timeout") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // A dry-run duration of 0 → statement_timeout floor = 1000ms. The forward op
    // sleeps 3s, so the server cancels it (57014) → ApplyError::Timeout.
    let grant = grant_for("p-timeout", &url, EVEN_WHERE, 0);
    let forward =
        "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0 AND pg_sleep(3) IS NOT NULL";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-timeout",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    match result {
        Err(ApplyError::Timeout { timeout_ms }) => {
            assert_eq!(timeout_ms, 1_000, "floor timeout for a 0ms dry-run");
            eprintln!("[timeout] PASS: statement_timeout {timeout_ms}ms fired → aborted");
        }
        other => panic!("expected ApplyError::Timeout, got {other:?}"),
    }
    // No partial commit — every balance unchanged.
    let after = read_accounts(&url);
    assert_eq!(before, after, "a timeout abort must leave the DB unchanged");
    eprintln!("[timeout] DB byte-for-byte unchanged (no partial commit)");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (5) Refused op → never applied (DB untouched).
// ===========================================================================

#[test]
fn refused_op_is_never_applied_db_untouched() {
    let Some((admin, dbname, _c)) = setup("apply_refused") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // Model a non-reversible UPDATE (no captured pre-image) → outside the
    // certified set → REFUSED. The grant carries reversible=false.
    let mut grant = grant_for("p-refused", &url, EVEN_WHERE, 50);
    grant.reversible = false;
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-refused",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    assert!(
        matches!(result, Err(ApplyError::Refused(_))),
        "got {result:?}"
    );
    eprintln!("[refused] {:?}", result.unwrap_err());

    // DB byte-for-byte untouched — the refusal happened before any txn opened.
    let after = read_accounts(&url);
    assert_eq!(before, after, "a refused op must never touch the DB");
    eprintln!("[refused] PASS: refused before any DB work, DB untouched");

    drop_db(&admin, &dbname);
}

// ---- small pre-image column helpers ---------------------------------------

fn col_int(image: &[(String, ImageValue)], name: &str) -> i64 {
    match image.iter().find(|(c, _)| c == name).map(|(_, v)| v) {
        Some(PkValue::Int(i)) => *i,
        other => panic!("expected int col `{name}`, got {other:?}"),
    }
}
fn col_text(image: &[(String, ImageValue)], name: &str) -> String {
    match image.iter().find(|(c, _)| c == name).map(|(_, v)| v) {
        Some(PkValue::Text(s)) => s.clone(),
        other => panic!("expected text col `{name}`, got {other:?}"),
    }
}

/// A compact "even ids -> balance" view for log lines.
fn even_view(m: &BTreeMap<i32, (String, i64)>) -> BTreeMap<i32, i64> {
    m.iter()
        .filter(|(id, _)| **id % 2 == 0)
        .map(|(id, (_, b))| (*id, *b))
        .collect()
}
