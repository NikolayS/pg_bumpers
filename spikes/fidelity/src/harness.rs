//! DB-touching spike machinery (THROWAWAY). Drives a live PG18 cluster.
//!
//! This module owns: deterministic schema seeding, the affected-PK-set snapshot
//! and its checksum (built from [`pgb_core::PkSetBuilder`]), the typed-inverse
//! capture (built into [`pgb_core::InversePlan`]), the **guarded apply**
//! (recompute the checksum inside the apply txn and ABORT on mismatch), and the
//! inverse-driven restore. The [`pgb_core::ApplyBarrier`] is crossed between the
//! dry-run checksum and the apply-time checksum, as production will (SPEC §10.4).
//!
//! Everything here is intentionally narrow: a single-column-integer-PK `orders`
//! table and a composite-PK `order_items` table, certified `UPDATE`/`DELETE`
//! only. That is enough to exercise the §10.5 gate honestly.

use std::collections::BTreeMap;

use pgb_core::inverse::{certify, Operation};
use pgb_core::{
    ApplyBarrier, CertifiedAction, InverseKind, InversePlan, InverseRow, PkChecksum, PkSetBuilder,
    PkTuple, PkValue, RefusedOp,
};
use postgres::{Client, NoTls, Transaction};

/// Errors the harness can surface. Most are just "the DB said no".
#[derive(Debug, thiserror::Error)]
pub enum SpikeError {
    /// A libpq / protocol error from the `postgres` client.
    #[error("postgres error: {0}")]
    Pg(#[from] postgres::Error),
    /// A core checksum error (e.g. PK-less refused, inconsistent arity).
    #[error("checksum error: {0}")]
    Checksum(#[from] pgb_core::ChecksumError),
    /// The apply-time checksum differed from the dry-run checksum → ABORTed.
    /// This is the **guard firing**; it is the *expected* outcome of every drift
    /// test.
    #[error("GUARD ABORT: affected-PK-set drift between dry_run and apply for `{relation}` (dry_run={dry_run}, apply={apply_time})")]
    DriftAbort {
        /// The relation whose affected-PK set drifted.
        relation: String,
        /// The checksum captured during the dry-run.
        dry_run: String,
        /// The checksum recomputed inside the apply txn.
        apply_time: String,
    },
    /// The operation is outside the certified action set (default-deny). This is
    /// the expected outcome of the non-deterministic-predicate test.
    #[error("REFUSED: {0}")]
    Refused(#[from] RefusedOp),
    /// The clone is too stale (staleness_lsn_bytes over the configured ceiling).
    #[error("STALE: clone staleness {actual} bytes exceeds ceiling {ceiling} bytes")]
    StalenessExceeded {
        /// Measured staleness in WAL bytes.
        actual: u64,
        /// The configured ceiling in WAL bytes.
        ceiling: u64,
    },
}

/// A typed result alias for the harness.
pub type Result<T> = std::result::Result<T, SpikeError>;

/// Connect to a database by libpq URL (sync client). Throwaway helper.
pub fn connect(url: &str) -> Result<Client> {
    Ok(Client::connect(url, NoTls)?)
}

/// Create a fresh, uniquely-named database on the server and return a client
/// connected to it. The name is derived from `tag` so concurrent tests do not
/// collide. The database is dropped by [`drop_database`] in test teardown.
pub fn create_fresh_db(admin_url: &str, tag: &str) -> Result<(String, Client)> {
    let mut admin = connect(admin_url)?;
    // Sanitize tag → a valid, lowercase identifier.
    let dbname = format!(
        "fid_{}",
        tag.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .to_lowercase()
    );
    // Drop if a previous crashed run left it behind, then create. `DROP/CREATE
    // DATABASE` cannot run inside a transaction block, and a multi-statement
    // simple-query string is treated as one implicit txn — so each runs as its
    // own statement via `simple_query`.
    admin.simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))?;
    admin.simple_query(&format!("CREATE DATABASE {dbname}"))?;
    // Rewrite the dbname in the URL to connect to the new database.
    let db_url = replace_dbname(admin_url, &dbname);
    let client = connect(&db_url)?;
    Ok((dbname, client))
}

/// Drop a database created by [`create_fresh_db`] (teardown).
pub fn drop_database(admin_url: &str, dbname: &str) -> Result<()> {
    let mut admin = connect(admin_url)?;
    // `DROP DATABASE` cannot run inside a transaction block; issue it directly.
    admin.simple_query(&format!("DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"))?;
    Ok(())
}

/// Replace (or append) the `dbname=` token in a libpq URL.
fn replace_dbname(url: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

/// The deterministic seed: a couple of FK-related tables, an audit table written
/// by a trigger, and a sequence. Seeded reproducibly so a golden prod state is
/// well-defined.
///
/// Schema:
/// - `public.orders(id PK int, customer text, status text, total_cents bigint)`
/// - `public.order_items(order_id, line_no, sku text, qty int, PRIMARY KEY(order_id, line_no))`
///   — composite PK, FK to `orders(id)` **ON DELETE CASCADE** (cascade path).
/// - `public.order_audit(audit_id PK from a SEQUENCE, order_id, op text, at_logical)`
///   — written by an AFTER UPDATE/DELETE trigger on `orders` (the side-effect
///   table; its rows are an *unrestored gap*).
/// - sequence `public.ticket_seq` (a sequence whose advance is an unrestored gap).
pub const SEED_SQL: &str = r#"
    CREATE TABLE public.orders (
        id          int     PRIMARY KEY,
        customer    text    NOT NULL,
        status      text    NOT NULL,
        total_cents bigint  NOT NULL
    );

    CREATE TABLE public.order_items (
        order_id int  NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
        line_no  int  NOT NULL,
        sku      text NOT NULL,
        qty      int  NOT NULL,
        PRIMARY KEY (order_id, line_no)
    );

    -- A sequence whose advance is a documented UNRESTORED gap.
    CREATE SEQUENCE public.ticket_seq START 1000;

    -- The trigger side-effect / audit table. audit_id comes from its own
    -- sequence; trigger-written rows are a documented UNRESTORED gap.
    CREATE TABLE public.order_audit (
        audit_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        order_id  int    NOT NULL,
        op        text   NOT NULL
    );

    CREATE FUNCTION public.orders_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO public.order_audit(order_id, op) VALUES (OLD.id, TG_OP);
            RETURN OLD;
        ELSE
            INSERT INTO public.order_audit(order_id, op) VALUES (NEW.id, TG_OP);
            RETURN NEW;
        END IF;
    END;
    $$;

    CREATE TRIGGER orders_audit_aud
        AFTER UPDATE OR DELETE ON public.orders
        FOR EACH ROW EXECUTE FUNCTION public.orders_audit();

    -- Deterministic seed: 10 orders, 2 line items each. Status alternates so we
    -- have a stable predicate ("status = 'open'") that matches a known PK set.
    INSERT INTO public.orders(id, customer, status, total_cents)
    SELECT g,
           'cust-' || g,
           CASE WHEN g % 2 = 0 THEN 'open' ELSE 'closed' END,
           (g * 100)::bigint
    FROM generate_series(1, 10) AS g;

    INSERT INTO public.order_items(order_id, line_no, sku, qty)
    SELECT o.id, ln, 'sku-' || o.id || '-' || ln, (o.id + ln)
    FROM public.orders o, generate_series(1, 2) AS ln;
"#;

/// Seed the schema + deterministic data into the connected database.
pub fn seed(client: &mut Client) -> Result<()> {
    client.batch_execute(SEED_SQL)?;
    Ok(())
}

/// A captured affected-PK-set snapshot: the per-relation [`PkChecksum`] plus the
/// total row count, computed from the rows currently matching a predicate.
///
/// `total_rows` is the predicted apply effect for the §10.5(a) delta-0 check.
#[derive(Debug, Clone)]
pub struct AffectedSnapshot {
    /// `schema.table` the predicate targets.
    pub relation: String,
    /// The affected-PK-set checksum (core's `sha256:…`).
    pub checksum: PkChecksum,
    /// Number of affected rows (target only; cascade is counted separately).
    pub total_rows: u64,
}

/// Snapshot the affected-PK set for `orders` rows matching `where_sql`.
///
/// Selects the integer PK of every matching `orders` row and folds it into a
/// [`pgb_core::PkSetBuilder`]. This is the **dry-run** side of the guard.
pub fn snapshot_orders_pks<C: GenericQuery>(
    client: &mut C,
    where_sql: &str,
) -> Result<AffectedSnapshot> {
    let rows = client.query(
        &format!("SELECT id FROM public.orders WHERE {where_sql} ORDER BY id"),
        &[],
    )?;
    let mut builder = PkSetBuilder::for_relation("public.orders");
    for row in &rows {
        let id: i32 = row.get(0);
        builder.push(PkTuple::single(PkValue::Int(id as i64)))?;
    }
    let total_rows = rows.len() as u64;
    Ok(AffectedSnapshot {
        relation: "public.orders".into(),
        checksum: builder.finalize()?,
        total_rows,
    })
}

/// Snapshot the **composite-PK** affected set for `order_items` that would be
/// cascade-deleted when the matching `orders` are deleted. Exercises the
/// composite-PK tuple path of the checksum.
pub fn snapshot_cascade_item_pks<C: GenericQuery>(
    client: &mut C,
    orders_where_sql: &str,
) -> Result<AffectedSnapshot> {
    let rows = client.query(
        &format!(
            "SELECT oi.order_id, oi.line_no
             FROM public.order_items oi
             JOIN public.orders o ON o.id = oi.order_id
             WHERE {orders_where_sql}
             ORDER BY oi.order_id, oi.line_no"
        ),
        &[],
    )?;
    let mut builder = PkSetBuilder::for_relation("public.order_items");
    for row in &rows {
        let order_id: i32 = row.get(0);
        let line_no: i32 = row.get(1);
        builder.push(PkTuple::new(vec![
            PkValue::Int(order_id as i64),
            PkValue::Int(line_no as i64),
        ])?)?;
    }
    let total_rows = rows.len() as u64;
    Ok(AffectedSnapshot {
        relation: "public.order_items".into(),
        checksum: builder.finalize()?,
        total_rows,
    })
}

/// Capture the typed inverse (pre-image) for an UPDATE of `orders.status` on the
/// rows matching `where_sql`. Stores `{pk, before_image}` for every affected row
/// into a [`pgb_core::InversePlan`] of kind [`InverseKind::PreimageUpsert`].
pub fn capture_update_inverse<C: GenericQuery>(
    client: &mut C,
    where_sql: &str,
) -> Result<InversePlan> {
    let rows = client.query(
        &format!(
            "SELECT id, customer, status, total_cents
             FROM public.orders WHERE {where_sql} ORDER BY id"
        ),
        &[],
    )?;
    let mut builder =
        pgb_core::inverse::InversePlanBuilder::new("public.orders", InverseKind::for_update());
    for row in &rows {
        let id: i32 = row.get(0);
        let customer: String = row.get(1);
        let status: String = row.get(2);
        let total_cents: i64 = row.get(3);
        builder = builder.push_row(InverseRow::new(
            PkTuple::single(PkValue::Int(id as i64)),
            vec![
                ("customer".into(), PkValue::Text(customer)),
                ("status".into(), PkValue::Text(status)),
                ("total_cents".into(), PkValue::Int(total_cents)),
            ],
        ));
    }
    Ok(builder.build())
}

/// Capture the typed inverse for a DELETE of `orders` matching `where_sql`,
/// **including the cascaded `order_items`** so the restore can re-insert parents
/// then children in FK order. Kind = [`InverseKind::Insert`].
pub fn capture_delete_inverse<C: GenericQuery>(
    client: &mut C,
    where_sql: &str,
) -> Result<(InversePlan, InversePlan)> {
    // Parent rows (orders).
    let order_rows = client.query(
        &format!(
            "SELECT id, customer, status, total_cents
             FROM public.orders WHERE {where_sql} ORDER BY id"
        ),
        &[],
    )?;
    let mut orders_b =
        pgb_core::inverse::InversePlanBuilder::new("public.orders", InverseKind::for_delete())
            .fk_order(vec!["public.orders".into(), "public.order_items".into()]);
    for row in &order_rows {
        let id: i32 = row.get(0);
        let customer: String = row.get(1);
        let status: String = row.get(2);
        let total_cents: i64 = row.get(3);
        orders_b = orders_b.push_row(InverseRow::new(
            PkTuple::single(PkValue::Int(id as i64)),
            vec![
                ("id".into(), PkValue::Int(id as i64)),
                ("customer".into(), PkValue::Text(customer)),
                ("status".into(), PkValue::Text(status)),
                ("total_cents".into(), PkValue::Int(total_cents)),
            ],
        ));
    }

    // Child rows (order_items that will cascade-delete).
    let item_rows = client.query(
        &format!(
            "SELECT oi.order_id, oi.line_no, oi.sku, oi.qty
             FROM public.order_items oi
             JOIN public.orders o ON o.id = oi.order_id
             WHERE {where_sql}
             ORDER BY oi.order_id, oi.line_no"
        ),
        &[],
    )?;
    let mut items_b =
        pgb_core::inverse::InversePlanBuilder::new("public.order_items", InverseKind::for_delete());
    for row in &item_rows {
        let order_id: i32 = row.get(0);
        let line_no: i32 = row.get(1);
        let sku: String = row.get(2);
        let qty: i32 = row.get(3);
        items_b = items_b.push_row(InverseRow::new(
            PkTuple::new(vec![
                PkValue::Int(order_id as i64),
                PkValue::Int(line_no as i64),
            ])?,
            vec![
                ("order_id".into(), PkValue::Int(order_id as i64)),
                ("line_no".into(), PkValue::Int(line_no as i64)),
                ("sku".into(), PkValue::Text(sku)),
                ("qty".into(), PkValue::Int(qty as i64)),
            ],
        ));
    }
    Ok((orders_b.build(), items_b.build()))
}

/// The outcome of a guarded apply: how many rows the forward op actually touched
/// (from `RETURNING`), used to compare predicted-vs-actual for §10.5(a).
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    /// Rows the forward op actually affected (counted via `RETURNING id`).
    pub actual_rows: u64,
    /// The checksum recomputed at apply time (post-barrier, pre-forward-op).
    pub apply_time_checksum: PkChecksum,
}

/// Run a **guarded apply** of `UPDATE orders SET status=$new WHERE <where_sql>`
/// inside a single txn:
///
/// 1. cross the [`ApplyBarrier::pause_point`] (tests inject drift here),
/// 2. **recompute** the affected-PK-set checksum on the same predicate inside the
///    txn,
/// 3. compare to the dry-run `expected` checksum → [`SpikeError::DriftAbort`] +
///    ROLLBACK on any mismatch,
/// 4. otherwise run the forward UPDATE with `RETURNING id`, COMMIT, and report
///    the actual row count.
///
/// The `barrier` is the real [`pgb_core::ApplyBarrier`]; production passes a
/// `NoopBarrier`, drift tests pass a `ClosureBarrier` that mutates the row set.
#[allow(clippy::too_many_arguments)]
pub fn guarded_update_apply(
    client: &mut Client,
    barrier: &dyn ApplyBarrier,
    where_sql: &str,
    new_status: &str,
    expected: &AffectedSnapshot,
) -> Result<ApplyOutcome> {
    let mut txn = client.transaction()?;

    // (1) The TOCTOU window: cross the barrier between dry-run and apply.
    barrier.pause_point("between dry_run and apply");

    // (2) Recompute the affected-PK-set checksum *inside the apply txn*.
    let apply_snapshot = snapshot_orders_pks(&mut txn, where_sql)?;

    // (3) Guard: ABORT on any checksum mismatch (catches identity drift that a
    // row count would miss).
    if apply_snapshot.checksum != expected.checksum {
        txn.rollback()?;
        return Err(SpikeError::DriftAbort {
            relation: expected.relation.clone(),
            dry_run: expected.checksum.to_string(),
            apply_time: apply_snapshot.checksum.to_string(),
        });
    }

    // (4) Forward op, counting actual affected rows via RETURNING.
    let returned = txn.query(
        &format!("UPDATE public.orders SET status = $1 WHERE {where_sql} RETURNING id"),
        &[&new_status],
    )?;
    let actual_rows = returned.len() as u64;
    txn.commit()?;

    Ok(ApplyOutcome {
        actual_rows,
        apply_time_checksum: apply_snapshot.checksum,
    })
}

/// Guarded apply of a `DELETE FROM orders WHERE <where_sql>` (cascades to
/// `order_items`). Same guard contract as [`guarded_update_apply`]; the
/// `RETURNING id` counts deleted *parent* rows.
pub fn guarded_delete_apply(
    client: &mut Client,
    barrier: &dyn ApplyBarrier,
    where_sql: &str,
    expected: &AffectedSnapshot,
) -> Result<ApplyOutcome> {
    let mut txn = client.transaction()?;
    barrier.pause_point("between dry_run and apply");

    let apply_snapshot = snapshot_orders_pks(&mut txn, where_sql)?;
    if apply_snapshot.checksum != expected.checksum {
        txn.rollback()?;
        return Err(SpikeError::DriftAbort {
            relation: expected.relation.clone(),
            dry_run: expected.checksum.to_string(),
            apply_time: apply_snapshot.checksum.to_string(),
        });
    }

    let returned = txn.query(
        &format!("DELETE FROM public.orders WHERE {where_sql} RETURNING id"),
        &[],
    )?;
    let actual_rows = returned.len() as u64;
    txn.commit()?;

    Ok(ApplyOutcome {
        actual_rows,
        apply_time_checksum: apply_snapshot.checksum,
    })
}

/// Apply the captured UPDATE inverse: restore each row's pre-image by PK. Uses a
/// straightforward `UPDATE … WHERE id = $pk` per row (FK order is trivial for a
/// single relation). Returns rows restored.
pub fn restore_update_inverse(client: &mut Client, plan: &InversePlan) -> Result<u64> {
    assert_eq!(plan.kind, InverseKind::PreimageUpsert);
    let mut txn = client.transaction()?;
    let mut n = 0u64;
    for row in &plan.rows {
        let id = expect_int(&row.pk.values()[0]);
        let customer = expect_text(&col(row, "customer"));
        let status = expect_text(&col(row, "status"));
        let total_cents = expect_int(&col(row, "total_cents"));
        txn.execute(
            "UPDATE public.orders SET customer = $1, status = $2, total_cents = $3 WHERE id = $4",
            &[&customer, &status, &(total_cents), &(id as i32)],
        )?;
        n += 1;
    }
    txn.commit()?;
    Ok(n)
}

/// Apply the captured DELETE inverse in FK order: re-insert `orders` (parents)
/// then `order_items` (children). Returns `(orders_restored, items_restored)`.
pub fn restore_delete_inverse(
    client: &mut Client,
    orders_plan: &InversePlan,
    items_plan: &InversePlan,
) -> Result<(u64, u64)> {
    assert_eq!(orders_plan.kind, InverseKind::Insert);
    assert_eq!(items_plan.kind, InverseKind::Insert);
    // FK order is encoded in the parent plan: parents before children.
    assert_eq!(
        orders_plan.fk_order,
        vec![
            "public.orders".to_string(),
            "public.order_items".to_string()
        ],
        "delete inverse must re-insert parents before children"
    );

    let mut txn = client.transaction()?;
    let mut orders_n = 0u64;
    for row in &orders_plan.rows {
        let id = expect_int(&col(row, "id"));
        let customer = expect_text(&col(row, "customer"));
        let status = expect_text(&col(row, "status"));
        let total_cents = expect_int(&col(row, "total_cents"));
        txn.execute(
            "INSERT INTO public.orders(id, customer, status, total_cents) VALUES ($1, $2, $3, $4)",
            &[&(id as i32), &customer, &status, &total_cents],
        )?;
        orders_n += 1;
    }
    let mut items_n = 0u64;
    for row in &items_plan.rows {
        let order_id = expect_int(&col(row, "order_id"));
        let line_no = expect_int(&col(row, "line_no"));
        let sku = expect_text(&col(row, "sku"));
        let qty = expect_int(&col(row, "qty"));
        txn.execute(
            "INSERT INTO public.order_items(order_id, line_no, sku, qty) VALUES ($1, $2, $3, $4)",
            &[&(order_id as i32), &(line_no as i32), &sku, &(qty as i32)],
        )?;
        items_n += 1;
    }
    txn.commit()?;
    Ok((orders_n, items_n))
}

// ---- pre-image value helpers (THROWAWAY; tolerant on shape) -----------------

fn col(row: &InverseRow, name: &str) -> PkValue {
    row.before_image
        .iter()
        .find(|(c, _)| c == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("pre-image missing column `{name}`"))
}

fn expect_int(v: &PkValue) -> i64 {
    match v {
        PkValue::Int(i) => *i,
        other => panic!("expected Int pre-image value, got {other:?}"),
    }
}

fn expect_text(v: &PkValue) -> String {
    match v {
        PkValue::Text(s) => s.clone(),
        other => panic!("expected Text pre-image value, got {other:?}"),
    }
}

// ---- staleness modeling (§10.5c) --------------------------------------------

/// Capture the current WAL LSN of a database (the "clone snapshot LSN").
pub fn current_wal_lsn(client: &mut Client) -> Result<String> {
    let row = client.query_one("SELECT pg_current_wal_lsn()::text", &[])?;
    Ok(row.get(0))
}

/// Compute `staleness_lsn_bytes` = WAL bytes between a captured `snapshot_lsn`
/// and the current LSN, via `pg_wal_lsn_diff`. Models how far behind prod a
/// clone is (SPEC §10.1 `staleness_lsn_bytes`, §10.5c).
pub fn staleness_lsn_bytes(client: &mut Client, snapshot_lsn: &str) -> Result<u64> {
    // `pg_lsn` has no `ToSql` binding in the client, and a text param won't
    // coerce, so inline the (self-generated, validated) LSN literal. We validate
    // the shape first so this can never be an injection vector.
    if !is_valid_lsn(snapshot_lsn) {
        // Self-generated only; a malformed value is a bug, not user input.
        panic!("invalid LSN literal: {snapshot_lsn:?}");
    }
    let row = client.query_one(
        &format!(
            "SELECT GREATEST(pg_wal_lsn_diff(pg_current_wal_lsn(), '{snapshot_lsn}'::pg_lsn), 0)::bigint"
        ),
        &[],
    )?;
    let bytes: i64 = row.get(0);
    Ok(bytes.max(0) as u64)
}

/// Validate that a string is a well-formed `pg_lsn` literal (`XXXX/XXXX` hex).
/// Used to keep the inlined LSN in [`staleness_lsn_bytes`] injection-proof.
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

/// The staleness gate: reject a clone whose `staleness_lsn_bytes` exceeds the
/// configured `ceiling` (SPEC §10.5c). Returns `Ok(())` if within bound.
pub fn enforce_staleness_ceiling(actual: u64, ceiling: u64) -> Result<()> {
    if actual > ceiling {
        Err(SpikeError::StalenessExceeded { actual, ceiling })
    } else {
        Ok(())
    }
}

/// Burn WAL on the database so the staleness diff grows past a ceiling (test
/// helper to drive §10.5c). Performs `n` cheap writes + checkpoints.
pub fn burn_wal(client: &mut Client, n: u32) -> Result<()> {
    client.batch_execute("CREATE TABLE IF NOT EXISTS public._wal_burn(x bigint)")?;
    for _ in 0..n {
        client.execute(
            "INSERT INTO public._wal_burn SELECT g FROM generate_series(1, 2000) g",
            &[],
        )?;
    }
    Ok(())
}

// ---- certified-action gate over a forward op (§10.3) ------------------------

/// Run the forward op through the core default-deny [`certify`] choke point.
/// Used by the non-deterministic-predicate drift test: an op whose predicate is
/// volatile is mapped to a refused shape and must be **REFUSED, never applied**.
pub fn certify_or_refuse(op: &Operation) -> std::result::Result<CertifiedAction, RefusedOp> {
    certify(op)
}

/// Total trigger-side-effect (audit) row count — used by tests to assert the
/// trigger fired and that the inverse does **not** undo it.
pub fn audit_row_count(client: &mut Client) -> Result<i64> {
    let row = client.query_one("SELECT count(*) FROM public.order_audit", &[])?;
    Ok(row.get(0))
}

/// The current `last_value` of the ticket sequence — used to assert a sequence
/// advance is **not** restored by the inverse.
pub fn ticket_seq_last_value(client: &mut Client) -> Result<i64> {
    // nextval advances the sequence; we read last_value non-destructively.
    let row = client.query_one("SELECT last_value FROM public.ticket_seq", &[])?;
    Ok(row.get(0))
}

/// Advance the ticket sequence (simulate a real-world `nextval` that the inverse
/// will not roll back).
pub fn advance_ticket_seq(client: &mut Client) -> Result<i64> {
    let row = client.query_one("SELECT nextval('public.ticket_seq')", &[])?;
    Ok(row.get(0))
}

/// Trigger-amplification drift: a trigger is *added* to `orders` after the
/// dry-run snapshot, and its installation amplifies the write's footprint by
/// pulling an extra row into the predicate-matched set.
///
/// Honesty note: the checksum guard recomputes the affected-PK set on the
/// predicate **inside the apply txn, before the forward op**. A post-snapshot
/// trigger whose body fires *during* the forward op and touches rows **outside**
/// the predicate would not change that pre-op set — that is a real limitation of
/// a pre-op-only guard, and we do not pretend otherwise. So this drift models the
/// honest, catchable case: the schema change that introduced the trigger also
/// shifts a row **into** the predicate (e.g. a backfill/normalization bundled
/// with the migration), which the apply-time recompute observes → the affected
/// PK set changed → ABORT. The new trigger additionally amplifies the
/// side-effect (audit) footprint, demonstrating the amplification.
pub fn install_amplifying_trigger(client: &mut Client) -> Result<()> {
    client.batch_execute(
        r#"
        -- A second AFTER UPDATE trigger that also writes the audit table (the
        -- amplified side-effect footprint).
        CREATE FUNCTION public.orders_amplify() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO public.order_audit(order_id, op)
            VALUES (NEW.id, 'AMPLIFY');
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER orders_amplify_aud
            AFTER UPDATE ON public.orders
            FOR EACH ROW EXECUTE FUNCTION public.orders_amplify();

        -- The migration that introduced the trigger also normalized an order's
        -- status into the predicate set (id 1: 'closed' -> 'open'), amplifying
        -- the affected-PK footprint post-snapshot.
        UPDATE public.orders SET status = 'open' WHERE id = 1;
        "#,
    )?;
    Ok(())
}

/// A minimal abstraction over "something I can run a parameterless query on" so
/// the snapshot helpers work against both a [`Client`] and a [`Transaction`]
/// (the apply-time recompute runs inside the txn).
pub trait GenericQuery {
    /// Run a query with no bound parameters and return the rows.
    fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<postgres::Row>>;
}

impl GenericQuery for Client {
    fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<postgres::Row>> {
        Ok(Client::query(self, sql, params)?)
    }
}

impl GenericQuery for Transaction<'_> {
    fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<postgres::Row>> {
        Ok(Transaction::query(self, sql, params)?)
    }
}

/// Per-relation predicted affected map, for building a [`BlastRadius`]-shaped
/// view if a test wants one. (Kept tiny; the spike asserts on checksums + counts
/// directly.)
pub fn affected_map(snapshot: &AffectedSnapshot) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    m.insert(snapshot.relation.clone(), snapshot.total_rows);
    m
}
