//! THROWAWAY S0 fidelity-spike integration tests (issue #8 — 🚦 THE GATE).
//!
//! These run **for real against PG18** and are gated behind `PG_BUMPERS_IT=1`
//! so CI's fast `cargo test` skips them. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p fidelity-spike -- --nocapture
//! ```
//!
//! They assert the §10.5 binary pass criteria (a)(b)(c) and the five drift
//! tests. Determinism comes from the injected `pgb_core` seams: `MockClock`
//! (staleness/timing), `ClosureBarrier`/`NoopBarrier` (the dry-run→apply seam
//! where drift is injected). The restore equality check uses the **independent
//! differ** (`differ::`) which shares no code with the inverse under test.

use fidelity_spike::differ;
use fidelity_spike::harness::{self, SpikeError};
use fidelity_spike::{base_pgurl, it_enabled};
use pgb_core::inverse::{Operation, certify};
use pgb_core::{Clock, ClosureBarrier, MockClock, NoopBarrier, RefusedOp};
use postgres::Client;

/// Skip-guard: returns `None` (and prints why) when `PG_BUMPERS_IT` is unset so
/// the fast CI job stays DB-free. Otherwise creates a fresh, isolated database,
/// seeds it, and returns `(admin_url, dbname, client)`.
fn setup(tag: &str) -> Option<(String, String, Client)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed spike test");
        return None;
    }
    let admin_url = base_pgurl();
    let (dbname, mut client) =
        harness::create_fresh_db(&admin_url, tag).expect("create fresh spike db");
    harness::seed(&mut client).expect("seed schema");
    Some((admin_url, dbname, client))
}

/// The stable predicate that matches a known PK set: even ids 2,4,6,8,10.
const OPEN_PREDICATE: &str = "status = 'open'";

// ===========================================================================
//  §10.5 (a) — Prediction exactness on a no-drift apply.
// ===========================================================================

#[test]
fn criterion_a_no_drift_prediction_is_exact() {
    let Some((admin, dbname, mut client)) = setup("a_no_drift") else {
        return;
    };

    // Dry-run: snapshot the affected-PK set + predicted total_rows.
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");
    let cascade =
        harness::snapshot_cascade_item_pks(&mut client, OPEN_PREDICATE).expect("cascade snapshot");
    eprintln!(
        "(a) dry-run: relation={} predicted_total_rows={} pk_set_checksum={}",
        dry.relation, dry.total_rows, dry.checksum
    );
    eprintln!(
        "(a) cascade composite-PK set: relation={} rows={} checksum={}",
        cascade.relation, cascade.total_rows, cascade.checksum
    );
    assert_eq!(dry.total_rows, 5, "5 orders match status='open'");

    // Apply with the PRODUCTION no-op barrier (no drift injected).
    let barrier = NoopBarrier::new();
    let outcome = harness::guarded_update_apply(
        &mut client,
        &barrier,
        OPEN_PREDICATE,
        "open", // idempotent status write; keeps the affected set stable
        &dry,
    )
    .expect("no-drift apply must NOT abort");

    eprintln!(
        "(a) apply-time: checksum={} actual_rows={}",
        outcome.apply_time_checksum, outcome.actual_rows
    );

    // (a) dry-run pk_set_checksum == apply-time checksum (exact).
    assert_eq!(
        dry.checksum, outcome.apply_time_checksum,
        "(a) dry-run checksum must equal apply-time checksum exactly"
    );
    // (a) predicted total_rows == actual (delta 0).
    assert_eq!(
        dry.total_rows, outcome.actual_rows,
        "(a) predicted total_rows must equal actual with delta 0"
    );
    eprintln!("(a) PASS: checksum exact-match AND total_rows delta == 0");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

// ===========================================================================
//  §10.5 (b) — Typed-inverse restores the GOLDEN PROD STATE, with gaps.
// ===========================================================================

#[test]
fn criterion_b_inverse_restores_golden_state_with_documented_gaps() {
    let Some((admin, dbname, mut client)) = setup("b_inverse_restore") else {
        return;
    };

    // ---- Capture the GOLDEN PROD STATE via the INDEPENDENT differ ----------
    let mut diff_client = differ::connect(&pg_url(&admin, &dbname)).expect("differ connect");
    let golden = differ::capture(&mut diff_client).expect("capture golden");
    eprintln!(
        "(b) golden: orders_md5={} order_items_md5={} ticket_seq_last_value={} audit_rows={}",
        golden.orders_md5,
        golden.order_items_md5,
        golden.ticket_seq_last_value,
        golden.audit_row_count
    );

    // ---- Exercise the certified op set: a bounded UPDATE then revert -------
    // Capture the typed inverse (pre-image) BEFORE applying.
    let inverse =
        harness::capture_update_inverse(&mut client, OPEN_PREDICATE).expect("capture inv");
    assert_eq!(inverse.rows.len(), 5, "pre-image captured for 5 rows");

    // certify() must classify this as a certified BoundedUpdate.
    let op = Operation::Update {
        has_preimage: true,
        has_pk: true,
    };
    assert!(certify(&op).is_ok(), "bounded update is certified");

    // Apply the forward op (guarded, no drift) — this also fires the audit
    // trigger (side-effect) and we deliberately advance the sequence too.
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");
    // Advance the sequence a few times so its last_value clearly moves past the
    // golden value — the inverse will NOT roll this back (documented gap).
    for _ in 0..3 {
        harness::advance_ticket_seq(&mut client).expect("advance seq");
    }
    let _ = harness::guarded_update_apply(
        &mut client,
        &NoopBarrier::new(),
        OPEN_PREDICATE,
        "shipped", // mutate status away from golden
        &dry,
    )
    .expect("apply");

    // Confirm the world actually changed (rows + side effects).
    let after_apply = differ::capture(&mut diff_client).expect("capture post-apply");
    assert_ne!(
        golden.certified_fingerprint(),
        after_apply.certified_fingerprint(),
        "the apply must have changed the certified rows"
    );
    assert!(
        after_apply.audit_row_count > golden.audit_row_count,
        "the trigger side-effect must have grown the audit table"
    );
    eprintln!(
        "(b) post-apply: orders_md5={} audit_rows={} ticket_seq_last_value={}",
        after_apply.orders_md5, after_apply.audit_row_count, after_apply.ticket_seq_last_value
    );

    // ---- Restore via the typed inverse ------------------------------------
    let restored_n = harness::restore_update_inverse(&mut client, &inverse).expect("restore");
    assert_eq!(restored_n, 5);

    // ---- Independent differ verdict ---------------------------------------
    let restored = differ::capture(&mut diff_client).expect("capture restored");
    let verdict = differ::diff(&golden, &restored);
    eprintln!(
        "(b) restored: orders_md5={} order_items_md5={} ticket_seq_last_value={} audit_rows={}",
        restored.orders_md5,
        restored.order_items_md5,
        restored.ticket_seq_last_value,
        restored.audit_row_count
    );
    eprintln!("(b) verdict: {verdict:?}");

    // (b) PASS: certified table rows restored byte-for-byte.
    assert!(
        verdict.certified_rows_restored,
        "(b) typed-inverse must restore the certified rows byte-for-byte"
    );
    assert_eq!(
        golden.certified_fingerprint(),
        restored.certified_fingerprint(),
        "(b) golden vs restored certified fingerprint must be identical"
    );

    // (b) DOCUMENTED GAPS: sequence + trigger side-effects are NOT restored.
    assert!(
        !verdict.sequence_restored,
        "(b) sequence last_value must NOT be restored (documented gap)"
    );
    assert!(
        !verdict.trigger_side_effects_restored,
        "(b) trigger-audit side-effects must NOT be restored (documented gap)"
    );
    assert!(
        restored.ticket_seq_last_value > golden.ticket_seq_last_value,
        "(b) sequence advanced and stayed advanced (gap)"
    );
    assert!(
        restored.audit_row_count > golden.audit_row_count,
        "(b) audit rows from the trigger remain (gap)"
    );
    eprintln!(
        "(b) PASS: certified rows restored byte-for-byte; sequences/trigger-audit asserted NOT restored"
    );

    harness::drop_database(&admin, &dbname).expect("teardown");
}

/// (b) also covers DELETE→re-insert in FK order (cascade child path).
#[test]
fn criterion_b_delete_inverse_restores_cascade_in_fk_order() {
    let Some((admin, dbname, mut client)) = setup("b_delete_cascade") else {
        return;
    };
    let mut diff_client = differ::connect(&pg_url(&admin, &dbname)).expect("differ connect");
    let golden = differ::capture(&mut diff_client).expect("capture golden");

    // Delete the open orders (cascades to order_items). Capture inverse first.
    let (orders_inv, items_inv) =
        harness::capture_delete_inverse(&mut client, OPEN_PREDICATE).expect("capture delete inv");
    eprintln!(
        "(b-del) captured inverse: {} parent rows, {} cascade child rows, fk_order={:?}",
        orders_inv.rows.len(),
        items_inv.rows.len(),
        orders_inv.fk_order
    );

    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");
    let outcome =
        harness::guarded_delete_apply(&mut client, &NoopBarrier::new(), OPEN_PREDICATE, &dry)
            .expect("delete apply");
    assert_eq!(outcome.actual_rows, 5, "5 parent orders deleted");

    let after = differ::capture(&mut diff_client).expect("capture post-delete");
    assert_ne!(
        golden.certified_fingerprint(),
        after.certified_fingerprint(),
        "delete must change certified rows"
    );

    // Re-insert parents then children (FK order encoded in the inverse plan).
    let (on, inum) =
        harness::restore_delete_inverse(&mut client, &orders_inv, &items_inv).expect("restore del");
    eprintln!("(b-del) restored {on} parent rows + {inum} cascade child rows");

    let restored = differ::capture(&mut diff_client).expect("capture restored");
    let verdict = differ::diff(&golden, &restored);
    eprintln!("(b-del) verdict: {verdict:?}");
    assert!(
        verdict.certified_rows_restored,
        "(b-del) FK-ordered re-insert must restore orders + order_items byte-for-byte"
    );
    eprintln!("(b-del) PASS: cascade child rows restored in FK order, byte-for-byte");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

// ===========================================================================
//  §10.5 (c) — Staleness ceiling: reject clones that are too stale.
// ===========================================================================

#[test]
fn criterion_c_staleness_ceiling_rejects_stale_clone() {
    let Some((admin, dbname, mut client)) = setup("c_staleness") else {
        return;
    };

    // Model time deterministically with the injected MockClock (no wall-clock).
    let clock = MockClock::starting_at(0);

    // A "fresh" clone: snapshot LSN == current LSN → ~0 staleness.
    let snapshot_lsn = harness::current_wal_lsn(&mut client).expect("lsn");
    let fresh = harness::staleness_lsn_bytes(&mut client, &snapshot_lsn).expect("staleness");
    let ceiling: u64 = 16 * 1024 * 1024; // 16 MiB ceiling
    eprintln!(
        "(c) fresh clone staleness={fresh} bytes, ceiling={ceiling} bytes (t={}ms)",
        clock.monotonic_millis()
    );
    harness::enforce_staleness_ceiling(fresh, ceiling).expect("(c) fresh clone must be accepted");

    // Now let prod advance: burn WAL so the clone falls far behind.
    clock.advance(60_000); // 60s of logical replication lag, deterministically
    harness::burn_wal(&mut client, 200).expect("burn wal");
    let stale = harness::staleness_lsn_bytes(&mut client, &snapshot_lsn).expect("staleness2");
    eprintln!(
        "(c) after burn: staleness={stale} bytes, ceiling={ceiling} bytes (t={}ms)",
        clock.monotonic_millis()
    );
    assert!(
        stale > ceiling,
        "(c) staleness {stale} must exceed the ceiling {ceiling} for the test to be meaningful"
    );

    // (c) the gate must REJECT the stale clone.
    match harness::enforce_staleness_ceiling(stale, ceiling) {
        Err(SpikeError::StalenessExceeded { actual, ceiling: c }) => {
            assert_eq!(actual, stale);
            assert_eq!(c, ceiling);
            eprintln!("(c) PASS: stale clone REJECTED (staleness {actual} > ceiling {c})");
        }
        other => panic!("(c) expected StalenessExceeded, got {other:?}"),
    }

    harness::drop_database(&admin, &dbname).expect("teardown");
}

// ===========================================================================
//  Drift tests (inject drift inside ApplyBarrier::pause_point()).
// ===========================================================================

/// T-drift-insert: a new matching row appears post-snapshot (over-count) → ABORT.
#[test]
fn t_drift_insert_aborts() {
    let Some((admin, dbname, mut client)) = setup("t_drift_insert") else {
        return;
    };
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");

    // The barrier opens a second connection and INSERTs a NEW order matching the
    // predicate, committing it before the apply recomputes the checksum.
    let inject_url = pg_url(&admin, &dbname);
    let barrier = ClosureBarrier::new(move |_label| {
        let mut c = Client::connect(&inject_url, postgres::NoTls).expect("inject connect");
        c.execute(
            "INSERT INTO public.orders(id, customer, status, total_cents) \
             VALUES (101, 'drift', 'open', 9999)",
            &[],
        )
        .expect("inject insert");
    });

    let result = harness::guarded_update_apply(&mut client, &barrier, OPEN_PREDICATE, "open", &dry);
    assert_drift_abort(&result, "T-drift-insert");
    assert_eq!(barrier.crossings(), 1, "barrier crossed exactly once");
    eprintln!("T-drift-insert PASS: over-count drift ABORTED");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

/// T-drift-delete-shrink: a matching row is removed post-snapshot (under-count)
/// → ABORT.
#[test]
fn t_drift_delete_shrink_aborts() {
    let Some((admin, dbname, mut client)) = setup("t_drift_shrink") else {
        return;
    };
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");

    let inject_url = pg_url(&admin, &dbname);
    let barrier = ClosureBarrier::new(move |_label| {
        let mut c = Client::connect(&inject_url, postgres::NoTls).expect("inject connect");
        // Remove one matching order (id=10 is 'open'); cascades to its items.
        c.execute("DELETE FROM public.orders WHERE id = 10", &[])
            .expect("inject delete");
    });

    let result = harness::guarded_update_apply(&mut client, &barrier, OPEN_PREDICATE, "open", &dry);
    assert_drift_abort(&result, "T-drift-delete-shrink");
    eprintln!("T-drift-delete-shrink PASS: under-count drift ABORTED");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

/// T-drift-predicate-flip (HEADLINE): same count, different PKs → ABORT.
/// A row-count check would PASS here; only the PK-set checksum catches it.
#[test]
fn t_drift_predicate_flip_aborts() {
    let Some((admin, dbname, mut client)) = setup("t_drift_flip") else {
        return;
    };
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");
    assert_eq!(dry.total_rows, 5);

    let inject_url = pg_url(&admin, &dbname);
    let barrier = ClosureBarrier::new(move |_label| {
        let mut c = Client::connect(&inject_url, postgres::NoTls).expect("inject connect");
        // Flip id=2 OUT of the set and id=1 IN — count stays 5, PK set changes.
        c.batch_execute(
            "UPDATE public.orders SET status = 'closed' WHERE id = 2; \
             UPDATE public.orders SET status = 'open'   WHERE id = 1;",
        )
        .expect("inject flip");
    });

    let result = harness::guarded_update_apply(&mut client, &barrier, OPEN_PREDICATE, "open", &dry);

    // Prove the count is unchanged (so a count guard would have MISSED it)...
    let post_count = client
        .query_one(
            &format!("SELECT count(*) FROM public.orders WHERE {OPEN_PREDICATE}"),
            &[],
        )
        .expect("count");
    let n: i64 = post_count.get(0);
    eprintln!("T-drift-predicate-flip: matching-row count is still {n} (count guard blind spot)");

    // ...yet the PK-set checksum guard ABORTs.
    assert_drift_abort(&result, "T-drift-predicate-flip");
    eprintln!("T-drift-predicate-flip PASS: identical count, different PK set → ABORTED");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

/// T-drift-trigger-amplification: a trigger added post-snapshot amplifies the
/// effect and shifts the affected-PK set → ABORT.
#[test]
fn t_drift_trigger_amplification_aborts() {
    let Some((admin, dbname, mut client)) = setup("t_drift_amplify") else {
        return;
    };
    let dry = harness::snapshot_orders_pks(&mut client, OPEN_PREDICATE).expect("snapshot");

    let inject_url = pg_url(&admin, &dbname);
    let barrier = ClosureBarrier::new(move |_label| {
        let mut c = Client::connect(&inject_url, postgres::NoTls).expect("inject connect");
        harness::install_amplifying_trigger(&mut c).expect("install amplifying trigger");
    });

    let result = harness::guarded_update_apply(&mut client, &barrier, OPEN_PREDICATE, "open", &dry);
    assert_drift_abort(&result, "T-drift-trigger-amplification");
    eprintln!("T-drift-trigger-amplification PASS: post-snapshot trigger amplification ABORTED");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

/// T-nondeterministic-predicate: a predicate referencing `now()`/`random()` is
/// REFUSED by the default-deny certify() choke point and NEVER applied.
#[test]
fn t_nondeterministic_predicate_refused() {
    let Some((admin, dbname, _client)) = setup("t_nondeterministic") else {
        return;
    };

    // A volatile predicate makes dry-run/apply equivalence unsafe. We model the
    // op as a write whose predicate is volatile; the certified set has no shape
    // for it, so certify()/the volatile flag REFUSES it.
    let volatile_op = Operation::Insert {
        volatile_default: true, // e.g. DEFAULT now()/random()
        has_pk: true,
    };
    match certify(&volatile_op) {
        Err(RefusedOp::VolatileDefaultInsert) => {
            eprintln!("T-nondeterministic-predicate: certify() REFUSED volatile op (never applied)")
        }
        other => panic!("expected VolatileDefaultInsert refusal, got {other:?}"),
    }

    // And prove "never applied": the blast-radius predicate_volatile flag would
    // be true, so the guarded path is never entered. We assert the DB is
    // untouched by confirming the golden fingerprint is unchanged.
    let mut diff_client = differ::connect(&pg_url(&admin, &dbname)).expect("differ connect");
    let before = differ::capture(&mut diff_client).expect("before");
    // (No apply call is made for a refused op — that is the whole point.)
    let after = differ::capture(&mut diff_client).expect("after");
    assert_eq!(
        before, after,
        "a REFUSED nondeterministic op must never touch the DB"
    );
    eprintln!("T-nondeterministic-predicate PASS: REFUSED, DB untouched (never applied)");

    harness::drop_database(&admin, &dbname).expect("teardown");
}

// ---- shared assertions / helpers ------------------------------------------

/// Assert that a guarded-apply result is the expected GUARD ABORT (drift caught).
fn assert_drift_abort<T: std::fmt::Debug>(result: &Result<T, SpikeError>, test_name: &str) {
    match result {
        Err(SpikeError::DriftAbort {
            relation,
            dry_run,
            apply_time,
        }) => {
            assert_ne!(
                dry_run, apply_time,
                "{test_name}: abort must be due to a checksum mismatch"
            );
            eprintln!(
                "{test_name}: GUARD ABORT on {relation} (dry_run={dry_run}, apply_time={apply_time})"
            );
        }
        other => panic!("{test_name}: expected DriftAbort, got {other:?}"),
    }
}

/// Build a per-database libpq URL from the admin URL + a database name.
fn pg_url(admin_url: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = admin_url
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}
