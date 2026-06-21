//! Real-PG18 integration tests for the dry-run blast-radius engine (SPEC §4,
//! §10.1, §12). Env-gated behind `PG_BUMPERS_IT=1` so CI's fast `cargo test`
//! skips them. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test dry_run_it -- --nocapture
//! ```
//!
//! These drive the **same engine** the production path uses
//! ([`pgb_clone_orchestrator::dry_run`]) through the baseline in-txn
//! [`common::PgRehearsal`] (SPEC §12 `clone.provider: none`) against a throwaway
//! PG18 cluster on a dedicated port (never 5432). They assert:
//!
//! - **MARQUEE:** a no-`WHERE` `UPDATE … SET balance = 0` → the blast-radius
//!   record reports the correct row count + affected-PK set, and the primary
//!   rows are **UNCHANGED** afterward (the rehearsal rolled back).
//! - a `DELETE` cascade → child PKs + counts measured.
//! - a volatile predicate (`… WHERE … > now()`) → **REFUSED**, never executed.
//! - a PK-less table → **REFUSED** (no `ctid` fallback).
//! - the §10.1 record round-trips through serde; staleness / locks / wal_bytes
//!   are populated.

mod common;

use common::{
    account_balances, base_pgurl, create_seeded_db, current_wal_lsn, drop_db, it_enabled,
    row_count, staleness_lsn_bytes, PgRehearsal,
};
use pgb_clone_orchestrator::{dry_run, propose, DryRunError};
use pgb_core::{BlastRadius, LockMode, SystemClock};

/// Skip-guard: returns `None` (printing why) when the IT gate is unset so the
/// fast CI job stays DB-free.
fn setup(tag: &str) -> Option<(String, String, postgres::Client)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed dry-run test");
        return None;
    }
    Some(create_seeded_db(&base_pgurl(), tag))
}

// ===========================================================================
//  MARQUEE — no-WHERE UPDATE … SET balance = 0  (the demo core)
// ===========================================================================

#[test]
fn marquee_no_where_update_previews_and_leaves_primary_unchanged() {
    let Some((admin, dbname, mut client)) = setup("marquee") else {
        return;
    };

    // The golden pre-state: 8 accounts with distinct, non-zero balances.
    let before = account_balances(&mut client);
    eprintln!("[marquee] pre-state balances: {before:?}");
    assert_eq!(before.len(), 8);
    assert!(
        before.values().all(|&b| b != 0),
        "seed balances must be non-zero so SET balance=0 is observable"
    );

    // Propose + dry-run the no-WHERE blast.
    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = 0";
    let proposal = propose(statement, Some(8), &clock);
    let br = {
        // The rehearsal reads this clock to measure the forward op's wall-clock
        // duration_ms; production injects the same Clock seam.
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).expect("marquee dry-run must succeed")
    };

    eprintln!(
        "[marquee] BLAST-RADIUS PREVIEW:\n{}",
        serde_json::to_string_pretty(&br).unwrap()
    );

    // (1) Correct row count: a no-WHERE update touches ALL 8 rows.
    assert_eq!(br.affected.by_table["public.accounts"], 8);
    assert_eq!(br.affected.total_rows, 8);
    assert_eq!(
        proposal.expected_rows,
        Some(8),
        "matches the operator's expectation"
    );

    // (2) Affected-PK set is captured as a sha256 checksum.
    let checksum = &br.affected.pk_set_checksum["public.accounts"];
    assert!(checksum.starts_with("sha256:"), "got {checksum}");
    assert_eq!(checksum.len(), "sha256:".len() + 64);

    // (3) The trigger that fires per row is reported.
    assert!(
        br.triggers_fired
            .iter()
            .any(|t| t.name == "accounts_audit_aud"),
        "the AFTER UPDATE trigger must be reported as fired"
    );
    assert_eq!(br.triggers_fired[0].rows, 8);

    // (4) Reversible UPDATE → PREIMAGE_UPSERT inverse, deterministic predicate.
    assert!(br.reversible);
    assert_eq!(br.inverse_kind, pgb_core::InverseKind::PreimageUpsert);
    assert!(!br.predicate_volatile);

    // (5) Locks: the in-txn baseline took at least RowExclusiveLock (§12); it was
    // held during the rehearsal and released by the ROLLBACK.
    assert!(
        br.locks
            .iter()
            .any(|l| l.mode == LockMode::RowExclusiveLock),
        "expected a RowExclusiveLock on the target; got {:?}",
        br.locks
    );
    assert_eq!(br.max_lock_mode, br.computed_max_lock_mode().unwrap());

    // (6) §10.1 record round-trips through serde.
    let json = serde_json::to_string(&br).unwrap();
    let reparsed: BlastRadius = serde_json::from_str(&json).unwrap();
    assert_eq!(br, reparsed, "blast-radius record must round-trip");

    // ===== THE GUARANTEE: the primary rows are UNCHANGED (rolled back). =====
    let after = account_balances(&mut client);
    eprintln!("[marquee] post-dry-run balances: {after:?}");
    assert_eq!(
        before, after,
        "dry-run must NOT persist: balances must be byte-for-byte unchanged"
    );
    assert!(
        after.values().all(|&b| b != 0),
        "NO balance may have been zeroed — the rehearsal rolled back"
    );

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  DELETE cascade — child PKs + counts measured
// ===========================================================================

#[test]
fn delete_cascade_measures_child_pk_set() {
    let Some((admin, dbname, mut client)) = setup("cascade") else {
        return;
    };

    let accounts_before = row_count(&mut client, "public.accounts");
    let entries_before = row_count(&mut client, "public.entries");
    assert_eq!(accounts_before, 8);
    assert_eq!(entries_before, 16);

    let clock = SystemClock::new();
    // Delete the even-id accounts (ids 2,4,6,8 = 4 parents → 8 cascade children).
    let statement = "DELETE FROM public.accounts WHERE id % 2 = 0";
    let proposal = propose(statement, Some(4), &clock);
    let br = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).expect("cascade dry-run must succeed")
    };

    eprintln!(
        "[cascade] BLAST-RADIUS PREVIEW:\n{}",
        serde_json::to_string_pretty(&br).unwrap()
    );

    assert_eq!(br.affected.by_table["public.accounts"], 4, "4 parent rows");
    assert_eq!(
        br.affected.cascade_by_table["public.entries"], 8,
        "each deleted account cascades to its 2 entries → 8 children"
    );
    assert_eq!(br.affected.total_rows, 12, "4 parents + 8 cascade children");
    assert!(br.affected.pk_set_checksum.contains_key("public.entries"));
    assert_eq!(br.inverse_kind, pgb_core::InverseKind::Insert);

    // Primary unchanged — rolled back.
    assert_eq!(row_count(&mut client, "public.accounts"), 8);
    assert_eq!(row_count(&mut client, "public.entries"), 16);

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  REFUSALS — volatile predicate + PK-less table (fail-closed, never executed)
// ===========================================================================

#[test]
fn volatile_predicate_is_refused_and_never_executed() {
    let Some((admin, dbname, mut client)) = setup("volatile") else {
        return;
    };

    let before = account_balances(&mut client);
    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = 0 WHERE balance > now()";
    let proposal = propose(statement, None, &clock);

    let err = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).unwrap_err()
    };
    eprintln!("[volatile] refused as expected: {err}");
    assert!(
        matches!(err, DryRunError::Volatile(_)),
        "now() predicate must be REFUSED, got {err:?}"
    );

    // The DB is untouched (the statement never ran).
    assert_eq!(account_balances(&mut client), before);
    drop_db(&admin, &dbname);
}

#[test]
fn pk_less_table_is_refused_no_ctid_fallback() {
    let Some((admin, dbname, mut client)) = setup("pkless") else {
        return;
    };

    let before = row_count(&mut client, "public.event_log");
    assert_eq!(before, 1);

    let clock = SystemClock::new();
    // event_log has no primary key / replica identity.
    let statement = "DELETE FROM public.event_log WHERE kind = 'seed'";
    let proposal = propose(statement, None, &clock);

    let err = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).unwrap_err()
    };
    eprintln!("[pkless] refused as expected: {err}");
    match err {
        DryRunError::PkLess(rel) => assert_eq!(rel, "public.event_log"),
        other => panic!("expected PkLess refusal (no ctid fallback), got {other:?}"),
    }

    // Untouched.
    assert_eq!(row_count(&mut client, "public.event_log"), before);
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  Field population — staleness / wal_bytes / clone_lsn are real
// ===========================================================================

#[test]
fn record_fields_are_populated_from_real_pg() {
    let Some((admin, dbname, mut client)) = setup("fields") else {
        return;
    };

    // Capture a snapshot LSN, then burn WAL so staleness is > 0. We write a
    // chunky table in its own statements so the WAL insert pointer advances well
    // past the snapshot (synchronous_commit=off only delays the *flush* pointer,
    // not pg_current_wal_lsn's insert pointer).
    let snapshot = current_wal_lsn(&mut client).unwrap();
    client
        .batch_execute("CREATE TABLE public._wal_burn(x bigint)")
        .unwrap();
    for _ in 0..5 {
        client
            .execute(
                "INSERT INTO public._wal_burn SELECT g FROM generate_series(1, 50000) g",
                &[],
            )
            .unwrap();
    }
    let staleness = staleness_lsn_bytes(&mut client, &snapshot).unwrap();
    eprintln!("[fields] staleness since snapshot = {staleness} bytes");
    assert!(staleness > 0, "burning WAL must move the LSN");

    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = balance + 1";
    let proposal = propose(statement, None, &clock);
    let br = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).expect("dry-run")
    };

    eprintln!(
        "[fields] clone_lsn={} wal_bytes={} duration_ms={} locks={}",
        br.clone_lsn,
        br.wal_bytes,
        br.duration_ms,
        br.locks.len()
    );
    // clone_lsn is a real LSN literal.
    assert!(br.clone_lsn.contains('/'), "clone_lsn looks like an LSN");
    // The forward UPDATE generated WAL (heap + the trigger's audit inserts).
    assert!(br.wal_bytes > 0, "an 8-row UPDATE must generate WAL");
    // At least one lock was observed on the target during the rehearsal.
    assert!(!br.locks.is_empty(), "locks must be measured from pg_locks");

    drop_db(&admin, &dbname);
}
