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
//! - the AST + `pg_proc.provolatile` refusal vectors (SPEC §4): parenless
//!   `CURRENT_TIMESTAMP`/`LOCALTIMESTAMP`/`CURRENT_DATE`, a volatile UDF wrapping
//!   `clock_timestamp()`, and `random()`/`nextval()`/`timeofday()` nested in
//!   `CASE`/subquery → all **REFUSED** before execution (DB untouched); an
//!   immutable predicate (`id = 5`, `lower(owner)`) still **proceeds**.
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

// ---------------------------------------------------------------------------
//  REFUSE-VOLATILE — the AST + pg_proc.provolatile fix (red→green vectors)
// ---------------------------------------------------------------------------
//
//  Before the fix these predicates were *executed* in the rehearsal and stamped
//  `predicate_volatile:false`. Now each is REFUSED before any execution, and the
//  DB is byte-for-byte untouched.

/// One refusal vector: assert `statement` is REFUSED as volatile, never executed,
/// and the `accounts` balances are unchanged afterward. Shared by the cases.
fn assert_refused_volatile_untouched(client: &mut postgres::Client, statement: &str) {
    let before = account_balances(client);
    let clock = SystemClock::new();
    let proposal = propose(statement, None, &clock);
    let err = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).unwrap_err()
    };
    eprintln!("[refuse-volatile] {statement}\n  => {err}");
    assert!(
        matches!(err, DryRunError::Volatile(_)),
        "must be REFUSED as volatile, got {err:?}"
    );
    assert_eq!(
        account_balances(client),
        before,
        "DB must be untouched — the volatile predicate never ran"
    );
}

#[test]
fn parenless_special_keywords_are_refused() {
    let Some((admin, dbname, mut client)) = setup("kw_volatile") else {
        return;
    };
    // The headline bypass: parenless CURRENT_TIMESTAMP behind a cast.
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE owner < CURRENT_TIMESTAMP::text",
    );
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE owner < LOCALTIMESTAMP::text",
    );
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE balance > EXTRACT(epoch FROM CURRENT_DATE)",
    );
    drop_db(&admin, &dbname);
}

#[test]
fn volatile_udf_and_builtins_are_refused_via_provolatile() {
    let Some((admin, dbname, mut client)) = setup("udf_volatile") else {
        return;
    };
    // A genuinely volatile UDF wrapping clock_timestamp() — caught ONLY by
    // pg_proc.provolatile (it is on no name denylist).
    client
        .batch_execute(
            "CREATE FUNCTION public.evil_now() RETURNS timestamptz \
             LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp() $$;",
        )
        .expect("create volatile UDF");
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE owner > public.evil_now()::text",
    );
    // Volatile built-ins nested in CASE / subquery / cast — the AST walk reaches
    // them and provolatile='v' refuses.
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 \
         WHERE id = (CASE WHEN random() < 0.5 THEN 1 ELSE 2 END)",
    );
    assert_refused_volatile_untouched(
        &mut client,
        "DELETE FROM public.accounts \
         WHERE id IN (SELECT id FROM public.accounts WHERE balance > nextval('public.ticket_seq'))",
    );
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE owner < timeofday()",
    );
    drop_db(&admin, &dbname);
}

#[test]
fn immutable_predicate_is_not_over_refused() {
    let Some((admin, dbname, mut client)) = setup("immutable_ok") else {
        return;
    };
    // lower() is IMMUTABLE and `id = 5` has no function — neither must be refused.
    // They run, preview, and roll back (balances unchanged).
    let before = account_balances(&mut client);
    let clock = SystemClock::new();
    for statement in [
        "UPDATE public.accounts SET balance = 0 WHERE id = 5",
        "UPDATE public.accounts SET balance = 0 WHERE lower(owner) = 'owner-3'",
    ] {
        let proposal = propose(statement, None, &clock);
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        let br = dry_run(&proposal, &mut backend, &clock).unwrap_or_else(|e| {
            panic!("immutable predicate `{statement}` must proceed, got {e:?}")
        });
        assert!(
            !br.predicate_volatile,
            "an immutable/stable predicate must record predicate_volatile=false"
        );
    }
    // Still rolled back — no false-positive and no persistence.
    assert_eq!(account_balances(&mut client), before);
    drop_db(&admin, &dbname);
}

#[test]
fn catalog_less_special_forms_proceed_against_real_pg() {
    // RED→GREEN (re-review): `coalesce`/`nullif`/`greatest`/`least` parse as
    // `Expr::Function` but have NO `pg_proc` row, so the live `provolatile`
    // resolver returns `Unknown` for them. Before the allow-set the engine
    // fail-closed REFUSED this everyday SQL — a false positive. They are
    // deterministic by construction and must now PROCEED with
    // predicate_volatile=false. We assert against the real pg_proc lookup (the
    // resolver genuinely finds n=0 for these names) to prove it's the allow-set,
    // not a fixture, letting them through.
    let Some((admin, dbname, mut client)) = setup("special_forms_ok") else {
        return;
    };
    // Sanity-check the premise on this very cluster: these names have no pg_proc
    // row, so the catalog lookup alone would (and did) over-refuse them.
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM pg_proc \
             WHERE proname IN ('coalesce','nullif','greatest','least')",
            &[],
        )
        .expect("count special-form pg_proc rows")
        .get(0);
    assert_eq!(n, 0, "premise: special forms have no pg_proc row");

    let before = account_balances(&mut client);
    let clock = SystemClock::new();
    for statement in [
        "UPDATE public.accounts SET balance = 0 WHERE coalesce(owner, '') = 'owner-3'",
        "UPDATE public.accounts SET balance = 0 WHERE nullif(owner, '') IS NULL",
        "UPDATE public.accounts SET balance = 0 WHERE greatest(balance, 0) > 0",
        "UPDATE public.accounts SET balance = 0 WHERE least(balance, 0) < 10",
    ] {
        let proposal = propose(statement, None, &clock);
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        let br = dry_run(&proposal, &mut backend, &clock).unwrap_or_else(|e| {
            panic!("catalog-less special form `{statement}` must proceed, got {e:?}")
        });
        eprintln!(
            "[special-forms] {statement}\n  => PROCEEDS (predicate_volatile={})",
            br.predicate_volatile
        );
        assert!(
            !br.predicate_volatile,
            "a deterministic special form must record predicate_volatile=false"
        );
    }
    // No persistence — every dry-run rolled back.
    assert_eq!(account_balances(&mut client), before);
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  §4 qualified-bypass fix — public.coalesce(bigint) volatile UDF → REFUSED
// ===========================================================================

#[test]
fn schema_qualified_volatile_coalesce_udf_is_refused() {
    // RED→GREEN (re-review §4 qualified-bypass): before the fix the allow-set
    // matched `public.coalesce` on its bare name `coalesce`, skipping the
    // pg_proc.provolatile lookup and proceeding with a VOLATILE UDF. After the
    // fix a schema-qualified name is NOT short-circuited; it falls through to the
    // real pg_proc lookup which returns provolatile='v' → REFUSED.
    //
    // We create a VOLATILE `public.coalesce(bigint)` UDF and assert that
    // `WHERE public.coalesce(id::bigint) IS NOT NULL` is REFUSED before any
    // execution and the DB is untouched.
    let Some((admin, dbname, mut client)) = setup("qualified_coalesce_volatile") else {
        return;
    };
    client
        .batch_execute(
            "CREATE FUNCTION public.coalesce(bigint) RETURNS bigint \
             LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()::text::bigint $$;",
        )
        .expect("create volatile public.coalesce(bigint) UDF");

    // Prove the UDF really is volatile in pg_proc (the premise).
    let provolatile: String = client
        .query_one(
            "SELECT provolatile::text FROM pg_proc \
             WHERE proname = 'coalesce' AND pronamespace = 'public'::regnamespace",
            &[],
        )
        .expect("find public.coalesce in pg_proc")
        .get(0);
    assert_eq!(
        provolatile, "v",
        "premise: public.coalesce(bigint) is VOLATILE"
    );

    eprintln!(
        "[qualified-coalesce] public.coalesce provolatile={provolatile} — now asserting REFUSED"
    );

    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE public.coalesce(id::bigint) IS NOT NULL",
    );

    // Also assert fail-closed: a qualified call to a non-existent schema-qualified
    // function (schema exists but function does not) → REFUSED (Unknown).
    assert_refused_volatile_untouched(
        &mut client,
        "UPDATE public.accounts SET balance = 0 WHERE public.no_such_fn_xyz(id) IS NOT NULL",
    );

    drop_db(&admin, &dbname);
}

#[test]
fn bare_coalesce_still_proceeds_against_real_pg() {
    // Regression guard: bare (unqualified) `coalesce` must still PROCEED after
    // the qualified-bypass fix. The real pg_proc has no row for `coalesce` (it is
    // a SQL special form handled by the planner), so only the allow-set keeps it
    // from being fail-closed refused. This test proves the allow-set still fires
    // for the unqualified name.
    let Some((admin, dbname, mut client)) = setup("bare_coalesce_proceeds") else {
        return;
    };
    let before = account_balances(&mut client);
    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = 0 WHERE coalesce(owner, '') = 'owner-3'";
    let proposal = propose(statement, None, &clock);
    let inner_clock = SystemClock::new();
    let mut backend = PgRehearsal::new(&mut client, &inner_clock);
    let br = dry_run(&proposal, &mut backend, &clock)
        .unwrap_or_else(|e| panic!("bare coalesce must proceed after the fix, got {e:?}"));
    eprintln!(
        "[bare-coalesce] PROCEEDS (predicate_volatile={})",
        br.predicate_volatile
    );
    assert!(
        !br.predicate_volatile,
        "bare coalesce must record predicate_volatile=false"
    );
    // Rolled back — no persistence.
    assert_eq!(account_balances(&mut client), before);
    drop_db(&admin, &dbname);
}

#[test]
fn unknown_user_function_is_still_refused_fail_closed() {
    // A genuinely unknown / unresolvable user function in the predicate must
    // STILL be refused (fail-closed) — the allow-set must not weaken this. The
    // function does not exist in pg_proc, so the resolver returns Unknown and the
    // engine refuses before any execution.
    let Some((admin, dbname, mut client)) = setup("unknown_fn") else {
        return;
    };
    let before = account_balances(&mut client);
    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = 0 WHERE no_such_udf_xyz(owner) = 'x'";
    let proposal = propose(statement, None, &clock);
    let err = {
        let inner_clock = SystemClock::new();
        let mut backend = PgRehearsal::new(&mut client, &inner_clock);
        dry_run(&proposal, &mut backend, &clock).unwrap_err()
    };
    eprintln!("[unknown-fn] {statement}\n  => {err}");
    assert!(
        matches!(err, DryRunError::Volatile(_)),
        "an unknown user function must be REFUSED (fail-closed), got {err:?}"
    );
    assert_eq!(
        account_balances(&mut client),
        before,
        "DB must be untouched — the unknown-function predicate never ran"
    );
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
