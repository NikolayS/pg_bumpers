//! Real-PG18 integration tests for the **production grant-gated apply path**
//! (SPEC §14.3, §10.1, §12.2; #66, #45). Env-gated behind `PG_BUMPERS_IT=1`. Run:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test apply_grant_it -- --nocapture
//! ```
//!
//! These drive [`pgb_clone_orchestrator::guarded_apply_with_grant`] — the
//! production caller that **bridges a `PolicyConfig` and consumes the §14.3 signed
//! grant at the real apply** — against a throwaway PG18 cluster on a dedicated
//! port (NEVER 5432). They prove, end-to-end through the real apply path (not the
//! CLI demo):
//!
//! - a CLI-minted grant **verifies at the real apply** and the bounded write
//!   commits **reversibly** (the typed-inverse restores the pre-state);
//! - the **5 T-grant-\* tamper cases** all ABORT with **no mutation**:
//!   sql-swap / param-swap / cross-session / proposal-swap → BindingMismatch;
//!   nonce reuse → ReplayedNonce; past-expiry → Expired;
//! - **no grant** (attacker-minted / wrong key) ⇒ **fail-closed abort**;
//! - the **apply-time MAGNITUDE-drift** case (EPIC #91 PR-B): concurrent inserts
//!   swell `id % 2 = 0` past the approved cap ⇒ **`CapExceeded` abort** (the cap is
//!   the absolute-magnitude anchor that replaced the dropped exact-PK-set checksum);
//!   a within-cap headroom write still commits + reverts;
//! - a join-correlated `UPDATE … FROM` is **REFUSED before the txn opens** by the
//!   self-determined-predicate gate (the carried PR-A finding);
//! - the surviving §4 guards still hold under the grant path (RR isolation +
//!   pre-image seam fire on barrier-injected drift; the reversible apply reverts).
//!
//! On every abort path we re-read the primary and assert it is byte-for-byte
//! unchanged.

mod common;

use std::collections::BTreeMap;

use common::{base_pgurl, create_seeded_db, drop_db, it_enabled};
use ed25519_dalek::{SigningKey, VerifyingKey};
// The apply + revert conns are the LIFTED library impls (one source of truth,
// shared with pgb-applyd) — not a test-local copy.
use pgb_clone_orchestrator::apply::ApplyError;
use pgb_clone_orchestrator::{
    GrantedApplyError, LiveRequest, PgApplyConn, PgRevertConn, RevertReport, WriteKind,
    guarded_apply_with_grant, revert,
};
use pgb_core::{
    BlastRadius, Clock, InverseKind, InversePlan, MockClock, NoopBarrier, OpCounts, PkChecksum,
    PkSetBuilder, PkTuple, PkValue, SystemClock, WriteCap,
};
use pgb_policy::{
    AutonomyLevel, CloneConfig, CloneProvider, GrantBinding, GrantError, GrantToken,
    InMemoryNonceStore, NonceStore, PitrConfig as PolicyPitr, PolicyConfig, RoleBudget, RolePolicy,
    WindowBudget,
};
use postgres::{Client, NoTls};
use rand_core::OsRng;

/// Skip-guard.
fn setup(tag: &str) -> Option<(String, String, Client)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed grant-apply test");
        return None;
    }
    Some(create_seeded_db(&base_pgurl(), tag))
}

const EVEN_WHERE: &str = "id % 2 = 0";
const REL: &str = "public.accounts";

// ===========================================================================
//  Helpers: build the blast radius + the live request + sign the grant.
// ===========================================================================

fn url_for(admin: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = admin
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

fn read_accounts(url: &str) -> BTreeMap<i32, (String, i64)> {
    let mut c = Client::connect(url, NoTls).expect("read connect");
    c.query(
        "SELECT id, owner, balance FROM public.accounts ORDER BY id",
        &[],
    )
    .expect("read accounts")
    .iter()
    .map(|r| {
        (
            r.get::<_, i32>(0),
            (r.get::<_, String>(1), r.get::<_, i64>(2)),
        )
    })
    .collect()
}

/// Measure the full per-relation footprint by rehearsing `forward_sql` in a
/// rolled-back txn (the symmetric pg_stat_xact_* measure the dry-run records).
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

/// Snapshot the `accounts` affected-PK-set checksum for `where_sql` (dry-run side).
fn target_checksum(url: &str, where_sql: &str) -> PkChecksum {
    let mut c = Client::connect(url, NoTls).expect("checksum connect");
    let rows = c
        .query(
            &format!("SELECT id FROM public.accounts WHERE {where_sql} ORDER BY id"),
            &[],
        )
        .expect("checksum select");
    let mut b = PkSetBuilder::for_relation("public.accounts");
    for row in &rows {
        let id: i32 = row.get(0);
        b.push(PkTuple::single(PkValue::Int(id as i64))).unwrap();
    }
    b.finalize().unwrap()
}

/// Build a [`BlastRadius`] UPDATE grant for `accounts` over `where_sql`, with the
/// full effect_by_table footprint MEASURED (so the apply does not flag the audit
/// trigger writes as drift).
fn blast_radius_for(
    proposal_id: &str,
    url: &str,
    where_sql: &str,
    forward_sql: &str,
) -> BlastRadius {
    use pgb_core::LockMode;
    use pgb_core::blast_radius::Affected;
    let cs = target_checksum(url, where_sql);
    let mut c = Client::connect(url, NoTls).expect("count connect");
    let n: i64 = c
        .query_one(
            &format!("SELECT count(*) FROM public.accounts WHERE {where_sql}"),
            &[],
        )
        .unwrap()
        .get(0);
    let n = n as u64;
    let mut pk_set_checksum = BTreeMap::new();
    pk_set_checksum.insert("public.accounts".to_string(), cs.as_prefixed());
    let mut by_table = BTreeMap::new();
    by_table.insert("public.accounts".to_string(), n);
    let effect_by_table = measure_full_effect(url, forward_sql);
    BlastRadius {
        proposal_id: proposal_id.to_string(),
        clone_lsn: "3A/7F00C8".into(),
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
        duration_ms: 50,
        wal_bytes: 0,
        constraint_violations: vec![],
        reversible: true,
        inverse_kind: InverseKind::PreimageUpsert,
        predicate_volatile: false,
    }
}

fn keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

const FORWARD: &str = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

fn live_for(proposal_id: &str) -> LiveRequest {
    LiveRequest {
        statement_text: FORWARD.to_string(),
        normalized_params: vec![],
        role: "app_writer".to_string(),
        session_id: "sess-prod".to_string(),
        proposal_id: proposal_id.to_string(),
    }
}

/// A generous default cap (EPIC #91 PR-B) for the tamper tests (they exercise the
/// binding, not the cap; the cap-bound tests pass an explicit cap).
fn test_cap() -> WriteCap {
    WriteCap::new(1000, 50_000_000)
}

/// Sign the §14.3 grant over the live request + blast radius + the approved cap (the
/// honest grant the approver would mint via the CLI), with `nonce` + `expiry`.
fn sign_grant(
    sk: &SigningKey,
    live: &LiveRequest,
    br: &BlastRadius,
    nonce: &str,
    expiry: u64,
) -> GrantToken {
    sign_grant_cap(sk, live, br, nonce, expiry, test_cap())
}

/// Like [`sign_grant`] but with an explicit cap (the cap-bound / cap-fires tests).
fn sign_grant_cap(
    sk: &SigningKey,
    live: &LiveRequest,
    br: &BlastRadius,
    nonce: &str,
    expiry: u64,
    cap: WriteCap,
) -> GrantToken {
    let binding = GrantBinding {
        statement_text: live.statement_text.clone(),
        normalized_params: live.normalized_params.clone(),
        role: live.role.clone(),
        session_id: live.session_id.clone(),
        proposal_id: live.proposal_id.clone(),
        dry_run_lsn: br.clone_lsn.clone(),
        cap,
        nonce: nonce.to_string(),
        expiry_unix_millis: expiry,
    };
    GrantToken::sign(binding, sk)
}

fn policy() -> PolicyConfig {
    let mut roles = BTreeMap::new();
    roles.insert(
        "app_writer".to_string(),
        RolePolicy {
            select_whitelist: vec![],
            budget: RoleBudget {
                max_bytes: 1000,
                max_rows: 100,
                max_plan_cost: 1000.0,
                max_plan_rows: 1000,
                per_window: WindowBudget {
                    window_secs: 60,
                    max_bytes: 10_000,
                    max_rows: 1000,
                },
            },
            autonomy: AutonomyLevel::L1,
        },
    );
    PolicyConfig {
        version: 1,
        roles,
        replica: Default::default(),
        clone: CloneConfig {
            provider: CloneProvider::None,
        },
        pitr: PolicyPitr { enabled: false },
        approvers: Default::default(),
        audit: Default::default(),
    }
}

// ===========================================================================
//  (1) HAPPY PATH — a CLI-minted grant verifies at the REAL apply; the bounded
//      write commits and REVERTS (reversibility proven end-to-end).
// ===========================================================================

#[test]
fn valid_grant_verifies_at_real_apply_and_write_reverts() {
    let Some((admin, dbname, _c)) = setup("grant_commit_revert") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let (sk, vk) = keypair();
    let br = blast_radius_for("p-ok", &url, EVEN_WHERE, FORWARD);
    let live = live_for("p-ok");
    let pol = policy();
    let mut nonces = InMemoryNonceStore::new();
    let clock = SystemClock::new();
    // This test runs on the real wall clock; the grant TTL must be relative to now
    // (not the MockClock-relative 10_000 the tamper cases use), so the grant is
    // unexpired when verified.
    let expiry = clock.now_unix_millis() + 60_000;
    let grant = sign_grant(&sk, &live, &br, "nonce-ok", expiry);

    let inverse: InversePlan = {
        let mut client = Client::connect(&url, NoTls).expect("apply connect");
        let mut conn = PgApplyConn::new(&mut client, FORWARD, EVEN_WHERE);
        let (applied, bridged) = guarded_apply_with_grant(
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            WriteKind::Update,
            REL,
            &br,
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .expect("a valid CLI-minted grant must verify at the real apply + commit");
        assert_eq!(applied.rows_written, 4);
        assert_eq!(bridged.provider, pgb_clone_orchestrator::ProviderKind::None);
        eprintln!(
            "[grant-commit] PASS: grant verified at real apply; {} rows written, fence={:?}",
            applied.rows_written, applied.fence
        );
        applied.inverse
    };

    // The bounded write committed: even accounts zeroed.
    let after_apply = read_accounts(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(
            after_apply[&id].1, 0,
            "even {id} zeroed by the committed write"
        );
    }
    // The nonce is consumed — a replay of the same grant now fails.
    assert!(
        !nonces.consume("nonce-ok"),
        "the grant's nonce was consumed"
    );

    // REVERT via the captured typed-inverse → the pre-state is restored.
    {
        let mut client = Client::connect(&url, NoTls).expect("revert connect");
        let mut rconn = PgRevertConn::new(&mut client);
        let report: RevertReport = revert(&inverse, &mut rconn).expect("revert must succeed");
        assert_eq!(report.total_restored, 4);
    }
    let after_revert = read_accounts(&url);
    assert_eq!(
        before, after_revert,
        "revert restored the pre-apply state byte-for-byte (reversible apply proven)"
    );
    eprintln!("[grant-commit] PASS: reversible — revert restored the exact pre-state");
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (2) THE 5 T-grant-* TAMPER CASES + NO-GRANT + DATA-DRIFT — all ABORT
//      end-to-end through the real apply path, with NO mutation.
// ===========================================================================

/// Run a grant-gated apply against the real DB and return the result + a probe of
/// whether the DB changed. `mutate_live` lets a test tamper with the live request;
/// `recompute_where` lets a test inject apply-time data drift by pointing the
/// conn's recompute at a different predicate (here we instead inject drift by
/// committing a row before apply — see the data-drift case).
struct TamperOutcome {
    result: Result<(), GrantedApplyError>,
    unchanged: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_tamper(
    url: &str,
    pol: &PolicyConfig,
    grant: &GrantToken,
    live: &LiveRequest,
    vk: &VerifyingKey,
    nonces: &mut InMemoryNonceStore,
    br: &BlastRadius,
    clock: &dyn Clock,
) -> TamperOutcome {
    let before = read_accounts(url);
    let mut client = Client::connect(url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, FORWARD, EVEN_WHERE);
        guarded_apply_with_grant(
            pol,
            grant,
            live,
            vk,
            nonces,
            WriteKind::Update,
            REL,
            br,
            &mut conn,
            &NoopBarrier::new(),
            clock,
        )
        .map(|_| ())
    };
    let after = read_accounts(url);
    TamperOutcome {
        result,
        unchanged: before == after,
    }
}

#[test]
fn five_tamper_cases_plus_no_grant_all_abort_with_no_mutation() {
    let Some((admin, dbname, _c)) = setup("grant_tamper_matrix") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let pol = policy();

    // ---- T-grant-sql-swap ------------------------------------------------
    {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-sql", &url, EVEN_WHERE, FORWARD);
        let live = live_for("p-sql");
        let grant = sign_grant(&sk, &live, &br, "n-sql", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        let mut tampered = live.clone();
        // A DIFFERENT but still self-determined (PK-only) statement, so the swap is
        // caught precisely by the grant binding hash (BindingMismatch), not
        // (incidentally) the EPIC #91 PR-A self-determined gate.
        tampered.statement_text = "DELETE FROM public.accounts WHERE id = 1".to_string();
        let out = run_tamper(
            &url,
            &pol,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::BindingMismatch))
            ),
            "sql-swap: {:?}",
            out.result
        );
        assert!(out.unchanged, "sql-swap: DB unchanged");
        assert!(
            nonces.consume("n-sql"),
            "sql-swap: nonce NOT burned by reject"
        );
        eprintln!("T-grant-sql-swap PASS: BindingMismatch abort, no mutation");
    }

    // ---- T-grant-param-swap ----------------------------------------------
    {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-par", &url, EVEN_WHERE, FORWARD);
        let mut live = live_for("p-par");
        live.normalized_params = vec!["1".to_string()];
        let grant = sign_grant(&sk, &live, &br, "n-par", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        let mut tampered = live.clone();
        tampered.normalized_params = vec!["999".to_string()];
        let out = run_tamper(
            &url,
            &pol,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::BindingMismatch))
            ),
            "param-swap: {:?}",
            out.result
        );
        assert!(out.unchanged, "param-swap: DB unchanged");
        eprintln!("T-grant-param-swap PASS: BindingMismatch abort, no mutation");
    }

    // ---- T-grant-cross-session-replay ------------------------------------
    {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-ses", &url, EVEN_WHERE, FORWARD);
        let live = live_for("p-ses");
        let grant = sign_grant(&sk, &live, &br, "n-ses", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        let mut tampered = live.clone();
        tampered.session_id = "sess-attacker".to_string();
        let out = run_tamper(
            &url,
            &pol,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::BindingMismatch))
            ),
            "cross-session: {:?}",
            out.result
        );
        assert!(out.unchanged, "cross-session: DB unchanged");
        eprintln!("T-grant-cross-session PASS: BindingMismatch abort, no mutation");
    }

    // ---- T-grant-proposal-swap -------------------------------------------
    {
        let (sk, vk) = keypair();
        // Grant minted for p-A.
        let br_a = blast_radius_for("p-A", &url, EVEN_WHERE, FORWARD);
        let live_a = live_for("p-A");
        let grant = sign_grant(&sk, &live_a, &br_a, "n-prop", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        // Apply onto p-B (same data set + checksum, different proposal id).
        let br_b = blast_radius_for("p-B", &url, EVEN_WHERE, FORWARD);
        let live_b = live_for("p-B");
        let out = run_tamper(
            &url,
            &pol,
            &grant,
            &live_b,
            &vk,
            &mut nonces,
            &br_b,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::BindingMismatch))
            ),
            "proposal-swap: {:?}",
            out.result
        );
        assert!(out.unchanged, "proposal-swap: DB unchanged");
        eprintln!("T-grant-proposal-swap PASS: BindingMismatch abort, no mutation");
    }

    // ---- T-grant-replay (nonce reuse) ------------------------------------
    {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-rep", &url, EVEN_WHERE, FORWARD);
        let live = live_for("p-rep");
        let grant = sign_grant(&sk, &live, &br, "n-rep", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        // First apply: legitimate, commits + consumes the nonce.
        let first = run_tamper(
            &url,
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            first.result.is_ok(),
            "first replay-case apply commits: {:?}",
            first.result
        );
        // Restore the pre-state so the SECOND attempt's "unchanged" probe is clean
        // (the second apply must itself make NO change; it is rejected pre-txn).
        Client::connect(&url, NoTls)
            .unwrap()
            .batch_execute("UPDATE public.accounts SET balance = id * 1000 WHERE id % 2 = 0")
            .unwrap();
        // Second apply with the SAME grant: nonce already used → replay → REJECT.
        let second = run_tamper(
            &url,
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                second.result,
                Err(GrantedApplyError::Grant(GrantError::ReplayedNonce))
            ),
            "replay: {:?}",
            second.result
        );
        assert!(
            second.unchanged,
            "replay: DB unchanged on the rejected reuse"
        );
        eprintln!("T-grant-replay PASS: ReplayedNonce abort on reuse, no mutation");
    }

    // ---- T-grant-expiry --------------------------------------------------
    {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-exp", &url, EVEN_WHERE, FORWARD);
        let live = live_for("p-exp");
        let grant = sign_grant(&sk, &live, &br, "n-exp", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        clock.advance(5_000); // now = expiry = 10_000 → expired (>=)
        let out = run_tamper(&url, &pol, &grant, &live, &vk, &mut nonces, &br, &clock);
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::Expired { .. }))
            ),
            "expiry: {:?}",
            out.result
        );
        assert!(out.unchanged, "expiry: DB unchanged");
        assert!(
            nonces.consume("n-exp"),
            "expiry: nonce NOT burned by reject"
        );
        eprintln!("T-grant-expiry PASS: Expired abort, no mutation");
    }

    // ---- NO GRANT (attacker-minted with the WRONG key) -------------------
    {
        let (attacker_sk, _) = keypair();
        let (_approver_sk, approver_vk) = keypair();
        let br = blast_radius_for("p-nok", &url, EVEN_WHERE, FORWARD);
        let live = live_for("p-nok");
        let grant = sign_grant(&attacker_sk, &live, &br, "n-nok", 10_000);
        let mut nonces = InMemoryNonceStore::new();
        let out = run_tamper(
            &url,
            &pol,
            &grant,
            &live,
            &approver_vk,
            &mut nonces,
            &br,
            &MockClock::starting_at(5_000),
        );
        assert!(
            matches!(
                out.result,
                Err(GrantedApplyError::Grant(GrantError::BadSignature))
            ),
            "no-grant: {:?}",
            out.result
        );
        assert!(out.unchanged, "no-grant: DB unchanged (fail-closed)");
        eprintln!(
            "NO-GRANT PASS: attacker-minted grant (wrong key) → BadSignature abort, no mutation"
        );
    }

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3) THE NEW MOAT ANCHOR — apply-time MAGNITUDE drift caught by the CAP
//      (EPIC #91 PR-B, replacing the dropped exact-PK-set checksum). The grant +
//      cap are for the 4-row even set; concurrent INSERTs swell `id % 2 = 0` to 5
//      matching rows by apply time. The live write's magnitude (5 rows) exceeds the
//      approved cap (4) → CapExceeded abort, no mutation. The self-determined
//      predicate gate pins identity; the cap pins magnitude.
// ===========================================================================

#[test]
fn apply_time_magnitude_drift_rejects_via_cap_no_mutation() {
    let Some((admin, dbname, _c)) = setup("grant_cap_drift") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    // Isolate the CAP as the sole magnitude anchor on the TARGET's primary channel:
    // drop the seed's AFTER-UPDATE audit trigger so the only footprint is
    // `accounts.upd` (which the per-channel reconciliation EXEMPTS for the target —
    // the cap governs it). With the trigger present, a magnitude over-write would
    // also trip the audit table's `ins` channel (also fail-closed), but here we prove
    // the cap itself catches target-primary magnitude drift.
    Client::connect(&url, NoTls)
        .unwrap()
        .batch_execute("DROP TRIGGER accounts_audit_aud ON public.accounts")
        .unwrap();

    let (sk, vk) = keypair();
    // Grant signed for the CURRENT even set {2,4,6,8} (4 rows). The human approves a
    // cap of exactly the 4 rows they saw at dry-run.
    let br = blast_radius_for("p-cap-drift", &url, EVEN_WHERE, FORWARD);
    let live = live_for("p-cap-drift");
    let grant = sign_grant_cap(
        &sk,
        &live,
        &br,
        "n-cap-drift",
        10_000,
        WriteCap::new(4, 50_000_000),
    );
    let pol = policy();
    let mut nonces = InMemoryNonceStore::new();

    // MAGNITUDE DRIFT: a NEW even-id row appears AFTER the grant was signed, so the
    // live `UPDATE … WHERE id % 2 = 0` now updates 5 accounts (the target's primary
    // channel), over the approved cap of 4.
    Client::connect(&url, NoTls)
        .unwrap()
        .batch_execute("INSERT INTO public.accounts(id, owner, balance) VALUES (10, 'drift', 5)")
        .unwrap();
    let before_drift = read_accounts(&url);

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, FORWARD, EVEN_WHERE);
        guarded_apply_with_grant(
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            WriteKind::Update,
            REL,
            &br,
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::starting_at(5_000),
        )
        .map(|_| ())
    };
    // The grant verified (statement + cap + nonce all match), the apply txn opened,
    // the forward op ran, but the live magnitude (5 target updates) exceeded the
    // approved cap (4) → CapExceeded ROLLBACK, no mutation. The target's primary
    // channel is exempt from the relative reconciliation, so the CAP is the sole catch.
    match &result {
        Err(GrantedApplyError::Apply(ApplyError::CapExceeded {
            kind, cap, actual, ..
        })) => {
            assert_eq!(*kind, "rows");
            assert_eq!(*cap, 4);
            assert_eq!(
                *actual, 5,
                "the live write updated 5 target rows, over the cap of 4"
            );
        }
        other => {
            panic!("apply-time magnitude drift must REJECT via CapExceeded(rows), got {other:?}")
        }
    }
    // No mutation: the drift row is still present, but NO balance was zeroed.
    let after = read_accounts(&url);
    assert_eq!(
        before_drift, after,
        "cap-drift: no mutation (apply rolled back on CapExceeded)"
    );
    for (id, (_o, bal)) in &after {
        if *id % 2 == 0 {
            assert_ne!(
                *bal, 0,
                "no even account was zeroed (apply aborted on the cap)"
            );
        }
    }
    eprintln!(
        "T-grant-cap-drift PASS: concurrent inserts swelled `id % 2 = 0`'s target updates from \
         4 (approved) to 5 → CapExceeded(rows) abort, no mutation. The cap is the \
         absolute-magnitude anchor that replaced the dropped exact-PK-set checksum."
    );
    drop_db(&admin, &dbname);
}

#[test]
fn within_cap_concurrent_insert_still_commits_reversibly() {
    // The companion: the SAME concurrent-insert drift, but the human approved a cap
    // with headroom (5). The live 5-target-update write now FITS the cap → commits
    // (the cap does not over-fire), and reverts. Proves the cap admits an
    // approved-headroom write the OLD exact-PK-set checksum would have rejected as
    // drift. (Trigger dropped so the cap is exercised on the target's primary channel.)
    let Some((admin, dbname, _c)) = setup("grant_cap_headroom") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    Client::connect(&url, NoTls)
        .unwrap()
        .batch_execute("DROP TRIGGER accounts_audit_aud ON public.accounts")
        .unwrap();

    let (sk, vk) = keypair();
    let br = blast_radius_for("p-cap-ok", &url, EVEN_WHERE, FORWARD);
    let live = live_for("p-cap-ok");
    let clock = SystemClock::new();
    let expiry = clock.now_unix_millis() + 60_000;
    // Cap of 5: +1 headroom over the 4 target rows the human saw at dry-run.
    let grant = sign_grant_cap(
        &sk,
        &live,
        &br,
        "n-cap-ok",
        expiry,
        WriteCap::new(5, 50_000_000),
    );
    let pol = policy();
    let mut nonces = InMemoryNonceStore::new();

    Client::connect(&url, NoTls)
        .unwrap()
        .batch_execute("INSERT INTO public.accounts(id, owner, balance) VALUES (10, 'drift', 5)")
        .unwrap();
    let before = read_accounts(&url);

    let inverse: InversePlan = {
        let mut client = Client::connect(&url, NoTls).expect("apply connect");
        let mut conn = PgApplyConn::new(&mut client, FORWARD, EVEN_WHERE);
        let (applied, _bridged) = guarded_apply_with_grant(
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            WriteKind::Update,
            REL,
            &br,
            &mut conn,
            &NoopBarrier::new(),
            &clock,
        )
        .expect("a within-cap write (5 rows, cap 5) must commit");
        assert_eq!(applied.rows_written, 5, "all 5 even rows zeroed within cap");
        applied.inverse
    };
    // Revert restores the pre-apply state (reversibility intact under the cap path).
    {
        let mut client = Client::connect(&url, NoTls).expect("revert connect");
        let mut rconn = PgRevertConn::new(&mut client);
        let report: RevertReport = revert(&inverse, &mut rconn).expect("revert");
        assert_eq!(report.total_restored, 5);
    }
    assert_eq!(before, read_accounts(&url), "revert restored the pre-state");
    eprintln!("[cap-headroom] PASS: a within-cap (5-row) write committed + reverted reversibly");
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (4) S3 GUARDS INTACT under the grant path — a VALID grant whose apply-time
//      barrier injects drift still aborts at guarded_apply's PK-set re-check
//      (the grant gate is tighten-only; it does not weaken the §4 guards).
// ===========================================================================

#[test]
fn s3_pk_set_guard_still_fires_under_the_grant_path() {
    use pgb_core::ClosureBarrier;
    let Some((admin, dbname, _c)) = setup("grant_s3_guard") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let (sk, vk) = keypair();
    let br = blast_radius_for("p-s3", &url, EVEN_WHERE, FORWARD);
    let live = live_for("p-s3");
    // Sign the grant; the LIVE recompute at the grant gate still matches (the drift
    // is injected LATER, at the §10.4 barrier inside guarded_apply, AFTER the grant
    // gate's recompute). So the grant VERIFIES, then the §4 apply-time guards inside
    // the txn catch the barrier-injected drift → fail-closed abort.
    //
    // #87 / REPEATABLE READ note: the §10.4 barrier fires AFTER `conn.begin()` pins
    // the apply's RR snapshot, so the barrier's committed `DELETE id=8` is NOT visible
    // to the step-5 PK-set recompute (it reads the consistent snapshot) — instead the
    // apply's `FOR UPDATE` on id=8 cannot serialize against the concurrent delete and
    // raises SQLSTATE 40001 → `SerializationFailure`. Both are equally fail-closed
    // aborts with NO mutation; the grant gate remains tighten-only either way. (A
    // drift that commits BEFORE the apply snapshot — the realistic dry-run→apply
    // window — is still caught by the PK-set re-check; this test injects at the §10.4
    // seam, which under RR surfaces as the serialization abort.)
    let grant = sign_grant(&sk, &live, &br, "n-s3", 10_000);
    let pol = policy();
    let mut nonces = InMemoryNonceStore::new();

    let inject_url = url.clone();
    let barrier = ClosureBarrier::new(move |_| {
        // Post-grant, post-gate: a matching row vanishes → the apply-time PK-set
        // re-check INSIDE guarded_apply sees {2,4,6} ≠ grant {2,4,6,8} → abort.
        Client::connect(&inject_url, NoTls)
            .unwrap()
            .batch_execute("DELETE FROM public.accounts WHERE id = 8")
            .unwrap();
    });

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, FORWARD, EVEN_WHERE);
        guarded_apply_with_grant(
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            WriteKind::Update,
            REL,
            &br,
            &mut conn,
            &barrier,
            &MockClock::starting_at(5_000),
        )
        .map(|_| ())
    };
    // The grant VERIFIED (nonce consumed), but a §4 apply-time guard inside
    // guarded_apply caught the barrier-injected drift → fail-closed abort. EPIC #91
    // PR-B dropped the apply-time PK-set re-check; under REPEATABLE READ the
    // post-snapshot barrier `DELETE id=8` makes the apply's `FOR UPDATE id=8` unable
    // to serialize → SerializationFailure (40001). This proves the grant gate did NOT
    // weaken the surviving §4 guards (RR isolation + the fail-closed pre-image seam).
    match result {
        Err(GrantedApplyError::Apply(ApplyError::SerializationFailure)) => {
            eprintln!(
                "S3-guard-intact PASS: grant verified, then under REPEATABLE READ the §10.4 \
                 barrier-injected concurrent DELETE made the apply's FOR UPDATE unable to \
                 serialize → SerializationFailure (40001) ABORT. Still fail-closed, no mutation; \
                 the grant gate is tighten-only and did NOT weaken the surviving §4 guards."
            );
        }
        other => panic!(
            "expected a fail-closed S3 abort (SerializationFailure under RR) on the barrier-injected \
             concurrent DELETE under the grant path, got {other:?}"
        ),
    }
    assert_eq!(barrier.crossings(), 1, "barrier crossed once");
    // No even account was zeroed (apply rolled back); only the injected DELETE of
    // id=8 persisted (a separate committed txn, not the apply's doing).
    let after = read_accounts(&url);
    for (id, (_o, bal)) in &after {
        if *id % 2 == 0 {
            assert_ne!(*bal, 0, "no even account zeroed (apply aborted)");
        }
    }
    assert!(
        !after.contains_key(&8),
        "the barrier's own DELETE persisted"
    );
    assert!(before.contains_key(&8));
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (5) THE CARRIED PR-A FINDING — a join-correlated `UPDATE … FROM other` is
//      REFUSED by the self-determined-predicate gate BEFORE the apply txn opens.
//      Its row set is steerable by the joined table (only incidentally fail-closed
//      by the now-removed apply-time PK-set recompute). EPIC #91 PR-B.
// ===========================================================================

#[test]
fn join_correlated_update_from_is_refused_before_txn() {
    let Some((admin, dbname, _c)) = setup("grant_update_from") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let (sk, vk) = keypair();
    // A grant whose statement is a join-correlated `UPDATE accounts … FROM entries`.
    // (We build the blast radius / live request over this steerable statement; the
    // gate refuses it at the apply path regardless of any grant presented.)
    let steerable = "UPDATE public.accounts SET balance = 0 FROM public.entries \
                     WHERE public.entries.account_id = public.accounts.id";
    let br = blast_radius_for("p-from", &url, EVEN_WHERE, FORWARD);
    let mut live = live_for("p-from");
    live.statement_text = steerable.to_string();
    let grant = sign_grant(&sk, &live, &br, "n-from", 10_000);
    let pol = policy();
    let mut nonces = InMemoryNonceStore::new();

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, steerable, EVEN_WHERE);
        guarded_apply_with_grant(
            &pol,
            &grant,
            &live,
            &vk,
            &mut nonces,
            WriteKind::Update,
            REL,
            &br,
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::starting_at(5_000),
        )
        .map(|_| ())
    };
    assert!(
        matches!(
            result,
            Err(GrantedApplyError::NotSelfDetermined(
                pgb_clone_orchestrator::NotSelfDetermined::JoinCorrelation
            ))
        ),
        "a join-correlated UPDATE … FROM must be REFUSED at the apply path, got {result:?}"
    );
    // No mutation: the apply txn never opened (the gate precedes verify + begin).
    assert_eq!(before, read_accounts(&url), "UPDATE … FROM: no mutation");
    eprintln!(
        "T-update-from PASS: a join-correlated UPDATE … FROM (steerable by the joined \
         table) was REFUSED by the self-determined-predicate gate before the apply txn \
         opened — the carried PR-A finding, now explicitly foreclosed."
    );
    drop_db(&admin, &dbname);
}
