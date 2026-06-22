//! DB-free unit tests for the `pgb-applyd` write-safety service (the FakeCore
//! production peer). These drive [`pgb_applyd::Service`] with an in-memory
//! audit sink + a scripted `MockRehearsal` / `MockConn` (no DB), proving:
//!
//! 1. **happy path** — propose → dry_run → request_elevation → approve → apply
//!    commits the bounded write through the §4 grant-gated floor;
//! 2. the **5 T-grant tamper cases** surface as the right JSON-RPC error CODES
//!    (`GRANT_REJECTED` for sql/param/session/proposal swap + replay + expiry,
//!    and the no-grant / wrong-key path), all fail-closed with NO mutation;
//! 3. the **stored-proposal re-derivation invariant** — the `apply` RPC carries
//!    only `{proposal_id, confirm_rows, confirm_token}`, so a tampered apply-time
//!    field is impossible: the service pins statement/role/session from its OWN
//!    stored record, and a grant minted for a DIFFERENT (statement/session)
//!    cannot be applied via a swapped record.
//!
//! The §4 guards + the grant crypto are REUSED (not reimplemented); these tests
//! assert the service's wiring + the recoverable error contract.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

use pgb_applyd::{ErrorCode, Service};
use pgb_audit::{InMemorySink, SharedSink};
use pgb_cli::{ApprovalFlow, InMemoryNonceStore, RecordingWebhookSender};
use pgb_clone_orchestrator::apply::{
    ApplyConn, ApplyError, CapturedRow, ForwardResult, RelationChange,
};
use pgb_clone_orchestrator::dry_run::{
    AffectedTable, Measurement, Rehearsal, RelationEffect, WriteKind,
};
use pgb_clone_orchestrator::Volatility;
use pgb_core::blast_radius::OpCounts;
use pgb_core::{
    ApplyBarrier, Clock, LockHeld, LockMode, MockClock, NoopBarrier, PkChecksum, PkSetBuilder,
    PkTuple, PkValue, TriggerFired,
};

const REL: &str = "public.accounts";
const FORWARD: &str = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
const IDS: &[i64] = &[2, 4, 6, 8];

type Svc = Service<RecordingWebhookSender, InMemoryNonceStore, InMemoryNonceStore>;

fn keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn policy() -> pgb_policy::PolicyConfig {
    use pgb_policy::{
        AutonomyLevel, CloneConfig, CloneProvider, PitrConfig as PolicyPitr, PolicyConfig,
        RoleBudget, RolePolicy, WindowBudget,
    };
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

/// Build a fresh service whose §4 floor verifies grants against `vk`. The flow's
/// own verifying key is the same `vk` (unused for apply — the floor verifies);
/// the in-memory sink is shared between the flow and the apply-path record.
fn service(vk: VerifyingKey) -> Svc {
    let sink = SharedSink::new(InMemorySink::new());
    let flow = ApprovalFlow::new(
        sink.clone(),
        RecordingWebhookSender::new(),
        vk,
        InMemoryNonceStore::new(),
    );
    Service::new(flow, sink, InMemoryNonceStore::new(), vk, policy())
}

// ---- the scripted DB-free backends ----------------------------------------

/// A `MockRehearsal` that measures the `IDS` UPDATE footprint (so dry_run yields
/// a real-shaped BlastRadius without a DB).
struct MockRehearsal {
    rel: String,
    ids: Vec<i64>,
}
impl MockRehearsal {
    fn new(rel: &str, ids: &[i64]) -> Self {
        MockRehearsal {
            rel: rel.to_string(),
            ids: ids.to_vec(),
        }
    }
}
impl Rehearsal for MockRehearsal {
    fn volatility_of(&mut self, _name: &str) -> Volatility {
        // The happy-path predicate `id % 2 = 0` has no function; the engine never
        // calls this. Default to Immutable-equivalent (Stable) for safety.
        Volatility::Stable
    }
    fn rehearse(
        &mut self,
        _statement: &str,
        _kind: WriteKind,
        target_relation: &str,
    ) -> Result<Measurement, String> {
        let mut b = PkSetBuilder::for_relation(target_relation);
        for &id in &self.ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        let checksum = b.finalize().unwrap();
        Ok(Measurement {
            target: AffectedTable {
                relation: target_relation.to_string(),
                checksum: Some(checksum),
                rows: self.ids.len() as u64,
            },
            cascades: vec![],
            full_effect: vec![RelationEffect {
                relation: self.rel.clone(),
                counts: OpCounts::new(0, self.ids.len() as u64, 0),
            }],
            triggers_fired: vec![TriggerFired {
                name: "accounts_audit_aud".into(),
                rows: self.ids.len() as u64,
            }],
            locks: vec![LockHeld {
                relation: target_relation.to_string(),
                mode: LockMode::RowExclusiveLock,
                held_ms: 0,
            }],
            duration_ms: 5,
            wal_bytes: 128,
            constraint_violations: vec![],
            clone_lsn: "3A/7F00C8".into(),
            staleness_lsn_bytes: 0,
        })
    }
}

/// A scripted in-memory `ApplyConn` (mirrors the apply_grant.rs unit mock).
#[derive(Default)]
struct MockConnInner {
    recompute_ids: BTreeMap<String, Vec<i64>>,
    written_ids: Vec<i64>,
    began: bool,
    committed: bool,
}
#[derive(Clone)]
struct MockConn(Arc<Mutex<MockConnInner>>);
impl MockConn {
    fn new(rel: &str, ids: &[i64]) -> Self {
        let mut recompute_ids = BTreeMap::new();
        recompute_ids.insert(rel.to_string(), ids.to_vec());
        MockConn(Arc::new(Mutex::new(MockConnInner {
            recompute_ids,
            written_ids: ids.to_vec(),
            ..Default::default()
        })))
    }
    fn inner(&self) -> std::sync::MutexGuard<'_, MockConnInner> {
        self.0.lock().unwrap()
    }
}
impl ApplyConn for MockConn {
    fn create_restore_point(&mut self, _label: &str) -> Result<String, ApplyError> {
        Ok("0/16B6358".into())
    }
    fn begin(&mut self, _timeout_ms: u64) -> Result<(), ApplyError> {
        self.inner().began = true;
        Ok(())
    }
    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
        let ids = self
            .inner()
            .recompute_ids
            .get(relation)
            .cloned()
            .unwrap_or_default();
        let mut b = PkSetBuilder::for_relation(relation);
        for id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }
    fn apply_forward(
        &mut self,
        _kind: WriteKind,
        _relation: &str,
        _cascade: &[String],
    ) -> Result<ForwardResult, ApplyError> {
        let ids = self.inner().written_ids.clone();
        let written = ids
            .iter()
            .map(|&id| CapturedRow {
                pk: PkTuple::single(PkValue::Int(id)),
                before_image: vec![
                    ("id".into(), PkValue::Int(id)),
                    ("owner".into(), PkValue::Text(format!("owner-{id}"))),
                    ("balance".into(), PkValue::Int(id * 1000)),
                ],
            })
            .collect();
        Ok(ForwardResult::new(written))
    }
    fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
        let n = self.inner().written_ids.len() as u64;
        Ok(vec![RelationChange {
            relation: REL.into(),
            ins: 0,
            upd: n,
            del: 0,
        }])
    }
    fn commit(&mut self) -> Result<(), ApplyError> {
        self.inner().committed = true;
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), ApplyError> {
        Ok(())
    }
}

// ---- a helper that runs propose→dry_run→elevate→approve and returns ids -----

struct Approved {
    proposal_id: String,
    confirm_token: String,
    total_rows: u64,
}

/// Run the lifecycle up to (and including) approve, returning what apply needs.
/// `session` is the proposal's session (the requester); `approver` differs.
fn approve_through(
    svc: &mut Svc,
    sk: &SigningKey,
    clock: &dyn Clock,
    statement: &str,
    session: &str,
    nonce: &str,
) -> Approved {
    let proposed = svc
        .propose(
            statement,
            Some(IDS.len() as u64),
            "app_writer",
            session,
            clock,
        )
        .expect("propose");
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    let dry = svc
        .dry_run(&proposed.proposal_id, &mut rehearsal, clock)
        .expect("dry_run");
    let req = svc
        .request_elevation(&proposed.proposal_id, "raise the bound", clock)
        .expect("request_elevation");
    svc.approve(&req.request_id, "operator-1", sk, nonce, 60_000, clock)
        .expect("approve");
    Approved {
        proposal_id: proposed.proposal_id,
        confirm_token: dry.confirm_token,
        total_rows: dry.total_rows,
    }
}

fn run_apply(
    svc: &mut Svc,
    proposal_id: &str,
    confirm_rows: u64,
    token: Option<&str>,
    conn: &mut MockConn,
    barrier: &dyn ApplyBarrier,
    clock: &dyn Clock,
) -> Result<pgb_applyd::protocol::ApplyResult, pgb_applyd::RpcError> {
    svc.apply(proposal_id, confirm_rows, token, conn, barrier, clock)
}

// ===========================================================================
//  (1) HAPPY PATH
// ===========================================================================

#[test]
fn lifecycle_propose_dry_run_approve_apply_commits() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-ok");

    let mut conn = MockConn::new(REL, IDS);
    let probe = conn.clone();
    let res = run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows,
        Some(&a.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .expect("the grant-gated apply must commit");
    assert!(res.applied);
    assert_eq!(res.rows_written, 4);
    assert!(res.reversible);
    assert!(probe.inner().committed, "the bounded write committed");

    // The proposal is consumed (single-use): a replay is PROPOSAL_NOT_FOUND.
    let mut conn2 = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows,
        Some(&a.confirm_token),
        &mut conn2,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::ProposalNotFound.as_str());
}

// ===========================================================================
//  (2) confirm_rows / confirm_token forcing function
// ===========================================================================

#[test]
fn apply_without_matching_confirm_rows_blocks() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-c");

    let mut conn = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows + 1, // wrong count
        Some(&a.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::ConfirmMismatch.as_str());
    assert!(err.data.retryable);
    assert!(
        !conn.inner().began,
        "no apply txn opened on a confirm mismatch"
    );
}

#[test]
fn apply_with_wrong_confirm_token_blocks() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-t");

    let mut conn = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows,
        Some("ct-bogus"),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::ConfirmMismatch.as_str());
}

// ===========================================================================
//  (3) NO GRANT → APPROVAL_REQUIRED (recoverable)
// ===========================================================================

#[test]
fn apply_without_a_grant_is_approval_required() {
    let (_sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    // propose + dry_run but DO NOT approve.
    let proposed = svc
        .propose(
            FORWARD,
            Some(IDS.len() as u64),
            "app_writer",
            "sess-a",
            &clock,
        )
        .unwrap();
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    let dry = svc
        .dry_run(&proposed.proposal_id, &mut rehearsal, &clock)
        .unwrap();

    let mut conn = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &proposed.proposal_id,
        dry.total_rows,
        Some(&dry.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::ApprovalRequired.as_str());
    assert!(err.data.retryable, "approval-required is recoverable");
    assert!(!conn.inner().began, "no apply txn opened without a grant");
}

// ===========================================================================
//  (4) THE STORED-PROPOSAL RE-DERIVATION INVARIANT (the issue #67 headline)
// ===========================================================================

#[test]
fn apply_rederives_from_stored_record_a_grant_for_a_different_session_cannot_apply() {
    // Two proposals exist with the SAME statement but DIFFERENT sessions. A grant
    // is approved for proposal-A (session sess-a). The agent tries to apply
    // proposal-B (session sess-b) — but apply takes only a proposal_id, so the
    // service re-derives the LiveRequest from proposal-B's STORED record
    // (session sess-b). proposal-B has NO grant → APPROVAL_REQUIRED. The grant for
    // A can NEVER be redirected onto B by any apply-time field, because there are
    // no apply-time fields to redirect.
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);

    // Approve a grant for proposal-A (sess-a).
    let _a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-a");

    // Propose B (same SQL, session sess-b) + dry_run, but DO NOT approve B.
    let proposed_b = svc
        .propose(
            FORWARD,
            Some(IDS.len() as u64),
            "app_writer",
            "sess-b",
            &clock,
        )
        .unwrap();
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    let dry_b = svc
        .dry_run(&proposed_b.proposal_id, &mut rehearsal, &clock)
        .unwrap();

    // Apply B: the service re-derives from B's record (sess-b, no grant).
    let mut conn = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &proposed_b.proposal_id,
        dry_b.total_rows,
        Some(&dry_b.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        err.data.code,
        ErrorCode::ApprovalRequired.as_str(),
        "B has no grant; the A grant cannot be redirected because apply takes only a proposal_id"
    );
    assert!(!conn.inner().began);
}

// ===========================================================================
//  (5) TAMPER — apply-time DATA DRIFT → GRANT_REJECTED (binding mismatch)
// ===========================================================================

#[test]
fn apply_time_data_drift_is_grant_rejected_no_mutation() {
    // The grant is bound to {2,4,6,8}; at apply the recompute sees {2,4,6,8,10}
    // (a row drifted into the predicate). The §4 floor re-derives the binding
    // from the apply-time checksum, which no longer matches the signed one →
    // BindingMismatch → GRANT_REJECTED, no mutation.
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-d");

    // Apply with a conn whose recompute sees a DRIFTED set.
    let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
    let err = run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows, // confirm_rows still matches the dry-run total (4)
        Some(&a.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::GrantRejected.as_str());
    assert!(!conn.inner().committed, "no mutation on data drift");
}

// ===========================================================================
//  (6) TAMPER — nonce replay across two proposals with the SAME nonce
// ===========================================================================

#[test]
fn replayed_nonce_is_grant_rejected() {
    // Approve proposal-A (nonce N), apply it (consumes N). Approve proposal-B with
    // the SAME nonce N, apply it → the apply-time nonce store rejects the reuse →
    // GRANT_REJECTED.
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);

    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "shared-nonce");
    let mut conn_a = MockConn::new(REL, IDS);
    run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows,
        Some(&a.confirm_token),
        &mut conn_a,
        &NoopBarrier::new(),
        &clock,
    )
    .expect("first apply commits");
    assert!(conn_a.inner().committed);

    let b = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-b", "shared-nonce");
    let mut conn_b = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &b.proposal_id,
        b.total_rows,
        Some(&b.confirm_token),
        &mut conn_b,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::GrantRejected.as_str());
    assert!(!conn_b.inner().committed, "no mutation on nonce replay");
}

// ===========================================================================
//  (7) TAMPER — expired grant → GRANT_REJECTED
// ===========================================================================

#[test]
fn expired_grant_is_grant_rejected() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    // Approve with a SHORT grant TTL, then advance the clock past it.
    let proposed = svc
        .propose(
            FORWARD,
            Some(IDS.len() as u64),
            "app_writer",
            "sess-a",
            &clock,
        )
        .unwrap();
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    let dry = svc
        .dry_run(&proposed.proposal_id, &mut rehearsal, &clock)
        .unwrap();
    let req = svc
        .request_elevation(&proposed.proposal_id, "raise", &clock)
        .unwrap();
    svc.approve(
        &req.request_id,
        "operator-1",
        &sk,
        "nonce-exp",
        1_000,
        &clock,
    )
    .unwrap();

    clock.advance(2_000); // grant expired (TTL was 1_000)
    let mut conn = MockConn::new(REL, IDS);
    let err = run_apply(
        &mut svc,
        &proposed.proposal_id,
        dry.total_rows,
        Some(&dry.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::GrantRejected.as_str());
    assert!(!conn.inner().committed);
}

// ===========================================================================
//  (8) TAMPER — operator self-approval refused (the agent can't self-authorize)
// ===========================================================================

#[test]
fn self_approval_is_refused() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let proposed = svc
        .propose(
            FORWARD,
            Some(IDS.len() as u64),
            "app_writer",
            "sess-a",
            &clock,
        )
        .unwrap();
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    svc.dry_run(&proposed.proposal_id, &mut rehearsal, &clock)
        .unwrap();
    let req = svc
        .request_elevation(&proposed.proposal_id, "raise", &clock)
        .unwrap();
    // The approver id EQUALS the requester (sess-a) → self-approval refused.
    let err = svc
        .approve(&req.request_id, "sess-a", &sk, "nonce-self", 60_000, &clock)
        .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::GrantRejected.as_str());
}

// ===========================================================================
//  (9) wrong approver key refused at approve (the floor's trust root)
// ===========================================================================

#[test]
fn approve_with_a_foreign_key_is_refused() {
    let (_real_sk, vk) = keypair();
    let (foreign_sk, _) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let proposed = svc
        .propose(
            FORWARD,
            Some(IDS.len() as u64),
            "app_writer",
            "sess-a",
            &clock,
        )
        .unwrap();
    let mut rehearsal = MockRehearsal::new(REL, IDS);
    svc.dry_run(&proposed.proposal_id, &mut rehearsal, &clock)
        .unwrap();
    let req = svc
        .request_elevation(&proposed.proposal_id, "raise", &clock)
        .unwrap();
    // Sign with a key that is NOT the configured approver pubkey → refused.
    let err = svc
        .approve(
            &req.request_id,
            "operator-1",
            &foreign_sk,
            "nonce-f",
            60_000,
            &clock,
        )
        .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::GrantRejected.as_str());
}

// ===========================================================================
//  (10) refusals: non-rehearsable shape at propose; the audit chain records
// ===========================================================================

#[test]
fn non_rehearsable_statement_is_refused_at_propose() {
    let (_sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let err = svc
        .propose(
            "TRUNCATE public.accounts",
            None,
            "app_writer",
            "sess-a",
            &clock,
        )
        .unwrap_err();
    assert_eq!(err.data.code, ErrorCode::NotRehearsable.as_str());
}

#[test]
fn full_lifecycle_is_audited_to_the_shared_chain() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(5_000);
    let mut svc = service(vk);
    let a = approve_through(&mut svc, &sk, &clock, FORWARD, "sess-a", "nonce-aud");
    let mut conn = MockConn::new(REL, IDS);
    run_apply(
        &mut svc,
        &a.proposal_id,
        a.total_rows,
        Some(&a.confirm_token),
        &mut conn,
        &NoopBarrier::new(),
        &clock,
    )
    .unwrap();

    let records = svc.audit_records(50);
    // request_elevation (BLOCK), grant_signed (ALLOW), apply_committed (ALLOW).
    let codes: Vec<&str> = records
        .iter()
        .map(|r| r.payload.reason_code.as_str())
        .collect();
    assert!(codes.contains(&"approval_required"), "{codes:?}");
    assert!(codes.contains(&"grant_signed"), "{codes:?}");
    assert!(codes.contains(&"apply_committed"), "{codes:?}");
    // The chain verifies within-chain (one shared genesis).
    pgb_audit::verify_chain(&records).expect("the lifecycle chain verifies");
}
