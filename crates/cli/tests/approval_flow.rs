//! End-to-end §14 approval-flow acceptance tests (SPEC §5 authorization suite,
//! §14.3).
//!
//! These drive the CLI flow through the **same** four operations a real
//! deployment uses — `request_elevation` → `approve` → `verify_at_apply` — and
//! assert the four issue-#56 acceptance proofs:
//!
//! 1. **verify-at-apply (happy path):** an approved grant verifies at apply.
//! 2. **the 5 T-grant-* tamper cases** re-verified *end-to-end through the CLI
//!    flow* (tampering any bound field → REJECTED at apply).
//! 3. **agent-self-approve → REJECT** (the approver must be a human, not the
//!    agent/DB-operator principal).
//! 4. **a structural/irreversible op → default-deny REFUSED** (no grant can
//!    authorize it in the MVP).
//!
//! Plus: the one generic webhook fires with the request payload, webhook failure
//! does not gate, and every step is recorded in the tamper-evident audit chain.
//!
//! Time is the deterministic `MockClock` throughout (no wall clock). No Postgres
//! and no external network: the only socket use is a local `127.0.0.1:0` stub
//! HTTP server in the webhook transport test.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

use pgb_audit::{Decision, InMemorySink, Sink};
use pgb_cli::{
    ApprovalFlow, ApproveError, AuthorityError, ElevationError, GrantBinding, GrantError,
    HttpWebhookSender, InMemoryNonceStore, Principal, Proposal, RecordingWebhookSender, RequestId,
    WebhookSender,
};
use pgb_core::MockClock;
use pgb_core::inverse::Operation;

// ----------------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------------

fn keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn sample_proposal() -> Proposal {
    Proposal {
        proposal_id: "p-001".to_string(),
        statement_text: "UPDATE public.orders SET status='fixed' WHERE id = $1".to_string(),
        normalized_params: vec!["42".to_string()],
        role: "app_writer".to_string(),
        session_id: "sess-abc".to_string(),
        dry_run_lsn: "3A/7F00C8".to_string(),
        blast_radius_checksum: "sha256:abc123".to_string(),
    }
}

/// A bounded, reversible UPDATE — the certified, elevation-eligible shape.
fn eligible_op() -> Operation {
    Operation::Update {
        has_preimage: true,
        has_pk: true,
    }
}

/// Build a flow over an in-memory audit sink + a recording webhook.
fn flow_with(
    vk: VerifyingKey,
) -> ApprovalFlow<InMemorySink, RecordingWebhookSender, InMemoryNonceStore> {
    ApprovalFlow::new(
        InMemorySink::new(),
        RecordingWebhookSender::new(),
        vk,
        InMemoryNonceStore::new(),
    )
}

/// Drive request → approve and return (flow, signed grant, the binding used).
/// The shared happy-path setup the tamper cases mutate.
fn request_and_approve(
    sk: &SigningKey,
    vk: VerifyingKey,
    clock: &MockClock,
) -> (
    ApprovalFlow<InMemorySink, RecordingWebhookSender, InMemoryNonceStore>,
    pgb_cli::GrantToken,
    GrantBinding,
) {
    let mut flow = flow_with(vk);
    let id = RequestId("req-1".to_string());

    flow.request_elevation(
        id.clone(),
        sample_proposal(),
        "agent-7",
        &eligible_op(),
        60_000,
        clock,
    )
    .expect("eligible op opens a request");

    let approver = Principal::approver("human-alice");
    let approval = flow
        .approve(&id, &approver, sk, "nonce-001", 30_000, clock)
        .expect("human approver signs the grant");

    // The live binding the apply path re-derives from the recorded proposal.
    let live = flow
        .store()
        .get(&id)
        .expect("request exists")
        .proposal
        .to_binding("nonce-001", approval.grant.binding.expiry_unix_millis);

    (flow, approval.grant, live)
}

// ----------------------------------------------------------------------------
// Acceptance proof 1: verify-at-apply (happy path)
// ----------------------------------------------------------------------------

#[test]
fn approve_then_grant_verifies_at_apply() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);

    let (mut flow, grant, live) = request_and_approve(&sk, vk, &clock);

    // The grant re-verifies at apply: binding matches, nonce fresh, unexpired.
    assert!(
        flow.verify_at_apply(&grant, &live, &clock).is_ok(),
        "an untampered, approved grant must verify at apply"
    );

    // And the whole flow left a verifiable audit trail with the expected steps.
    let chain = flow.audit().load_chain().expect("load chain");
    assert!(flow.audit().verify().is_ok(), "audit chain must be intact");
    let codes: Vec<&str> = chain
        .iter()
        .map(|r| r.payload.reason_code.as_str())
        .collect();
    assert_eq!(
        codes,
        vec!["approval_required", "grant_signed", "grant_verified"],
        "audit must record request -> approve -> verified"
    );
    // The signed + verified steps are ALLOW; the initial block is BLOCK.
    assert_eq!(chain[0].payload.decision, Decision::Block);
    assert_eq!(chain[1].payload.decision, Decision::Allow);
    assert_eq!(chain[2].payload.decision, Decision::Allow);
}

// ----------------------------------------------------------------------------
// Acceptance proof 2: the 5 T-grant-* tamper cases, end-to-end through the CLI
// ----------------------------------------------------------------------------

/// T-grant-sql-swap — mutate the statement after approval → REJECT at apply.
#[test]
fn t_grant_sql_swap_rejected_through_flow() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let (mut flow, grant, mut live) = request_and_approve(&sk, vk, &clock);

    live.statement_text = "DELETE FROM public.orders".to_string();

    assert_eq!(
        flow.verify_at_apply(&grant, &live, &clock).unwrap_err(),
        GrantError::BindingMismatch
    );
    assert_last_audit_rejected(&flow, "grant_rejected");
}

/// T-grant-param-swap — mutate a prepared param after approval → REJECT.
#[test]
fn t_grant_param_swap_rejected_through_flow() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let (mut flow, grant, mut live) = request_and_approve(&sk, vk, &clock);

    live.normalized_params = vec!["99".to_string()];

    assert_eq!(
        flow.verify_at_apply(&grant, &live, &clock).unwrap_err(),
        GrantError::BindingMismatch
    );
    assert_last_audit_rejected(&flow, "grant_rejected");
}

/// T-grant-cross-session-replay — replay from another session → REJECT.
#[test]
fn t_grant_cross_session_replay_rejected_through_flow() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let (mut flow, grant, mut live) = request_and_approve(&sk, vk, &clock);

    live.session_id = "sess-attacker".to_string();

    assert_eq!(
        flow.verify_at_apply(&grant, &live, &clock).unwrap_err(),
        GrantError::BindingMismatch
    );
    assert_last_audit_rejected(&flow, "grant_rejected");
}

/// T-grant-replay — reuse a valid grant twice (nonce reused) → second REJECT.
#[test]
fn t_grant_replay_rejected_through_flow() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let (mut flow, grant, live) = request_and_approve(&sk, vk, &clock);

    // First apply: legitimate, consumes the single-use nonce.
    assert!(flow.verify_at_apply(&grant, &live, &clock).is_ok());
    // Second apply with the same valid grant: replay → REJECT.
    assert_eq!(
        flow.verify_at_apply(&grant, &live, &clock).unwrap_err(),
        GrantError::ReplayedNonce
    );
    assert_last_audit_rejected(&flow, "grant_rejected");
}

/// T-grant-expiry — advance the clock past the grant TTL → REJECT.
#[test]
fn t_grant_expiry_rejected_through_flow() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let (mut flow, grant, live) = request_and_approve(&sk, vk, &clock);

    // The grant TTL was 30_000ms from now=1_000 → expiry at 31_000. Jump past it.
    clock.advance(40_000);

    assert!(matches!(
        flow.verify_at_apply(&grant, &live, &clock).unwrap_err(),
        GrantError::Expired { .. }
    ));
    assert_last_audit_rejected(&flow, "grant_rejected");
}

// ----------------------------------------------------------------------------
// Acceptance proof 3: agent-self-approve → REJECT
// ----------------------------------------------------------------------------

/// T-self-auth — the agent/DB-operator principal cannot sign its own grant.
#[test]
fn agent_self_approve_is_rejected() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let mut flow = flow_with(vk);
    let id = RequestId("req-self".to_string());

    // The agent opens the request under its own id.
    flow.request_elevation(
        id.clone(),
        sample_proposal(),
        "agent-7",
        &eligible_op(),
        60_000,
        &clock,
    )
    .unwrap();

    // (a) The same identity, even labeled "approver", is a self-approval → REJECT.
    let self_as_approver = Principal::approver("agent-7");
    let err = flow
        .approve(&id, &self_as_approver, &sk, "nonce-x", 30_000, &clock)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ApproveError::Authority(AuthorityError::SelfApproval(_))
        ),
        "self-approval must be refused, got {err:?}"
    );

    // (b) A requester-kind principal (the agent) cannot approve at all → REJECT.
    let agent = Principal::requester("agent-9");
    let err2 = flow
        .approve(&id, &agent, &sk, "nonce-y", 30_000, &clock)
        .unwrap_err();
    assert!(
        matches!(
            err2,
            ApproveError::Authority(AuthorityError::NotAnApprover(_))
        ),
        "a non-approver principal must be refused, got {err2:?}"
    );

    // The request is still pending (no grant was minted by either attempt), so a
    // real human approver can still approve it.
    let human = Principal::approver("human-alice");
    assert!(
        flow.approve(&id, &human, &sk, "nonce-ok", 30_000, &clock)
            .is_ok(),
        "a distinct human approver must still be able to approve"
    );

    // Both self-approval attempts are audited as REJECT.
    let chain = flow.audit().load_chain().unwrap();
    let rejects = chain
        .iter()
        .filter(|r| r.payload.reason_code == "self_approval_refused")
        .count();
    assert_eq!(rejects, 2, "both self-approve attempts must be audited");
}

// ----------------------------------------------------------------------------
// Acceptance proof 4: structural/irreversible op → default-deny REFUSED
// ----------------------------------------------------------------------------

/// A structural/irreversible op never enters the flow — no grant can authorize
/// it in the MVP (break-glass unreachable). Sweeps the refused categories.
#[test]
fn structural_irreversible_ops_are_default_deny_refused() {
    let (_sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);

    let structural = [
        Operation::Truncate,
        Operation::Drop,
        Operation::Alter,
        // No-pre-image DELETE (not reversible).
        Operation::Delete {
            has_preimage: false,
            has_pk: true,
        },
        // PK-less write (ctid unsafe across the boundary).
        Operation::Update {
            has_preimage: true,
            has_pk: false,
        },
        // INSERT with a volatile default.
        Operation::Insert {
            volatile_default: true,
            has_pk: true,
        },
        // Anything the parser couldn't map.
        Operation::Unknown("MERGE".to_string()),
    ];

    for (i, op) in structural.iter().enumerate() {
        let mut flow = flow_with(vk);
        let id = RequestId(format!("req-refused-{i}"));
        let err = flow
            .request_elevation(id.clone(), sample_proposal(), "agent-7", op, 60_000, &clock)
            .expect_err("a structural/irreversible op must be refused");
        assert!(
            matches!(err, ElevationError::Refused(_)),
            "op {op:?} must be default-deny refused, got {err:?}"
        );
        // No request was created — there is no ticket and no grant path.
        assert!(
            flow.store().get(&id).is_none(),
            "a refused op must not create an approval request"
        );
        // The refusal is audited as REJECT.
        let chain = flow.audit().load_chain().unwrap();
        assert_eq!(chain.len(), 1, "exactly one audit row for the refusal");
        assert_eq!(chain[0].payload.decision, Decision::Reject);
        assert_eq!(chain[0].payload.reason_code, "structural_op_refused");
    }
}

// ----------------------------------------------------------------------------
// The one generic webhook
// ----------------------------------------------------------------------------

#[test]
fn request_elevation_fires_one_generic_webhook_with_the_payload() {
    let (_sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let recorder = RecordingWebhookSender::new();
    // Build the flow with our own recorder so we can read it back afterwards.
    let mut flow = ApprovalFlow::new(InMemorySink::new(), recorder, vk, InMemoryNonceStore::new());
    let id = RequestId("req-wh".to_string());

    let outcome = flow
        .request_elevation(
            id.clone(),
            sample_proposal(),
            "agent-7",
            &eligible_op(),
            60_000,
            &clock,
        )
        .unwrap();
    assert!(outcome.webhook.is_ok(), "webhook should deliver");

    // The recorder lives inside the flow; re-create the expected payload and
    // compare via the public API by re-sending is not possible, so we assert the
    // contract instead: exactly one APPROVAL_REQUIRED ticket with the request id.
    assert_eq!(outcome.contract.code, "APPROVAL_REQUIRED");
    assert_eq!(outcome.contract.request_id, id);
}

#[test]
fn webhook_failure_does_not_gate_the_request() {
    let (_sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    // A failing webhook must NOT prevent the ticket from being created — webhook
    // is best-effort notification, never a gate.
    let mut flow = ApprovalFlow::new(
        InMemorySink::new(),
        RecordingWebhookSender::failing(),
        vk,
        InMemoryNonceStore::new(),
    );
    let id = RequestId("req-wh-fail".to_string());

    let outcome = flow
        .request_elevation(
            id.clone(),
            sample_proposal(),
            "agent-7",
            &eligible_op(),
            60_000,
            &clock,
        )
        .expect("ticket must be created even when the webhook fails");
    assert!(
        outcome.webhook.is_err(),
        "the webhook was configured to fail"
    );
    // The ticket exists and is pending — the agent can still get it approved.
    assert!(flow.store().get(&id).is_some());
}

/// The production HTTP webhook sender POSTs the JSON payload to a *local* stub
/// server on an ephemeral 127.0.0.1 port (never an external endpoint, never the
/// founder's :5432).
#[test]
fn http_webhook_sender_posts_payload_to_local_stub() {
    // Bind a local stub HTTP server on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local stub");
    let addr = listener.local_addr().unwrap();
    assert_ne!(addr.port(), 5432, "must never touch the founder's Postgres");

    let (tx, rx) = mpsc::channel::<String>();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).expect("read request");
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        // Minimal 200 response.
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("write response");
        tx.send(request).expect("send captured request");
    });

    // Build a real request payload and POST it.
    let request = pgb_cli::ApprovalRequest {
        id: RequestId("req-http".to_string()),
        proposal: sample_proposal(),
        requester_id: "agent-7".to_string(),
        created_unix_millis: 1_000,
        ttl_millis: 60_000,
        status: pgb_cli::RequestStatus::Pending,
    };
    let payload = pgb_cli::WebhookPayload::from_request(&request);
    let sender = HttpWebhookSender::new(format!("http://{}/hook", addr));
    sender.send(&payload).expect("POST should get a 2xx");

    let captured = rx.recv().expect("server captured the request");
    server.join().expect("server thread");

    // The stub saw a POST to /hook carrying our JSON body (the request id is in
    // the body), confirming the generic webhook delivered the payload.
    assert!(
        captured.starts_with("POST /hook HTTP/1.1"),
        "got: {captured}"
    );
    assert!(captured.contains("application/json"));
    assert!(
        captured.contains("\"event\":\"approval_required\""),
        "body missing event: {captured}"
    );
    assert!(
        captured.contains("req-http"),
        "body missing request id: {captured}"
    );
}

// ----------------------------------------------------------------------------
// Request lifecycle: TTL + single-use
// ----------------------------------------------------------------------------

#[test]
fn expired_request_cannot_be_approved() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let mut flow = flow_with(vk);
    let id = RequestId("req-ttl".to_string());

    flow.request_elevation(
        id.clone(),
        sample_proposal(),
        "agent-7",
        &eligible_op(),
        5_000, // 5s TTL
        &clock,
    )
    .unwrap();

    // Past the request TTL: approval is refused.
    clock.advance(6_000);
    let human = Principal::approver("human-alice");
    let err = flow
        .approve(&id, &human, &sk, "nonce-late", 30_000, &clock)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ApproveError::Request(pgb_cli::RequestError::Expired { .. })
        ),
        "an expired request must not be approvable, got {err:?}"
    );
}

#[test]
fn a_request_can_only_be_approved_once() {
    let (sk, vk) = keypair();
    let clock = MockClock::starting_at(1_000);
    let mut flow = flow_with(vk);
    let id = RequestId("req-once".to_string());

    flow.request_elevation(
        id.clone(),
        sample_proposal(),
        "agent-7",
        &eligible_op(),
        60_000,
        &clock,
    )
    .unwrap();

    let human = Principal::approver("human-alice");
    assert!(
        flow.approve(&id, &human, &sk, "nonce-a", 30_000, &clock)
            .is_ok()
    );
    // A second approval of the same request is refused (single-use ticket).
    let err = flow
        .approve(&id, &human, &sk, "nonce-b", 30_000, &clock)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ApproveError::Request(pgb_cli::RequestError::NotPending(_))
        ),
        "a resolved request must not be re-approvable, got {err:?}"
    );
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

fn assert_last_audit_rejected(
    flow: &ApprovalFlow<InMemorySink, RecordingWebhookSender, InMemoryNonceStore>,
    expected_code: &str,
) {
    let chain = flow.audit().load_chain().expect("load chain");
    let last = chain.last().expect("at least one audit record");
    assert_eq!(last.payload.decision, Decision::Reject);
    assert_eq!(last.payload.reason_code, expected_code);
    assert!(
        flow.audit().verify().is_ok(),
        "audit chain must stay intact"
    );
}
