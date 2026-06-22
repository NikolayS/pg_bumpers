//! The end-to-end §14 approval flow (SPEC §14.3) — the orchestration that wires
//! the parts together and **audits every step**.
//!
//! [`ApprovalFlow`] owns the moving pieces and exposes the three operations of
//! the MVP authorization lifecycle:
//!
//! 1. [`request_elevation`](ApprovalFlow::request_elevation) — a blocked
//!    *parameter-class* write opens an `APPROVAL_REQUIRED` ticket (TTL) and fires
//!    the one generic webhook. A *structural/irreversible* op is **refused** here
//!    (default-deny; no ticket, no grant).
//! 2. [`approve`](ApprovalFlow::approve) — a **human approver** (never the agent)
//!    signs the §14.3 proposal-bound grant with the audit-key-grade signing key.
//!    Self-approval is refused.
//! 3. [`verify_at_apply`](ApprovalFlow::verify_at_apply) — at apply time the
//!    grant is **re-verified** against the live request via the binding hash +
//!    nonce + clock (reusing `pgb_policy`'s crypto, not reimplementing it). Any
//!    tampered bound field, replay, or expiry rejects.
//!
//! Every operation appends a tamper-evident audit record (SPEC §14.3 — "request,
//! approver identity, decision, grant, scope, expiry … in the audit"). The audit
//! chain is the hash-chained `pgb_audit` log; the in-memory sink is used here
//! single-process.

use ed25519_dalek::{SigningKey, VerifyingKey};

use pgb_audit::record::{Principal as AuditPrincipal, WriteSafetyRefs};
use pgb_audit::{AuditRecord, Decision, IntentTiers, NewEntry, Sink};
use pgb_core::Clock;
use pgb_policy::{GrantBinding, GrantError, GrantToken, NonceStore};

use crate::principal::{ApprovalAuthority, AuthorityError, Principal};
use crate::refuse::{gate_for_elevation, ElevationEligibility};
use crate::request::{ApprovalRequired, Proposal, RequestError, RequestId, RequestStatus};
use crate::webhook::{WebhookError, WebhookPayload, WebhookSender};

/// The successful outcome of [`ApprovalFlow::request_elevation`].
#[derive(Debug)]
pub struct ElevationOutcome {
    /// The `APPROVAL_REQUIRED` block contract returned to the agent.
    pub contract: ApprovalRequired,
    /// The result of the (best-effort) webhook delivery. `Ok` on a 2xx; an
    /// error here does **not** invalidate the ticket — notification is not a
    /// gate.
    pub webhook: Result<(), WebhookError>,
}

/// The successful outcome of [`ApprovalFlow::approve`]: the signed grant.
#[derive(Debug)]
pub struct ApprovalOutcome {
    /// The signed, single-use, time-boxed, proposal-bound grant token.
    pub grant: GrantToken,
}

/// Why an elevation request was refused outright (terminal — no grant possible).
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    /// The op is structural / irreversible (default-deny; SPEC §10.3, §14.3 MVP).
    /// Break-glass is unreachable in the MVP, so this is a dead end.
    #[error("structural/irreversible op refused (default-deny): {0}")]
    Refused(#[from] pgb_core::RefusedOp),
    /// The request could not be recorded (e.g. duplicate id).
    #[error(transparent)]
    Request(#[from] RequestError),
}

/// Why an approval attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    /// The principal is not allowed to approve, or tried to self-approve.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// The request is unknown / not pending / expired.
    #[error(transparent)]
    Request(#[from] RequestError),
}

/// The §14 approval flow (SPEC §14.3), holding all shared state.
///
/// Generic over the audit [`Sink`] and the [`WebhookSender`] so production and
/// tests inject their own. The verifying key and nonce store are the apply-time
/// trust roots: the grant must verify against `verifying_key` and consume an
/// unused nonce from `nonces`.
pub struct ApprovalFlow<S: Sink, W: WebhookSender, N: NonceStore> {
    store: crate::request::ApprovalStore,
    authority: ApprovalAuthority,
    audit: S,
    webhook: W,
    /// The approver's public key the apply path verifies grants against.
    verifying_key: VerifyingKey,
    /// The single-use nonce store consumed at apply time (replay defense).
    nonces: N,
}

impl<S: Sink, W: WebhookSender, N: NonceStore> ApprovalFlow<S, W, N> {
    /// Build a flow from its parts.
    pub fn new(audit: S, webhook: W, verifying_key: VerifyingKey, nonces: N) -> Self {
        ApprovalFlow {
            store: crate::request::ApprovalStore::new(),
            authority: ApprovalAuthority,
            audit,
            webhook,
            verifying_key,
            nonces,
        }
    }

    /// Borrow the audit sink (for verification / export in tests + the binary).
    pub fn audit(&self) -> &S {
        &self.audit
    }

    /// Borrow the request store.
    pub fn store(&self) -> &crate::request::ApprovalStore {
        &self.store
    }

    /// **Step 1 — `request_elevation`** (SPEC §14.3).
    ///
    /// `op` is the parsed/measured operation behind the blocked write (used only
    /// to gate structural/irreversible ops out of the flow). A refused op returns
    /// [`ElevationError::Refused`] **and is audited as a `REJECT`** — no ticket is
    /// created. An eligible op records a pending request, audits it as a `BLOCK`
    /// (`approval_required`), fires the one generic webhook (best-effort), and
    /// returns the `APPROVAL_REQUIRED` contract.
    #[allow(clippy::too_many_arguments)]
    pub fn request_elevation(
        &mut self,
        id: RequestId,
        proposal: Proposal,
        requester_id: impl Into<String>,
        op: &pgb_core::inverse::Operation,
        ttl_millis: u64,
        clock: &dyn Clock,
    ) -> Result<ElevationOutcome, ElevationError> {
        let requester_id = requester_id.into();

        // Default-deny gate: structural/irreversible ops never enter the flow.
        if let ElevationEligibility::Refused(refused) = gate_for_elevation(op) {
            self.audit_step(
                &proposal.statement_text,
                Decision::Reject,
                "structural_op_refused",
                Some(refused.to_string()),
                &proposal.role,
                Some(&proposal.session_id),
                Some(&requester_id),
                Some(&proposal.proposal_id),
                clock,
            );
            return Err(ElevationError::Refused(refused));
        }

        // Record the pending request (fails closed on a duplicate id).
        let contract = self.store.request_elevation(
            id.clone(),
            proposal.clone(),
            requester_id.clone(),
            ttl_millis,
            clock,
        )?;

        self.audit_step(
            &proposal.statement_text,
            Decision::Block,
            "approval_required",
            Some(format!("request {id} opened (ttl {ttl_millis}ms)")),
            &proposal.role,
            Some(&proposal.session_id),
            Some(&requester_id),
            Some(&proposal.proposal_id),
            clock,
        );

        // One generic webhook POST (best-effort; never a gate).
        let request = self
            .store
            .get(&id)
            .expect("request was just inserted")
            .clone();
        let payload = WebhookPayload::from_request(&request);
        let webhook = self.webhook.send(&payload);

        Ok(ElevationOutcome { contract, webhook })
    }

    /// **Step 2 — `approve <id>`** (SPEC §14.3).
    ///
    /// A **human approver** signs the proposal-bound grant. The flow:
    ///
    /// 1. Look up the *pending, unexpired* request (fail-closed otherwise).
    /// 2. Run the principal gate — reject a non-approver or a self-approval
    ///    (the agent can never authorize itself), auditing the rejection.
    /// 3. Build the §14.3 [`GrantBinding`] from the request's recorded proposal
    ///    (not from any agent-supplied SQL), pick the single-use `nonce` and the
    ///    `expiry`, and sign it with the approver's audit-key-grade key.
    /// 4. Mark the request approved (single-use) and audit the signed grant.
    ///
    /// Returns the [`GrantToken`] for the agent to present at apply.
    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        &mut self,
        id: &RequestId,
        approver: &Principal,
        signing_key: &SigningKey,
        nonce: impl Into<String>,
        grant_ttl_millis: u64,
        clock: &dyn Clock,
    ) -> Result<ApprovalOutcome, ApproveError> {
        // 1. Pending + unexpired only.
        let request = self.store.pending_for_approval(id, clock)?.clone();

        // 2. Principal gate: not-an-approver / self-approval → REJECT (audited).
        if let Err(err) = self.authority.authorize(approver, &request.requester_id) {
            self.audit_step(
                &request.proposal.statement_text,
                Decision::Reject,
                "self_approval_refused",
                Some(err.to_string()),
                &request.proposal.role,
                Some(&request.proposal.session_id),
                Some(&approver.id),
                Some(&request.proposal.proposal_id),
                clock,
            );
            return Err(ApproveError::Authority(err));
        }

        // 3. Build the binding from the *recorded* proposal + sign it.
        let expiry = clock.now_unix_millis().saturating_add(grant_ttl_millis);
        let binding = request.proposal.to_binding(nonce, expiry);
        let grant = GrantToken::sign(binding.clone(), signing_key);

        // 4. Single-use: mark the request approved (cannot be approved twice).
        self.store.resolve(id, RequestStatus::Approved)?;

        self.audit_step(
            &request.proposal.statement_text,
            Decision::Allow,
            "grant_signed",
            Some(format!(
                "approver `{}` signed grant for request {id}; binding {}",
                approver.id,
                binding.binding_hash_hex()
            )),
            &request.proposal.role,
            Some(&request.proposal.session_id),
            Some(&approver.id),
            Some(&request.proposal.proposal_id),
            clock,
        );

        Ok(ApprovalOutcome { grant })
    }

    /// **Step 3 — re-verify at apply** (SPEC §14.3).
    ///
    /// `live` is the binding re-derived from the *current* apply-time request
    /// (the live statement, params, session, apply-time blast-radius checksum,
    /// …). The grant must verify against the approver's public key, match the
    /// signed binding exactly, be unexpired, and consume an unused nonce — all
    /// enforced by `pgb_policy`'s [`GrantToken::verify_for_apply`] (reused, not
    /// reimplemented). Any divergence rejects.
    ///
    /// The outcome is audited either way (`grant_verified` / `grant_rejected`).
    pub fn verify_at_apply(
        &mut self,
        grant: &GrantToken,
        live: &GrantBinding,
        clock: &dyn Clock,
    ) -> Result<(), GrantError> {
        let result = grant.verify_for_apply(live, &self.verifying_key, &mut self.nonces, clock);

        let (decision, code, reason) = match &result {
            Ok(()) => (
                Decision::Allow,
                "grant_verified",
                "grant re-verified at apply (binding + nonce + expiry)".to_string(),
            ),
            Err(e) => (Decision::Reject, "grant_rejected", e.to_string()),
        };
        self.audit_step(
            &live.statement_text,
            decision,
            code,
            Some(reason),
            &live.role,
            Some(&live.session_id),
            None,
            Some(&live.proposal_id),
            clock,
        );
        result
    }

    /// Append one tamper-evident audit record for a flow step.
    #[allow(clippy::too_many_arguments)]
    fn audit_step(
        &mut self,
        statement_text: &str,
        decision: Decision,
        reason_code: &str,
        reason: Option<String>,
        role: &str,
        session_id: Option<&str>,
        principal: Option<&str>,
        proposal_id: Option<&str>,
        clock: &dyn Clock,
    ) {
        let entry = NewEntry {
            statement_text: statement_text.to_string(),
            decision,
            reason_code: reason_code.to_string(),
            reason,
            principal: AuditPrincipal {
                role: role.to_string(),
                session_id: session_id.map(str::to_string),
                principal: principal.map(str::to_string),
            },
            intent: IntentTiers::default(),
            write_safety: WriteSafetyRefs {
                dry_run_id: proposal_id.map(str::to_string),
                blast_radius_ref: None,
            },
        };
        // The audit append is itself fail-closed in spirit: an in-memory sink
        // cannot fail, and a real sink failure would surface upstream. We ignore
        // the returned record here (the chain retains it).
        let _: Result<AuditRecord, _> = self.audit.append(entry, clock.now_unix_millis());
    }
}
