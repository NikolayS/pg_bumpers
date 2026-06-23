//! The approval **request** + the `APPROVAL_REQUIRED` block contract (SPEC §14.3,
//! §14.4).
//!
//! When the deterministic floor blocks a *parameter-class* write (e.g. a
//! row/byte budget the human can raise — SPEC §14.2), the block is not a dead
//! end: it returns an [`ApprovalRequired`] contract carrying a **request id** and
//! a **TTL**. `request_elevation` records the request in an [`ApprovalStore`];
//! the human later runs `approve <id>` to sign a grant bound to *exactly* this
//! request's proposal.
//!
//! The request captures the full proposal binding — the §14.3 fields
//! `{statement, params, role, session, proposal_id, dry_run_lsn, cap, nonce,
//! expiry}` — so the grant the approver signs binds to the request's recorded
//! proposal, not to whatever SQL the agent later presents at apply time. That is
//! what makes the flow TOCTOU-safe end to end. (EPIC #91 PR-B: the absolute
//! [`WriteCap`] `cap` the human approves replaced the dropped exact-PK-set
//! `blast_radius_checksum`.)
//!
//! Time is read only through `core::Clock` (no wall clock), so request creation,
//! TTL expiry, and grant expiry are all deterministic in tests.

use pgb_core::{Clock, WriteCap};
use pgb_policy::GrantBinding;
use serde::{Deserialize, Serialize};

/// A unique approval-request id (the ticket the agent polls on — SPEC §14.4).
///
/// A newtype over `String` so it can't be confused with a proposal id, a nonce,
/// or any other identifier in the flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequestId(pub String);

impl RequestId {
    /// Borrow the id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The proposal a request is asking to elevate (SPEC §14.3 binding fields).
///
/// This is everything the approver authorizes and everything the apply-time
/// re-verification re-derives. It holds the nine bound fields directly — the
/// same nine that [`GrantBinding`] covers — plus the database role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// The proposal id (links a request back to a dry-run / blast-radius
    /// record).
    pub proposal_id: String,
    /// The exact statement text the agent proposed.
    pub statement_text: String,
    /// The normalized prepared-statement parameters, in order.
    pub normalized_params: Vec<String>,
    /// The database role the statement would run as.
    pub role: String,
    /// The session / principal id this proposal originated from.
    pub session_id: String,
    /// The clone LSN the dry-run ran against (SPEC §10.1).
    pub dry_run_lsn: String,
    /// The **absolute apply-time cap** (EPIC #91 PR-B) the approver authorizes — the
    /// magnitude anchor that replaced the dropped exact-PK-set `blast_radius_checksum`.
    /// Pre-filled from the dry-run's measured footprint plus headroom
    /// ([`pgb_core::BlastRadius::suggested_cap`]); the approver may tighten or raise it
    /// per §14.2 before signing.
    pub cap: WriteCap,
}

impl Proposal {
    /// Build the §14.3 [`GrantBinding`] for this proposal, given the single-use
    /// `nonce` and the absolute `expiry` instant the approver chose. The result
    /// is exactly what gets signed and, later, re-derived at apply time.
    pub fn to_binding(&self, nonce: impl Into<String>, expiry_unix_millis: u64) -> GrantBinding {
        GrantBinding {
            statement_text: self.statement_text.clone(),
            normalized_params: self.normalized_params.clone(),
            role: self.role.clone(),
            session_id: self.session_id.clone(),
            proposal_id: self.proposal_id.clone(),
            dry_run_lsn: self.dry_run_lsn.clone(),
            cap: self.cap,
            nonce: nonce.into(),
            expiry_unix_millis,
        }
    }

    /// Override the approved cap (the approver tightening or raising it per §14.2)
    /// before signing. Returns `self` for chaining.
    pub fn with_cap(mut self, cap: WriteCap) -> Self {
        self.cap = cap;
        self
    }
}

/// The state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestStatus {
    /// Awaiting an approver decision.
    Pending,
    /// Approved — a grant has been signed for it (single-use: it cannot be
    /// approved again).
    Approved,
    /// Explicitly denied by an approver.
    Denied,
}

/// A recorded approval request (SPEC §14.3/§14.4).
///
/// Created by `request_elevation`, looked up by `approve <id>`. It carries the
/// [`Proposal`], the requester principal id (for the self-approval guard), its
/// creation time and TTL (for expiry), and its current [`RequestStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The request id (the ticket).
    pub id: RequestId,
    /// The proposal this request is asking to elevate.
    pub proposal: Proposal,
    /// The id of the requester (agent / DB-operator) that opened the request.
    /// Compared against the approver id to forbid self-approval.
    pub requester_id: String,
    /// When the request was created (unix millis, from `core::Clock`).
    pub created_unix_millis: u64,
    /// The request TTL in milliseconds: after `created + ttl` the request is
    /// expired and cannot be approved.
    pub ttl_millis: u64,
    /// Current status.
    pub status: RequestStatus,
}

impl ApprovalRequest {
    /// The absolute instant (unix millis) at which this request expires.
    pub fn expires_at(&self) -> u64 {
        self.created_unix_millis.saturating_add(self.ttl_millis)
    }

    /// Whether the request has expired as of `now_unix_millis`.
    pub fn is_expired(&self, now_unix_millis: u64) -> bool {
        now_unix_millis >= self.expires_at()
    }
}

/// The `APPROVAL_REQUIRED` block contract returned to a blocked agent
/// (SPEC §14.3 — "Block returns `APPROVAL_REQUIRED` + a remedy with an
/// approval-request id (TTL)").
///
/// This is the structured, recoverable next step (the §2 self-correcting-agent
/// story): the agent gets the ticket id and the TTL and knows to await a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequired {
    /// The stable machine code (`"APPROVAL_REQUIRED"`).
    pub code: String,
    /// The request id to poll / pass to `approve`.
    pub request_id: RequestId,
    /// The absolute expiry instant (unix millis) of the request.
    pub expires_at_unix_millis: u64,
    /// A human-readable remedy line.
    pub remedy: String,
}

/// The machine code carried by every [`ApprovalRequired`] block contract.
pub const APPROVAL_REQUIRED_CODE: &str = "APPROVAL_REQUIRED";

/// Errors creating or resolving an approval request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// A request with this id already exists (ids must be unique).
    #[error("duplicate request id: `{0}`")]
    DuplicateId(String),
    /// No request exists for the given id.
    #[error("unknown request id: `{0}`")]
    UnknownId(String),
    /// The request is not in [`RequestStatus::Pending`] (already approved or
    /// denied — single-use).
    #[error("request `{0}` is not pending (already resolved)")]
    NotPending(String),
    /// The request's TTL has elapsed.
    #[error("request `{id}` expired at {expires_at}ms (now={now}ms)")]
    Expired {
        /// The request id.
        id: String,
        /// The request's expiry instant.
        expires_at: u64,
        /// The clock reading at the failed operation.
        now: u64,
    },
}

/// An in-memory store of approval requests (SPEC §14.3 — proposal/ticket state,
/// TTL).
///
/// Production backs this with `core` state + the tamper-evident audit; this
/// in-memory store is the deterministic reference used by the CLI binary
/// single-process and by the tests. State is keyed by [`RequestId`].
#[derive(Debug, Default)]
pub struct ApprovalStore {
    requests: std::collections::BTreeMap<RequestId, ApprovalRequest>,
}

impl ApprovalStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        ApprovalStore {
            requests: std::collections::BTreeMap::new(),
        }
    }

    /// **`request_elevation`** (SPEC §14.3): record a new pending request for a
    /// blocked write and return the `APPROVAL_REQUIRED` block contract the agent
    /// receives.
    ///
    /// Time is read from `clock` so creation + TTL are deterministic. Fails if
    /// the id is already in use (fail-closed: never silently overwrite an
    /// existing ticket).
    pub fn request_elevation(
        &mut self,
        id: RequestId,
        proposal: Proposal,
        requester_id: impl Into<String>,
        ttl_millis: u64,
        clock: &dyn Clock,
    ) -> Result<ApprovalRequired, RequestError> {
        if self.requests.contains_key(&id) {
            return Err(RequestError::DuplicateId(id.0));
        }
        let now = clock.now_unix_millis();
        let request = ApprovalRequest {
            id: id.clone(),
            proposal,
            requester_id: requester_id.into(),
            created_unix_millis: now,
            ttl_millis,
            status: RequestStatus::Pending,
        };
        let contract = ApprovalRequired {
            code: APPROVAL_REQUIRED_CODE.to_string(),
            request_id: id.clone(),
            expires_at_unix_millis: request.expires_at(),
            remedy: format!(
                "blocked: a human must approve. run `pgb-cli approve {id}` before \
                 the request expires, then retry apply"
            ),
        };
        self.requests.insert(id, request);
        Ok(contract)
    }

    /// Look up a request by id.
    pub fn get(&self, id: &RequestId) -> Option<&ApprovalRequest> {
        self.requests.get(id)
    }

    /// Fetch a *pending, unexpired* request by id, ready to be approved.
    ///
    /// Returns [`RequestError::UnknownId`] / [`NotPending`](RequestError::NotPending)
    /// / [`Expired`](RequestError::Expired) as appropriate — all fail-closed.
    pub fn pending_for_approval(
        &self,
        id: &RequestId,
        clock: &dyn Clock,
    ) -> Result<&ApprovalRequest, RequestError> {
        let request = self
            .requests
            .get(id)
            .ok_or_else(|| RequestError::UnknownId(id.0.clone()))?;
        if request.status != RequestStatus::Pending {
            return Err(RequestError::NotPending(id.0.clone()));
        }
        let now = clock.now_unix_millis();
        if request.is_expired(now) {
            return Err(RequestError::Expired {
                id: id.0.clone(),
                expires_at: request.expires_at(),
                now,
            });
        }
        Ok(request)
    }

    /// Mark a request resolved (approved / denied). Single-use: a request can
    /// only transition out of [`Pending`](RequestStatus::Pending) once.
    pub fn resolve(&mut self, id: &RequestId, status: RequestStatus) -> Result<(), RequestError> {
        let request = self
            .requests
            .get_mut(id)
            .ok_or_else(|| RequestError::UnknownId(id.0.clone()))?;
        if request.status != RequestStatus::Pending {
            return Err(RequestError::NotPending(id.0.clone()));
        }
        request.status = status;
        Ok(())
    }
}
