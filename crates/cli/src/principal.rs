//! Principals in the approval flow + the **agent-can-never-self-authorize**
//! guard (SPEC §14.1).
//!
//! The whole point of the §14 authorization flow is that a *blocked* action is
//! routed to a **human** who authenticates **independently of the agent**. The
//! agent that proposed the write — or the DB-operator principal it runs as —
//! must never be able to sign its own grant. We model this with two principal
//! *kinds*:
//!
//! - [`PrincipalKind::Requester`] — the agent / DB-operator that proposed the
//!   blocked write and created the elevation request. It can call
//!   `request_elevation`, never `approve`.
//! - [`PrincipalKind::Approver`] — a human approver holding an audit-key-grade
//!   signing key (§10.9). Only this kind may sign a grant.
//!
//! [`ApprovalAuthority::authorize`] is the single choke point: it rejects a
//! self-approval (the approver id equals the request's requester id) and rejects
//! any non-approver principal. This is the deterministic, fail-closed gate that
//! makes T-self-auth (SPEC §5) impossible — there is no code path by which a
//! requester principal mints a grant.

use serde::{Deserialize, Serialize};

/// What role a principal plays in the approval flow.
///
/// The kind is **structural**, not advisory: only an [`Approver`](Self::Approver)
/// can reach the signing path, and the choke point additionally forbids an
/// approver whose identity coincides with the request's requester (one-person,
/// two-hats self-approval).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalKind {
    /// The agent / DB-operator that proposed the blocked write. May *request*
    /// elevation; may **never** approve.
    Requester,
    /// A human approver holding the audit-key-grade CLI signing key (§10.9).
    /// The only kind permitted to sign a grant.
    Approver,
}

/// A principal in the approval flow: a stable id + its [`PrincipalKind`].
///
/// The `id` is the identity the audit log records and the self-approval guard
/// compares. For a requester it is the agent/session principal; for an approver
/// it is the human/key identity (resolved out-of-band from KMS / a keyring,
/// §10.9). The two namespaces are compared directly, so an attacker cannot
/// self-approve by reusing the agent id under an approver label — the guard
/// catches the id collision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The stable identity string (agent/session id, or human/key id).
    pub id: String,
    /// Whether this principal may request or approve.
    pub kind: PrincipalKind,
}

impl Principal {
    /// A requester principal (the agent / DB-operator).
    pub fn requester(id: impl Into<String>) -> Self {
        Principal {
            id: id.into(),
            kind: PrincipalKind::Requester,
        }
    }

    /// An approver principal (a human holding the signing key).
    pub fn approver(id: impl Into<String>) -> Self {
        Principal {
            id: id.into(),
            kind: PrincipalKind::Approver,
        }
    }

    /// Whether this principal is allowed to *approve* (sign a grant).
    pub fn can_approve(&self) -> bool {
        matches!(self.kind, PrincipalKind::Approver)
    }
}

/// Why an authorization attempt was refused at the principal gate (SPEC §14.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// The principal attempting to approve is not an approver (e.g. the agent /
    /// DB-operator tried to sign its own grant by claiming the approver role).
    #[error("not an approver: principal `{0}` may not authorize (only a human approver can)")]
    NotAnApprover(String),
    /// The approver's identity is the **same** as the request's requester — a
    /// one-person self-approval. Forbidden (SPEC §14.1: the agent can never
    /// authorize itself).
    #[error(
        "self-approval refused: approver `{0}` is the same identity as the requester \
         (the agent can never authorize itself)"
    )]
    SelfApproval(String),
}

/// The deterministic, fail-closed principal gate (SPEC §14.1).
///
/// [`authorize`](Self::authorize) is the *only* path to a signing decision; it
/// must pass before any grant is minted. It encodes two rules, both denials:
///
/// 1. the actor must be an [`Approver`](PrincipalKind::Approver), and
/// 2. the approver id must differ from the request's requester id.
///
/// Either failure returns an [`AuthorityError`] and no grant is produced.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApprovalAuthority;

impl ApprovalAuthority {
    /// Decide whether `approver` may authorize a request that was opened by
    /// `requester_id`. Fail-closed: any doubt denies.
    pub fn authorize(
        &self,
        approver: &Principal,
        requester_id: &str,
    ) -> Result<(), AuthorityError> {
        if !approver.can_approve() {
            return Err(AuthorityError::NotAnApprover(approver.id.clone()));
        }
        if approver.id == requester_id {
            return Err(AuthorityError::SelfApproval(approver.id.clone()));
        }
        Ok(())
    }
}
