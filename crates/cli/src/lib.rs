//! pg_bumpers CLI approval flow (SPEC §14 MVP mechanism).
//!
//! This is the **MVP authorization surface** (SPEC §14.3): a blocked write is
//! routed to a human who approves it on the CLI, emitting a **signed, single-use,
//! time-boxed, proposal-bound grant** that is re-verified at apply time. The
//! agent can **never authorize itself** (SPEC §14.1), and structural/irreversible
//! ops are **default-deny refused** so break-glass is unreachable in the MVP
//! (SPEC §14.3 MVP safety note, §10.3).
//!
//! The load-bearing TOCTOU-safe grant token lives in [`pgb_policy::grant`]; this
//! crate **reuses** it (the binding hash, the Ed25519 sign/verify, the nonce
//! store, the clock) rather than reimplementing any cryptography. What lives here
//! is the *flow* around it:
//!
//! - [`request`] — the `APPROVAL_REQUIRED` block contract + the TTL'd request
//!   store (`request_elevation`).
//! - [`principal`] — the principal model + the agent-can-never-self-authorize
//!   gate (`approve` is approver-only and forbids self-approval).
//! - [`refuse`] — the structural/irreversible default-deny gate (reuses
//!   `pgb_core::certify`).
//! - [`webhook`] — the one generic webhook POST of the request payload.
//! - [`flow`] — the [`ApprovalFlow`] that wires request → approve → verify-at-apply
//!   and **audits every step** (`pgb_audit`).
//!
//! The deterministic floor — not this flow — remains the safety guarantee; the
//! grant only ever *raises a parameter bound* for an already-reversible write
//! (SPEC §14.2), and it can never loosen the floor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod flow;
pub mod principal;
pub mod refuse;
pub mod request;
pub mod webhook;

pub use flow::{ApprovalFlow, ApprovalOutcome, ApproveError, ElevationError, ElevationOutcome};
pub use principal::{ApprovalAuthority, AuthorityError, Principal, PrincipalKind};
pub use refuse::{gate_for_elevation, ElevationEligibility, REFUSED_CODE};
pub use request::{
    ApprovalRequest, ApprovalRequired, ApprovalStore, Proposal, RequestError, RequestId,
    RequestStatus, APPROVAL_REQUIRED_CODE,
};
pub use webhook::{
    HttpWebhookSender, RecordingWebhookSender, WebhookError, WebhookPayload, WebhookSender,
    WEBHOOK_EVENT,
};

// Re-export the reused grant primitives so callers (and the binary) get them
// from one place without each reaching into `pgb_policy`.
pub use pgb_policy::{GrantBinding, GrantError, GrantToken, InMemoryNonceStore, NonceStore};
