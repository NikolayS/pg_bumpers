//! Structural / irreversible ops are **default-deny REFUSED** — break-glass is
//! unreachable in the MVP (SPEC §14.3 MVP safety note, §10.3).
//!
//! The §14 approval flow only ever unblocks *parameter-class* floor blocks
//! (SPEC §14.2: "a row/cost budget the human can raise … runs still reversibly
//! under the higher bound"). A **structural / irreversible** op
//! (`TRUNCATE`/`DROP`/`ALTER`/no-inverse/PK-less) is in the default-deny refused
//! set (SPEC §10.3); break-glass for it is **deferred to fast-follow**, so in the
//! MVP there is *no grant that can authorize it*.
//!
//! [`gate_for_elevation`] is the choke point a blocked write passes through
//! before [`crate::request::ApprovalStore::request_elevation`]. It delegates to
//! the core default-deny certifier ([`pgb_core::inverse::certify`]) — the single
//! source of truth for the certified action set — and translates the outcome:
//!
//! - a **certified** (bounded + reversible) op ⇒ [`ElevationEligibility::Eligible`]:
//!   an approval request may be opened.
//! - a **refused** op ⇒ [`ElevationEligibility::Refused`]: no request, no grant,
//!   ever. The agent gets a terminal `REFUSED`, not an `APPROVAL_REQUIRED`.
//!
//! Reusing `core::certify` (rather than re-encoding the list here) means the CLI
//! can never drift from the rest of the system about what is irreversible.

use pgb_core::inverse::{Operation, certify};
use pgb_core::{CertifiedAction, RefusedOp};

/// Whether a blocked op may be routed to the approval flow at all (SPEC §14.2 /
/// §14.3 MVP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationEligibility {
    /// The op is in the certified (bounded + reversible) set — a human may
    /// approve a higher bound and it applies reversibly. Carries the certified
    /// action for the audit log.
    Eligible(CertifiedAction),
    /// The op is structural / irreversible — default-deny. No approval request
    /// is created and no grant can authorize it in the MVP. Carries the refusal
    /// reason for the audit log.
    Refused(RefusedOp),
}

impl ElevationEligibility {
    /// Whether elevation is permitted (the op may enter the approval flow).
    pub fn is_eligible(&self) -> bool {
        matches!(self, ElevationEligibility::Eligible(_))
    }
}

/// The break-glass machine code (terminal; never an `APPROVAL_REQUIRED`).
///
/// A structural / irreversible op blocked by the floor returns this — it is a
/// dead end in the MVP, by design (SPEC §14.3 MVP safety note).
pub const REFUSED_CODE: &str = "REFUSED";

/// Gate a blocked op for the approval flow (SPEC §14.2/§14.3, §10.3).
///
/// Returns [`ElevationEligibility::Refused`] for any op the default-deny
/// certifier rejects (structural / irreversible / no-inverse / PK-less), and
/// [`ElevationEligibility::Eligible`] only for the closed certified set. This is
/// the single point that decides whether an `APPROVAL_REQUIRED` ticket may be
/// opened, so an irreversible op can never reach the grant-signing path.
pub fn gate_for_elevation(op: &Operation) -> ElevationEligibility {
    match certify(op) {
        Ok(action) => ElevationEligibility::Eligible(action),
        Err(refused) => ElevationEligibility::Refused(refused),
    }
}
