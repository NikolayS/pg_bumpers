//! PostgreSQL **wire-protocol layer** for pg_bumpers (SPEC §3 layer 2, §4, §7 S1).
//!
//! This crate gives the proxy byte-level control over the FE/BE message loop so
//! it can enforce the deterministic floor: force the **extended protocol**
//! (kills `SELECT 1; DROP …` statement-stacking), **reject** simple-query and
//! `COPY`, and cut a session off mid-stream. It is a **clean-room** v3 codec
//! built from the protocol spec and the public `sqlparser` AST — no pgDog
//! (AGPL) code was consulted or copied.
//!
//! # Modules
//! - [`codec`] — async length-prefixed framing over a `tokio` stream
//!   ([`codec::RawFrame`], [`codec::read_tagged_frame`], …).
//! - [`frontend`] — client→server messages: [`frontend::StartupMessage`],
//!   [`frontend::SslRequest`], [`frontend::FrontendMessage`] (Query / Parse /
//!   Bind / Describe / Execute / Sync / Close / Copy* / password+SASL).
//! - [`backend`] — server→client messages: [`backend::BackendMessage`]
//!   (Authentication* incl. SASL, ParameterStatus, BackendKeyData,
//!   ReadyForQuery, ErrorResponse, RowDescription, DataRow, CommandComplete,
//!   PortalSuspended, Copy*).
//! - [`scram`] — SASL/SCRAM-SHA-256 message bodies.
//! - [`detector`] — tag-only rejection of simple-query/COPY frames.
//! - [`classifier`] — advisory, **fail-closed** read-only SQL classification.
//! - [`error`] — the [`error::ProtocolError`] type (every malformed frame is a
//!   hard error — fail-closed).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod buf;

pub mod backend;
pub mod classifier;
pub mod codec;
pub mod detector;
pub mod error;
pub mod frontend;
pub mod scram;

pub use backend::BackendMessage;
pub use classifier::{classify, classify_with_reason, Classification, NotReadReason};
pub use codec::{read_startup_body, read_tagged_frame, write_frame, RawFrame, MAX_FRAME_LEN};
pub use detector::{
    backend_starts_copy, classify_frontend_frame, classify_frontend_tag, RejectReason,
};
pub use error::ProtocolError;
pub use frontend::{FrontendMessage, SslRequest, StartupMessage};

/// Which PostgreSQL query protocol a connection is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMode {
    /// Simple query protocol — permits statement-stacking; rejected for agents.
    Simple,
    /// Extended (parse/bind/execute) protocol — the only mode the proxy allows.
    Extended,
}

impl ProtocolMode {
    /// Whether this mode is permitted for an agent connection.
    ///
    /// Fail-closed: only the extended protocol is allowed, because the simple
    /// protocol enables `COMMIT; DROP SCHEMA ...` statement-stacking bypasses.
    pub fn is_allowed_for_agent(self) -> bool {
        matches!(self, ProtocolMode::Extended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_extended_protocol_is_allowed_for_agents() {
        assert!(ProtocolMode::Extended.is_allowed_for_agent());
        // Simple query protocol must be rejected (anti statement-stacking).
        assert!(!ProtocolMode::Simple.is_allowed_for_agent());
    }
}
