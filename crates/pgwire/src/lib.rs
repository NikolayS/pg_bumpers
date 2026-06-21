//! PostgreSQL wire-protocol helpers for pg_bumpers.
//!
//! The proxy forces the extended protocol to kill statement-stacking and
//! rejects simple-query / COPY fallback (SPEC §3 layer 2, §4). This crate will
//! own the FE/BE message handling; for S0 it carries the protocol-mode marker
//! and the fail-closed default so other crates can reference a stable type.

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
