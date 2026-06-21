//! Audit sinks: the append-only write target for sealed records (SPEC §4).
//!
//! A [`Sink`] is *append-only* — there is intentionally no update or delete in
//! the trait, because the audit log must be immutable evidence. The two MVP
//! implementations are:
//!
//! - [`InMemorySink`] — wraps an [`AuditChain`]; used by unit tests and as the
//!   reference for the chain semantics.
//! - the Postgres `_meta` sink ([`crate::pg`]) — appends to an append-only
//!   table whose grants `REVOKE` write from the audited principal.
//!
//! Both stamp time from `core::Clock` (passed in by the caller), so no sink
//! reads a wall clock itself and tests are fully deterministic.

use crate::chain::{AuditChain, ChainBreak, NewEntry};
use crate::record::AuditRecord;

/// Errors a sink can surface while appending or reading back the chain.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// A backend (e.g. Postgres) returned an error.
    #[error("audit sink backend error: {0}")]
    Backend(String),
    /// The chain read back from the sink failed verification.
    #[error("audit chain integrity broken: {0:?}")]
    Integrity(ChainBreak),
}

/// An append-only audit sink.
///
/// The contract is deliberately minimal: append a sealed record, read the chain
/// back, and verify it. There is **no** mutation or deletion method — the audit
/// log is write-once, and tamper-evidence assumes the only legitimate operation
/// is append.
pub trait Sink {
    /// Append a new entry, stamping it at `timestamp_ms` (from `core::Clock`),
    /// and return the sealed record that was stored.
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError>;

    /// Read the full chain back, oldest first, for verification / export.
    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError>;

    /// Verify the persisted chain's integrity, returning the first broken link.
    fn verify(&self) -> Result<(), SinkError> {
        crate::chain::verify_chain(&self.load_chain()?).map_err(SinkError::Integrity)
    }
}

/// An in-memory append-only sink backed by an [`AuditChain`].
///
/// Used by unit tests and as the semantic reference for the persistent sink:
/// the bytes it stores are identical to what the Postgres sink stores, so a
/// chain appended here verifies the same way as one read from `_meta`.
#[derive(Debug, Clone, Default)]
pub struct InMemorySink {
    chain: AuditChain,
}

impl InMemorySink {
    /// A fresh, empty in-memory sink.
    pub fn new() -> Self {
        InMemorySink {
            chain: AuditChain::new(),
        }
    }

    /// Borrow the underlying chain (for `head_hash`/`len`/etc.).
    pub fn chain(&self) -> &AuditChain {
        &self.chain
    }
}

impl Sink for InMemorySink {
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError> {
        Ok(self.chain.append(entry, timestamp_ms))
    }

    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError> {
        Ok(self.chain.records().to_vec())
    }
}
