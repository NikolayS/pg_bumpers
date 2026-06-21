//! Tamper-evident audit for pg_bumpers (SPEC §3, §4, §5, §10.9; issue #21).
//!
//! Append-only, **hash-chained** records record *every* statement the proxy
//! sees — including the ones it blocks or rejects — so the audit log is the
//! tamper-evident evidence that a hostile statement was stopped. Each record is
//! linked to its predecessor by
//! `record_hash = sha256(prev_hash ∥ canonical_encoding(record))`, anchored at a
//! defined [`GENESIS_PREV_HASH`](record::GENESIS_PREV_HASH). Editing or deleting
//! any mid-chain record breaks the chain, and [`verify_chain`](chain::verify_chain)
//! returns the **first** broken link.
//!
//! The chain lives in the `_meta` DB on an append-only table whose grants
//! `REVOKE` write from the audited principal — "the audited cannot write audit"
//! (SPEC §3/§4/§10.9). The external WORM **anchor** + KMS **key-separation** are
//! S4 (this S1 crate ships the chain + recording + the `_meta` schema + the
//! REVOKE).
//!
//! # Modules
//! - [`record`] — the [`AuditRecord`]/[`AuditPayload`], the [`Decision`] enum
//!   (`ALLOW`/`BLOCK`/`REJECT`), the canonical encoding, and the chain hash.
//! - [`chain`] — the append-only [`AuditChain`] builder and
//!   [`verify_chain`](chain::verify_chain) (the tamper detector).
//! - [`sink`] — the append-only [`Sink`] trait + the [`InMemorySink`].
//! - [`pg`] — the Postgres `_meta` sink (behind the default-on `pg` feature).
//!
//! Time is always read from `core::Clock` upstream and passed in as a
//! millisecond stamp, so no part of the crate touches a wall clock and tests
//! are fully deterministic via `core::MockClock`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chain;
pub mod record;
pub mod sink;

#[cfg(feature = "pg")]
pub mod pg;

pub use chain::{verify_chain, AuditChain, ChainBreak, NewEntry};
pub use record::{
    AuditPayload, AuditRecord, Decision, IntentTiers, Principal, WriteSafetyRefs, GENESIS_PREV_HASH,
};
pub use sink::{InMemorySink, Sink, SinkError};

#[cfg(feature = "pg")]
pub use pg::PgSink;
