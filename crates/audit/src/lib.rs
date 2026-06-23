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
//! (SPEC §3/§4/§10.9). S1 shipped the chain + recording + the `_meta` schema +
//! the REVOKE. **S4 (this addition)** closes the full-chain-rewrite gap with an
//! external WORM **anchor** of the chain head, signed by a **KMS-separated** key
//! the DB operator cannot reach, loaded from a **secret store** with documented
//! rotation (SPEC §10.9).
//!
//! # Modules
//! - [`record`] — the [`AuditRecord`]/[`AuditPayload`], the [`Decision`] enum
//!   (`ALLOW`/`BLOCK`/`REJECT`), the canonical encoding, and the chain hash.
//! - [`chain`] — the append-only [`AuditChain`] builder and
//!   [`verify_chain`](chain::verify_chain) (the within-chain tamper detector).
//! - [`sink`] — the append-only [`Sink`] trait + the [`InMemorySink`].
//! - [`pg`] — the Postgres `_meta` sink (behind the default-on `pg` feature).
//! - [`secret`] — the [`SecretStore`](secret::SecretStore) seam for DSNs + the
//!   audit signing key, with rotation (S4).
//! - [`kms`] — the [`Kms`](kms::Kms) signing seam; the signer is **separated
//!   from the DB operator** at the type level and by principal check (S4).
//! - [`anchor`] — the interval-driven external WORM/transparency anchor of the
//!   chain head; [`verify_against_anchor`](anchor::verify_against_anchor) catches
//!   a *full-chain rewrite* that the within-chain check cannot (S4).
//! - [`boot`] — (S5, behind `pg`) the wiring that gives the proxy + CLI **one**
//!   shared, persistent, anchored `_meta` chain: it constructs the [`SharedSink`]
//!   over the Postgres `_meta` sink, runs the interval [`Anchorer`] over it, and
//!   performs the **fail-closed startup verification** against the anchored head.
//!
//! Time is always read from `core::Clock` upstream and passed in as a
//! millisecond stamp, so no part of the crate touches a wall clock and tests
//! are fully deterministic via `core::MockClock`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anchor;
pub mod chain;
pub mod kms;
pub mod record;
pub mod secret;
pub mod sink;

#[cfg(feature = "pg")]
pub mod boot;

#[cfg(feature = "pg")]
pub mod pg;

pub use anchor::{
    AnchorEntry, AnchorError, AnchorVerification, Anchored, Anchorer, WormAnchor, WormAnchorError,
    head_of, verify_against_anchor, verify_against_anchor_with, verify_records_against_anchor,
    verify_records_against_anchor_with,
};
pub use chain::{AuditChain, ChainBreak, NewEntry, verify_chain};
pub use kms::{HeadSignature, Kms, KmsError, LocalKms, OPERATOR_PRINCIPAL};
pub use record::{
    AuditPayload, AuditRecord, Decision, GENESIS_PREV_HASH, IntentTiers, Principal, WriteSafetyRefs,
};
pub use secret::{AUDIT_SIGNING_KEY_ID, LocalSecretStore, SecretError, SecretStore};
pub use sink::{InMemorySink, SharedSink, Sink, SinkError};

#[cfg(feature = "pg")]
pub use boot::{AnchorRole, AuditBoot, BootError};

#[cfg(feature = "pg")]
pub use pg::{AUDIT_CHAIN_LOCK_KEY, PgSink};
