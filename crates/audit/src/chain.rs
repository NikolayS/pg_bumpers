//! The hash chain: building, appending, and **verification** that detects any
//! edited or deleted mid-chain record (SPEC §5 "hash-chain integrity +
//! tamper-injection", §10.9 root-of-trust).
//!
//! Two independent invariants make tampering detectable:
//!
//! 1. **Self-consistency** — each record's stored `record_hash` must equal
//!    `sha256(prev_hash ∥ canonical(payload))`. Editing any hashed field breaks
//!    this on that record.
//! 2. **Linkage** — each record's `prev_hash` must equal the previous record's
//!    `record_hash`, and `seq` must increase by exactly one. Deleting a record
//!    (or reordering) breaks the linkage at the gap, even though every
//!    *surviving* record is still individually self-consistent.
//!
//! [`verify_chain`] returns the **first** broken link as a [`ChainBreak`], so a
//! caller (and a test) learns exactly where the chain was attacked.

use crate::record::{AuditPayload, AuditRecord, Decision, GENESIS_PREV_HASH, Hash};

/// The first place a chain fails verification, with enough context to point at
/// the attacked record. `index` is the position in the verified slice; `seq` is
/// the record's own claimed sequence number (they diverge when a record was
/// deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// The genesis record's `prev_hash` is not [`GENESIS_PREV_HASH`] — the
    /// chain does not start where it must (a replaced/forged head).
    BadGenesis {
        /// Slice index of the offending record (always 0).
        index: usize,
        /// The `prev_hash` the genesis record actually carried.
        found_prev_hash: Hash,
    },
    /// A record's stored `record_hash` does not match the hash recomputed from
    /// its payload — the record's **content was edited** in place.
    HashMismatch {
        /// Slice index of the tampered record.
        index: usize,
        /// The record's claimed `seq`.
        seq: u64,
        /// The `record_hash` stored on the record.
        stored_hash: Hash,
        /// The hash recomputed from the (tampered) payload.
        recomputed_hash: Hash,
    },
    /// A record's `prev_hash` does not equal the previous record's
    /// `record_hash` — the link is **broken** (a record was deleted, inserted,
    /// or reordered between them).
    BrokenLink {
        /// Slice index of the record whose back-link is wrong.
        index: usize,
        /// The record's claimed `seq`.
        seq: u64,
        /// The `prev_hash` this record carries.
        expected_prev_hash: Hash,
        /// The actual `record_hash` of the preceding record.
        actual_prev_hash: Hash,
    },
    /// A record's `seq` is not exactly one more than its predecessor's — the
    /// sequence has a **gap or repeat** (a deleted/duplicated record). Linkage
    /// usually catches a deletion first; this catches the case where seqs alone
    /// are inspected and pinpoints the gap.
    SeqGap {
        /// Slice index of the record with the bad seq.
        index: usize,
        /// The `seq` expected (predecessor + 1).
        expected_seq: u64,
        /// The `seq` actually found.
        found_seq: u64,
    },
}

/// Verify a slice of records as a well-formed hash chain.
///
/// Returns `Ok(())` if the chain is intact, or `Err(ChainBreak)` describing the
/// **first** broken link. An empty slice is a valid (empty) chain.
///
/// The check is purely a function of the records' bytes — it needs no DB, no
/// clock, and no external state — so it is deterministic and can run over rows
/// pulled from the `_meta` sink or over the in-memory chain identically.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), ChainBreak> {
    let mut prev: Option<&AuditRecord> = None;
    for (index, record) in records.iter().enumerate() {
        // (1) Self-consistency: stored hash must match recomputed hash.
        let recomputed = record.payload.compute_hash();
        if recomputed != record.record_hash {
            return Err(ChainBreak::HashMismatch {
                index,
                seq: record.payload.seq,
                stored_hash: record.record_hash.clone(),
                recomputed_hash: recomputed,
            });
        }

        match prev {
            None => {
                // (2a) Genesis must anchor at the defined genesis prev-hash.
                if record.payload.prev_hash != GENESIS_PREV_HASH {
                    return Err(ChainBreak::BadGenesis {
                        index,
                        found_prev_hash: record.payload.prev_hash.clone(),
                    });
                }
            }
            Some(previous) => {
                // (2b) Sequence must increase by exactly one (gap/repeat = a
                // deleted or duplicated record).
                let expected_seq = previous.payload.seq + 1;
                if record.payload.seq != expected_seq {
                    return Err(ChainBreak::SeqGap {
                        index,
                        expected_seq,
                        found_seq: record.payload.seq,
                    });
                }
                // (2c) Back-link must point at the predecessor's record_hash.
                if record.payload.prev_hash != previous.record_hash {
                    return Err(ChainBreak::BrokenLink {
                        index,
                        seq: record.payload.seq,
                        expected_prev_hash: record.payload.prev_hash.clone(),
                        actual_prev_hash: previous.record_hash.clone(),
                    });
                }
            }
        }
        prev = Some(record);
    }
    Ok(())
}

/// An in-memory, append-only hash chain (SPEC §4).
///
/// This is the canonical chain builder: it stamps each appended payload with
/// the correct `seq` + `prev_hash`, seals it (computes `record_hash`), and
/// tracks the head. It is used directly by unit tests and by the in-memory
/// sink, and the same sealing logic is what the Postgres `_meta` sink relies on
/// so both produce byte-identical, mutually verifiable chains.
#[derive(Debug, Clone, Default)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
}

/// The fields of a not-yet-chained record. The chain supplies `seq`,
/// `prev_hash`, and `timestamp` (via the caller's clock), so callers describe
/// only *what happened*, not *where it sits in the chain*.
#[derive(Debug, Clone, PartialEq)]
pub struct NewEntry {
    /// The raw statement text.
    pub statement_text: String,
    /// The gating decision.
    pub decision: Decision,
    /// A machine-readable reason code.
    pub reason_code: String,
    /// An optional human-readable reason.
    pub reason: Option<String>,
    /// Who/where.
    pub principal: crate::record::Principal,
    /// Logged T0–T2 intent context.
    pub intent: crate::record::IntentTiers,
    /// Optional dry-run / blast-radius references.
    pub write_safety: crate::record::WriteSafetyRefs,
}

impl AuditChain {
    /// A fresh, empty chain.
    pub fn new() -> Self {
        AuditChain {
            records: Vec::new(),
        }
    }

    /// The `prev_hash` the next appended record will carry: the head record's
    /// `record_hash`, or [`GENESIS_PREV_HASH`] when the chain is empty.
    pub fn head_hash(&self) -> Hash {
        self.records
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
    }

    /// The next sequence number (the chain length).
    pub fn next_seq(&self) -> u64 {
        self.records.len() as u64
    }

    /// Append a new entry, stamping it with the timestamp from `timestamp_ms`
    /// (read upstream from `core::Clock` so tests stay wall-clock-free), the
    /// correct `seq`, and the current head as `prev_hash`. Returns the sealed
    /// record.
    pub fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> AuditRecord {
        let payload = AuditPayload {
            seq: self.next_seq(),
            statement_text: entry.statement_text,
            decision: entry.decision,
            reason_code: entry.reason_code,
            reason: entry.reason,
            principal: entry.principal,
            intent: entry.intent,
            write_safety: entry.write_safety,
            timestamp_unix_millis: timestamp_ms,
            prev_hash: self.head_hash(),
        };
        let record = AuditRecord::seal(payload);
        self.records.push(record.clone());
        record
    }

    /// All records, oldest first.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// The number of records in the chain.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the chain has no records yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Verify this chain's integrity (delegates to [`verify_chain`]).
    pub fn verify(&self) -> Result<(), ChainBreak> {
        verify_chain(&self.records)
    }
}
