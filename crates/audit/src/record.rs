//! The append-only audit record and its canonical, hashable encoding
//! (SPEC §4 "Audit", §10.9, §5 hash-chain integrity).
//!
//! Each record captures **one decision about one statement** — including the
//! ones that were blocked or rejected (SPEC §4: "Records every statement incl.
//! rejects"). The record carries everything needed to reconstruct *what* the
//! agent asked for, *who* asked, *what we decided and why*, the logged T0–T2
//! intent context, and the **chain links** (`prev_hash`, `record_hash`).
//!
//! # The hash chain
//! `record_hash = sha256(prev_hash ∥ canonical_encoding(record))`. The
//! [`AuditPayload`] is the part of the record that is hashed — everything
//! *except* `record_hash` itself (the digest cannot cover itself) — and its
//! [`canonical_bytes`](AuditPayload::canonical_bytes) encoding is **stable and
//! deterministic** so the same logical record always hashes identically. We get
//! determinism for free by serializing through `serde_json` with field order
//! fixed by the struct definition and all maps using `BTreeMap` (sorted keys),
//! exactly as the embedded `pgb_policy::IntentTiers` already does.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use pgb_policy::IntentTiers;

/// A SHA-256 digest, rendered as lowercase hex (64 chars) for stable
/// storage/transport. The chain links are these strings.
pub type Hash = String;

/// The genesis predecessor hash for the **first** record in a chain.
///
/// A defined genesis is required so `verify_chain()` has a fixed anchor: the
/// first record's `prev_hash` must equal this exact value, and tampering that
/// removes/replaces the genesis link is detectable. It is the all-zero SHA-256
/// (64 hex zeros) — conventional, unambiguous, and never a real digest of any
/// payload (no payload hashes to all zeros in practice).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The gating decision recorded for a statement (SPEC §4, §11).
///
/// `Allow` is the only non-rejecting outcome; `Block` and `Reject` are the two
/// flavours of "did not run", and **both are recorded** — the audit log is the
/// evidence that a hostile statement was stopped, so rejects must leave a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// The statement was permitted (still subject to the deterministic floor).
    Allow,
    /// The statement was blocked by an enforcement rule (e.g. a write on the
    /// read-only path, a budget overrun, a refused op).
    Block,
    /// The statement was rejected outright before/at parse (e.g. a stacked
    /// statement, a `COPY`, a simple-query-protocol fallback the proxy refuses).
    Reject,
}

impl Decision {
    /// Whether this decision *prevented* the statement from running. Both
    /// [`Block`](Decision::Block) and [`Reject`](Decision::Reject) do; only
    /// [`Allow`](Decision::Allow) lets it through.
    pub fn is_rejecting(self) -> bool {
        !matches!(self, Decision::Allow)
    }
}

/// Who and where: the principal/session context for a recorded action.
///
/// The audited *principal* (the agent role) is named here for forensics; note
/// that this same principal is `REVOKE`d from writing the audit table (SPEC
/// §3/§4 "audited cannot write audit"), so it can be named in a row it cannot
/// itself insert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The database role the session authenticated as (the audited principal).
    pub role: String,
    /// A stable session identifier (e.g. the proxy's per-connection id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// An optional higher-level principal label (e.g. the MCP actor / ticket
    /// owner) when known. Informational; never a gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

/// Optional references to write-safety artifacts produced for this statement
/// (SPEC §10.1 blast-radius, §10.3 typed-inverse). These are *references*
/// (ids/checksums), not the full records, so the audit row stays compact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteSafetyRefs {
    /// The dry-run proposal id this decision relates to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run_id: Option<String>,
    /// A reference (id or checksum) to the blast-radius record, if a dry-run
    /// was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_ref: Option<String>,
}

impl WriteSafetyRefs {
    /// Whether no write-safety references were attached (keeps the serialized
    /// row minimal for read-path actions).
    pub fn is_empty(&self) -> bool {
        self.dry_run_id.is_none() && self.blast_radius_ref.is_none()
    }
}

/// The **hashed** portion of an audit record: everything except `record_hash`.
///
/// This is the canonical-encoding subject. A digest cannot cover itself, so the
/// record's own `record_hash` is *not* part of what is hashed; `prev_hash`
/// **is** (that is what chains the records together).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPayload {
    /// Monotonic chain sequence number (0 = genesis record). Lets a verifier
    /// and the DB sink order rows without trusting wall-clock time.
    pub seq: u64,
    /// The raw statement text as seen at the wire (verbatim, for forensics).
    pub statement_text: String,
    /// The gating decision (`ALLOW` / `BLOCK` / `REJECT`).
    pub decision: Decision,
    /// A short machine-readable reason code (e.g. `"write_on_readonly"`,
    /// `"stacked_statement"`, `"ok"`).
    pub reason_code: String,
    /// A human-readable reason / remedy string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Who/where: the audited principal + session context.
    pub principal: Principal,
    /// The logged T0–T2 intent context (captured-only in MVP, SPEC §11.5). This
    /// is the policy crate's one-way-door shape, embedded verbatim.
    #[serde(default, skip_serializing_if = "intent_is_default")]
    pub intent: IntentTiers,
    /// Optional dry-run / blast-radius references (SPEC §10.1/§10.3).
    #[serde(default, skip_serializing_if = "WriteSafetyRefs::is_empty")]
    pub write_safety: WriteSafetyRefs,
    /// Wall-clock-style stamp (Unix millis) read from `core::Clock`. For human
    /// ordering only — the chain order is `seq` + the hash links, never time.
    pub timestamp_unix_millis: u64,
    /// The predecessor record's `record_hash` ([`GENESIS_PREV_HASH`] for seq 0).
    pub prev_hash: Hash,
}

/// `skip_serializing_if` helper: omit the intent block when it is the default
/// (empty) so read-path rows stay compact. Default tiers serialize to nothing
/// useful, and an absent block is treated as default on the way back in.
fn intent_is_default(intent: &IntentTiers) -> bool {
    *intent == IntentTiers::default()
}

impl AuditPayload {
    /// The **canonical, deterministic** byte encoding that is fed to SHA-256.
    ///
    /// Determinism guarantees: field order is fixed by the struct; every map in
    /// the embedded intent tiers is a `BTreeMap` (sorted keys); `serde_json`
    /// emits no insignificant whitespace by default. Therefore the same logical
    /// payload always yields identical bytes on every machine and run — the
    /// property the whole chain rests on.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // `to_vec` cannot fail for these plain data types; if it ever did, an
        // empty encoding would poison the chain, so surface it loudly instead.
        serde_json::to_vec(self).expect("audit payload is always serializable")
    }

    /// Compute this payload's `record_hash`:
    /// `sha256(prev_hash_bytes ∥ canonical_encoding(payload))`.
    ///
    /// `prev_hash` is already inside the payload, but we *also* prepend its raw
    /// hex bytes to the digest input to match the spec's
    /// `sha256(prev_hash ∥ canonical(record))` formula literally and to make the
    /// link explicit and order-sensitive.
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(self.canonical_bytes());
        hex::encode(hasher.finalize())
    }
}

/// A complete, sealed audit record: the hashed [`AuditPayload`] plus its
/// computed `record_hash`. This is what a sink stores and what
/// `verify_chain()` checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The hashed payload (statement, decision, principal, intent, links).
    #[serde(flatten)]
    pub payload: AuditPayload,
    /// `sha256(prev_hash ∥ canonical(payload))` — the chain link this record
    /// contributes, and the `prev_hash` the *next* record must carry.
    pub record_hash: Hash,
}

impl AuditRecord {
    /// Seal a payload into a record by computing its `record_hash`.
    pub fn seal(payload: AuditPayload) -> Self {
        let record_hash = payload.compute_hash();
        AuditRecord {
            payload,
            record_hash,
        }
    }

    /// Recompute the hash from the (possibly tampered) payload and report
    /// whether it still matches the stored `record_hash`.
    ///
    /// This is the per-record half of tamper detection: editing any hashed
    /// field changes `compute_hash()` but leaves the stored `record_hash`
    /// untouched, so they diverge.
    pub fn hash_is_intact(&self) -> bool {
        self.payload.compute_hash() == self.record_hash
    }

    /// The chain sequence number of this record (0 = genesis).
    pub fn seq(&self) -> u64 {
        self.payload.seq
    }
}
