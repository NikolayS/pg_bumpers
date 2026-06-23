//! The external WORM / transparency-log **anchor** of the chain head, on an
//! interval (SPEC §3, §4, §10.9; issue #54, S4).
//!
//! # Why an external anchor at all
//! S1's hash chain (`crate::chain`) detects *within-chain* tampering: edit or
//! delete one record and a hash link breaks. But it cannot stop an attacker who
//! **owns the audit table** and rewrites the *entire* chain consistently —
//! re-hashing and re-linking every record around their edit. The rewritten chain
//! verifies clean on its own (`verify_chain` is happy), because every link is
//! internally consistent. That is the gap this module closes.
//!
//! # The defence
//! Periodically — on an interval driven by `core::Clock` (monotonic, mockable) —
//! we take the current chain **head** (`record_hash` of the last record), sign it
//! with a KMS key the DB operator cannot reach ([`crate::kms`]), and publish the
//! signed head to an **append-only / WORM** sink with independent retention
//! ([`WormAnchor`]). To pass off a rewritten chain the attacker would need an
//! anchor entry that signs *their* head — but they cannot mint a valid signature
//! (no key), and they cannot delete/replace the already-published honest entry
//! (the sink is append-only/WORM). So [`verify_against_anchor`] catches the
//! full-chain rewrite as a [`AnchorVerification::HeadMismatch`].
//!
//! # What is in the MVP vs production
//! - **Local WORM stand-in:** [`WormAnchor`] — an in-memory, append-only log,
//!   optionally backed by an append-only **file** ([`WormAnchor::open_file`]) to
//!   model object-lock / independent retention. The local impl exposes **no**
//!   mutate/delete method, mirroring object-lock.
//! - **Production target (documented, not built here):** an S3 bucket with
//!   **Object Lock (compliance mode)** or a **transparency log** (e.g. an
//!   append-only Merkle log), with retention independent of the DB operator and
//!   a real asymmetric KMS signature. See `deploy/README.md` → *"Audit anchor,
//!   KMS key separation & secret store"*.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::chain::AuditChain;
use crate::kms::{HeadSignature, Kms, LocalKms};
use crate::record::{AuditRecord, GENESIS_PREV_HASH};

/// One published anchor: a signed snapshot of the chain head at an interval tick.
///
/// `head_hash`/`seq`/`timestamp_unix_millis` are exactly the head the signature
/// covers (see [`crate::kms::head_signing_input`]); `signature` is the KMS
/// signature over them. An empty chain anchors the [`GENESIS_PREV_HASH`] at
/// `seq` 0 so even "no records yet" has a signed baseline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnchorEntry {
    /// The chain head this entry pins: the `record_hash` of the last record (or
    /// [`GENESIS_PREV_HASH`] for an empty chain).
    pub head_hash: String,
    /// The `seq` of the head record (0 for an empty chain).
    pub seq: u64,
    /// The head record's `core::Clock` unix stamp (for human ordering; the
    /// anchor *cadence* uses the monotonic clock, see [`Anchorer`]).
    pub timestamp_unix_millis: u64,
    /// The KMS signature over `(head_hash, seq, timestamp_unix_millis)`.
    pub signature: HeadSignature,
}

/// The result of an interval tick that *did* publish an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchored {
    /// The `seq` of the head that was anchored.
    pub seq: u64,
    /// The head hash that was anchored.
    pub head_hash: String,
}

/// Errors raised while verifying a chain against an anchor.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    /// The anchor sink holds no published head to verify against. Fail closed:
    /// with no anchor we cannot assert the chain was not rewritten.
    #[error("no anchor has been published yet")]
    NoAnchor,
    /// The anchored head carries a signature that does not verify under the KMS
    /// key — the anchor entry itself was tampered with (a head swapped in without
    /// a valid signature). This is the WORM-tamper case.
    #[error("anchored head signature is invalid (anchor tampered): seq {seq}")]
    BadSignature {
        /// The `seq` of the anchor entry whose signature failed.
        seq: u64,
    },
    /// Verification needs a KMS verifier but none was available (the anchor was
    /// loaded from a file with no embedded verifier; use
    /// [`verify_against_anchor_with`]).
    #[error("no KMS verifier available; call verify_against_anchor_with(.., verifier)")]
    NoVerifier,
}

/// The outcome of verifying a chain against its latest anchored head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorVerification {
    /// The chain's current head matches the (validly-signed) anchored head — the
    /// chain has not been rewritten since it was anchored.
    Verified,
    /// The chain's current head does **not** match the anchored head: the chain
    /// was rewritten (or truncated/extended) after anchoring. This is the
    /// full-chain-rewrite detection.
    HeadMismatch {
        /// The head the WORM anchor pins (the honest, signed one).
        anchored_head: String,
        /// The head the presented chain actually has now.
        actual_head: String,
        /// The `seq` the anchor pinned.
        anchored_seq: u64,
    },
}

/// The head of a record slice as `(head_hash, seq, timestamp)`: the
/// `record_hash` and `seq` of the last record, or `(GENESIS_PREV_HASH, 0, 0)`
/// for an empty slice.
///
/// This is the canonical head-extraction used by **every** anchor path — the
/// in-memory [`AuditChain`] and the records loaded back from the persistent
/// `_meta` sink — so an anchor taken over an in-memory chain and one taken over
/// the same records read from Postgres pin the **identical** head. That identity
/// is what lets the proxy/CLI anchor the canonical `_meta` chain they share and
/// lets a later verifier (over the persisted rows) match it.
pub fn head_of(records: &[AuditRecord]) -> (String, u64, u64) {
    match records.last() {
        Some(r) => (
            r.record_hash.clone(),
            r.payload.seq,
            r.payload.timestamp_unix_millis,
        ),
        None => (GENESIS_PREV_HASH.to_string(), 0, 0),
    }
}

/// Errors specific to the **file-backed** WORM stand-in.
#[derive(Debug, thiserror::Error)]
pub enum WormAnchorError {
    /// An I/O error opening/reading/appending the anchor file.
    #[error("worm anchor file io error: {source}")]
    Io {
        /// The underlying I/O error.
        #[from]
        source: std::io::Error,
    },
    /// A line in the anchor file was not valid anchor-entry JSON.
    #[error("corrupt worm anchor file (bad entry json): {0}")]
    Corrupt(String),
}

/// An append-only / WORM sink for anchor entries (the local stand-in).
///
/// Models object-lock: [`append`](WormAnchor::append) adds an entry,
/// [`entries`](WormAnchor::entries) / [`latest`](WormAnchor::latest) read them,
/// and there is **no** method to mutate or delete a published entry. An optional
/// file backing ([`open_file`](WormAnchor::open_file)) gives independent
/// retention across process restarts.
///
/// It also (optionally) holds a **verifier** capability so the no-arg
/// [`verify_against_anchor`] can check signatures; this is set when an
/// [`Anchorer`] publishes through it. After loading from a file no verifier is
/// embedded — use [`verify_against_anchor_with`] and supply one. The verifier is
/// the KMS capability ([`LocalKms`]); it never serializes, so the file holds only
/// entries, never the key.
#[derive(Default)]
pub struct WormAnchor {
    entries: Vec<AnchorEntry>,
    /// Set when this anchor was written through an `Anchorer`; lets the no-arg
    /// verifier check signatures. Never persisted.
    verifier: Option<LocalKms>,
    /// File backing for independent retention, if opened via `open_file`.
    file_path: Option<PathBuf>,
}

impl std::fmt::Debug for WormAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WormAnchor")
            .field("entries", &self.entries.len())
            .field("has_verifier", &self.verifier.is_some())
            .field("file_path", &self.file_path)
            .finish()
    }
}

impl WormAnchor {
    /// A fresh, empty in-memory WORM anchor.
    pub fn new() -> Self {
        WormAnchor {
            entries: Vec::new(),
            verifier: None,
            file_path: None,
        }
    }

    /// Open (or create) an append-only file-backed WORM anchor at `path`,
    /// loading any already-published entries. Opening **never truncates** — it is
    /// idempotent and preserves existing entries (independent retention).
    pub fn open_file(path: impl AsRef<Path>) -> Result<Self, WormAnchorError> {
        let path = path.as_ref().to_path_buf();
        let mut entries = Vec::new();
        match std::fs::File::open(&path) {
            Ok(f) => {
                let reader = std::io::BufReader::new(f);
                for line in reader.lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let entry: AnchorEntry = serde_json::from_str(&line)
                        .map_err(|e| WormAnchorError::Corrupt(e.to_string()))?;
                    entries.push(entry);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create the file now so the directory error (if any) surfaces at
                // open time, matching the "object-lock target exists" semantics.
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
            }
            Err(e) => return Err(WormAnchorError::Io { source: e }),
        }
        Ok(WormAnchor {
            entries,
            verifier: None,
            file_path: Some(path),
        })
    }

    /// All published anchor entries, oldest first.
    pub fn entries(&self) -> &[AnchorEntry] {
        &self.entries
    }

    /// The most-recently-published anchor entry, if any.
    pub fn latest(&self) -> Option<&AnchorEntry> {
        self.entries.last()
    }

    /// Append a signed anchor entry. **Append-only** — there is no delete/mutate.
    /// If file-backed, the entry is also appended to the file (one JSON object
    /// per line), giving independent retention.
    pub fn append(&mut self, entry: AnchorEntry) -> Result<(), WormAnchorError> {
        if let Some(path) = &self.file_path {
            let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
            let line = serde_json::to_string(&entry)
                .map_err(|e| WormAnchorError::Corrupt(e.to_string()))?;
            writeln!(f, "{line}")?;
        }
        self.entries.push(entry);
        Ok(())
    }

    /// **Test-only helper** modelling an attacker who reaches the anchor sink and
    /// swaps the latest head for `forged_head` *without* a valid signature (they
    /// have no KMS key). Returns a tampered **copy** so the original honest
    /// anchor is left intact for comparison. The forged copy keeps the old
    /// (now-mismatched) signature, so [`verify_against_anchor`] flags
    /// [`AnchorError::BadSignature`].
    pub fn forge_latest_head_for_test(&self, forged_head: &str) -> WormAnchor {
        let mut entries = self.entries.clone();
        if let Some(last) = entries.last_mut() {
            last.head_hash = forged_head.to_string();
            // The signature is NOT recomputed (the attacker can't), so it no
            // longer matches the swapped head.
        }
        WormAnchor {
            entries,
            // Carry the verifier so the no-arg verify path can run and detect the
            // bad signature (in the real world the public key is always known).
            verifier: self.verifier.clone(),
            file_path: None,
        }
    }
}

/// Drives interval anchoring: holds the signing KMS capability and the interval,
/// and decides at each tick whether to publish a fresh anchor.
///
/// Cadence is measured on the **monotonic** clock (`core::Clock::monotonic_millis`,
/// passed in by the caller) so it never depends on a wall clock and is fully
/// deterministic under `MockClock`.
#[derive(Debug)]
pub struct Anchorer {
    signer: LocalKms,
    interval_millis: u64,
    last_anchor_at: Option<u64>,
}

impl Anchorer {
    /// Build an anchorer that re-anchors at most once per `interval_millis`
    /// (monotonic). The very first tick always anchors (bootstrap baseline).
    pub fn new(signer: LocalKms, interval_millis: u64) -> Self {
        Anchorer {
            signer,
            interval_millis,
            last_anchor_at: None,
        }
    }

    /// At a monotonic instant `now_monotonic_millis`, publish a fresh anchor to
    /// `worm` **iff** an interval has elapsed since the last anchor (or this is
    /// the first tick). Returns `Some(Anchored)` if it published, `None` if the
    /// interval has not elapsed yet.
    pub fn maybe_anchor(
        &mut self,
        chain: &AuditChain,
        now_monotonic_millis: u64,
        worm: &mut WormAnchor,
    ) -> Result<Option<Anchored>, WormAnchorError> {
        self.maybe_anchor_records(chain.records(), now_monotonic_millis, worm)
    }

    /// Anchor over a **record slice** rather than an in-memory [`AuditChain`].
    ///
    /// This is the path the proxy/CLI take over the rows read back from the
    /// persistent `_meta` sink ([`crate::pg::PgSink::load_chain_mut`]): the
    /// canonical chain lives in Postgres, so the anchorer pins the head of the
    /// persisted records directly. The head is computed by [`head_of`], so an
    /// anchor over `chain.records()` and one over the same rows read from `_meta`
    /// pin the **identical** head.
    pub fn maybe_anchor_records(
        &mut self,
        records: &[AuditRecord],
        now_monotonic_millis: u64,
        worm: &mut WormAnchor,
    ) -> Result<Option<Anchored>, WormAnchorError> {
        let due = match self.last_anchor_at {
            None => true,
            Some(prev) => now_monotonic_millis.saturating_sub(prev) >= self.interval_millis,
        };
        if !due {
            return Ok(None);
        }

        let (head_hash, seq, ts) = head_of(records);
        let signature = self.signer.sign_head(&head_hash, seq, ts);
        let entry = AnchorEntry {
            head_hash: head_hash.clone(),
            seq,
            timestamp_unix_millis: ts,
            signature,
        };
        worm.append(entry)?;
        // Embed the verifier so the no-arg `verify_against_anchor` can check
        // signatures without re-supplying the key (the verifier never serializes).
        worm.verifier = Some(self.signer.verifier_handle());
        self.last_anchor_at = Some(now_monotonic_millis);
        Ok(Some(Anchored { seq, head_hash }))
    }

    /// The interval (monotonic millis) this anchorer re-anchors on.
    pub fn interval_millis(&self) -> u64 {
        self.interval_millis
    }
}

/// Verify `chain` against its latest WORM-anchored head, using the verifier the
/// anchor carries (set when an [`Anchorer`] published through it).
///
/// Returns [`AnchorVerification::Verified`] when the current head matches the
/// validly-signed anchored head, or [`AnchorVerification::HeadMismatch`] when the
/// chain was rewritten/truncated/extended after anchoring. Errors:
/// [`AnchorError::NoAnchor`] (nothing published), [`AnchorError::BadSignature`]
/// (the anchor entry itself was tampered), [`AnchorError::NoVerifier`] (loaded
/// from a file with no embedded verifier — use [`verify_against_anchor_with`]).
pub fn verify_against_anchor(
    chain: &AuditChain,
    worm: &WormAnchor,
) -> Result<AnchorVerification, AnchorError> {
    verify_records_against_anchor(chain.records(), worm)
}

/// Verify `chain` against its latest WORM-anchored head using an **explicit**
/// KMS verifier (needed when the anchor was loaded from a file and carries no
/// embedded verifier). Same outcomes as [`verify_against_anchor`].
pub fn verify_against_anchor_with(
    chain: &AuditChain,
    worm: &WormAnchor,
    verifier: &impl Kms,
) -> Result<AnchorVerification, AnchorError> {
    verify_records_against_anchor_with(chain.records(), worm, verifier)
}

/// Verify a **record slice** (e.g. the rows read back from the persistent
/// `_meta` sink) against its latest WORM-anchored head, using the verifier the
/// anchor carries.
///
/// This is the **fail-closed startup check** the proxy/CLI run on boot: load the
/// canonical `_meta` chain, and refuse to start unless its current head matches
/// the validly-signed anchored head. A full-chain rewrite changes the head, so
/// it surfaces here as [`AnchorVerification::HeadMismatch`]; a missing anchor is
/// [`AnchorError::NoAnchor`] (fail closed — with no anchor we cannot assert the
/// chain was not rewritten). Same outcomes/semantics as [`verify_against_anchor`].
pub fn verify_records_against_anchor(
    records: &[AuditRecord],
    worm: &WormAnchor,
) -> Result<AnchorVerification, AnchorError> {
    match &worm.verifier {
        Some(v) => verify_records_against_anchor_with(records, worm, v),
        None => Err(AnchorError::NoVerifier),
    }
}

/// Verify a **record slice** against its latest WORM-anchored head using an
/// **explicit** KMS verifier (needed when the anchor was loaded from a file and
/// carries no embedded verifier). Same outcomes as
/// [`verify_records_against_anchor`].
pub fn verify_records_against_anchor_with(
    records: &[AuditRecord],
    worm: &WormAnchor,
    verifier: &impl Kms,
) -> Result<AnchorVerification, AnchorError> {
    let anchor = worm.latest().ok_or(AnchorError::NoAnchor)?;

    // (1) The anchor entry's own signature must be valid — else the anchor was
    //     tampered (a head swapped in without a valid KMS signature).
    if !verifier.verify_head(
        &anchor.head_hash,
        anchor.seq,
        anchor.timestamp_unix_millis,
        &anchor.signature,
    ) {
        return Err(AnchorError::BadSignature { seq: anchor.seq });
    }

    // (2) Compare the slice's current head to the validly-signed anchored head.
    let (actual_head, _seq, _ts) = head_of(records);
    if actual_head == anchor.head_hash {
        Ok(AnchorVerification::Verified)
    } else {
        Ok(AnchorVerification::HeadMismatch {
            anchored_head: anchor.head_hash.clone(),
            actual_head,
            anchored_seq: anchor.seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewEntry;
    use crate::kms::LocalKms;
    use crate::record::{Decision, Principal};
    use crate::secret::{AUDIT_SIGNING_KEY_ID, LocalSecretStore, SecretStore};
    use pgb_policy::IntentTiers;

    fn signer() -> LocalKms {
        let mut s = LocalSecretStore::new();
        s.put(AUDIT_SIGNING_KEY_ID, b"unit-test-key").unwrap();
        LocalKms::from_secret_store(&s, AUDIT_SIGNING_KEY_ID).unwrap()
    }

    fn one_record_chain() -> AuditChain {
        let mut c = AuditChain::new();
        c.append(
            NewEntry {
                statement_text: "SELECT 1".into(),
                decision: Decision::Allow,
                reason_code: "ok".into(),
                reason: None,
                principal: Principal {
                    role: "pgb_agent".into(),
                    session_id: None,
                    principal: None,
                },
                intent: IntentTiers::default(),
                write_safety: Default::default(),
            },
            42,
        );
        c
    }

    #[test]
    fn empty_chain_anchors_genesis_baseline() {
        let chain = AuditChain::new();
        let mut worm = WormAnchor::new();
        let mut a = Anchorer::new(signer(), 1_000);
        let got = a.maybe_anchor(&chain, 0, &mut worm).unwrap().unwrap();
        assert_eq!(got.head_hash, GENESIS_PREV_HASH);
        assert_eq!(got.seq, 0);
        assert_eq!(
            verify_against_anchor(&chain, &worm).unwrap(),
            AnchorVerification::Verified
        );
    }

    #[test]
    fn no_anchor_published_is_an_error() {
        let chain = one_record_chain();
        let worm = WormAnchor::new();
        // No verifier embedded and nothing published.
        assert_eq!(
            verify_against_anchor_with(&chain, &worm, &signer()).unwrap_err(),
            AnchorError::NoAnchor
        );
    }

    #[test]
    fn loaded_anchor_without_verifier_reports_no_verifier() {
        let chain = one_record_chain();
        let mut worm = WormAnchor::new();
        let mut a = Anchorer::new(signer(), 1_000);
        a.maybe_anchor(&chain, 0, &mut worm).unwrap().unwrap();
        // Simulate a freshly-loaded anchor: strip the embedded verifier.
        worm.verifier = None;
        assert_eq!(
            verify_against_anchor(&chain, &worm).unwrap_err(),
            AnchorError::NoVerifier
        );
        // With an explicit verifier it works.
        assert_eq!(
            verify_against_anchor_with(&chain, &worm, &signer()).unwrap(),
            AnchorVerification::Verified
        );
    }
}
