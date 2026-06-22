//! Boot wiring for the **one shared, persistent, anchored** `_meta` audit chain
//! (SPEC §3/§4/§10.9; issue #64, S5).
//!
//! S4 shipped the chain, the `_meta` [`PgSink`](crate::pg::PgSink), the external
//! WORM anchor, and the KMS key-separation as *libraries*, but the proxy and the
//! CLI each built their own ephemeral in-memory chain with an independent
//! genesis, and nothing anchored the running chain. This module is the seam that
//! S5's consumers (proxy + CLI) call to:
//!
//! 1. construct **one** [`SharedSink`] over the Postgres `_meta`
//!    [`PgSink`](crate::pg::PgSink) — the single canonical chain both consumers
//!    hash-chain into ([`AuditBoot::connect`]);
//! 2. run an [`Anchorer`] over that canonical chain on a `core::Clock` interval
//!    ([`AuditBoot::maybe_anchor`]); and
//! 3. perform the **fail-closed startup verification** ([`AuditBoot::startup_verify`]):
//!    load the persisted chain, check it verifies within-chain, and check its
//!    head matches the validly-signed WORM-anchored head — refusing to proceed
//!    on any mismatch (a full-chain rewrite) or a tampered anchor.
//!
//! # Durable WORM, and verify-BEFORE-anchor (the cross-restart property)
//! The external anchor only catches a full-chain rewrite **across a process
//! restart** if two things hold:
//!
//! - the anchored head is stored in a **durable** location that survives the
//!   restart and the DB operator cannot rewrite — here the **file-backed**
//!   [`WormAnchor::open_file`] stand-in (`PGB_ANCHOR_PATH`); and
//! - on boot we **verify the persisted `_meta` chain against that durable
//!   anchored head BEFORE re-anchoring**. If a fresh process re-anchored first,
//!   it would simply re-pin whatever head is now in `_meta` — including an
//!   offline-forged head — and the verify would trivially pass against it. So the
//!   correct boot sequence is [`AuditBoot::verify_then_anchor`]: verify against
//!   the prior durable head first, refuse to start on a mismatch, and only
//!   anchor **forward** after a clean verify.
//!
//! A legitimate **first boot / genesis** (the durable WORM is empty — nothing was
//! ever anchored) has nothing to verify against yet; [`AuditBoot::verify_then_anchor`]
//! treats that as the baseline case and anchors the genesis head without opening a
//! hole. From the second boot on, the persisted chain MUST match the durable head.
//! The durable WORM's own integrity (object-lock / transparency-log retention the
//! operator cannot rewrite) is the §10.9 trust anchor; the file stand-in models
//! that retention but is not itself true WORM (see the production swap below).
//!
//! The KMS signer is loaded from a [`SecretStore`](crate::secret::SecretStore)
//! the audited DB operator cannot reach (SPEC §10.9). It is retained so the
//! verify can check a durable anchor's signature **after a restart**, when the
//! file-loaded [`WormAnchor`] carries no embedded verifier (the key never
//! serializes to the file). Time is always read from a `core::Clock` passed in by
//! the caller, so anchoring cadence is mockable and no wall clock is touched.
//!
//! This module is behind the `pg` feature (it needs the Postgres client).

use std::path::Path;
use std::sync::{Arc, Mutex};

use postgres::{Client, NoTls};

use crate::anchor::{
    verify_records_against_anchor_with, AnchorError, AnchorVerification, Anchorer,
};
use crate::kms::LocalKms;
use crate::pg::PgSink;
use crate::secret::{SecretStore, AUDIT_SIGNING_KEY_ID};
use crate::sink::{SharedSink, Sink, SinkError};
use crate::WormAnchor;

/// Why the audit boot wiring failed. Every variant is **fail-closed** — a boot
/// error means the consumer must refuse to start (the audit chain is the
/// tamper-evidence root of trust; if it cannot be established or verified, the
/// system has no business running).
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// Could not connect to the `_meta` database as the audit writer.
    #[error("audit _meta connect failed: {0}")]
    Connect(String),
    /// Could not load the audit chain-head signing key from the secret store.
    #[error("audit signing key load failed: {0}")]
    Kms(#[from] crate::kms::KmsError),
    /// A sink read/append failed.
    #[error(transparent)]
    Sink(#[from] SinkError),
    /// Publishing the anchor to the WORM sink failed (e.g. the file backing).
    #[error("audit anchor publish failed: {0}")]
    Worm(#[from] crate::anchor::WormAnchorError),
    /// The persisted chain failed within-chain integrity (a mid-chain edit/delete).
    #[error("persisted _meta chain integrity broken: {0:?}")]
    ChainIntegrity(crate::chain::ChainBreak),
    /// The chain's head does **not** match the WORM-anchored head — a full-chain
    /// rewrite was detected at startup. **Refuse to start.**
    #[error(
        "FAIL-CLOSED: _meta chain head does not match the anchored head \
         (full-chain rewrite detected): anchored seq {anchored_seq}, anchored_head {anchored_head}, \
         actual_head {actual_head}"
    )]
    AnchorHeadMismatch {
        /// The head the WORM anchor pins (the honest, signed one).
        anchored_head: String,
        /// The head the persisted chain actually has now.
        actual_head: String,
        /// The `seq` the anchor pinned.
        anchored_seq: u64,
    },
    /// The anchor verification itself errored (no anchor published / bad
    /// signature / no verifier). Fail closed.
    #[error("FAIL-CLOSED: anchor verification error at startup: {0}")]
    Anchor(#[from] AnchorError),
}

/// Which role a booting binary plays over the **one shared, durable anchor**
/// (S5 #76, item 3).
///
/// Proxy and applyd both boot over the SAME `_meta` chain and the SAME durable
/// WORM anchor file + signing key. Exactly ONE of them must **own** the anchor
/// (publish forward); the others must **verify-only** (still fail-closed on a
/// tampered chain) but never anchor. Two uncoordinated anchorers over one chain
/// is the bug this closes: each would pin a different head into the (now-shared)
/// file at a different cadence, so a restart could fail-closed-deadlock against
/// the *other's* head, or a fresh process could re-baseline a tampered chain by
/// anchoring first.
///
/// Resolved from `PGB_ANCHOR_ROLE` (`owner` | `verify`); the proxy defaults to
/// `owner`, applyd to `verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorRole {
    /// This binary OWNS the anchor: it runs the verify-before-anchor boot
    /// sequence ([`AuditBoot::verify_then_anchor`]) and the interval anchorer.
    Owner,
    /// This binary VERIFIES ONLY ([`AuditBoot::verify_only`]): it checks the
    /// persisted chain against the owner's durable anchored head (fail-closed on a
    /// mismatch) but NEVER anchors — so there is exactly one anchorer over the
    /// shared chain.
    Verify,
}

impl AnchorRole {
    /// Parse `PGB_ANCHOR_ROLE` (case-insensitive `owner`|`verify`). `default` is
    /// returned when the value is unset/empty (so each binary can pick its own
    /// default — proxy `Owner`, applyd `Verify`). An unrecognized value is an
    /// error (fail-closed: never silently guess the anchor topology).
    pub fn parse(value: Option<&str>, default: AnchorRole) -> Result<AnchorRole, String> {
        match value.map(|v| v.trim().to_ascii_lowercase()) {
            None => Ok(default),
            Some(v) if v.is_empty() => Ok(default),
            Some(v) if v == "owner" => Ok(AnchorRole::Owner),
            Some(v) if v == "verify" || v == "verifier" || v == "verify-only" => {
                Ok(AnchorRole::Verify)
            }
            Some(other) => Err(format!(
                "PGB_ANCHOR_ROLE must be `owner` or `verify`, got `{other}`"
            )),
        }
    }

    /// Whether this role anchors (only the owner does).
    pub fn is_owner(self) -> bool {
        matches!(self, AnchorRole::Owner)
    }
}

/// The boot handle for the canonical, anchored `_meta` chain.
///
/// Holds the [`SharedSink`] both consumers append to, the WORM anchor, and the
/// interval [`Anchorer`]. Construct it with [`connect`](AuditBoot::connect) (real
/// `_meta`) or [`with_sink`](AuditBoot::with_sink) (any [`Sink`], for tests),
/// then [`startup_verify`](AuditBoot::startup_verify) before serving traffic and
/// [`maybe_anchor`](AuditBoot::maybe_anchor) on the clock cadence.
pub struct AuditBoot {
    sink: SharedSink,
    worm: WormAnchor,
    anchorer: Anchorer,
    /// A verifier capability (the symmetric KMS handle) retained so the
    /// fail-closed startup verify can check the durable anchor's signature even
    /// after a restart — when a file-loaded [`WormAnchor`] carries no embedded
    /// verifier (the key never serializes to the file).
    verifier: LocalKms,
}

impl AuditBoot {
    /// Build a boot handle over a `_meta` writer DSN with an **in-memory**
    /// (non-durable) WORM anchor. The anchor does **not** survive a restart, so
    /// this constructor cannot provide the cross-restart tamper-evidence
    /// guarantee — production callers MUST use [`connect_with_anchor`](AuditBoot::connect_with_anchor)
    /// with a durable `anchor_path`. Kept for unit/in-process use.
    ///
    /// The DSN must authenticate as the **audit writer** role (never the audited
    /// agent — see `crates/audit/sql/10_audit_meta.sql`). `interval_millis` is the
    /// anchoring cadence (monotonic millis, measured by the caller's `core::Clock`).
    pub fn connect(
        writer_dsn: &str,
        store: &impl SecretStore,
        interval_millis: u64,
    ) -> Result<Self, BootError> {
        let signer = LocalKms::from_secret_store(store, AUDIT_SIGNING_KEY_ID)?;
        let client =
            Client::connect(writer_dsn, NoTls).map_err(|e| BootError::Connect(e.to_string()))?;
        Ok(Self::with_sink_and_worm(
            PgSink::new(client),
            signer,
            interval_millis,
            WormAnchor::new(),
        ))
    }

    /// Build a boot handle over a `_meta` writer DSN with a **durable**,
    /// file-backed WORM anchor at `anchor_path` ([`WormAnchor::open_file`]). The
    /// anchored head **persists across restarts** — this is the constructor the
    /// proxy/CLI use so an offline `_meta` full-chain rewrite is caught on the
    /// *next* boot via [`verify_then_anchor`](AuditBoot::verify_then_anchor).
    ///
    /// The file stand-in models object-lock / transparency-log retention the DB
    /// operator cannot rewrite; it is **not** itself true WORM (the production
    /// swap is documented on [`crate::anchor`]).
    pub fn connect_with_anchor(
        writer_dsn: &str,
        store: &impl SecretStore,
        interval_millis: u64,
        anchor_path: impl AsRef<Path>,
    ) -> Result<Self, BootError> {
        let signer = LocalKms::from_secret_store(store, AUDIT_SIGNING_KEY_ID)?;
        let worm = WormAnchor::open_file(anchor_path)?;
        let client =
            Client::connect(writer_dsn, NoTls).map_err(|e| BootError::Connect(e.to_string()))?;
        Ok(Self::with_sink_and_worm(
            PgSink::new(client),
            signer,
            interval_millis,
            worm,
        ))
    }

    /// Build a boot handle over an arbitrary backing [`Sink`] with an in-memory
    /// WORM anchor (e.g. an [`InMemorySink`](crate::sink::InMemorySink) in unit
    /// tests). See [`with_sink_and_worm`](AuditBoot::with_sink_and_worm) to supply
    /// a durable file-backed WORM (the cross-restart path).
    pub fn with_sink(
        sink: impl Sink + Send + 'static,
        signer: LocalKms,
        interval_millis: u64,
    ) -> Self {
        Self::with_sink_and_worm(sink, signer, interval_millis, WormAnchor::new())
    }

    /// Build a boot handle over an arbitrary backing [`Sink`] and an explicit
    /// [`WormAnchor`] — pass a [`WormAnchor::open_file`] to exercise the durable,
    /// cross-restart anchor path in tests. The sink is wrapped in a [`SharedSink`]
    /// so every consumer clone shares the one chain. The `signer` is both the
    /// anchorer's signing key and the retained verifier used by the startup verify
    /// (so a file-loaded anchor with no embedded verifier can still be checked).
    pub fn with_sink_and_worm(
        sink: impl Sink + Send + 'static,
        signer: LocalKms,
        interval_millis: u64,
        worm: WormAnchor,
    ) -> Self {
        let verifier = signer.verifier_handle();
        AuditBoot {
            sink: SharedSink::new(sink),
            worm,
            anchorer: Anchorer::new(signer, interval_millis),
            verifier,
        }
    }

    /// A cloneable handle to the **one** shared sink, to inject into a consumer
    /// (the proxy `Recorder`, the CLI flow). Every clone appends to and reads
    /// from the same canonical chain.
    pub fn shared_sink(&self) -> SharedSink {
        self.sink.clone()
    }

    /// The shared sink as the exact `Arc<Mutex<dyn Sink + Send>>` the proxy
    /// `Recorder` is constructed from — so the recorder and the anchorer/verify
    /// share the identical backing sink.
    pub fn sink_arc(&self) -> Arc<Mutex<dyn Sink + Send>> {
        self.sink.arc()
    }

    /// Read the canonical persisted chain back (oldest first).
    pub fn load_chain(&mut self) -> Result<Vec<crate::record::AuditRecord>, BootError> {
        Ok(self.sink.load_chain_mut()?)
    }

    /// Run one interval tick: anchor the **current persisted head** to the WORM
    /// sink iff an interval has elapsed (or this is the first tick). `now_monotonic_millis`
    /// comes from the caller's `core::Clock::monotonic_millis`.
    ///
    /// Returns the anchored head (and seq) if it published, or `None` if the
    /// interval has not elapsed.
    pub fn maybe_anchor(
        &mut self,
        now_monotonic_millis: u64,
    ) -> Result<Option<crate::anchor::Anchored>, BootError> {
        let records = self.sink.load_chain_mut()?;
        Ok(self
            .anchorer
            .maybe_anchor_records(&records, now_monotonic_millis, &mut self.worm)?)
    }

    /// The correct **fail-closed boot sequence** (SPEC §3/§10.9): verify the
    /// persisted `_meta` chain against the **prior durable anchored head**, then
    /// — only on a clean verify — anchor the chain **forward**.
    ///
    /// This ordering is the cross-restart tamper-evidence guarantee. Calling
    /// [`maybe_anchor`](AuditBoot::maybe_anchor) first would re-pin whatever head
    /// is currently in `_meta` (including an offline-forged head) and make the
    /// verify trivially pass — the hole this method closes. So:
    ///
    /// 1. If the durable WORM already holds an anchor (a **prior boot** pinned the
    ///    honest head), [`startup_verify`](AuditBoot::startup_verify) runs first:
    ///    the persisted chain must verify within-chain AND its head must match that
    ///    durable head, or boot **refuses to start** ([`BootError::AnchorHeadMismatch`]).
    /// 2. If the durable WORM is **empty** (legitimate first boot / genesis — nothing
    ///    was ever anchored), there is nothing to verify against yet; we only check
    ///    within-chain integrity, then anchor the baseline. From the second boot on,
    ///    step 1 applies.
    /// 3. After a clean verify, [`maybe_anchor`](AuditBoot::maybe_anchor) pins the
    ///    current head forward (durably).
    ///
    /// `now_monotonic_millis` comes from the caller's `core::Clock::monotonic_millis`.
    pub fn verify_then_anchor(&mut self, now_monotonic_millis: u64) -> Result<(), BootError> {
        let records = self.sink.load_chain_mut()?;
        // Within-chain integrity always holds (catches a mid-chain edit/delete).
        crate::chain::verify_chain(&records).map_err(BootError::ChainIntegrity)?;

        if self.worm.latest().is_some() {
            // A prior boot pinned a durable head: VERIFY the persisted chain
            // against it BEFORE re-anchoring. A full-chain rewrite (re-linked so
            // the within-chain check is blind) changed the head ⇒ mismatch ⇒
            // refuse to start.
            self.assert_head_matches_durable_anchor(&records)?;
        }
        // else: first boot / genesis — empty durable WORM, nothing to verify
        // against yet. The durable WORM's own integrity is the §10.9 trust anchor.

        // Only AFTER a clean verify do we anchor the current head forward.
        self.anchorer
            .maybe_anchor_records(&records, now_monotonic_millis, &mut self.worm)?;
        Ok(())
    }

    /// The **verify-only** boot for a non-owner binary (S5 #76, item 3). It checks
    /// the persisted `_meta` chain but NEVER anchors — so over the one shared chain
    /// there is exactly ONE anchorer (the owner). Fail-closed:
    ///
    /// 1. within-chain integrity must hold (catches a mid-chain edit/delete);
    /// 2. IF the durable WORM already holds the owner's anchored head, the chain's
    ///    head MUST match it ([`BootError::AnchorHeadMismatch`] otherwise) — so a
    ///    verify-only binary booting over a tampered chain REFUSES, and crucially
    ///    cannot re-baseline it (it does not anchor);
    /// 3. IF the durable WORM is still empty (the owner has not published the first
    ///    baseline yet — a benign genesis race), there is nothing to verify
    ///    against, so we pass on within-chain integrity alone WITHOUT anchoring. The
    ///    owner establishes the baseline; this binary will verify against it on its
    ///    next boot. (It never opens the re-baseline hole because it never anchors.)
    pub fn verify_only(&mut self) -> Result<(), BootError> {
        let records = self.sink.load_chain_mut()?;
        crate::chain::verify_chain(&records).map_err(BootError::ChainIntegrity)?;
        if self.worm.latest().is_some() {
            self.assert_head_matches_durable_anchor(&records)?;
        }
        // else: no owner baseline yet — verify-only does NOT anchor (single owner).
        Ok(())
    }

    /// Dispatch the correct boot sequence for `role` (S5 #76, item 3): the
    /// [`AnchorRole::Owner`] runs [`verify_then_anchor`](AuditBoot::verify_then_anchor)
    /// (verify-before-anchor + the interval anchorer), the [`AnchorRole::Verify`]
    /// runs [`verify_only`](AuditBoot::verify_only) (fail-closed, never anchors).
    /// `now_monotonic_millis` is the caller's `core::Clock::monotonic_millis`.
    pub fn boot(&mut self, role: AnchorRole, now_monotonic_millis: u64) -> Result<(), BootError> {
        match role {
            AnchorRole::Owner => self.verify_then_anchor(now_monotonic_millis),
            AnchorRole::Verify => self.verify_only(),
        }
    }

    /// **Fail-closed startup verification** (SPEC §3/§10.9). Loads the persisted
    /// `_meta` chain and asserts:
    ///
    /// 1. it verifies within-chain (no mid-chain edit/delete), and
    /// 2. its head matches the validly-signed **durable** WORM-anchored head.
    ///
    /// A full-chain rewrite (every record re-linked so step 1 passes) is caught
    /// at step 2 as [`BootError::AnchorHeadMismatch`]; a missing/forged anchor is
    /// a [`BootError::Anchor`]. Any error here means **refuse to start**.
    ///
    /// Use [`verify_then_anchor`](AuditBoot::verify_then_anchor) for the full boot
    /// sequence — it verifies against the *prior* durable head before anchoring
    /// forward, which is what makes the rewrite detectable across a restart. This
    /// method alone fails closed if **no** anchor has been published yet (e.g. a
    /// genuine first boot before any anchor) — call it only when a prior durable
    /// anchor is expected.
    pub fn startup_verify(&mut self) -> Result<(), BootError> {
        let records = self.sink.load_chain_mut()?;
        // (1) Within-chain integrity.
        crate::chain::verify_chain(&records).map_err(BootError::ChainIntegrity)?;
        // (2) Durable anchored-head match (catches a full-chain rewrite).
        self.assert_head_matches_durable_anchor(&records)
    }

    /// Verify a record slice's head against the latest **durable** anchored head,
    /// using the retained verifier (so a file-loaded anchor with no embedded
    /// verifier still checks). A mismatch is [`BootError::AnchorHeadMismatch`]; a
    /// missing/forged anchor is [`BootError::Anchor`].
    fn assert_head_matches_durable_anchor(
        &self,
        records: &[crate::record::AuditRecord],
    ) -> Result<(), BootError> {
        match verify_records_against_anchor_with(records, &self.worm, &self.verifier)? {
            AnchorVerification::Verified => Ok(()),
            AnchorVerification::HeadMismatch {
                anchored_head,
                actual_head,
                anchored_seq,
            } => Err(BootError::AnchorHeadMismatch {
                anchored_head,
                actual_head,
                anchored_seq,
            }),
        }
    }

    /// Borrow the WORM anchor (e.g. to inspect published entries in tests).
    pub fn worm(&self) -> &WormAnchor {
        &self.worm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Decision;
    use crate::sink::InMemorySink;
    use crate::{LocalSecretStore, NewEntry, Principal};
    use pgb_core::{Clock, MockClock};
    use pgb_policy::IntentTiers;

    fn signer() -> LocalKms {
        let mut store = LocalSecretStore::new();
        store
            .put(AUDIT_SIGNING_KEY_ID, b"boot-test-key-000001")
            .unwrap();
        LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).unwrap()
    }

    fn entry(role: &str, sql: &str, decision: Decision, code: &str) -> NewEntry {
        NewEntry {
            statement_text: sql.to_string(),
            decision,
            reason_code: code.to_string(),
            reason: None,
            principal: Principal {
                role: role.to_string(),
                session_id: Some("s".to_string()),
                principal: None,
            },
            intent: IntentTiers::default(),
            write_safety: Default::default(),
        }
    }

    #[test]
    fn boot_anchors_and_startup_verify_passes_on_honest_chain() {
        let clock = MockClock::starting_at(1_000);
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);

        // Two consumers share the one sink.
        let mut a = boot.shared_sink();
        let mut b = boot.shared_sink();
        a.append(
            entry("pgb_agent", "X", Decision::Reject, "rej"),
            clock.now_unix_millis(),
        )
        .unwrap();
        b.append(
            entry("human", "Y", Decision::Allow, "grant"),
            clock.now_unix_millis(),
        )
        .unwrap();

        // First tick anchors; startup verify then passes.
        boot.maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .unwrap();
        boot.startup_verify().expect("honest chain passes startup");
    }

    #[test]
    fn startup_verify_is_fail_closed_without_an_anchor() {
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Allow, "ok"), 1)
            .unwrap();
        // No maybe_anchor() call => no anchor published => refuse to start.
        let err = boot
            .startup_verify()
            .expect_err("no anchor must fail closed");
        assert!(matches!(err, BootError::Anchor(_)), "got {err:?}");
    }

    /// The honest boot sequence: `verify_then_anchor` over an empty durable WORM
    /// (genesis first boot) anchors the baseline; a second `verify_then_anchor`
    /// over the same handle verifies cleanly against the now-durable head.
    #[test]
    fn verify_then_anchor_genesis_then_clean_restart() {
        let clock = MockClock::starting_at(0);
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Reject, "rej"), 1)
            .unwrap();

        // First boot / genesis: empty WORM ⇒ nothing to verify against ⇒ anchor.
        boot.verify_then_anchor(clock.monotonic_millis())
            .expect("genesis boot anchors baseline");
        assert!(boot.worm().latest().is_some(), "baseline anchored");

        // A later in-process boot tick re-verifies against the durable head and
        // (interval elapsed) re-anchors — still clean.
        clock.advance(1_000);
        boot.verify_then_anchor(clock.monotonic_millis())
            .expect("clean restart verifies against the prior durable head");
    }

    /// **The cross-restart hole, closed (DB-free):** boot1 anchors the honest head
    /// to a DURABLE (file-backed) WORM. A fresh boot2 over the SAME WORM file but a
    /// `_meta` chain that was offline-rewritten into a consistent-but-different
    /// chain must REFUSE via `verify_then_anchor` — verify-BEFORE-anchor catches the
    /// forged head against the prior durable anchor.
    #[test]
    fn verify_then_anchor_refuses_forged_chain_across_durable_restart() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "pgb_boot_durable_{}.worm",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        // --- boot1: honest chain, anchored to the DURABLE file WORM. ---
        {
            let clock = MockClock::starting_at(0);
            let mut honest = InMemorySink::new();
            honest
                .append(
                    entry("pgb_agent", "UPDATE t SET x=1", Decision::Block, "ro"),
                    1,
                )
                .unwrap();
            honest
                .append(
                    entry("pgb_agent", "COPY t FROM STDIN", Decision::Reject, "copy"),
                    2,
                )
                .unwrap();
            let mut boot1 = AuditBoot::with_sink_and_worm(
                honest,
                signer(),
                1_000,
                WormAnchor::open_file(&path).unwrap(),
            );
            boot1
                .verify_then_anchor(clock.monotonic_millis())
                .expect("boot1 anchors honest head durably");
            // The file now holds the honest anchor.
            assert!(WormAnchor::open_file(&path).unwrap().latest().is_some());
        }

        // --- offline forge: a consistent-but-different `_meta` chain (BLOCK→ALLOW). ---
        let mut forged = InMemorySink::new();
        forged
            .append(
                entry("pgb_agent", "UPDATE t SET x=1", Decision::Allow, "ok"),
                1,
            )
            .unwrap();
        forged
            .append(
                entry("pgb_agent", "COPY t FROM STDIN", Decision::Reject, "copy"),
                2,
            )
            .unwrap();
        // The forged chain is internally consistent (within-chain verify passes).
        crate::chain::verify_chain(&forged.load_chain().unwrap()).unwrap();

        // --- boot2 (the REAL restart path): same durable WORM file, forged chain. ---
        let clock2 = MockClock::starting_at(0);
        let mut boot2 = AuditBoot::with_sink_and_worm(
            forged,
            signer(),
            1_000,
            WormAnchor::open_file(&path).unwrap(),
        );
        let err = boot2
            .verify_then_anchor(clock2.monotonic_millis())
            .expect_err("forged restart must FAIL CLOSED via verify-before-anchor");
        assert!(
            matches!(err, BootError::AnchorHeadMismatch { .. }),
            "expected AnchorHeadMismatch, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Positive durable restart: an UNtampered `_meta` chain over the same durable
    /// WORM file verifies and the boot proceeds (anchors forward).
    #[test]
    fn verify_then_anchor_accepts_untampered_durable_restart() {
        let path = std::env::temp_dir().join(format!(
            "pgb_boot_durable_ok_{}.worm",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        // Build the honest records once; reuse the identical bytes for both boots
        // so the persisted head is unchanged across the restart.
        let mk = || {
            let mut s = InMemorySink::new();
            s.append(entry("pgb_agent", "SELECT 1", Decision::Allow, "ok"), 1)
                .unwrap();
            s.append(entry("human", "GRANT", Decision::Allow, "grant"), 2)
                .unwrap();
            s
        };

        // boot1 anchors the honest head durably.
        {
            let mut boot1 = AuditBoot::with_sink_and_worm(
                mk(),
                signer(),
                1_000,
                WormAnchor::open_file(&path).unwrap(),
            );
            boot1.verify_then_anchor(0).expect("boot1 anchors");
        }

        // boot2 over the SAME durable WORM + the SAME (untampered) chain verifies
        // cleanly and anchors forward.
        let mut boot2 = AuditBoot::with_sink_and_worm(
            mk(),
            signer(),
            1_000,
            WormAnchor::open_file(&path).unwrap(),
        );
        boot2
            .verify_then_anchor(2_000)
            .expect("untampered durable restart verifies and starts");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn anchor_respects_the_injected_clock_interval() {
        let clock = MockClock::starting_at(0);
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Allow, "ok"), 1)
            .unwrap();

        // t=0 first tick anchors.
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_some());
        // t=500 not due.
        clock.advance(500);
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_none());
        // t=1000 due again.
        clock.advance(500);
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_some());
    }

    // -----------------------------------------------------------------------
    //  S5 #76 item 3 — SINGLE ANCHOR OWNER over the one shared chain.
    // -----------------------------------------------------------------------

    #[test]
    fn anchor_role_parse_defaults_and_values() {
        // Unset / empty ⇒ the binary's default.
        assert_eq!(
            AnchorRole::parse(None, AnchorRole::Owner).unwrap(),
            AnchorRole::Owner
        );
        assert_eq!(
            AnchorRole::parse(Some(""), AnchorRole::Verify).unwrap(),
            AnchorRole::Verify
        );
        // Explicit values (case-insensitive).
        assert_eq!(
            AnchorRole::parse(Some("owner"), AnchorRole::Verify).unwrap(),
            AnchorRole::Owner
        );
        assert_eq!(
            AnchorRole::parse(Some("VERIFY"), AnchorRole::Owner).unwrap(),
            AnchorRole::Verify
        );
        // Unrecognized ⇒ fail-closed error (never silently guess the topology).
        assert!(AnchorRole::parse(Some("both"), AnchorRole::Owner).is_err());
        assert!(AnchorRole::Owner.is_owner());
        assert!(!AnchorRole::Verify.is_owner());
    }

    /// A VERIFY-only boot over an empty durable WORM (the owner has not anchored
    /// the baseline yet) passes on within-chain integrity alone and does NOT
    /// anchor — so it never re-baselines, and there is only ONE anchorer (the
    /// owner). RED before item 3: there was no verify-only path; the non-owner ran
    /// `verify_then_anchor` and became a SECOND anchorer.
    #[test]
    fn verify_only_does_not_anchor_when_no_owner_baseline_exists() {
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Allow, "ok"), 1)
            .unwrap();

        boot.boot(AnchorRole::Verify, 0)
            .expect("verify-only boots clean over an un-anchored chain");
        assert!(
            boot.worm().latest().is_none(),
            "verify-only MUST NOT anchor — there is exactly one anchorer (the owner)"
        );
    }

    /// The coherent single-owner topology across a concurrent restart (DB-free):
    /// the OWNER anchors the honest baseline to a DURABLE file; a VERIFY-only
    /// binary booting over the SAME durable WORM but a tampered (offline-rewritten)
    /// chain REFUSES — and, because it never anchors, it cannot re-baseline the
    /// tampered chain. An honest verify-only boot over the untampered chain passes.
    #[test]
    fn verify_only_refuses_a_tampered_chain_and_never_rebaselines() {
        let path = std::env::temp_dir().join(format!(
            "pgb_boot_role_{}.worm",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        // OWNER anchors the honest baseline to the durable file.
        {
            let mut honest = InMemorySink::new();
            honest
                .append(
                    entry("pgb_agent", "UPDATE t SET x=1", Decision::Block, "ro"),
                    1,
                )
                .unwrap();
            let mut owner = AuditBoot::with_sink_and_worm(
                honest,
                signer(),
                1_000,
                WormAnchor::open_file(&path).unwrap(),
            );
            owner
                .boot(AnchorRole::Owner, 0)
                .expect("owner anchors the honest baseline");
            assert!(WormAnchor::open_file(&path).unwrap().latest().is_some());
        }

        // VERIFY-only over a TAMPERED chain (BLOCK→ALLOW, re-linked) + the same
        // durable WORM ⇒ head mismatch ⇒ REFUSE, and the WORM is untouched (no
        // re-baseline).
        {
            let mut forged = InMemorySink::new();
            forged
                .append(
                    entry("pgb_agent", "UPDATE t SET x=1", Decision::Allow, "ok"),
                    1,
                )
                .unwrap();
            crate::chain::verify_chain(&forged.load_chain().unwrap()).unwrap();
            let mut verifier = AuditBoot::with_sink_and_worm(
                forged,
                signer(),
                1_000,
                WormAnchor::open_file(&path).unwrap(),
            );
            let before = WormAnchor::open_file(&path).unwrap().entries().len();
            let err = verifier
                .boot(AnchorRole::Verify, 0)
                .expect_err("verify-only over a tampered chain must FAIL CLOSED");
            assert!(
                matches!(err, BootError::AnchorHeadMismatch { .. }),
                "expected AnchorHeadMismatch, got {err:?}"
            );
            let after = WormAnchor::open_file(&path).unwrap().entries().len();
            assert_eq!(
                before, after,
                "verify-only MUST NOT anchor (no re-baseline of a tampered chain)"
            );
        }

        // VERIFY-only over the UNTAMPERED chain + same durable WORM ⇒ passes,
        // still without anchoring.
        {
            let mut honest = InMemorySink::new();
            honest
                .append(
                    entry("pgb_agent", "UPDATE t SET x=1", Decision::Block, "ro"),
                    1,
                )
                .unwrap();
            let mut verifier = AuditBoot::with_sink_and_worm(
                honest,
                signer(),
                1_000,
                WormAnchor::open_file(&path).unwrap(),
            );
            let before = WormAnchor::open_file(&path).unwrap().entries().len();
            verifier
                .boot(AnchorRole::Verify, 0)
                .expect("verify-only over the honest chain passes");
            let after = WormAnchor::open_file(&path).unwrap().entries().len();
            assert_eq!(before, after, "verify-only still does not anchor");
        }

        let _ = std::fs::remove_file(&path);
    }
}
