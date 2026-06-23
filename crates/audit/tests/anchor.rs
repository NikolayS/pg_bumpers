//! External WORM/transparency anchor + KMS key-separation + secret-store tests
//! (SPEC §3, §4, §10.9; issue #54, S4).
//!
//! S1 (`tests/chain.rs`) proves *within-chain* tamper detection: editing or
//! deleting a mid-chain record breaks a hash link. But a determined attacker who
//! controls the audit table can rewrite the **entire** chain consistently —
//! re-hash and re-link *every* record around the edit — so the rewritten chain
//! verifies clean on its own. The S1 hash chain alone cannot catch that.
//!
//! The defence is an **external anchor**: on an interval (driven by the injected
//! `core::Clock`, never a wall clock) we sign the current chain head with a
//! KMS-held key the DB operator cannot reach, and publish the signed head to an
//! append-only/WORM sink with independent retention. A full-chain rewrite
//! produces a *different* head than the one already anchored, so verifying the
//! chain against the anchored head **fails** — the attacker cannot forge the
//! signature over the original head.
//!
//! These tests are DB-free and deterministic (no `PG_BUMPERS_IT`, no wall
//! clock). The env-gated PG18 path lives in `tests/pg_meta_it.rs`.

use pgb_audit::anchor::{
    AnchorError, AnchorVerification, Anchorer, WormAnchor, WormAnchorError, verify_against_anchor,
    verify_against_anchor_with,
};
use pgb_audit::kms::{Kms, KmsError, LocalKms, OPERATOR_PRINCIPAL};
use pgb_audit::secret::{AUDIT_SIGNING_KEY_ID, LocalSecretStore, SecretError, SecretStore};
use pgb_audit::{AuditChain, Decision, NewEntry, Principal};
use pgb_core::{Clock, MockClock};
use pgb_policy::IntentTiers;

/// Build a `NewEntry` for `sql`/`decision` (mirrors `tests/chain.rs`).
fn entry(role: &str, sql: &str, decision: Decision, reason_code: &str) -> NewEntry {
    NewEntry {
        statement_text: sql.to_string(),
        decision,
        reason_code: reason_code.to_string(),
        reason: None,
        principal: Principal {
            role: role.to_string(),
            session_id: Some("sess-1".to_string()),
            principal: None,
        },
        intent: IntentTiers::from_statement(role, sql, Some("anthropic-mcp".to_string())),
        write_safety: Default::default(),
    }
}

/// Seed a 3-record chain: an allowed read, a blocked write, a rejected stack.
fn seed_chain(clock: &MockClock) -> AuditChain {
    let mut chain = AuditChain::new();
    chain.append(
        entry("pgb_agent", "SELECT * FROM orders", Decision::Allow, "ok"),
        clock.now_unix_millis(),
    );
    clock.advance(10);
    chain.append(
        entry(
            "pgb_agent",
            "UPDATE orders SET status='x'",
            Decision::Block,
            "write_on_readonly",
        ),
        clock.now_unix_millis(),
    );
    clock.advance(10);
    chain.append(
        entry(
            "pgb_agent",
            "SELECT 1; DROP TABLE orders",
            Decision::Reject,
            "stacked_statement",
        ),
        clock.now_unix_millis(),
    );
    chain
}

/// A KMS dev signer loaded from the secret store, the way production wiring will
/// fetch the audit signing key — never from the DB host, never the operator key.
fn signer_from_store() -> LocalKms {
    let mut store = LocalSecretStore::new();
    // The signing key material lives ONLY in the secret store (dev impl); in
    // production this is a KMS handle, never on the DB host.
    store
        .put(AUDIT_SIGNING_KEY_ID, b"dev-audit-signing-key-material-0001")
        .expect("seed signing key");
    LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).expect("load signer from store")
}

// ---------------------------------------------------------------------------
// THE KEY PROPERTY: the anchored head catches a FULL-CHAIN REWRITE.
// ---------------------------------------------------------------------------

#[test]
fn anchored_head_detects_full_chain_rewrite() {
    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);

    // The operator anchors the *honest* head once (interval tick), signing it
    // with the KMS key and publishing to the WORM sink.
    let signer = signer_from_store();
    let mut worm = WormAnchor::new();
    let mut anchorer = Anchorer::new(signer, /* interval */ 60_000);

    // First tick anchors at t0 (no prior anchor).
    let anchored = anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .expect("anchor must succeed")
        .expect("first tick always anchors");
    assert_eq!(anchored.seq, chain.records().last().unwrap().seq());

    // The honest chain verifies against its anchored head.
    let v = verify_against_anchor(&chain, &worm).expect("verification runs");
    assert_eq!(
        v,
        AnchorVerification::Verified,
        "honest chain must verify against its anchored head"
    );

    // ---- ATTACK: a full, internally-consistent rewrite of the WHOLE chain. ----
    // The attacker edits the blocked UPDATE (index 1) to look permitted (ALLOW)
    // and then re-links + re-seals EVERY downstream record so the rewritten chain
    // passes S1's `verify_chain` on its own (no broken hash link).
    let mut forged = AuditChain::new();
    // Rebuild from the tampered entries, re-chaining cleanly:
    let clock2 = MockClock::starting_at(1_700_000_000_000);
    forged.append(
        entry("pgb_agent", "SELECT * FROM orders", Decision::Allow, "ok"),
        clock2.now_unix_millis(),
    );
    clock2.advance(10);
    forged.append(
        // tampered: was BLOCK/write_on_readonly, now ALLOW/ok
        entry(
            "pgb_agent",
            "UPDATE orders SET status='x'",
            Decision::Allow,
            "ok",
        ),
        clock2.now_unix_millis(),
    );
    clock2.advance(10);
    forged.append(
        entry(
            "pgb_agent",
            "SELECT 1; DROP TABLE orders",
            Decision::Reject,
            "stacked_statement",
        ),
        clock2.now_unix_millis(),
    );

    // The forged chain is internally consistent — S1 detection alone is blind.
    forged
        .verify()
        .expect("forged chain is internally consistent (S1 blind)");
    // Its head hash differs from the honest head (the edit propagated).
    assert_ne!(
        forged.records().last().unwrap().record_hash,
        chain.records().last().unwrap().record_hash,
        "rewrite must change the head hash"
    );

    // THE DETECTION: verifying the FORGED chain against the WORM-anchored head
    // FAILS — the anchored head is the honest one and the attacker cannot forge
    // the signature over it.
    let forged_v =
        verify_against_anchor(&forged, &worm).expect("verification runs over forged chain");
    match forged_v {
        AnchorVerification::HeadMismatch {
            anchored_head,
            actual_head,
            ..
        } => {
            assert_eq!(
                anchored_head,
                chain.records().last().unwrap().record_hash,
                "anchor still pins the honest head"
            );
            assert_eq!(
                actual_head,
                forged.records().last().unwrap().record_hash,
                "actual head is the forged one"
            );
        }
        other => panic!("expected HeadMismatch on a full-chain rewrite, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The anchor's own signature must be valid + WORM (append-only, tamper-evident).
// ---------------------------------------------------------------------------

#[test]
fn tampered_anchor_signature_is_rejected() {
    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);
    let signer = signer_from_store();
    let mut worm = WormAnchor::new();
    let mut anchorer = Anchorer::new(signer, 60_000);
    anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .unwrap()
        .unwrap();

    // An attacker who reaches the anchor sink and rewrites the recorded head to
    // match their forged chain CANNOT produce a valid signature (no KMS key), so
    // a forged anchor entry is detected as a bad signature.
    let forged_head = "deadbeef".repeat(8); // 64 hex chars, not the real head
    let tampered = worm.forge_latest_head_for_test(&forged_head);
    let v = verify_against_anchor(&chain, &tampered);
    assert!(
        matches!(v, Err(AnchorError::BadSignature { .. })),
        "a head swapped in the WORM sink without a valid KMS signature is rejected, got {v:?}"
    );
}

#[test]
fn worm_anchor_is_append_only() {
    // The WORM stand-in models object-lock: published anchor entries can be
    // appended and read, but never mutated or deleted in place — there is no
    // such method on the trait, and the local impl exposes none.
    let clock = MockClock::starting_at(1_000);
    let chain = seed_chain(&clock);
    let signer = signer_from_store();
    let mut worm = WormAnchor::new();
    let mut anchorer = Anchorer::new(signer, 10);

    // Two interval ticks => two appended anchor entries; the log only grows.
    anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .unwrap()
        .expect("first tick anchors");
    let after_first = worm.entries().len();
    clock.advance(10);
    let mut chain2 = chain.clone();
    chain2.append(
        entry("pgb_agent", "SELECT now()", Decision::Allow, "ok"),
        clock.now_unix_millis(),
    );
    anchorer
        .maybe_anchor(&chain2, clock.monotonic_millis(), &mut worm)
        .unwrap()
        .expect("second tick anchors");
    assert_eq!(
        worm.entries().len(),
        after_first + 1,
        "anchor log only grows"
    );
    // The latest entry pins the newer head.
    assert_eq!(
        worm.latest().unwrap().head_hash,
        chain2.records().last().unwrap().record_hash
    );
}

// ---------------------------------------------------------------------------
// Interval anchoring is clock-driven (no wall clock): a tick before the interval
// elapses does NOT anchor; a tick at/after the interval does.
// ---------------------------------------------------------------------------

#[test]
fn anchoring_respects_the_injected_clock_interval() {
    let clock = MockClock::starting_at(0);
    let chain = seed_chain(&clock);
    let signer = signer_from_store();
    let mut worm = WormAnchor::new();
    let interval = 1_000;
    let mut anchorer = Anchorer::new(signer, interval);

    // t=0: first tick anchors (no prior anchor — bootstrap).
    let a0 = anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .unwrap();
    assert!(a0.is_some(), "first tick bootstraps the anchor");
    assert_eq!(worm.entries().len(), 1);

    // t=500: interval not yet elapsed -> NO new anchor.
    clock.advance(500);
    let a1 = anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .unwrap();
    assert!(a1.is_none(), "before the interval elapses, no re-anchor");
    assert_eq!(worm.entries().len(), 1, "no new WORM entry mid-interval");

    // t=1000: interval elapsed -> a new anchor is published.
    clock.advance(500);
    let a2 = anchorer
        .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
        .unwrap();
    assert!(a2.is_some(), "at the interval boundary, re-anchor");
    assert_eq!(
        worm.entries().len(),
        2,
        "a second WORM entry at the boundary"
    );
}

// ---------------------------------------------------------------------------
// KEY SEPARATION — the audited / DB-operator principal can neither sign a head
// nor produce a valid anchor. Type-level: the signing capability has no public
// ctor, no Deserialize, no Default. Runtime: the operator principal is rejected.
// ---------------------------------------------------------------------------

#[test]
fn operator_principal_cannot_obtain_the_signer() {
    // Attempting to load the signing capability *as the audited DB-operator
    // principal* is rejected — the key is KMS-held and separated from the
    // operator (SPEC §10.9: "signing key ... never on the DB host").
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"dev-audit-signing-key-material-0001")
        .unwrap();
    let err = LocalKms::for_principal(&store, AUDIT_SIGNING_KEY_ID, OPERATOR_PRINCIPAL)
        .expect_err("operator principal must be denied the signer");
    assert!(
        matches!(err, KmsError::OperatorPrincipalDenied { .. }),
        "operator principal is denied the signing capability, got {err:?}"
    );
}

#[test]
fn secret_store_hides_key_material_and_rotates() {
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"v1-key-material-aaaaaaaaaaaaaaaa")
        .unwrap();

    // A signer built over v1 produces a stable signature for a fixed head.
    let s1 = LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).unwrap();
    let head = "a".repeat(64);
    let sig_v1 = s1.sign_head(&head, 5, 1_000);

    // ROTATION: replace the key material. A new signer over v2 signs the SAME
    // head differently — proving the signature actually depends on the secret.
    store
        .rotate(AUDIT_SIGNING_KEY_ID, b"v2-key-material-bbbbbbbbbbbbbbbb")
        .unwrap();
    let s2 = LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).unwrap();
    let sig_v2 = s2.sign_head(&head, 5, 1_000);
    assert_ne!(
        sig_v1.signature, sig_v2.signature,
        "rotated key must change the signature over the same head"
    );

    // A missing key is a typed error, never a panic / empty signature.
    let missing = LocalKms::from_secret_store(&store, "no-such-key");
    assert!(matches!(
        missing,
        Err(KmsError::Secret(SecretError::NotFound { .. }))
    ));
}

#[test]
fn worm_file_anchor_persists_and_reloads() {
    // The local WORM stand-in is an append-only, object-locked *file*: anchors
    // published to it survive a reload (independent retention), and the reloaded
    // anchor still verifies an honest chain. This is the file-backed sibling of
    // the in-memory `WormAnchor`; production target is S3 object-lock /
    // transparency log (documented in deploy/).
    let dir = std::env::temp_dir().join(format!("pgb_worm_it_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("anchor.worm");
    let _ = std::fs::remove_file(&path);

    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);
    let signer = signer_from_store();

    {
        let mut worm = WormAnchor::open_file(&path).expect("open worm file");
        let mut anchorer = Anchorer::new(signer, 60_000);
        anchorer
            .maybe_anchor(&chain, clock.monotonic_millis(), &mut worm)
            .unwrap()
            .expect("anchor to file");
    }
    // Reopen from disk — the anchor entry is still there and still verifies.
    let reloaded = WormAnchor::open_file(&path).expect("reopen worm file");
    assert_eq!(
        reloaded.entries().len(),
        1,
        "anchor persisted across reload"
    );
    let signer2 = signer_from_store();
    let v = verify_against_anchor_with(&chain, &reloaded, &signer2)
        .expect("verify with explicit verifier");
    assert_eq!(v, AnchorVerification::Verified);

    // Append-only file: opening it must not have truncated it; a second open is
    // idempotent and preserves the single entry.
    let _ = WormAnchor::open_file(&path).expect("third open");
    let reloaded2 = WormAnchor::open_file(&path).unwrap();
    assert_eq!(
        reloaded2.entries().len(),
        1,
        "reopen never truncates the WORM file"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);

    // Touch the file-error type so it is reachable from the public API.
    let bad = WormAnchor::open_file("/nonexistent-dir-xyz/anchor.worm");
    assert!(matches!(bad, Err(WormAnchorError::Io { .. })));
}
