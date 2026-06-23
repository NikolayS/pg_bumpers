//! Unit (DB-free) tests for the S5 shared-chain + slice-anchor seam (issue #64,
//! SPEC §3/§4/§10.9).
//!
//! S4 shipped the chain, the `_meta` `PgSink`, and the anchor as libraries, but
//! the proxy and CLI each built a **separate** in-memory chain with an
//! independent genesis, and the anchor only knew how to pin an in-memory
//! `AuditChain`. S5 collapses those into ONE shared sink and lets the anchor +
//! the fail-closed startup verify run over the **records read back** from the
//! canonical (persistent) chain.
//!
//! These tests prove that seam deterministically with an [`InMemorySink`] behind
//! the [`SharedSink`] (the real wiring uses the Postgres `_meta` `PgSink` behind
//! the same `SharedSink`; the env-gated PG18 IT exercises that path).

use pgb_audit::{
    AUDIT_SIGNING_KEY_ID, AnchorError, AnchorVerification, Anchorer, Decision, InMemorySink,
    LocalKms, LocalSecretStore, NewEntry, Principal, SecretStore, SharedSink, Sink, WormAnchor,
    head_of, verify_chain, verify_records_against_anchor,
};
use pgb_core::{Clock, MockClock};
use pgb_policy::IntentTiers;

fn entry(role: &str, sql: &str, decision: Decision, code: &str) -> NewEntry {
    NewEntry {
        statement_text: sql.to_string(),
        decision,
        reason_code: code.to_string(),
        reason: None,
        principal: Principal {
            role: role.to_string(),
            session_id: Some("sess".to_string()),
            principal: None,
        },
        intent: IntentTiers::from_statement(role, sql, Some("test".to_string())),
        write_safety: Default::default(),
    }
}

fn signer() -> LocalKms {
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"s5-shared-anchor-test-key-000001")
        .unwrap();
    LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).unwrap()
}

/// THE S5 KEY PROPERTY: two independent consumers (modelling the proxy + the
/// CLI) append to the SAME shared sink — one genesis — the persisted chain
/// verifies, an anchor taken over the loaded chain pins its head, and the head
/// matches.
#[test]
fn two_consumers_share_one_chain_and_anchor_matches_head() {
    let clock = MockClock::starting_at(1_700_000_000_000);

    // ONE backing sink, shared by two consumers via cloned handles.
    let shared = SharedSink::new(InMemorySink::new());
    let mut proxy_side = shared.clone();
    let mut cli_side = shared.clone();

    // Proxy records a REJECT (a blocked hostile statement).
    proxy_side
        .append(
            entry(
                "pgb_agent",
                "COMMIT; DROP SCHEMA public CASCADE",
                Decision::Reject,
                "simple_query_rejected",
            ),
            clock.now_unix_millis(),
        )
        .unwrap();
    clock.advance(5);
    // CLI records an APPROVE (a human-signed grant) — onto the SAME chain.
    cli_side
        .append(
            entry(
                "human-alice",
                "UPDATE orders SET status='fixed' WHERE id=$1",
                Decision::Allow,
                "grant_signed",
            ),
            clock.now_unix_millis(),
        )
        .unwrap();

    // The persisted chain has BOTH events, in order, single genesis (seq 0,1).
    let records = shared.load_chain().expect("load shared chain");
    assert_eq!(records.len(), 2, "both consumers landed on ONE chain");
    assert_eq!(records[0].payload.seq, 0, "single genesis at seq 0");
    assert_eq!(records[1].payload.seq, 1);
    assert_eq!(records[0].payload.decision, Decision::Reject);
    assert_eq!(records[1].payload.decision, Decision::Allow);
    assert_eq!(
        records[1].payload.prev_hash, records[0].record_hash,
        "the CLI record links to the proxy record — one hash chain"
    );
    verify_chain(&records).expect("shared chain verifies");

    // Anchor the canonical chain (over the loaded records) and confirm the
    // anchored head matches the chain head.
    let mut worm = WormAnchor::new();
    let mut anchorer = Anchorer::new(signer(), 60_000);
    let anchored = anchorer
        .maybe_anchor_records(&records, clock.monotonic_millis(), &mut worm)
        .expect("anchor ok")
        .expect("first tick anchors");
    let (head, _seq, _ts) = head_of(&records);
    assert_eq!(anchored.head_hash, head, "anchored head == chain head");

    assert_eq!(
        verify_records_against_anchor(&records, &worm).expect("verify runs"),
        AnchorVerification::Verified,
        "the canonical chain verifies against its anchored head",
    );
}

/// FAIL-CLOSED STARTUP: a full-chain rewrite (every record re-linked so the
/// within-chain `verify_chain` is happy) is caught by the anchor, exactly as the
/// proxy/CLI startup check would catch it.
#[test]
fn full_chain_rewrite_is_caught_against_anchor_at_startup() {
    let clock = MockClock::starting_at(1_700_000_000_000);

    let shared = SharedSink::new(InMemorySink::new());
    let mut h = shared.clone();
    h.append(
        entry("pgb_agent", "SELECT 1", Decision::Allow, "ok"),
        clock.now_unix_millis(),
    )
    .unwrap();
    clock.advance(5);
    h.append(
        entry(
            "pgb_agent",
            "UPDATE t SET x=1",
            Decision::Block,
            "write_on_readonly",
        ),
        clock.now_unix_millis(),
    )
    .unwrap();

    let honest = shared.load_chain().unwrap();

    // Anchor the honest head.
    let mut worm = WormAnchor::new();
    let mut anchorer = Anchorer::new(signer(), 60_000);
    anchorer
        .maybe_anchor_records(&honest, clock.monotonic_millis(), &mut worm)
        .unwrap()
        .unwrap();

    // ATTACK: rebuild the WHOLE chain with the BLOCK flipped to ALLOW, re-linked
    // cleanly. `verify_chain` passes on the forgery (S1 blind), but the head
    // differs, so the anchor catches it.
    let clock2 = MockClock::starting_at(1_700_000_000_000);
    let forged_sink = SharedSink::new(InMemorySink::new());
    let mut f = forged_sink.clone();
    f.append(
        entry("pgb_agent", "SELECT 1", Decision::Allow, "ok"),
        clock2.now_unix_millis(),
    )
    .unwrap();
    clock2.advance(5);
    f.append(
        // tampered: was BLOCK, now ALLOW
        entry("pgb_agent", "UPDATE t SET x=1", Decision::Allow, "ok"),
        clock2.now_unix_millis(),
    )
    .unwrap();
    let forged = forged_sink.load_chain().unwrap();
    verify_chain(&forged).expect("forged chain is internally consistent (S1 blind)");

    // The startup verify over the FORGED records FAILS — head mismatch.
    match verify_records_against_anchor(&forged, &worm).expect("verify runs") {
        AnchorVerification::HeadMismatch {
            anchored_head,
            actual_head,
            ..
        } => {
            assert_eq!(
                anchored_head,
                honest.last().unwrap().record_hash,
                "anchor still pins the honest head"
            );
            assert_eq!(actual_head, forged.last().unwrap().record_hash);
        }
        other => panic!("expected HeadMismatch on full-chain rewrite, got {other:?}"),
    }
}

/// FAIL-CLOSED with NO anchor: a startup verify with nothing anchored yet must
/// be a hard error, never a silent "ok" (we cannot assert the chain was not
/// rewritten without an anchor).
#[test]
fn startup_verify_with_no_anchor_is_fail_closed() {
    let clock = MockClock::starting_at(1);
    let shared = SharedSink::new(InMemorySink::new());
    let mut h = shared.clone();
    h.append(
        entry("pgb_agent", "SELECT 1", Decision::Allow, "ok"),
        clock.now_unix_millis(),
    )
    .unwrap();
    let records = shared.load_chain().unwrap();
    let worm = WormAnchor::new(); // nothing published, no verifier embedded
    let err = verify_records_against_anchor(&records, &worm)
        .expect_err("no anchor must be a hard error, not a silent pass");
    assert!(
        matches!(err, AnchorError::NoVerifier | AnchorError::NoAnchor),
        "fail-closed on a missing anchor, got {err:?}"
    );
}
