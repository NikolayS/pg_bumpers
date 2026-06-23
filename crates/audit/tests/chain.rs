//! Hash-chain integrity + tamper-injection tests (SPEC §5, issue #21).
//!
//! These are the red/green acceptance criteria for the chain itself, all
//! DB-free and deterministic via `core::MockClock`:
//!   * a well-formed chain verifies; appending extends it;
//!   * **tamper-injection (the key test):** an edited mid-chain record is
//!     detected at that link; a deleted mid-chain record is detected;
//!   * rejects (blocked/rejected statements) are recorded as rows.

use pgb_audit::{
    AuditChain, ChainBreak, Decision, GENESIS_PREV_HASH, InMemorySink, NewEntry, Principal, Sink,
    verify_chain,
};
use pgb_core::{Clock, MockClock};
use pgb_policy::IntentTiers;

/// Build a `NewEntry` for `sql`/`decision`, deriving the logged T0–T2 intent
/// from the statement (exactly as the proxy will upstream).
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

/// A clock-stamped append helper: reads the unix stamp from the injected
/// `MockClock`, so the chain timestamps are deterministic and wall-clock-free.
fn append(chain: &mut AuditChain, clock: &MockClock, e: NewEntry) {
    chain.append(e, clock.now_unix_millis());
}

/// Seed a 3-record chain: an allowed read, a blocked write, a rejected stack.
fn seed_chain(clock: &MockClock) -> AuditChain {
    let mut chain = AuditChain::new();
    append(
        &mut chain,
        clock,
        entry("pgb_agent", "SELECT * FROM orders", Decision::Allow, "ok"),
    );
    clock.advance(10);
    append(
        &mut chain,
        clock,
        entry(
            "pgb_agent",
            "UPDATE orders SET status='x'",
            Decision::Block,
            "write_on_readonly",
        ),
    );
    clock.advance(10);
    append(
        &mut chain,
        clock,
        entry(
            "pgb_agent",
            "SELECT 1; DROP TABLE orders",
            Decision::Reject,
            "stacked_statement",
        ),
    );
    chain
}

#[test]
fn wellformed_chain_verifies_and_append_extends() {
    let clock = MockClock::starting_at(1_700_000_000_000);
    let mut chain = seed_chain(&clock);

    assert_eq!(chain.len(), 3);
    // Genesis anchors at the defined genesis prev-hash.
    assert_eq!(chain.records()[0].payload.prev_hash, GENESIS_PREV_HASH);
    // Each record links to its predecessor.
    assert_eq!(
        chain.records()[1].payload.prev_hash,
        chain.records()[0].record_hash
    );
    assert_eq!(
        chain.records()[2].payload.prev_hash,
        chain.records()[1].record_hash
    );
    // The well-formed chain verifies.
    chain.verify().expect("seeded chain must verify");

    // Appending extends it and the head advances.
    let head_before = chain.head_hash();
    clock.advance(10);
    append(
        &mut chain,
        &clock,
        entry("pgb_agent", "SELECT now()", Decision::Allow, "ok"),
    );
    assert_eq!(chain.len(), 4);
    assert_eq!(chain.records()[3].payload.prev_hash, head_before);
    chain.verify().expect("extended chain must still verify");
}

#[test]
fn tamper_edit_midchain_record_is_detected_at_that_link() {
    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);
    let mut records = chain.records().to_vec();

    // Intact chain verifies first (so the break we inject is the only cause).
    verify_chain(&records).expect("intact chain verifies");

    // TAMPER: edit the *content* of the mid-chain (index 1) record — flip the
    // recorded decision from BLOCK to ALLOW, as an attacker hiding that a write
    // was stopped would. The stored record_hash is left as-is (the attacker
    // cannot recompute it without re-chaining everything downstream).
    records[1].payload.decision = Decision::Allow;
    records[1].payload.reason_code = "ok".to_string();

    let break_found = verify_chain(&records).expect_err("edited record must be detected");
    match break_found {
        ChainBreak::HashMismatch { index, seq, .. } => {
            assert_eq!(index, 1, "break detected at the tampered link");
            assert_eq!(seq, 1);
        }
        other => panic!("expected HashMismatch at the edited link, got {other:?}"),
    }
}

#[test]
fn tamper_delete_midchain_record_is_detected() {
    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);
    let mut records = chain.records().to_vec();
    verify_chain(&records).expect("intact chain verifies");

    // TAMPER: delete the mid-chain (index 1) record entirely. Every surviving
    // record is still individually self-consistent, but the link/seq from the
    // record that followed the deleted one no longer matches — the gap is
    // detectable.
    records.remove(1);

    let break_found = verify_chain(&records).expect_err("deleted record must be detected");
    match break_found {
        // The former index-2 record is now at index 1; its seq is 2 (a gap from
        // the expected 1) and/or its prev_hash no longer matches index 0.
        ChainBreak::SeqGap {
            index,
            expected_seq,
            found_seq,
        } => {
            assert_eq!(index, 1, "gap detected right after the deletion");
            assert_eq!(expected_seq, 1);
            assert_eq!(found_seq, 2);
        }
        ChainBreak::BrokenLink { index, .. } => {
            assert_eq!(index, 1, "broken back-link detected after the deletion");
        }
        other => panic!("expected a gap/broken-link after deletion, got {other:?}"),
    }
}

#[test]
fn tamper_delete_head_then_relink_still_breaks_on_content() {
    // A subtler attack: delete the genesis and try to pass off record 1 as the
    // new head. Its prev_hash is NOT the genesis sentinel, so BadGenesis fires.
    let clock = MockClock::starting_at(1_700_000_000_000);
    let chain = seed_chain(&clock);
    let mut records = chain.records().to_vec();
    records.remove(0);

    let break_found = verify_chain(&records).expect_err("removed genesis must be detected");
    assert!(
        matches!(break_found, ChainBreak::BadGenesis { index: 0, .. }),
        "expected BadGenesis, got {break_found:?}"
    );
}

#[test]
fn rejects_are_recorded_as_rows() {
    // A blocked statement and a rejected statement each produce an audit row
    // (SPEC §4: "Records every statement incl. rejects").
    let clock = MockClock::new();
    let mut sink = InMemorySink::new();

    sink.append(
        entry(
            "pgb_agent",
            "DELETE FROM orders",
            Decision::Block,
            "write_on_readonly",
        ),
        clock.now_unix_millis(),
    )
    .unwrap();
    clock.advance(5);
    sink.append(
        entry(
            "pgb_agent",
            "COPY orders TO PROGRAM 'curl evil'",
            Decision::Reject,
            "copy_program_refused",
        ),
        clock.now_unix_millis(),
    )
    .unwrap();

    let rows = sink.load_chain().unwrap();
    assert_eq!(rows.len(), 2, "both rejecting decisions left a row");
    assert_eq!(rows[0].payload.decision, Decision::Block);
    assert!(rows[0].payload.decision.is_rejecting());
    assert_eq!(rows[1].payload.decision, Decision::Reject);
    assert!(rows[1].payload.decision.is_rejecting());
    // The recorded chain of rejects still verifies.
    sink.verify().expect("reject-only chain verifies");
}

#[test]
fn chain_is_deterministic_under_mock_clock() {
    // Two independent runs with the same MockClock schedule produce identical
    // record hashes — the canonical encoding + injected clock make the whole
    // chain reproducible (no wall-clock anywhere).
    let build = || {
        let clock = MockClock::starting_at(42);
        seed_chain(&clock)
    };
    let a = build();
    let b = build();
    let ha: Vec<_> = a.records().iter().map(|r| r.record_hash.clone()).collect();
    let hb: Vec<_> = b.records().iter().map(|r| r.record_hash.clone()).collect();
    assert_eq!(ha, hb, "identical clock schedule => identical chain hashes");
    // And the hash is sha256 hex (64 chars).
    assert_eq!(ha[0].len(), 64);
}

#[test]
fn empty_chain_is_valid() {
    let chain = AuditChain::new();
    assert!(chain.is_empty());
    chain.verify().expect("empty chain is a valid empty chain");
}
