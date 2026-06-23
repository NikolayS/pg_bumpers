//! `pgb-cli verify` — the **read-only chain verifier** over the shared, persistent
//! `_meta` audit chain (issue #64/#68, SPEC §3/§4/§10.9).
//!
//! The S5 marquee needs a single, reusable command that proves, at the end of a
//! run, that **every decision** the assembled stack made (proxy block, refuse,
//! approval, apply, warden kill) landed on **one** anchored `_meta` chain and that
//! the chain is intact. This module is that verifier's pure core: given the loaded
//! records, it runs the within-chain [`verify_chain`](pgb_audit::verify_chain) and
//! summarizes the head + a per-reason-code histogram, fail-closed (any break is an
//! `Err`). The binary's `verify` subcommand wires this over an [`AuditBoot`] which
//! ALSO checks the persisted chain against the external-WORM **anchored head**
//! (the full-chain-rewrite backstop) before this within-chain pass runs.
//!
//! Reusing `pgb_audit::verify_chain` (not a re-encoding) keeps the verifier in
//! lock-step with what the proxy/applyd/warden actually write.

use std::collections::BTreeMap;

use pgb_audit::{AuditRecord, ChainBreak, verify_chain};

/// A read-only summary of a verified `_meta` chain (the `verify` command output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSummary {
    /// The number of records on the chain.
    pub len: usize,
    /// The chain head hash (`record_hash` of the last record), or the genesis
    /// prev-hash for an empty chain.
    pub head: String,
    /// Per-`reason_code` counts (sorted), so a reviewer can see at a glance that
    /// the expected decisions (e.g. `STACKED_QUERY`, `NOT_REHEARSABLE`,
    /// `APPROVAL_REQUIRED`, `apply_committed`, `WARDEN_TERMINATE`) are all present.
    pub reason_code_counts: BTreeMap<String, usize>,
}

/// Verify a loaded `_meta` chain (within-chain hash links) and summarize it.
///
/// Fail-closed: returns `Err(ChainBreak)` (the FIRST broken link) if the chain
/// does not verify, so a caller can exit non-zero. On success returns the
/// [`ChainSummary`]. The anchored-head check (full-chain-rewrite backstop) is a
/// SEPARATE concern owned by [`pgb_audit::AuditBoot::startup_verify`]; the binary
/// runs both.
pub fn verify_meta_chain(records: &[AuditRecord]) -> Result<ChainSummary, ChainBreak> {
    verify_chain(records)?;
    let mut reason_code_counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in records {
        *reason_code_counts
            .entry(r.payload.reason_code.clone())
            .or_insert(0) += 1;
    }
    let head = records
        .last()
        .map(|r| r.record_hash.clone())
        .unwrap_or_else(|| pgb_audit::GENESIS_PREV_HASH.to_string());
    Ok(ChainSummary {
        len: records.len(),
        head,
        reason_code_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_audit::{Decision, IntentTiers, Principal, WriteSafetyRefs};
    use pgb_audit::{InMemorySink, NewEntry, Sink};

    fn entry(reason_code: &str, decision: Decision) -> NewEntry {
        NewEntry {
            statement_text: format!("stmt for {reason_code}"),
            decision,
            reason_code: reason_code.to_string(),
            reason: None,
            principal: Principal {
                role: "pgb_agent".into(),
                session_id: Some("sess".into()),
                principal: None,
            },
            intent: IntentTiers::default(),
            write_safety: WriteSafetyRefs {
                dry_run_id: None,
                blast_radius_ref: None,
            },
        }
    }

    #[test]
    fn verify_summarizes_an_intact_chain_with_per_code_counts() {
        let mut sink = InMemorySink::new();
        // Two blocks + one allow — the kind of mixed decision history the marquee
        // produces (a refuse, an approval, an apply).
        sink.append(entry("STACKED_QUERY", Decision::Block), 1)
            .unwrap();
        sink.append(entry("NOT_REHEARSABLE", Decision::Block), 2)
            .unwrap();
        sink.append(entry("apply_committed", Decision::Allow), 3)
            .unwrap();
        let chain = sink.load_chain().unwrap();

        let summary = verify_meta_chain(&chain).expect("intact chain must verify");
        assert_eq!(summary.len, 3);
        assert_eq!(summary.reason_code_counts.get("STACKED_QUERY"), Some(&1));
        assert_eq!(summary.reason_code_counts.get("NOT_REHEARSABLE"), Some(&1));
        assert_eq!(summary.reason_code_counts.get("apply_committed"), Some(&1));
        // The head is the last record's hash (non-empty).
        assert!(!summary.head.is_empty());
        assert_ne!(summary.head, pgb_audit::GENESIS_PREV_HASH);
    }

    #[test]
    fn verify_fails_closed_on_a_tampered_chain() {
        let mut sink = InMemorySink::new();
        sink.append(entry("A", Decision::Block), 1).unwrap();
        sink.append(entry("B", Decision::Block), 2).unwrap();
        let mut chain = sink.load_chain().unwrap();
        // Tamper a mid-chain record's statement → its hash no longer links.
        chain[0].payload.statement_text = "tampered".into();
        assert!(
            verify_meta_chain(&chain).is_err(),
            "a tampered chain must NOT verify (fail-closed)"
        );
    }

    #[test]
    fn empty_chain_summarizes_to_genesis_head() {
        let summary = verify_meta_chain(&[]).expect("empty chain trivially verifies");
        assert_eq!(summary.len, 0);
        assert_eq!(summary.head, pgb_audit::GENESIS_PREV_HASH);
        assert!(summary.reason_code_counts.is_empty());
    }
}
