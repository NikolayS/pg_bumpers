//! pg_bumpers CLI binary (`pgb-cli`) — the MVP approval surface (SPEC §14).
//!
//! Subcommands:
//! - `pgb-cli approve <request-id>` — a human approver signs the §14.3
//!   proposal-bound grant for a pending request. In a real deployment the
//!   request store, the approver's audit-key-grade signing key (§10.9), and the
//!   webhook target are resolved from `policy.yaml` / KMS; this binary wires the
//!   library flow and documents the contract.
//! - `pgb-cli demo` — runs the full request → approve → verify-at-apply flow
//!   in-process against an in-memory store + audit chain, printing each step.
//!   This is a runnable smoke of the §14 mechanism (no DB, no network).
//! - `pgb-cli keygen` — generate a throwaway Ed25519 approver keypair and print
//!   two hex lines to stdout: line 1 = the 32-byte signing-key **seed**, line 2 =
//!   the 32-byte **verifying key** (pubkey). This is the Rust-native replacement
//!   for the keypair generation `deploy/up.sh` previously shelled out to: the seed
//!   feeds `SigningKey::from_bytes` and the pubkey feeds applyd's
//!   `PGB_APPROVER_PUBKEY` (`VerifyingKey::from_bytes`) — byte-identical to the
//!   old `last-32-bytes-of-the-PKCS8-DER` derivation, so existing keys still work.
//!
//! The cryptography is entirely `pgb_policy`'s grant token (reused, not
//! reimplemented); this binary is glue + UX.

use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use pgb_audit::{AUDIT_SIGNING_KEY_ID, AuditBoot, LocalSecretStore, SecretStore, Sink};
use pgb_cli::{
    ApprovalFlow, InMemoryNonceStore, Principal, Proposal, RecordingWebhookSender, RequestId,
    verify_meta_chain,
};
use pgb_core::{Clock, SystemClock, inverse::Operation};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("approve") => match args.get(2) {
            Some(id) => {
                // In the MVP binary the request store is per-process; a real
                // deployment resolves it (and the signing key) from policy/KMS.
                // We document the contract and exit non-zero because there is no
                // standing request in this stub invocation.
                eprintln!(
                    "pgb-cli approve: would sign a single-use, proposal-bound grant for \
                     request `{id}` using the approver's audit-key-grade signing key (SPEC \
                     §10.9). The agent can never self-approve. Wire the request store + KMS \
                     key from policy.yaml to use this against a live request; run `pgb-cli \
                     demo` for an in-process end-to-end run."
                );
                ExitCode::from(2)
            }
            None => {
                eprintln!("usage: pgb-cli approve <request-id>");
                ExitCode::from(2)
            }
        },
        Some("demo") => match run_demo() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("pgb-cli demo failed: {e}");
                ExitCode::from(1)
            }
        },
        Some("verify") => match run_verify() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("pgb-cli verify FAILED (fail-closed): {e}");
                ExitCode::from(1)
            }
        },
        Some("keygen") => {
            run_keygen();
            ExitCode::SUCCESS
        }
        _ => {
            println!(
                "pgb-cli — pg_bumpers approval CLI (SPEC §14 MVP).\n\
                 usage:\n  \
                 pgb-cli approve <request-id>   sign a proposal-bound grant (human approver)\n  \
                 pgb-cli demo                   run request -> approve -> verify-at-apply\n  \
                 pgb-cli verify                 load + verify the shared `_meta` chain + anchored head\n  \
                 pgb-cli keygen                 print a fresh Ed25519 approver keypair (seed hex, then pubkey hex)\n\
                 \n\
                 Set PGB_META_DSN (audit-writer DSN) + PGB_AUDIT_SIGNING_KEY to run the demo\n\
                 against the SHARED, persistent, anchored `_meta` chain (the one the proxy\n\
                 also writes); otherwise the demo runs in-process on an in-memory chain.\n\
                 `verify` needs PGB_META_DSN + PGB_AUDIT_SIGNING_KEY + PGB_ANCHOR_PATH."
            );
            ExitCode::SUCCESS
        }
    }
}

/// `pgb-cli keygen` — generate a fresh throwaway Ed25519 approver keypair and
/// print it as two hex lines to stdout: line 1 = the 32-byte signing-key **seed**
/// (`SigningKey::to_bytes`), line 2 = the 32-byte **verifying key**
/// (`VerifyingKey::to_bytes`, the apply-time trust root).
///
/// This is the Rust-native replacement for the keypair generation `deploy/up.sh`
/// previously shelled out to (issue #101). The shapes are **byte-identical** to the
/// values `crates/applyd` parses: the seed round-trips through
/// `SigningKey::from_bytes`, and the pubkey is exactly what
/// `PGB_APPROVER_PUBKEY` feeds into `VerifyingKey::from_bytes`. The old non-Rust
/// generator took the last 32 bytes of the PKCS8 DER as the seed, which is the same
/// 32 bytes `to_bytes()` returns — so keys minted either way are interchangeable.
fn run_keygen() {
    let signing_key = SigningKey::generate(&mut OsRng);
    // Line 1: the 32-byte seed — the private signing material the approve path parses
    // via `SigningKey::from_bytes` to SIGN the grant; applyd verifies at apply time
    // with the line-2 public key.
    println!("{}", hex::encode(signing_key.to_bytes()));
    // Line 2: the 32-byte public verifying key (applyd's PGB_APPROVER_PUBKEY).
    println!("{}", hex::encode(signing_key.verifying_key().to_bytes()));
}

/// `pgb-cli verify` — load the shared, persistent `_meta` chain and **fail-closed
/// verify** it, then prove the **anchored-head** guarantee over the unified chain:
///
/// 1. load every record the assembled stack wrote (proxy block, refuse, approval,
///    apply, warden kill) — one chain, written by multiple components;
/// 2. [`verify_meta_chain`] — the within-chain hash links are intact (one genesis,
///    contiguous, un-tampered) → this is the cross-component UNITY proof;
/// 3. `verify_then_anchor` over the caller-supplied `PGB_ANCHOR_PATH` — the same
///    fail-closed boot sequence #64 ships: verify-within-chain, then pin the
///    current head to the durable external WORM; we then assert the durable
///    anchored head EQUALS the chain head (the full-chain-rewrite backstop, proven
///    exactly as `crates/cli/tests/shared_meta_it.rs` does).
///
/// The verify step uses its OWN anchor file (distinct from the running applyd's),
/// so re-anchoring here pins the FINAL unified head without disturbing the
/// daemon's anchor. Any break exits non-zero (fail-closed). Prints the head + a
/// per-reason-code histogram so a reviewer sees every expected decision is present.
fn run_verify() -> Result<(), String> {
    let clock = SystemClock::new();
    let dsn = std::env::var("PGB_META_DSN").map_err(|_| {
        "PGB_META_DSN is required (the `_meta` audit DSN to verify the shared chain)".to_string()
    })?;
    if dsn.is_empty() {
        return Err("PGB_META_DSN is set but empty; refusing (fail-closed)".to_string());
    }
    let key = std::env::var("PGB_AUDIT_SIGNING_KEY").map_err(|_| {
        "PGB_AUDIT_SIGNING_KEY is required (the anchor signing key) and has no default".to_string()
    })?;
    let anchor_path = std::env::var("PGB_ANCHOR_PATH").map_err(|_| {
        "PGB_ANCHOR_PATH is required (the durable WORM anchor path for the verify step; use a \
         FRESH path distinct from the running daemon's) and has no default"
            .to_string()
    })?;
    if anchor_path.is_empty() {
        return Err("PGB_ANCHOR_PATH is set but empty; refusing (fail-closed)".to_string());
    }
    let interval_ms: u64 = std::env::var("PGB_ANCHOR_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000);

    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, key.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut boot = AuditBoot::connect_with_anchor(&dsn, &store, interval_ms, &anchor_path)
        .map_err(|e| format!("audit `_meta` boot failed (fail-closed): {e}"))?;

    // (1)+(2) Load + within-chain verification, with the head/per-code summary.
    let records = boot
        .load_chain()
        .map_err(|e| format!("load `_meta` chain: {e}"))?;
    let summary = verify_meta_chain(&records)
        .map_err(|brk| format!("within-chain verification failed at {brk:?}"))?;

    // (3) Anchor the unified head to the durable WORM (fail-closed boot sequence)
    //     and assert the durable anchored head equals the chain head.
    boot.verify_then_anchor(clock.monotonic_millis())
        .map_err(|e| format!("verify_then_anchor over the unified chain failed: {e}"))?;
    let anchored = boot
        .worm()
        .latest()
        .ok_or_else(|| "no anchor was published (fail-closed)".to_string())?;
    if anchored.head_hash != summary.head {
        return Err(format!(
            "anchored head {} != chain head {} (full-chain rewrite?)",
            anchored.head_hash, summary.head
        ));
    }

    println!(
        "pgb-cli verify: the shared `_meta` chain VERIFIES ({} records) and the durable anchored \
         head MATCHES the chain head.\n  head = {}\n  anchored_seq = {}\n  decisions by reason_code:",
        summary.len, summary.head, anchored.seq
    );
    for (code, n) in &summary.reason_code_counts {
        println!("    {code:32} x{n}");
    }
    Ok(())
}

/// Run the full §14 flow + print each step. When `PGB_META_DSN` +
/// `PGB_AUDIT_SIGNING_KEY` are set, the flow hash-chains into the **shared,
/// persistent, anchored `_meta` chain** (issue #64 — the same chain the proxy
/// writes), and the run anchors + fail-closed-verifies it on exit. Otherwise it
/// runs in-process on an in-memory chain (the DB-free smoke).
fn run_demo() -> Result<(), String> {
    let clock = SystemClock::new();

    // The approver's audit-key-grade signing key (§10.9). In production this is
    // KMS-held and separated from the DB operator; here it is generated for the
    // demo and its public half seeds the flow's verifier.
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    match (
        std::env::var("PGB_META_DSN").ok(),
        std::env::var("PGB_AUDIT_SIGNING_KEY").ok(),
    ) {
        (Some(dsn), Some(key)) if !dsn.is_empty() && !key.is_empty() => {
            // SHARED `_meta` path: build the boot handle over a DURABLE WORM,
            // FAIL-CLOSED verify-before-anchor on boot (the prior durable head must
            // match the persisted chain), run the flow against a clone of its
            // shared sink, then anchor the newly-extended head forward.
            let interval_ms: u64 = std::env::var("PGB_ANCHOR_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60_000);
            // The durable anchor path: persisted across restarts so the boot can
            // verify against the prior head before re-anchoring (fail-closed).
            let anchor_path = std::env::var("PGB_ANCHOR_PATH").map_err(|_| {
                "PGB_ANCHOR_PATH is required (the durable WORM anchor path) and has no \
                 default — the cross-restart tamper-evidence guarantee needs it"
                    .to_string()
            })?;
            if anchor_path.is_empty() {
                return Err("PGB_ANCHOR_PATH is set but empty; refusing (fail-closed)".to_string());
            }
            let mut store = LocalSecretStore::new();
            store
                .put(AUDIT_SIGNING_KEY_ID, key.as_bytes())
                .map_err(|e| e.to_string())?;
            let mut boot = AuditBoot::connect_with_anchor(&dsn, &store, interval_ms, &anchor_path)
                .map_err(|e| format!("audit _meta boot failed (fail-closed): {e}"))?;

            // VERIFY BEFORE ANCHOR on boot: the persisted chain must match the
            // PRIOR durable anchored head (catches an offline full-chain rewrite
            // across a restart); only then anchor the current head forward. Genesis
            // first run (empty durable WORM) anchors the baseline.
            boot.verify_then_anchor(clock.monotonic_millis())
                .map_err(|e| {
                    format!("audit `_meta` startup verification failed (fail-closed): {e}")
                })?;

            let audit = boot.shared_sink();
            run_flow(audit, &signing_key, verifying_key, &clock)?;

            // Anchor the head we just extended forward (durably).
            boot.maybe_anchor(clock.monotonic_millis())
                .map_err(|e| format!("audit anchor failed: {e}"))?;
            let n = boot.load_chain().map(|c| c.len()).unwrap_or(0);
            println!(
                "audit: {n} records on the SHARED, durably-anchored `_meta` chain; \
                 chain verified against its prior anchored head before extending"
            );
            Ok(())
        }
        _ => {
            // DB-free smoke on an in-memory chain, wrapped in a SharedSink so we
            // can read the same chain back after the flow consumes its handle.
            let audit = pgb_audit::SharedSink::new(pgb_audit::InMemorySink::new());
            let readback = audit.clone();
            run_flow(audit, &signing_key, verifying_key, &clock)?;
            let chain_ok = readback.verify().is_ok();
            println!(
                "audit: {} records (in-memory), chain intact={}",
                readback.load_chain().map(|c| c.len()).unwrap_or(0),
                chain_ok
            );
            Ok(())
        }
    }
}

/// Drive request → approve → verify-at-apply over an arbitrary audit [`Sink`],
/// printing each step. The audit sink is whatever the caller injected — an
/// in-memory chain or a clone of the shared, persistent `_meta` chain.
fn run_flow<S: Sink>(
    audit: S,
    signing_key: &SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    clock: &dyn Clock,
) -> Result<(), String> {
    let mut flow = ApprovalFlow::new(
        audit,
        RecordingWebhookSender::new(),
        verifying_key,
        InMemoryNonceStore::new(),
    );

    let proposal = Proposal {
        proposal_id: "p-demo-1".to_string(),
        statement_text: "UPDATE public.orders SET status='fixed' WHERE id = $1".to_string(),
        normalized_params: vec!["42".to_string()],
        role: "app_writer".to_string(),
        session_id: "sess-demo".to_string(),
        dry_run_lsn: "3A/7F00C8".to_string(),
        // EPIC #91 PR-B: the approver-authorized absolute cap (here a demo value the
        // CLI would pre-fill from the dry-run footprint + headroom).
        cap: pgb_core::WriteCap::new(1, 4096),
    };
    // A bounded, reversible UPDATE — eligible for elevation (not structural).
    let op = Operation::Update {
        has_preimage: true,
        has_pk: true,
    };
    let id = RequestId("req-demo-1".to_string());

    // 1. The blocked write opens an APPROVAL_REQUIRED ticket + fires the webhook.
    let outcome = flow
        .request_elevation(id.clone(), proposal, "agent-demo", &op, 60_000, clock)
        .map_err(|e| format!("request_elevation: {e}"))?;
    println!(
        "1) request_elevation -> {} (request {}, webhook delivered={})",
        outcome.contract.code,
        outcome.contract.request_id,
        outcome.webhook.is_ok()
    );

    // 2. A human approver (NOT the agent) signs the grant.
    let approver = Principal::approver("human-alice");
    let approval = flow
        .approve(&id, &approver, signing_key, "nonce-demo-1", 30_000, clock)
        .map_err(|e| format!("approve: {e}"))?;
    println!("2) approve -> grant signed by `{}`", approver.id);

    // 3. At apply, re-derive the live binding and re-verify the grant.
    let live = flow
        .store()
        .get(&id)
        .expect("request exists")
        .proposal
        .to_binding("nonce-demo-1", approval.grant.binding.expiry_unix_millis);
    match flow.verify_at_apply(&approval.grant, &live, clock) {
        Ok(()) => println!("3) verify_at_apply -> VERIFIED (grant binds to the approved proposal)"),
        Err(e) => println!("3) verify_at_apply -> REJECTED: {e}"),
    }
    Ok(())
}
