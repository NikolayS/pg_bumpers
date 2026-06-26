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
use pgb_cli::doctor::{
    CheckResult, CheckStatus, DoctorReport, HbaRule, RoleAttrs, check_agent_hardening,
    check_applier_dml, check_hba_boundary,
};
use pgb_cli::{
    ApprovalFlow, InMemoryNonceStore, Principal, Proposal, RecordingWebhookSender, RequestId,
    verify_meta_chain,
};
use pgb_core::{Clock, SystemClock, inverse::Operation};
use pgb_policy::{PolicyConfig, ResolvedTarget, TargetResolver};
use postgres::{Client, NoTls};

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
        Some("doctor") => match run_doctor() {
            // Fail-closed: zero ONLY when every load-bearing check passed.
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("pgb-cli doctor: preflight could not run (fail-closed): {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            println!(
                "pgb-cli — pg_bumpers approval CLI (SPEC §14 MVP).\n\
                 usage:\n  \
                 pgb-cli approve <request-id>   sign a proposal-bound grant (human approver)\n  \
                 pgb-cli demo                   run request -> approve -> verify-at-apply\n  \
                 pgb-cli verify                 load + verify the shared `_meta` chain + anchored head\n  \
                 pgb-cli doctor                 BYO preflight: reachability + WALL hardening + applier DML-only\n  \
                 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20+ pg_hba boundary + _meta chain (fail-closed; non-zero on any failure)\n  \
                 pgb-cli keygen                 print a fresh Ed25519 approver keypair (seed hex, then pubkey hex)\n\
                 \n\
                 Set PGB_META_DSN (audit-writer DSN) + PGB_AUDIT_SIGNING_KEY to run the demo\n\
                 against the SHARED, persistent, anchored `_meta` chain (the one the proxy\n\
                 also writes); otherwise the demo runs in-process on an in-memory chain.\n\
                 `verify` needs PGB_META_DSN + PGB_AUDIT_SIGNING_KEY + PGB_ANCHOR_PATH.\n\
                 `doctor` reads PGB_POLICY_PATH (the BYO DSN targets) + PGB_DOCTOR_PASSWORD\n\
                 (the primary connect secret); env PGB_BACKEND_* override the policy target.\n\
                 It optionally checks the `_meta` chain when PGB_META_DSN is set."
            );
            ExitCode::SUCCESS
        }
    }
}

/// Read an env var, falling back to `default` when unset or empty.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}

/// `pgb-cli doctor` — the **fail-closed BYO preflight** (SPEC §0.5). Resolves the
/// `policy.yaml` DSN targets (env override > policy target > fail-closed), opens
/// real connections, and runs the [`pgb_cli::doctor`] checks: primary (+ optional
/// replica + `_meta`) reachable; `pgb_agent` WALL-hardened; `pgb_applier` DML-only;
/// the pg_hba boundary (best-effort/advisory); and the `_meta` audit chain verifies
/// (reusing the same `crates/audit` verify the daemons boot against).
///
/// Returns `Ok(true)` iff every load-bearing check passed; `Ok(false)` on a failed
/// check (the report is printed either way); `Err` if the preflight itself could
/// not run (an unresolvable target / unreachable primary — also fail-closed).
///
/// Environment:
///   * `PGB_POLICY_PATH`     — the `policy.yaml` carrying the BYO DSN targets.
///   * `PGB_BACKEND_HOST/PORT/DB/ROLE` — overrides over the policy `primary:`
///     target (precedence env > policy > fail-closed; the `ROLE` is the connect
///     role, default `pgb_agent`'s hardening is checked regardless).
///   * `PGB_DOCTOR_PASSWORD` — the password the doctor connects to the primary with
///     (a privileged role that can read the catalogs; the policy file never carries
///     a literal password — SPEC §0.5).
///   * `PGB_AGENT_ROLE` / `PGB_APPLIER_ROLE` — the role names whose hardening is
///     checked (default `pgb_agent` / `pgb_applier`).
///   * `PGB_APP_SCHEMA`      — the application schema the applier's CREATE privilege
///     is checked on (default `public`).
///   * `PGB_META_DSN` / `PGB_AUDIT_SIGNING_KEY` / `PGB_ANCHOR_PATH` — when all set,
///     the `_meta` audit chain is loaded + verified (else that check is skipped with
///     an advisory note — the `_meta` chain may live elsewhere).
fn run_doctor() -> Result<bool, String> {
    let mut report = DoctorReport::new();

    // 1. Resolve the BYO primary target (SPEC §0.5): env override > policy.yaml
    //    `primary:` target > FAIL-CLOSED. No throwaway-cluster default.
    let policy = load_doctor_policy()?;
    let target = resolve_doctor_target(policy.as_ref(), |k| std::env::var(k).ok())?;
    let agent_role = env_or("PGB_AGENT_ROLE", "pgb_agent");
    let applier_role = env_or("PGB_APPLIER_ROLE", "pgb_applier");
    let app_schema = env_or("PGB_APP_SCHEMA", "public");

    let password = std::env::var("PGB_DOCTOR_PASSWORD").map_err(|_| {
        "PGB_DOCTOR_PASSWORD is required (the password the doctor connects to the primary with; \
         a role that can read the catalogs) — the policy file never carries a literal password"
            .to_string()
    })?;
    let dsn = format!("{} password={}", target.to_credential_less_dsn(), password);

    // 2. Reachability (fail-closed: if the primary is unreachable the preflight
    //    cannot run — a hard error, not a soft "skip").
    let mut client = Client::connect(&dsn, NoTls).map_err(|e| {
        format!(
            "primary unreachable at {}:{} as `{}` (fail-closed): {e}",
            target.host, target.port, target.role
        )
    })?;
    report.push(CheckResult::pass(
        "primary_reachable",
        format!(
            "connected to the primary at {}:{}/{} as `{}`",
            target.host, target.port, target.database, target.role
        ),
    ));

    // 3. `pgb_agent` WALL hardening.
    for c in doctor_role_checks(&mut client, &agent_role, &app_schema, true)? {
        report.push(c);
    }
    // 4. `pgb_applier` DML-only.
    for c in doctor_role_checks(&mut client, &applier_role, &app_schema, false)? {
        report.push(c);
    }

    // 5. pg_hba origin boundary (best-effort/advisory).
    report.push(doctor_hba_check(&mut client, &agent_role));

    // 6. Optional read-replica reachability (when a typed target is configured).
    if let Some(replica) = policy.as_ref().and_then(|p| p.replica.target.as_ref()) {
        let rdsn = format!("{} password={}", replica.to_credential_less_dsn(), password);
        match Client::connect(&rdsn, NoTls) {
            Ok(_) => report.push(CheckResult::pass(
                "replica_reachable",
                format!(
                    "connected to the read replica at {}:{}",
                    replica.host, replica.port
                ),
            )),
            Err(e) => report.push(CheckResult::fail(
                "replica_reachable",
                format!(
                    "replica configured but unreachable at {}:{} (fail-closed): {e}",
                    replica.host, replica.port
                ),
            )),
        }
    }

    // 7. The `_meta` audit chain — installed + verifying (reuse crates/audit verify).
    report.push(doctor_meta_check());

    // Print the structured report; exit non-zero on any load-bearing failure.
    let passed = report.passed();
    println!(
        "pgb-cli doctor — BYO preflight (SPEC §0.5):\n{}",
        report.render()
    );
    Ok(passed)
}

/// Load the `policy.yaml` named by `PGB_POLICY_PATH` (fail-closed on a present-but-
/// unreadable/invalid file). Absent ⇒ `Ok(None)` (the target then resolves purely
/// from the `PGB_BACKEND_*` env overrides, or fails closed if those are unset too).
fn load_doctor_policy() -> Result<Option<PolicyConfig>, String> {
    match std::env::var("PGB_POLICY_PATH") {
        Err(_) => Ok(None),
        Ok(path) if path.is_empty() => Ok(None),
        Ok(path) => {
            let yaml = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read PGB_POLICY_PATH `{path}` (fail-closed): {e}"))?;
            Ok(Some(PolicyConfig::load_from_yaml(&yaml).map_err(|e| {
                format!("invalid policy.yaml `{path}` (fail-closed): {e}")
            })?))
        }
    }
}

/// Resolve the doctor's primary target from the BYO policy + env overrides, with the
/// §0.5 precedence **env override > policy.yaml `primary:` target > FAIL-CLOSED**.
/// Pure (env reader injected) so the precedence is unit-testable without a DB.
fn resolve_doctor_target(
    policy: Option<&PolicyConfig>,
    getenv: impl Fn(&str) -> Option<String>,
) -> Result<ResolvedTarget, String> {
    TargetResolver {
        policy_target: policy.and_then(|p| p.primary.as_ref()),
        host_override: getenv("PGB_BACKEND_HOST"),
        port_override: getenv("PGB_BACKEND_PORT"),
        db_override: getenv("PGB_BACKEND_DB"),
        role_override: getenv("PGB_BACKEND_ROLE"),
        default_database: "postgres",
        default_role: "pgb_agent",
        host_env_key: "PGB_BACKEND_HOST",
        port_env_key: "PGB_BACKEND_PORT",
        policy_hint: "policy.yaml `primary:` (the BYO primary target, SPEC §0.5)",
    }
    .resolve()
    .map_err(|e| e.to_string())
}

/// Run the catalog queries for one role and feed the rows into the pure check
/// functions. `is_agent` selects the read-WALL checks (no write grant) vs. the
/// applier DML-only checks (no CREATE on the app schema).
fn doctor_role_checks(
    client: &mut Client,
    role: &str,
    app_schema: &str,
    is_agent: bool,
) -> Result<Vec<CheckResult>, String> {
    // Role attributes (or absent ⇒ the pure fn reports the missing-role failure).
    let attr_rows = client
        .query(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls \
             FROM pg_roles WHERE rolname = $1",
            &[&role],
        )
        .map_err(|e| format!("querying pg_roles for `{role}`: {e}"))?;
    let attrs = attr_rows.first().map(|r| RoleAttrs {
        is_superuser: r.get(0),
        can_create_db: r.get(1),
        can_create_role: r.get(2),
        can_replicate: r.get(3),
        can_bypass_rls: r.get(4),
    });

    // Member-of-nothing: count predefined/other role memberships.
    let membership_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_auth_members m \
             JOIN pg_roles a ON a.oid = m.member WHERE a.rolname = $1",
            &[&role],
        )
        .map_err(|e| format!("counting role memberships for `{role}`: {e}"))?
        .get(0);

    if is_agent {
        // Write grants on USER tables (the read WALL must hold none). Count distinct
        // tables on which the role holds INSERT/UPDATE/DELETE/TRUNCATE.
        let write_grant_count: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM ( \
                   SELECT DISTINCT table_schema, table_name FROM information_schema.role_table_grants \
                   WHERE grantee = $1 AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE') \
                     AND table_schema NOT IN ('pg_catalog','information_schema') \
                 ) g",
                &[&role],
            )
            .map_err(|e| format!("counting write grants for `{role}`: {e}"))?
            .get(0);
        Ok(check_agent_hardening(
            role,
            attrs,
            membership_count,
            write_grant_count,
        ))
    } else {
        // CREATE on the application schema (the applier must NOT be able to DDL).
        let has_create: bool = client
            .query_one(
                "SELECT coalesce(has_schema_privilege($1, $2, 'CREATE'), false)",
                &[&role, &app_schema],
            )
            .map_err(|e| format!("checking schema CREATE for `{role}`: {e}"))?
            .get(0);
        Ok(check_applier_dml(role, attrs, membership_count, has_create))
    }
}

/// The best-effort/advisory pg_hba boundary check: read `pg_hba_file_rules` if it is
/// accessible (it needs elevated privileges), else report an advisory `Warn`.
fn doctor_hba_check(client: &mut Client, agent_role: &str) -> CheckResult {
    // The view exists 10+; reading it requires elevated privileges. Treat any error
    // (permission / absent) as "unreadable" ⇒ advisory Warn (pass None).
    let rules: Option<Vec<HbaRule>> = client
        .query(
            "SELECT type, coalesce(user_name, ARRAY[]::text[]), coalesce(address, '') \
             FROM pg_hba_file_rules",
            &[],
        )
        .ok()
        .map(|rows| {
            rows.into_iter()
                .map(|r| {
                    let users: Vec<String> = r.get(1);
                    HbaRule {
                        conn_type: r.get::<_, String>(0),
                        user_name: users.into_iter().map(|u| u.to_ascii_lowercase()).collect(),
                        address: r.get::<_, String>(2),
                    }
                })
                .collect()
        });
    check_hba_boundary(agent_role, rules.as_deref())
}

/// The `_meta` audit-chain check: load + verify the hash-chained chain (reusing the
/// same `crates/audit` verify the daemons boot against). When `PGB_META_DSN` /
/// `PGB_AUDIT_SIGNING_KEY` / `PGB_ANCHOR_PATH` are not all set, the `_meta` chain may
/// live elsewhere — report an advisory `Warn` rather than fail (the chain's integrity
/// is the daemons' boot concern; the doctor checks it when pointed at it).
fn doctor_meta_check() -> CheckResult {
    let (dsn, key, anchor) = match (
        std::env::var("PGB_META_DSN").ok().filter(|s| !s.is_empty()),
        std::env::var("PGB_AUDIT_SIGNING_KEY")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("PGB_ANCHOR_PATH")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        (Some(d), Some(k), Some(a)) => (d, k, a),
        _ => {
            return CheckResult::advisory(
                "meta_chain_verifies",
                CheckStatus::Warn,
                "PGB_META_DSN / PGB_AUDIT_SIGNING_KEY / PGB_ANCHOR_PATH not all set — skipping the \
                 `_meta` chain verification (set them to verify the audit chain here)"
                    .to_string(),
            );
        }
    };
    let interval_ms: u64 = std::env::var("PGB_ANCHOR_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000);
    let mut store = LocalSecretStore::new();
    if let Err(e) = store.put(AUDIT_SIGNING_KEY_ID, key.as_bytes()) {
        return CheckResult::fail("meta_chain_verifies", format!("audit key load failed: {e}"));
    }
    let mut boot = match AuditBoot::connect_with_anchor(&dsn, &store, interval_ms, &anchor) {
        Ok(b) => b,
        Err(e) => {
            return CheckResult::fail(
                "meta_chain_reachable",
                format!(
                    "the `_meta` audit DB is unreachable / chain not installed (fail-closed): {e}"
                ),
            );
        }
    };
    match boot.load_chain() {
        Ok(records) => match verify_meta_chain(&records) {
            Ok(summary) => CheckResult::pass(
                "meta_chain_verifies",
                format!(
                    "the `_meta` audit chain is installed and VERIFIES ({} records, head {})",
                    summary.len, summary.head
                ),
            ),
            Err(brk) => CheckResult::fail(
                "meta_chain_verifies",
                format!("the `_meta` chain FAILED within-chain verification at {brk:?}"),
            ),
        },
        Err(e) => CheckResult::fail(
            "meta_chain_verifies",
            format!("could not load the `_meta` chain (fail-closed): {e}"),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    fn byo_policy() -> PolicyConfig {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
primary:
  host: byo.db.internal
  port: 6543
  database: appdb
  role: pgb_agent
"#;
        PolicyConfig::load_from_yaml(yaml).unwrap()
    }

    /// `doctor` resolves its primary target from the BYO policy — NOT a 54321
    /// default — when no env override is set.
    #[test]
    fn doctor_resolves_target_from_byo_policy_not_54321() {
        let policy = byo_policy();
        let t = resolve_doctor_target(Some(&policy), fake_env(&[])).unwrap();
        assert_eq!(t.host, "byo.db.internal");
        assert_eq!(t.port, 6543);
        assert_eq!(t.database, "appdb");
        assert_ne!(t.port, 54321, "must NOT fall back to the throwaway 54321");
    }

    /// The env override wins over the policy target.
    #[test]
    fn doctor_env_override_wins_over_policy_target() {
        let policy = byo_policy();
        let t = resolve_doctor_target(
            Some(&policy),
            fake_env(&[
                ("PGB_BACKEND_HOST", "127.0.0.1"),
                ("PGB_BACKEND_PORT", "54399"),
            ]),
        )
        .unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 54399);
    }

    /// FAIL-CLOSED: with neither a policy primary target nor an env override, the
    /// doctor refuses to run rather than default to 54321.
    #[test]
    fn doctor_fails_closed_with_no_policy_target_and_no_env() {
        let err = resolve_doctor_target(None, fake_env(&[])).unwrap_err();
        assert!(err.contains("NO throwaway-cluster default"), "{err}");
        assert!(!err.contains("54321"), "no 54321 anywhere: {err}");
    }
}
