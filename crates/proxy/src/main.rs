//! pg_bumpers proxy binary — the inline, agent-only enforcement endpoint
//! (SPEC §3 layer 2, §7 S1).
//!
//! Reads its wiring from the environment (so it stays 12-factor and secret-store
//! friendly), loads per-role budgets from `policy.yaml`, optionally terminates
//! TLS on the agent endpoint, and serves each connection through the enforced
//! FE/BE loop in [`pgb_proxy::serve_connection`].
//!
//! Environment:
//! - `PGB_PROXY_LISTEN`      — agent listen addr (default `127.0.0.1:6432`).
//! - `PGB_PROXY_TLS_CERT` / `PGB_PROXY_TLS_KEY` — PEM paths; both ⇒ TLS on.
//! - `PGB_PROXY_REQUIRE_TLS` — explicit override of the TLS-required posture.
//!   Default: TLS is **required** whenever cert+key are configured (no silent
//!   cleartext downgrade). Set `false` for the explicit dev-only no-TLS mode;
//!   setting `true` with no TLS material is a hard error (fail-closed).
//! - `PGB_BACKEND_HOST` / `PGB_BACKEND_PORT` / `PGB_BACKEND_DB` — PG18 target
//!   (defaults `127.0.0.1` / `54321` / `postgres`; **never 5432**).
//! - `PGB_BACKEND_ROLE` — the WALL role the proxy connects as (default
//!   `pgb_agent`).
//! - `PGB_BACKEND_PASSWORD` — the WALL role's password. **Required**: there is
//!   no default secret literal in the binary (source it from the secret store /
//!   env, e.g. `deploy/proxy.env.example`).
//! - `PGB_AGENT_USER` — the SCRAM username the proxy verifies (default
//!   `pgb_agent`).
//! - `PGB_AGENT_PASSWORD` — the SCRAM secret the proxy verifies. **Required**:
//!   no default secret literal in the binary.
//! - `PGB_POLICY_PATH` — path to `policy.yaml`.
//! - `PGB_POLICY_ROLE` — which role's budgets apply (default `analytics`).
//! - `PGB_STATEMENT_TIMEOUT_MS` — injected `statement_timeout` (default 30000).
//! - `PGB_SEARCH_PATH` — the authoritative per-session `search_path` pinned on
//!   every brokered backend session (default `pg_catalog, "public"`, matching
//!   `deploy/sql/10_hardened_role.sql`). Keep it minimal (no `"$user"`); empty
//!   disables the pin (not recommended). SPEC §3 layer-1 WALL ("search_path
//!   pinned").
//!
//! Audit (`_meta` chain — SPEC §3/§4/§10.9, issue #64):
//! - `PGB_META_DSN` — the `_meta` writer DSN (keyword/value, **`pgb_audit_writer`**
//!   role; **never** the audited agent). **Required**: there is no default — the
//!   proxy refuses to start without somewhere to persist + anchor the canonical
//!   audit chain (fail-closed; the audit log is the tamper-evidence root).
//! - `PGB_AUDIT_SIGNING_KEY` — the audit chain-head **signing key** material (the
//!   dev secret-store seam; production addresses a KMS key version under the same
//!   id). **Required** (no literal default).
//! - `PGB_ANCHOR_INTERVAL_MS` — the external-WORM anchoring cadence in millis
//!   (default 60000). The very first tick anchors a baseline on startup.
//! - `PGB_ANCHOR_PATH` — the **durable** file-backed WORM anchor path. The
//!   anchored chain head is persisted here so it survives a process restart and
//!   the boot can verify the `_meta` chain against the *prior* durable head BEFORE
//!   re-anchoring (catching an offline full-chain rewrite across a restart).
//!   **Required** (no literal default; the file stand-in models object-lock /
//!   transparency-log retention — see `deploy/README.md`). Without a durable
//!   anchor the cross-restart tamper-evidence guarantee cannot hold (fail-closed).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pgb_audit::{AUDIT_SIGNING_KEY_ID, AnchorRole, AuditBoot, LocalSecretStore, SecretStore, Sink};
use pgb_core::{Clock, SystemClock};
use pgb_policy::PolicyConfig;
use pgb_proxy::config::{BackendTarget, TlsConfig};
use pgb_proxy::{ProxyConfig, Recorder, ThreadedSink, serve_connection};
use tokio::net::TcpListener;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required secret from the environment. Fail-closed: there are **no**
/// secret literals in the binary — a missing credential is a hard startup error,
/// never a silent dev default that could ship to production.
fn env_secret(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let v = std::env::var(key).map_err(|_| {
        format!(
            "{key} is required and has no default; source it from the secret store / env \
             (see deploy/proxy.env.example) — the binary ships no credential literals"
        )
    })?;
    if v.is_empty() {
        return Err(format!("{key} is set but empty; refusing to start (fail-closed)").into());
    }
    Ok(v)
}

/// Parse a tri-state boolean env override (`true`/`1`/`yes`/`on` ⇒ `Some(true)`,
/// `false`/`0`/`no`/`off` ⇒ `Some(false)`, unset ⇒ `None`).
fn env_bool(key: &str) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    match std::env::var(key) {
        Err(_) => Ok(None),
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(Some(true)),
            "false" | "0" | "no" | "off" => Ok(Some(false)),
            other => Err(format!("{key}: expected a boolean, got `{other}`").into()),
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the ring crypto provider for rustls (process-wide, once).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listen = env_or("PGB_PROXY_LISTEN", "127.0.0.1:6432").parse()?;

    let tls = match (
        std::env::var("PGB_PROXY_TLS_CERT"),
        std::env::var("PGB_PROXY_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => Some(TlsConfig {
            cert_pem: cert.into(),
            key_pem: key.into(),
        }),
        _ => None,
    };
    // TLS is REQUIRED whenever TLS material is configured (no silent cleartext
    // downgrade); an explicit `PGB_PROXY_REQUIRE_TLS` override wins (e.g. the
    // dev-only no-TLS mode).
    let require_tls =
        ProxyConfig::resolve_require_tls(tls.is_some(), env_bool("PGB_PROXY_REQUIRE_TLS")?);

    let policy_path = env_or("PGB_POLICY_PATH", "crates/policy/policy.example.yaml");
    let policy_role = env_or("PGB_POLICY_ROLE", "analytics");
    let policy = PolicyConfig::load_from_yaml(&std::fs::read_to_string(&policy_path)?)?;
    let budget = ProxyConfig::budget_for(&policy, &policy_role)?;

    let cfg = Arc::new(ProxyConfig {
        listen,
        tls,
        require_tls,
        backend: BackendTarget {
            host: env_or("PGB_BACKEND_HOST", "127.0.0.1"),
            port: env_or("PGB_BACKEND_PORT", "54321").parse()?,
            database: env_or("PGB_BACKEND_DB", "postgres"),
            role: env_or("PGB_BACKEND_ROLE", "pgb_agent"),
            // Secrets: no literal defaults in the binary (fail-closed).
            password: env_secret("PGB_BACKEND_PASSWORD")?,
        },
        agent_user: env_or("PGB_AGENT_USER", "pgb_agent"),
        agent_password: env_secret("PGB_AGENT_PASSWORD")?,
        policy_role: policy_role.clone(),
        budget,
        statement_timeout_ms: env_or("PGB_STATEMENT_TIMEOUT_MS", "30000").parse()?,
        // The authoritative per-session search_path pin (SPEC §3 layer-1 WALL).
        // Defaults to the minimal fixed path the WALL role intends, matching
        // deploy/sql/10_hardened_role.sql. Operators may override but should keep
        // it minimal (no "$user", not wide-open).
        search_path: env_or("PGB_SEARCH_PATH", ProxyConfig::DEFAULT_SEARCH_PATH),
    });

    // Fail-closed on an incoherent TLS posture (require_tls without material).
    cfg.validate_tls()?;

    // Audit: ONE shared, persistent, anchored `_meta` chain (SPEC §3/§4/§10.9,
    // issue #64). The proxy `Recorder` and the CLI approval flow both hash-chain
    // into this single canonical chain in the `_meta` DB (single genesis), and an
    // external WORM anchor pins its head on a clock interval so a full-chain
    // rewrite is caught. The chain is the tamper-evident evidence that hostile
    // statements were stopped.
    let meta_dsn = env_secret("PGB_META_DSN")?;
    let signing_key = env_secret("PGB_AUDIT_SIGNING_KEY")?;
    let anchor_interval_ms: u64 = env_or("PGB_ANCHOR_INTERVAL_MS", "60000").parse()?;
    // The DURABLE anchor path: the anchored head must survive a restart so the
    // boot can verify the persisted chain against the PRIOR durable head before
    // re-anchoring (fail-closed; no literal default).
    let anchor_path = env_secret("PGB_ANCHOR_PATH")?;

    // The signing key lives in the secret-store seam, NOT on the DB host (§10.9);
    // production addresses a KMS key version under the same id.
    let mut store = LocalSecretStore::new();
    store.put(AUDIT_SIGNING_KEY_ID, signing_key.as_bytes())?;

    // Connect as the audit WRITER (never the audited agent) and build the boot
    // handle over a DURABLE, file-backed WORM anchor: the shared sink + the
    // interval anchorer over the canonical chain, with the anchored head persisted
    // across restarts.
    // S5 #76 item 3: the proxy is the DEFAULT anchor OWNER over the ONE shared
    // chain — it owns the durable anchor file + signing key and is the sole
    // anchorer. applyd (and any other consumer) boots VERIFY-ONLY against this
    // owner's anchored head. Exactly one anchorer over the shared chain means no
    // two-anchorer race; `PGB_ANCHOR_ROLE` can override (e.g. to make a different
    // binary the owner).
    let anchor_role = AnchorRole::parse(
        std::env::var("PGB_ANCHOR_ROLE").ok().as_deref(),
        AnchorRole::Owner,
    )
    .map_err(|e| format!("{e} (fail-closed)"))?;

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // The audit boot uses the SYNCHRONOUS `postgres` crate (a blocking client
    // that drives its OWN internal tokio runtime via `block_on`). Calling it
    // directly from this `#[tokio::main]` async context panics
    // ("Cannot start a runtime from within a runtime"). Run the connect + the
    // FAIL-CLOSED verify-before-anchor boot on a dedicated blocking thread
    // (`spawn_blocking`) so the sync client never collides with this runtime.
    //
    // FAIL-CLOSED boot sequence — for the OWNER, VERIFY BEFORE ANCHOR (SPEC
    // §3/§10.9): verify the persisted `_meta` chain against the PRIOR durable
    // anchored head FIRST, and only on a clean verify anchor the current head
    // forward. Re-anchoring first would re-pin whatever head is now in `_meta`
    // (incl. an offline-forged head) and make the verify trivially pass — the hole
    // this ordering closes. A full-chain rewrite across a restart changes the head
    // ⇒ mismatch ⇒ refuse to start. (Genesis/first boot: empty durable WORM,
    // nothing to verify against yet; anchored as the baseline.) A VERIFY-only role
    // checks but never anchors. Any error here is a hard exit.
    let boot = {
        let meta_dsn = meta_dsn.clone();
        let anchor_path = anchor_path.clone();
        let boot_clock = clock.clone();
        tokio::task::spawn_blocking(move || -> Result<AuditBoot, String> {
            let mut boot =
                AuditBoot::connect_with_anchor(&meta_dsn, &store, anchor_interval_ms, &anchor_path)
                    .map_err(|e| format!("audit _meta boot failed (fail-closed): {e}"))?;
            boot.boot(anchor_role, boot_clock.monotonic_millis())
                .map_err(|e| {
                    format!("audit startup verification failed — refusing to start: {e}")
                })?;
            Ok(boot)
        })
        .await
        .map_err(|e| format!("audit boot task join failed: {e}"))??
    };
    eprintln!(
        "pgb-proxy: audit `_meta` chain verified against its durable anchored head on startup \
         (anchor role: {anchor_role:?}, anchor {anchor_path}, interval {anchor_interval_ms}ms)"
    );

    // The proxy `Recorder` appends a gate verdict SYNCHRONOUSLY on every statement
    // from inside an async connection task. The `_meta` `PgSink` is the sync
    // `postgres` client (its own `block_on`), which panics if driven from inside
    // this runtime. So the recorder writes through a `ThreadedSink`: its OWN writer
    // client on a dedicated OS thread (off the runtime). Cross-process chain
    // integrity is preserved — `PgSink::append` serializes head-read + insert under
    // a `pg_advisory_xact_lock`, so this client appends safely alongside the boot's
    // anchor client and applyd/warden onto the ONE shared `_meta.audit_log`.
    let recorder_sink = ThreadedSink::connect(&meta_dsn)
        .map_err(|e| format!("audit recorder sink connect failed (fail-closed): {e}"))?;
    let sink: Arc<Mutex<dyn Sink + Send>> = Arc::new(Mutex::new(recorder_sink));
    let recorder = Recorder::new(sink, clock.clone(), cfg.backend.role.clone());

    // Run the interval anchorer in the background ONLY when this binary OWNS the
    // anchor (item 3) — a verify-only role must never anchor. The anchorer ticks
    // on the same injected clock cadence; `AuditBoot` (sync Postgres client) runs
    // its blocking `maybe_anchor` on a `spawn_blocking` thread per tick so the sync
    // client never blocks (or collides with) this tokio runtime.
    let boot = Arc::new(Mutex::new(boot));
    if anchor_role.is_owner() {
        let boot = boot.clone();
        let clock = clock.clone();
        let tick = Duration::from_millis(anchor_interval_ms.max(1));
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = clock.monotonic_millis();
                let boot = boot.clone();
                let res = tokio::task::spawn_blocking(move || {
                    let mut b = boot
                        .lock()
                        .map_err(|_| "anchor mutex poisoned".to_string())?;
                    b.maybe_anchor(now).map_err(|e| e.to_string()).map(|_| ())
                })
                .await;
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("pgb-proxy: audit anchor tick failed: {e}"),
                    Err(e) => eprintln!("pgb-proxy: audit anchor task join failed: {e}"),
                }
            }
        });
    }

    let tls_acceptor = match &cfg.tls {
        Some(t) => Some(Arc::new(tokio_rustls::TlsAcceptor::from(
            pgb_proxy::tls::server_config(t)?,
        ))),
        None => None,
    };

    let listener = TcpListener::bind(cfg.listen).await?;
    eprintln!(
        "pgb-proxy: listening on {} → backend {}:{} as {} (policy role `{}`, \
         statement_timeout={}ms, tls={}, require_tls={})",
        cfg.listen,
        cfg.backend.host,
        cfg.backend.port,
        cfg.backend.role,
        cfg.policy_role,
        cfg.statement_timeout_ms,
        cfg.tls.is_some(),
        cfg.require_tls,
    );

    let mut conn_id: u64 = 0;
    loop {
        let (tcp, peer) = listener.accept().await?;
        conn_id += 1;
        let session_id = format!("conn-{conn_id}");
        let cfg = cfg.clone();
        let tls_acceptor = tls_acceptor.clone();
        let recorder = recorder.clone();
        tokio::spawn(async move {
            if let Err(e) =
                serve_connection(tcp, cfg, tls_acceptor, recorder, session_id.clone()).await
            {
                eprintln!("pgb-proxy: session {session_id} ({peer}) ended: {e}");
            }
        });
    }
}
