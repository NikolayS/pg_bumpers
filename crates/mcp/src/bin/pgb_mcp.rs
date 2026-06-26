//! `pgb-mcp` — the deployable stdio MCP server entrypoint (EPIC #83).
//!
//! The single binary that makes the §4 nine-tool catalog a REAL, connectable
//! Model Context Protocol server. It serves the [`PgBumpersMcp`] handler over
//! stdin/stdout via the official `rmcp` SDK, so:
//!
//! ```sh
//! claude mcp add pg-bumpers -- pgb-mcp
//! ```
//!
//! connects a real Claude Code to it. The handshake (`initialize`) +
//! `tools/list` + `tools/call` work end-to-end. PR2 wired the **read path**:
//! `query` / `explain_plan` / `discover_schema` execute THROUGH the live
//! `pgb-proxy` (the real boundary, NOT raw PG), and `get_audit` reads the `_meta`
//! audit tail. PR3 wires the **write path**: `propose_write` / `dry_run` /
//! `request_elevation` / `apply_write` execute THROUGH the `pgb-applyd` Unix-socket
//! daemon (the grant-gated §4 floor). applyd stays a SEPARATE daemon — the write
//! credential never enters this agent-facing process.
//!
//! Honesty (SPEC §3): this server is COOPERATIVE, not a security boundary. The
//! deterministic floor (proxy + WALL + applyd + warden) is the real boundary.
//!
//! Lazy-connect: the binary starts even if the proxy/applyd are down — the first
//! read dials the proxy, the first write dials the applyd socket, and a down
//! proxy/applyd is a recoverable `PROXY_UNAVAILABLE` / `APPLYD_UNAVAILABLE` block,
//! never a crash. A dropped / warden-killed proxy connection or a reset applyd
//! socket is absorbed and re-dialed on the next call (no uncaught failure kills the
//! process).
//!
//! Environment (mirrors the deploy stack's `connect.env` / `PgProxyTransport`):
//!   - `PGB_ROLE`            — the authenticated role (T0). Default `pgb_agent`.
//!   - `PGB_SESSION_ID`      — the session/principal id. Default `mcp-<pid>`.
//!   - `PGB_PROXY_HOST`      — the proxy's agent host (default `127.0.0.1`).
//!   - `PGB_PROXY_PORT`      — the proxy's agent port (default `6432`; NEVER 5432).
//!   - `PGB_PROXY_DB`        — the database (default `postgres`).
//!   - `PGB_PROXY_USER`      — the SCRAM user (default `pgb_agent`).
//!   - `PGB_PROXY_PASSWORD`  — the SCRAM password (no read tool works without it).
//!   - `PGB_PROXY_APP_NAME`  — the wire `application_name` (default `pgb_mcp`).
//!   - `PGB_PROXY_REQUIRE_TLS` — `true` ⇒ TLS-on (verify the proxy cert against
//!     `PGB_PROXY_TLS_CA`); `false` ⇒ explicit dev-only no-TLS (plaintext).
//!     Default: TLS-on iff a CA is configured.
//!   - `PGB_PROXY_TLS_CA`    — PEM path of trust anchors to verify the proxy cert.
//!   - `PGB_STATEMENT_TIMEOUT_MS` — client-side statement_timeout (default 30000).
//!   - `PGB_APPLYD_SOCKET`   — the `pgb-applyd` Unix-socket path the write tools
//!     dial (optional; without it the write tools return a recoverable
//!     `APPLYD_UNAVAILABLE` block). NEVER a TCP port.
//!   - `PGB_APPLYD_TIMEOUT_MS` — per-call applyd round-trip timeout (default 30000).
//!   - `PGB_POLICY_PATH`     — path to `policy.yaml` (optional). When set, its
//!     `audit:` `target:` BYO `_meta` DSN target (SPEC §0.5) supplies the
//!     `get_audit` reader location when `PGB_META_DSN` is unset (env override >
//!     policy `audit.target` > optional). The mcp talks to the proxy (NOT the
//!     primary DB directly), so the primary target is never used here.
//!   - `PGB_META_DSN`        — the `_meta` reader DSN for `get_audit` (optional;
//!     **overrides** any `policy.yaml` `audit.target`). Without it AND without a
//!     `policy.yaml` audit target, `get_audit` returns a recoverable
//!     `AUDIT_UNAVAILABLE` block (the `_meta` reader is optional, not fail-closed).
//!   - `PGB_META_PASSWORD`   — the password the credential-less `policy.yaml`
//!     `audit.target` DSN connects with (the policy file never carries a literal
//!     password). Only consulted when the `_meta` DSN is resolved from the policy
//!     target rather than `PGB_META_DSN`.

use std::process::ExitCode;

use pgb_mcp::{
    ApplydClient, ApplydConfig, AuditConfig, AuditReader, PgBumpersMcp, ProxyConfig,
    ProxyTransport, TlsMode,
};
use pgb_policy::PolicyConfig;
use rmcp::{ServiceExt, transport::stdio};

/// Read an env var, falling back to `default` when unset or empty.
fn env_or(key: &str, default: impl Into<String>) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.into(),
    }
}

/// Parse a tri-state boolean env override (`true`/`1`/`yes`/`on` ⇒ Some(true),
/// `false`/`0`/`no`/`off` ⇒ Some(false), unset/garbage ⇒ None).
fn env_bool(key: &str) -> Option<bool> {
    match std::env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Resolve the optional `_meta` reader DSN for `get_audit` (SPEC §0.5 BYO), with
/// the precedence **`PGB_META_DSN` env override > `policy.yaml` `audit.target` >
/// None**. The mcp talks to the proxy for reads/writes, so the only DB DSN it ever
/// resolves directly is this `_meta` *reader* — and it stays **optional** (a
/// missing `_meta` reader yields a recoverable `AUDIT_UNAVAILABLE` block, not a
/// fail-closed startup error; the `_meta` chain's tamper-evidence is owned by the
/// proxy/applyd writers, not this read-only viewer).
///
/// When resolved from the credential-less `policy.yaml` `audit.target`, the
/// password is layered in from `PGB_META_PASSWORD` (the policy file never carries
/// a literal password — SPEC §0.5 "no literal passwords in files"). If that
/// password is absent the credential-less DSN is still returned (a local-trust /
/// peer-auth `_meta` connects without one); the literal secret is never in policy.
///
/// `getenv` is taken as a closure (not a direct `std::env` read) so this is
/// **pure + unit-testable** — the BYO-wiring test drives it with a BYO policy + a
/// fake env and asserts the env override wins and that the policy target is used
/// without any throwaway-cluster default.
fn resolve_meta_dsn(
    policy: Option<&PolicyConfig>,
    getenv: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    // 1. The explicit env DSN override wins (the existing ITs / up.sh path).
    if let Some(dsn) = getenv("PGB_META_DSN").filter(|s| !s.is_empty()) {
        return Some(dsn);
    }
    // 2. Else the BYO `policy.yaml` `audit.target` (credential-less) + the
    //    out-of-band `PGB_META_PASSWORD`.
    let target = policy?.audit.target.as_ref()?;
    let base = target.to_credential_less_dsn();
    match getenv("PGB_META_PASSWORD").filter(|s| !s.is_empty()) {
        Some(pw) => Some(format!("{base} password={pw}")),
        None => Some(base),
    }
}

/// Load the optional `policy.yaml` named by `PGB_POLICY_PATH`. Absent ⇒ `Ok(None)`
/// (the mcp's policy is optional — it only sources the `_meta` reader target from
/// it). A present-but-unreadable / invalid policy is a hard error (fail-closed on a
/// config the operator explicitly pointed at).
fn load_policy() -> Result<Option<PolicyConfig>, String> {
    match std::env::var("PGB_POLICY_PATH") {
        Err(_) => Ok(None),
        Ok(path) if path.is_empty() => Ok(None),
        Ok(path) => {
            let yaml = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read PGB_POLICY_PATH `{path}` (fail-closed): {e}"))?;
            let cfg = PolicyConfig::load_from_yaml(&yaml)
                .map_err(|e| format!("invalid policy.yaml `{path}` (fail-closed): {e}"))?;
            Ok(Some(cfg))
        }
    }
}

/// Build the proxy [`TlsMode`] from the env. TLS-on verifies the proxy cert
/// against the PEM trust anchors at `PGB_PROXY_TLS_CA`; dev no-TLS is plaintext
/// (stated explicitly via `PGB_PROXY_REQUIRE_TLS=false`). Fail-closed: requesting
/// TLS with no CA material is an error (we refuse to silently downgrade).
fn build_tls() -> Result<TlsMode, String> {
    let ca_path = std::env::var("PGB_PROXY_TLS_CA")
        .ok()
        .filter(|s| !s.is_empty());
    // Default: TLS-on iff a CA is configured. An explicit override wins.
    let require_tls = env_bool("PGB_PROXY_REQUIRE_TLS").unwrap_or(ca_path.is_some());
    if !require_tls {
        // Explicit dev-only no-TLS mode (plaintext). Stated, never silent.
        return Ok(TlsMode::Disabled);
    }
    let ca_path = ca_path.ok_or_else(|| {
        "PGB_PROXY_REQUIRE_TLS is on but PGB_PROXY_TLS_CA is unset; set the proxy's CA \
         PEM path, or use the explicit dev-only no-TLS mode (PGB_PROXY_REQUIRE_TLS=false)"
            .to_string()
    })?;
    use rustls_pki_types::pem::PemObject;
    let pem = std::fs::read(&ca_path)
        .map_err(|e| format!("could not read PGB_PROXY_TLS_CA at {ca_path}: {e}"))?;
    // Parse every CERTIFICATE block out of the PEM into DER trust anchors.
    let roots_der = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("could not parse PGB_PROXY_TLS_CA PEM: {e}"))?
        .into_iter()
        .map(|c| c.as_ref().to_vec())
        .collect::<Vec<_>>();
    if roots_der.is_empty() {
        return Err(format!(
            "PGB_PROXY_TLS_CA at {ca_path} contained no certificates"
        ));
    }
    Ok(TlsMode::Rustls { roots_der })
}

/// Build the `PgBumpersMcp` server from the environment: the session identity, the
/// live proxy transport (lazy), and the optional `_meta` audit reader.
fn build_server() -> Result<PgBumpersMcp, String> {
    let role = env_or("PGB_ROLE", "pgb_agent");
    let session_id = env_or("PGB_SESSION_ID", format!("mcp-{}", std::process::id()));

    // Optional BYO `policy.yaml` (SPEC §0.5): the mcp sources its `_meta` reader
    // target from it (env override). Absent ⇒ no policy; a present-but-invalid one
    // is fail-closed.
    let policy = load_policy()?;

    let proxy_cfg = ProxyConfig {
        host: env_or("PGB_PROXY_HOST", "127.0.0.1"),
        port: env_or("PGB_PROXY_PORT", "6432")
            .parse()
            .map_err(|e| format!("PGB_PROXY_PORT is not a valid port: {e}"))?,
        database: env_or("PGB_PROXY_DB", "postgres"),
        user: env_or("PGB_PROXY_USER", "pgb_agent"),
        password: env_or("PGB_PROXY_PASSWORD", ""),
        application_name: env_or("PGB_PROXY_APP_NAME", pgb_mcp::DEFAULT_APP_NAME),
        tls: build_tls()?,
        statement_timeout_ms: env_or("PGB_STATEMENT_TIMEOUT_MS", "30000")
            .parse()
            .map_err(|e| format!("PGB_STATEMENT_TIMEOUT_MS is not a number: {e}"))?,
    };
    let role_for_writes = env_or("PGB_ROLE", "pgb_agent");
    let session_for_writes = env_or("PGB_SESSION_ID", format!("mcp-{}", std::process::id()));
    let mut server = PgBumpersMcp::new(role, session_id).with_proxy(ProxyTransport::new(proxy_cfg));

    // The write tools dial the `pgb-applyd` Unix socket. Optional: if unset, the
    // write tools return a recoverable APPLYD_UNAVAILABLE block. The role/session
    // are pinned into applyd's stored proposal record at propose (the apply
    // re-derives from them — the agent can never swap them at apply time). The
    // write credential lives in the SEPARATE applyd daemon, never here.
    if let Ok(socket_path) = std::env::var("PGB_APPLYD_SOCKET")
        && !socket_path.is_empty()
    {
        let timeout_ms = env_or(
            "PGB_APPLYD_TIMEOUT_MS",
            pgb_mcp::DEFAULT_TIMEOUT_MS.to_string(),
        )
        .parse()
        .map_err(|e| format!("PGB_APPLYD_TIMEOUT_MS is not a number: {e}"))?;
        server = server.with_applyd(ApplydClient::new(ApplydConfig {
            socket_path,
            role: role_for_writes,
            session_id: session_for_writes,
            timeout_ms,
        }));
    }

    // `get_audit` reads the `_meta` audit tail through a reader DSN, resolved with
    // the §0.5 BYO precedence: `PGB_META_DSN` env override > `policy.yaml`
    // `audit.target` (credential-less + `PGB_META_PASSWORD`) > None. Optional: if
    // neither source provides it, `get_audit` returns a recoverable
    // AUDIT_UNAVAILABLE block (the `_meta` viewer is read-only; not fail-closed).
    if let Some(dsn) = resolve_meta_dsn(policy.as_ref(), |k| std::env::var(k).ok()) {
        server = server.with_audit(AuditReader::new(AuditConfig { dsn }));
    }
    Ok(server)
}

#[tokio::main]
async fn main() -> ExitCode {
    // Install the ring crypto provider for rustls (process-wide, once) so TLS-on
    // proxy connections work. Idempotent; harmless in dev no-TLS mode.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = match build_server() {
        Ok(s) => s,
        Err(err) => {
            eprintln!("pgb-mcp: configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Serve the MCP protocol over stdio. `serve` performs the `initialize`
    // handshake; `waiting` blocks until the client disconnects (EOF on stdin).
    // The proxy is dialed LAZILY on the first read — the server starts even if the
    // proxy is down.
    let running = match server.serve(stdio()).await {
        Ok(running) => running,
        Err(err) => {
            eprintln!("pgb-mcp: failed to start MCP server: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = running.waiting().await {
        eprintln!("pgb-mcp: server terminated abnormally: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A BYO `policy.yaml` carrying an `audit:` `target:` `_meta` DSN target
    /// (credential-less; no literal password).
    fn byo_policy_with_meta_target() -> PolicyConfig {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
audit:
  target:
    host: meta.db.internal
    port: 5432
    database: app_meta
    role: pgb_audit_writer
"#;
        PolicyConfig::load_from_yaml(yaml).unwrap()
    }

    fn fake_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// BYO-wiring (RED #2, mcp): with NO `PGB_META_DSN` env, the `_meta` reader DSN
    /// resolves from the BYO `policy.yaml` `audit.target` — NOT any throwaway
    /// (54321) default — layering in the out-of-band `PGB_META_PASSWORD`.
    #[test]
    fn resolves_meta_dsn_from_byo_policy_audit_target_not_54321() {
        let policy = byo_policy_with_meta_target();
        let dsn = resolve_meta_dsn(Some(&policy), fake_env(&[("PGB_META_PASSWORD", "metapw")]))
            .expect("a policy audit target must resolve a _meta DSN");
        assert!(dsn.contains("host=meta.db.internal"), "{dsn}");
        assert!(dsn.contains("dbname=app_meta"), "{dsn}");
        assert!(dsn.contains("user=pgb_audit_writer"), "{dsn}");
        assert!(dsn.contains("password=metapw"), "{dsn}");
        assert!(!dsn.contains("54321"), "no throwaway 54321 default: {dsn}");
    }

    /// The credential-less policy target resolves even without a password (a
    /// local-trust `_meta`); the literal secret is never in the policy file.
    #[test]
    fn resolves_meta_dsn_from_policy_target_without_password() {
        let policy = byo_policy_with_meta_target();
        let dsn = resolve_meta_dsn(Some(&policy), fake_env(&[])).expect("resolves credential-less");
        assert!(dsn.contains("host=meta.db.internal"), "{dsn}");
        assert!(!dsn.contains("password="), "no literal password: {dsn}");
    }

    /// The explicit `PGB_META_DSN` env override wins over the policy target.
    #[test]
    fn meta_dsn_env_override_wins_over_policy_target() {
        let policy = byo_policy_with_meta_target();
        let dsn = resolve_meta_dsn(
            Some(&policy),
            fake_env(&[(
                "PGB_META_DSN",
                "host=override.host port=5999 dbname=ov user=r password=p",
            )]),
        )
        .unwrap();
        assert_eq!(
            dsn,
            "host=override.host port=5999 dbname=ov user=r password=p"
        );
    }

    /// With NEITHER an env DSN NOR a policy audit target, the `_meta` reader is
    /// simply absent (None) — the read-only viewer is OPTIONAL, so `get_audit`
    /// returns a recoverable AUDIT_UNAVAILABLE rather than a fail-closed startup
    /// error. (The `_meta` chain's tamper-evidence is owned by the writers.)
    #[test]
    fn meta_dsn_absent_when_no_env_and_no_policy_target() {
        assert!(resolve_meta_dsn(None, fake_env(&[])).is_none());
        // A policy with no audit target is also None.
        let yaml = "version: 1\nroles:\n  app:\n    autonomy: L0\n    budget:\n      \
                    max_bytes: 1\n      max_rows: 1\n      per_window: { window_secs: 1, \
                    max_bytes: 1, max_rows: 1 }\n";
        let policy = PolicyConfig::load_from_yaml(yaml).unwrap();
        assert!(resolve_meta_dsn(Some(&policy), fake_env(&[])).is_none());
    }
}
