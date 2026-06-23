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
//!   - `PGB_META_DSN`        — the `_meta` reader DSN for `get_audit` (optional;
//!     without it `get_audit` returns a recoverable `AUDIT_UNAVAILABLE` block).

use std::process::ExitCode;

use pgb_mcp::{
    ApplydClient, ApplydConfig, AuditConfig, AuditReader, PgBumpersMcp, ProxyConfig,
    ProxyTransport, TlsMode,
};
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

    // `get_audit` reads the `_meta` audit tail through a reader DSN. Optional: if
    // unset, `get_audit` returns a recoverable AUDIT_UNAVAILABLE block.
    if let Ok(dsn) = std::env::var("PGB_META_DSN")
        && !dsn.is_empty()
    {
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
