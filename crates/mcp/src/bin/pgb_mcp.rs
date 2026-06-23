//! `pgb-mcp` — the deployable stdio MCP server entrypoint (EPIC #83 PR1).
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
//! `tools/list` + `tools/call whoami` work end-to-end; the eight not-yet-wired
//! tools return the recoverable `UNIMPLEMENTED` block (reads land in #83 PR2,
//! writes in #83 PR3).
//!
//! Honesty (SPEC §3): this server is COOPERATIVE, not a security boundary. The
//! deterministic floor (proxy + WALL + applyd + warden) is the real boundary.
//!
//! Environment (all optional in the skeleton — sane defaults so the bare binary
//! connects; the wired read/write paths in PR2/PR3 add their own required vars):
//!   - `PGB_ROLE`       — the authenticated role (T0). Default `pgb_agent`.
//!   - `PGB_SESSION_ID` — the session/principal id. Default `mcp-<pid>`.

use std::process::ExitCode;

use pgb_mcp::PgBumpersMcp;
use rmcp::{ServiceExt, transport::stdio};

/// Read an env var, falling back to `default` when unset or empty.
fn env_or(key: &str, default: impl Into<String>) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.into(),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let role = env_or("PGB_ROLE", "pgb_agent");
    let session_id = env_or("PGB_SESSION_ID", format!("mcp-{}", std::process::id()));

    let server = PgBumpersMcp::new(role, session_id);

    // Serve the MCP protocol over stdio. `serve` performs the `initialize`
    // handshake; `waiting` blocks until the client disconnects (EOF on stdin).
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
