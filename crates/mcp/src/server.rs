//! The rmcp [`ServerHandler`] implementation: the §4 nine-tool MCP server.
//!
//! This is the skeleton (EPIC #83 PR1). It handles the real Model Context
//! Protocol handshake (`initialize` + `notifications/initialized`), advertises
//! the nine-tool catalog (`tools/list`), and dispatches `tools/call`:
//!   - `whoami` is FULLY implemented — it returns the §3 posture
//!     (`security_boundary: false`, the role/session, the tool list).
//!   - the other eight tools return the `UNIMPLEMENTED` block contract naming the
//!     tracking PR — honest, never a panic. Reads land in PR2, writes in PR3.
//!
//! Honesty (SPEC §3): this server is COOPERATIVE, NOT a security boundary. It
//! adds no privilege; reads will go through the proxy/WALL and writes through
//! applyd's deterministic floor once those paths are wired.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Implementation, InitializeResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
};

use crate::catalog::{ToolSpec, catalog};
use crate::contract::{BlockContract, WhoamiResult};

/// The MCP server name advertised in `initialize` (the `serverInfo.name`).
pub const SERVER_NAME: &str = "pg-bumpers-mcp";

/// The protocol version this server speaks. `2024-11-05` is the widely-supported
/// MCP revision the TS server advertised; we keep it for client compatibility.
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2024_11_05;

/// The §4 nine-tool MCP server (skeleton).
///
/// Stateless by construction (SPEC §4): it holds only the session identity
/// (`role` / `session_id`) used by `whoami`. Proposal / ticket / audit state
/// lives behind the floor (proxy / applyd), never in this process.
#[derive(Debug, Clone)]
pub struct PgBumpersMcp {
    /// The authenticated role (T0), from `PGB_ROLE`. `whoami` reports it; the
    /// server never elevates beyond it.
    role: String,
    /// The session/principal id, from `PGB_SESSION_ID`.
    session_id: String,
}

impl PgBumpersMcp {
    /// Construct the server bound to a `role` + `session_id`.
    pub fn new(role: impl Into<String>, session_id: impl Into<String>) -> Self {
        PgBumpersMcp {
            role: role.into(),
            session_id: session_id.into(),
        }
    }

    /// Build the `whoami` posture result (SPEC §3 honesty contract).
    fn whoami(&self) -> WhoamiResult {
        WhoamiResult::new(&self.role, &self.session_id, &crate::catalog::TOOL_NAMES)
    }

    /// Dispatch one `tools/call` to a structured JSON result.
    ///
    /// Fail-closed: an unknown tool name is an error (it is not in the catalog).
    /// `whoami` returns its posture; every other (not-yet-wired) tool returns the
    /// `UNIMPLEMENTED` block naming the tracking PR — never a panic.
    fn dispatch(&self, name: &str) -> Result<CallToolResult, McpError> {
        match name {
            "whoami" => Ok(structured_ok(&self.whoami())),
            // The read paths (PR2) and write paths (PR3) are not wired yet; each
            // returns the recoverable UNIMPLEMENTED block, honestly tracked.
            "discover_schema" | "query" | "explain_plan" => Ok(structured_block(
                &BlockContract::unimplemented(name, "#83 PR2"),
            )),
            "propose_write" | "dry_run" | "apply_write" | "request_elevation" | "get_audit" => Ok(
                structured_block(&BlockContract::unimplemented(name, "#83 PR3")),
            ),
            other => Err(McpError::invalid_params(
                format!("no such tool: {other}"),
                None,
            )),
        }
    }
}

impl ServerHandler for PgBumpersMcp {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(PROTOCOL_VERSION)
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "pg_bumpers MCP server (SPEC §3/§4). COOPERATIVE, not a security boundary: \
                 the deterministic floor (proxy + WALL + applyd + warden) is the real boundary. \
                 Call whoami to see the posture. Reads (discover_schema/query/explain_plan) and \
                 writes (propose_write→dry_run→apply_write) are being wired (EPIC #83 PR2/PR3).",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(
            catalog().into_iter().map(tool_from_spec).collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatch(request.name.as_ref())
    }
}

/// Convert a catalog [`ToolSpec`] into an rmcp [`Tool`] for `tools/list`.
fn tool_from_spec(spec: ToolSpec) -> Tool {
    // The schema is a JSON object by construction (see `catalog`), so the
    // `as_object` cannot be `None` in practice; fall back to an empty object to
    // stay panic-free (fail-closed).
    let schema = spec.input_schema.as_object().cloned().unwrap_or_default();
    Tool::new(spec.name, spec.description, Arc::new(schema))
}

/// Wrap a serializable success payload as a success `CallToolResult`.
///
/// `CallToolResult::structured` carries the value as BOTH a JSON text block (for
/// clients that read `content`) and `structuredContent` — the result data lives
/// ONLY under those fields, never hoisted into a control position.
fn structured_ok<T: serde::Serialize>(value: &T) -> CallToolResult {
    let json = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    CallToolResult::structured(json)
}

/// Wrap a [`BlockContract`] as an ERROR `CallToolResult` (a recoverable denial):
/// `isError: true`, the block carried as both a JSON text block and
/// `structuredContent`.
fn structured_block(block: &BlockContract) -> CallToolResult {
    let json = serde_json::to_value(block).unwrap_or(serde_json::Value::Null);
    CallToolResult::structured_error(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_whoami_returns_posture_not_a_boundary() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let r = s.dispatch("whoami").unwrap();
        assert_eq!(r.is_error, Some(false));
        let sc = r.structured_content.unwrap();
        assert_eq!(sc["security_boundary"], serde_json::json!(false));
        assert_eq!(sc["role"], serde_json::json!("pgb_agent"));
        assert_eq!(sc["tools"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn dispatch_query_returns_unimplemented_block_no_panic() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let r = s.dispatch("query").unwrap();
        assert_eq!(
            r.is_error,
            Some(true),
            "an UNIMPLEMENTED block is an error result"
        );
        let sc = r.structured_content.unwrap();
        assert_eq!(sc["status"], serde_json::json!("blocked"));
        assert_eq!(sc["code"], serde_json::json!("UNIMPLEMENTED"));
        assert_eq!(sc["retryable"], serde_json::json!(false));
        assert!(sc["remedy"].as_str().unwrap().contains("#83 PR2"));
    }

    #[test]
    fn dispatch_write_tools_track_pr3() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for name in [
            "propose_write",
            "dry_run",
            "apply_write",
            "request_elevation",
            "get_audit",
        ] {
            let r = s.dispatch(name).unwrap();
            let sc = r.structured_content.unwrap();
            assert!(
                sc["remedy"].as_str().unwrap().contains("#83 PR3"),
                "{name} tracks PR3"
            );
        }
    }

    #[test]
    fn dispatch_unknown_tool_is_fail_closed_error() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        assert!(s.dispatch("definitely_not_a_tool").is_err());
    }

    #[test]
    fn get_info_advertises_tools_capability_and_protocol() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let info = s.get_info();
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability advertised"
        );
        assert_eq!(info.server_info.name, SERVER_NAME);
    }
}
