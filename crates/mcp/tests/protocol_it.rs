//! End-to-end protocol test: a REAL MCP client drives the `pgb-mcp` server over
//! an in-process duplex pipe (the same `AsyncRead`/`AsyncWrite` transport the
//! stdio binary uses), exercising the full handshake + catalog + a tool call.
//!
//! This is the RED→GREEN test for EPIC #83 PR1. It asserts:
//!   1. `initialize` — the handshake completes; the server reports the expected
//!      protocolVersion, server name, and the `tools` capability.
//!   2. `tools/list` — ALL nine §4 tools are advertised with correct names +
//!      object input schemas (with the right required fields).
//!   3. `tools/call whoami` — returns the posture incl. `security_boundary: false`
//!      and the nine tool names.
//!   4. `tools/call query` — returns the recoverable `UNIMPLEMENTED` block
//!      contract (no panic, the server stays up and serves another call).
//!
//! The driver is rmcp's real client (`().serve(...)`) — not a hand-rolled
//! JSON-RPC stub — so the assertions exercise the genuine protocol path.

use std::collections::BTreeSet;

use pgb_mcp::{PgBumpersMcp, SERVER_NAME, TOOL_NAMES};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, ProtocolVersion};

/// Spin up the server + a real client over an in-process duplex pipe, returning
/// the running client (whose `peer_info` is the server's `initialize` result).
async fn connect() -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    // Two ends of an in-memory bidirectional pipe. The server reads `s_read` /
    // writes `s_write`; the client gets the mirror image. This is exactly the
    // (AsyncRead, AsyncWrite) tuple transport the stdio binary uses.
    let (client_io, server_io) = tokio::io::duplex(8 * 1024);
    let (s_read, s_write) = tokio::io::split(server_io);
    let (c_read, c_write) = tokio::io::split(client_io);

    // Serve the server in the background; it performs the handshake then serves.
    let server = PgBumpersMcp::new("pgb_agent", "sess-it");
    tokio::spawn(async move {
        let running = server
            .serve((s_read, s_write))
            .await
            .expect("server handshake");
        let _ = running.waiting().await;
    });

    // The client drives `initialize` as part of `serve`; `peer_info` then holds
    // the server's InitializeResult.
    ().serve((c_read, c_write)).await.expect("client handshake")
}

#[tokio::test]
async fn initialize_lists_nine_tools_and_whoami_is_not_a_boundary() {
    let client = connect().await;

    // ---- 1. initialize: the handshake result ----
    let info = client.peer_info().expect("server sent InitializeResult");
    assert_eq!(
        info.protocol_version,
        ProtocolVersion::V_2024_11_05,
        "server advertises the 2024-11-05 protocol revision"
    );
    assert_eq!(info.server_info.name, SERVER_NAME, "server name");
    assert!(
        info.capabilities.tools.is_some(),
        "server advertises the tools capability"
    );

    // ---- 2. tools/list: all nine §4 tools, with schemas ----
    let tools = client.list_all_tools().await.expect("tools/list");
    let got: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let want: BTreeSet<String> = TOOL_NAMES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "exactly the nine §4 tool names are advertised");

    for t in &tools {
        let schema = &*t.input_schema;
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "{} input schema is an object",
            t.name
        );
    }
    // `query` requires `sql`; `apply_write` requires `proposal_id`.
    let query = tools.iter().find(|t| t.name == "query").unwrap();
    let required: Vec<&str> = query.input_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(required, vec!["sql"], "query requires sql");

    // ---- 3. tools/call whoami: the §3 posture ----
    let whoami = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await
        .expect("tools/call whoami");
    assert_eq!(whoami.is_error, Some(false), "whoami is a success result");
    let sc = whoami
        .structured_content
        .as_ref()
        .expect("whoami structuredContent");
    assert_eq!(
        sc["security_boundary"],
        serde_json::json!(false),
        "MCP is NOT a security boundary (SPEC §3)"
    );
    assert_eq!(sc["role"], serde_json::json!("pgb_agent"));
    assert_eq!(
        sc["tools"].as_array().unwrap().len(),
        9,
        "whoami reports the nine tools"
    );

    // ---- 4. tools/call query: the recoverable UNIMPLEMENTED block (no panic) ----
    let query_res = client
        .call_tool(CallToolRequestParams::new("query"))
        .await
        .expect("tools/call query does not error the transport");
    assert_eq!(
        query_res.is_error,
        Some(true),
        "an UNIMPLEMENTED block is reported as a tool error"
    );
    let qsc = query_res
        .structured_content
        .as_ref()
        .expect("query structuredContent");
    assert_eq!(qsc["status"], serde_json::json!("blocked"));
    assert_eq!(qsc["code"], serde_json::json!("UNIMPLEMENTED"));
    assert_eq!(qsc["retryable"], serde_json::json!(false));
    assert!(
        qsc["remedy"].as_str().unwrap().contains("#83 PR2"),
        "query's UNIMPLEMENTED block tracks #83 PR2"
    );

    // The server survived the block and still serves: whoami again succeeds.
    let again = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await
        .expect("server still serving after a block");
    assert_eq!(again.is_error, Some(false));

    client.cancel().await.expect("clean shutdown");
}
