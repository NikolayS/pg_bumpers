//! The §4 nine-tool catalog: the EXACT tool names, one-line descriptions, and
//! JSON input schemas the MCP server advertises in `tools/list`.
//!
//! This is the agent-facing contract. The names + shapes MIRROR the TypeScript
//! `mcp/server` this Rust server replaces (EPIC #83) so a client sees the same
//! surface regardless of which implementation is wired. The schemas are derived
//! from the `pgb-applyd` wire params (`crates/applyd/src/protocol.rs`) and the TS
//! `McpServer` call signatures — but NOTHING is wired to those engines yet (PR1
//! is the skeleton; reads land in PR2, writes in PR3).

use serde_json::{Map, Value, json};

/// The exactly-nine MCP tool names (SPEC §4), in catalog order.
///
/// Fail-closed: an unknown tool name is rejected (it is not in this list), it is
/// never silently dispatched.
pub const TOOL_NAMES: [&str; 9] = [
    "whoami",
    "discover_schema",
    "query",
    "explain_plan",
    "propose_write",
    "dry_run",
    "apply_write",
    "request_elevation",
    "get_audit",
];

/// A single tool's catalog entry: name + one-line purpose + JSON input schema.
pub struct ToolSpec {
    /// The stable tool name (one of [`TOOL_NAMES`]).
    pub name: &'static str,
    /// The one-line human-readable purpose (mirrors the TS descriptions).
    pub description: &'static str,
    /// The JSON Schema (draft-07 flavored `{type:object, properties, required}`)
    /// describing the tool's arguments.
    pub input_schema: Value,
}

/// Build the full nine-tool catalog with descriptions + input schemas.
///
/// The descriptions are copied verbatim from the TS `TOOL_DESCRIPTIONS` so the
/// agent-facing wording does not drift across the TS→Rust consolidation.
pub fn catalog() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "whoami",
            description: "Report the agent's role and posture (MCP is not a security boundary).",
            input_schema: object_schema(&[], &[]),
        },
        ToolSpec {
            name: "discover_schema",
            description: "List accessible schema (tables/columns) through the proxy.",
            input_schema: object_schema(&[], &[]),
        },
        ToolSpec {
            name: "query",
            description: "Run a read-only statement through the proxy (cost/byte budgeted).",
            input_schema: object_schema(
                &[
                    (
                        "sql",
                        string_prop("The read-only statement to execute through the proxy."),
                    ),
                    (
                        "application_name",
                        string_prop("Optional application_name tag carried to the proxy/warden."),
                    ),
                ],
                &["sql"],
            ),
        },
        ToolSpec {
            name: "explain_plan",
            description: "EXPLAIN (never ANALYZE) a statement through the proxy.",
            input_schema: object_schema(
                &[(
                    "sql",
                    string_prop("The read-only statement to EXPLAIN (never EXPLAIN ANALYZE)."),
                )],
                &["sql"],
            ),
        },
        ToolSpec {
            name: "propose_write",
            description: "Create a TTL'd write proposal in core (state lives in core).",
            input_schema: object_schema(
                &[
                    (
                        "sql",
                        string_prop("The candidate write statement to rehearse + later apply."),
                    ),
                    (
                        "expected_rows",
                        integer_prop("Optional row-count expectation (the confirm_rows seed)."),
                    ),
                    (
                        "application_name",
                        string_prop("Optional application_name tag carried to the proxy/warden."),
                    ),
                ],
                &["sql"],
            ),
        },
        ToolSpec {
            name: "dry_run",
            description: "Rehearse a proposal → blast radius (bounded row/WAL-byte estimate vs the WriteCap).",
            input_schema: object_schema(
                &[(
                    "proposal_id",
                    string_prop("The proposal id minted by propose_write."),
                )],
                &["proposal_id"],
            ),
        },
        ToolSpec {
            name: "apply_write",
            description: "Apply a dry-run proposal under the grant-gated WriteCap floor (needs confirm_rows).",
            input_schema: object_schema(
                &[
                    ("proposal_id", string_prop("The dry-run proposal to apply.")),
                    (
                        "confirm_rows",
                        integer_prop(
                            "The confirm_rows forcing function: must equal the dry-run total.",
                        ),
                    ),
                    (
                        "confirm_token",
                        string_prop("The opaque token returned by dry_run (echoed back)."),
                    ),
                ],
                &["proposal_id"],
            ),
        },
        ToolSpec {
            name: "request_elevation",
            description: "Open an approval-request ticket for a blocked action (§14).",
            input_schema: object_schema(
                &[
                    (
                        "proposal_id",
                        string_prop("The dry-run proposal to elevate."),
                    ),
                    (
                        "reason",
                        string_prop("A human-readable reason recorded in the request."),
                    ),
                ],
                &["proposal_id", "reason"],
            ),
        },
        ToolSpec {
            name: "get_audit",
            description: "Read the hash-chained audit for this session.",
            input_schema: object_schema(
                &[(
                    "limit",
                    integer_prop("Max records to return (clamped to a sane window)."),
                )],
                &[],
            ),
        },
    ]
}

/// A JSON-Schema `{type:"string", description}` property.
fn string_prop(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

/// A JSON-Schema `{type:"integer", description}` property.
fn integer_prop(description: &str) -> Value {
    json!({ "type": "integer", "description": description })
}

/// A JSON-Schema object with the given named properties + required list.
///
/// `additionalProperties` is `false` — fail-closed: a client cannot smuggle
/// unrecognized fields past the schema.
fn object_schema(props: &[(&str, Value)], required: &[&str]) -> Value {
    let mut properties = Map::new();
    for (name, schema) in props {
        properties.insert((*name).to_string(), schema.clone());
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required.iter().map(|r| json!(r)).collect::<Vec<_>>(),
        "additionalProperties": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_exactly_nine_named_tools_in_order() {
        let cat = catalog();
        assert_eq!(cat.len(), 9, "the §4 catalog is exactly nine tools");
        let names: Vec<&str> = cat.iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            TOOL_NAMES.to_vec(),
            "catalog order matches TOOL_NAMES"
        );
    }

    #[test]
    fn every_tool_has_a_nonempty_description_and_object_schema() {
        for t in catalog() {
            assert!(!t.description.is_empty(), "{} has a description", t.name);
            assert_eq!(
                t.input_schema["type"],
                json!("object"),
                "{} schema is object",
                t.name
            );
        }
    }

    #[test]
    fn query_schema_requires_sql() {
        let q = catalog().into_iter().find(|t| t.name == "query").unwrap();
        assert_eq!(q.input_schema["required"], json!(["sql"]));
        assert_eq!(q.input_schema["properties"]["sql"]["type"], json!("string"));
    }
}
