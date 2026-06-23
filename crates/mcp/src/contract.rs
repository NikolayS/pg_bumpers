//! The structured tool-result envelopes the MCP server returns (SPEC §4): the
//! recoverable **block contract** and the `whoami` posture result.
//!
//! These mirror the TypeScript `mcp/server` block contract
//! `{status, code, reason, remedy, retryable}` and the `whoami` result
//! (`{role, security_boundary:false, tools}`) so the agent-facing surface is
//! identical across the TS→Rust consolidation (EPIC #83).
//!
//! Honesty invariant (SPEC §3): a denial is NEVER an opaque error — it is a
//! structured block carrying a machine-readable `code` and an actionable
//! `remedy`, so the agent can recover. In PR1 the eight not-yet-wired tools all
//! return the `UNIMPLEMENTED` block; reads land in PR2, writes in PR3.

use serde::{Deserialize, Serialize};

/// A structured, recoverable block returned by an MCP tool (SPEC §4).
///
/// `status` is always `"blocked"`. The result data of a tool can NEVER widen
/// capability: a block carries only these control fields, never caller-supplied
/// rows hoisted into the envelope (the structural half of the
/// prompt-injection-via-data defense).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockContract {
    /// Always `"blocked"` for this contract.
    pub status: BlockStatus,
    /// The stable machine-readable code (e.g. `"UNIMPLEMENTED"`, `"READ_ONLY"`).
    pub code: String,
    /// The human-readable reason.
    pub reason: String,
    /// The actionable path out (e.g. "tracked in #83 PR2").
    pub remedy: String,
    /// Whether retrying the same action could succeed without intervention.
    pub retryable: bool,
}

/// The single-valued `status` tag of a [`BlockContract`] (`"blocked"`).
///
/// Modeled as an enum so it serializes to the exact literal `"blocked"` and can
/// never accidentally carry another value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockStatus {
    /// The tool denied the request; the block fields say why + how to recover.
    Blocked,
}

impl BlockContract {
    /// Build a block contract. Fail-closed: `retryable` is explicit so a block
    /// never implies "just try again" unless marked recoverable.
    pub fn new(
        code: impl Into<String>,
        reason: impl Into<String>,
        remedy: impl Into<String>,
        retryable: bool,
    ) -> Self {
        BlockContract {
            status: BlockStatus::Blocked,
            code: code.into(),
            reason: reason.into(),
            remedy: remedy.into(),
            retryable,
        }
    }

    /// The PR1 `UNIMPLEMENTED` block for a tool whose real impl lands later.
    ///
    /// `tracking` names the EPIC #83 sub-PR that will wire the tool (PR2 for the
    /// read paths, PR3 for the write paths), so the block is honest about WHEN
    /// the capability arrives. `retryable` is false: retrying now cannot succeed.
    pub fn unimplemented(tool: &str, tracking: &str) -> Self {
        BlockContract::new(
            "UNIMPLEMENTED",
            format!("the `{tool}` tool is not wired yet in this MCP skeleton (EPIC #83 PR1)"),
            format!(
                "tracked: {tracking}; the read paths land in #83 PR2, the write paths in #83 PR3"
            ),
            false,
        )
    }
}

/// The `whoami` posture result (SPEC §3/§4).
///
/// The **honesty contract**: `security_boundary` is ALWAYS `false`. The MCP
/// server adds no privilege; the deterministic floor — proxy + WALL + applyd +
/// warden — is the real boundary. `whoami` exists so an agent can SEE that the
/// layer it is talking to is cooperative, not the thing enforcing safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiResult {
    /// The authenticated role (T0) this session runs as (from `PGB_ROLE`).
    pub role: String,
    /// The session/principal id (from `PGB_SESSION_ID`).
    pub session_id: String,
    /// ALWAYS `false`: the MCP server is NOT the security boundary (SPEC §3).
    pub security_boundary: bool,
    /// A short statement of where the real boundary lives.
    pub boundary: String,
    /// The nine §4 tool names this server exposes.
    pub tools: Vec<String>,
}

impl WhoamiResult {
    /// Build the posture result for `role` / `session_id`, advertising `tools`.
    ///
    /// `security_boundary` is hard-coded `false` and `boundary` names the real
    /// floor — this is the §3 honesty contract, not a configurable field.
    pub fn new(role: impl Into<String>, session_id: impl Into<String>, tools: &[&str]) -> Self {
        WhoamiResult {
            role: role.into(),
            session_id: session_id.into(),
            security_boundary: false,
            boundary: "the deterministic floor (proxy + WALL + applyd + warden) is the real \
                       security boundary; this MCP layer is cooperative and adds no privilege"
                .to_string(),
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_status_serializes_to_blocked_literal() {
        let b = BlockContract::new("X", "r", "m", false);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["status"], serde_json::json!("blocked"));
        assert_eq!(v["retryable"], serde_json::json!(false));
    }

    #[test]
    fn unimplemented_block_is_honest_and_not_retryable() {
        let b = BlockContract::unimplemented("query", "#83 PR2");
        assert_eq!(b.code, "UNIMPLEMENTED");
        assert!(
            !b.retryable,
            "retrying an unimplemented tool cannot succeed"
        );
        assert!(b.reason.contains("query"));
        assert!(b.remedy.contains("#83 PR2"));
    }

    #[test]
    fn whoami_is_never_a_security_boundary() {
        let w = WhoamiResult::new("pgb_agent", "sess-1", &["whoami"]);
        assert!(
            !w.security_boundary,
            "MCP is never the security boundary (SPEC §3)"
        );
        assert_eq!(w.role, "pgb_agent");
        assert!(w.boundary.contains("proxy"));
    }
}
