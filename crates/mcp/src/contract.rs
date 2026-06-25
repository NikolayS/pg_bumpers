//! The structured tool-result envelopes the MCP server returns (SPEC §4): the
//! recoverable **block contract** and the `whoami` posture result.
//!
//! These mirror the block contract `{status, code, reason, remedy, retryable}`
//! and the `whoami` result (`{role, security_boundary:false, tools}`) of the
//! former non-Rust MCP server, so the agent-facing surface stayed identical
//! across the consolidation onto Rust (EPIC #83; the original MCP server is removed).
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

    /// The cooperative read-only fast-path block (SPEC §4; mirrors the TS
    /// `READ_ONLY` contract). The `query` / `explain_plan` read tools run only
    /// provably-pure reads; a write/DDL/stacked statement gets this *recoverable*
    /// block pointing at the write lifecycle, instead of a pointless round-trip to
    /// the proxy. The proxy/WALL would reject it too (the real guarantee); this is
    /// a cooperative fast-path, NOT the boundary. `retryable` is false: the same
    /// statement cannot become a read by retrying.
    pub fn read_only(detail: &str) -> Self {
        BlockContract::new(
            "READ_ONLY",
            format!("this tool runs read-only statements; this looks like a {detail}"),
            "use propose_write → dry_run → apply_write for changes",
            false,
        )
    }

    /// The block returned when the proxy connection is unavailable or was LOST
    /// (the warden's `pg_terminate_backend`, a backend restart, an idle reset, or
    /// the proxy simply being down). Mirrors the TS `PROXY_UNAVAILABLE`. It is
    /// `retryable`: the transport re-dials the proxy on the next read, so a
    /// transient loss recovers — this is what turns a dropped connection into a
    /// recoverable signal instead of a crashed process.
    pub fn proxy_unavailable(detail: &str) -> Self {
        BlockContract::new(
            "PROXY_UNAVAILABLE",
            format!("the proxy connection is unavailable: {detail}"),
            "the proxy may be down or the backend session ended (e.g. a warden \
             terminate, restart, or idle reset); retry — the read will re-dial the proxy",
            true,
        )
    }

    /// The block for a proxy/WALL **least-privilege default-deny** (SQLSTATE
    /// 42501 — `permission denied`: the hardened agent role lacks SELECT on a
    /// non-whitelisted relation). Mirrors the TS `WALL_DENIED`. This is the
    /// proxy/WALL enforcing the floor — a structured denial, never an opaque
    /// crash. Not retryable: the grant does not exist.
    pub fn wall_denied(detail: &str) -> Self {
        BlockContract::new(
            "WALL_DENIED",
            format!("the proxy/WALL denied this read (least-privilege default-deny): {detail}"),
            "the hardened agent role has no SELECT on this relation; request access \
             to a whitelisted relation",
            false,
        )
    }

    /// The generic block for any other proxy/floor denial of a read (a budget
    /// cutoff surfaced as an error, an EXPLAIN-gate block, a syntax/relation
    /// error, a read-only rejection at the wire). Mirrors the TS `PROXY_BLOCKED`.
    /// Not retryable by default: the statement was refused at the deterministic
    /// floor and the same statement will be refused again.
    pub fn proxy_blocked(detail: &str) -> Self {
        BlockContract::new(
            "PROXY_BLOCKED",
            format!("the proxy refused this read at the deterministic floor: {detail}"),
            "adjust the statement to a permitted read, or use the write lifecycle for changes",
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

    #[test]
    fn read_only_block_mirrors_the_ts_contract() {
        let b = BlockContract::read_only("write/DDL");
        assert_eq!(b.code, "READ_ONLY");
        assert!(!b.retryable, "a write does not become a read on retry");
        assert!(b.remedy.contains("propose_write"));
        // The shape is the §4 contract: status/code/reason/remedy/retryable.
        let v = serde_json::to_value(&b).unwrap();
        for k in ["status", "code", "reason", "remedy", "retryable"] {
            assert!(v.get(k).is_some(), "block carries `{k}`");
        }
        assert_eq!(v["status"], serde_json::json!("blocked"));
    }

    #[test]
    fn proxy_unavailable_is_retryable_wall_denied_is_not() {
        let lost = BlockContract::proxy_unavailable("connection terminated");
        assert_eq!(lost.code, "PROXY_UNAVAILABLE");
        assert!(lost.retryable, "a lost connection re-dials → recoverable");

        let wall = BlockContract::wall_denied("permission denied for table secret_data");
        assert_eq!(wall.code, "WALL_DENIED");
        assert!(!wall.retryable, "no grant ⇒ retrying cannot help");

        let other = BlockContract::proxy_blocked("EXPLAIN-cost gate: blocked before execution");
        assert_eq!(other.code, "PROXY_BLOCKED");
        assert!(!other.retryable);
    }
}
