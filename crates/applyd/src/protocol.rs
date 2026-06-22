//! The `pgb-applyd` wire protocol: **line-delimited JSON-RPC 2.0** (one JSON
//! object per line) over the Unix-domain socket (SPEC §4; issue #67).
//!
//! Every denial is returned as a JSON-RPC **error object** carrying the
//! recoverable-block contract `{code, message, remedy, retryable}` (the same
//! contract the MCP block surfaces). The stable `code` strings are the
//! [`ErrorCode`] vocabulary: `PROPOSAL_NOT_FOUND` / `VOLATILE` / `PK_LESS` /
//! `NOT_REHEARSABLE` / `APPROVAL_REQUIRED` / `GRANT_REJECTED` / `CONFIRM_MISMATCH`
//! / `BLAST_DRIFT`. The agent/MCP can recover from a denial because the error
//! tells it the next step.
//!
//! Security note: the socket is the boundary, not the MCP server. The `apply`
//! RPC takes **only** `{proposal_id, confirm_rows, confirm_token}` — never a
//! statement/role/session — so the apply re-derives the [`LiveRequest`] from the
//! STORED proposal record, defeating an apply-time field swap.
//!
//! [`LiveRequest`]: pgb_clone_orchestrator::LiveRequest

use serde::{Deserialize, Serialize};

/// The JSON-RPC 2.0 version literal every request/response carries.
pub const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC 2.0 request: `{jsonrpc, id, method, params}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The correlation id (echoed in the response). A null id is a notification
    /// in JSON-RPC, but applyd always answers, so callers should set one.
    #[serde(default)]
    pub id: serde_json::Value,
    /// The method name (one of the [`Method`] variants).
    pub method: String,
    /// The method params (method-specific object); absent ⇒ `null`.
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A JSON-RPC 2.0 response: exactly one of `result` / `error` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The echoed request id.
    pub id: serde_json::Value,
    /// The success payload (absent on error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The error object (absent on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// A success response for `id` carrying `result`.
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Response {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error response for `id` carrying the recoverable-block contract.
    pub fn err(id: serde_json::Value, error: RpcError) -> Self {
        Response {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// A JSON-RPC error object EXTENDED with the recoverable-block contract.
///
/// `code` is the numeric JSON-RPC code (negative, per spec); the
/// `data.code`/`remedy`/`retryable` carry the stable machine vocabulary the
/// agent recovers from. `message` is the human-readable reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    /// The numeric JSON-RPC error code (application errors use -32000).
    pub code: i64,
    /// The human-readable reason.
    pub message: String,
    /// The recoverable-block data the agent/MCP maps to its block contract.
    pub data: BlockData,
}

/// The recoverable-block payload carried in every applyd error
/// (= the MCP block contract `{code, message, remedy, retryable}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockData {
    /// The stable machine code (one of the [`ErrorCode`] strings).
    pub code: String,
    /// The actionable next step (e.g. "open an approval ticket").
    pub remedy: String,
    /// Whether retrying could succeed without intervention.
    pub retryable: bool,
}

/// The application JSON-RPC error code (a single bucket; the stable
/// vocabulary lives in `data.code`).
pub const APP_ERROR_CODE: i64 = -32000;
/// The JSON-RPC "invalid request" code (malformed line / bad version).
pub const INVALID_REQUEST_CODE: i64 = -32600;
/// The JSON-RPC "method not found" code.
pub const METHOD_NOT_FOUND_CODE: i64 = -32601;
/// The JSON-RPC "invalid params" code.
pub const INVALID_PARAMS_CODE: i64 = -32602;

/// The stable error-code vocabulary (every applyd denial is exactly one of
/// these; the recoverable-block contract carries it as `data.code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// No live proposal with that id (unknown or TTL-expired).
    ProposalNotFound,
    /// The proposed predicate references a volatile/non-deterministic function.
    Volatile,
    /// The target relation has no primary key (no ctid fallback).
    PkLess,
    /// The statement is not a certified rehearsable write (DDL/TRUNCATE/…).
    NotRehearsable,
    /// The apply is blocked pending a human approval (no valid grant yet).
    ApprovalRequired,
    /// The §14.3 grant did not verify at apply (signature / binding mismatch /
    /// replay / expiry) — fail-closed, no mutation.
    GrantRejected,
    /// The caller's `confirm_rows` (or `confirm_token`) did not match the
    /// dry-run's affected set.
    ConfirmMismatch,
    /// The apply-time PK-set drifted from the dry-run (the §4 guard fired).
    BlastDrift,
}

impl ErrorCode {
    /// The stable string the agent/MCP keys on.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::ProposalNotFound => "PROPOSAL_NOT_FOUND",
            ErrorCode::Volatile => "VOLATILE",
            ErrorCode::PkLess => "PK_LESS",
            ErrorCode::NotRehearsable => "NOT_REHEARSABLE",
            ErrorCode::ApprovalRequired => "APPROVAL_REQUIRED",
            ErrorCode::GrantRejected => "GRANT_REJECTED",
            ErrorCode::ConfirmMismatch => "CONFIRM_MISMATCH",
            ErrorCode::BlastDrift => "BLAST_DRIFT",
        }
    }

    /// The default remedy line + retryability for this code.
    fn remedy(self) -> (&'static str, bool) {
        match self {
            ErrorCode::ProposalNotFound => {
                ("call propose again to mint a fresh proposal, then dry_run", false)
            }
            ErrorCode::Volatile => (
                "rewrite the predicate without volatile/non-deterministic functions",
                false,
            ),
            ErrorCode::PkLess => (
                "the target has no primary key; pg_bumpers cannot key the affected set (no ctid fallback)",
                false,
            ),
            ErrorCode::NotRehearsable => (
                "only single-statement UPDATE/DELETE are certified writes",
                false,
            ),
            ErrorCode::ApprovalRequired => (
                "open an approval ticket via request_elevation, await the operator approve, then retry apply",
                true,
            ),
            ErrorCode::GrantRejected => (
                "the grant did not verify (tamper/replay/expiry); request a fresh elevation + approve",
                false,
            ),
            ErrorCode::ConfirmMismatch => (
                "re-run dry_run and confirm the exact reported affected row count",
                true,
            ),
            ErrorCode::BlastDrift => (
                "the data drifted since dry_run; re-run dry_run and re-approve before applying",
                false,
            ),
        }
    }

    /// Build the full recoverable [`RpcError`] for this code with `message`.
    pub fn error(self, message: impl Into<String>) -> RpcError {
        let (remedy, retryable) = self.remedy();
        RpcError {
            code: APP_ERROR_CODE,
            message: message.into(),
            data: BlockData {
                code: self.as_str().to_string(),
                remedy: remedy.to_string(),
                retryable,
            },
        }
    }
}

/// The applyd JSON-RPC methods (issue #67): the propose→dry_run→approve→apply
/// lifecycle. `approve` is the operator hop (the signing key NEVER enters the
/// agent/MCP path; it is presented out-of-band by the operator tool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Mint a TTL'd proposal for a candidate statement.
    Propose,
    /// Rehearse a proposal → blast-radius preview (real measurement).
    DryRun,
    /// Open an `APPROVAL_REQUIRED` ticket for a dry-run proposal.
    RequestElevation,
    /// Operator-only: sign the §14.3 grant for a pending request.
    Approve,
    /// Apply a dry-run + approved proposal under the grant-gated §4 floor.
    Apply,
    /// Read the session's hash-chained audit tail.
    GetAudit,
}

impl Method {
    /// Parse a method name (fail-closed: unknown ⇒ `None`).
    pub fn parse(name: &str) -> Option<Method> {
        Some(match name {
            "propose" => Method::Propose,
            "dry_run" => Method::DryRun,
            "request_elevation" => Method::RequestElevation,
            "approve" => Method::Approve,
            "apply" => Method::Apply,
            "get_audit" => Method::GetAudit,
            _ => return None,
        })
    }
}

// ---- typed params/results for each method (serde over `params`/`result`) ----

/// `propose` params: the candidate statement + optional row expectation + the
/// role/session this proposal binds to (pinned into the stored record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeParams {
    /// The exact candidate statement to rehearse + later apply.
    pub sql: String,
    /// The operator's row-count expectation, if any (the confirm_rows seed).
    #[serde(default)]
    pub expected_rows: Option<u64>,
    /// The DB role this write binds to (pinned into the proposal record).
    pub role: String,
    /// The session/principal id this proposal binds to (pinned; defeats
    /// cross-session replay — it is in the §14.3 binding hash).
    pub session_id: String,
}

/// `propose` result: the minted proposal handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeResult {
    /// The stable proposal id.
    pub proposal_id: String,
    /// The proposal TTL in milliseconds.
    pub ttl_millis: u64,
}

/// `dry_run` params: which proposal to rehearse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunParams {
    /// The proposal id minted by `propose`.
    pub proposal_id: String,
}

/// `dry_run` result: the blast-radius preview (subset) + the confirm token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    /// Total affected rows (target + cascades).
    pub total_rows: u64,
    /// The target's affected-PK-set checksum (`"sha256:…"`).
    pub pk_set_checksum: String,
    /// Whether the write is reversible (a captured typed-inverse exists).
    pub reversible: bool,
    /// The opaque token bound to this dry-run; echoed back at apply.
    pub confirm_token: String,
}

/// `request_elevation` params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestElevationParams {
    /// The dry-run proposal to elevate.
    pub proposal_id: String,
    /// A human-readable reason (recorded in the request + audit).
    #[serde(default)]
    pub reason: String,
}

/// `request_elevation` result: the ticket id + TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestElevationResult {
    /// The approval-request id to poll / pass to `approve`.
    pub request_id: String,
    /// The request TTL in milliseconds.
    pub ttl_millis: u64,
}

/// `approve` params: the OPERATOR hop. The signing-key material is presented
/// here by the operator tool, NEVER by the agent/MCP. `approver_id` must differ
/// from the proposal's requester (self-approval refused).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveParams {
    /// The approval-request id to sign.
    pub request_id: String,
    /// The human approver's identity (must differ from the requester).
    pub approver_id: String,
    /// The approver's Ed25519 signing-key material (hex of the 32-byte seed).
    /// The applyd verifies the resulting public key matches its configured
    /// approver pubkey (the apply-time trust root) before signing.
    pub signing_key_hex: String,
    /// The single-use nonce for this grant.
    pub nonce: String,
    /// The grant TTL in milliseconds.
    pub grant_ttl_millis: u64,
}

/// `approve` result: the request was approved + a grant minted in-process. The
/// grant is held by applyd (it never crosses to the agent); apply consumes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveResult {
    /// Echo the approved request id.
    pub request_id: String,
    /// The grant's single-use nonce (so the operator can confirm).
    pub nonce: String,
}

/// `apply` params: the agent presents **only** these. No statement/role/session
/// — those are re-derived from the STORED proposal record (the security
/// invariant: the agent cannot swap what is applied at apply time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyParams {
    /// The dry-run + approved proposal to apply.
    pub proposal_id: String,
    /// The caller's affected-row confirmation (the confirm_rows forcing
    /// function): must equal the dry-run total.
    pub confirm_rows: u64,
    /// The confirm token returned by dry_run (echoed back).
    #[serde(default)]
    pub confirm_token: Option<String>,
}

/// `apply` result: the bounded, reversible write committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    /// Always true on success.
    pub applied: bool,
    /// How many rows the forward op committed.
    pub rows_written: u64,
    /// Whether a typed-inverse was captured (reversible).
    pub reversible: bool,
}

/// `get_audit` params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAuditParams {
    /// Max records to return (clamped to a sane window).
    #[serde(default)]
    pub limit: Option<u64>,
}

/// One audit record in the `get_audit` tail (subset for the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecordWire {
    /// The chain sequence number.
    pub seq: u64,
    /// The gating decision (`ALLOW`/`BLOCK`/`REJECT`).
    pub decision: String,
    /// The machine-readable reason code.
    pub reason_code: String,
}

/// `get_audit` result: the (oldest-first) tail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAuditResult {
    /// The audit records.
    pub records: Vec<AuditRecordWire>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip_to_stable_strings() {
        assert_eq!(ErrorCode::ProposalNotFound.as_str(), "PROPOSAL_NOT_FOUND");
        assert_eq!(ErrorCode::Volatile.as_str(), "VOLATILE");
        assert_eq!(ErrorCode::PkLess.as_str(), "PK_LESS");
        assert_eq!(ErrorCode::NotRehearsable.as_str(), "NOT_REHEARSABLE");
        assert_eq!(ErrorCode::ApprovalRequired.as_str(), "APPROVAL_REQUIRED");
        assert_eq!(ErrorCode::GrantRejected.as_str(), "GRANT_REJECTED");
        assert_eq!(ErrorCode::ConfirmMismatch.as_str(), "CONFIRM_MISMATCH");
        assert_eq!(ErrorCode::BlastDrift.as_str(), "BLAST_DRIFT");
    }

    #[test]
    fn error_carries_recoverable_block_contract() {
        let e = ErrorCode::ApprovalRequired.error("blocked pending approval");
        assert_eq!(e.code, APP_ERROR_CODE);
        assert_eq!(e.data.code, "APPROVAL_REQUIRED");
        assert!(e.data.retryable, "approval-required is recoverable");
        assert!(!e.data.remedy.is_empty());
    }

    #[test]
    fn method_parse_is_fail_closed() {
        assert_eq!(Method::parse("apply"), Some(Method::Apply));
        assert_eq!(Method::parse("propose"), Some(Method::Propose));
        assert_eq!(Method::parse("nope"), None);
    }

    #[test]
    fn response_serializes_one_of_result_or_error() {
        let ok = Response::ok(serde_json::json!(1), serde_json::json!({"applied": true}));
        let s = serde_json::to_string(&ok).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));

        let err = Response::err(serde_json::json!(2), ErrorCode::GrantRejected.error("nope"));
        let s = serde_json::to_string(&err).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
        assert!(s.contains("GRANT_REJECTED"));
    }
}
