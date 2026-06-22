//! `pgb-applyd` — the pg_bumpers **write-path daemon** (issue #67, S5).
//!
//! A long-lived process that binds a **Unix-domain socket** (`PGB_APPLYD_SOCKET`,
//! dir `0700`, socket `0600` — NOT a TCP port, NOT agent-reachable) and speaks
//! **line-delimited JSON-RPC 2.0** (one JSON object per line). It owns the
//! write-safety STATE in-process, TTL'd via an injected [`pgb_core::Clock`] — the
//! production analog of the TS `FakeCore` — and drives the merged grant-gated
//! apply floor ([`pgb_clone_orchestrator::guarded_apply_with_grant`], #66) for
//! writes. The MCP server's `ApplydCore` (TS) wires to it; reads go through the
//! proxy, not here.
//!
//! - [`protocol`] — the JSON-RPC types + the stable recoverable-error vocabulary
//!   (`PROPOSAL_NOT_FOUND` / `VOLATILE` / `PK_LESS` / `NOT_REHEARSABLE` /
//!   `APPROVAL_REQUIRED` / `GRANT_REJECTED` / `CONFIRM_MISMATCH` / `BLAST_DRIFT`).
//! - [`service`] — the DB-free [`service::Service`] state machine (the FakeCore
//!   peer): proposals, cached blast radii, elevation requests, the nonce store,
//!   the approver key, the policy, the shared `_meta` audit chain, and the
//!   propose / dry_run / request_elevation / approve / apply methods. The
//!   security-critical invariant lives here: `apply` re-derives the
//!   [`pgb_clone_orchestrator::LiveRequest`] from the STORED proposal record,
//!   never from apply-time params.
//!
//! The grant crypto, the audit chain, and the §4 guards are all **reused** from
//! `pgb-policy` / `pgb-audit` / `pgb-clone-orchestrator` — applyd only
//! orchestrates them behind the socket. The MCP/socket is a cooperative seam, not
//! a security boundary; the deterministic floor stays in Rust.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod protocol;
pub mod service;

pub use protocol::{
    AuditRecordWire, BlockData, ErrorCode, Method, Request, Response, RpcError, JSONRPC_VERSION,
};
pub use service::{Service, DEFAULT_REQUEST_TTL_MILLIS};
