//! pg_bumpers MCP server — the agent-facing Model Context Protocol surface
//! (EPIC #83; SPEC §3 layer 3, §4).
//!
//! This crate speaks the **real Model Context Protocol over stdio** via the
//! official Rust SDK [`rmcp`], so `claude mcp add pg-bumpers -- pgb-mcp`
//! connects a real Claude Code to the §4 nine-tool catalog. It is the Rust
//! replacement for the TypeScript `mcp/server` (the TS→Rust consolidation).
//!
//! **Honesty (SPEC §3): the MCP server is COOPERATIVE, NOT a security boundary.**
//! It adds no privilege of its own; the deterministic floor — proxy + WALL +
//! applyd + warden — is the real boundary. `whoami` says so explicitly
//! (`security_boundary: false`).
//!
//! PR2 wired the **read path** through the live `pgb-proxy`:
//! `query` / `explain_plan` / `discover_schema` execute THROUGH the proxy (the
//! real boundary), and `get_audit` reads the `_meta` audit tail. The read-only
//! fast-path REUSES the canonical Rust classifier (`pgb_pgwire::classify`) — no
//! new classifier.
//!
//! PR3 (this update) wires the **write path** through the live `pgb-applyd`
//! Unix-socket daemon: `propose_write` / `dry_run` / `request_elevation` /
//! `apply_write` map onto applyd's JSON-RPC lifecycle (propose→dry_run→
//! request_elevation→apply over the grant-gated §4 floor). applyd stays a SEPARATE
//! daemon: the write credential never enters this agent-facing process. The
//! operator `approve` hop carries the signing key and stays OUT of the agent stdio
//! (via `pgb-cli approve` / the applyd operator path) — there is NO `approve` MCP
//! tool (the catalog stays at nine). `whoami` stays `security_boundary: false`.
//!
//! The modules:
//!   - [`catalog`] — the exact §4 tool names + descriptions + JSON input schemas.
//!   - [`contract`] — the recoverable block contract + the `whoami` posture.
//!   - [`proxy`] — the live `tokio-postgres` transport to the proxy's agent
//!     endpoint (SCRAM; TLS-on or explicit dev no-TLS; lazy-connect + crash-proof
//!     loss handling) the read tools execute through.
//!   - [`applyd`] — the live line-delimited JSON-RPC `UnixStream` client to the
//!     `pgb-applyd` write daemon (lazy-connect + crash-proof loss handling) the
//!     write tools execute through.
//!   - [`audit`] — the read-through to the hash-chained `_meta` audit tail
//!     (`get_audit`), reusing the `pgb_audit` crate.
//!   - [`server`] — the rmcp [`rmcp::ServerHandler`] impl wiring it together.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod applyd;
pub mod audit;
pub mod catalog;
pub mod contract;
pub mod proxy;
pub mod server;

pub use applyd::{ApplydClient, ApplydConfig, ApplydOutcome, DEFAULT_TIMEOUT_MS};
pub use audit::{AuditConfig, AuditReader, AuditRecordView};
pub use catalog::{TOOL_NAMES, ToolSpec, catalog};
pub use contract::{BlockContract, BlockStatus, WhoamiResult};
pub use proxy::{
    DEFAULT_APP_NAME, PlanJson, ProxyConfig, ProxyTransport, ReadOutcome, RowJson, SchemaColumn,
    TlsMode,
};
pub use server::{PgBumpersMcp, SERVER_NAME};
