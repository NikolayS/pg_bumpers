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
//! PR1 (this crate) is the **skeleton**: the protocol handshake, the nine-tool
//! catalog with correct JSON input schemas, and `whoami` FULLY implemented. The
//! other eight tools return the recoverable `UNIMPLEMENTED` block contract
//! naming the tracking PR — honest, never a panic. The **read paths** land in
//! #83 PR2 and the **write paths** in #83 PR3.
//!
//! The three modules:
//!   - [`catalog`] — the exact §4 tool names + descriptions + JSON input schemas.
//!   - [`contract`] — the recoverable block contract + the `whoami` posture.
//!   - [`server`] — the rmcp [`rmcp::ServerHandler`] impl wiring it together.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod catalog;
pub mod contract;
pub mod server;

pub use catalog::{TOOL_NAMES, ToolSpec, catalog};
pub use contract::{BlockContract, BlockStatus, WhoamiResult};
pub use server::{PgBumpersMcp, SERVER_NAME};
