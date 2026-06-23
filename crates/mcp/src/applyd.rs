//! The LIVE wire to `pgb-applyd` — the WRITE path's real boundary (SPEC §3/§4).
//!
//! Every write the MCP server performs goes through a **Unix-domain socket** to
//! the `pgb-applyd` daemon (NOT a TCP port, NOT raw PG). `applyd` owns the
//! write-safety STATE (the propose→dry_run→approve→apply lifecycle) and drives the
//! merged grant-gated apply floor (`guarded_apply_with_grant`). This module is the
//! Rust analogue of the TypeScript `ApplydCore`: a thin line-delimited JSON-RPC
//! client that maps the MCP write tools onto the applyd socket and translates
//! every applyd denial into the recoverable block contract.
//!
//! Honesty (SPEC §3): the MCP server is COOPERATIVE, NOT a security boundary. The
//! deterministic floor stays in Rust BEHIND the socket; a compromised MCP server
//! cannot invent privilege, because every write effect must pass through applyd
//! (which re-derives the apply from its OWN stored proposal record — the agent
//! cannot swap statement/role/session at apply time, issue #67). The **write
//! credential** (the resident apply `Client`) lives in the SEPARATE applyd
//! process, never in this agent-facing `pgb-mcp` process (the architecture
//! decision).
//!
//! ## Crash-proof loss handling (mirrors the proxy transport, the #84 lesson)
//! - **Lazy-connect:** the client does NOT die if applyd is down. The first write
//!   dials; a failed dial is a *recoverable* `APPLYD_UNAVAILABLE` block, and the
//!   next call re-dials.
//! - **A dropped applyd socket can't crash the process:** if the socket closes
//!   mid-stream, the held connection is dropped and the next call re-dials; a
//!   persistent failure surfaces a recoverable `APPLYD_UNAVAILABLE` block. There is
//!   no `panic`/`unwrap` on the wire path.
//!
//! The cap + self-determined-predicate gate (EPIC #91) is enforced INSIDE applyd
//! (the exact-PK-set checksum is gone; the floor is the predicate gate + absolute
//! `WriteCap` + reconciliation + pre-image). This client only relays applyd's
//! recoverable error codes — `NOT_REHEARSABLE` (structural/predicate-gate refusal),
//! `APPROVAL_REQUIRED`, `GRANT_REJECTED`, `BLAST_DRIFT` (cap-exceeded), `CONFIRM_*`
//! — verbatim, so injection-via-data can never widen capability.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

use crate::contract::BlockContract;

/// The default per-call socket round-trip timeout (ms). A write apply runs a real
/// txn on the backend, so the budget is generous; mirrors the TS 10s default but
/// roomier for the apply path's dry-run/commit work behind the socket.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Connection + binding details for the applyd socket client. Mirrors the TS
/// `ApplydCoreConfig` + the `PGB_APPLYD_*` env the deploy stack writes.
#[derive(Debug, Clone)]
pub struct ApplydConfig {
    /// The Unix-domain socket path `pgb-applyd` binds (`PGB_APPLYD_SOCKET`).
    pub socket_path: String,
    /// The DB role writes bind to (pinned into the proposal record at propose).
    pub role: String,
    /// The session/principal id writes bind to (pinned; defeats cross-session
    /// replay — it is in the §14.3 binding hash).
    pub session_id: String,
    /// Per-call timeout (ms) for one socket round-trip.
    pub timeout_ms: u64,
}

/// The recoverable-block payload applyd returns under a JSON-RPC error's `data`
/// (= the MCP block contract's machine vocabulary). Deserialized from the wire.
#[derive(Debug, Clone, Deserialize)]
struct BlockData {
    /// The stable machine code (`NOT_REHEARSABLE` / `APPROVAL_REQUIRED` / …).
    code: String,
    /// The actionable next step.
    #[serde(default)]
    remedy: String,
    /// Whether retrying could succeed without intervention.
    #[serde(default)]
    retryable: bool,
}

/// A JSON-RPC error object as applyd returns it (with the recoverable block data).
#[derive(Debug, Clone, Deserialize)]
struct RpcErrorWire {
    /// The human-readable reason.
    #[serde(default)]
    message: String,
    /// The recoverable-block data the agent/MCP maps to its block contract.
    /// Optional: a malformed/transport error may omit it (then we fail-closed).
    #[serde(default)]
    data: Option<BlockData>,
}

/// A JSON-RPC response line: exactly one of `result` / `error` is set.
///
/// The response `id` is intentionally NOT deserialized: calls are strictly
/// sequential (one round-trip under the mutex), so there is exactly one in-flight
/// request and the line that comes back IS its response — no id→pending routing is
/// needed. serde ignores the `id` field on the wire (unknown fields are skipped).
#[derive(Debug, Clone, Deserialize)]
struct RpcResponse {
    /// The success payload (absent on error).
    #[serde(default)]
    result: Option<serde_json::Value>,
    /// The error object (absent on success).
    #[serde(default)]
    error: Option<RpcErrorWire>,
}

/// The outcome of one applyd call: a success payload (the method's `result`), or a
/// recoverable block (an applyd denial OR a transport loss). Either way it is a
/// CONTRACT the server relays — never an opaque error, never a crash.
pub enum ApplydOutcome {
    /// The call succeeded; the JSON `result` payload (method-specific).
    Ok(serde_json::Value),
    /// applyd denied, or the socket was unavailable/lost — a recoverable block.
    Blocked(BlockContract),
}

/// The live client to `pgb-applyd`. Lazily holds at most one connected socket
/// (split into a buffered read half + a write half) behind an async mutex; a lost
/// socket is dropped and re-dialed on the next call. Cloneable + `Send`/`Sync` so
/// one instance backs the whole MCP server across concurrent write-tool calls.
///
/// The transport is **sequential per call** (the mutex serializes the whole
/// request→response round-trip): applyd itself serializes the write path under one
/// lock, so there is no benefit to pipelining, and a strict request/response pairing
/// keeps the line framing unambiguous without an id→pending map.
#[derive(Clone)]
pub struct ApplydClient {
    config: Arc<ApplydConfig>,
    /// The live connection, or `None` when never-dialed / lost.
    conn: Arc<Mutex<Option<Conn>>>,
    /// Monotonic JSON-RPC id source (informational; the response id is not used to
    /// route since calls are strictly sequential, but a unique id is correct).
    next_id: Arc<AtomicU64>,
}

/// One connected applyd socket, split into its read + write halves.
struct Conn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl ApplydClient {
    /// Build a client for `config`. Does NOT connect — the first call dials
    /// (lazy-connect), so constructing this never fails even if applyd is down.
    pub fn new(config: ApplydConfig) -> Self {
        ApplydClient {
            config: Arc::new(config),
            conn: Arc::new(Mutex::new(None)),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// **`propose`** — mint a TTL'd write proposal. The role/session are pinned
    /// into the stored record from the client config (the apply re-derives from
    /// these, never from apply-time params). A non-rehearsable / structural shape
    /// (DROP/TRUNCATE/steerable predicate) is refused by applyd's classify choke →
    /// a recoverable block (`NOT_REHEARSABLE`).
    pub async fn propose(&self, sql: &str, expected_rows: Option<u64>) -> ApplydOutcome {
        let mut params = serde_json::json!({
            "sql": sql,
            "role": self.config.role,
            "session_id": self.config.session_id,
        });
        if let Some(n) = expected_rows {
            params["expected_rows"] = serde_json::json!(n);
        }
        self.call("propose", params).await
    }

    /// **`dry_run`** — rehearse a proposal → the real measured blast radius +
    /// confirm token. A volatile / PK-less / non-rehearsable refusal surfaces as
    /// the matching recoverable code.
    pub async fn dry_run(&self, proposal_id: &str) -> ApplydOutcome {
        self.call("dry_run", serde_json::json!({ "proposal_id": proposal_id }))
            .await
    }

    /// **`request_elevation`** — open an `APPROVAL_REQUIRED` ticket for a dry-run
    /// proposal. Returns the request id + TTL + the §14.2 disclosures (the
    /// suggested absolute cap + the side-effecting triggers the human reviews).
    pub async fn request_elevation(&self, proposal_id: &str, reason: &str) -> ApplydOutcome {
        self.call(
            "request_elevation",
            serde_json::json!({ "proposal_id": proposal_id, "reason": reason }),
        )
        .await
    }

    /// **`apply`** — apply a dry-run + approved proposal under the grant-gated §4
    /// floor. The client presents ONLY `{proposal_id, confirm_rows, confirm_token}`:
    /// applyd re-derives the live request from its STORED record, so the agent can
    /// never swap what is applied. `confirm_rows` is the forcing function.
    pub async fn apply(
        &self,
        proposal_id: &str,
        confirm_rows: u64,
        confirm_token: Option<&str>,
    ) -> ApplydOutcome {
        let mut params = serde_json::json!({
            "proposal_id": proposal_id,
            "confirm_rows": confirm_rows,
        });
        if let Some(t) = confirm_token {
            params["confirm_token"] = serde_json::json!(t);
        }
        self.call("apply", params).await
    }

    /// One JSON-RPC round-trip with lazy-connect + one reconnect-on-drop retry.
    ///
    /// The retry contract (mirrors the proxy transport): if the held socket is
    /// unusable (closed/reset), the FIRST attempt fails, we drop it and re-dial,
    /// and the SECOND attempt runs on a fresh socket. A persistent failure (applyd
    /// down) surfaces the recoverable `APPLYD_UNAVAILABLE` block so the caller can
    /// retry — never a crash.
    async fn call(&self, method: &str, params: serde_json::Value) -> ApplydOutcome {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                match self.dial().await {
                    Ok(c) => *guard = Some(c),
                    Err(block) => return ApplydOutcome::Blocked(block),
                }
            }
            let conn = guard.as_mut().expect("conn present after dial");
            match self.round_trip(conn, method, &params).await {
                Ok(resp) => return map_response(resp),
                Err(WireError::Lost(detail)) => {
                    // The socket died: drop it so the next iteration re-dials. On
                    // the first attempt retry on a fresh socket; on the second,
                    // surface the recoverable loss.
                    *guard = None;
                    if attempt == 0 {
                        continue;
                    }
                    return ApplydOutcome::Blocked(applyd_unavailable(&detail));
                }
                Err(WireError::Timeout) => {
                    // A timed-out call leaves the framing ambiguous (a late
                    // response would desync the line stream), so drop the socket —
                    // the next call re-dials a clean one. Fail-closed: a timeout is
                    // a recoverable block, never a silent success.
                    *guard = None;
                    return ApplydOutcome::Blocked(applyd_timeout(method, self.config.timeout_ms));
                }
            }
        }
        // Unreachable in practice (the loop returns), but fail-closed.
        ApplydOutcome::Blocked(applyd_unavailable("exhausted reconnect attempts"))
    }

    /// Dial the applyd Unix socket and split it into read/write halves. A dial
    /// failure is a recoverable `APPLYD_UNAVAILABLE` block (the next call re-dials).
    async fn dial(&self) -> Result<Conn, BlockContract> {
        let stream = UnixStream::connect(&self.config.socket_path)
            .await
            .map_err(|e| {
                applyd_unavailable(&format!(
                    "could not connect to the applyd socket at {}: {e}",
                    self.config.socket_path
                ))
            })?;
        let (read_half, writer) = stream.into_split();
        Ok(Conn {
            reader: BufReader::new(read_half),
            writer,
        })
    }

    /// Write one JSON-RPC request line + read exactly one response line, under the
    /// per-call timeout. A closed/reset socket (EOF, broken pipe) is a re-dialable
    /// [`WireError::Lost`]; a malformed response line is also treated as a loss
    /// (fail-closed: the framing is no longer trustworthy).
    async fn round_trip(
        &self,
        conn: &mut Conn,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<RpcResponse, WireError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        // One line per request (line-delimited JSON-RPC 2.0).
        let mut line =
            serde_json::to_string(&request).map_err(|e| WireError::Lost(e.to_string()))?;
        line.push('\n');

        let dur = Duration::from_millis(self.config.timeout_ms);
        let exchange = async {
            conn.writer
                .write_all(line.as_bytes())
                .await
                .map_err(|e| WireError::Lost(e.to_string()))?;
            conn.writer
                .flush()
                .await
                .map_err(|e| WireError::Lost(e.to_string()))?;
            // Read exactly one response line.
            let mut resp_line = String::new();
            let n = conn
                .reader
                .read_line(&mut resp_line)
                .await
                .map_err(|e| WireError::Lost(e.to_string()))?;
            if n == 0 {
                // EOF: applyd closed the socket. Re-dialable loss.
                return Err(WireError::Lost("applyd socket closed (EOF)".to_string()));
            }
            serde_json::from_str::<RpcResponse>(resp_line.trim())
                .map_err(|e| WireError::Lost(format!("unparseable applyd response line: {e}")))
        };
        match timeout(dur, exchange).await {
            Ok(res) => res,
            Err(_elapsed) => Err(WireError::Timeout),
        }
    }
}

/// A wire-level failure of one round-trip: a re-dialable connection loss, or a
/// per-call timeout. (A JSON-RPC *application* error is NOT a `WireError` — it
/// rides in the parsed [`RpcResponse`] and becomes a recoverable block.)
enum WireError {
    /// The socket died / returned an untrustworthy line — drop + re-dial.
    Lost(String),
    /// The round-trip exceeded the per-call timeout.
    Timeout,
}

/// Map a parsed JSON-RPC response into an [`ApplydOutcome`]: a `result` becomes
/// `Ok(payload)`; an `error` becomes a recoverable [`BlockContract`] carrying
/// applyd's stable `data.code` / `remedy` / `retryable` verbatim (the recoverable
/// contract the server relays). A response with NEITHER is fail-closed to a block.
fn map_response(resp: RpcResponse) -> ApplydOutcome {
    if let Some(err) = resp.error {
        return ApplydOutcome::Blocked(block_of(&err));
    }
    match resp.result {
        Some(v) => ApplydOutcome::Ok(v),
        // No result AND no error: a malformed response. Fail-closed.
        None => ApplydOutcome::Blocked(BlockContract::new(
            "APPLYD_ERROR",
            "applyd returned a response with neither result nor error",
            "retry; if it persists, inspect the applyd daemon logs",
            false,
        )),
    }
}

/// Build the recoverable [`BlockContract`] from an applyd JSON-RPC error. The
/// stable `data.code` is the block's code (so the agent keys on the SAME machine
/// vocabulary applyd uses: `NOT_REHEARSABLE` / `APPROVAL_REQUIRED` / `GRANT_REJECTED`
/// / `CONFIRM_MISMATCH` / `BLAST_DRIFT` / `PROPOSAL_NOT_FOUND` / …). When `data` is
/// absent (a transport-level error), fail-closed to a non-retryable `APPLYD_ERROR`.
fn block_of(err: &RpcErrorWire) -> BlockContract {
    match &err.data {
        Some(d) => BlockContract::new(
            d.code.clone(),
            err.message.clone(),
            if d.remedy.is_empty() {
                "see the applyd error for the next step".to_string()
            } else {
                d.remedy.clone()
            },
            d.retryable,
        ),
        None => BlockContract::new(
            "APPLYD_ERROR",
            if err.message.is_empty() {
                "applyd returned an error with no recoverable data".to_string()
            } else {
                err.message.clone()
            },
            "retry; if it persists, inspect the applyd daemon logs",
            false,
        ),
    }
}

/// The recoverable block for an applyd socket that is down or was LOST (never
/// dialed, a closed socket, a daemon restart). `retryable` is true: the client
/// re-dials on the next call, so a transient loss recovers — this turns a dropped
/// socket into a recoverable signal instead of a crashed process. Mirrors the
/// proxy transport's `PROXY_UNAVAILABLE`.
fn applyd_unavailable(detail: &str) -> BlockContract {
    BlockContract::new(
        "APPLYD_UNAVAILABLE",
        format!("the applyd write daemon is unavailable: {detail}"),
        "the applyd daemon may be down or the socket was reset; retry — the write \
         will re-dial the applyd socket",
        true,
    )
}

/// The recoverable block for a per-call timeout. `retryable` is true: a fresh
/// socket is re-dialed on the next call.
fn applyd_timeout(method: &str, timeout_ms: u64) -> BlockContract {
    BlockContract::new(
        "APPLYD_UNAVAILABLE",
        format!("the applyd `{method}` call timed out after {timeout_ms}ms"),
        "the applyd daemon did not respond in time; retry — the write will re-dial",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lazy_client_constructs_without_connecting() {
        // Constructing a client for a DOWN applyd must NOT fail or block — the
        // first call dials lazily, so the process never dies on a down daemon.
        let c = ApplydClient::new(ApplydConfig {
            socket_path: "/nonexistent/pgb-applyd-does-not-exist.sock".into(),
            role: "app_writer".into(),
            session_id: "sess-1".into(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        });
        // The clone shares the same lazy state.
        let _clone = c.clone();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn calls_against_a_down_applyd_are_recoverable_blocks_not_a_crash() {
        // Nothing binds this socket. Every write tool must come back as the
        // RECOVERABLE APPLYD_UNAVAILABLE block — the process must NOT panic or die.
        let c = ApplydClient::new(ApplydConfig {
            socket_path: "/nonexistent/pgb-applyd-down.sock".into(),
            role: "app_writer".into(),
            session_id: "sess-1".into(),
            timeout_ms: 1000,
        });
        for outcome in [
            c.propose("UPDATE accounts SET balance = 0 WHERE id = 1", Some(1))
                .await,
            c.dry_run("p-1").await,
            c.request_elevation("p-1", "because").await,
            c.apply("p-1", 1, Some("ct-1")).await,
        ] {
            match outcome {
                ApplydOutcome::Blocked(b) => {
                    assert_eq!(b.code, "APPLYD_UNAVAILABLE");
                    assert!(b.retryable, "a down applyd is retryable (re-dial)");
                }
                ApplydOutcome::Ok(_) => panic!("a down applyd cannot return a result"),
            }
        }
    }

    #[test]
    fn maps_an_applyd_error_to_the_recoverable_block_contract_verbatim() {
        // The block-contract mapping: applyd's stable data.code/remedy/retryable
        // become the block's code/remedy/retryable; message becomes the reason.
        let err = RpcErrorWire {
            message: "no approved grant for this proposal".into(),
            data: Some(BlockData {
                code: "APPROVAL_REQUIRED".into(),
                remedy: "open an approval ticket via request_elevation".into(),
                retryable: true,
            }),
        };
        let b = block_of(&err);
        assert_eq!(b.code, "APPROVAL_REQUIRED");
        assert_eq!(b.reason, "no approved grant for this proposal");
        assert!(b.remedy.contains("approval ticket"));
        assert!(b.retryable);
    }

    #[test]
    fn maps_a_structural_refusal_to_not_rehearsable_not_retryable() {
        // A DROP/TRUNCATE/steerable-predicate refusal: applyd returns
        // NOT_REHEARSABLE, not retryable — relayed verbatim.
        let err = RpcErrorWire {
            message: "predicate is not self-determined (steerable)".into(),
            data: Some(BlockData {
                code: "NOT_REHEARSABLE".into(),
                remedy: "restrict the WHERE to the primary key + literals".into(),
                retryable: false,
            }),
        };
        let b = block_of(&err);
        assert_eq!(b.code, "NOT_REHEARSABLE");
        assert!(
            !b.retryable,
            "a structural refusal does not retry into success"
        );
    }

    #[test]
    fn maps_cap_exceeded_blast_drift_verbatim() {
        // An over-cap apply: applyd maps CapExceeded → BLAST_DRIFT; relayed.
        let err = RpcErrorWire {
            message: "the live write's magnitude exceeded the approved cap".into(),
            data: Some(BlockData {
                code: "BLAST_DRIFT".into(),
                remedy: "re-run dry_run and re-approve with a larger cap".into(),
                retryable: false,
            }),
        };
        let b = block_of(&err);
        assert_eq!(b.code, "BLAST_DRIFT");
        assert!(!b.retryable);
    }

    #[test]
    fn an_error_without_data_fails_closed_to_applyd_error() {
        // A transport-level error (no recoverable data) fails closed: a
        // non-retryable APPLYD_ERROR, never a silent success.
        let err = RpcErrorWire {
            message: "malformed JSON-RPC line".into(),
            data: None,
        };
        let b = block_of(&err);
        assert_eq!(b.code, "APPLYD_ERROR");
        assert!(!b.retryable);
        assert_eq!(b.reason, "malformed JSON-RPC line");
    }

    #[test]
    fn map_response_success_yields_ok_payload() {
        let resp = RpcResponse {
            result: Some(serde_json::json!({ "proposal_id": "p-1", "ttl_millis": 1800000 })),
            error: None,
        };
        match map_response(resp) {
            ApplydOutcome::Ok(v) => {
                assert_eq!(v["proposal_id"], serde_json::json!("p-1"));
                assert_eq!(v["ttl_millis"], serde_json::json!(1800000));
            }
            ApplydOutcome::Blocked(_) => panic!("a result payload must map to Ok"),
        }
    }

    #[test]
    fn map_response_neither_result_nor_error_fails_closed() {
        let resp = RpcResponse {
            result: None,
            error: None,
        };
        match map_response(resp) {
            ApplydOutcome::Blocked(b) => assert_eq!(b.code, "APPLYD_ERROR"),
            ApplydOutcome::Ok(_) => panic!("a result-less, error-less response must fail closed"),
        }
    }
}
