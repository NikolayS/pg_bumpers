//! The LIVE wire to `pgb-proxy` — the read path's real boundary (SPEC §3 layer 2).
//!
//! Every read the MCP server performs goes through a Postgres wire connection to
//! the **proxy's agent endpoint**, NOT raw PG. In production that endpoint is the
//! Apache Rust `pgb-proxy` (proxy + warden + WALL = the real boundary); the proxy
//! is what enforces extended-protocol-only / read-only / budgets / audit. This
//! module is the Rust analogue of the original non-Rust `PgProxyTransport`: it speaks
//! `tokio-postgres` to the proxy and surfaces what the proxy returns.
//!
//! Honesty (SPEC §3): the MCP server is COOPERATIVE, NOT a security boundary. The
//! connection this holds is exactly the privilege the proxy/WALL granted — nothing
//! more. The cooperative read-only fast-path lives in [`crate::server`] (it reuses
//! `pgb_pgwire::classify`); this transport just runs the (already-classified) read
//! through the proxy and maps the proxy's denials into the recoverable block
//! contract.
//!
//! ## Lazy-connect + crash-proof loss handling (the #84 lesson, in Rust)
//! - **Lazy-connect:** the transport does NOT die if the proxy is down. The first
//!   read dials; a failed dial is a *recoverable* [`BlockContract::proxy_unavailable`]
//!   block, and the next read re-dials.
//! - **A dropped / warden-killed connection can't crash the process:** the
//!   `tokio-postgres` `Connection` future is driven on a spawned task; when the
//!   backend session ends (a `pg_terminate_backend` on the agent-tagged session, a
//!   restart, an idle reset) that future resolves with an error which we *absorb*
//!   (drop the dead client) instead of letting it propagate. The next read sees no
//!   live client and re-dials. There is no `panic`, no `unwrap` on the wire path.
//!
//! ## TLS
//! TLS-on (rustls/ring, verifying the proxy's cert) is the production posture; a
//! TLS-off **dev mode** (plaintext) is supported and must be stated explicitly via
//! config. Either way the proxy authenticates the agent via SCRAM-SHA-256 — the
//! credential the transport presents.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_postgres::{Client, Config, NoTls};

use crate::contract::BlockContract;

/// The `application_name` the MCP read session presents on the wire. The proxy
/// re-stamps `pgb_proxy` on the backend session it originates (the warden's tag),
/// so this client-side value is informational only — never a security control.
pub const DEFAULT_APP_NAME: &str = "pgb_mcp";

/// How the transport secures the wire to the proxy.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Plaintext — **dev only**, and only when the proxy is in its explicit
    /// dev-only no-TLS mode. Stated explicitly so a no-TLS posture is never silent.
    Disabled,
    /// TLS via rustls/ring. The proxy's certificate is verified against the
    /// supplied roots (DER-encoded trust anchors). An empty root set with TLS
    /// enabled is a misconfiguration the dial will reject (fail-closed).
    Rustls {
        /// DER-encoded trust anchors used to verify the proxy's server cert.
        roots_der: Vec<Vec<u8>>,
    },
}

/// Connection details for the proxy's agent endpoint. Mirrors the TS
/// `PgProxyConfig` + the `PGB_PROXY_*` env the deploy stack writes.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// The proxy host (e.g. `127.0.0.1`). NEVER the raw backend.
    pub host: String,
    /// The proxy's agent port (e.g. `6432`). NEVER `5432` and not the backend.
    pub port: u16,
    /// The database to connect to (the proxy brokers it to the backend).
    pub database: String,
    /// The SCRAM username the proxy verifies (the agent role, e.g. `pgb_agent`).
    pub user: String,
    /// The SCRAM password for `user`.
    pub password: String,
    /// The `application_name` presented on the wire (informational; default
    /// [`DEFAULT_APP_NAME`]).
    pub application_name: String,
    /// The TLS posture (TLS-on verifying the proxy cert, or explicit dev no-TLS).
    pub tls: TlsMode,
    /// Per-statement timeout (ms) set on the session — defence-in-depth, not THE
    /// floor (the proxy injects its own authoritative `statement_timeout`).
    pub statement_timeout_ms: u64,
}

impl ProxyConfig {
    /// Build a [`Config`] for `tokio-postgres` from these connection details.
    fn pg_config(&self) -> Config {
        let mut cfg = Config::new();
        cfg.host(&self.host)
            .port(self.port)
            .dbname(&self.database)
            .user(&self.user)
            .password(&self.password)
            .application_name(&self.application_name);
        if self.statement_timeout_ms > 0 {
            // `options` carries `-c statement_timeout=…` as a startup option. The
            // proxy injects its own authoritative timeout too; this is belt-and-
            // braces from the client side.
            cfg.options(format!(
                "-c statement_timeout={}",
                self.statement_timeout_ms
            ));
        }
        cfg
    }
}

/// One row of a read result: an ordered map of column-name → JSON value. The
/// values are **opaque data** — never interpreted as instructions or hoisted into
/// the result envelope (the structural half of the injection-via-data defense).
pub type RowJson = serde_json::Map<String, serde_json::Value>;

/// The outcome of a read through the proxy: rows, or a recoverable block.
pub enum ReadOutcome {
    /// The read returned rows (data only, never control).
    Rows {
        /// The rows, each an ordered column→value map.
        rows: Vec<RowJson>,
        /// The row count the proxy returned.
        row_count: usize,
    },
    /// The proxy/floor denied (or the connection was lost) — a recoverable block.
    Blocked(BlockContract),
}

/// The live transport to the proxy. Lazily holds at most one `tokio-postgres`
/// [`Client`]; a lost connection is dropped and re-dialed on the next read.
///
/// Cloneable + `Send`/`Sync` so a single instance backs the whole MCP server
/// across concurrent tool calls; the inner `Mutex` serializes dial/use so two
/// reads never race to create two clients.
#[derive(Clone)]
pub struct ProxyTransport {
    config: Arc<ProxyConfig>,
    /// The live client, or `None` when never-dialed / lost. Behind an async mutex
    /// so a dial and a read can't interleave into two clients.
    client: Arc<Mutex<Option<Client>>>,
}

impl ProxyTransport {
    /// Build a transport for `config`. Does NOT connect — the first read dials
    /// (lazy-connect), so constructing this never fails even if the proxy is down.
    pub fn new(config: ProxyConfig) -> Self {
        ProxyTransport {
            config: Arc::new(config),
            client: Arc::new(Mutex::new(None)),
        }
    }

    /// Dial the proxy and spawn the connection driver. The driver future is
    /// spawned so that when the backend session ends (warden terminate / restart /
    /// idle reset) its error is ABSORBED on that task — it can never propagate as
    /// an uncaught failure that crashes the process. We do not learn of the loss
    /// eagerly; the next read finds the client unusable and re-dials. Returns a
    /// recoverable [`BlockContract::proxy_unavailable`] on a dial failure.
    async fn dial(&self) -> Result<Client, BlockContract> {
        let cfg = self.config.pg_config();
        match &self.config.tls {
            TlsMode::Disabled => {
                let (client, connection) = cfg
                    .connect(NoTls)
                    .await
                    .map_err(|e| BlockContract::proxy_unavailable(&e.to_string()))?;
                // Absorb the connection future's terminal error on its own task.
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                Ok(client)
            }
            TlsMode::Rustls { roots_der } => {
                let mut roots = rustls::RootCertStore::empty();
                for der in roots_der {
                    roots
                        .add(rustls_pki_types::CertificateDer::from(der.clone()))
                        .map_err(|e| {
                            BlockContract::proxy_unavailable(&format!(
                                "bad proxy trust anchor: {e}"
                            ))
                        })?;
                }
                let tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);
                let (client, connection) = cfg
                    .connect(tls)
                    .await
                    .map_err(|e| BlockContract::proxy_unavailable(&e.to_string()))?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                Ok(client)
            }
        }
    }

    /// Run `f` against a live client, lazily dialing (and, on a dropped
    /// connection, re-dialing once) so a warden-killed / restarted backend
    /// recovers transparently. `f` returns either a value or a recoverable block.
    ///
    /// The retry contract: if the held client is unusable (the connection died),
    /// the FIRST attempt fails, we drop it and re-dial, and the SECOND attempt
    /// runs on a fresh proxy-brokered session. A persistent failure (the proxy is
    /// down) surfaces the recoverable `PROXY_UNAVAILABLE` so the caller can retry.
    async fn with_client<T, F>(&self, mut f: F) -> Result<T, BlockContract>
    where
        F: FnMut(
            &Client,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, ReadError>> + Send + '_>,
        >,
    {
        let mut guard = self.client.lock().await;

        for attempt in 0..2 {
            // Ensure we hold a (possibly fresh) client.
            if guard.is_none() {
                match self.dial().await {
                    Ok(c) => *guard = Some(c),
                    // Dial failed → recoverable; the next read re-dials.
                    Err(block) => return Err(block),
                }
            }
            // SAFETY: just ensured Some above.
            let client = guard.as_ref().expect("client present after dial");
            match f(client).await {
                Ok(v) => return Ok(v),
                Err(ReadError::ConnectionLost(detail)) => {
                    // The connection died (warden terminate / restart / reset).
                    // Drop the dead client so the next iteration re-dials. On the
                    // first attempt, retry on a fresh session; on the second,
                    // surface the recoverable loss.
                    *guard = None;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(BlockContract::proxy_unavailable(&detail));
                }
                // A genuine proxy/floor denial of the statement: surface verbatim.
                Err(ReadError::Denied(block)) => return Err(block),
            }
        }
        // Unreachable in practice (the loop returns), but fail-closed.
        Err(BlockContract::proxy_unavailable(
            "exhausted reconnect attempts",
        ))
    }

    /// Execute a (pre-classified) read through the proxy. The classifier fast-path
    /// in [`crate::server`] has already ensured this is a pure read; the proxy
    /// enforces independently. Returns rows or a recoverable block.
    pub async fn query(&self, sql: &str) -> ReadOutcome {
        let sql = sql.to_string();
        match self
            .with_client(move |client| {
                let sql = sql.clone();
                Box::pin(async move {
                    // `tokio-postgres::query` uses the EXTENDED protocol (Parse/
                    // Bind/Execute) — exactly what the proxy REQUIRES (extended-
                    // protocol-only is its statement-stacking defense). A simple-
                    // query path would be rejected by the proxy.
                    let rows = client.query(&sql, &[]).await.map_err(classify_pg_error)?;
                    let json = rows.iter().map(row_to_json).collect::<Vec<_>>();
                    let count = json.len();
                    Ok(ReadOutcome::Rows {
                        rows: json,
                        row_count: count,
                    })
                })
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(block) => ReadOutcome::Blocked(block),
        }
    }

    /// `EXPLAIN (FORMAT JSON)` of a (pre-classified) read through the proxy — the
    /// statement is PLANNED, never executed (no `ANALYZE`). The server has already
    /// gated the inner SQL exactly like `query` (reusing `pgb_pgwire::classify`),
    /// so a write/stacked statement can never reach this `EXPLAIN … ${sql}` path —
    /// the TS explain-hole stays closed. Returns the plan JSON + the top-level
    /// total cost, or a recoverable block.
    pub async fn explain(&self, inner_sql: &str) -> Result<PlanJson, BlockContract> {
        let wrapped = format!("EXPLAIN (FORMAT JSON) {inner_sql}");
        self.with_client(move |client| {
            let wrapped = wrapped.clone();
            Box::pin(async move {
                let rows = client
                    .query(&wrapped, &[])
                    .await
                    .map_err(classify_pg_error)?;
                Ok(plan_from_rows(&rows))
            })
        })
        .await
    }

    /// Read the agent-visible schema (tables/columns the proxy's role can see)
    /// from `information_schema`, through the proxy. The query is a pure read, so
    /// it traverses the proxy's read path like any other. Returns the columns or a
    /// recoverable block.
    pub async fn discover_schema(&self) -> Result<Vec<SchemaColumn>, BlockContract> {
        // A single read of information_schema.columns, excluding the system
        // catalogs — mirrors the TS `discoverSchema`. The agent only sees what its
        // role is granted (information_schema applies the role's visibility).
        const SQL: &str = "SELECT table_schema AS schema, table_name AS \"table\", \
             column_name AS \"column\", data_type AS \"type\" \
             FROM information_schema.columns \
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema') \
             ORDER BY table_schema, table_name, ordinal_position";
        self.with_client(move |client| {
            Box::pin(async move {
                let rows = client.query(SQL, &[]).await.map_err(classify_pg_error)?;
                let cols = rows
                    .iter()
                    .map(|r| SchemaColumn {
                        schema: r.get::<_, String>("schema"),
                        table: r.get::<_, String>("table"),
                        column: r.get::<_, String>("column"),
                        data_type: r.get::<_, String>("type"),
                    })
                    .collect::<Vec<_>>();
                Ok(cols)
            })
        })
        .await
    }
}

/// A discovered schema column (a row of the `discover_schema` result).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SchemaColumn {
    /// The schema name.
    pub schema: String,
    /// The table name.
    pub table: String,
    /// The column name.
    pub column: String,
    /// The column's SQL data type.
    pub data_type: String,
}

/// The `explain_plan` result: the raw plan JSON (as a string) + the top-level
/// estimated total cost.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlanJson {
    /// The `EXPLAIN (FORMAT JSON)` output, serialized back to a JSON string.
    pub plan: String,
    /// The planner's estimated top-level total cost (0.0 if unparseable).
    pub cost: f64,
}

/// Internal read-error: either the connection was lost (re-dialable) or the proxy/
/// floor denied the statement (a recoverable block to surface).
enum ReadError {
    /// The wire connection died (warden terminate / restart / reset). Re-dialable.
    ConnectionLost(String),
    /// The proxy/floor refused the statement — surface this block.
    Denied(BlockContract),
}

/// Map a `tokio-postgres` error from a read into the right [`ReadError`].
///
/// - A **connection-class** failure (08xxx, the admin/crash shutdown 57Pxx, or a
///   socket-level "connection closed") is a re-dialable [`ReadError::ConnectionLost`].
/// - A **42501** permission-denied is the proxy/WALL default-deny → `WALL_DENIED`.
/// - Anything else the backend/proxy returned (a budget cutoff surfaced as an
///   error, an EXPLAIN-gate block, a syntax/relation error, a read-only rejection)
///   becomes the generic `PROXY_BLOCKED` recoverable contract.
fn classify_pg_error(err: tokio_postgres::Error) -> ReadError {
    if let Some(db) = err.as_db_error() {
        let code = db.code().code();
        let message = db.message().to_string();
        if code == "42501" {
            return ReadError::Denied(BlockContract::wall_denied(&message));
        }
        // Connection-class SQLSTATEs the backend may send on termination.
        if code.starts_with("08") || code == "57P01" || code == "57P02" || code == "57P03" {
            return ReadError::ConnectionLost(message);
        }
        return ReadError::Denied(BlockContract::proxy_blocked(&message));
    }
    // No DB error ⇒ a transport/connection-level failure (closed socket, reset,
    // the proxy cutting the session mid-stream). Treat as a re-dialable loss.
    ReadError::ConnectionLost(err.to_string())
}

/// Parse the top-level total cost out of an `EXPLAIN (FORMAT JSON)` result and
/// re-serialize the plan JSON to a string (mirrors the TS `explain`).
fn plan_from_rows(rows: &[tokio_postgres::Row]) -> PlanJson {
    // EXPLAIN (FORMAT JSON) returns one row, one column ("QUERY PLAN") holding a
    // JSON array. `tokio-postgres` maps `json`/`jsonb` to `serde_json::Value`.
    let plan_value: serde_json::Value = rows
        .first()
        .and_then(|r| r.try_get::<_, serde_json::Value>(0).ok())
        .unwrap_or(serde_json::Value::Null);
    let cost = plan_value
        .as_array()
        .and_then(|a| a.first())
        .and_then(|top| top.get("Plan"))
        .and_then(|p| p.get("Total Cost"))
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0);
    PlanJson {
        plan: plan_value.to_string(),
        cost,
    }
}

/// Convert one `tokio-postgres` row to an ordered column→JSON map.
///
/// Each value is coerced to a JSON value by trying the common Postgres types in
/// order, with a final fallback to a stringified representation. The values are
/// opaque DATA — never interpreted as control. (A column whose value mimics a
/// contract field is just a string/JSON value under `rows`, never hoisted.)
fn row_to_json(row: &tokio_postgres::Row) -> RowJson {
    let mut map = serde_json::Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        map.insert(col.name().to_string(), column_value_to_json(row, i, col));
    }
    map
}

/// Coerce a single column value to JSON, trying common types in order.
fn column_value_to_json(
    row: &tokio_postgres::Row,
    idx: usize,
    col: &tokio_postgres::Column,
) -> serde_json::Value {
    use serde_json::Value;
    // NULL of any type comes back as `None` for the first matching type; try the
    // common ones and emit `null` when the value is SQL NULL.
    // Booleans.
    if let Ok(v) = row.try_get::<_, Option<bool>>(idx) {
        return v.map(Value::Bool).unwrap_or(Value::Null);
    }
    // Integers (widen to i64).
    if let Ok(v) = row.try_get::<_, Option<i64>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i32>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i16>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    // Floats.
    if let Ok(v) = row.try_get::<_, Option<f64>>(idx) {
        return v
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<f32>>(idx) {
        return v
            .and_then(|f| serde_json::Number::from_f64(f as f64))
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }
    // JSON / JSONB.
    if let Ok(v) = row.try_get::<_, Option<serde_json::Value>>(idx) {
        return v.unwrap_or(Value::Null);
    }
    // Text and text-like types (the broad fallback for varchar/name/etc.).
    if let Ok(v) = row.try_get::<_, Option<String>>(idx) {
        return v.map(Value::String).unwrap_or(Value::Null);
    }
    // Last resort: name the type so the value is never silently dropped. We never
    // panic on an unknown type — fail-closed to an honest placeholder.
    Value::String(format!("<unrepresentable {}>", col.type_().name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_builds_extended_protocol_config_with_app_name() {
        let cfg = ProxyConfig {
            host: "127.0.0.1".into(),
            port: 6432,
            database: "postgres".into(),
            user: "pgb_agent".into(),
            password: "pw".into(),
            application_name: DEFAULT_APP_NAME.into(),
            tls: TlsMode::Disabled,
            statement_timeout_ms: 5000,
        };
        let pg = cfg.pg_config();
        assert_eq!(pg.get_application_name(), Some(DEFAULT_APP_NAME));
        assert_eq!(pg.get_dbname(), Some("postgres"));
    }

    #[test]
    fn lazy_transport_constructs_without_connecting() {
        // Constructing a transport for a DOWN proxy must NOT fail or block — the
        // first read dials lazily, so the process never dies on a down proxy.
        let t = ProxyTransport::new(ProxyConfig {
            host: "127.0.0.1".into(),
            port: 1, // nothing listens here
            database: "postgres".into(),
            user: "pgb_agent".into(),
            password: "pw".into(),
            application_name: DEFAULT_APP_NAME.into(),
            tls: TlsMode::Disabled,
            statement_timeout_ms: 5000,
        });
        // The clone shares the same lazy state.
        let _clone = t.clone();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_against_a_down_proxy_is_a_recoverable_block_not_a_crash() {
        // Port 1: nothing listens. A read must come back as the RECOVERABLE
        // PROXY_UNAVAILABLE block — the process must NOT panic or die.
        let t = ProxyTransport::new(ProxyConfig {
            host: "127.0.0.1".into(),
            port: 1,
            database: "postgres".into(),
            user: "pgb_agent".into(),
            password: "pw".into(),
            application_name: DEFAULT_APP_NAME.into(),
            tls: TlsMode::Disabled,
            statement_timeout_ms: 1000,
        });
        match t.query("SELECT 1").await {
            ReadOutcome::Blocked(b) => {
                assert_eq!(b.code, "PROXY_UNAVAILABLE");
                assert!(b.retryable, "a down proxy is retryable (re-dial)");
            }
            ReadOutcome::Rows { .. } => panic!("a down proxy cannot return rows"),
        }
        // And explain/schema fail the same recoverable way (no crash).
        let e = t.explain("SELECT 1").await.unwrap_err();
        assert_eq!(e.code, "PROXY_UNAVAILABLE");
        let s = t.discover_schema().await.unwrap_err();
        assert_eq!(s.code, "PROXY_UNAVAILABLE");
    }

    #[test]
    fn wall_denied_maps_from_42501() {
        // A simulated 42501 path: the classifier maps permission-denied to
        // WALL_DENIED (we can't fabricate a tokio_postgres::Error cheaply, so this
        // asserts the contract constructor the classifier uses).
        let b = BlockContract::wall_denied("permission denied for table secret_data");
        assert_eq!(b.code, "WALL_DENIED");
        assert!(!b.retryable);
    }
}
