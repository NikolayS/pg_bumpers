//! `pgb-applyd` binary — the write-path daemon (issue #67, S5).
//!
//! Binds a **Unix-domain socket** (`PGB_APPLYD_SOCKET`; dir `0700`, socket
//! `0600` — NOT a TCP port, NOT agent-reachable) and serves **line-delimited
//! JSON-RPC 2.0** (one request object per line, one response object per line). It
//! owns the propose→dry_run→request_elevation→approve→apply lifecycle over the §4
//! grant-gated apply floor, with a resident PG18 `Client` for applies and the
//! shared, anchored `_meta` audit chain.
//!
//! Environment (mirrors `crates/proxy/src/main.rs`'s audit/env wiring):
//! - `PGB_APPLYD_SOCKET` — the Unix-socket path (default
//!   `/tmp/pgb-applyd/applyd.sock`). The parent dir is created `0700` and the
//!   socket chmod'd `0600` (owner-only; the agent has no reach to it).
//! - `PGB_POLICY_PATH` / `PGB_POLICY_ROLE` — the policy (clone.provider + pitr
//!   bridged onto the apply).
//! - `PGB_APPROVER_PUBKEY` — the approver's Ed25519 verifying key, hex (32 bytes).
//!   The apply-time trust root the §4 floor verifies grants against. **Required.**
//! - `PGB_BACKEND_HOST` / `PGB_BACKEND_PORT` / `PGB_BACKEND_DB` /
//!   `PGB_BACKEND_ROLE` / `PGB_BACKEND_PASSWORD` — the PRIMARY the resident apply
//!   `Client` connects to (defaults `127.0.0.1` / `54321` / `postgres` /
//!   `pgb_agent`; **never 5432**).
//! - `PGB_META_DSN` / `PGB_AUDIT_SIGNING_KEY` / `PGB_ANCHOR_PATH` /
//!   `PGB_ANCHOR_INTERVAL_MS` — the shared `_meta` audit chain (same as the proxy).
//!
//! Security note: the socket is the boundary, not the MCP server. The `apply` RPC
//! takes only `{proposal_id, confirm_rows, confirm_token}` — the service
//! re-derives the live request from its STORED proposal record (issue #67).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use postgres::{Client, NoTls};

use pgb_applyd::Service;
use pgb_applyd::protocol::{
    ApplyParams, ApproveParams, AuditRecordWire, DryRunParams, ErrorCode, GetAuditParams,
    GetAuditResult, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, JSONRPC_VERSION,
    METHOD_NOT_FOUND_CODE, Method, ProposeParams, Request, RequestElevationParams, Response,
    RpcError,
};
use pgb_audit::{
    AUDIT_SIGNING_KEY_ID, AnchorRole, AuditBoot, LocalSecretStore, SecretStore, SharedSink,
};
use pgb_cli::{ApprovalFlow, InMemoryNonceStore, RecordingWebhookSender};
use pgb_clone_orchestrator::{PgApplyConn, PgRehearsal};
use pgb_core::{Clock, NoopBarrier, SystemClock};
use pgb_policy::PolicyConfig;

type Svc = Service<RecordingWebhookSender, InMemoryNonceStore, InMemoryNonceStore>;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// A required secret/config with no default literal (fail-closed).
fn env_secret(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let v = std::env::var(key)
        .map_err(|_| format!("{key} is required and has no default (fail-closed)"))?;
    if v.is_empty() {
        return Err(format!("{key} is set but empty; refusing to start").into());
    }
    Ok(v)
}

/// Parse a hex-encoded 32-byte Ed25519 verifying key.
fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| format!("PGB_APPROVER_PUBKEY is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "PGB_APPROVER_PUBKEY must be 32 bytes (64 hex chars)")?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid Ed25519 public key: {e}").into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = env_or("PGB_APPLYD_SOCKET", "/tmp/pgb-applyd/applyd.sock");

    // Policy (clone.provider + pitr bridged onto the apply).
    let policy_path = env_or("PGB_POLICY_PATH", "crates/policy/policy.example.yaml");
    let policy = PolicyConfig::load_from_yaml(&std::fs::read_to_string(&policy_path)?)?;

    // The apply-time trust root (the approver's verifying key).
    let verifying_key = parse_pubkey(&env_secret("PGB_APPROVER_PUBKEY")?)?;

    // The shared, anchored `_meta` audit chain (mirror the proxy boot sequence).
    let meta_dsn = env_secret("PGB_META_DSN")?;
    let signing_key = env_secret("PGB_AUDIT_SIGNING_KEY")?;
    let anchor_interval_ms: u64 = env_or("PGB_ANCHOR_INTERVAL_MS", "60000").parse()?;
    let anchor_path = env_secret("PGB_ANCHOR_PATH")?;

    // S5 #76 item 3: applyd defaults to the VERIFY-ONLY anchor role over the ONE
    // shared chain — the proxy OWNS the anchor file + signing key and is the sole
    // anchorer. applyd verifies the persisted chain against the owner's durable
    // anchored head on boot (fail-closed on a mismatch) but never anchors, so there
    // is exactly one anchorer over the shared chain (no two-anchorer race).
    let anchor_role = AnchorRole::parse(
        std::env::var("PGB_ANCHOR_ROLE").ok().as_deref(),
        AnchorRole::Verify,
    )
    .map_err(|e| format!("{e} (fail-closed)"))?;

    let mut store = LocalSecretStore::new();
    store.put(AUDIT_SIGNING_KEY_ID, signing_key.as_bytes())?;
    let mut boot =
        AuditBoot::connect_with_anchor(&meta_dsn, &store, anchor_interval_ms, &anchor_path)
            .map_err(|e| format!("audit _meta boot failed (fail-closed): {e}"))?;
    let clock = SystemClock::new();
    boot.boot(anchor_role, clock.monotonic_millis())
        .map_err(|e| format!("audit startup verification failed — refusing to start: {e}"))?;
    eprintln!(
        "pgb-applyd: audit `_meta` chain verified on startup (anchor role: {anchor_role:?}, \
         anchor {anchor_path})"
    );
    let sink = SharedSink::from_arc(boot.sink_arc());

    // The resident PG18 apply Client (the primary as the WALL role; never 5432).
    let backend_dsn = format!(
        "host={} port={} dbname={} user={} password={}",
        env_or("PGB_BACKEND_HOST", "127.0.0.1"),
        env_or("PGB_BACKEND_PORT", "54321"),
        env_or("PGB_BACKEND_DB", "postgres"),
        env_or("PGB_BACKEND_ROLE", "pgb_agent"),
        env_secret("PGB_BACKEND_PASSWORD")?,
    );
    let apply_client = Client::connect(&backend_dsn, NoTls)
        .map_err(|e| format!("apply backend connect failed: {e}"))?;
    let read_client = Client::connect(&backend_dsn, NoTls)
        .map_err(|e| format!("rehearsal backend connect failed: {e}"))?;

    // The service (the FakeCore production peer).
    let flow = ApprovalFlow::new(
        sink.clone(),
        RecordingWebhookSender::new(),
        verifying_key,
        InMemoryNonceStore::new(),
    );
    let service = Service::new(flow, sink, InMemoryNonceStore::new(), verifying_key, policy);

    // Bind the Unix socket (dir 0700, socket 0600 — owner-only, NOT agent-reachable).
    let listener = bind_socket(&socket_path)?;
    eprintln!(
        "pgb-applyd: listening on unix:{socket_path} (write-path daemon; reads go through the proxy)"
    );

    // The shared state behind ONE mutex: the service (proposals/grants/nonces/
    // audit) + the two resident PG18 connections. A thread per connection serves
    // requests, taking the lock only for the duration of a single dispatch. This
    // keeps the WRITE path serialized (one apply txn at a time, under the lock)
    // while still letting a SEPARATE operator-approve connection be served
    // concurrently with an idle agent connection — without that, an idle agent
    // socket would block the accept loop and the operator could never approve.
    let shared = Arc::new(Mutex::new(SharedState {
        service,
        backends: Backends {
            apply_client,
            read_client,
        },
    }));

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve_connection(s, &shared) {
                        eprintln!("pgb-applyd: connection ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("pgb-applyd: accept failed: {e}"),
        }
    }
    Ok(())
}

/// The two resident PG18 connections (apply + rehearsal). Kept separate so the
/// rehearsal's rolled-back txn never shares the apply's committing txn.
struct Backends {
    apply_client: Client,
    read_client: Client,
}

/// All applyd state behind one mutex: the service + the resident DB connections.
struct SharedState {
    service: Svc,
    backends: Backends,
}

/// Create the socket's parent dir `0700`, remove a stale socket, bind, chmod the
/// socket `0600`.
fn bind_socket(path: &str) -> Result<UnixListener, Box<dyn std::error::Error>> {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    // Remove a stale socket from a prior run (fail-closed: refuse a non-socket).
    if p.exists() {
        let meta = fs::symlink_metadata(p)?;
        if meta.file_type().is_socket() {
            fs::remove_file(p)?;
        } else {
            return Err(format!("{path} exists and is not a socket; refusing to bind").into());
        }
    }
    let listener = UnixListener::bind(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serve one connection: read line-delimited JSON-RPC requests, dispatch each
/// (taking the shared lock per request, so a concurrent connection can interleave),
/// write one response line per request.
fn serve_connection(
    stream: UnixStream,
    shared: &Arc<Mutex<SharedState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let write_half = stream.try_clone()?;
    let reader = BufReader::new(stream);
    let mut writer = write_half;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = {
            let mut guard = shared.lock().unwrap_or_else(|poison| poison.into_inner());
            let st = &mut *guard;
            dispatch_line(&line, &mut st.service, &mut st.backends)
        };
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes())?;
        writer.flush()?;
    }
    Ok(())
}

/// Parse one JSON-RPC line, dispatch it onto the service, return the response.
fn dispatch_line(line: &str, service: &mut Svc, backends: &mut Backends) -> Response {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Response::err(
                serde_json::Value::Null,
                RpcError {
                    code: INVALID_REQUEST_CODE,
                    message: format!("malformed JSON-RPC line: {e}"),
                    data: pgb_applyd::protocol::BlockData {
                        code: "INVALID_REQUEST".into(),
                        remedy: "send one JSON-RPC 2.0 object per line".into(),
                        retryable: false,
                    },
                },
            );
        }
    };
    let id = req.id.clone();
    if req.jsonrpc != JSONRPC_VERSION {
        return Response::err(
            id,
            RpcError {
                code: INVALID_REQUEST_CODE,
                message: format!("expected jsonrpc \"2.0\", got {:?}", req.jsonrpc),
                data: pgb_applyd::protocol::BlockData {
                    code: "INVALID_REQUEST".into(),
                    remedy: "set jsonrpc to \"2.0\"".into(),
                    retryable: false,
                },
            },
        );
    }
    let Some(method) = Method::parse(&req.method) else {
        return Response::err(
            id,
            RpcError {
                code: METHOD_NOT_FOUND_CODE,
                message: format!("no such method: {}", req.method),
                data: pgb_applyd::protocol::BlockData {
                    code: "METHOD_NOT_FOUND".into(),
                    remedy: "call propose/dry_run/request_elevation/approve/apply/get_audit".into(),
                    retryable: false,
                },
            },
        );
    };
    let clock = SystemClock::new();
    let svc = service;

    macro_rules! params {
        ($t:ty) => {
            match serde_json::from_value::<$t>(req.params.clone()) {
                Ok(p) => p,
                Err(e) => return invalid_params(id, e),
            }
        };
    }

    match method {
        Method::Propose => {
            let p = params!(ProposeParams);
            to_response(
                id,
                svc.propose(&p.sql, p.expected_rows, &p.role, &p.session_id, &clock),
            )
        }
        Method::DryRun => {
            let p = params!(DryRunParams);
            let mut rehearsal = PgRehearsal::new(&mut backends.read_client, &clock);
            to_response(id, svc.dry_run(&p.proposal_id, &mut rehearsal, &clock))
        }
        Method::RequestElevation => {
            let p = params!(RequestElevationParams);
            to_response(id, svc.request_elevation(&p.proposal_id, &p.reason, &clock))
        }
        Method::Approve => {
            let p = params!(ApproveParams);
            let sk = match parse_signing_key(&p.signing_key_hex) {
                Ok(sk) => sk,
                Err(e) => {
                    return Response::err(
                        id,
                        ErrorCode::GrantRejected.error(format!("bad signing key: {e}")),
                    );
                }
            };
            to_response(
                id,
                svc.approve(
                    &p.request_id,
                    &p.approver_id,
                    &sk,
                    &p.nonce,
                    p.grant_ttl_millis,
                    &clock,
                ),
            )
        }
        Method::Apply => {
            let p = params!(ApplyParams);
            // Re-derive the forward SQL + predicate from the STORED proposal so the
            // conn applies exactly what was proposed (issue #67). The service owns
            // the statement; the conn needs the forward SQL + WHERE for the
            // recompute/pre-image. We fetch them from the service's record.
            let Some((forward_sql, where_sql)) = svc.apply_sql_for(&p.proposal_id, &clock) else {
                return to_response::<pgb_applyd::protocol::ApplyResult>(
                    id,
                    Err(ErrorCode::ProposalNotFound
                        .error("no live proposal with that id (unknown or TTL-expired)")),
                );
            };
            let mut conn = PgApplyConn::new(&mut backends.apply_client, &forward_sql, &where_sql);
            to_response(
                id,
                svc.apply(
                    &p.proposal_id,
                    p.confirm_rows,
                    p.confirm_token.as_deref(),
                    &mut conn,
                    &NoopBarrier::new(),
                    &clock,
                ),
            )
        }
        Method::GetAudit => {
            let p = params!(GetAuditParams);
            let limit = p.limit.unwrap_or(50).min(1000) as usize;
            let records = svc
                .audit_records(limit)
                .into_iter()
                .map(|r| AuditRecordWire {
                    seq: r.payload.seq,
                    decision: format!("{:?}", r.payload.decision).to_uppercase(),
                    reason_code: r.payload.reason_code,
                })
                .collect();
            Response::ok(
                id,
                serde_json::to_value(GetAuditResult { records }).unwrap_or(serde_json::Value::Null),
            )
        }
    }
}

/// Build the success/error response from a service result.
fn to_response<T: serde::Serialize>(
    id: serde_json::Value,
    result: Result<T, RpcError>,
) -> Response {
    match result {
        Ok(v) => Response::ok(
            id,
            serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
        ),
        Err(e) => Response::err(id, e),
    }
}

fn invalid_params(id: serde_json::Value, e: serde_json::Error) -> Response {
    Response::err(
        id,
        RpcError {
            code: INVALID_PARAMS_CODE,
            message: format!("invalid params: {e}"),
            data: pgb_applyd::protocol::BlockData {
                code: "INVALID_PARAMS".into(),
                remedy: "send the method's required params object".into(),
                retryable: false,
            },
        },
    )
}

/// Parse a hex-encoded 32-byte Ed25519 signing-key seed.
fn parse_signing_key(hex_str: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be 32 bytes (64 hex chars)".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}
