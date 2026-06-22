//! The per-connection FE/BE loop — where the enforcement hooks meet the wire
//! (SPEC §3 layer 2, §4, §7 S1).
//!
//! One [`serve_connection`] call drives a single agent connection end to end:
//!
//! 1. **startup + TLS negotiation** — answer the PostgreSQL `SSLRequest`, then
//!    read the `StartupMessage`;
//! 2. **client-side SCRAM-SHA-256 auth** — prove the agent before any backend
//!    work ([`crate::auth`]);
//! 3. **originate the backend** — open a fresh PG18 session as the WALL role and
//!    inject `statement_timeout` (terminate-and-originate);
//! 4. **the query loop** — read each frontend frame, run the [`Enforcement`]
//!    gate, forward allowed frames, and relay backend responses while the
//!    [`Budget`] meters **every** bulk path — `DataRow` *and* backend-COPY
//!    `CopyData` — and cuts it off at the cap (fail-closed).
//!
//! Everything fails closed: a malformed frame, a failed audit append, a budget
//! overrun, or a rejected statement all stop the offending statement (or the
//! connection) rather than letting bytes through ungated.

use std::sync::Arc;

use bytes::Bytes;
use pgb_pgwire::backend::{BackendMessage, TransactionStatus};
use pgb_pgwire::frontend::PROTOCOL_VERSION_3;
use pgb_pgwire::scram::{
    AuthenticationSasl, AuthenticationSaslContinue, AuthenticationSaslFinal, SaslInitialResponse,
    SaslResponse,
};
use pgb_pgwire::{
    read_startup_body, read_tagged_frame, write_frame, FrontendMessage, RawFrame, SslRequest,
    StartupMessage,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::{ScramServer, ScramVerifier};
use crate::budget::{Budget, BudgetOutcome};
use crate::config::{BackendTarget, ProxyConfig};
use crate::enforce::{Enforcement, GateDecision};
use crate::explain::{
    explain_wrap, EstimateDecision, ExplainCeiling, ExplainGate, EXPLAIN_FAIL_CLOSED_CODE,
};
use crate::recorder::Recorder;
use crate::window::{WindowMeter, WindowOutcome};
use pgb_core::Clock;

/// Errors the session loop can end with. Most are terminal for the connection.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A wire/IO error on the agent or backend socket.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A protocol decode/encode error from [`pgb_pgwire`].
    #[error("protocol error: {0}")]
    Protocol(#[from] pgb_pgwire::ProtocolError),
    /// SCRAM authentication of the agent failed (fail-closed).
    #[error("auth error: {0}")]
    Auth(#[from] crate::auth::ScramError),
    /// The agent sent something out of sequence during startup/auth.
    #[error("handshake error: {0}")]
    Handshake(&'static str),
    /// Appending to the audit chain failed — audit is evidence, so this is fatal.
    #[error("audit error: {0}")]
    Audit(String),
    /// The backend refused our connection / behaved unexpectedly.
    #[error("backend error: {0}")]
    Backend(String),
}

/// The agent-facing stream after optional TLS upgrade: either plaintext TCP or a
/// rustls-wrapped TCP stream. Boxed as a trait object so the query loop is
/// monomorphic over one type.
pub type AgentStream = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Marker trait combining the async read+write bounds the loop needs.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Serve one agent connection to completion.
///
/// `tls` is an optional rustls acceptor; when present the proxy answers the
/// `SSLRequest` with `S` and upgrades. `recorder` records every gate verdict on
/// the shared audit chain. The function returns when the agent disconnects or a
/// terminal error occurs; per-statement blocks/rejects do **not** end it.
pub async fn serve_connection(
    tcp: TcpStream,
    cfg: Arc<ProxyConfig>,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    recorder: Recorder,
    session_id: String,
) -> Result<(), SessionError> {
    tcp.set_nodelay(true).ok();
    let (mut stream, encrypted) = startup_and_tls(tcp, &tls, cfg.require_tls).await?;

    // (1b) Post-handshake encryption check (fail-closed): when the deployment
    // requires TLS, the session must NOT proceed to auth/queries unless the
    // stream is actually encrypted. This is the belt to the negotiation
    // suspenders — there is no path to cleartext auth when `require_tls` is on.
    if cfg.require_tls && !encrypted {
        send_fatal(
            &mut stream,
            "08P01",
            "TLS is required on the agent endpoint; \
             this connection is not encrypted — refusing (no cleartext downgrade)",
        )
        .await?;
        return Err(SessionError::Handshake(
            "require_tls: refused unencrypted session",
        ));
    }

    // Read the real StartupMessage (post-TLS).
    let body = read_startup_body(&mut stream).await?;
    let startup = StartupMessage::decode_body(body)?;
    if startup.protocol_version != PROTOCOL_VERSION_3 {
        send_fatal(&mut stream, "0A000", "unsupported protocol version").await?;
        return Err(SessionError::Handshake("unsupported protocol version"));
    }

    // (2) Authenticate the agent over SCRAM-SHA-256.
    authenticate_agent(&mut stream, &cfg).await?;

    // Auth ok → send the post-auth startup sequence to the agent.
    finish_agent_startup(&mut stream).await?;

    // (3) Originate the backend session as the WALL role.
    let mut backend = connect_backend(&cfg.backend, cfg.statement_timeout_ms).await?;

    // (4) The enforced query loop.
    query_loop(&mut stream, &mut backend, &cfg, &recorder, &session_id).await
}

/// Handle the `SSLRequest` negotiation and (when configured) upgrade to TLS.
///
/// Returns the (possibly TLS-wrapped) agent stream and a flag indicating whether
/// the stream is actually **encrypted**. The negotiation enforces the
/// `require_tls` posture (SPEC §7 S1 — agent-endpoint TLS, no silent downgrade):
///
/// - `SSLRequest` + TLS acceptor present ⇒ answer `'S'`, upgrade ⇒ `encrypted`.
/// - `SSLRequest` + no acceptor:
///   - `require_tls` ⇒ **refuse** (`'N'` then close; the caller never sees a
///     plaintext stream because TLS was promised but cannot be provided).
///   - else (dev no-TLS) ⇒ answer `'N'`, continue in plaintext (not encrypted).
/// - **direct `StartupMessage`** (no `SSLRequest`):
///   - `require_tls` ⇒ **reject** (FATAL ErrorResponse + close) — a plaintext
///     client must not be served when TLS is required.
///   - else ⇒ continue in plaintext (not encrypted).
async fn startup_and_tls(
    tcp: TcpStream,
    tls: &Option<Arc<tokio_rustls::TlsAcceptor>>,
    require_tls: bool,
) -> Result<(AgentStream, bool), SessionError> {
    let mut tcp = tcp;
    // Peek the first 8 bytes: an SSLRequest is exactly `00 00 00 08 <magic>`.
    let mut head = [0u8; 8];
    peek_exact(&mut tcp, &mut head).await?;
    let is_ssl_request = SslRequest::decode_body(Bytes::copy_from_slice(&head[4..8])).is_ok()
        && i32::from_be_bytes([head[0], head[1], head[2], head[3]]) == 8;

    if is_ssl_request {
        // Consume the 8-byte SSLRequest we peeked.
        tcp.read_exact(&mut head).await?;
        match tls {
            Some(acceptor) => {
                tcp.write_all(b"S").await?;
                tcp.flush().await?;
                let tls_stream = acceptor.accept(tcp).await?;
                Ok((Box::new(tls_stream), true))
            }
            None if require_tls => {
                // TLS is required but no acceptor is configured: refuse rather
                // than fall back to cleartext (fail-closed — should be caught at
                // startup by validate_tls, but never downgrade here either).
                tcp.write_all(b"N").await?;
                tcp.flush().await?;
                Err(SessionError::Handshake(
                    "require_tls: no TLS acceptor configured; refusing plaintext",
                ))
            }
            None => {
                // Explicit dev no-TLS mode → tell the client plaintext, continue.
                tcp.write_all(b"N").await?;
                tcp.flush().await?;
                Ok((Box::new(tcp), false))
            }
        }
    } else if require_tls {
        // Direct StartupMessage (no SSLRequest) while TLS is required: a
        // plaintext client must NOT be served. Emit a FATAL ErrorResponse and
        // close (no cleartext auth, no query loop).
        send_fatal(
            &mut tcp,
            "08P01",
            "TLS is required on the agent endpoint; \
             connect with sslmode=require (a direct cleartext StartupMessage is refused)",
        )
        .await?;
        tcp.flush().await?;
        Err(SessionError::Handshake(
            "require_tls: rejected direct plaintext StartupMessage",
        ))
    } else {
        // Explicit dev no-TLS mode: direct StartupMessage, plaintext.
        Ok((Box::new(tcp), false))
    }
}

/// Peek `buf.len()` bytes without consuming them.
async fn peek_exact(tcp: &mut TcpStream, buf: &mut [u8]) -> Result<(), SessionError> {
    loop {
        let n = tcp.peek(buf).await?;
        if n >= buf.len() {
            return Ok(());
        }
        if n == 0 {
            return Err(SessionError::Handshake("connection closed during startup"));
        }
        // Brief yield so the kernel buffers more; bounded by the OS — the peer
        // either sends the rest of the 8-byte header or we error out.
        tokio::task::yield_now().await;
    }
}

/// Run the SCRAM-SHA-256 server handshake against the agent (SPEC §7 S1).
async fn authenticate_agent<S>(stream: &mut S, cfg: &ProxyConfig) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Offer SCRAM-SHA-256.
    let offer = BackendMessage::AuthenticationSasl(AuthenticationSasl {
        mechanisms: vec!["SCRAM-SHA-256".to_string()],
    });
    write_frame(stream, &offer.encode()).await?;

    // client-first: a 'p' SASLInitialResponse.
    let frame = read_tagged_frame(stream)
        .await?
        .ok_or(SessionError::Handshake("eof before SASLInitialResponse"))?;
    if frame.tag != b'p' {
        return Err(SessionError::Handshake("expected SASLInitialResponse 'p'"));
    }
    let mut body = frame.body;
    let initial = SaslInitialResponse::decode_body_from(&mut body)?;
    if initial.mechanism != "SCRAM-SHA-256" {
        send_fatal(stream, "28000", "unsupported SASL mechanism").await?;
        return Err(SessionError::Auth(
            crate::auth::ScramError::UnsupportedMechanism,
        ));
    }
    let client_first = initial
        .initial_response
        .ok_or(SessionError::Handshake("empty SASL initial response"))?;
    let client_first = std::str::from_utf8(&client_first)
        .map_err(|_| SessionError::Handshake("non-utf8 client-first"))?;

    // Derive a verifier from the configured agent password and challenge.
    let verifier = ScramVerifier::from_password(&cfg.agent_password);
    let mut server = ScramServer::new(verifier);
    let server_first = server.handle_client_first(client_first)?;
    let cont = BackendMessage::AuthenticationSaslContinue(AuthenticationSaslContinue {
        data: Bytes::from(server_first.message.into_bytes()),
    });
    write_frame(stream, &cont.encode()).await?;

    // client-final: a 'p' SASLResponse.
    let frame = read_tagged_frame(stream)
        .await?
        .ok_or(SessionError::Handshake("eof before SASLResponse"))?;
    if frame.tag != b'p' {
        return Err(SessionError::Handshake("expected SASLResponse 'p'"));
    }
    let mut body = frame.body;
    let response = SaslResponse::decode_body_from(&mut body)?;
    let client_final = std::str::from_utf8(&response.data)
        .map_err(|_| SessionError::Handshake("non-utf8 client-final"))?;

    // Verify the proof — fail-closed on a bad password.
    let server_final = match server.handle_client_final(client_final) {
        Ok(f) => f,
        Err(e) => {
            send_fatal(stream, "28P01", "password authentication failed").await?;
            return Err(SessionError::Auth(e));
        }
    };
    let final_msg = BackendMessage::AuthenticationSaslFinal(AuthenticationSaslFinal {
        data: Bytes::from(server_final.message.into_bytes()),
    });
    write_frame(stream, &final_msg.encode()).await?;
    Ok(())
}

/// Send the post-auth startup tail to the agent: `AuthenticationOk`, a couple of
/// `ParameterStatus` messages, a `BackendKeyData`, and `ReadyForQuery`.
async fn finish_agent_startup<S>(stream: &mut S) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &BackendMessage::AuthenticationOk.encode()).await?;
    for (name, value) in [
        ("server_version", "18.0 (pg_bumpers proxy)"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("standard_conforming_strings", "on"),
    ] {
        let ps = BackendMessage::ParameterStatus {
            name: name.to_string(),
            value: value.to_string(),
        };
        write_frame(stream, &ps.encode()).await?;
    }
    write_frame(
        stream,
        &BackendMessage::BackendKeyData {
            process_id: 0,
            secret_key: 0,
        }
        .encode(),
    )
    .await?;
    write_frame(
        stream,
        &BackendMessage::ReadyForQuery {
            status: TransactionStatus::Idle,
        }
        .encode(),
    )
    .await?;
    Ok(())
}

/// A backend (proxy→PG18) connection as the WALL role.
struct Backend {
    stream: TcpStream,
}

/// Open the backend session as the WALL role and inject `statement_timeout`.
///
/// The local-stack primary trusts local connections (auth is `trust` for the
/// boundary's loopback), so the proxy sends a `StartupMessage` and expects
/// `AuthenticationOk`. (Terminate-and-originate: the agent's SCRAM proof gates
/// reaching this point; the backend trusts the network boundary — SPEC §3
/// layer 0. TLS to the backend is out of MVP scope and noted in the PR.)
async fn connect_backend(
    target: &BackendTarget,
    statement_timeout_ms: u64,
) -> Result<Backend, SessionError> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    stream.set_nodelay(true).ok();

    let startup = StartupMessage {
        protocol_version: PROTOCOL_VERSION_3,
        parameters: vec![
            ("user".to_string(), target.role.clone()),
            ("database".to_string(), target.database.clone()),
            ("application_name".to_string(), "pgb_proxy".to_string()),
        ],
    };
    write_frame(&mut stream, &startup.encode()).await?;

    // Drive auth to AuthenticationOk, then to the first ReadyForQuery.
    wait_for_ready(&mut stream, target).await?;

    // (4) Timeout injection — set statement_timeout on the backend session.
    if statement_timeout_ms > 0 {
        inject_statement_timeout(&mut stream, statement_timeout_ms).await?;
    }
    Ok(Backend { stream })
}

/// Consume backend startup messages until the first `ReadyForQuery`. Handles the
/// trust/cleartext/MD5 auth replies the local-stack might send; SCRAM to the
/// backend is not required on the loopback boundary.
async fn wait_for_ready(
    stream: &mut TcpStream,
    target: &BackendTarget,
) -> Result<(), SessionError> {
    loop {
        let frame = read_tagged_frame(stream)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed during startup".into()))?;
        let msg = BackendMessage::decode(frame.tag, frame.body)?;
        match msg {
            BackendMessage::AuthenticationOk => {}
            BackendMessage::AuthenticationCleartextPassword => {
                let pw = FrontendMessage::PasswordMessage {
                    password: target.password.clone(),
                };
                write_frame(stream, &pw.encode()).await?;
            }
            BackendMessage::AuthenticationMd5Password { .. }
            | BackendMessage::AuthenticationSasl(_) => {
                return Err(SessionError::Backend(
                    "backend requires md5/scram auth; the local-stack boundary uses \
                     trust on loopback (MVP). Configure trust or extend backend auth."
                        .into(),
                ));
            }
            BackendMessage::ErrorResponse { fields } => {
                return Err(SessionError::Backend(format!(
                    "backend rejected startup: {}",
                    diag(&fields)
                )));
            }
            BackendMessage::ReadyForQuery { .. } => return Ok(()),
            // ParameterStatus / BackendKeyData / NoticeResponse: ignore.
            _ => {}
        }
    }
}

/// Inject `statement_timeout` via an extended-protocol round-trip on the backend
/// (Parse/Bind/Execute/Sync), draining to `ReadyForQuery`.
async fn inject_statement_timeout(
    stream: &mut TcpStream,
    timeout_ms: u64,
) -> Result<(), SessionError> {
    // A parameterless SET via the extended protocol (we force extended for
    // ourselves too — no simple query path anywhere).
    let sql = format!("SET statement_timeout = {timeout_ms}");
    send_extended_unit(stream, &sql).await?;
    drain_to_ready(stream).await
}

/// Send a single statement through the backend via Parse/Bind/Describe-less/
/// Execute/Sync (unnamed statement + portal).
async fn send_extended_unit(stream: &mut TcpStream, sql: &str) -> Result<(), SessionError> {
    let parse = FrontendMessage::Parse {
        statement: String::new(),
        sql: sql.to_string(),
        param_types: vec![],
    };
    // Bind body: 0 param-format-codes, 0 params, 0 result-format-codes.
    let bind = FrontendMessage::Bind {
        portal: String::new(),
        statement: String::new(),
        rest: Bytes::from_static(&[0, 0, 0, 0, 0, 0]),
    };
    let execute = FrontendMessage::Execute {
        portal: String::new(),
        max_rows: 0,
    };
    write_frame(stream, &parse.encode()).await?;
    write_frame(stream, &bind.encode()).await?;
    write_frame(stream, &execute.encode()).await?;
    write_frame(stream, &FrontendMessage::Sync.encode()).await?;
    Ok(())
}

/// Drain backend frames until `ReadyForQuery`, returning an error if the backend
/// reported one.
async fn drain_to_ready(stream: &mut TcpStream) -> Result<(), SessionError> {
    loop {
        let frame = read_tagged_frame(stream)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed mid-command".into()))?;
        let msg = BackendMessage::decode(frame.tag, frame.body)?;
        if let BackendMessage::ErrorResponse { fields } = &msg {
            return Err(SessionError::Backend(format!(
                "backend error: {}",
                diag(fields)
            )));
        }
        if matches!(msg, BackendMessage::ReadyForQuery { .. }) {
            return Ok(());
        }
    }
}

/// Run an advisory `EXPLAIN` (no `ANALYZE`) of `sql` on the **backend** session
/// and return the top plan line's text — the pre-flight EXPLAIN-cost gate's input
/// (SPEC §3 EXPLAIN-cost gate). This is a self-contained extended-protocol unit
/// (Parse/Bind/Execute/Sync on the unnamed statement+portal) that the proxy runs
/// on the otherwise-idle backend connection *before* it forwards the agent's real
/// statement, draining the response to `ReadyForQuery`.
///
/// Returns:
/// - `Ok(Some(line))` — the first plan-line `DataRow`'s single text column;
/// - `Ok(None)` — EXPLAIN ran but produced no plan row (treated as fail-closed by
///   the caller, since we cannot prove the read is under the ceiling);
/// - `Err(reason)` — EXPLAIN itself errored (the SQL doesn't plan, a permission
///   error, …). The caller fails **closed** on this.
///
/// `EXPLAIN` does not execute the statement, so this is safe to run as a
/// pre-flight probe; `statement_timeout` (already injected on the backend) also
/// bounds a pathological planning time.
async fn run_explain_on_backend(
    backend: &mut TcpStream,
    sql: &str,
) -> Result<Result<Option<String>, String>, SessionError> {
    send_extended_unit(backend, &explain_wrap(sql)).await?;

    let mut first_line: Option<String> = None;
    let mut explain_error: Option<String> = None;
    loop {
        let frame = read_tagged_frame(backend)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed during EXPLAIN".into()))?;
        match frame.tag {
            // DataRow: the first column of the first row is the top plan line.
            b'D' if first_line.is_none() && explain_error.is_none() => {
                if let Ok(BackendMessage::DataRow { columns }) =
                    BackendMessage::decode(b'D', frame.body.clone())
                {
                    if let Some(Some(bytes)) = columns.into_iter().next() {
                        first_line = Some(String::from_utf8_lossy(&bytes).into_owned());
                    }
                }
            }
            // An ErrorResponse means EXPLAIN failed → fail-closed for the caller.
            b'E' => {
                if let Ok(BackendMessage::ErrorResponse { fields }) =
                    BackendMessage::decode(b'E', frame.body.clone())
                {
                    explain_error = Some(diag(&fields));
                }
            }
            // ReadyForQuery terminates the EXPLAIN unit.
            b'Z' => break,
            // Everything else (ParseComplete/BindComplete/RowDescription/
            // CommandComplete/remaining plan rows/NoticeResponse) is drained.
            _ => {}
        }
    }

    if let Some(err) = explain_error {
        return Ok(Err(err));
    }
    Ok(Ok(first_line))
}

/// The advisory EXPLAIN-cost pre-flight for one read (SPEC §3 EXPLAIN-cost gate).
///
/// Runs `EXPLAIN <sql>` on the backend, applies the role's [`ExplainGate`], and:
/// - **within ceiling** → `Ok(None)`: the read may proceed (the caller forwards
///   the real Parse and continues);
/// - **over ceiling / fail-closed** → `Ok(Some(PendingError))`: the read is
///   blocked *before* execution; the caller defers the error to the next `Sync`
///   (so the agent's already-pipelined Bind/Execute frames are discarded, exactly
///   like a read-only block) and the block is audited.
///
/// Fail-closed: an EXPLAIN error, an empty plan, or an unparseable estimate all
/// block. The gate is advisory (planner misestimation can defeat it) — the
/// un-foolable backstops are `statement_timeout` + the byte/row cutoff + the
/// per-window budget + the warden.
async fn explain_preflight(
    gate: &ExplainGate,
    backend: &mut TcpStream,
    recorder: &Recorder,
    session_id: &str,
    sql: &str,
) -> Result<Option<PendingError>, SessionError> {
    let decision = match run_explain_on_backend(backend, sql).await? {
        // EXPLAIN errored on the backend → fail closed.
        Err(reason) => EstimateDecision::FailClosed(format!(
            "EXPLAIN failed on the backend (fail-closed): {reason}"
        )),
        // EXPLAIN produced no plan row → fail closed (cannot prove under ceiling).
        Ok(None) => {
            EstimateDecision::FailClosed("EXPLAIN returned no plan row (fail-closed)".to_string())
        }
        Ok(Some(line)) => gate.decide_plan_line(&line),
    };

    match decision {
        EstimateDecision::Within(_) => Ok(None),
        EstimateDecision::Exceeded { dim, estimate } => {
            let message = format!(
                "read blocked before execution by the EXPLAIN-cost gate: estimated \
                 {} (cost={:.2}, rows={}) exceeds the role ceiling (cost={:.2}, \
                 rows={}) — advisory pre-flight gate",
                match dim {
                    crate::explain::EstimateDim::Cost => "plan cost",
                    crate::explain::EstimateDim::Rows => "row count",
                },
                estimate.total_cost,
                estimate.rows,
                gate.ceiling().max_cost,
                gate.ceiling().max_rows,
            );
            recorder
                .block(session_id, sql, dim.code(), Some(message.clone()))
                .map_err(SessionError::Audit)?;
            Ok(Some(PendingError {
                code: "53400",
                message,
            }))
        }
        EstimateDecision::FailClosed(reason) => {
            recorder
                .block(
                    session_id,
                    sql,
                    EXPLAIN_FAIL_CLOSED_CODE,
                    Some(reason.clone()),
                )
                .map_err(SessionError::Audit)?;
            Ok(Some(PendingError {
                code: "42501",
                message: reason,
            }))
        }
    }
}

/// A deferred error for extended-protocol error recovery: when the proxy blocks
/// or rejects a frame mid-pipeline, it must (like PostgreSQL) **discard every
/// following frontend message until the next `Sync`**, then report the error and
/// a single `ReadyForQuery`. This carries the error to emit at that `Sync`.
struct PendingError {
    code: &'static str,
    message: String,
}

/// The enforced FE/BE query loop.
///
/// Implements PostgreSQL's extended-protocol error semantics: a blocked/rejected
/// `Parse` (or a malformed/`Copy*`/`Query` frame) puts the loop into a
/// **skip-until-Sync** state so the client's already-pipelined `Bind`/`Describe`/
/// `Execute` frames for that statement are discarded — never forwarded to the
/// backend out of context — and exactly one `ErrorResponse` + `ReadyForQuery`
/// is returned at the `Sync`. This keeps the FE/BE streams in lock-step so the
/// session survives every recoverable block.
async fn query_loop<S>(
    agent: &mut S,
    backend: &mut Backend,
    cfg: &ProxyConfig,
    recorder: &Recorder,
    session_id: &str,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gate = Enforcement::new();
    // The advisory EXPLAIN-cost gate for this connection's role ceiling, and the
    // cumulative per-window volume meter (anti slow-drip), both driven by the
    // injected clock so the window boundary is deterministic.
    let explain_gate = ExplainGate::new(ExplainCeiling::for_role(&cfg.budget));
    let mut window = WindowMeter::for_window(&cfg.budget.per_window);
    let clock = recorder.clock();
    // When `Some`, we are skipping frames until the next Sync, then will emit it.
    let mut pending: Option<PendingError> = None;

    loop {
        let frame = match read_tagged_frame(agent).await? {
            Some(f) => f,
            None => return Ok(()), // clean disconnect between messages
        };

        // Decode for the gate. A malformed frame fails closed: skip-until-Sync.
        let msg = match FrontendMessage::decode(frame.tag, frame.body.clone()) {
            Ok(m) => m,
            Err(e) => {
                if pending.is_none() {
                    recorder
                        .reject(
                            session_id,
                            "<undecodable frame>",
                            "malformed_frame",
                            Some(e.to_string()),
                        )
                        .map_err(SessionError::Audit)?;
                    pending = Some(PendingError {
                        code: "08P01",
                        message: "malformed protocol frame".to_string(),
                    });
                }
                continue;
            }
        };

        if matches!(msg, FrontendMessage::Terminate) {
            return Ok(());
        }

        // In skip mode, swallow everything until a Sync flushes the deferred error.
        if let Some(err) = &pending {
            if matches!(msg, FrontendMessage::Sync) {
                send_error_then_ready(agent, err.code, &err.message).await?;
                pending = None;
            }
            // (Flush during skip is ignored; nothing is produced until Sync.)
            continue;
        }

        match gate.gate(&msg) {
            GateDecision::Allow { sql } => {
                if let Some(sql) = sql {
                    // (3) EXPLAIN-cost gate (advisory, fail-closed): a read frame
                    // carries SQL — run EXPLAIN on the backend BEFORE forwarding
                    // the real Parse, and block pre-flight if the estimate breaks
                    // the role ceiling (or if EXPLAIN itself fails → fail-closed).
                    if let Some(pe) = explain_preflight(
                        &explain_gate,
                        &mut backend.stream,
                        recorder,
                        session_id,
                        &sql,
                    )
                    .await?
                    {
                        pending = Some(pe);
                        continue;
                    }
                    recorder
                        .allow(session_id, &sql)
                        .map_err(SessionError::Audit)?;
                }
                // Forward the original frame bytes verbatim to the backend.
                forward_frame(&mut backend.stream, &frame).await?;
                // A Sync flushes the pipeline: relay the backend response(s) to
                // the agent under the single-shot byte/row budget AND the
                // cumulative per-window volume budget (anti slow-drip).
                if matches!(msg, FrontendMessage::Sync) {
                    relay_until_ready(
                        agent,
                        &mut backend.stream,
                        cfg,
                        recorder,
                        session_id,
                        &mut window,
                        clock.as_ref(),
                    )
                    .await?;
                }
            }
            GateDecision::Block { sql, code, message } => {
                recorder
                    .block(session_id, &sql, code, Some(message.clone()))
                    .map_err(SessionError::Audit)?;
                // Defer the error to the next Sync (extended-protocol recovery).
                pending = Some(PendingError {
                    code: "42501",
                    message,
                });
            }
            GateDecision::Reject { code, message, .. } => {
                let stmt = match &msg {
                    FrontendMessage::Query { sql } => sql.clone(),
                    _ => format!("<{} frame>", frame.tag as char),
                };
                recorder
                    .reject(session_id, &stmt, code, Some(message.clone()))
                    .map_err(SessionError::Audit)?;
                match &msg {
                    // A simple `Query` ('Q') is a complete message: respond with
                    // the error + ReadyForQuery immediately (no Sync follows it).
                    FrontendMessage::Query { .. } => {
                        send_error_then_ready(agent, "0A000", &message).await?;
                    }
                    // A `Copy*` frame inside the extended flow: skip-until-Sync.
                    _ => {
                        pending = Some(PendingError {
                            code: "0A000",
                            message,
                        });
                    }
                }
            }
        }
    }
}

/// Build the human-readable cutoff message + machine code for an exceeded
/// budget, given the breaching stream's pre-row totals.
fn cutoff_message(cap: crate::budget::Cap, bytes: u64, rows: u64) -> String {
    format!(
        "result cut off at the {} budget after {} rows / {} bytes \
         (single-shot cap exceeded)",
        match cap {
            crate::budget::Cap::Bytes => "byte",
            crate::budget::Cap::Rows => "row",
        },
        rows,
        bytes
    )
}

/// Build the cutoff message for an exceeded **cumulative per-window** budget
/// (anti slow-drip), given the pre-charge cumulative totals.
fn window_cutoff_message(cap: crate::window::WindowCap, bytes: u64, rows: u64) -> String {
    format!(
        "result stream cut off at the cumulative per-window {} budget after \
         {} rows / {} bytes streamed in the window (slow-drip volume limit)",
        match cap {
            crate::window::WindowCap::Bytes => "byte",
            crate::window::WindowCap::Rows => "row",
        },
        rows,
        bytes
    )
}

/// Relay backend frames to the agent until `ReadyForQuery`, applying the
/// per-statement byte/row cutoff. **Both** `DataRow` ('D') and backend-COPY
/// `CopyData` ('d') payloads are metered against the same per-role budget — the
/// byte-cutoff is the un-foolable §4 guarantee and must hold on **every** bulk
/// path, not just the `DataRow` path (a classifier-mis-allowed `COPY … TO
/// STDOUT`, or a misbehaving backend, must not be able to stream bytes outside
/// the budget). On a cutoff we stop forwarding, emit an `ErrorResponse` to the
/// agent, record the block, and fail-closed (tearing down a backend COPY rather
/// than proxying it unmetered).
#[allow(clippy::too_many_arguments)]
async fn relay_until_ready<S>(
    agent: &mut S,
    backend: &mut TcpStream,
    cfg: &ProxyConfig,
    recorder: &Recorder,
    session_id: &str,
    window: &mut WindowMeter,
    clock: &dyn Clock,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut budget = Budget::for_role(&cfg.budget);
    let mut cut_off = false;
    // Whether the backend has begun a COPY-out stream ('H'/'G'/'W'). In copy
    // mode the 'd' CopyData payloads are metered exactly like DataRows, and a
    // cutoff fails the whole session closed (a COPY-out cannot be cleanly
    // cancelled mid-stream from the FE without a side-channel CancelRequest).
    let mut in_copy = false;

    loop {
        let frame = read_tagged_frame(backend)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed mid-result".into()))?;

        // Detect a backend-initiated COPY-out start ('H'/'G'/'W'). The proxy
        // never legitimately drives COPY for an agent, but the byte-cutoff must
        // still hold on this path, so we enter metered copy mode rather than
        // forwarding the bulk stream verbatim.
        if pgb_pgwire::backend_starts_copy(&frame) {
            in_copy = true;
            // Forward the CopyOutResponse header so the agent's protocol state
            // tracks; the 'd' payloads that follow are what we meter.
            if !cut_off {
                forward_frame(agent, &frame).await?;
            }
            continue;
        }

        match frame.tag {
            // ReadyForQuery — the terminator. After a cutoff we already sent an
            // ErrorResponse, so forward Z to re-sync the agent and finish.
            b'Z' => {
                forward_frame(agent, &frame).await?;
                return Ok(());
            }
            // CopyDone ('c') from the backend ends the copy stream.
            b'c' if in_copy => {
                in_copy = false;
                if !cut_off {
                    forward_frame(agent, &frame).await?;
                }
            }
            // DataRow ('D') and backend CopyData ('d') are BOTH metered against
            // the same budgets. Before a cutoff, charge the payload bytes as one
            // "row" against (a) the single-shot per-statement budget and (b) the
            // cumulative per-window volume budget (anti slow-drip). Once cut off,
            // the remaining payloads are suppressed.
            b'D' | b'd' if !cut_off => {
                let row_bytes = frame.body.len() as u64;
                // (a) Single-shot per-statement cutoff.
                match budget.charge_row(row_bytes) {
                    BudgetOutcome::Within { .. } => {}
                    BudgetOutcome::Exceeded { cap, bytes, rows } => {
                        cut_off = true;
                        let message = cutoff_message(cap, bytes, rows);
                        recorder
                            .block(
                                session_id,
                                "<result stream>",
                                cap.code(),
                                Some(message.clone()),
                            )
                            .map_err(SessionError::Audit)?;
                        // Tell the agent the stream was cut.
                        write_frame(agent, &error_response("53400", &message).encode()).await?;
                        // On a metered COPY-out the only safe cutoff is to fail
                        // the session closed: tear the backend down so the bulk
                        // stream cannot continue draining the DB unmetered.
                        if in_copy {
                            backend.shutdown().await.ok();
                            return Err(SessionError::Backend(format!(
                                "backend COPY-out cut off at the budget: {message}"
                            )));
                        }
                        continue;
                    }
                }
                // (b) Cumulative per-window volume budget (slow-drip kill). The
                // row is within the single-shot budget; now charge it against the
                // rolling window. A breach KILLS the session (fail-closed): the
                // bounded-disclosure guarantee is "≤ B leaked, then stopped".
                match window.charge(row_bytes, 1, clock) {
                    WindowOutcome::Within { .. } => forward_frame(agent, &frame).await?,
                    WindowOutcome::Exceeded { cap, bytes, rows } => {
                        let message = window_cutoff_message(cap, bytes, rows);
                        recorder
                            .block(
                                session_id,
                                "<result stream>",
                                cap.code(),
                                Some(message.clone()),
                            )
                            .map_err(SessionError::Audit)?;
                        // The breaching row is NOT forwarded; tell the agent and
                        // fail the session closed (the cumulative budget kill).
                        write_frame(agent, &error_response("53400", &message).encode()).await?;
                        backend.shutdown().await.ok();
                        return Err(SessionError::Backend(format!(
                            "cumulative per-window volume budget exceeded — session \
                             killed (anti slow-drip): {message}"
                        )));
                    }
                }
            }
            // Suppressed after a cutoff: remaining DataRows/CopyData + the
            // now-redundant CommandComplete (we already emitted our error).
            b'D' | b'd' | b'C' if cut_off => {}
            // Everything else (RowDescription, ParseComplete, BindComplete,
            // CommandComplete pre-cutoff, NoticeResponse, ErrorResponse, …)
            // passes through verbatim.
            _ => forward_frame(agent, &frame).await?,
        }
    }
}

/// Forward a raw frame verbatim by re-encoding tag + length + body.
async fn forward_frame<W>(out: &mut W, frame: &RawFrame) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = bytes::BytesMut::with_capacity(5 + frame.body.len());
    use bytes::BufMut;
    buf.put_u8(frame.tag);
    buf.put_i32((4 + frame.body.len()) as i32);
    buf.put_slice(&frame.body);
    write_frame(out, &buf).await?;
    Ok(())
}

/// Build an `ErrorResponse` with severity/code/message fields.
fn error_response(code: &str, message: &str) -> BackendMessage {
    BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "ERROR".to_string()),
            (b'V', "ERROR".to_string()),
            (b'C', code.to_string()),
            (b'M', message.to_string()),
        ],
    }
}

/// Send an `ErrorResponse` followed by a `ReadyForQuery(Idle)` so the agent can
/// continue issuing statements after a recoverable block/reject.
async fn send_error_then_ready<S>(
    stream: &mut S,
    code: &str,
    message: &str,
) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &error_response(code, message).encode()).await?;
    write_frame(
        stream,
        &BackendMessage::ReadyForQuery {
            status: TransactionStatus::Idle,
        }
        .encode(),
    )
    .await?;
    Ok(())
}

/// Send a fatal `ErrorResponse` (no `ReadyForQuery`) — used during startup/auth.
async fn send_fatal<S>(stream: &mut S, code: &str, message: &str) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    let err = BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "FATAL".to_string()),
            (b'V', "FATAL".to_string()),
            (b'C', code.to_string()),
            (b'M', message.to_string()),
        ],
    };
    write_frame(stream, &err.encode()).await?;
    Ok(())
}

/// Render diagnostic fields into a `message (code)` string for logs/errors.
fn diag(fields: &[(u8, String)]) -> String {
    let msg = fields
        .iter()
        .find(|(c, _)| *c == b'M')
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    let code = fields
        .iter()
        .find(|(c, _)| *c == b'C')
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    format!("{msg} ({code})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_audit::{Decision, InMemorySink, Sink};
    use pgb_core::{Clock, MockClock};
    use pgb_policy::{RoleBudget, WindowBudget};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn tiny_budget_cfg(max_bytes: u64, max_rows: u64) -> ProxyConfig {
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            require_tls: false,
            backend: BackendTarget {
                host: "127.0.0.1".into(),
                port: 54321,
                database: "postgres".into(),
                role: "pgb_agent".into(),
                password: "x".into(),
            },
            agent_user: "pgb_agent".into(),
            agent_password: "x".into(),
            policy_role: "analytics".into(),
            budget: RoleBudget {
                max_bytes,
                max_rows,
                max_plan_cost: RoleBudget::DEFAULT_MAX_PLAN_COST,
                max_plan_rows: RoleBudget::DEFAULT_MAX_PLAN_ROWS,
                per_window: WindowBudget {
                    window_secs: 60,
                    max_bytes: max_bytes * 100,
                    max_rows: max_rows * 100,
                },
            },
            statement_timeout_ms: 30_000,
        }
    }

    fn recorder() -> (Recorder, Arc<Mutex<InMemorySink>>) {
        let inner = Arc::new(Mutex::new(InMemorySink::new()));
        let as_trait: Arc<Mutex<dyn Sink + Send>> = inner.clone();
        let clock: Arc<dyn Clock> = Arc::new(MockClock::starting_at(1_700_000_000_000));
        (Recorder::new(as_trait, clock, "pgb_agent"), inner)
    }

    /// Drive `relay_until_ready` against a simulated backend that produces a
    /// COPY-out stream (CopyOutResponse + oversized CopyData) — no live PG
    /// needed. Proves the un-foolable byte-cutoff holds on the COPY message path:
    /// the `CopyData` payload bytes ARE metered, the stream is cut at ≤ B, an
    /// ErrorResponse reaches the agent, the cutoff is audited, and the session
    /// fails closed (the backend COPY is torn down, not proxied unmetered).
    #[tokio::test]
    async fn copy_out_copydata_is_metered_and_cut_at_budget() {
        // Budget: 50 bytes / 1000 rows. The single CopyData payload (100 bytes)
        // exceeds the BYTE cap → must be cut before forwarding.
        let cfg = tiny_budget_cfg(50, 1000);
        let (rec, sink) = recorder();

        // A loopback "backend": it accepts one connection and writes the
        // COPY-out frames the proxy must meter.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // CopyOutResponse ('H') — starts the copy.
            let h = BackendMessage::CopyOutResponse {
                format: 0,
                column_formats: vec![],
            };
            write_frame(&mut s, &h.encode()).await.unwrap();
            // CopyData ('d') with a 100-byte payload — over the 50-byte budget.
            let d = BackendMessage::CopyData {
                data: Bytes::from(vec![b'Z'; 100]),
            };
            write_frame(&mut s, &d.encode()).await.unwrap();
            // The backend would keep streaming; we let the proxy tear us down.
            // Read until the proxy shuts the connection (cutoff fail-closed).
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
        });

        let mut backend = TcpStream::connect(backend_addr).await.unwrap();
        backend.set_nodelay(true).ok();

        // The agent side: an in-memory duplex stream we can read back.
        let (agent_proxy_side, mut agent_client_side) = tokio::io::duplex(64 * 1024);

        let mut agent = agent_proxy_side;
        let mut window = WindowMeter::for_window(&cfg.budget.per_window);
        let clock = MockClock::starting_at(0);
        let result = relay_until_ready(
            &mut agent,
            &mut backend,
            &cfg,
            &rec,
            "copy-test",
            &mut window,
            &clock,
        )
        .await;

        // The session fails closed on the metered-COPY cutoff.
        let err = result.expect_err("metered COPY-out cutoff must fail the session closed");
        assert!(
            matches!(err, SessionError::Backend(ref m) if m.contains("COPY-out cut off")),
            "expected a fail-closed Backend cutoff error, got {err:?}"
        );

        // The agent received the CopyOutResponse header then a cutoff
        // ErrorResponse (53400) — NOT the 100-byte payload.
        drop(agent);
        let mut received = Vec::new();
        agent_client_side.read_to_end(&mut received).await.unwrap();
        // The 'H' header is forwarded; the oversized 'd' payload is not.
        assert!(received.contains(&b'H'), "CopyOutResponse header forwarded");
        assert!(
            !received.windows(4).any(|w| w == b"ZZZZ"),
            "the over-budget CopyData payload must NOT have been forwarded"
        );
        // The cutoff ErrorResponse code 53400 is present.
        assert!(
            String::from_utf8_lossy(&received).contains("53400"),
            "cutoff ErrorResponse (53400) must reach the agent"
        );
        assert!(
            String::from_utf8_lossy(&received).contains("cut off"),
            "cutoff message must reach the agent"
        );

        // The cutoff was audited as a BLOCK against the byte budget.
        let chain = sink.lock().unwrap().chain().records().to_vec();
        assert_eq!(chain.len(), 1, "exactly one block record for the cutoff");
        assert_eq!(chain[0].payload.decision, Decision::Block);
        assert_eq!(chain[0].payload.reason_code, "byte_budget_exceeded");

        server.await.unwrap();
    }

    /// Companion to the integration cutoff: a `CopyData` payload that FITS the
    /// budget is metered (charged) and forwarded, proving the metering is on the
    /// 'd' path, not a blanket refusal.
    #[tokio::test]
    async fn copy_out_copydata_within_budget_is_forwarded() {
        let cfg = tiny_budget_cfg(1_000, 1_000);
        let (rec, _sink) = recorder();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let h = BackendMessage::CopyOutResponse {
                format: 0,
                column_formats: vec![],
            };
            write_frame(&mut s, &h.encode()).await.unwrap();
            let d = BackendMessage::CopyData {
                data: Bytes::from(vec![b'A'; 10]),
            };
            write_frame(&mut s, &d.encode()).await.unwrap();
            write_frame(&mut s, &BackendMessage::CopyDone.encode())
                .await
                .unwrap();
            // CommandComplete + ReadyForQuery to terminate cleanly.
            let cc = BackendMessage::CommandComplete {
                tag: "COPY 1".to_string(),
            };
            write_frame(&mut s, &cc.encode()).await.unwrap();
            write_frame(
                &mut s,
                &BackendMessage::ReadyForQuery {
                    status: TransactionStatus::Idle,
                }
                .encode(),
            )
            .await
            .unwrap();
        });

        let mut backend = TcpStream::connect(backend_addr).await.unwrap();
        let (agent_proxy_side, mut agent_client_side) = tokio::io::duplex(64 * 1024);
        let mut agent = agent_proxy_side;
        let mut window = WindowMeter::for_window(&cfg.budget.per_window);
        let clock = MockClock::starting_at(0);

        relay_until_ready(
            &mut agent,
            &mut backend,
            &cfg,
            &rec,
            "copy-ok",
            &mut window,
            &clock,
        )
        .await
        .expect("within-budget COPY-out relays cleanly");

        drop(agent);
        let mut received = Vec::new();
        agent_client_side.read_to_end(&mut received).await.unwrap();
        // The within-budget payload IS forwarded.
        assert!(
            received.windows(4).any(|w| w == b"AAAA"),
            "within-budget CopyData payload must be forwarded"
        );
        server.await.unwrap();
    }
}
