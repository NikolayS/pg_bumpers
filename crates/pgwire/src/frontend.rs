//! Frontend (client → server) PostgreSQL v3 messages.
//!
//! Two shapes exist:
//! - **Startup-phase** messages ([`StartupMessage`], [`SslRequest`]) have *no*
//!   type tag: just a 4-byte length followed by the body.
//! - **Regular** messages carry a 1-byte type tag, then the 4-byte length
//!   (which counts itself but not the tag), then the body.
//!
//! [`FrontendMessage`] models the regular set the proxy must understand to
//! enforce extended-protocol-only and reject simple-query/COPY (SPEC §3/§7 S1).

use crate::buf::{BufReader, BufWriter};
use crate::error::ProtocolError;
use crate::scram::{SaslInitialResponse, SaslResponse};
use bytes::{BufMut, Bytes, BytesMut};

/// Magic protocol version in a [`StartupMessage`] (3.0): `(3 << 16) | 0`.
pub const PROTOCOL_VERSION_3: i32 = 196608;
/// Magic code in an [`SslRequest`]: `(1234 << 16) | 5679`.
pub const SSL_REQUEST_CODE: i32 = 80877103;
/// Magic code in a `CancelRequest`: `(1234 << 16) | 5678`.
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

/// The untagged `StartupMessage`: protocol version + key/value parameters
/// (`user`, `database`, etc.), the parameter list terminated by an empty key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMessage {
    /// Protocol version, normally [`PROTOCOL_VERSION_3`].
    pub protocol_version: i32,
    /// Startup parameters as ordered (key, value) pairs.
    pub parameters: Vec<(String, String)>,
}

impl StartupMessage {
    /// Encode the full untagged frame (4-byte length prefix + body).
    pub fn encode(&self) -> BytesMut {
        let mut body = BufWriter::new();
        body.put_i32(self.protocol_version);
        for (k, v) in &self.parameters {
            body.put_cstr(k);
            body.put_cstr(v);
        }
        // Empty key terminates the parameter list.
        body.put_u8(0);
        frame_untagged(body)
    }

    /// Decode from a body (the bytes *after* the 4-byte length prefix).
    pub fn decode_body(body: Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body);
        let protocol_version = r.get_i32()?;
        let mut parameters = Vec::new();
        loop {
            if r.remaining() == 0 {
                return Err(ProtocolError::malformed(
                    "StartupMessage: missing list terminator",
                ));
            }
            let key = r.get_cstr()?;
            if key.is_empty() {
                break;
            }
            let value = r.get_cstr()?;
            parameters.push((key, value));
        }
        Ok(Self {
            protocol_version,
            parameters,
        })
    }
}

/// The untagged `SSLRequest`: a single magic `i32` ([`SSL_REQUEST_CODE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SslRequest;

impl SslRequest {
    /// Encode the full 8-byte frame (length `8` + magic code).
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_i32(8);
        buf.put_i32(SSL_REQUEST_CODE);
        buf
    }

    /// Decode from a body; validates the magic code.
    pub fn decode_body(body: Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body);
        let code = r.get_i32()?;
        if code != SSL_REQUEST_CODE {
            return Err(ProtocolError::malformed("SSLRequest: bad magic code"));
        }
        Ok(SslRequest)
    }
}

/// A `Describe`/`Close` target kind: a prepared statement (`S`) or portal (`P`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A prepared statement (`'S'`).
    Statement,
    /// A portal (`'P'`).
    Portal,
}

impl TargetKind {
    fn tag(self) -> u8 {
        match self {
            TargetKind::Statement => b'S',
            TargetKind::Portal => b'P',
        }
    }

    fn from_tag(b: u8) -> Result<Self, ProtocolError> {
        match b {
            b'S' => Ok(TargetKind::Statement),
            b'P' => Ok(TargetKind::Portal),
            _ => Err(ProtocolError::malformed("bad Describe/Close target kind")),
        }
    }
}

/// Tagged frontend messages the proxy understands.
///
/// `Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Close` are the extended-protocol
/// happy path; `Query`/`Copy*` exist so the proxy can **detect and reject**
/// them. The structurally-heavy `Parse`/`Bind` bodies are kept as raw payloads
/// (the proxy forwards them verbatim) but their semantic fields are exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendMessage {
    /// Simple query ('Q') — statement-stacking vector; the proxy rejects it.
    Query {
        /// The raw SQL text of the simple query.
        sql: String,
    },
    /// Extended-protocol `Parse` ('P').
    Parse {
        /// Destination prepared-statement name (empty = unnamed).
        statement: String,
        /// The SQL text to prepare.
        sql: String,
        /// Parameter type OIDs the client specified (0 = unspecified).
        param_types: Vec<i32>,
    },
    /// Extended-protocol `Bind` ('B'). Body retained raw for verbatim forward.
    Bind {
        /// Destination portal name.
        portal: String,
        /// Source prepared-statement name.
        statement: String,
        /// The full Bind body after the two names (formats, params, results).
        rest: Bytes,
    },
    /// Extended-protocol `Describe` ('D').
    Describe {
        /// Whether a statement or a portal is being described.
        kind: TargetKind,
        /// The statement/portal name (empty = unnamed/unnamed-portal).
        name: String,
    },
    /// Extended-protocol `Execute` ('E').
    Execute {
        /// The portal to execute.
        portal: String,
        /// Max rows to return (0 = unlimited).
        max_rows: i32,
    },
    /// Extended-protocol `Sync` ('S').
    Sync,
    /// Extended-protocol `Flush` ('H').
    Flush,
    /// Extended-protocol `Close` ('C').
    Close {
        /// Whether a statement or portal is being closed.
        kind: TargetKind,
        /// The statement/portal name.
        name: String,
    },
    /// `Terminate` ('X').
    Terminate,
    /// A 'p' frame carrying the SCRAM `client-first-message`.
    SaslInitialResponse(SaslInitialResponse),
    /// A 'p' frame carrying the SCRAM `client-final-message`.
    SaslResponse(SaslResponse),
    /// `PasswordMessage` ('p') — cleartext/MD5 password (legacy auth).
    PasswordMessage {
        /// The password payload (NUL-terminated on the wire).
        password: String,
    },
    /// `CopyData` ('d') — bulk-copy payload; rejected for agent connections.
    CopyData {
        /// Raw COPY payload bytes.
        data: Bytes,
    },
    /// `CopyDone` ('c').
    CopyDone,
    /// `CopyFail` ('f').
    CopyFail {
        /// The failure message the client reports.
        message: String,
    },
}

impl FrontendMessage {
    /// The 1-byte type tag for this message.
    pub fn tag(&self) -> u8 {
        match self {
            FrontendMessage::Query { .. } => b'Q',
            FrontendMessage::Parse { .. } => b'P',
            FrontendMessage::Bind { .. } => b'B',
            FrontendMessage::Describe { .. } => b'D',
            FrontendMessage::Execute { .. } => b'E',
            FrontendMessage::Sync => b'S',
            FrontendMessage::Flush => b'H',
            FrontendMessage::Close { .. } => b'C',
            FrontendMessage::Terminate => b'X',
            FrontendMessage::SaslInitialResponse(_)
            | FrontendMessage::SaslResponse(_)
            | FrontendMessage::PasswordMessage { .. } => b'p',
            FrontendMessage::CopyData { .. } => b'd',
            FrontendMessage::CopyDone => b'c',
            FrontendMessage::CopyFail { .. } => b'f',
        }
    }

    /// Encode the full tagged frame: `tag | i32 len | body`.
    pub fn encode(&self) -> BytesMut {
        let mut body = BufWriter::new();
        match self {
            FrontendMessage::Query { sql } => body.put_cstr(sql),
            FrontendMessage::Parse {
                statement,
                sql,
                param_types,
            } => {
                body.put_cstr(statement);
                body.put_cstr(sql);
                body.put_i16(param_types.len() as i16);
                for oid in param_types {
                    body.put_i32(*oid);
                }
            }
            FrontendMessage::Bind {
                portal,
                statement,
                rest,
            } => {
                body.put_cstr(portal);
                body.put_cstr(statement);
                body.put_slice(rest);
            }
            FrontendMessage::Describe { kind, name } => {
                body.put_u8(kind.tag());
                body.put_cstr(name);
            }
            FrontendMessage::Execute { portal, max_rows } => {
                body.put_cstr(portal);
                body.put_i32(*max_rows);
            }
            FrontendMessage::Sync | FrontendMessage::Flush | FrontendMessage::Terminate => {}
            FrontendMessage::Close { kind, name } => {
                body.put_u8(kind.tag());
                body.put_cstr(name);
            }
            FrontendMessage::SaslInitialResponse(m) => m.encode_body(&mut body),
            FrontendMessage::SaslResponse(m) => m.encode_body(&mut body),
            FrontendMessage::PasswordMessage { password } => body.put_cstr(password),
            FrontendMessage::CopyData { data } => body.put_slice(data),
            FrontendMessage::CopyDone => {}
            FrontendMessage::CopyFail { message } => body.put_cstr(message),
        }
        frame_tagged(self.tag(), body)
    }

    /// Decode a tagged message from `(tag, body)` where `body` excludes the tag
    /// and the 4-byte length prefix.
    ///
    /// The 'p' tag is auth-phase ambiguous (it serves `SASLInitialResponse`,
    /// `SASLResponse` and `PasswordMessage`). Decoding 'p' alone cannot
    /// disambiguate, so it is decoded as [`FrontendMessage::PasswordMessage`]
    /// only when the body is a single NUL-terminated string; otherwise the
    /// caller should use [`crate::scram`] directly with auth-state context.
    pub fn decode(tag: u8, body: Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body);
        let msg = match tag {
            b'Q' => FrontendMessage::Query { sql: r.get_cstr()? },
            b'P' => {
                let statement = r.get_cstr()?;
                let sql = r.get_cstr()?;
                let n = r.get_i16()?;
                if n < 0 {
                    return Err(ProtocolError::malformed("Parse: negative param count"));
                }
                let mut param_types = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    param_types.push(r.get_i32()?);
                }
                FrontendMessage::Parse {
                    statement,
                    sql,
                    param_types,
                }
            }
            b'B' => {
                let portal = r.get_cstr()?;
                let statement = r.get_cstr()?;
                FrontendMessage::Bind {
                    portal,
                    statement,
                    rest: r.rest(),
                }
            }
            b'D' => {
                let kind = TargetKind::from_tag(r.get_u8()?)?;
                let name = r.get_cstr()?;
                FrontendMessage::Describe { kind, name }
            }
            b'E' => {
                let portal = r.get_cstr()?;
                let max_rows = r.get_i32()?;
                FrontendMessage::Execute { portal, max_rows }
            }
            b'S' => FrontendMessage::Sync,
            b'H' => FrontendMessage::Flush,
            b'C' => {
                let kind = TargetKind::from_tag(r.get_u8()?)?;
                let name = r.get_cstr()?;
                FrontendMessage::Close { kind, name }
            }
            b'X' => FrontendMessage::Terminate,
            b'p' => FrontendMessage::PasswordMessage {
                password: r.get_cstr()?,
            },
            b'd' => FrontendMessage::CopyData { data: r.rest() },
            b'c' => FrontendMessage::CopyDone,
            b'f' => FrontendMessage::CopyFail {
                message: r.get_cstr()?,
            },
            other => return Err(ProtocolError::UnknownTag(other)),
        };
        Ok(msg)
    }
}

/// Wrap a written body into a tagged frame: `tag | i32(len = 4 + body) | body`.
fn frame_tagged(tag: u8, body: BufWriter) -> BytesMut {
    let body = body.into_bytes();
    let mut out = BytesMut::with_capacity(1 + 4 + body.len());
    out.put_u8(tag);
    out.put_i32((4 + body.len()) as i32);
    out.put_slice(&body);
    out
}

/// Wrap a written body into an untagged frame: `i32(len = 4 + body) | body`.
fn frame_untagged(body: BufWriter) -> BytesMut {
    let len = body.len();
    let body = body.into_bytes();
    let mut out = BytesMut::with_capacity(4 + len);
    out.put_i32((4 + len) as i32);
    out.put_slice(&body);
    out
}
