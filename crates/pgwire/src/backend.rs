//! Backend (server → client) PostgreSQL v3 messages.
//!
//! Every backend message carries a 1-byte type tag, then a 4-byte length (which
//! counts itself but not the tag), then the body. [`BackendMessage`] models the
//! set the proxy must understand to drive auth, surface results, and inject
//! `ErrorResponse`/`ReadyForQuery` when it rejects a request (SPEC §7 S1).

use crate::buf::{BufReader, BufWriter};
use crate::error::ProtocolError;
use crate::scram::{
    AuthenticationSasl, AuthenticationSaslContinue, AuthenticationSaslFinal, auth_type,
};
use bytes::{BufMut, Bytes, BytesMut};

/// Transaction status reported by `ReadyForQuery` ('Z').
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// `'I'` — idle, not in a transaction block.
    Idle,
    /// `'T'` — in a transaction block.
    InTransaction,
    /// `'E'` — in a failed transaction block.
    Failed,
}

impl TransactionStatus {
    fn tag(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    fn from_tag(b: u8) -> Result<Self, ProtocolError> {
        match b {
            b'I' => Ok(TransactionStatus::Idle),
            b'T' => Ok(TransactionStatus::InTransaction),
            b'E' => Ok(TransactionStatus::Failed),
            _ => Err(ProtocolError::malformed("ReadyForQuery: bad status")),
        }
    }
}

/// One field of a `RowDescription` ('T') message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    /// Column name.
    pub name: String,
    /// OID of the table the column belongs to (0 if not a simple column).
    pub table_oid: i32,
    /// Attribute number of the column (0 if not a simple column).
    pub column_attr: i16,
    /// OID of the field's data type.
    pub type_oid: i32,
    /// Data type size (negative = variable width).
    pub type_size: i16,
    /// Type modifier.
    pub type_modifier: i32,
    /// Format code: 0 = text, 1 = binary.
    pub format: i16,
}

/// One `(code, value)` field of an `ErrorResponse`/`NoticeResponse`.
pub type DiagnosticField = (u8, String);

/// Tagged backend messages the proxy understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendMessage {
    /// `AuthenticationOk` ('R', type 0).
    AuthenticationOk,
    /// `AuthenticationCleartextPassword` ('R', type 3).
    AuthenticationCleartextPassword,
    /// `AuthenticationMD5Password` ('R', type 5) with its 4-byte salt.
    AuthenticationMd5Password {
        /// The 4-byte MD5 salt.
        salt: [u8; 4],
    },
    /// `AuthenticationSASL` ('R', type 10).
    AuthenticationSasl(AuthenticationSasl),
    /// `AuthenticationSASLContinue` ('R', type 11).
    AuthenticationSaslContinue(AuthenticationSaslContinue),
    /// `AuthenticationSASLFinal` ('R', type 12).
    AuthenticationSaslFinal(AuthenticationSaslFinal),
    /// `ParameterStatus` ('S'): a runtime parameter report.
    ParameterStatus {
        /// Parameter name (e.g. `server_version`).
        name: String,
        /// Parameter value.
        value: String,
    },
    /// `BackendKeyData` ('K'): cancellation key for this session.
    BackendKeyData {
        /// Backend process id.
        process_id: i32,
        /// Secret cancellation key.
        secret_key: i32,
    },
    /// `ReadyForQuery` ('Z').
    ReadyForQuery {
        /// Current transaction status.
        status: TransactionStatus,
    },
    /// `ErrorResponse` ('E'): the proxy emits this to reject a request.
    ErrorResponse {
        /// Diagnostic fields as `(field-type-byte, value)` pairs.
        fields: Vec<DiagnosticField>,
    },
    /// `NoticeResponse` ('N').
    NoticeResponse {
        /// Diagnostic fields as `(field-type-byte, value)` pairs.
        fields: Vec<DiagnosticField>,
    },
    /// `RowDescription` ('T').
    RowDescription {
        /// The column descriptions.
        fields: Vec<FieldDescription>,
    },
    /// `DataRow` ('D'): a result row. `None` is a SQL NULL column.
    DataRow {
        /// Column values; `None` represents SQL NULL.
        columns: Vec<Option<Bytes>>,
    },
    /// `CommandComplete` ('C').
    CommandComplete {
        /// The command tag (e.g. `SELECT 3`).
        tag: String,
    },
    /// `PortalSuspended` ('s'): row-limit reached, portal still open.
    PortalSuspended,
    /// `ParseComplete` ('1').
    ParseComplete,
    /// `BindComplete` ('2').
    BindComplete,
    /// `CloseComplete` ('3').
    CloseComplete,
    /// `NoData` ('n').
    NoData,
    /// `EmptyQueryResponse` ('I').
    EmptyQueryResponse,
    /// `CopyInResponse` ('G'): COPY FROM STDIN handshake; rejected for agents.
    CopyInResponse {
        /// Overall format: 0 = text, 1 = binary.
        format: u8,
        /// Per-column format codes.
        column_formats: Vec<i16>,
    },
    /// `CopyOutResponse` ('H'): COPY TO STDOUT handshake; rejected for agents.
    CopyOutResponse {
        /// Overall format: 0 = text, 1 = binary.
        format: u8,
        /// Per-column format codes.
        column_formats: Vec<i16>,
    },
    /// `CopyData` ('d').
    CopyData {
        /// Raw COPY payload bytes.
        data: Bytes,
    },
    /// `CopyDone` ('c').
    CopyDone,
}

impl BackendMessage {
    /// The 1-byte type tag for this message.
    pub fn tag(&self) -> u8 {
        match self {
            BackendMessage::AuthenticationOk
            | BackendMessage::AuthenticationCleartextPassword
            | BackendMessage::AuthenticationMd5Password { .. }
            | BackendMessage::AuthenticationSasl(_)
            | BackendMessage::AuthenticationSaslContinue(_)
            | BackendMessage::AuthenticationSaslFinal(_) => b'R',
            BackendMessage::ParameterStatus { .. } => b'S',
            BackendMessage::BackendKeyData { .. } => b'K',
            BackendMessage::ReadyForQuery { .. } => b'Z',
            BackendMessage::ErrorResponse { .. } => b'E',
            BackendMessage::NoticeResponse { .. } => b'N',
            BackendMessage::RowDescription { .. } => b'T',
            BackendMessage::DataRow { .. } => b'D',
            BackendMessage::CommandComplete { .. } => b'C',
            BackendMessage::PortalSuspended => b's',
            BackendMessage::ParseComplete => b'1',
            BackendMessage::BindComplete => b'2',
            BackendMessage::CloseComplete => b'3',
            BackendMessage::NoData => b'n',
            BackendMessage::EmptyQueryResponse => b'I',
            BackendMessage::CopyInResponse { .. } => b'G',
            BackendMessage::CopyOutResponse { .. } => b'H',
            BackendMessage::CopyData { .. } => b'd',
            BackendMessage::CopyDone => b'c',
        }
    }

    /// Encode the full tagged frame: `tag | i32 len | body`.
    pub fn encode(&self) -> BytesMut {
        let mut body = BufWriter::new();
        match self {
            BackendMessage::AuthenticationOk => body.put_i32(auth_type::OK),
            BackendMessage::AuthenticationCleartextPassword => {
                body.put_i32(auth_type::CLEARTEXT_PASSWORD)
            }
            BackendMessage::AuthenticationMd5Password { salt } => {
                body.put_i32(auth_type::MD5_PASSWORD);
                body.put_slice(salt);
            }
            BackendMessage::AuthenticationSasl(m) => m.encode_body(&mut body),
            BackendMessage::AuthenticationSaslContinue(m) => m.encode_body(&mut body),
            BackendMessage::AuthenticationSaslFinal(m) => m.encode_body(&mut body),
            BackendMessage::ParameterStatus { name, value } => {
                body.put_cstr(name);
                body.put_cstr(value);
            }
            BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            } => {
                body.put_i32(*process_id);
                body.put_i32(*secret_key);
            }
            BackendMessage::ReadyForQuery { status } => body.put_u8(status.tag()),
            BackendMessage::ErrorResponse { fields }
            | BackendMessage::NoticeResponse { fields } => {
                for (code, value) in fields {
                    body.put_u8(*code);
                    body.put_cstr(value);
                }
                body.put_u8(0);
            }
            BackendMessage::RowDescription { fields } => {
                body.put_i16(fields.len() as i16);
                for f in fields {
                    body.put_cstr(&f.name);
                    body.put_i32(f.table_oid);
                    body.put_i16(f.column_attr);
                    body.put_i32(f.type_oid);
                    body.put_i16(f.type_size);
                    body.put_i32(f.type_modifier);
                    body.put_i16(f.format);
                }
            }
            BackendMessage::DataRow { columns } => {
                body.put_i16(columns.len() as i16);
                for col in columns {
                    match col {
                        None => body.put_i32(-1),
                        Some(bytes) => {
                            body.put_i32(bytes.len() as i32);
                            body.put_slice(bytes);
                        }
                    }
                }
            }
            BackendMessage::CommandComplete { tag } => body.put_cstr(tag),
            BackendMessage::PortalSuspended
            | BackendMessage::ParseComplete
            | BackendMessage::BindComplete
            | BackendMessage::CloseComplete
            | BackendMessage::NoData
            | BackendMessage::EmptyQueryResponse
            | BackendMessage::CopyDone => {}
            BackendMessage::CopyInResponse {
                format,
                column_formats,
            }
            | BackendMessage::CopyOutResponse {
                format,
                column_formats,
            } => {
                body.put_u8(*format);
                body.put_i16(column_formats.len() as i16);
                for c in column_formats {
                    body.put_i16(*c);
                }
            }
            BackendMessage::CopyData { data } => body.put_slice(data),
        }
        frame_tagged(self.tag(), body)
    }

    /// Decode a tagged message from `(tag, body)` where `body` excludes the tag
    /// and the 4-byte length prefix.
    pub fn decode(tag: u8, body: Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body);
        let msg = match tag {
            b'R' => decode_authentication(&mut r)?,
            b'S' => BackendMessage::ParameterStatus {
                name: r.get_cstr()?,
                value: r.get_cstr()?,
            },
            b'K' => BackendMessage::BackendKeyData {
                process_id: r.get_i32()?,
                secret_key: r.get_i32()?,
            },
            b'Z' => BackendMessage::ReadyForQuery {
                status: TransactionStatus::from_tag(r.get_u8()?)?,
            },
            b'E' => BackendMessage::ErrorResponse {
                fields: decode_diagnostics(&mut r)?,
            },
            b'N' => BackendMessage::NoticeResponse {
                fields: decode_diagnostics(&mut r)?,
            },
            b'T' => {
                let n = r.get_i16()?;
                if n < 0 {
                    return Err(ProtocolError::malformed("RowDescription: negative count"));
                }
                let mut fields = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    fields.push(FieldDescription {
                        name: r.get_cstr()?,
                        table_oid: r.get_i32()?,
                        column_attr: r.get_i16()?,
                        type_oid: r.get_i32()?,
                        type_size: r.get_i16()?,
                        type_modifier: r.get_i32()?,
                        format: r.get_i16()?,
                    });
                }
                BackendMessage::RowDescription { fields }
            }
            b'D' => {
                let n = r.get_i16()?;
                if n < 0 {
                    return Err(ProtocolError::malformed("DataRow: negative count"));
                }
                let mut columns = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let len = r.get_i32()?;
                    if len < 0 {
                        columns.push(None);
                    } else {
                        columns.push(Some(r.get_bytes(len as usize)?));
                    }
                }
                BackendMessage::DataRow { columns }
            }
            b'C' => BackendMessage::CommandComplete { tag: r.get_cstr()? },
            b's' => BackendMessage::PortalSuspended,
            b'1' => BackendMessage::ParseComplete,
            b'2' => BackendMessage::BindComplete,
            b'3' => BackendMessage::CloseComplete,
            b'n' => BackendMessage::NoData,
            b'I' => BackendMessage::EmptyQueryResponse,
            b'G' => {
                let (format, column_formats) = decode_copy_response(&mut r)?;
                BackendMessage::CopyInResponse {
                    format,
                    column_formats,
                }
            }
            b'H' => {
                let (format, column_formats) = decode_copy_response(&mut r)?;
                BackendMessage::CopyOutResponse {
                    format,
                    column_formats,
                }
            }
            b'd' => BackendMessage::CopyData { data: r.rest() },
            b'c' => BackendMessage::CopyDone,
            other => return Err(ProtocolError::UnknownTag(other)),
        };
        Ok(msg)
    }
}

fn decode_authentication(r: &mut BufReader) -> Result<BackendMessage, ProtocolError> {
    let kind = r.get_i32()?;
    let msg = match kind {
        auth_type::OK => BackendMessage::AuthenticationOk,
        auth_type::CLEARTEXT_PASSWORD => BackendMessage::AuthenticationCleartextPassword,
        auth_type::MD5_PASSWORD => {
            let raw = r.get_bytes(4)?;
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&raw);
            BackendMessage::AuthenticationMd5Password { salt }
        }
        auth_type::SASL => BackendMessage::AuthenticationSasl(AuthenticationSasl::decode_body(r)?),
        auth_type::SASL_CONTINUE => {
            BackendMessage::AuthenticationSaslContinue(AuthenticationSaslContinue::decode_body(r)?)
        }
        auth_type::SASL_FINAL => {
            BackendMessage::AuthenticationSaslFinal(AuthenticationSaslFinal::decode_body(r)?)
        }
        _ => return Err(ProtocolError::malformed("Authentication: unsupported type")),
    };
    Ok(msg)
}

fn decode_diagnostics(r: &mut BufReader) -> Result<Vec<DiagnosticField>, ProtocolError> {
    let mut fields = Vec::new();
    loop {
        let code = r.get_u8()?;
        if code == 0 {
            break;
        }
        let value = r.get_cstr()?;
        fields.push((code, value));
    }
    Ok(fields)
}

fn decode_copy_response(r: &mut BufReader) -> Result<(u8, Vec<i16>), ProtocolError> {
    let format = r.get_u8()?;
    let n = r.get_i16()?;
    if n < 0 {
        return Err(ProtocolError::malformed("Copy*Response: negative count"));
    }
    let mut column_formats = Vec::with_capacity(n as usize);
    for _ in 0..n {
        column_formats.push(r.get_i16()?);
    }
    Ok((format, column_formats))
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
