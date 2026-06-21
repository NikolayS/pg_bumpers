//! Error type for the wire-protocol codec.

use std::io;

/// Errors raised while encoding/decoding PostgreSQL v3 wire messages.
///
/// The codec is **fail-closed**: a malformed or truncated frame is a hard
/// error, never a best-effort guess, so the proxy can reject the connection
/// rather than mis-parse a hostile byte stream.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Underlying transport I/O failed (connection closed, reset, etc.).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A length-prefixed frame declared a length we will not honor (too small
    /// to contain its own header, or larger than [`crate::codec::MAX_FRAME_LEN`]).
    #[error("invalid frame length: {0}")]
    InvalidLength(i32),

    /// A message body did not match the layout required by its type tag
    /// (e.g. truncated, missing NUL terminator, bad field count).
    #[error("malformed message body: {0}")]
    Malformed(&'static str),

    /// A required C-string field was not NUL-terminated within the frame.
    #[error("unterminated cstring")]
    UnterminatedCString,

    /// A string field contained bytes that are not valid UTF-8.
    #[error("invalid utf-8 in protocol string")]
    InvalidUtf8,

    /// The message type tag byte is one this codec does not model.
    #[error("unknown message tag: {0:?}")]
    UnknownTag(u8),
}

impl ProtocolError {
    /// Convenience constructor for a malformed-body error.
    pub(crate) fn malformed(what: &'static str) -> Self {
        ProtocolError::Malformed(what)
    }
}
