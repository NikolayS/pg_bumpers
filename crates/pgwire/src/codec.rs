//! Async length-prefixed framing of v3 messages over a `tokio` stream.
//!
//! This is the byte-level seam the proxy sits on: it reads one **raw frame** at
//! a time and lets the caller decode it into a typed [`crate::frontend`] /
//! [`crate::backend`] message, mutate, drop, or re-encode it. Keeping framing
//! and typed decoding separate is what gives the proxy mid-stream control
//! (reject, cut off, inject `ErrorResponse`) without buffering a whole stream.

use crate::error::ProtocolError;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound on a single frame we will read (1 GiB, matching PostgreSQL's own
/// limit). A larger declared length is rejected fail-closed rather than used to
/// drive an unbounded allocation from a hostile peer.
pub const MAX_FRAME_LEN: usize = 0x4000_0000;

/// A raw **tagged** frame: a 1-byte type tag plus the body bytes (the 4-byte
/// length prefix has been consumed and is not included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    /// The 1-byte message type tag.
    pub tag: u8,
    /// The message body (everything after the length prefix).
    pub body: Bytes,
}

/// Read one **untagged** startup-phase frame body (the bytes after the 4-byte
/// length prefix). Used for `StartupMessage` / `SSLRequest` / `CancelRequest`,
/// which have no type tag.
pub async fn read_startup_body<R>(stream: &mut R) -> Result<Bytes, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let len = stream.read_i32().await?;
    let body_len = checked_body_len(len)?;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok(Bytes::from(body))
}

/// Read one raw **tagged** frame: type byte, then length-prefixed body.
///
/// Returns `Ok(None)` on a clean EOF *before* any byte of a new frame (the peer
/// closed between messages); a mid-frame EOF is a hard error.
pub async fn read_tagged_frame<R>(stream: &mut R) -> Result<Option<RawFrame>, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let tag = match stream.read_u8().await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = stream.read_i32().await?;
    let body_len = checked_body_len(len)?;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok(Some(RawFrame {
        tag,
        body: Bytes::from(body),
    }))
}

/// Write any already-encoded frame (the output of `*::encode`) to the stream and
/// flush it.
pub async fn write_frame<W>(stream: &mut W, frame: &BytesMut) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(frame).await?;
    stream.flush().await?;
    Ok(())
}

/// Validate a declared 4-byte length and return the remaining body length.
///
/// The length counts itself (the 4 length bytes) but never the tag, so a valid
/// length is `>= 4`; the body is `len - 4`. Anything below 4 or above
/// [`MAX_FRAME_LEN`] is rejected fail-closed.
fn checked_body_len(len: i32) -> Result<usize, ProtocolError> {
    if !(4..=(MAX_FRAME_LEN as i32)).contains(&len) {
        return Err(ProtocolError::InvalidLength(len));
    }
    Ok((len - 4) as usize)
}
