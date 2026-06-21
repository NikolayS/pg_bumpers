//! Rejection detector: which frames the proxy must refuse for an agent.
//!
//! The proxy forces the **extended protocol** (kills statement-stacking) and
//! rejects the simple `Query` ('Q') path and all `Copy*` traffic (SPEC §3
//! layer 2, §7 S1). This module classifies a raw frame *by tag alone* — cheap,
//! allocation-free, and fail-closed: an unrecognized/forbidden tag is rejected,
//! not waved through.

use crate::codec::RawFrame;

/// The reason a frontend frame is rejected for an agent connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Simple `Query` ('Q') — enables `SELECT 1; DROP …` statement-stacking.
    SimpleQuery,
    /// A `Copy*` frame (`CopyData`/`CopyDone`/`CopyFail`) — bulk path, no
    /// per-statement gate; `COPY … PROGRAM` is an RCE vector.
    Copy,
}

/// Whether a raw **frontend** frame is allowed for an agent connection, by tag.
///
/// `Ok(())` = allowed (extended protocol, auth, terminate). `Err(reason)` =
/// reject. This is intentionally a pure tag check so it runs before the body is
/// decoded; the [`crate::classifier`] then inspects extended-protocol SQL text.
pub fn classify_frontend_frame(frame: &RawFrame) -> Result<(), RejectReason> {
    classify_frontend_tag(frame.tag)
}

/// Tag-only variant of [`classify_frontend_frame`].
pub fn classify_frontend_tag(tag: u8) -> Result<(), RejectReason> {
    match tag {
        // Simple query — the statement-stacking vector.
        b'Q' => Err(RejectReason::SimpleQuery),
        // COPY frontend frames: CopyData('d'), CopyDone('c'), CopyFail('f').
        b'd' | b'c' | b'f' => Err(RejectReason::Copy),
        // Everything else (Parse/Bind/Describe/Execute/Sync/Flush/Close/
        // Terminate/password+SASL 'p') is allowed at the framing layer.
        _ => Ok(()),
    }
}

/// Whether a raw **backend** frame indicates the server is trying to start a
/// COPY (`CopyInResponse` 'G' / `CopyOutResponse` 'H' / `CopyBothResponse` 'W').
///
/// The proxy never legitimately initiates COPY for an agent, but a misbehaving
/// or compromised backend could; surfacing it lets the proxy tear the
/// connection down rather than proxy bulk data.
pub fn backend_starts_copy(frame: &RawFrame) -> bool {
    matches!(frame.tag, b'G' | b'H' | b'W')
}
