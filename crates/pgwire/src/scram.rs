//! SASL / SCRAM-SHA-256 message bodies (SPEC §7 S1 "SCRAM auth passthrough").
//!
//! SCRAM travels inside the ordinary FE/BE envelope: the backend's
//! `AuthenticationSASL` / `AuthenticationSASLContinue` / `AuthenticationSASLFinal`
//! are all `Authentication` ('R') messages distinguished by a leading auth-type
//! `i32`; the frontend replies in `PasswordMessage`-shaped 'p' frames
//! (`SASLInitialResponse` / `SASLResponse`).
//!
//! pg_bumpers terminates the agent connection and re-authenticates to the
//! backend, so it must be able to **parse and reconstruct** these payloads
//! byte-for-byte. This module models just the SASL-specific bodies; the
//! enveloping is done in [`crate::backend`] / [`crate::frontend`].

use crate::buf::{BufReader, BufWriter};
use crate::error::ProtocolError;
use bytes::Bytes;

/// The auth-type discriminator carried by an `Authentication` ('R') message.
pub mod auth_type {
    /// AuthenticationOk.
    pub const OK: i32 = 0;
    /// AuthenticationCleartextPassword.
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    /// AuthenticationMD5Password.
    pub const MD5_PASSWORD: i32 = 5;
    /// AuthenticationSASL.
    pub const SASL: i32 = 10;
    /// AuthenticationSASLContinue.
    pub const SASL_CONTINUE: i32 = 11;
    /// AuthenticationSASLFinal.
    pub const SASL_FINAL: i32 = 12;
}

/// Body of `AuthenticationSASL` (auth-type 10): the list of SASL mechanism
/// names the server offers, NUL-terminated, the list itself terminated by an
/// extra NUL. For SCRAM-SHA-256 this is typically `["SCRAM-SHA-256"]` (and
/// `SCRAM-SHA-256-PLUS` when channel binding is available).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationSasl {
    /// Offered mechanism names, in server preference order.
    pub mechanisms: Vec<String>,
}

impl AuthenticationSasl {
    pub(crate) fn encode_body(&self, w: &mut BufWriter) {
        w.put_i32(auth_type::SASL);
        for m in &self.mechanisms {
            w.put_cstr(m);
        }
        // The mechanism list is terminated by a zero-length (NUL-only) entry.
        w.put_u8(0);
    }

    pub(crate) fn decode_body(r: &mut BufReader) -> Result<Self, ProtocolError> {
        let mut mechanisms = Vec::new();
        loop {
            if r.remaining() == 0 {
                return Err(ProtocolError::malformed(
                    "AuthenticationSASL: missing list terminator",
                ));
            }
            let m = r.get_cstr()?;
            if m.is_empty() {
                // The trailing zero-length entry ends the list.
                break;
            }
            mechanisms.push(m);
        }
        Ok(Self { mechanisms })
    }
}

/// Body of `AuthenticationSASLContinue` (auth-type 11): the server's SASL
/// challenge bytes (the SCRAM `server-first-message`). Opaque to the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationSaslContinue {
    /// Raw SASL challenge data.
    pub data: Bytes,
}

impl AuthenticationSaslContinue {
    pub(crate) fn encode_body(&self, w: &mut BufWriter) {
        w.put_i32(auth_type::SASL_CONTINUE);
        w.put_slice(&self.data);
    }

    pub(crate) fn decode_body(r: &mut BufReader) -> Result<Self, ProtocolError> {
        Ok(Self { data: r.rest() })
    }
}

/// Body of `AuthenticationSASLFinal` (auth-type 12): the SCRAM
/// `server-final-message` (server signature). Opaque to the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationSaslFinal {
    /// Raw SASL outcome / additional data.
    pub data: Bytes,
}

impl AuthenticationSaslFinal {
    pub(crate) fn encode_body(&self, w: &mut BufWriter) {
        w.put_i32(auth_type::SASL_FINAL);
        w.put_slice(&self.data);
    }

    pub(crate) fn decode_body(r: &mut BufReader) -> Result<Self, ProtocolError> {
        Ok(Self { data: r.rest() })
    }
}

/// Frontend `SASLInitialResponse` (a 'p' frame): names the chosen mechanism and
/// carries the SCRAM `client-first-message`. A length of `-1` means "no initial
/// response"; here we model the data as optional to round-trip both cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslInitialResponse {
    /// The SASL mechanism the client selected (e.g. `SCRAM-SHA-256`).
    pub mechanism: String,
    /// The initial client response, or `None` when length is encoded as `-1`.
    pub initial_response: Option<Bytes>,
}

impl SaslInitialResponse {
    pub(crate) fn encode_body(&self, w: &mut BufWriter) {
        w.put_cstr(&self.mechanism);
        match &self.initial_response {
            Some(data) => {
                w.put_i32(data.len() as i32);
                w.put_slice(data);
            }
            None => w.put_i32(-1),
        }
    }

    pub(crate) fn decode_body(r: &mut BufReader) -> Result<Self, ProtocolError> {
        let mechanism = r.get_cstr()?;
        let len = r.get_i32()?;
        let initial_response = if len < 0 {
            None
        } else {
            Some(r.get_bytes(len as usize)?)
        };
        Ok(Self {
            mechanism,
            initial_response,
        })
    }

    /// Decode this `SASLInitialResponse` from the body of a 'p' frame.
    ///
    /// The 'p' tag is auth-phase ambiguous, so the proxy selects the right
    /// decoder using its auth state and calls this directly on the frame body
    /// (`RawFrame::body`). Consumes the bytes it reads.
    pub fn decode_body_from(body: &mut Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body.split_off(0));
        Self::decode_body(&mut r)
    }
}

/// Frontend `SASLResponse` (a 'p' frame): the SCRAM `client-final-message`.
/// The whole body is opaque SASL data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslResponse {
    /// Raw SASL response data.
    pub data: Bytes,
}

impl SaslResponse {
    pub(crate) fn encode_body(&self, w: &mut BufWriter) {
        w.put_slice(&self.data);
    }

    pub(crate) fn decode_body(r: &mut BufReader) -> Result<Self, ProtocolError> {
        Ok(Self { data: r.rest() })
    }

    /// Decode this `SASLResponse` (the SCRAM `client-final-message`) from the
    /// body of a 'p' frame. See [`SaslInitialResponse::decode_body_from`].
    pub fn decode_body_from(body: &mut Bytes) -> Result<Self, ProtocolError> {
        let mut r = BufReader::new(body.split_off(0));
        Self::decode_body(&mut r)
    }
}
