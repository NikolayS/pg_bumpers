//! One **generic webhook POST** of the approval-request payload (SPEC §14.3 MVP).
//!
//! The MVP delivers a blocked-and-routed request out-of-band via a *single,
//! documented, generic* webhook: an HTTP `POST` of the request payload as JSON.
//! Customers wire Slack / email / PagerDuty themselves on the receiving end — we
//! deliberately do **not** ship per-vendor connectors (those are fast-follow,
//! SPEC §14.3).
//!
//! Delivery is behind the [`WebhookSender`] trait so the transport is
//! injectable: production uses [`HttpWebhookSender`] (a tiny, dependency-free
//! HTTP/1.1 `POST` over `std::net::TcpStream` — no async runtime, no new HTTP
//! crate), and tests use either a recording fake or a real local stub server on
//! an ephemeral `127.0.0.1` port. The webhook never targets an external endpoint
//! in tests.
//!
//! Failure posture: webhook delivery is **best-effort notification, not a
//! gate**. The authorization decision is made by the signed grant; a failed POST
//! is surfaced to the caller (and audited) but never loosens anything.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::request::{ApprovalRequest, Proposal, RequestId};

/// The JSON body POSTed to the webhook (SPEC §14.3 — "POST of the request
/// payload").
///
/// It carries the full context an approver needs to decide (SPEC §14.2):
/// the request id + TTL, the proposal SQL + role + blast-radius checksum, and
/// the requester identity. It is a stable, documented shape so a customer's
/// receiver can parse it without our SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event discriminator (`"approval_required"`).
    pub event: String,
    /// The request id to approve.
    pub request_id: RequestId,
    /// The requester (agent / DB-operator) identity.
    pub requester_id: String,
    /// The proposal being elevated (SQL, role, blast-radius, …).
    pub proposal: Proposal,
    /// Absolute expiry instant of the request (unix millis).
    pub expires_at_unix_millis: u64,
}

/// The webhook event discriminator.
pub const WEBHOOK_EVENT: &str = "approval_required";

impl WebhookPayload {
    /// Build the payload from a recorded [`ApprovalRequest`].
    pub fn from_request(request: &ApprovalRequest) -> Self {
        WebhookPayload {
            event: WEBHOOK_EVENT.to_string(),
            request_id: request.id.clone(),
            requester_id: request.requester_id.clone(),
            proposal: request.proposal.clone(),
            expires_at_unix_millis: request.expires_at(),
        }
    }

    /// Serialize to the JSON body bytes that go on the wire.
    pub fn to_json(&self) -> String {
        // Plain data — serialization cannot fail; surface loudly if it ever did.
        serde_json::to_string(self).expect("webhook payload is always serializable")
    }
}

/// A webhook delivery failure (best-effort notification; never a gate).
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The target URL was not a parseable `http://host:port/path`.
    #[error("invalid webhook url: {0}")]
    InvalidUrl(String),
    /// A transport / IO error talking to the endpoint.
    #[error("webhook transport error: {0}")]
    Transport(String),
    /// The endpoint returned a non-2xx HTTP status.
    #[error("webhook endpoint returned HTTP {0}")]
    Status(u16),
}

/// The generic webhook transport seam (SPEC §14.3 MVP — one generic webhook).
///
/// Object-safe so the transport can be swapped (`Box<dyn WebhookSender>`): the
/// HTTP impl in production, a recording fake or a local stub in tests.
pub trait WebhookSender {
    /// Deliver the payload. `Ok(())` on a 2xx response; any error is surfaced to
    /// the caller (and audited) but does **not** affect the authorization
    /// decision.
    fn send(&self, payload: &WebhookPayload) -> Result<(), WebhookError>;
}

/// A dependency-free HTTP/1.1 `POST` sender (SPEC §14.3 MVP generic webhook).
///
/// Writes a minimal `POST` request to `http://host:port/path` over a plain
/// [`TcpStream`] and reads back the status line. This avoids pulling a heavy
/// async HTTP crate into the CLI for a single fire-and-forget POST. TLS / richer
/// transports are a fast-follow if a customer needs `https` directly (most front
/// it with a local relay).
#[derive(Debug, Clone)]
pub struct HttpWebhookSender {
    url: String,
    timeout: Duration,
}

impl HttpWebhookSender {
    /// A sender targeting `url` (an `http://host:port/path` endpoint) with a
    /// default 5s timeout.
    pub fn new(url: impl Into<String>) -> Self {
        HttpWebhookSender {
            url: url.into(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Override the connect/read/write timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A parsed `http://host:port/path` target.
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

/// Parse a minimal `http://host:port/path` URL. Only plain `http` is supported;
/// anything else (or a missing host) is an [`WebhookError::InvalidUrl`].
fn parse_http_url(url: &str) -> Result<ParsedUrl, WebhookError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| WebhookError::InvalidUrl(url.to_string()))?;
    // Split authority from path at the first '/'.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(WebhookError::InvalidUrl(url.to_string()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| WebhookError::InvalidUrl(url.to_string()))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(WebhookError::InvalidUrl(url.to_string()));
    }
    Ok(ParsedUrl {
        host,
        port,
        path: path.to_string(),
    })
}

impl WebhookSender for HttpWebhookSender {
    fn send(&self, payload: &WebhookPayload) -> Result<(), WebhookError> {
        let parsed = parse_http_url(&self.url)?;
        let body = payload.to_json();

        let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| WebhookError::Transport(e.to_string()))?;

        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            path = parsed.path,
            host = parsed.host,
            len = body.len(),
            body = body,
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| WebhookError::Transport(e.to_string()))?;

        // Read the response status line and confirm a 2xx.
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        let status = parse_status_code(&response)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(WebhookError::Status(status))
        }
    }
}

/// Extract the numeric status code from an HTTP/1.1 response's status line
/// (`HTTP/1.1 200 OK`).
fn parse_status_code(response: &str) -> Result<u16, WebhookError> {
    let first_line = response
        .lines()
        .next()
        .ok_or_else(|| WebhookError::Transport("empty webhook response".to_string()))?;
    let code = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            WebhookError::Transport(format!("malformed webhook status line: {first_line:?}"))
        })?;
    Ok(code)
}

/// A recording [`WebhookSender`] for tests: captures every payload and can be
/// configured to fail, exercising the best-effort-notification posture.
#[derive(Debug, Default)]
pub struct RecordingWebhookSender {
    sent: std::sync::Mutex<Vec<WebhookPayload>>,
    fail: bool,
}

impl RecordingWebhookSender {
    /// A recorder that succeeds and captures payloads.
    pub fn new() -> Self {
        RecordingWebhookSender::default()
    }

    /// A recorder that always fails delivery (to test the best-effort posture).
    pub fn failing() -> Self {
        RecordingWebhookSender {
            sent: std::sync::Mutex::new(Vec::new()),
            fail: true,
        }
    }

    /// The payloads captured so far.
    pub fn sent(&self) -> Vec<WebhookPayload> {
        self.sent.lock().expect("recorder mutex").clone()
    }
}

impl WebhookSender for RecordingWebhookSender {
    fn send(&self, payload: &WebhookPayload) -> Result<(), WebhookError> {
        self.sent
            .lock()
            .expect("recorder mutex")
            .push(payload.clone());
        if self.fail {
            Err(WebhookError::Transport("configured to fail".to_string()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_url_with_port_and_path() {
        let p = parse_http_url("http://127.0.0.1:8080/hook").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/hook");
    }

    #[test]
    fn parses_http_url_default_port_and_root_path() {
        let p = parse_http_url("http://example.test").unwrap();
        assert_eq!(p.host, "example.test");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn rejects_non_http_url() {
        assert!(matches!(
            parse_http_url("https://x/y"),
            Err(WebhookError::InvalidUrl(_))
        ));
        assert!(matches!(
            parse_http_url("http://"),
            Err(WebhookError::InvalidUrl(_))
        ));
        assert!(matches!(
            parse_http_url("http://h:notaport/x"),
            Err(WebhookError::InvalidUrl(_))
        ));
    }

    #[test]
    fn parses_2xx_status_line() {
        assert_eq!(
            parse_status_code("HTTP/1.1 204 No Content\r\n\r\n").unwrap(),
            204
        );
        assert_eq!(parse_status_code("HTTP/1.1 200 OK\r\n").unwrap(), 200);
    }
}
