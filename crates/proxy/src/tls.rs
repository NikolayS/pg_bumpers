//! TLS on the agent-facing listener (SPEC §7 S1 "SCRAM auth + TLS").
//!
//! The proxy is the trust boundary the agent connects to, so the agent endpoint
//! is TLS-terminated with `rustls` (Apache-2.0/MIT/ISC — keeps `cargo deny`
//! green; `ring` crypto provider). PostgreSQL's TLS is *negotiated*: the client
//! sends an `SSLRequest` (a magic untagged frame) and the server answers with a
//! single byte `S` (use TLS) or `N` (plaintext) **before** the TLS handshake.
//! The session loop ([`crate::session`]) handles that one-byte negotiation and
//! **enforces the `require_tls` posture** — when TLS is configured it is
//! required: answer `'S'` and upgrade, reject a direct cleartext
//! `StartupMessage`, never silently downgrade to `'N'`, and verify the stream is
//! encrypted before auth. This module just builds the `ServerConfig` from the
//! configured PEM material.
//!
//! PEM is parsed via `rustls-pki-types`' [`PemObject`] (the maintained home of
//! the parser that used to live in the now-unmaintained `rustls-pemfile`,
//! RUSTSEC-2025-0134).

use std::io;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::TlsConfig;

/// Build a `rustls` server config from the configured cert + key PEM files.
///
/// Fail-closed: a missing/empty cert or an unparseable key is a hard error — the
/// proxy will not fall back to plaintext when TLS was requested.
pub fn server_config(cfg: &TlsConfig) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(&cfg.cert_pem)?;
    let key = load_key(&cfg.key_pem)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad TLS material: {e}"))
        })?;
    Ok(Arc::new(config))
}

fn load_certs(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(pem_err)?
        .collect::<Result<_, _>>()
        .map_err(pem_err)?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", path.display()),
        ));
    }
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(pem_err)
}

/// Map a PEM parse error to an `io::Error` (fail-closed, no plaintext fallback).
fn pem_err(e: rustls::pki_types::pem::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("PEM parse error: {e}"))
}
