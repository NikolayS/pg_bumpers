//! KMS-backed signing of the audit chain head, **separated from the DB operator**
//! (SPEC §3, §4, §10.9; issue #54, S4).
//!
//! The external anchor is only as trustworthy as the key that signs it. SPEC
//! §10.9 pins the property: the signing key is **KMS-backed, never on the DB
//! host**, and the **audited (DB-operator) principal cannot sign** — otherwise an
//! attacker who owns the database could forge a fresh anchor over their rewritten
//! chain. This module models that seam.
//!
//! # The seam
//! - [`Kms`] — the production-facing trait: given the chain head (`head_hash`,
//!   `seq`, `timestamp`), produce a [`HeadSignature`]; and verify one. A real KMS
//!   (AWS KMS / GCP KMS / Vault transit) implements this with an asymmetric key
//!   whose private half never leaves the HSM — the DB host only ever sees the
//!   *signature*, never the key.
//! - [`LocalKms`] — an in-memory **dev** signer using HMAC-SHA256 over the head.
//!   It is the only impl in the MVP; the trait exists so swapping a real KMS in
//!   later does not touch the anchor logic.
//!
//! # Key separation — enforced at the type level
//! [`LocalKms`] is a *capability*: holding one means you can sign. We make it
//! **unforgeable by the audited principal** structurally:
//! - **no public constructor** takes raw key bytes — the only ways to obtain one
//!   are [`LocalKms::from_secret_store`] / [`LocalKms::for_principal`], which read
//!   the key from the [`crate::secret::SecretStore`] (the operator does not have
//!   the store), and [`for_principal`](LocalKms::for_principal) **rejects the
//!   [`OPERATOR_PRINCIPAL`]**;
//! - **no [`Default`]** — there is no "empty" signer to conjure;
//! - **no `Serialize`/`Deserialize`** — the capability cannot be reconstructed
//!   from attacker-controlled bytes (e.g. a forged config), and the key material
//!   it wraps can never be serialized out.
//!
//! Verification, by contrast, needs only the *public* side. In the HMAC dev impl
//! the same `LocalKms` verifies (symmetric), but the [`Kms::verify_head`] method
//! is the seam a real deployment backs with the **public** key, so any party can
//! check an anchor without the ability to sign.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::secret::{SecretError, SecretStore};

type HmacSha256 = Hmac<Sha256>;

/// The principal label of the **audited DB operator**. This is the role that
/// owns/operates the database — exactly the principal that must NOT be able to
/// obtain the signing capability (SPEC §10.9: "signing key ... never on the DB
/// host"; "audited principal `REVOKE`d from writing audit"). It mirrors the
/// `pgb_agent` audited role named in the audit records.
pub const OPERATOR_PRINCIPAL: &str = "pgb_agent";

/// Errors the KMS seam can surface. Never carries key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KmsError {
    /// The signing capability was requested *as the audited DB-operator
    /// principal*. Denied: the operator must never be able to sign an anchor
    /// (SPEC §10.9). This is the runtime half of key separation.
    #[error("audited/operator principal '{principal}' is denied the audit signing capability")]
    OperatorPrincipalDenied {
        /// The principal that was rejected.
        principal: String,
    },
    /// The signing key could not be loaded from the secret store.
    #[error("kms: {0}")]
    Secret(#[from] SecretError),
}

/// A signature over a chain head: the bytes plus the metadata the verifier needs
/// to recompute what was signed. Carries the **key id** so a deployment that
/// rotates keys can record which key version produced an anchor (old anchors
/// stay verifiable against the matching key version).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeadSignature {
    /// The id of the key that produced this signature (e.g.
    /// [`crate::secret::AUDIT_SIGNING_KEY_ID`]). Lets the verifier select the
    /// matching key/version after a rotation.
    pub key_id: String,
    /// The signature bytes, hex-encoded. In the HMAC dev impl this is
    /// `HMAC-SHA256(key, signing_input(head, seq, ts))`; in production it is an
    /// asymmetric signature over the same input.
    pub signature: String,
}

/// The bytes that get signed: a domain-separated, canonical encoding of the head
/// `(head_hash, seq, timestamp)`. Domain separation (`pgb-audit-anchor:v1`) stops
/// a signature minted for some *other* purpose from being replayed as an anchor.
pub fn head_signing_input(head_hash: &str, seq: u64, timestamp_unix_millis: u64) -> Vec<u8> {
    // Length-prefix the variable field so distinct (head, seq, ts) tuples can
    // never collide into the same signing input.
    let mut v = Vec::with_capacity(head_hash.len() + 48);
    v.extend_from_slice(b"pgb-audit-anchor:v1\0");
    v.extend_from_slice(&(head_hash.len() as u64).to_be_bytes());
    v.extend_from_slice(head_hash.as_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&timestamp_unix_millis.to_be_bytes());
    v
}

/// The KMS signing/verification seam (SPEC §10.9).
///
/// Implementors hold (a handle to) the key. The trait is the only thing the
/// anchor logic depends on, so a real KMS drops in without touching the anchor.
pub trait Kms {
    /// Sign a chain head, returning the [`HeadSignature`].
    fn sign_head(&self, head_hash: &str, seq: u64, timestamp_unix_millis: u64) -> HeadSignature;

    /// Verify a signature over a chain head. Returns `true` iff `sig` was
    /// produced by this key over exactly `(head_hash, seq, timestamp)`.
    fn verify_head(
        &self,
        head_hash: &str,
        seq: u64,
        timestamp_unix_millis: u64,
        sig: &HeadSignature,
    ) -> bool;
}

/// In-memory **dev** KMS signer (HMAC-SHA256). **Not for production.**
///
/// It deliberately has **no** public byte constructor, **no** `Default`, and
/// **no** `Serialize`/`Deserialize`: the only way to get one is to load the key
/// from a [`SecretStore`] the audited operator does not hold (see the module
/// docs). The wrapped key material never leaves this type.
///
/// `Clone` is derived: cloning a capability you *already legitimately hold* does
/// not let an attacker forge a new one (there is still no path from raw bytes to
/// a `LocalKms`), so it is safe and lets a verifier handle be embedded in the
/// WORM anchor. The derived `Debug` is overridden below to redact the key.
#[derive(Clone)]
pub struct LocalKms {
    key_id: String,
    // Private: never exposed, never serialized. The only path that fills it is
    // a secret-store load behind a principal check.
    key: Vec<u8>,
}

impl LocalKms {
    /// Load the audit signing key from the secret store under `key_id`.
    ///
    /// This is the *system* path (proxy/warden boot), which runs as the audit
    /// **writer** identity, not the operator. For the explicit principal-checked
    /// path use [`for_principal`](LocalKms::for_principal).
    pub fn from_secret_store(store: &impl SecretStore, key_id: &str) -> Result<Self, KmsError> {
        let key = store.get(key_id)?;
        Ok(LocalKms {
            key_id: key_id.to_string(),
            key,
        })
    }

    /// Load the signing key **as `principal`**, rejecting the audited
    /// [`OPERATOR_PRINCIPAL`].
    ///
    /// This is the runtime half of key separation: even with access to the
    /// secret store, the audited DB-operator principal is denied the signing
    /// capability ([`KmsError::OperatorPrincipalDenied`]). Any other principal
    /// (the dedicated anchor signer identity) is allowed.
    pub fn for_principal(
        store: &impl SecretStore,
        key_id: &str,
        principal: &str,
    ) -> Result<Self, KmsError> {
        if principal == OPERATOR_PRINCIPAL {
            return Err(KmsError::OperatorPrincipalDenied {
                principal: principal.to_string(),
            });
        }
        Self::from_secret_store(store, key_id)
    }

    /// The id of the key this signer holds.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// A **verifier handle** for this key, suitable to embed alongside published
    /// anchors so any verifier can check signatures.
    ///
    /// In the HMAC dev impl the verifier is symmetric (same key), so this is a
    /// clone — a documented dev limitation. In a production asymmetric KMS this
    /// would return only the *public* key, which cannot sign. Either way the
    /// returned capability is a `Kms` and is used solely through
    /// [`Kms::verify_head`].
    pub fn verifier_handle(&self) -> LocalKms {
        self.clone()
    }
}

impl Kms for LocalKms {
    fn sign_head(&self, head_hash: &str, seq: u64, timestamp_unix_millis: u64) -> HeadSignature {
        let input = head_signing_input(head_hash, seq, timestamp_unix_millis);
        // `new_from_slice` only fails on a bad key length; HMAC accepts any
        // length, so this cannot fail for our material.
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(&input);
        let tag = mac.finalize().into_bytes();
        HeadSignature {
            key_id: self.key_id.clone(),
            signature: hex::encode(tag),
        }
    }

    fn verify_head(
        &self,
        head_hash: &str,
        seq: u64,
        timestamp_unix_millis: u64,
        sig: &HeadSignature,
    ) -> bool {
        // Key id must match (a signature from a different key/version is not
        // valid under this one).
        if sig.key_id != self.key_id {
            return false;
        }
        let Ok(raw) = hex::decode(&sig.signature) else {
            return false;
        };
        let input = head_signing_input(head_hash, seq, timestamp_unix_millis);
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(&input);
        // Constant-time verification via the MAC's own `verify_slice`.
        mac.verify_slice(&raw).is_ok()
    }
}

// A redacting Debug so a `{:?}` of a signer never prints the key bytes.
impl std::fmt::Debug for LocalKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKms")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{AUDIT_SIGNING_KEY_ID, LocalSecretStore, SecretStore};

    fn store_with_key() -> LocalSecretStore {
        let mut s = LocalSecretStore::new();
        s.put(AUDIT_SIGNING_KEY_ID, b"dev-key-material-0001")
            .unwrap();
        s
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let kms = LocalKms::from_secret_store(&store_with_key(), AUDIT_SIGNING_KEY_ID).unwrap();
        let head = "a".repeat(64);
        let sig = kms.sign_head(&head, 7, 1_000);
        assert!(kms.verify_head(&head, 7, 1_000, &sig));
        // Signature is a 32-byte HMAC tag in hex.
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(sig.key_id, AUDIT_SIGNING_KEY_ID);
    }

    #[test]
    fn verify_fails_on_any_field_change() {
        let kms = LocalKms::from_secret_store(&store_with_key(), AUDIT_SIGNING_KEY_ID).unwrap();
        let head = "b".repeat(64);
        let sig = kms.sign_head(&head, 3, 500);
        // Different head / seq / ts all fail.
        assert!(!kms.verify_head(&"c".repeat(64), 3, 500, &sig));
        assert!(!kms.verify_head(&head, 4, 500, &sig));
        assert!(!kms.verify_head(&head, 3, 501, &sig));
    }

    #[test]
    fn verify_fails_on_garbled_signature() {
        let kms = LocalKms::from_secret_store(&store_with_key(), AUDIT_SIGNING_KEY_ID).unwrap();
        let head = "d".repeat(64);
        let mut sig = kms.sign_head(&head, 1, 1);
        sig.signature = "not-hex-zz".to_string();
        assert!(!kms.verify_head(&head, 1, 1, &sig));
        sig.signature = "00".to_string(); // valid hex, wrong length/value
        assert!(!kms.verify_head(&head, 1, 1, &sig));
    }

    #[test]
    fn operator_principal_is_denied() {
        let err =
            LocalKms::for_principal(&store_with_key(), AUDIT_SIGNING_KEY_ID, OPERATOR_PRINCIPAL)
                .unwrap_err();
        assert!(matches!(err, KmsError::OperatorPrincipalDenied { .. }));
        // A non-operator principal is allowed.
        let ok =
            LocalKms::for_principal(&store_with_key(), AUDIT_SIGNING_KEY_ID, "pgb_anchor_signer");
        assert!(ok.is_ok());
    }

    #[test]
    fn missing_key_is_typed_error() {
        let s = LocalSecretStore::new();
        let err = LocalKms::from_secret_store(&s, AUDIT_SIGNING_KEY_ID).unwrap_err();
        assert!(matches!(
            err,
            KmsError::Secret(SecretError::NotFound { .. })
        ));
    }

    #[test]
    fn debug_redacts_key() {
        let kms = LocalKms::from_secret_store(&store_with_key(), AUDIT_SIGNING_KEY_ID).unwrap();
        let dbg = format!("{kms:?}");
        assert!(dbg.contains(AUDIT_SIGNING_KEY_ID));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("dev-key-material"));
    }

    #[test]
    fn signature_under_a_different_key_does_not_verify() {
        let kms1 = LocalKms::from_secret_store(&store_with_key(), AUDIT_SIGNING_KEY_ID).unwrap();
        let mut s2 = LocalSecretStore::new();
        s2.put(AUDIT_SIGNING_KEY_ID, b"a-totally-different-key")
            .unwrap();
        let kms2 = LocalKms::from_secret_store(&s2, AUDIT_SIGNING_KEY_ID).unwrap();
        let head = "e".repeat(64);
        let sig = kms1.sign_head(&head, 9, 9);
        // Same key_id label, different material => verification fails.
        assert!(!kms2.verify_head(&head, 9, 9, &sig));
    }
}
