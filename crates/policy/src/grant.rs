//! The §14.3 signed, single-use, time-boxed, **proposal-bound** grant token.
//!
//! This is the load-bearing TOCTOU-safe authorization artifact (SPEC §14.3).
//! When a human approves a blocked action, the CLI emits a grant whose
//! signature commits to a **binding hash** over *exactly*:
//!
//! ```text
//! { statement_text, normalized_params, role, session/principal id,
//!   proposal_id, dry_run_lsn, blast_radius_checksum, nonce, expiry }
//! ```
//!
//! At apply time the apply path is *intended* to re-derive the binding hash from
//! the **live** request and re-verify the signature + the single-use nonce + the
//! expiry against the injected [`Clock`]. Any divergence — a swapped statement,
//! swapped prepared params, a replay onto a different session, a reused nonce, or
//! an expired TTL — makes [`GrantToken::verify_for_apply`] **REJECT**. The
//! binding hash is the reason statement-text-plus-blast-radius alone is
//! insufficient (round-3 fix): it pins the *principal* and *session* too,
//! defeating cross-session replay.
//!
//! **Status (S4 — not yet wired into a production apply path).** This token is
//! minted and verified end-to-end *only* in the CLI's in-process approval demo
//! (`pgb_cli::flow`, which calls [`GrantToken::verify_for_apply`]). **No
//! production apply path consumes it yet** — `guarded_apply`
//! (`crates/clone-orchestrator`) has no caller that threads a `GrantToken`
//! through, and the proxy never calls `verify_for_apply`. Wiring the §14.3 grant
//! into the production apply path is **deferred to S5** (#66; blocked on the
//! generic `ApplyConn`, #45). See `docs/spec/SPEC.amendments.md` §S4.
//!
//! Cryptography: Ed25519 via `ed25519-dalek` v2 (BSD-3-Clause). The signed
//! message is the 32-byte SHA-256 binding hash; verification uses
//! `verify_strict` (rejects the small-order / malleable signatures `verify`
//! would accept).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use pgb_core::Clock;

/// The exact set of fields the grant's signature binds to (SPEC §14.3).
///
/// Field order here is **load-bearing**: [`binding_hash`](Self::binding_hash)
/// serializes each field with an explicit length prefix in this fixed order, so
/// the hash is stable across runs/machines and collision-resistant against
/// field-boundary ambiguity (no two distinct field tuples can produce the same
/// byte stream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantBinding {
    /// The exact statement text the approver authorized.
    pub statement_text: String,
    /// The normalized prepared-statement parameters (canonical form), in order.
    pub normalized_params: Vec<String>,
    /// The database role the statement runs as.
    pub role: String,
    /// The session / principal id the grant is bound to (defeats cross-session
    /// replay).
    pub session_id: String,
    /// The proposal id this grant authorizes.
    pub proposal_id: String,
    /// The LSN of the clone the dry-run ran against.
    pub dry_run_lsn: String,
    /// The dry-run affected-PK-set checksum (`"sha256:…"`), from the
    /// blast-radius record (SPEC §10.2).
    pub blast_radius_checksum: String,
    /// A single-use nonce (uniqueness enforced by the verifier's nonce store).
    pub nonce: String,
    /// Expiry as a unix-millis instant; compared against
    /// [`Clock::now_unix_millis`].
    pub expiry_unix_millis: u64,
}

/// A domain separator mixed into the hash so a grant binding can never collide
/// with some other SHA-256 pre-image used elsewhere in the system.
const BINDING_DOMAIN: &[u8] = b"pg_bumpers.grant.binding.v1";

impl GrantBinding {
    /// Compute the canonical, stable, collision-resistant binding hash.
    ///
    /// Each field is absorbed as `len_be_u64 ∥ bytes` (length-prefixed) in a
    /// fixed order, behind a domain-separator. Length-prefixing means a value
    /// like `("ab", "c")` can never serialize to the same bytes as `("a",
    /// "bc")`, so distinct field tuples always yield distinct pre-images.
    pub fn binding_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(BINDING_DOMAIN);

        absorb_str(&mut h, &self.statement_text);
        // The params vector: count, then each element length-prefixed. The
        // count prevents `["a","b"]` colliding with `["ab"]`-style ambiguity.
        h.update((self.normalized_params.len() as u64).to_be_bytes());
        for p in &self.normalized_params {
            absorb_str(&mut h, p);
        }
        absorb_str(&mut h, &self.role);
        absorb_str(&mut h, &self.session_id);
        absorb_str(&mut h, &self.proposal_id);
        absorb_str(&mut h, &self.dry_run_lsn);
        absorb_str(&mut h, &self.blast_radius_checksum);
        absorb_str(&mut h, &self.nonce);
        h.update(self.expiry_unix_millis.to_be_bytes());

        h.finalize().into()
    }

    /// The binding hash in the `"sha256:<hex>"` form for logging / audit.
    pub fn binding_hash_hex(&self) -> String {
        format!("sha256:{}", hex::encode(self.binding_hash()))
    }
}

/// Length-prefix and absorb a string into the hasher.
fn absorb_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

/// A signed grant token (SPEC §14.3).
///
/// Holds the binding and the Ed25519 signature over its [`binding_hash`]. It is
/// inert without the verifier's public key, nonce store, and clock — see
/// [`GrantToken::verify_for_apply`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantToken {
    /// The bound fields.
    pub binding: GrantBinding,
    /// Ed25519 signature over `binding.binding_hash()` (64 bytes, hex-encoded
    /// for transport).
    pub signature_hex: String,
}

impl GrantToken {
    /// Sign a binding with the approver's signing key, producing a token.
    pub fn sign(binding: GrantBinding, signing_key: &SigningKey) -> GrantToken {
        let sig: Signature = signing_key.sign(&binding.binding_hash());
        GrantToken {
            binding,
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify just the **signature** over the current binding (no nonce / clock
    /// checks). Used internally by [`verify_for_apply`](Self::verify_for_apply);
    /// exposed for tests that isolate the cryptographic binding.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), GrantError> {
        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|_| GrantError::MalformedSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| GrantError::MalformedSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            // `verify_strict` rejects malleable / small-order signatures that
            // the plain `verify` would accept.
            .verify_strict(&self.binding.binding_hash(), &sig)
            .map_err(|_| GrantError::BadSignature)
    }

    /// **Re-verify-at-apply** (SPEC §14.3) — the single entry point the
    /// production apply path is *intended* to call at apply time. In S4 the only
    /// caller is the CLI's in-process approval demo (`pgb_cli::flow`); no proxy /
    /// `guarded_apply` call site exists yet (deferred to S5 — #66; see the
    /// module-level note and `docs/spec/SPEC.amendments.md` §S4).
    ///
    /// `live` is the binding re-derived from the *current* request (live
    /// statement text, live prepared params, live session id, the apply-time
    /// blast-radius checksum, …). This must equal the signed binding, the
    /// signature must verify, the nonce must be unused, and the grant must not
    /// be expired against `clock`.
    ///
    /// On success the nonce is **consumed** in `nonces` so a second apply with
    /// the same token is a replay and fails. Fail-closed: every check rejects.
    pub fn verify_for_apply(
        &self,
        live: &GrantBinding,
        verifying_key: &VerifyingKey,
        nonces: &mut dyn NonceStore,
        clock: &dyn Clock,
    ) -> Result<(), GrantError> {
        // 1. Signature over the *signed* binding must be valid. This proves the
        //    binding wasn't tampered with after signing.
        self.verify_signature(verifying_key)?;

        // 2. The live request must match the signed binding **exactly**. A
        //    mismatch is the SQL-swap / param-swap / cross-session / data-drift
        //    family — compare the binding hashes (covers every bound field).
        if live.binding_hash() != self.binding.binding_hash() {
            return Err(GrantError::BindingMismatch);
        }

        // 3. Expiry — read time only through the injected clock (no wall clock).
        let now = clock.now_unix_millis();
        if now >= self.binding.expiry_unix_millis {
            return Err(GrantError::Expired {
                now_unix_millis: now,
                expiry_unix_millis: self.binding.expiry_unix_millis,
            });
        }

        // 4. Single-use — consume the nonce last, so a rejected verify never
        //    burns the nonce. `consume` returns false if already used (replay).
        if !nonces.consume(&self.binding.nonce) {
            return Err(GrantError::ReplayedNonce);
        }

        Ok(())
    }
}

/// A single-use-nonce store. The verifier consumes a nonce exactly once;
/// a repeat consume must fail (replay protection).
///
/// Production backs this with the tamper-evident audit / a durable store; the
/// in-memory [`InMemoryNonceStore`] is for tests and single-process use.
pub trait NonceStore {
    /// Atomically mark `nonce` used. Returns `true` if it was previously unused
    /// (consumption succeeded), `false` if it was already consumed (replay).
    fn consume(&mut self, nonce: &str) -> bool;
}

/// An in-memory [`NonceStore`] (tests / single-process).
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    used: std::collections::HashSet<String>,
}

impl InMemoryNonceStore {
    /// A new, empty nonce store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn consume(&mut self, nonce: &str) -> bool {
        // `insert` returns true if the value was newly inserted.
        self.used.insert(nonce.to_string())
    }
}

/// Why a grant verification failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    /// The signature bytes were not 64 valid hex bytes.
    #[error("malformed signature encoding")]
    MalformedSignature,
    /// The signature did not verify against the binding hash + public key.
    #[error("signature does not verify")]
    BadSignature,
    /// The live request's binding did not match the signed binding (SQL swap,
    /// param swap, cross-session replay, or data drift).
    #[error("grant binding mismatch: the live request differs from what was approved")]
    BindingMismatch,
    /// The nonce was already consumed (single-use violated — replay).
    #[error("grant nonce already used (single-use violated)")]
    ReplayedNonce,
    /// The grant's TTL elapsed.
    #[error("grant expired (now={now_unix_millis}ms >= expiry={expiry_unix_millis}ms)")]
    Expired {
        /// The clock reading at verification time.
        now_unix_millis: u64,
        /// The grant's expiry instant.
        expiry_unix_millis: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::MockClock;
    use rand_core::OsRng;

    /// A deterministic-ish signing key for tests (random per run is fine — the
    /// public key is derived from it within the test).
    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// A representative valid binding, expiring at 10_000ms.
    fn sample_binding() -> GrantBinding {
        GrantBinding {
            statement_text: "UPDATE public.orders SET status='fixed' WHERE id=42".to_string(),
            normalized_params: vec!["42".to_string()],
            role: "app_writer".to_string(),
            session_id: "sess-abc".to_string(),
            proposal_id: "p-001".to_string(),
            dry_run_lsn: "3A/7F00C8".to_string(),
            blast_radius_checksum: "sha256:abc123".to_string(),
            nonce: "nonce-001".to_string(),
            expiry_unix_millis: 10_000,
        }
    }

    /// The happy path: an untampered grant verifies before expiry.
    #[test]
    fn valid_grant_verifies_at_apply() {
        let (sk, vk) = test_keypair();
        let binding = sample_binding();
        let token = GrantToken::sign(binding.clone(), &sk);

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000); // before expiry (10_000)

        let live = binding.clone(); // live request matches exactly
        assert!(token
            .verify_for_apply(&live, &vk, &mut nonces, &clock)
            .is_ok());
    }

    /// T-grant-sql-swap — mutate `statement_text` after signing → REJECT.
    #[test]
    fn t_grant_sql_swap_rejected() {
        let (sk, vk) = test_keypair();
        let token = GrantToken::sign(sample_binding(), &sk);

        // The attacker presents a DIFFERENT statement at apply time.
        let mut live = sample_binding();
        live.statement_text = "DELETE FROM public.orders".to_string();

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let err = token
            .verify_for_apply(&live, &vk, &mut nonces, &clock)
            .unwrap_err();
        assert_eq!(err, GrantError::BindingMismatch);
        // The nonce must NOT have been consumed by a rejected verify.
        assert!(nonces.consume("nonce-001"));
    }

    /// T-grant-param-swap — change `normalized_params` after signing → REJECT.
    #[test]
    fn t_grant_param_swap_rejected() {
        let (sk, vk) = test_keypair();
        let token = GrantToken::sign(sample_binding(), &sk);

        let mut live = sample_binding();
        live.normalized_params = vec!["99".to_string()]; // swapped prepared param

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let err = token
            .verify_for_apply(&live, &vk, &mut nonces, &clock)
            .unwrap_err();
        assert_eq!(err, GrantError::BindingMismatch);
    }

    /// T-grant-cross-session-replay — different session/principal id → REJECT.
    #[test]
    fn t_grant_cross_session_replay_rejected() {
        let (sk, vk) = test_keypair();
        let token = GrantToken::sign(sample_binding(), &sk);

        // Same approved statement + same nonce, but replayed from ANOTHER
        // session. Because session_id is in the binding hash, it mismatches —
        // this is exactly the round-3 reason statement+blast-radius alone is
        // insufficient.
        let mut live = sample_binding();
        live.session_id = "sess-attacker".to_string();

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let err = token
            .verify_for_apply(&live, &vk, &mut nonces, &clock)
            .unwrap_err();
        assert_eq!(err, GrantError::BindingMismatch);
    }

    /// T-grant-replay — reuse the same token twice (nonce reused) → second
    /// REJECT (single-use violated).
    #[test]
    fn t_grant_replay_rejected() {
        let (sk, vk) = test_keypair();
        let binding = sample_binding();
        let token = GrantToken::sign(binding.clone(), &sk);

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);

        // First apply: legitimate, succeeds and consumes the nonce.
        assert!(token
            .verify_for_apply(&binding, &vk, &mut nonces, &clock)
            .is_ok());

        // Second apply with the SAME valid token: replay → REJECT.
        let err = token
            .verify_for_apply(&binding, &vk, &mut nonces, &clock)
            .unwrap_err();
        assert_eq!(err, GrantError::ReplayedNonce);
    }

    /// T-grant-expiry — advance MockClock past the TTL → REJECT.
    #[test]
    fn t_grant_expiry_rejected() {
        let (sk, vk) = test_keypair();
        let binding = sample_binding(); // expiry at 10_000ms
        let token = GrantToken::sign(binding.clone(), &sk);

        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        // Advance the injected clock past the TTL.
        clock.advance(5_000); // now = 10_000 == expiry → expired (>=)

        let err = token
            .verify_for_apply(&binding, &vk, &mut nonces, &clock)
            .unwrap_err();
        match err {
            GrantError::Expired {
                now_unix_millis,
                expiry_unix_millis,
            } => {
                assert_eq!(now_unix_millis, 10_000);
                assert_eq!(expiry_unix_millis, 10_000);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        // Expiry must be checked BEFORE the nonce is burned.
        assert!(nonces.consume("nonce-001"));
    }

    /// A named mutation of one binding field, for the coverage test below.
    type FieldMutation = (&'static str, fn(&mut GrantBinding));

    /// The binding hash must change if **any** bound field changes — a
    /// collision-resistance / completeness check across every field.
    #[test]
    fn binding_hash_covers_every_field() {
        let base = sample_binding();
        let base_h = base.binding_hash();

        let mutators: Vec<FieldMutation> = vec![
            ("statement_text", |b| b.statement_text.push('!')),
            ("normalized_params", |b| {
                b.normalized_params.push("x".into())
            }),
            ("role", |b| b.role.push('!')),
            ("session_id", |b| b.session_id.push('!')),
            ("proposal_id", |b| b.proposal_id.push('!')),
            ("dry_run_lsn", |b| b.dry_run_lsn.push('!')),
            ("blast_radius_checksum", |b| {
                b.blast_radius_checksum.push('!')
            }),
            ("nonce", |b| b.nonce.push('!')),
            ("expiry", |b| b.expiry_unix_millis += 1),
        ];
        for (field, mutate) in mutators {
            let mut m = base.clone();
            mutate(&mut m);
            assert_ne!(
                m.binding_hash(),
                base_h,
                "binding hash did not change when `{field}` changed"
            );
        }
    }

    /// Length-prefixing must prevent field-boundary collisions: moving a
    /// character across a field boundary changes the hash.
    #[test]
    fn binding_hash_is_unambiguous_across_field_boundaries() {
        let mut a = sample_binding();
        a.role = "ab".to_string();
        a.session_id = "c".to_string();

        let mut b = sample_binding();
        b.role = "a".to_string();
        b.session_id = "bc".to_string();

        assert_ne!(
            a.binding_hash(),
            b.binding_hash(),
            "ambiguous field encoding: (ab,c) collided with (a,bc)"
        );
    }

    /// A signature from the WRONG key must not verify (basic crypto sanity).
    #[test]
    fn wrong_key_does_not_verify() {
        let (sk, _vk) = test_keypair();
        let (_sk2, vk2) = test_keypair();
        let token = GrantToken::sign(sample_binding(), &sk);
        assert_eq!(
            token.verify_signature(&vk2).unwrap_err(),
            GrantError::BadSignature
        );
    }

    /// The token + binding round-trip through serde (it is transported as
    /// JSON).
    #[test]
    fn grant_token_round_trips_through_serde() {
        let (sk, _vk) = test_keypair();
        let token = GrantToken::sign(sample_binding(), &sk);
        let json = serde_json::to_string(&token).unwrap();
        let back: GrantToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }
}
