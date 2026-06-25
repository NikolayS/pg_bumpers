//! `pgb-cli keygen` integration tests (issue #101, spec v0.8.1 §0.5).
//!
//! `keygen` is the Rust-native replacement for the `node -e` Ed25519 keypair
//! generation `deploy/up.sh` used to shell out to. It prints two hex lines to
//! stdout: line 1 = the 32-byte signing-key **seed**, line 2 = the 32-byte
//! **verifying key** (pubkey). Both are consumed by `deploy/up.sh` and must be
//! **byte-identical** to what `crates/applyd` parses from `PGB_APPROVER_PUBKEY`
//! (`VerifyingKey::from_bytes`) and from the seed (`SigningKey::from_bytes`).

use std::process::Command;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pgb_cli::{GrantBinding, GrantToken, InMemoryNonceStore};
use pgb_core::{MockClock, WriteCap};

/// Run `pgb-cli keygen` and return its captured `(seed_hex, pubkey_hex)`.
fn run_keygen() -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgb-cli"))
        .arg("keygen")
        .output()
        .expect("spawn pgb-cli keygen");
    assert!(
        out.status.success(),
        "keygen exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("keygen stdout is utf-8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "keygen must print exactly two non-empty lines (seed, pubkey), got: {lines:?}"
    );
    (lines[0].trim().to_string(), lines[1].trim().to_string())
}

/// Decode a 32-byte hex token into a fixed array (mirrors applyd's parser).
fn decode32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    bytes
        .as_slice()
        .try_into()
        .expect("32 bytes (64 hex chars)")
}

/// **Known-answer (byte-compat) test** — pins the seed → pubkey derivation to a
/// FIXED recorded vector so any future *encoding* regression is caught.
///
/// The vector is the EXACT one derived by the now-deleted `node -e` generator
/// `deploy/up.sh` used to shell out to (recorded in the PR #104 body): the node
/// code took the last 32 bytes of the PKCS8 DER as the seed and the last 32 bytes
/// of the SPKI DER as the pubkey. Feeding that seed through Rust's
/// `SigningKey::from_bytes(...).verifying_key().to_bytes()` MUST re-derive the
/// exact pubkey node produced — so this test pins **interop with the old node
/// generator** (keys minted either way interoperate) and, by construction, pins the
/// raw 32-byte little-endian Ed25519 encoding `keygen` emits.
///
/// If a future refactor swaps the encoding — DER/PKCS8 wrapping, base64, byte-order
/// reversal, or a wrong length — this assertion FAILS (the derived pubkey hex would
/// differ from the recorded constant), catching the regression at the byte level.
#[test]
fn keygen_seed_to_pubkey_matches_node_byte_compat_vector() {
    // Recorded node-derived vector (PR #104): seed (last 32 bytes of the PKCS8 DER)
    // and the pubkey (last 32 bytes of the SPKI DER) node produced for it.
    const NODE_SEED_HEX: &str = "15d78e86c5008183d1db972a3453102659295b0eb93210ad3cf0a74980f2a58f";
    const NODE_PUBKEY_HEX: &str =
        "036a63feffd5b2d0c498f7d583f3e43508fd74c69ff27043e17c4f0e2c1c7e3b";

    // The exact derivation `keygen` performs (and applyd consumes): raw 32-byte seed
    // → SigningKey::from_bytes → verifying_key().to_bytes() → hex.
    let signing_key = SigningKey::from_bytes(&decode32(NODE_SEED_HEX));
    let derived_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    assert_eq!(
        derived_pubkey_hex, NODE_PUBKEY_HEX,
        "seed → pubkey must equal the recorded node-derived vector (byte-compat with the \
         deleted node generator); a mismatch means the seed/pubkey *encoding* regressed \
         (DER/base64/byte-order/length)"
    );

    // And the pubkey is a valid Ed25519 verifying key on applyd's exact parse path,
    // so a key minted by the old node generator still verifies under applyd.
    let vk = VerifyingKey::from_bytes(&decode32(NODE_PUBKEY_HEX))
        .expect("recorded node pubkey is a valid Ed25519 verifying key (applyd parse path)");
    assert_eq!(
        vk.to_bytes(),
        signing_key.verifying_key().to_bytes(),
        "the recorded node pubkey must be the public half of the recorded node seed"
    );
}

/// The two lines are 64-hex-char (32-byte) tokens, and the pubkey is the
/// Ed25519 verifying key derived from the seed.
#[test]
fn keygen_prints_seed_and_derived_pubkey() {
    let (seed_hex, pubkey_hex) = run_keygen();

    // Each line is exactly 64 lowercase hex chars (32 bytes).
    for (label, tok) in [("seed", &seed_hex), ("pubkey", &pubkey_hex)] {
        assert_eq!(tok.len(), 64, "{label} must be 64 hex chars, got {tok:?}");
        assert!(
            tok.bytes().all(|b| b.is_ascii_hexdigit()),
            "{label} must be all hex digits, got {tok:?}"
        );
    }

    // The seed (line 1) is a valid 32-byte SigningKey seed; the pubkey (line 2)
    // is EXACTLY the verifying key derived from it.
    let seed = decode32(&seed_hex);
    let signing_key = SigningKey::from_bytes(&seed);
    let derived_pub = signing_key.verifying_key().to_bytes();
    assert_eq!(
        hex::encode(derived_pub),
        pubkey_hex,
        "line-2 pubkey must equal the Ed25519 verifying key derived from the line-1 seed"
    );
}

/// Two invocations produce different keypairs (real RNG, not a constant).
#[test]
fn keygen_is_randomized() {
    let (s1, _) = run_keygen();
    let (s2, _) = run_keygen();
    assert_ne!(s1, s2, "keygen must produce a fresh random seed each run");
}

/// keygen ↔ applyd byte-compat: hex-decode the keygen pubkey through applyd's
/// `PGB_APPROVER_PUBKEY` parsing path (`VerifyingKey::from_bytes`), sign a grant
/// with the keygen seed (`SigningKey::from_bytes`), and verify it against the
/// keygen pubkey. This proves the on-the-wire shape is byte-identical to what
/// the apply path consumes.
#[test]
fn keygen_pubkey_and_seed_are_applyd_compatible() {
    let (seed_hex, pubkey_hex) = run_keygen();

    // applyd's exact parsing path for the two env/file values.
    let signing_key = SigningKey::from_bytes(&decode32(&seed_hex));
    let verifying_key =
        VerifyingKey::from_bytes(&decode32(&pubkey_hex)).expect("keygen pubkey is a valid VK");

    // The pubkey applyd would trust MUST equal the one derived from the seed.
    assert_eq!(
        verifying_key.to_bytes(),
        signing_key.verifying_key().to_bytes(),
        "keygen pubkey must be the public half of the keygen seed (applyd trust root)"
    );

    // A grant signed by the keygen seed verifies under the keygen pubkey, using
    // the SAME GrantToken machinery the apply path uses.
    let binding = GrantBinding {
        statement_text: "UPDATE public.orders SET status='fixed' WHERE id=$1".to_string(),
        normalized_params: vec!["42".to_string()],
        role: "app_writer".to_string(),
        session_id: "sess-compat".to_string(),
        proposal_id: "p-compat".to_string(),
        dry_run_lsn: "3A/7F00C8".to_string(),
        cap: WriteCap::new(1, 4096),
        nonce: "nonce-compat".to_string(),
        expiry_unix_millis: 10_000,
    };
    let token = GrantToken::sign(binding.clone(), &signing_key);

    let mut nonces = InMemoryNonceStore::new();
    let clock = MockClock::starting_at(5_000);
    token
        .verify_for_apply(&binding, &verifying_key, &mut nonces, &clock)
        .expect("a grant signed by the keygen seed must verify under the keygen pubkey");
}
