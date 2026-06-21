//! Tamper-evident audit for pg_bumpers.
//!
//! Append-only, hash-chained records live in the `_meta` DB and the chain head
//! is anchored externally (WORM / transparency log) with a separated signing key
//! (SPEC §4). The audited principal cannot rewrite the audit. This S0 crate
//! provides a minimal, deterministic chain-link hash so the seam exists and is
//! tested; the full chain and anchor land later.

/// A simple, deterministic FNV-1a hash used to link audit records into a chain.
///
/// This is a placeholder digest for the S0 seam — the production chain uses a
/// cryptographic hash. The property tested here is determinism and chaining:
/// linking the same `(prev, payload)` always yields the same value.
pub fn chain_link(prev: u64, payload: &[u8]) -> u64 {
    // FNV-1a over prev-bytes then payload, so each link depends on the last.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in prev.to_le_bytes().iter().chain(payload.iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_link_is_deterministic() {
        assert_eq!(chain_link(0, b"first"), chain_link(0, b"first"));
    }

    #[test]
    fn chain_link_depends_on_predecessor() {
        // Tampering with a prior link changes every downstream link.
        let a = chain_link(0, b"record");
        let b = chain_link(a, b"record");
        assert_ne!(a, b);
        assert_ne!(chain_link(1, b"record"), chain_link(2, b"record"));
    }
}
