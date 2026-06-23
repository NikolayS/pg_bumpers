//! The affected-PK-set checksum — the guard's basis (SPEC §10.2).
//!
//! The guarded-write safety property is **not** a row count; it is the set of
//! **primary-key tuples** of every affected row (target + cascade). The dry-run
//! computes this checksum on the clone; the apply recomputes it inside the same
//! txn and **ABORTs on any mismatch**. That catches *row-identity drift* — the
//! count-only blind spot where the same number of rows is affected but they are
//! *different* rows (the headline correctness property here).
//!
//! Design points pinned by the tests:
//!
//! - **Typed, not stringly.** Each PK column value carries its type
//!   ([`PkValue`]), so `Int(1)` and `Text("1")` never collide. Values are
//!   encoded with a type tag + length prefix before hashing.
//! - **Composite PK = ordered typed tuple** ([`PkTuple`]). Column order within a
//!   tuple is significant; the *set* of tuples is order-independent.
//! - **Order-independent over rows.** The same rows in any order produce the
//!   same checksum (tuples are canonically sorted before hashing).
//! - **PK-less / no-replica-identity ⇒ REFUSED.** We never fall back to `ctid`
//!   (unsafe across the dry-run/apply boundary); the builder returns a typed
//!   [`ChecksumError::Refused`] instead.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// A single typed primary-key column value (SPEC §10.2 "sorted, typed").
///
/// The type tag is part of the canonical encoding, so two values that print the
/// same but have different types (e.g. the integer `1` and the text `"1"`)
/// produce **different** checksums. This is essential: a drift that swaps an
/// integer key for a text key with the same digits must not be masked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PkValue {
    /// A signed integer key (`smallint`/`int`/`bigint`).
    Int(i64),
    /// A textual key (`text`/`varchar`/`uuid`-as-text/etc.).
    Text(String),
    /// An opaque byte-string key (`bytea`, or a `uuid` in binary form).
    Bytes(Vec<u8>),
    /// A SQL `NULL` appearing in a key position (rare, but representable so it
    /// is never silently conflated with a missing column).
    Null,
}

impl PkValue {
    /// One-byte type tag used in the canonical encoding. Distinct per variant so
    /// values of different types can never produce identical bytes.
    const fn tag(&self) -> u8 {
        match self {
            PkValue::Int(_) => 0x01,
            PkValue::Text(_) => 0x02,
            PkValue::Bytes(_) => 0x03,
            PkValue::Null => 0x00,
        }
    }

    /// Append this value's canonical, self-delimiting byte encoding to `out`.
    ///
    /// Encoding = `tag ‖ u32_le(len) ‖ payload`. The length prefix makes the
    /// encoding unambiguous (no two different value sequences share a byte
    /// string), so concatenating tuple components is collision-free.
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            PkValue::Int(v) => {
                let bytes = v.to_be_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&bytes);
            }
            PkValue::Text(s) => {
                let bytes = s.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            PkValue::Bytes(b) => {
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            PkValue::Null => {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }
}

/// An ordered, typed primary-key tuple for one row (SPEC §10.2 composite PK).
///
/// For a single-column PK this holds one value; for a composite PK it holds the
/// key columns **in PK definition order** (column order is significant). A tuple
/// must be non-empty — an empty tuple means "no PK", which is refused at the
/// builder level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PkTuple(Vec<PkValue>);

impl PkTuple {
    /// Build a tuple from ordered key column values.
    ///
    /// Returns [`ChecksumError::EmptyTuple`] if `values` is empty — a row with
    /// no key columns cannot be safely identified across the dry-run/apply
    /// boundary.
    pub fn new(values: Vec<PkValue>) -> Result<Self, ChecksumError> {
        if values.is_empty() {
            return Err(ChecksumError::EmptyTuple);
        }
        Ok(PkTuple(values))
    }

    /// Convenience constructor for a single-column PK.
    pub fn single(value: PkValue) -> Self {
        PkTuple(vec![value])
    }

    /// The ordered key column values.
    pub fn values(&self) -> &[PkValue] {
        &self.0
    }

    /// Append the tuple's canonical encoding to `out`: a count-prefixed,
    /// length-delimited sequence of its component encodings.
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        for value in &self.0 {
            value.encode_into(out);
        }
    }
}

/// The computed checksum over an affected-PK set (SPEC §10.2).
///
/// Wraps the lowercase hex digest. [`Display`](std::fmt::Display) and
/// [`as_prefixed`](PkChecksum::as_prefixed) render the `"sha256:…"` form that
/// goes into the [`BlastRadius`](crate::blast_radius::BlastRadius) record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PkChecksum {
    hex: String,
}

impl PkChecksum {
    /// The bare lowercase hex digest (64 chars).
    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    /// The `"sha256:<hex>"` form used in the blast-radius record.
    pub fn as_prefixed(&self) -> String {
        format!("sha256:{}", self.hex)
    }
}

impl std::fmt::Display for PkChecksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

/// Reasons a PK-set checksum cannot be computed (SPEC §10.2 — refuse, never
/// silently fall back to `ctid`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChecksumError {
    /// The relation has no usable primary key / replica identity, so affected
    /// rows cannot be safely identified across the dry-run/apply boundary.
    /// **Refuse the write** — do not fall back to `ctid` (unsafe: `ctid`
    /// changes on `VACUUM`/`UPDATE`).
    #[error(
        "refused: relation `{relation}` has no usable primary key / replica identity; writes to PK-less tables are refused (no ctid fallback)"
    )]
    Refused {
        /// `schema.table` that was refused.
        relation: String,
    },
    /// A tuple was constructed with no key columns.
    #[error("a primary-key tuple must have at least one column")]
    EmptyTuple,
    /// A tuple was added whose arity differs from the others in the set — a sign
    /// the PK definition was misread; refuse rather than hash inconsistently.
    #[error("inconsistent PK arity: expected {expected} columns, got {actual}")]
    InconsistentArity {
        /// Arity established by the first tuple.
        expected: usize,
        /// Arity of the offending tuple.
        actual: usize,
    },
}

/// Accumulates the affected PK tuples for one relation, then finalizes them to a
/// [`PkChecksum`] (SPEC §10.2).
///
/// Usage: create with [`for_relation`](PkSetBuilder::for_relation), push each
/// affected row's [`PkTuple`], then call [`finalize`](PkSetBuilder::finalize).
/// A builder created with [`pk_less`](PkSetBuilder::pk_less) refuses on
/// finalize, modeling a PK-less / no-replica-identity table.
#[derive(Debug, Clone)]
pub struct PkSetBuilder {
    relation: String,
    /// `None` until the first tuple is pushed; then the established arity.
    arity: Option<usize>,
    tuples: Vec<PkTuple>,
    /// Set when the relation is known to be PK-less; finalize then refuses.
    pk_less: bool,
}

impl PkSetBuilder {
    /// Start collecting affected PK tuples for `relation` (a `schema.table`).
    pub fn for_relation(relation: impl Into<String>) -> Self {
        PkSetBuilder {
            relation: relation.into(),
            arity: None,
            tuples: Vec::new(),
            // A relation with a usable PK; `finalize` will hash rather than refuse.
            pk_less: false,
        }
    }

    /// Model a PK-less / no-replica-identity relation: [`finalize`] will return
    /// [`ChecksumError::Refused`] (SPEC §10.2 negative case).
    pub fn pk_less(relation: impl Into<String>) -> Self {
        PkSetBuilder {
            relation: relation.into(),
            arity: None,
            tuples: Vec::new(),
            pk_less: true,
        }
    }

    /// Add one affected row's PK tuple. Returns
    /// [`ChecksumError::InconsistentArity`] if its arity differs from earlier
    /// tuples.
    pub fn push(&mut self, tuple: PkTuple) -> Result<&mut Self, ChecksumError> {
        let arity = tuple.values().len();
        match self.arity {
            None => self.arity = Some(arity),
            Some(expected) if expected != arity => {
                return Err(ChecksumError::InconsistentArity {
                    expected,
                    actual: arity,
                });
            }
            Some(_) => {}
        }
        self.tuples.push(tuple);
        Ok(self)
    }

    /// Number of affected tuples collected so far.
    pub fn len(&self) -> usize {
        self.tuples.len()
    }

    /// Whether no tuples have been collected.
    pub fn is_empty(&self) -> bool {
        self.tuples.is_empty()
    }

    /// Canonicalize (sort the tuple set) and hash to a [`PkChecksum`].
    ///
    /// - PK-less relation ⇒ [`ChecksumError::Refused`] (no `ctid` fallback).
    /// - Sorting makes the checksum **order-independent** over rows.
    /// - The relation name is **not** hashed in, so two relations with the same
    ///   affected PK set produce the same per-table checksum (the
    ///   blast-radius keys by relation separately).
    pub fn finalize(mut self) -> Result<PkChecksum, ChecksumError> {
        if self.pk_less {
            return Err(ChecksumError::Refused {
                relation: self.relation,
            });
        }

        // Canonicalize the *set*: sort the tuples by their typed ordering so any
        // input ordering collapses to one byte stream. (Duplicate PKs would be a
        // bug upstream; we keep them — a multiset — so an accidental double-touch
        // changes the checksum rather than being hidden.)
        self.tuples.sort();

        let mut hasher = Sha256::new();
        // Domain-separate + commit to cardinality so a different number of rows
        // can never collide with a reordering.
        hasher.update(b"pgb-pkset-v1\0");
        hasher.update((self.tuples.len() as u64).to_le_bytes());

        let mut buf = Vec::new();
        for tuple in &self.tuples {
            buf.clear();
            tuple.encode_into(&mut buf);
            // Length-prefix each tuple's bytes so tuple boundaries are
            // unambiguous in the concatenated stream.
            hasher.update((buf.len() as u64).to_le_bytes());
            hasher.update(&buf);
        }

        Ok(PkChecksum {
            hex: hex::encode(hasher.finalize()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a checksum from single-column integer PKs (test helper).
    fn checksum_of_ints(rel: &str, ids: &[i64]) -> PkChecksum {
        let mut b = PkSetBuilder::for_relation(rel);
        for &id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().unwrap()
    }

    #[test]
    fn same_rows_different_order_same_checksum() {
        // Order-independence over rows: the *set* is what matters.
        let a = checksum_of_ints("public.orders", &[1, 2, 3, 4, 5]);
        let b = checksum_of_ints("public.orders", &[5, 3, 1, 4, 2]);
        assert_eq!(a, b, "row order must not change the checksum");
    }

    /// HEADLINE: the count-only blind spot. Same cardinality, different PKs ⇒
    /// **different** checksum. A row count cannot catch this; the checksum must.
    #[test]
    fn same_cardinality_different_pks_different_checksum() {
        let original = checksum_of_ints("public.orders", &[1, 2, 3, 4, 5]);
        // Same number of rows (5), but row id 5 drifted to id 6.
        let drifted = checksum_of_ints("public.orders", &[1, 2, 3, 4, 6]);
        assert_ne!(
            original, drifted,
            "row-identity drift with identical count must change the checksum"
        );
    }

    #[test]
    fn over_and_under_count_change_the_checksum() {
        let base = checksum_of_ints("public.orders", &[1, 2, 3]);
        let over = checksum_of_ints("public.orders", &[1, 2, 3, 4]);
        let under = checksum_of_ints("public.orders", &[1, 2]);
        assert_ne!(base, over);
        assert_ne!(base, under);
        assert_ne!(over, under);
    }

    #[test]
    fn typed_values_do_not_collide_int_vs_text() {
        // Int(1) and Text("1") must NOT produce the same checksum.
        let as_int = checksum_of_ints("t", &[1]);
        let mut tb = PkSetBuilder::for_relation("t");
        tb.push(PkTuple::single(PkValue::Text("1".into()))).unwrap();
        let as_text = tb.finalize().unwrap();
        assert_ne!(
            as_int, as_text,
            "integer 1 and text \"1\" must hash differently"
        );
    }

    #[test]
    fn composite_pk_is_an_ordered_tuple() {
        // (1, "a") differs from ("a", 1)-shaped swap and from (2, "a").
        let mut a = PkSetBuilder::for_relation("public.parts");
        a.push(PkTuple::new(vec![PkValue::Int(1), PkValue::Text("a".into())]).unwrap())
            .unwrap();
        let cs_a = a.finalize().unwrap();

        let mut b = PkSetBuilder::for_relation("public.parts");
        b.push(PkTuple::new(vec![PkValue::Int(2), PkValue::Text("a".into())]).unwrap())
            .unwrap();
        let cs_b = b.finalize().unwrap();
        assert_ne!(cs_a, cs_b);

        // Column order within the tuple is significant: (1,"a") != ("a"-ish).
        let mut c = PkSetBuilder::for_relation("public.parts");
        c.push(PkTuple::new(vec![PkValue::Text("a".into()), PkValue::Int(1)]).unwrap())
            .unwrap();
        let cs_c = c.finalize().unwrap();
        assert_ne!(
            cs_a, cs_c,
            "swapping composite-key column order must differ"
        );
    }

    #[test]
    fn composite_set_is_order_independent_over_rows() {
        let rows1 = vec![
            PkTuple::new(vec![PkValue::Int(1), PkValue::Text("x".into())]).unwrap(),
            PkTuple::new(vec![PkValue::Int(2), PkValue::Text("y".into())]).unwrap(),
        ];
        let rows2 = vec![
            PkTuple::new(vec![PkValue::Int(2), PkValue::Text("y".into())]).unwrap(),
            PkTuple::new(vec![PkValue::Int(1), PkValue::Text("x".into())]).unwrap(),
        ];
        let mut a = PkSetBuilder::for_relation("r");
        for t in rows1 {
            a.push(t).unwrap();
        }
        let mut b = PkSetBuilder::for_relation("r");
        for t in rows2 {
            b.push(t).unwrap();
        }
        assert_eq!(a.finalize().unwrap(), b.finalize().unwrap());
    }

    #[test]
    fn pk_less_relation_is_refused_not_ctid_fallback() {
        let err = PkSetBuilder::pk_less("public.event_log")
            .finalize()
            .unwrap_err();
        match err {
            ChecksumError::Refused { relation } => {
                assert_eq!(relation, "public.event_log");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn empty_tuple_is_rejected() {
        assert_eq!(PkTuple::new(vec![]).unwrap_err(), ChecksumError::EmptyTuple);
    }

    #[test]
    fn inconsistent_arity_is_rejected() {
        let mut b = PkSetBuilder::for_relation("r");
        b.push(PkTuple::single(PkValue::Int(1))).unwrap();
        let err = b
            .push(PkTuple::new(vec![PkValue::Int(1), PkValue::Int(2)]).unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            ChecksumError::InconsistentArity {
                expected: 1,
                actual: 2
            }
        );
    }

    #[test]
    fn checksum_is_stable_and_well_formed() {
        // Determinism across runs and the `sha256:` rendering.
        let a = checksum_of_ints("r", &[10, 20, 30]);
        let b = checksum_of_ints("r", &[30, 20, 10]);
        assert_eq!(a.as_hex().len(), 64);
        assert!(a.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a.as_prefixed(), format!("sha256:{}", a.as_hex()));
        assert_eq!(a.to_string(), a.as_prefixed());
        assert_eq!(a, b);
    }

    #[test]
    fn empty_affected_set_is_a_valid_distinct_checksum() {
        // Zero affected rows is legitimate (a no-op write) and must be stable
        // and distinct from any non-empty set.
        let empty = PkSetBuilder::for_relation("r").finalize().unwrap();
        let one = checksum_of_ints("r", &[1]);
        assert_ne!(empty, one);
        let empty2 = PkSetBuilder::for_relation("r").finalize().unwrap();
        assert_eq!(empty, empty2);
    }

    #[test]
    fn null_in_key_position_is_distinct() {
        let mut a = PkSetBuilder::for_relation("r");
        a.push(PkTuple::single(PkValue::Null)).unwrap();
        let mut b = PkSetBuilder::for_relation("r");
        b.push(PkTuple::single(PkValue::Text(String::new())))
            .unwrap();
        // NULL must not collide with empty text.
        assert_ne!(a.finalize().unwrap(), b.finalize().unwrap());
    }
}
