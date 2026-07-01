//! Fuzz the **read-only SQL classifier** (SPEC §4 — the advisory, fail-closed
//! read-only gate).
//!
//! Two invariants under test:
//!
//! 1. **Never panics.** `classify`/`classify_with_reason` over arbitrary UTF-8
//!    must always return, never crash (it parses hostile SQL via sqlparser).
//!
//! 2. **The safety invariant has teeth.** The classifier is a *tighten-only*
//!    safety control: a write / DDL / multi-statement input must **never** be
//!    classified as a safe single `Read`. We assert this two ways:
//!      a. If the classifier ever says `Read`, the reason is `None` and a
//!         re-classification is stable (`Read` is deterministic).
//!      b. We synthesize inputs we KNOW are genuinely two statements — by
//!         appending a stacked write statement (`; DROP TABLE …` / `; CREATE …`
//!         etc.) onto a base that is *itself* a clean single `Read` — and assert
//!         the classifier NEVER returns `Read` for the result. This is the
//!         property a deliberately-broken classifier (one that classifies a
//!         `DROP` as a read) would fail, proving the target's teeth.
//!
//! The fuzzer drives both: it controls the base SQL text AND which unsafe
//! suffix to append.
//!
//! ## Oracle correctness — why the stack uses a newline and a base guard
//!
//! Naively building the stacked input as `format!("{base} ; {tail}")` and
//! asserting it is never `Read` is **unsound**: SQL text that ends *mid-token*
//! swallows whatever we append, so the "stacked write" never actually becomes a
//! second statement. Concretely:
//!
//!   * a base ending in an **unterminated `--` line comment** (e.g. the fuzz
//!     base `VALUES (1)--\x05`) comments out a ` ; CREATE TABLE …` tail entirely
//!     — the whole thing is one legitimate read, so `classify` correctly returns
//!     `Read` and the naive oracle false-fails;
//!   * the same swallowing happens for a base ending in an **open `/* … */`
//!     block comment**, an **open string literal** (`SELECT 'oops`), or an
//!     **open dollar-quote** (`SELECT $$oops`) — all of which consume the tail.
//!
//! The classifier is byte-for-byte faithful to PostgreSQL here (only `\n`/`\r`
//! terminate a `--` comment; an open block-comment/string/dollar-quote runs to
//! its closer), so the bug is in the *oracle*, not the classifier. We fix the
//! oracle two ways, belt-and-braces:
//!
//!   1. **Separate the tail with a real newline** (`"{base}\n; {tail}"`). A `\n`
//!      ends a `--` comment, so an unterminated-line-comment base can no longer
//!      swallow the appended write.
//!   2. **Only assert the stacked invariant when `base` is itself a clean single
//!      `Read`.** If `classify(base) == Read`, the base parsed to exactly one
//!      read statement with no dangling open comment/string/dollar-quote (those
//!      all classify `NotRead`/`ParseError`), so appending `\n; <write>` is
//!      *genuinely* a second statement. This ties the oracle to the actual
//!      statement structure rather than to the syntactic presence of `;`+tail.
//!
//! Together these make 2b assert the real invariant — "a genuinely-stacked write
//! must never classify as a safe read" — with no false positives. The bare-tail
//! assertion (a lone write must be `NotRead`) is unconditional and unaffected.
//!
//! ## M2a (#114) — the stacking oracle is unchanged and STILL sound
//!
//! M2a tightened the classifier so a `SELECT` is `Read` only if every function it
//! references is on a curated read-safe allowlist (non-allowlisted function calls
//! — `lo_create`/`setval`/`pg_read_file`/`public.writing_fn()`/… — are now
//! `NotRead`). This oracle NEVER assumed function-bearing SELECTs are `Read`; it
//! only asserts the *tighten-only* safety direction — that writes / DDL / genuine
//! statement-stacks are NEVER `Read`. Making MORE inputs `NotRead` can only
//! REINFORCE those assertions, never break them (invariant 2a's determinism and
//! reason-freeness of `Read` also still hold: `Read` is still returned only for a
//! provable single read, now a stricter set). So no oracle change is needed for
//! the stacking teeth; the target keeps them against a classifier that would
//! wrongly admit a write.
//!
//! ## #115 fix round — new positive teeth for the operator/lock classes
//!
//! The #115 review found three more side-effecting-SELECT classes the classifier
//! must reject: a **qualified/custom operator** (`a OPERATOR(public.writeop) b` —
//! an arbitrary backing function), a **schema-qualified (non-builtin) cast**
//! (`x::public.evil` — a type input function), and a **`FOR UPDATE`/`FOR SHARE`
//! row lock** (real locks on the primary). Invariant 2c below adds UNCONDITIONAL
//! teeth for the operator and lock classes (a fixed corpus of poison SELECTs that
//! must never be `Read`), so a future regression that reopened one of them would
//! fail the fuzzer here rather than ship.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgb_pgwire::{Classification, classify, classify_with_reason};

/// Statements that are unambiguously NOT a safe single read. Appending any of
/// these (statement-stacked, newline-separated) onto a base that is itself a
/// clean single read yields input the classifier must reject — as a write, a
/// multi-statement, or a parse error. Never as `Read`.
const UNSAFE_TAILS: &[&str] = &[
    "DROP TABLE users",
    "DELETE FROM accounts",
    "UPDATE accounts SET balance = 0",
    "INSERT INTO logs VALUES (1)",
    "TRUNCATE audit",
    "CREATE TABLE t (id int)",
    "ALTER TABLE t ADD COLUMN c int",
    "GRANT ALL ON t TO public",
    "COPY t FROM PROGRAM 'sh'",
];

/// Single `SELECT` statements that are NOT a safe read even though they parse as
/// a lone SELECT — the #115 fix classes. A **qualified/custom operator** invokes
/// an arbitrary backing function (incl. a SECURITY DEFINER write), and a
/// **`FOR UPDATE`/`FOR SHARE` row-lock** clause takes real locks on the primary
/// (a lock-DoS side effect). The classifier must NEVER return `Read` for any of
/// these — the same tighten-only teeth we assert for writes/DDL/stacks, extended
/// to the side-effecting-SELECT classes so a future regression on operators or
/// locks is caught by the fuzzer, not shipped. Asserted UNCONDITIONALLY.
const SIDE_EFFECTING_SELECTS: &[&str] = &[
    // Qualified / custom operator in every expression position.
    "SELECT a OPERATOR(public.writeop) b FROM t",
    "SELECT * FROM t WHERE a OPERATOR(public.wop) b",
    "SELECT a FROM t GROUP BY a HAVING count(*) OPERATOR(public.wop) 0",
    "SELECT a FROM t ORDER BY a OPERATOR(public.wop) b",
    "WITH w AS (SELECT a OPERATOR(public.wop) b AS c FROM t) SELECT * FROM w",
    "SELECT (SELECT a OPERATOR(public.wop) b FROM t)",
    // `FOR UPDATE` / `FOR SHARE` row locks (incl. buried in a subquery/CTE).
    "SELECT * FROM t FOR UPDATE",
    "SELECT * FROM t FOR SHARE",
    "SELECT * FROM t FOR UPDATE NOWAIT",
    "SELECT * FROM (SELECT id FROM t FOR UPDATE) sub",
    "WITH w AS (SELECT id FROM t FOR SHARE) SELECT * FROM w",
];

// A non-fuzz, CI-run regression harness for this exact oracle (the known
// false-positive bytes + real-stacked-write teeth) lives in the workspace test
// `crates/pgwire/tests/classifier.rs`, which `cargo test --workspace` runs on
// the pinned stable toolchain. We deliberately do NOT add `#[cfg(test)]` units
// here: this `[[bin]]` is `test = false` (libFuzzer convention — its `main` is
// the libFuzzer entrypoint, so `cargo test` would *run the fuzzer*, not Rust
// unit tests), so any in-file tests would be dead code that never executes.
fuzz_target!(|data: &[u8]| {
    // Need valid UTF-8 to feed &str; non-UTF-8 inputs are simply skipped (the
    // classifier only ever sees decoded protocol strings, which are UTF-8).
    let Ok(base) = std::str::from_utf8(data) else {
        return;
    };

    // --- Invariant 1: never panic on arbitrary SQL. ---
    let (cls, reason) = classify_with_reason(base);

    // --- Invariant 2a: `Read` is reason-free and stable. ---
    if cls == Classification::Read {
        assert!(
            reason.is_none(),
            "Read classification must carry no NotReadReason; got {reason:?} for {base:?}"
        );
        assert_eq!(
            classify(base),
            Classification::Read,
            "classification must be deterministic for {base:?}"
        );
    }

    // --- Invariant 2b: fail-closed teeth. A *genuinely* two-statement input
    // (base + stacked write) must NEVER classify as a safe single read. ---
    let tail = UNSAFE_TAILS[(data.first().copied().unwrap_or(0) as usize) % UNSAFE_TAILS.len()];

    // Only assert when the base is itself a clean single read: that guarantees
    // it has no dangling open `--`/`/* */`/string/dollar-quote that would
    // swallow the appended tail (those all classify NotRead/ParseError). The
    // newline before `;` additionally terminates any trailing `--` line comment
    // so the write becomes a real second statement, not commented-out text.
    if cls == Classification::Read {
        let stacked = format!("{base}\n; {tail}");
        assert_ne!(
            classify(&stacked),
            Classification::Read,
            "SAFETY VIOLATION: genuinely-stacked write classified as a safe read: {stacked:?}"
        );
    }

    // The bare write alone must also never be a read — unconditional.
    assert_ne!(
        classify(tail),
        Classification::Read,
        "SAFETY VIOLATION: bare write classified as a safe read: {tail:?}"
    );

    // --- Invariant 2c (#115): a single SELECT that smuggles a side effect via a
    // qualified/custom OPERATOR or a `FOR UPDATE`/`FOR SHARE` row lock must NEVER
    // classify as a safe read — the same tighten-only teeth, extended to the
    // operator/lock classes so a regression there is caught here. Unconditional. ---
    for poison in SIDE_EFFECTING_SELECTS {
        assert_ne!(
            classify(poison),
            Classification::Read,
            "SAFETY VIOLATION: side-effecting SELECT classified as a safe read: {poison:?}"
        );
    }
});
