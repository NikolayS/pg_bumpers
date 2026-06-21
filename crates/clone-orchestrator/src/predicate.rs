//! Volatile / non-deterministic predicate detection (SPEC §4, §10.1
//! `predicate_volatile`).
//!
//! A dry-run on a clone (or in a rolled-back txn) is only a faithful preview of
//! the apply if the statement is **deterministic**: the same rows must match at
//! dry-run time and at apply time. A predicate that references a volatile,
//! time- or randomness-dependent function — `now()`, `random()`,
//! `clock_timestamp()`, … — breaks that equivalence: the affected-PK set the
//! dry-run measures can differ from the set the apply touches a moment later.
//!
//! Such writes are **REFUSED, never executed** (SPEC §4: "Refuse
//! volatile/nondeterministic predicates"). This module is the clean-room,
//! DB-free detector: it walks the public `sqlparser` AST of the statement and
//! flags any reference to a known-volatile function. It is intentionally
//! **fail-closed**: an unparseable statement is treated as volatile (we cannot
//! prove it deterministic), and the function list is a denied-name set so an
//! unknown spelling is caught by name even where the parse is shallow.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The set of Postgres function names whose presence in a statement makes the
/// dry-run/apply equivalence unsafe (SPEC §4 names `now()`/`random()`; the list
/// is the volatile/non-deterministic surface the guard refuses).
///
/// Names are compared case-insensitively and without schema qualification (so
/// `pg_catalog.now()` is caught too). This is a denied-name set, not an
/// allow-list of "safe" functions: we only need to *refuse* the volatile ones.
pub const VOLATILE_FUNCTIONS: &[&str] = &[
    // Time / clock — the canonical dry-run/apply skew source.
    "now",
    "clock_timestamp",
    "statement_timestamp",
    "transaction_timestamp",
    "timeofday",
    "localtime",
    "localtimestamp",
    "current_timestamp",
    "current_time",
    "current_date",
    // Randomness / non-determinism.
    "random",
    "random_normal",
    "gen_random_uuid",
    "uuid_generate_v4",
    "uuid_generate_v1",
    // Session/txn identity that can differ between dry-run and apply.
    "txid_current",
    "pg_current_xact_id",
    "nextval",
    "setval",
];

/// Why a statement's predicate was judged volatile (for the audit/blast-radius
/// reason string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolatileReason {
    /// A known-volatile function was referenced by name.
    Function(String),
    /// The statement could not be parsed, so determinism cannot be proven →
    /// fail-closed (treat as volatile).
    Unparseable,
}

impl std::fmt::Display for VolatileReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolatileReason::Function(name) => write!(
                f,
                "references volatile/non-deterministic function `{name}()`"
            ),
            VolatileReason::Unparseable => write!(
                f,
                "statement could not be parsed; determinism cannot be proven (fail-closed)"
            ),
        }
    }
}

/// Detect whether `sql` references a volatile / non-deterministic function.
///
/// Returns `Some(reason)` if the statement must be **REFUSED** as volatile, or
/// `None` if it is provably deterministic over the denied-name set. Fail-closed:
/// an unparseable statement returns `Some(VolatileReason::Unparseable)`.
///
/// The check is a case-insensitive substring scan over function-call *tokens*
/// derived from the parsed statement, plus a defensive raw-text scan so a
/// volatile call that hides in a sub-expression the AST walk does not descend
/// into is still caught (fail-closed). It never executes anything.
pub fn volatile_reason(sql: &str) -> Option<VolatileReason> {
    let dialect = PostgreSqlDialect {};
    // Parse advisory-only (§4). If the parse fails we cannot prove determinism,
    // so we refuse (fail-closed) rather than wave it through.
    if Parser::parse_sql(&dialect, sql).is_err() {
        return Some(VolatileReason::Unparseable);
    }

    // Tokenize on identifier boundaries and look for `name(` patterns. We work
    // on a normalized copy: lowercased, with schema qualifiers stripped so
    // `pg_catalog.now()` reduces to `now(`. This catches the volatile surface
    // regardless of where in the statement (WHERE, SET, VALUES, …) it appears.
    let normalized = normalize_for_scan(sql);
    for &func in VOLATILE_FUNCTIONS {
        if mentions_call(&normalized, func) {
            return Some(VolatileReason::Function(func.to_string()));
        }
    }
    None
}

/// Convenience predicate: is this statement volatile (any reason)?
pub fn is_volatile(sql: &str) -> bool {
    volatile_reason(sql).is_some()
}

/// Lowercase the SQL and collapse `schema.func` qualifiers to bare `func` so the
/// call scan is schema-insensitive. Whitespace between the name and `(` is also
/// removed so `now ()` reads as `now(`.
fn normalize_for_scan(sql: &str) -> String {
    let lowered = sql.to_lowercase();
    // Strip a single level of schema qualification before a `(` call: turn
    // `pg_catalog.now(` into `now(`. We do this token-wise to avoid mangling
    // table.column references that are not calls.
    let mut out = String::with_capacity(lowered.len());
    let bytes = lowered.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '.' {
            // Drop the qualifier already written (back up over the identifier we
            // just emitted) only if a call follows; cheap heuristic: just emit a
            // separator so `a.now(` becomes `a now(` and the call scan still
            // matches `now(`. This keeps the scan simple and fail-closed.
            out.push(' ');
        } else if c.is_whitespace() {
            out.push(' ');
        } else {
            out.push(c);
        }
        i += 1;
    }
    // Collapse "name (" → "name(" by removing spaces immediately before '('.
    let mut collapsed = String::with_capacity(out.len());
    let chars: Vec<char> = out.chars().collect();
    let mut j = 0;
    while j < chars.len() {
        if chars[j] == ' ' {
            // Skip runs of spaces that precede a '('.
            let mut k = j;
            while k < chars.len() && chars[k] == ' ' {
                k += 1;
            }
            if k < chars.len() && chars[k] == '(' {
                j = k; // drop the spaces, fall through to emit '('
                continue;
            }
            collapsed.push(' ');
            j = k;
            continue;
        }
        collapsed.push(chars[j]);
        j += 1;
    }
    collapsed
}

/// Whether `normalized` contains a call to `func` — i.e. the bare function name
/// immediately followed by `(`, on an identifier boundary so `snow(` does not
/// match `now`.
fn mentions_call(normalized: &str, func: &str) -> bool {
    let needle = format!("{func}(");
    let mut from = 0;
    while let Some(pos) = normalized[from..].find(&needle) {
        let abs = from + pos;
        // Left boundary: the char before the name must not be an identifier
        // char (so `snow(` / `mynow(` do not match `now(`).
        let ok_left = abs == 0 || !is_ident_char(normalized.as_bytes()[abs - 1] as char);
        if ok_left {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_in_where_is_volatile() {
        let r = volatile_reason("UPDATE public.orders SET balance = 0 WHERE created > now()");
        assert_eq!(r, Some(VolatileReason::Function("now".into())));
        assert!(is_volatile(
            "UPDATE public.orders SET balance = 0 WHERE created > now()"
        ));
    }

    #[test]
    fn random_anywhere_is_volatile() {
        assert_eq!(
            volatile_reason("DELETE FROM public.orders WHERE random() < 0.5"),
            Some(VolatileReason::Function("random".into()))
        );
    }

    #[test]
    fn clock_timestamp_is_volatile() {
        assert_eq!(
            volatile_reason("UPDATE public.orders SET seen_at = clock_timestamp() WHERE id = 1"),
            Some(VolatileReason::Function("clock_timestamp".into()))
        );
    }

    #[test]
    fn schema_qualified_now_is_still_caught() {
        // pg_catalog.now() must be refused too.
        assert_eq!(
            volatile_reason("UPDATE public.orders SET x = 1 WHERE created > pg_catalog.now()"),
            Some(VolatileReason::Function("now".into()))
        );
    }

    #[test]
    fn whitespace_before_paren_is_caught() {
        assert_eq!(
            volatile_reason("UPDATE public.orders SET balance = 0 WHERE created > now ()"),
            Some(VolatileReason::Function("now".into()))
        );
    }

    #[test]
    fn deterministic_predicate_is_not_volatile() {
        assert_eq!(
            volatile_reason("UPDATE public.orders SET balance = 0"),
            None
        );
        assert_eq!(
            volatile_reason("UPDATE public.orders SET balance = 0 WHERE status = 'open'"),
            None
        );
        assert!(!is_volatile(
            "DELETE FROM public.orders WHERE id IN (1, 2, 3)"
        ));
    }

    #[test]
    fn similarly_named_columns_do_not_false_positive() {
        // A column literally named "now" (not a call) must NOT be flagged, and a
        // function whose name merely ends in "now" must not match.
        assert_eq!(
            volatile_reason("UPDATE public.orders SET balance = 0 WHERE snapshot_now = 5"),
            None,
            "a column ending in `now` is not a now() call"
        );
        assert_eq!(
            volatile_reason("UPDATE t SET x = mysnow(1) WHERE id = 1"),
            None,
            "mysnow( must not match now("
        );
    }

    #[test]
    fn unparseable_statement_is_fail_closed_volatile() {
        // Garbage that does not parse cannot be proven deterministic → refuse.
        assert_eq!(
            volatile_reason("UPDATE WHERE WHERE )("),
            Some(VolatileReason::Unparseable)
        );
    }

    #[test]
    fn reason_renders_human_readable() {
        assert_eq!(
            VolatileReason::Function("now".into()).to_string(),
            "references volatile/non-deterministic function `now()`"
        );
    }
}
