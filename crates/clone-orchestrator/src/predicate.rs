//! Volatile / non-deterministic predicate detection (SPEC §4, §10.1
//! `predicate_volatile`).
//!
//! A dry-run on a clone (or in a rolled-back txn) is only a faithful preview of
//! the apply if the statement is **deterministic**: the same rows must match at
//! dry-run time and at apply time. A predicate that references a volatile,
//! time- or randomness-dependent function — `now()`, `random()`,
//! `clock_timestamp()`, the parenless special keyword `CURRENT_TIMESTAMP`, … —
//! breaks that equivalence: the affected-PK set the dry-run measures can differ
//! from the set the apply touches a moment later.
//!
//! Such writes are **REFUSED, never executed** (SPEC §4: "Refuse
//! volatile/nondeterministic predicates").
//!
//! ## How the check works (AST-based, fail-closed)
//!
//! This module does **not** scan SQL text for `name(` substrings (the old
//! approach, which missed the *parenless* special keywords and volatile UDFs).
//! Instead it:
//!
//! 1. **Parses** the statement and extracts the **WHERE predicate AST** of the
//!    certified `UPDATE`/`DELETE` (`Update.selection` / `Delete.selection`).
//!    Unparseable / non-`UPDATE`/`DELETE` → fail-closed (refuse).
//! 2. **Walks the predicate AST** (`visit_expressions`, depth-first, descending
//!    into subqueries / `CASE` / function args / casts / …) and collects every
//!    function-call name. The parenless special keywords
//!    (`CURRENT_TIMESTAMP`/`CURRENT_DATE`/`CURRENT_TIME`/`LOCALTIME`/
//!    `LOCALTIMESTAMP`) parse to `Expr::Function` nodes too, so they are caught
//!    here by the same walk.
//! 3. Classifies each collected function name in two stages:
//!    - the **non-deterministic special-value names** (the SQL keywords plus the
//!      time/transaction functions they desugar to — `now`, `current_timestamp`,
//!      `statement_timestamp`, `transaction_timestamp`, `txid_current`, … —
//!      which Postgres marks `STABLE`, not `volatile`, yet still differ across
//!      the dry-run/apply boundary) are **always refused**, by name;
//!    - the **known-deterministic SQL special forms**
//!      ([`KNOWN_DETERMINISTIC_SPECIAL_FORMS`] — `coalesce`/`nullif`/`greatest`/
//!      `least`) are accepted *before* the catalog lookup: sqlparser models them
//!      as `Expr::Function` but they have **no `pg_proc` row**, so resolving them
//!      would yield `Unknown` and wrongly fail-closed REFUSE this everyday SQL.
//!      They are immutable by construction;
//!    - every **other** function name is resolved against the live connection's
//!      `pg_proc.provolatile` ([`FunctionVolatility`]): `'v'` (volatile) →
//!      refused; immutable/stable (`'i'`/`'s'`) → allowed; **unknown /
//!      unresolvable → refused (fail-closed)**.
//!
//! The DB-free part (parse + AST walk + special-keyword deny-set) lives here; the
//! `pg_proc.provolatile` resolution is provided by the rehearsal connection via
//! the [`FunctionVolatility`] seam, so the whole decision still happens **before
//! any forward execution** (the DB is only *read*, never written).

use std::ops::ControlFlow;

use sqlparser::ast::{visit_expressions, Expr, FunctionArguments, ObjectName, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The non-deterministic special-value names that are **always refused** by name,
/// independent of `pg_proc.provolatile`.
///
/// These are the SQL special keywords (`CURRENT_TIMESTAMP`/`CURRENT_DATE`/… —
/// which sqlparser parses to `Expr::Function` with these bare names) plus the
/// time/transaction functions they desugar to. Postgres marks several of them
/// `STABLE` (not `volatile`) — `now()`, `current_timestamp`,
/// `transaction_timestamp()`, `statement_timestamp()`, `txid_current()` — so a
/// `provolatile = 'v'` test alone would *miss* them, yet they still produce a
/// different value (and therefore a different matched-row set) at apply time than
/// at dry-run time. SPEC §4 requires refusing them, so they are denied by name.
///
/// Compared case-insensitively and without schema qualification (so
/// `pg_catalog.now` is caught too).
pub const NONDETERMINISTIC_KEYWORDS: &[&str] = &[
    // SQL special-value keywords (parenless or parened) + the wall-clock /
    // transaction-clock functions they map to. STABLE in pg, but boundary-unsafe.
    "now",
    "current_timestamp",
    "current_time",
    "current_date",
    "localtime",
    "localtimestamp",
    "statement_timestamp",
    "transaction_timestamp",
    // Transaction identity that differs between the dry-run txn and the apply txn
    // (STABLE within a txn, but our dry-run and apply are *different* txns).
    "txid_current",
    "pg_current_xact_id",
    "pg_current_xact_id_if_assigned",
];

/// SQL **special-form primitives** that sqlparser models as `Expr::Function` but
/// that have **no `pg_proc` row**, and are deterministic (`IMMUTABLE`)
/// by construction.
///
/// These are syntactic constructs the grammar spells like a function call
/// (`coalesce(a, b)`, `nullif(a, b)`, `greatest(...)`, `least(...)`), so
/// sqlparser surfaces them as `Expr::Function` and they flow into
/// [`function_names_in`] — but the planner handles them directly, so
/// `SELECT count(*) FROM pg_proc WHERE proname = 'coalesce'` is `0`. Without
/// this allow-set the `pg_proc.provolatile` resolver would find no row,
/// return [`Volatility::Unknown`], and the engine would fail-closed REFUSE —
/// over-refusing everyday SQL (`WHERE coalesce(owner,'') = 'x'`). They are
/// known-deterministic, so we treat them as immutable **before** the catalog
/// lookup, never reaching the unresolvable path.
///
/// Scope note: the other catalog-less SQL special forms that sqlparser parses
/// (`CAST`/`TRIM`/`SUBSTRING`/`POSITION`/`OVERLAY`/`EXTRACT`/…) get their own
/// dedicated `Expr` variants (`Expr::Cast`, `Expr::Trim`, …), so they are *not*
/// `Expr::Function` and never reach the catalog lookup in the first place —
/// they already proceed and need no entry here. This set covers only the
/// special forms that *do* route through [`function_names_in`] as functions.
///
/// Compared case-insensitively, on the bare (schema-stripped) name.
pub const KNOWN_DETERMINISTIC_SPECIAL_FORMS: &[&str] = &[
    "coalesce", // COALESCE(...) — first non-NULL argument
    "nullif",   // NULLIF(a, b) — NULL when equal, else a
    "greatest", // GREATEST(...) — largest non-NULL argument
    "least",    // LEAST(...) — smallest non-NULL argument
];

/// The volatility class of a Postgres function, as recorded by
/// `pg_proc.provolatile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Volatility {
    /// `provolatile = 'i'` — `IMMUTABLE`: same inputs always give the same output.
    Immutable,
    /// `provolatile = 's'` — `STABLE`: constant within a single statement scan.
    Stable,
    /// `provolatile = 'v'` — `VOLATILE`: may change row-to-row / call-to-call.
    Volatile,
    /// The function could not be resolved (unknown name, ambiguous, no
    /// connection, …). Treated as **refuse** (fail-closed) by the caller.
    Unknown,
}

/// The connection-backed `pg_proc.provolatile` resolver seam.
///
/// The dry-run engine has a live connection in hand at refuse-time; it implements
/// this so [`predicate_volatile_reason`] can resolve UDF + built-in volatility
/// **before** executing anything. The lookup only *reads* `pg_proc`; it never
/// runs the candidate statement.
///
/// `name` is the function name as written in the predicate, lowercased, with its
/// schema-qualification parts joined by `.` (e.g. `now`, `pg_catalog.now`,
/// `public.evil_now`). Implementors should resolve it the way Postgres would
/// (search_path / schema-qualified), and **MUST** return [`Volatility::Unknown`]
/// rather than guessing when they cannot determine the class.
pub trait FunctionVolatility {
    /// Resolve the `pg_proc.provolatile` class of `name`.
    fn volatility_of(&mut self, name: &str) -> Volatility;
}

/// A resolver that knows nothing — every function is [`Volatility::Unknown`].
///
/// Used by the DB-free unit tests and by callers that only want the
/// special-keyword (no-DB) half of the check: with this resolver, *any*
/// non-keyword function in the predicate is refused fail-closed. It is **not**
/// the production resolver (which is `pg_proc`-backed).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFunctionVolatility;

impl FunctionVolatility for NoFunctionVolatility {
    fn volatility_of(&mut self, _name: &str) -> Volatility {
        Volatility::Unknown
    }
}

/// Why a statement's predicate was judged volatile (for the audit/blast-radius
/// reason string). Every variant means **REFUSE** (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolatileReason {
    /// A non-deterministic special-value keyword/function
    /// (`CURRENT_TIMESTAMP`/`now`/…) appears in the predicate. Always refused by
    /// name (these are boundary-unsafe even though pg marks them `STABLE`).
    NondeterministicKeyword(String),
    /// A function in the predicate resolves to `pg_proc.provolatile = 'v'`
    /// (volatile) — a volatile built-in (`random`/`clock_timestamp`/`nextval`/…)
    /// or a volatile UDF.
    VolatileFunction(String),
    /// A function in the predicate could not be resolved to a volatility class
    /// (unknown / unresolvable). We cannot prove it deterministic → refuse
    /// (fail-closed).
    UnresolvableFunction(String),
    /// The statement could not be parsed, so determinism cannot be proven →
    /// fail-closed (treat as volatile).
    Unparseable,
}

impl std::fmt::Display for VolatileReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolatileReason::NondeterministicKeyword(name) => write!(
                f,
                "predicate references non-deterministic special value `{name}` \
                 (value differs between dry-run and apply)"
            ),
            VolatileReason::VolatileFunction(name) => write!(
                f,
                "predicate references VOLATILE function `{name}` \
                 (pg_proc.provolatile = 'v')"
            ),
            VolatileReason::UnresolvableFunction(name) => write!(
                f,
                "predicate references function `{name}` whose volatility could \
                 not be determined; cannot prove determinism (fail-closed)"
            ),
            VolatileReason::Unparseable => write!(
                f,
                "statement could not be parsed; determinism cannot be proven (fail-closed)"
            ),
        }
    }
}

/// Detect whether `sql`'s **predicate** references a volatile / non-deterministic
/// element, resolving function volatility against `resolver`
/// (`pg_proc.provolatile`).
///
/// Returns `Some(reason)` if the statement must be **REFUSED**, or `None` only
/// when **every** element of the predicate has been *positively shown* to be
/// deterministic (no non-deterministic keyword, and every function call resolves
/// to `IMMUTABLE`/`STABLE`).
///
/// Fail-closed in three ways:
/// - an unparseable statement → `Some(Unparseable)`;
/// - a non-`UPDATE`/`DELETE` shape → `Some(Unparseable)` (it has no certified
///   predicate to prove deterministic; the engine's `classify` refuses these too,
///   but we never wave one through here);
/// - a function whose volatility the resolver cannot determine →
///   `Some(UnresolvableFunction)`.
///
/// It only *reads* via the resolver; it never executes the candidate statement.
pub fn predicate_volatile_reason(
    sql: &str,
    resolver: &mut dyn FunctionVolatility,
) -> Option<VolatileReason> {
    let dialect = PostgreSqlDialect {};
    let parsed = match Parser::parse_sql(&dialect, sql) {
        Ok(p) if p.len() == 1 => p,
        // Parse failure or multi-statement → cannot prove deterministic.
        _ => return Some(VolatileReason::Unparseable),
    };

    // Pull the certified predicate (the WHERE clause AST). A no-WHERE write has
    // an empty predicate — vacuously deterministic — but a non-UPDATE/DELETE
    // shape has no certified predicate, so we fail closed.
    let predicate = match predicate_of(&parsed[0]) {
        Some(p) => p,
        None => return Some(VolatileReason::Unparseable),
    };
    let Some(predicate) = predicate else {
        // No WHERE clause → no predicate functions to worry about.
        return None;
    };

    // Collect every function-call name in the predicate subtree (depth-first,
    // including subqueries / CASE / function args). The parenless special
    // keywords are `Expr::Function` nodes too, so they show up here.
    let names = function_names_in(predicate);

    // (a) Always-refused non-deterministic special-value names, by name.
    for name in &names {
        if NONDETERMINISTIC_KEYWORDS.contains(&bare_name(name).as_str()) {
            return Some(VolatileReason::NondeterministicKeyword(name.clone()));
        }
    }

    // (b) Resolve every remaining function against pg_proc.provolatile.
    //     Volatile → refuse; Unknown → refuse (fail-closed); Immutable/Stable → ok.
    for name in &names {
        // Catalog-less SQL special forms (`coalesce`/`nullif`/`greatest`/`least`)
        // parse as `Expr::Function` but have **no `pg_proc` row**, so the resolver
        // would return `Unknown` and we would wrongly fail-closed REFUSE everyday
        // SQL. They are deterministic (IMMUTABLE) by construction — accept them
        // here, *before* the catalog lookup, so we never reach the unresolvable
        // path for them.
        if KNOWN_DETERMINISTIC_SPECIAL_FORMS.contains(&bare_name(name).as_str()) {
            continue;
        }
        match resolver.volatility_of(name) {
            Volatility::Volatile => return Some(VolatileReason::VolatileFunction(name.clone())),
            Volatility::Unknown => return Some(VolatileReason::UnresolvableFunction(name.clone())),
            Volatility::Immutable | Volatility::Stable => {}
        }
    }

    // Every predicate element positively shown non-volatile.
    None
}

/// Extract the WHERE-clause predicate of a certified `UPDATE`/`DELETE`.
///
/// Returns:
/// - `Some(Some(expr))` — an `UPDATE`/`DELETE` with a WHERE clause;
/// - `Some(None)` — an `UPDATE`/`DELETE` with **no** WHERE clause;
/// - `None` — not a certified rehearsable shape (no predicate to vet).
fn predicate_of(stmt: &Statement) -> Option<Option<&Expr>> {
    match stmt {
        Statement::Update(update) => Some(update.selection.as_ref()),
        Statement::Delete(delete) => Some(delete.selection.as_ref()),
        _ => None,
    }
}

/// Collect every function-call name in `expr` (and its subtrees), each rendered
/// as a lowercase, dot-joined name (`now`, `pg_catalog.now`, `public.evil_now`).
///
/// Uses `visit_expressions`, the derived depth-first AST walk, so it descends
/// into subqueries, `CASE`, casts, `IN (...)`, function arguments, etc. — there
/// is no statement shape that hides a call from this walk (the fragility the
/// substring scan had).
fn function_names_in(expr: &Expr) -> Vec<String> {
    let mut names = Vec::new();
    let _ = visit_expressions(expr, |e| {
        if let Expr::Function(func) = e {
            names.push(object_name_lower(&func.name));
            // `func.parameters` / `func.args` are themselves Exprs and are
            // descended into by visit_expressions, so nested calls (e.g.
            // `lower(now()::text)`) are collected too — no extra work here.
            let _ = &func.args; // documented: walked by the visitor.
            if matches!(func.args, FunctionArguments::None) {
                // Parenless special keyword (CURRENT_TIMESTAMP, …) — already
                // pushed by name above; nothing more to do.
            }
        }
        ControlFlow::<()>::Continue(())
    });
    names
}

/// Render an `ObjectName` (possibly schema-qualified) as a lowercase, dot-joined
/// string. Quoted identifiers keep their (case-sensitive) value lowercased for
/// the keyword compare; the resolver receives the same form.
fn object_name_lower(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|part| match part.as_ident() {
            Some(ident) => ident.value.to_lowercase(),
            None => part.to_string().to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The bare (last) component of a possibly schema-qualified dot-joined name, so
/// `pg_catalog.now` matches the `now` keyword.
fn bare_name(dotted: &str) -> String {
    dotted.rsplit('.').next().unwrap_or(dotted).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A table-driven resolver for the DB-free unit tests: maps bare function
    /// names to a volatility class; unknown names resolve to `Unknown`
    /// (fail-closed), exactly like the real `pg_proc` resolver would for a name
    /// it cannot find.
    struct MapResolver(HashMap<&'static str, Volatility>);

    impl MapResolver {
        fn new(pairs: &[(&'static str, Volatility)]) -> Self {
            MapResolver(pairs.iter().copied().collect())
        }
    }

    impl FunctionVolatility for MapResolver {
        fn volatility_of(&mut self, name: &str) -> Volatility {
            let bare = bare_name(name);
            self.0
                .get(bare.as_str())
                .copied()
                .unwrap_or(Volatility::Unknown)
        }
    }

    fn immutable_world() -> MapResolver {
        MapResolver::new(&[
            ("lower", Volatility::Immutable),
            ("upper", Volatility::Immutable),
            ("abs", Volatility::Immutable),
            ("length", Volatility::Immutable),
            ("random", Volatility::Volatile),
            ("clock_timestamp", Volatility::Volatile),
            ("nextval", Volatility::Volatile),
            ("timeofday", Volatility::Volatile),
            ("gen_random_uuid", Volatility::Volatile),
            ("evil_now", Volatility::Volatile),
        ])
    }

    fn reason(sql: &str) -> Option<VolatileReason> {
        predicate_volatile_reason(sql, &mut immutable_world())
    }

    // --- non-deterministic special keywords (the RED bypass) -----------------

    #[test]
    fn parenless_current_timestamp_is_refused() {
        // The headline bypass: parenless CURRENT_TIMESTAMP, even behind a cast.
        let r =
            reason("UPDATE public.accounts SET balance=0 WHERE owner < CURRENT_TIMESTAMP::text");
        assert!(
            matches!(r, Some(VolatileReason::NondeterministicKeyword(ref n)) if n == "current_timestamp"),
            "got {r:?}"
        );
    }

    #[test]
    fn parenless_localtimestamp_and_current_date_are_refused() {
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE c > LOCALTIMESTAMP"),
            Some(VolatileReason::NondeterministicKeyword(_))
        ));
        assert!(matches!(
            reason("DELETE FROM t WHERE d < CURRENT_DATE"),
            Some(VolatileReason::NondeterministicKeyword(_))
        ));
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE c > LOCALTIME"),
            Some(VolatileReason::NondeterministicKeyword(_))
        ));
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE c > CURRENT_TIME"),
            Some(VolatileReason::NondeterministicKeyword(_))
        ));
    }

    #[test]
    fn parened_now_is_refused_as_keyword() {
        // now() is STABLE in pg (provolatile='s'), so it is caught by the
        // keyword deny-set, not by the provolatile test.
        assert!(matches!(
            reason("UPDATE public.orders SET balance=0 WHERE created > now()"),
            Some(VolatileReason::NondeterministicKeyword(ref n)) if n == "now"
        ));
    }

    #[test]
    fn schema_qualified_now_is_still_caught() {
        assert!(matches!(
            reason("UPDATE public.orders SET x=1 WHERE created > pg_catalog.now()"),
            Some(VolatileReason::NondeterministicKeyword(_))
        ));
    }

    // --- provolatile-resolved volatile functions -----------------------------

    #[test]
    fn volatile_builtin_random_is_refused_via_provolatile() {
        assert!(matches!(
            reason("DELETE FROM public.orders WHERE random() < 0.5"),
            Some(VolatileReason::VolatileFunction(ref n)) if n == "random"
        ));
    }

    #[test]
    fn volatile_udf_is_refused_via_provolatile() {
        // evil_now() is not on any name denylist; only pg_proc.provolatile='v'
        // catches it.
        assert!(matches!(
            reason("UPDATE public.accounts SET balance=0 WHERE owner > evil_now()::text"),
            Some(VolatileReason::VolatileFunction(ref n)) if n == "evil_now"
        ));
    }

    #[test]
    fn volatile_nested_in_case_and_subquery_is_refused() {
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE id = (CASE WHEN random() < 0.5 THEN 1 ELSE 2 END)"),
            Some(VolatileReason::VolatileFunction(_))
        ));
        assert!(matches!(
            reason("DELETE FROM t WHERE id IN (SELECT id FROM s WHERE ts > clock_timestamp())"),
            Some(VolatileReason::VolatileFunction(_))
        ));
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE n < timeofday()::text"),
            Some(VolatileReason::VolatileFunction(_))
        ));
    }

    // --- fail-closed on unknown ----------------------------------------------

    #[test]
    fn unknown_function_is_refused_fail_closed() {
        // Not a keyword, and the resolver does not know it → refuse, do NOT pass.
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE c = mystery_fn(1)"),
            Some(VolatileReason::UnresolvableFunction(ref n)) if n == "mystery_fn"
        ));
    }

    #[test]
    fn no_function_resolver_refuses_any_function() {
        // With the no-op resolver, any non-keyword function fails closed.
        let mut r = NoFunctionVolatility;
        assert!(matches!(
            predicate_volatile_reason("UPDATE t SET x=0 WHERE lower(name)='x'", &mut r),
            Some(VolatileReason::UnresolvableFunction(_))
        ));
    }

    // --- genuinely deterministic predicates proceed --------------------------

    #[test]
    fn no_where_clause_is_deterministic() {
        assert_eq!(reason("UPDATE public.orders SET balance = 0"), None);
    }

    #[test]
    fn plain_comparison_is_deterministic() {
        assert_eq!(
            reason("UPDATE public.orders SET balance=0 WHERE id = 5"),
            None
        );
        assert_eq!(
            reason("DELETE FROM public.orders WHERE id IN (1, 2, 3)"),
            None
        );
        assert_eq!(
            reason("UPDATE public.orders SET balance=0 WHERE status = 'open'"),
            None
        );
    }

    #[test]
    fn immutable_function_predicate_proceeds() {
        // lower()/abs() are IMMUTABLE → no false refusal.
        assert_eq!(reason("UPDATE t SET x=0 WHERE lower(name) = 'x'"), None);
        assert_eq!(reason("DELETE FROM t WHERE abs(amount) > 100"), None);
    }

    #[test]
    fn catalog_less_special_forms_proceed() {
        // RED→GREEN: `coalesce`/`nullif`/`greatest`/`least` parse as
        // `Expr::Function` but have NO `pg_proc` row, so the resolver returns
        // `Unknown` for them. Before the allow-set this fail-closed REFUSED these
        // everyday-SQL predicates (`UnresolvableFunction`); they must proceed.
        // Note: `immutable_world()` does NOT map these names, so they reach the
        // resolver as `Unknown` — exactly like the real `pg_proc` lookup (n=0) —
        // proving the allow-set, not a test fixture, lets them through.
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE coalesce(owner,'') = 'x'"),
            None,
            "coalesce in a WHERE predicate must proceed"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE nullif(a,b) IS NULL"),
            None,
            "nullif in a WHERE predicate must proceed"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE greatest(a,b) > 0"),
            None,
            "greatest in a WHERE predicate must proceed"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE least(a,b) < 10"),
            None,
            "least in a WHERE predicate must proceed"
        );
        // Case-insensitive + schema-qualified bare-name handling.
        assert_eq!(
            reason("DELETE FROM t WHERE COALESCE(owner, 'd') = 'x'"),
            None
        );
        assert_eq!(
            reason("UPDATE t SET x=0 WHERE pg_catalog.coalesce(owner,'') = 'x'"),
            None
        );
    }

    #[test]
    fn special_form_does_not_widen_to_real_volatile_or_unknown() {
        // The allow-set must NOT mask a genuinely volatile function or an unknown
        // UDF that happens to share an argument-position with a special form.
        // A volatile function still refuses even when nested as an arg to coalesce.
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE coalesce(random(), 0) > 0.5"),
            Some(VolatileReason::VolatileFunction(ref n)) if n == "random"
        ));
        // An unknown UDF still fail-closed refuses when wrapped by a special form.
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE coalesce(mystery_fn(1), 0) = 0"),
            Some(VolatileReason::UnresolvableFunction(ref n)) if n == "mystery_fn"
        ));
    }

    #[test]
    fn column_named_now_is_not_a_call() {
        // A column literally named "now" is an identifier, not a function → not
        // refused. (The AST distinguishes Identifier from Function.)
        assert_eq!(
            reason("UPDATE public.orders SET balance=0 WHERE snapshot_now = 5"),
            None
        );
    }

    // --- fail-closed parse / shape -------------------------------------------

    #[test]
    fn unparseable_statement_is_fail_closed() {
        assert_eq!(
            reason("UPDATE WHERE WHERE )("),
            Some(VolatileReason::Unparseable)
        );
    }

    #[test]
    fn non_update_delete_shape_is_fail_closed() {
        // No certified predicate to vet → refuse (classify also refuses these).
        assert_eq!(reason("SELECT now()"), Some(VolatileReason::Unparseable));
        assert_eq!(
            reason("INSERT INTO t(x) VALUES (now())"),
            Some(VolatileReason::Unparseable)
        );
    }

    #[test]
    fn reason_renders_human_readable() {
        assert_eq!(
            VolatileReason::NondeterministicKeyword("now".into()).to_string(),
            "predicate references non-deterministic special value `now` \
             (value differs between dry-run and apply)"
        );
        assert!(VolatileReason::VolatileFunction("random".into())
            .to_string()
            .contains("provolatile = 'v'"));
    }
}
