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

use sqlparser::ast::{Expr, FunctionArguments, Ident, ObjectName, Statement, visit_expressions};
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
        //
        // IMPORTANT: this short-circuit applies **only to unqualified names**
        // (no `.` in the rendered name). A schema-qualified call such as
        // `public.coalesce(...)` names a **real user-defined function** in the
        // `public` schema — a user may have defined a VOLATILE UDF with a name
        // that shadows the built-in special form. Matching on the bare name alone
        // would skip the `pg_proc.provolatile` lookup for that UDF and silently
        // allow a volatile predicate (§4 volatile-bypass). For qualified names we
        // fall through to the resolver: it will find the UDF's provolatile class
        // (REFUSE if 'v') or, if the function is unresolvable, fail-closed REFUSE.
        if !name.contains('.')
            && KNOWN_DETERMINISTIC_SPECIAL_FORMS.contains(&bare_name(name).as_str())
        {
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

// ===========================================================================
//  Self-determined-predicate gate (EPIC #91 PR-A) — the structural replacement
//  for the exact-PK-set checksum.
// ===========================================================================
//
// The checksum's only real job was catching "same statement, same count,
// DIFFERENT rows" predicate-meaning drift: an attacker mutates *other* data so a
// human-approved predicate matches a different (chosen, sensitive) row between
// approval and apply. That residual lives **entirely in predicates whose truth
// can be steered by other writes**.
//
// This gate forecloses it structurally: on the **grant-bound** apply/certify
// path, a write's WHERE may reference **only the immutable primary-key column +
// literal constants + immutable functions/operators on the PK**. A row's
// *immutable PK* cannot be re-pointed at a sensitive row by any other write, so
// the approved `statement_text` itself pins the row set — the checksum becomes
// redundant for identity-steerability.
//
// The cap (PR-B) handles magnitude drift (e.g. INSERTs into a PK range); this
// gate's job is purely **identity-steerability**.

/// Why a predicate is **not** self-determined (i.e. its row set can be steered by
/// other writes), for the grant-bound gate (EPIC #91 PR-A). Every variant means
/// **REFUSE** (fail-closed, `NOT_REHEARSABLE`-class). The row set of a
/// self-determined predicate is pinned by the immutable PK and the literal
/// statement text alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSelfDetermined {
    /// The predicate references a **non-PK column** (`status`, `owner`, …). A
    /// mutable column is steerable: an attacker can set a chosen sensitive row's
    /// column to match the approved predicate between approval and apply.
    NonPkColumn {
        /// The PK column the predicate is allowed to reference.
        pk_col: String,
        /// The offending non-PK column the predicate referenced.
        referenced: String,
    },
    /// The predicate contains a **subquery / correlated reference / `EXISTS` /
    /// `IN (SELECT …)` / `= ANY/ALL (SELECT …)`**. Its truth depends on other
    /// rows/tables an attacker can write, so it is not pinned by the PK.
    Subquery,
    /// The statement is an **`UPDATE … FROM other`** / **`DELETE … USING other`**
    /// (or otherwise JOINs a second relation into the target) — a join-correlation
    /// like `UPDATE t SET … FROM other WHERE other.id = t.id`. The set of target rows
    /// the write touches is then determined by the **content of `other`**, which an
    /// attacker can write between approval and apply — so the row set is *steerable*
    /// and NOT pinned by the immutable PK. EPIC #91 PR-B: this was only incidentally
    /// fail-closed by the now-removed apply-time PK-set recompute; the predicate gate
    /// refuses it explicitly. The `id`-pinned single-table form (`WHERE id IN (…)`) is
    /// the supported shape; correlate-by-join is refused.
    JoinCorrelation,
    /// The predicate references a **volatile / non-immutable function or special
    /// value** (`now()`, `random()`, `current_user`, …). Carries the underlying
    /// [`VolatileReason`] — a non-immutable predicate is steerable across the
    /// approval/apply boundary even when every column reference is the PK.
    NonImmutable(VolatileReason),
    /// The statement could not be parsed, or is not an `UPDATE`/`DELETE` with a
    /// vettable predicate → fail-closed (cannot prove self-determined).
    Unclassifiable,
}

impl std::fmt::Display for NotSelfDetermined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotSelfDetermined::NonPkColumn { pk_col, referenced } => write!(
                f,
                "predicate references non-PK column `{referenced}` (only the immutable \
                 primary-key column `{pk_col}` + literals + immutable functions on it are \
                 self-determined; a mutable column is steerable to a chosen row)"
            ),
            NotSelfDetermined::Subquery => write!(
                f,
                "predicate contains a subquery / correlated reference / EXISTS / IN (SELECT …) \
                 (its row set is not pinned by the immutable primary key)"
            ),
            NotSelfDetermined::JoinCorrelation => write!(
                f,
                "statement joins a second relation into the target (UPDATE … FROM / DELETE … USING \
                 / a JOIN on the target) — the affected row set is determined by the joined \
                 table's content, which is steerable, so it is not pinned by the immutable \
                 primary key"
            ),
            NotSelfDetermined::NonImmutable(reason) => {
                write!(f, "predicate is not immutable: {reason}")
            }
            NotSelfDetermined::Unclassifiable => write!(
                f,
                "predicate could not be classified as self-determined (fail-closed)"
            ),
        }
    }
}

/// Classify whether `sql`'s WHERE predicate is **self-determined** on the
/// single-column primary key `pk_col` (EPIC #91 PR-A grant-bound gate).
///
/// Returns `Some(reason)` if the statement must be **REFUSED** (the predicate's
/// row set could be steered by other writes), or `None` only when the predicate
/// has been *positively shown* self-determined: every column reference is the PK
/// column, there is no subquery/correlated/EXISTS node, and every function is
/// immutable (resolved via `resolver`, the same `pg_proc.provolatile` seam the
/// volatility check uses).
///
/// `pk_col` is compared case-insensitively on its bare (unqualified) name, so a
/// qualified reference (`accounts.id`, `t.id`) to the PK is accepted while a
/// reference to any *other* column is refused.
///
/// Fail-closed:
/// - an unparseable / non-`UPDATE`/`DELETE` statement → `Some(Unclassifiable)`;
/// - a **missing/empty WHERE** → `Some(Unclassifiable)` (a no-WHERE write is not a
///   self-determined *predicate*; the grant path must not treat the absence of a
///   predicate as a bypass — it is handled by the cap / row-count guards
///   elsewhere, but this gate refuses to certify it as self-determined);
/// - a function whose volatility cannot be resolved → `Some(NonImmutable(...))`;
/// - any column reference that is not the PK → `Some(NonPkColumn { .. })`.
///
/// It only *reads* via `resolver`; it never executes the candidate statement.
pub fn self_determined_predicate_reason(
    sql: &str,
    pk_col: &str,
    resolver: &mut dyn FunctionVolatility,
) -> Option<NotSelfDetermined> {
    let dialect = PostgreSqlDialect {};
    let parsed = match Parser::parse_sql(&dialect, sql) {
        Ok(p) if p.len() == 1 => p,
        _ => return Some(NotSelfDetermined::Unclassifiable),
    };

    // A join-correlated write (UPDATE … FROM / DELETE … USING / a JOIN on the target)
    // is steerable by the joined table's content → refuse BEFORE inspecting the WHERE
    // (the WHERE may itself reference only the PK, e.g. `… FROM other WHERE other.id =
    // t.id`, yet the row set is still determined by `other`). EPIC #91 PR-B.
    if let Some(reason) = join_correlation_reason(&parsed[0]) {
        return Some(reason);
    }

    let predicate = match predicate_of(&parsed[0]) {
        // No WHERE clause → not a self-determined *predicate* (fail-closed: the
        // grant path must not treat a no-WHERE write as self-determined).
        Some(None) | None => return Some(NotSelfDetermined::Unclassifiable),
        Some(Some(p)) => p,
    };

    // (a) Structural walk FIRST: refuse any subquery/correlated node, and require
    //     every column identifier to be the PK column. A subquery is a structural
    //     refusal independent of the functions inside it, so this runs before the
    //     volatility delegation (which would otherwise report a function *inside*
    //     the subquery — e.g. `(SELECT max(id) …)` — instead of the subquery
    //     itself). The two checks together pin the row set to the immutable PK +
    //     literals.
    let pk_bare = bare_name(&pk_col.to_lowercase());
    if let Some(reason) = classify_self_determined_expr(predicate, &pk_bare) {
        return Some(reason);
    }

    // (b) Reuse the volatility machinery on the (now subquery-free, PK-only)
    //     predicate: every function must be immutable (the keyword deny-set +
    //     pg_proc.provolatile resolver). A non-immutable / unresolvable /
    //     nondeterministic-keyword predicate is steerable across the approval/apply
    //     boundary → refuse. We re-derive the reason from the *whole* statement so
    //     the function walk + keyword check is identical to the volatility gate
    //     (single source of truth).
    if let Some(reason) = predicate_volatile_reason(sql, resolver) {
        return Some(NotSelfDetermined::NonImmutable(reason));
    }

    None
}

/// The **structural-only** half of the self-determined gate (no volatility seam):
/// classify whether `sql`'s WHERE predicate references only the PK column +
/// literals + (structurally) functions/operators, refusing non-PK columns and
/// subqueries/correlated nodes — but **not** resolving function volatility.
///
/// This is the apply-path **defense-in-depth** form (EPIC #91 PR-A): at apply
/// time the statement text is grant-bound (byte-identical to the one the dry-run
/// gate already vetted for volatility), and the apply seam has no
/// `pg_proc.provolatile` resolver in hand, so re-proving volatility here would
/// either need a second resolver or fail-closed-refuse every immutable function
/// the dry-run already allowed. We therefore re-check only the **structural**
/// identity-steerability (PK-only columns, no subquery) — the part that pins the
/// row set to the immutable PK — as a second, independent gate before the apply
/// txn opens. The full (volatility-resolving) gate is
/// [`self_determined_predicate_reason`], enforced at dry-run/certify.
///
/// Fail-closed identically: unparseable / non-`UPDATE`/`DELETE` / missing-WHERE →
/// `Some(Unclassifiable)`; a non-PK column → `Some(NonPkColumn)`; a subquery →
/// `Some(Subquery)`. Returns `None` only when the predicate is structurally
/// self-determined on `pk_col`.
pub fn self_determined_predicate_structural_reason(
    sql: &str,
    pk_col: &str,
) -> Option<NotSelfDetermined> {
    let dialect = PostgreSqlDialect {};
    let parsed = match Parser::parse_sql(&dialect, sql) {
        Ok(p) if p.len() == 1 => p,
        _ => return Some(NotSelfDetermined::Unclassifiable),
    };
    // Join-correlation (UPDATE … FROM / DELETE … USING / a JOIN on the target) is
    // refused structurally too — the apply-path defense-in-depth gate (EPIC #91 PR-B).
    if let Some(reason) = join_correlation_reason(&parsed[0]) {
        return Some(reason);
    }
    let predicate = match predicate_of(&parsed[0]) {
        Some(None) | None => return Some(NotSelfDetermined::Unclassifiable),
        Some(Some(p)) => p,
    };
    let pk_bare = bare_name(&pk_col.to_lowercase());
    classify_self_determined_expr(predicate, &pk_bare)
}

/// Recursively classify `expr`: refuse subqueries/correlated nodes and any
/// non-PK column reference. Returns `Some(reason)` on the first violation, `None`
/// if the whole subtree is self-determined.
///
/// We hand-walk (rather than reuse `visit_expressions`) so we can REFUSE a
/// subquery node *as a whole* — descending into a subquery's body and inspecting
/// its column identifiers would be both wrong (those columns belong to another
/// query scope) and a bypass risk.
fn classify_self_determined_expr(expr: &Expr, pk_bare: &str) -> Option<NotSelfDetermined> {
    match expr {
        // --- column references: the bare name must be the PK column -----------
        Expr::Identifier(ident) => non_pk_column(ident, pk_bare),
        Expr::CompoundIdentifier(parts) => {
            // `table.col` / `schema.table.col` — the *last* part is the column.
            match parts.last() {
                Some(col) => non_pk_column(col, pk_bare),
                None => Some(NotSelfDetermined::Unclassifiable),
            }
        }
        // A field/subscript access (`a.b`, `a['k']`, `a[1]`) is rooted at a
        // column expr — vet the root (and any index exprs).
        Expr::CompoundFieldAccess { root, access_chain } => {
            if let Some(r) = classify_self_determined_expr(root, pk_bare) {
                return Some(r);
            }
            // The access operations may carry index expressions; vet them too.
            // A subscript that is a literal is fine; a column ref inside is not.
            // We conservatively stringify-and-reparse-free: walk via visitor over
            // the access chain's exprs using the same per-expr classifier.
            let mut found = None;
            let _ = visit_expressions(expr, |e| {
                // Skip the root (already vetted) and the outer node itself.
                if std::ptr::eq(e, expr) {
                    return ControlFlow::Continue(());
                }
                if let Some(r) = classify_atom_only(e, pk_bare) {
                    found = Some(r);
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            let _ = access_chain;
            found
        }

        // --- subquery / correlated / set nodes: REFUSE as a whole ------------
        Expr::Subquery(_) | Expr::Exists { .. } => Some(NotSelfDetermined::Subquery),
        Expr::InSubquery { .. } => Some(NotSelfDetermined::Subquery),
        Expr::AnyOp { right, .. } | Expr::AllOp { right, .. } => {
            // `= ANY(<subquery>)` / `= ALL(<subquery>)` — the right side is a
            // subquery-or-array. Either way it is not pinned by the PK → refuse.
            // (An array literal would be self-determined, but ANY/ALL over a
            // (sub)query is the steerable form; we refuse the whole construct
            // fail-closed rather than try to distinguish, since the grant path
            // has no need for ANY/ALL — `id IN (1,2,3)` covers the literal case.)
            let _ = right;
            Some(NotSelfDetermined::Subquery)
        }
        Expr::InUnnest { .. } => Some(NotSelfDetermined::Subquery),

        // --- boolean / comparison / arithmetic structure: recurse ------------
        Expr::BinaryOp { left, right, .. } => classify_self_determined_expr(left, pk_bare)
            .or_else(|| classify_self_determined_expr(right, pk_bare)),
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr) => classify_self_determined_expr(expr, pk_bare),
        Expr::Between {
            expr, low, high, ..
        } => classify_self_determined_expr(expr, pk_bare)
            .or_else(|| classify_self_determined_expr(low, pk_bare))
            .or_else(|| classify_self_determined_expr(high, pk_bare)),
        Expr::InList { expr, list, .. } => {
            if let Some(r) = classify_self_determined_expr(expr, pk_bare) {
                return Some(r);
            }
            list.iter()
                .find_map(|e| classify_self_determined_expr(e, pk_bare))
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. }
        | Expr::RLike { expr, pattern, .. } => classify_self_determined_expr(expr, pk_bare)
            .or_else(|| classify_self_determined_expr(pattern, pk_bare)),
        Expr::Cast { expr, .. } | Expr::Collate { expr, .. } => {
            classify_self_determined_expr(expr, pk_bare)
        }
        Expr::IsDistinctFrom(a, b) | Expr::IsNotDistinctFrom(a, b) => {
            classify_self_determined_expr(a, pk_bare)
                .or_else(|| classify_self_determined_expr(b, pk_bare))
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(op) = operand
                && let Some(r) = classify_self_determined_expr(op, pk_bare)
            {
                return Some(r);
            }
            for when in conditions {
                if let Some(r) = classify_self_determined_expr(&when.condition, pk_bare) {
                    return Some(r);
                }
                if let Some(r) = classify_self_determined_expr(&when.result, pk_bare) {
                    return Some(r);
                }
            }
            if let Some(er) = else_result
                && let Some(r) = classify_self_determined_expr(er, pk_bare)
            {
                return Some(r);
            }
            None
        }

        // --- functions: their immutability was already proven in step (a). Their
        //     ARGUMENTS may still reference a non-PK column (`lower(status)`), so
        //     vet every argument expression via the generic atom walk. -----------
        Expr::Function(_) => {
            let mut found = None;
            let _ = visit_expressions(expr, |e| {
                if std::ptr::eq(e, expr) {
                    return ControlFlow::Continue(());
                }
                // A nested subquery inside a function arg is still a subquery.
                if let Some(r) = classify_atom_only(e, pk_bare) {
                    found = Some(r);
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            found
        }

        // --- literals / constants: always self-determined --------------------
        Expr::Value(_) | Expr::TypedString { .. } | Expr::Interval(_) => None,

        // --- anything else we do not explicitly model: fail-closed. New SQL
        //     surface (lambdas, JSON access over columns, struct/map literals,
        //     `AT TIME ZONE`, …) is REFUSED rather than waved through, so the gate
        //     never silently admits an un-vetted construct. -----------------------
        _ => {
            // Conservatively walk the subtree: if it contains ANY non-PK column or
            // subquery atom, refuse with that reason; otherwise refuse as
            // unclassifiable (a construct we do not model).
            let mut found = None;
            let _ = visit_expressions(expr, |e| {
                if let Some(r) = classify_atom_only(e, pk_bare) {
                    found = Some(r);
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            Some(found.unwrap_or(NotSelfDetermined::Unclassifiable))
        }
    }
}

/// Classify a *single* node for the "atom" sweep used inside function args and
/// unmodeled constructs: a non-PK column ref or a subquery node → its reason;
/// everything else → `None` (the visitor keeps descending).
fn classify_atom_only(e: &Expr, pk_bare: &str) -> Option<NotSelfDetermined> {
    match e {
        Expr::Identifier(ident) => non_pk_column(ident, pk_bare),
        Expr::CompoundIdentifier(parts) => parts.last().and_then(|col| non_pk_column(col, pk_bare)),
        Expr::Subquery(_)
        | Expr::Exists { .. }
        | Expr::InSubquery { .. }
        | Expr::AnyOp { .. }
        | Expr::AllOp { .. }
        | Expr::InUnnest { .. } => Some(NotSelfDetermined::Subquery),
        _ => None,
    }
}

/// `Some(NonPkColumn)` if `ident`'s bare name is not the PK column, else `None`.
fn non_pk_column(ident: &Ident, pk_bare: &str) -> Option<NotSelfDetermined> {
    if ident.value.to_lowercase() == pk_bare {
        None
    } else {
        Some(NotSelfDetermined::NonPkColumn {
            pk_col: pk_bare.to_string(),
            referenced: ident.value.clone(),
        })
    }
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

/// `Some(JoinCorrelation)` if `stmt` joins a **second relation** into the target
/// (EPIC #91 PR-B): an `UPDATE … FROM other`, a `DELETE … USING other`, or an
/// explicit JOIN on the target's `TableWithJoins`. Such a statement's affected
/// row set is a function of the joined table's content — steerable by another
/// write — so its row set is NOT pinned by the immutable PK, even when the WHERE
/// clause itself references only the PK (e.g. `UPDATE t SET … FROM other WHERE
/// other.id = t.id`). Returns `None` for the supported single-table form.
fn join_correlation_reason(stmt: &Statement) -> Option<NotSelfDetermined> {
    match stmt {
        Statement::Update(update) => {
            // `UPDATE … FROM other` (the additional value source) is a join.
            if update.from.is_some() {
                return Some(NotSelfDetermined::JoinCorrelation);
            }
            // An explicit JOIN attached to the UPDATE target relation is a join too.
            if !update.table.joins.is_empty() {
                return Some(NotSelfDetermined::JoinCorrelation);
            }
            None
        }
        Statement::Delete(delete) => {
            // `DELETE … USING other` is a join-correlated delete.
            if delete.using.is_some() {
                return Some(NotSelfDetermined::JoinCorrelation);
            }
            // A target table-factor that itself carries JOINs is a join.
            use sqlparser::ast::FromTable;
            let from_tables = match &delete.from {
                FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
            };
            if from_tables.iter().any(|twj| !twj.joins.is_empty()) {
                return Some(NotSelfDetermined::JoinCorrelation);
            }
            None
        }
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
        // Case-insensitive: bare COALESCE (uppercase) still proceeds.
        assert_eq!(
            reason("DELETE FROM t WHERE COALESCE(owner, 'd') = 'x'"),
            None
        );
        // Schema-qualified `pg_catalog.coalesce` is NOT covered by the allow-set
        // (it is schema-qualified and must fall through to pg_proc.provolatile;
        // pg_catalog.coalesce has no pg_proc row → Unknown → refused fail-closed).
        // This is intentionally more conservative than the old behaviour; the §4
        // qualified-bypass fix (see below) documents this edge.
        assert!(matches!(
            reason("UPDATE t SET x=0 WHERE pg_catalog.coalesce(owner,'') = 'x'"),
            Some(VolatileReason::UnresolvableFunction(_))
        ));
    }

    // --- §4 qualified-bypass fix: schema-qualified special-form names are NOT
    //     short-circuited; they fall through to pg_proc.provolatile (fail-closed)
    // -------------------------------------------------------------------------

    #[test]
    fn schema_qualified_coalesce_udf_is_refused_via_provolatile() {
        // THE BYPASS: `public.coalesce(bigint)` is a real VOLATILE UDF. Before the
        // fix the allow-set matched on the bare name `coalesce` regardless of
        // schema, skipping the pg_proc lookup and allowing the volatile predicate.
        // After the fix the schema-qualified name is NOT short-circuited; the
        // MapResolver returns Volatile for "coalesce" (simulating a volatile UDF),
        // and the engine correctly REFUSES.
        let mut resolver = MapResolver::new(&[("coalesce", Volatility::Volatile)]);
        let r = predicate_volatile_reason(
            "UPDATE public.accounts SET balance=0 WHERE public.coalesce(id::bigint) IS NOT NULL",
            &mut resolver,
        );
        assert!(
            matches!(r, Some(VolatileReason::VolatileFunction(ref n)) if n == "public.coalesce"),
            "schema-qualified volatile UDF named coalesce must be REFUSED via provolatile, got {r:?}"
        );
    }

    #[test]
    fn schema_qualified_nonexistent_function_is_refused_fail_closed() {
        // A schema-qualified call to a function that does not exist in pg_proc
        // (resolver returns Unknown) must be REFUSED fail-closed, even if the bare
        // name matches the allow-set.
        let mut resolver = NoFunctionVolatility; // everything → Unknown
        let r = predicate_volatile_reason(
            "UPDATE t SET x=0 WHERE public.coalesce(id::bigint) IS NOT NULL",
            &mut resolver,
        );
        assert!(
            matches!(r, Some(VolatileReason::UnresolvableFunction(ref n)) if n == "public.coalesce"),
            "schema-qualified unresolvable function must be REFUSED fail-closed, got {r:?}"
        );
    }

    #[test]
    fn bare_special_forms_still_proceed_after_fix() {
        // Regression guard: the fix must NOT break the legitimate use-case of bare
        // (unqualified) special forms. coalesce/nullif/greatest/least without a
        // schema prefix must still proceed (they are the genuine SQL special forms
        // with no pg_proc row, and they are deterministic).
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE coalesce(owner,'') = 'x'"),
            None,
            "bare coalesce must still proceed after the qualified-bypass fix"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE nullif(a,b) IS NULL"),
            None,
            "bare nullif must still proceed"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE greatest(a,b) > 0"),
            None,
            "bare greatest must still proceed"
        );
        assert_eq!(
            reason("UPDATE public.accounts SET balance=0 WHERE least(a,b) < 10"),
            None,
            "bare least must still proceed"
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
        assert!(
            VolatileReason::VolatileFunction("random".into())
                .to_string()
                .contains("provolatile = 'v'")
        );
    }

    // =======================================================================
    //  Self-determined-predicate gate (EPIC #91 PR-A).
    //
    //  ALLOW  ⇒ self_determined_predicate_reason(...) == None
    //  REFUSE ⇒ Some(<the steerability reason>)
    //
    //  PK column is `id` for the single-int4-PK shape.
    // =======================================================================

    fn sd(sql: &str) -> Option<NotSelfDetermined> {
        self_determined_predicate_reason(sql, "id", &mut immutable_world())
    }

    // --- ALLOW: PK-only predicates (literals + immutable ops on the PK) -------

    #[test]
    fn pk_equality_is_self_determined() {
        assert_eq!(sd("UPDATE accounts SET balance=0 WHERE id = 42"), None);
    }

    #[test]
    fn pk_in_list_is_self_determined() {
        assert_eq!(
            sd("UPDATE accounts SET balance=0 WHERE id IN (1,2,3)"),
            None
        );
        assert_eq!(sd("DELETE FROM accounts WHERE id IN (1, 2, 3)"), None);
    }

    #[test]
    fn pk_between_is_self_determined() {
        assert_eq!(
            sd("UPDATE accounts SET balance=0 WHERE id BETWEEN 1 AND 100"),
            None
        );
    }

    #[test]
    fn marquee_pk_modulo_is_self_determined() {
        // THE MARQUEE shape: `WHERE id % 2 = 0` — every column ref is the PK,
        // `%` is an immutable operator, `2`/`0` are literals. MUST be ALLOWED so
        // PR-B / the marquee do not break.
        assert_eq!(sd("UPDATE accounts SET balance=0 WHERE id % 2 = 0"), None);
    }

    #[test]
    fn pk_boolean_combinations_are_self_determined() {
        assert_eq!(sd("UPDATE t SET x=0 WHERE id = 42 OR id = 99"), None);
        assert_eq!(sd("UPDATE t SET x=0 WHERE id > 10 AND id < 20"), None);
        assert_eq!(sd("UPDATE t SET x=0 WHERE NOT (id = 5)"), None);
        assert_eq!(
            sd("DELETE FROM t WHERE (id = 1 OR id = 2) AND id < 100"),
            None
        );
    }

    #[test]
    fn immutable_function_on_pk_is_self_determined() {
        // abs(id) is IMMUTABLE and its only column arg is the PK.
        assert_eq!(sd("UPDATE t SET x=0 WHERE abs(id) > 100"), None);
    }

    #[test]
    fn qualified_pk_reference_is_self_determined() {
        // `accounts.id` / `t.id` — the column is still the PK (last component).
        assert_eq!(
            sd("UPDATE accounts SET balance=0 WHERE accounts.id = 7"),
            None
        );
    }

    #[test]
    fn case_insensitive_pk_match() {
        // The PK column name compare is case-insensitive.
        assert_eq!(
            self_determined_predicate_reason(
                "UPDATE t SET x=0 WHERE ID = 1",
                "id",
                &mut immutable_world()
            ),
            None
        );
    }

    // --- REFUSE: non-PK column references (steerable mutable columns) ---------

    #[test]
    fn non_pk_column_is_refused() {
        assert!(matches!(
            sd("UPDATE accounts SET balance=0 WHERE status = 'cancelled'"),
            Some(NotSelfDetermined::NonPkColumn { ref referenced, .. }) if referenced == "status"
        ));
    }

    #[test]
    fn bare_boolean_non_pk_column_is_refused() {
        assert!(matches!(
            sd("UPDATE accounts SET balance=0 WHERE flagged"),
            Some(NotSelfDetermined::NonPkColumn { ref referenced, .. }) if referenced == "flagged"
        ));
    }

    #[test]
    fn pk_and_non_pk_mix_is_refused() {
        // Even mixed with the PK, a non-PK column makes the row set steerable.
        // (My task prompt: only the PK column may be referenced.)
        assert!(matches!(
            sd("UPDATE accounts SET balance=0 WHERE id = 42 AND status = 'x'"),
            Some(NotSelfDetermined::NonPkColumn { ref referenced, .. }) if referenced == "status"
        ));
    }

    #[test]
    fn column_to_column_comparison_is_refused() {
        // `WHERE a = b` — `a` (non-PK) is the first violation.
        assert!(matches!(
            sd("UPDATE t SET x=0 WHERE a = b"),
            Some(NotSelfDetermined::NonPkColumn { .. })
        ));
        // `WHERE id = other` — the PK compared to another (mutable) column.
        assert!(matches!(
            sd("UPDATE t SET x=0 WHERE id = other_col"),
            Some(NotSelfDetermined::NonPkColumn { ref referenced, .. }) if referenced == "other_col"
        ));
    }

    #[test]
    fn non_pk_column_inside_function_arg_is_refused() {
        // lower() is IMMUTABLE, but its argument is a non-PK column → steerable.
        assert!(matches!(
            sd("UPDATE t SET x=0 WHERE lower(status) = 'x'"),
            Some(NotSelfDetermined::NonPkColumn { ref referenced, .. }) if referenced == "status"
        ));
    }

    // --- REFUSE: subqueries / correlated / EXISTS / IN(SELECT) / ANY/ALL ------

    #[test]
    fn in_subquery_is_refused() {
        assert_eq!(
            sd("UPDATE accounts SET balance=0 WHERE id IN (SELECT account_id FROM flags)"),
            Some(NotSelfDetermined::Subquery)
        );
    }

    #[test]
    fn scalar_subquery_is_refused() {
        assert_eq!(
            sd("UPDATE accounts SET balance=0 WHERE id = (SELECT max(id) FROM accounts)"),
            Some(NotSelfDetermined::Subquery)
        );
    }

    #[test]
    fn exists_subquery_is_refused() {
        assert_eq!(
            sd(
                "DELETE FROM accounts WHERE EXISTS (SELECT 1 FROM flags WHERE flags.id = accounts.id)"
            ),
            Some(NotSelfDetermined::Subquery)
        );
    }

    #[test]
    fn any_subquery_is_refused() {
        assert_eq!(
            sd("UPDATE t SET x=0 WHERE id = ANY (SELECT id FROM s)"),
            Some(NotSelfDetermined::Subquery)
        );
    }

    // --- REFUSE: join-correlation (UPDATE … FROM / DELETE … USING) — EPIC #91 PR-B -

    #[test]
    fn update_from_join_correlation_is_refused() {
        // THE CARRIED FINDING: `UPDATE t SET … FROM other WHERE other.id = t.id` —
        // the WHERE looks PK-pinned, but the affected row set is determined by the
        // joined `other`, which an attacker can write → steerable → REFUSED. (Was only
        // incidentally fail-closed by the now-removed apply-time PK-set recompute.)
        assert_eq!(
            sd("UPDATE accounts SET balance = 0 FROM evil WHERE evil.id = accounts.id"),
            Some(NotSelfDetermined::JoinCorrelation)
        );
        // Even with the WHERE referencing only the target PK + the joined table:
        assert_eq!(
            sd("UPDATE accounts SET balance = 0 FROM other WHERE accounts.id = other.account_id"),
            Some(NotSelfDetermined::JoinCorrelation)
        );
    }

    #[test]
    fn delete_using_join_correlation_is_refused() {
        // `DELETE FROM t USING other WHERE other.id = t.id` — same steerability.
        assert_eq!(
            sd("DELETE FROM accounts USING evil WHERE evil.id = accounts.id"),
            Some(NotSelfDetermined::JoinCorrelation)
        );
    }

    #[test]
    fn structural_gate_also_refuses_join_correlation() {
        // The apply-path structural-only gate (no volatility seam) must ALSO refuse
        // join-correlation (defense in depth, EPIC #91 PR-B).
        assert_eq!(
            self_determined_predicate_structural_reason(
                "UPDATE accounts SET balance = 0 FROM evil WHERE evil.id = accounts.id",
                "id",
            ),
            Some(NotSelfDetermined::JoinCorrelation)
        );
        assert_eq!(
            self_determined_predicate_structural_reason(
                "DELETE FROM accounts USING evil WHERE evil.id = accounts.id",
                "id",
            ),
            Some(NotSelfDetermined::JoinCorrelation)
        );
        // The supported single-table PK form still passes the structural gate.
        assert_eq!(
            self_determined_predicate_structural_reason(
                "UPDATE accounts SET balance = 0 WHERE id IN (1,2,3)",
                "id",
            ),
            None
        );
    }

    // --- REFUSE: volatile / non-immutable predicate (delegated to volatility) -

    #[test]
    fn volatile_now_against_non_pk_column_is_refused() {
        // `now() > created`: BOTH a volatile function AND a non-PK column. The
        // structural (column) check fires first — either refusal is correct; what
        // matters is that this steerable predicate is REFUSED, never allowed.
        assert!(matches!(
            sd("UPDATE accounts SET balance=0 WHERE now() > created"),
            Some(NotSelfDetermined::NonPkColumn { .. }) | Some(NotSelfDetermined::NonImmutable(_))
        ));
    }

    #[test]
    fn volatile_now_with_pk_only_columns_is_refused_as_non_immutable() {
        // PK-only columns but a volatile function → the volatility delegation
        // catches it as non-immutable (the steerability is the function, not a
        // column). This isolates the (b) volatility path of the gate.
        assert!(matches!(
            sd("UPDATE accounts SET balance=0 WHERE id % 2 = 0 AND now() > localtimestamp"),
            Some(NotSelfDetermined::NonImmutable(
                VolatileReason::NondeterministicKeyword(_)
            ))
        ));
    }

    #[test]
    fn volatile_random_with_pk_only_is_refused_as_non_immutable() {
        // random() is VOLATILE (pg_proc.provolatile='v'); no column references at
        // all, so only the volatility path can catch it.
        assert!(matches!(
            sd("DELETE FROM accounts WHERE random() < 0.5 OR id = 1"),
            Some(NotSelfDetermined::NonImmutable(
                VolatileReason::VolatileFunction(_)
            ))
        ));
    }

    // --- fail-closed: no WHERE / unparseable / non-update-delete -------------

    #[test]
    fn no_where_clause_is_not_self_determined() {
        // A no-WHERE write is NOT a self-determined *predicate*; the grant path
        // must not treat the absence of a predicate as a bypass.
        assert_eq!(
            sd("UPDATE accounts SET balance=0"),
            Some(NotSelfDetermined::Unclassifiable)
        );
    }

    #[test]
    fn unparseable_is_fail_closed() {
        assert_eq!(
            sd("UPDATE WHERE )( garbage"),
            Some(NotSelfDetermined::Unclassifiable)
        );
    }

    #[test]
    fn non_update_delete_is_fail_closed() {
        assert_eq!(
            sd("SELECT * FROM t WHERE id = 1"),
            Some(NotSelfDetermined::Unclassifiable)
        );
    }

    #[test]
    fn unresolvable_function_is_refused_fail_closed() {
        // An unknown function (not immutable-provable) → non-immutable refuse.
        assert!(matches!(
            sd("UPDATE t SET x=0 WHERE mystery_fn(id) = 1"),
            Some(NotSelfDetermined::NonImmutable(
                VolatileReason::UnresolvableFunction(_)
            ))
        ));
    }

    #[test]
    fn reasons_render_human_readable() {
        assert!(
            NotSelfDetermined::NonPkColumn {
                pk_col: "id".into(),
                referenced: "status".into()
            }
            .to_string()
            .contains("non-PK column `status`")
        );
        assert!(NotSelfDetermined::Subquery.to_string().contains("subquery"));
    }
}
