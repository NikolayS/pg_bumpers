//! pg_brakes **proxy** — the inline, agent-only enforcement point (SPEC §3
//! layer 2, §4, §7 S1). This is the project's core IP.
//!
//! The proxy terminates an agent's PostgreSQL connection (SCRAM-SHA-256 over
//! TLS), opens a **separate** backend connection to PG18 as the hardened WALL
//! role `pgb_agent` (the only network path to the DB — SPEC §3 layer 0), and
//! drives the FE/BE message loop through [`crate::pgwire`]-level framing with
//! the deterministic-floor enforcement hooks wired in:
//!
//! 1. **extended-protocol-only** — reject the simple `Query` ('Q') path and all
//!    `COPY` traffic, which kills `COMMIT; DROP SCHEMA …` statement-stacking;
//! 2. **read-only** — classify each `Parse` SQL; non-`Read` is blocked. This is
//!    the **real gate** for the function-call write class (M2a #114/#115): a
//!    `SELECT` is a read only if every function it references is on a curated
//!    read-safe allowlist AND it uses no **qualified/custom operator**, no
//!    **schema-qualified (non-builtin) cast target**, and no **`FOR
//!    UPDATE`/`FOR SHARE` row-lock clause** — so
//!    `SELECT lo_create(…)`/`setval(…)`/`public.writing_fn()`,
//!    `a OPERATOR(public.writeop) b`, `x::public.evil`, and `… FOR UPDATE` are
//!    all Blocked here, never forwarded. Because M2 (#113) drops the DB-level
//!    `REVOKE … FROM PUBLIC` for exactly this function/lo class, the WALL role is
//!    NOT the backstop here — the independent floors that remain are
//!    `statement_timeout` + the byte/row cutoff (see the threat-model note);
//! 3. **EXPLAIN-cost gate** ([`explain`]) — before a read executes, run
//!    `EXPLAIN` (no `ANALYZE`) and block pre-flight if the planner's estimated
//!    cost/rows exceed the per-role ceiling (advisory + fail-closed);
//! 4. **byte/row mid-stream cutoff** — count `DataRow` bytes/rows from the
//!    backend and cut the stream off at the per-role budget from `policy.yaml`;
//! 5. **cumulative per-window volume budget** ([`window`]) — accumulate
//!    bytes/rows streamed across statements and kill the session when the
//!    rolling-window budget is exceeded (anti slow-drip, deterministic clock);
//! 6. **timeout injection** — `SET statement_timeout` on the backend session;
//! 7. **fail-closed** — any parse/enforcement uncertainty denies;
//! 8. **audit** — every statement (allow/block/reject) is recorded on a
//!    hash-chained [`pgb_audit`] chain.
//!
//! ## Threat-model note (from the pgwire review; updated for M2a #114/#115)
//! The read-only classifier **fail-closes on non-allowlisted side-effecting
//! constructs**: a `SELECT` is a `Read` only if — anywhere in the statement AST
//! (projection, `WHERE`/`HAVING`/`GROUP BY`/`ORDER BY`, JOIN `ON`, aggregate
//! `FILTER`/`ORDER BY`, subqueries, CTEs, function/operator arguments, and
//! table-valued functions in `FROM`/`JOIN`) — EVERY function it references is on
//! a curated read-safe allowlist, it uses no **qualified/custom operator**
//! (`a OPERATOR(public.writeop) b`, whose backing function is arbitrary), no
//! **schema-qualified / non-builtin cast target** (`x::public.evil`, whose type
//! input function can side-effect), and no **`FOR UPDATE`/`FOR SHARE` row-lock
//! clause** (a lock-DoS side effect on the primary). So the previously "foolable"
//! forms — `nextval`/`setval`/`pg_sleep`/`lo_export`/`lo_create`/`pg_read_file`/
//! `dblink` and EVERY user/unknown/qualified `schema.fn()` (incl. a SECURITY
//! DEFINER write fn), qualified/custom operators, non-builtin casts, and lock
//! clauses — now classify `NotRead` and are **Blocked at this gate**, never
//! forwarded to the backend.
//!
//! This is what lets the DB-level `REVOKE … FROM PUBLIC` backstop be dropped from
//! a BYO-prod default for exactly this function/large-object class (M2 #113)
//! without reopening the catastrophic-FN path. **Precisely because M2 removes
//! that revoke for this class, the WALL `… FROM PUBLIC` grant is NO LONGER the
//! backstop here** — the classifier is the primary gate, and the *independent*
//! floors that still backstop this class are **`statement_timeout`** and the
//! **byte/row cutoff** (both fail-closed). (The WALL hardened role still governs
//! everything the revoke does cover — table DML, DDL, etc. — but it is not what
//! stops a `SELECT lo_create(…)` for this class; the classifier is.)
//!
//! ## Clean-room note
//! Built from the SPEC and the public PostgreSQL v3 protocol / RFC 5802+7677
//! only. No pgDog (AGPL) code was consulted or copied.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod budget;
pub mod config;
pub mod enforce;
pub mod explain;
pub mod recorder;
pub mod session;
pub mod threaded_sink;
pub mod tls;
pub mod window;

pub use budget::{Budget, BudgetOutcome};
pub use config::ProxyConfig;
pub use enforce::{Enforcement, GateDecision, RejectKind};
pub use explain::{
    EstimateDecision, EstimateDim, ExplainCeiling, ExplainGate, PlanEstimate, explain_wrap,
};
pub use recorder::Recorder;
pub use session::{SessionError, serve_connection};
pub use threaded_sink::ThreadedSink;
pub use window::{WindowCap, WindowMeter, WindowOutcome};
