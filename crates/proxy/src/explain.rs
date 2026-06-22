//! The **EXPLAIN-cost gate** — an *advisory, fail-closed* pre-flight cost gate
//! for the read path (SPEC §3 layer 2, §11.6, deferred from S1 → S4).
//!
//! Before a classified read is executed, the proxy runs `EXPLAIN` (no `ANALYZE`,
//! so the statement is *not* run) on the backend, parses the planner's estimated
//! **total cost** and **row estimate** off the top plan node, and compares them
//! to a per-role ceiling from `policy.yaml`. An estimate over the ceiling is
//! **blocked before execution** — the heavy query never streams a single row.
//!
//! ## Advisory + fail-closed (read this)
//!
//! This gate is **advisory**: it trusts the PostgreSQL planner's *estimate*, and
//! a planner misestimation (stale stats, a correlated predicate the planner
//! underestimates, a `LIMIT` it discounts) can let an actually-heavy query slip
//! the ceiling. So it is **never the sole DoS backstop**. The un-foolable
//! guarantees remain the **`statement_timeout`** (caps wall-clock), the
//! **byte/row mid-stream cutoff** ([`crate::budget`], caps a single statement's
//! volume), the **per-window cumulative budget** ([`crate::window`], caps
//! slow-drip), and the out-of-band **warden**. The EXPLAIN gate is
//! defense-in-depth that stops the *obvious* heavy plan ~for free, before it
//! runs.
//!
//! It is **fail-closed**: if `EXPLAIN` itself errors (the SQL doesn't plan, a
//! permission error, a backend error) or its output can't be parsed into an
//! estimate, the statement is **blocked** — the gate refuses anything it cannot
//! prove is under the ceiling, exactly like the read-only classifier.

use pgb_policy::RoleBudget;

/// The per-role EXPLAIN ceiling: the maximum estimated total plan cost and the
/// maximum estimated row count a read may have before it is allowed to execute.
///
/// Derived from a role's [`RoleBudget`] in [`ExplainCeiling::for_role`] so the
/// single `policy.yaml` stays the source of truth: the cost ceiling is the
/// budget's explicit `max_plan_cost` and the row ceiling is its explicit
/// `max_plan_rows` — **both independent of the single-shot cutoff caps**. The
/// EXPLAIN gate is advisory (planner *estimates*); coupling its row dimension to
/// the un-foolable single-shot `max_rows` cutoff would let an over-estimate
/// pre-empt the real cutoff (an un-analyzed table the planner over-estimates
/// would be blocked even though the actual result is tiny). So `max_plan_rows`
/// defaults generously high; the cost ceiling is the primary EXPLAIN dimension.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExplainCeiling {
    /// Maximum estimated **total cost** (planner cost units) for a read.
    pub max_cost: f64,
    /// Maximum estimated **row count** for a read.
    pub max_rows: u64,
}

impl ExplainCeiling {
    /// Build the ceiling for a role from its budget: the cost ceiling is the
    /// role's `max_plan_cost`; the row ceiling is its `max_plan_rows` (both
    /// distinct from the single-shot cutoff caps — see the type docs).
    pub fn for_role(budget: &RoleBudget) -> Self {
        ExplainCeiling {
            max_cost: budget.max_plan_cost,
            max_rows: budget.max_plan_rows,
        }
    }

    /// Build an explicit ceiling (test/utility constructor).
    pub fn new(max_cost: f64, max_rows: u64) -> Self {
        ExplainCeiling { max_cost, max_rows }
    }
}

/// A parsed planner estimate from the top node of an `EXPLAIN` plan.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlanEstimate {
    /// The estimated **total** cost (the second number in `cost=START..TOTAL`).
    pub total_cost: f64,
    /// The estimated row count (`rows=N`).
    pub rows: u64,
}

/// The EXPLAIN gate's verdict for one read.
#[derive(Debug, Clone, PartialEq)]
pub enum EstimateDecision {
    /// The plan is within the ceiling — execute the read.
    Within(PlanEstimate),
    /// The estimate breaches the ceiling — block before execution.
    Exceeded {
        /// Which dimension tripped.
        dim: EstimateDim,
        /// The parsed estimate that breached.
        estimate: PlanEstimate,
    },
    /// EXPLAIN failed or its output could not be parsed — fail closed (block).
    /// Carries a short reason for the audit/error message.
    FailClosed(String),
}

/// Which EXPLAIN dimension breached the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateDim {
    /// The estimated total plan cost exceeded `max_cost`.
    Cost,
    /// The estimated row count exceeded `max_rows`.
    Rows,
}

impl EstimateDim {
    /// A short machine-readable code for audit/error reasons.
    pub fn code(self) -> &'static str {
        match self {
            EstimateDim::Cost => "explain_cost_exceeded",
            EstimateDim::Rows => "explain_rows_exceeded",
        }
    }
}

/// The audit/error code used when the EXPLAIN gate fails closed.
pub const EXPLAIN_FAIL_CLOSED_CODE: &str = "explain_failed";

/// The stateless EXPLAIN-cost gate. Holds the per-role ceiling.
#[derive(Debug, Clone, Copy)]
pub struct ExplainGate {
    ceiling: ExplainCeiling,
}

impl ExplainGate {
    /// Construct the gate for a role's ceiling.
    pub fn new(ceiling: ExplainCeiling) -> Self {
        ExplainGate { ceiling }
    }

    /// The configured ceiling.
    pub fn ceiling(&self) -> ExplainCeiling {
        self.ceiling
    }

    /// Decide on a *parsed* estimate (the pure decision, no I/O).
    ///
    /// Cost is checked first, then rows; the first breach wins. Both ceilings
    /// are **inclusive**: an estimate exactly at the ceiling is within.
    pub fn decide(&self, estimate: PlanEstimate) -> EstimateDecision {
        if estimate.total_cost > self.ceiling.max_cost {
            return EstimateDecision::Exceeded {
                dim: EstimateDim::Cost,
                estimate,
            };
        }
        if estimate.rows > self.ceiling.max_rows {
            return EstimateDecision::Exceeded {
                dim: EstimateDim::Rows,
                estimate,
            };
        }
        EstimateDecision::Within(estimate)
    }

    /// Decide on the **raw text of the top plan line** returned by `EXPLAIN`
    /// (the first `DataRow`'s single text column). Parses the estimate and runs
    /// [`decide`](Self::decide); a parse failure fails **closed**.
    pub fn decide_plan_line(&self, plan_line: &str) -> EstimateDecision {
        match parse_plan_estimate(plan_line) {
            Some(estimate) => self.decide(estimate),
            None => EstimateDecision::FailClosed(format!(
                "EXPLAIN output could not be parsed into a cost/row estimate \
                 (fail-closed): {:?}",
                truncate(plan_line, 200)
            )),
        }
    }
}

/// Wrap an `EXPLAIN <sql>` so the backend plans (does not run) the statement.
///
/// We deliberately use the **default text format** (no `ANALYZE`, no `FORMAT`):
/// it is one `DataRow` per plan line whose top line carries
/// `(cost=START..TOTAL rows=N width=W)`, which [`parse_plan_estimate`] reads.
/// `ANALYZE` is *never* used — that would execute the statement, defeating the
/// whole point of a pre-flight gate.
pub fn explain_wrap(sql: &str) -> String {
    format!("EXPLAIN {sql}")
}

/// Parse the planner's estimate off a plan line of text-format `EXPLAIN` output.
///
/// The top node looks like:
/// `Seq Scan on t  (cost=0.00..22.70 rows=1270 width=36)`. We pull the **total**
/// cost (the number after `..` inside `cost=START..TOTAL`) and the `rows=N`
/// estimate. Returns `None` if either field is missing/unparseable — the caller
/// treats `None` as fail-closed.
pub fn parse_plan_estimate(line: &str) -> Option<PlanEstimate> {
    let total_cost = parse_total_cost(line)?;
    let rows = parse_rows(line)?;
    Some(PlanEstimate { total_cost, rows })
}

/// Extract the TOTAL cost from a `cost=START..TOTAL` token.
fn parse_total_cost(line: &str) -> Option<f64> {
    let after = line.find("cost=").map(|i| &line[i + "cost=".len()..])?;
    // The token is `START..TOTAL`, terminated by whitespace or ')'.
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ')')
        .collect();
    let total = token.split("..").nth(1)?;
    total.parse::<f64>().ok()
}

/// Extract the row estimate from a `rows=N` token.
fn parse_rows(line: &str) -> Option<u64> {
    let after = line.find("rows=").map(|i| &line[i + "rows=".len()..])?;
    let token: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if token.is_empty() {
        return None;
    }
    token.parse::<u64>().ok()
}

/// Truncate a string for inclusion in an error message (keep messages bounded).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_policy::WindowBudget;

    fn role_budget(max_plan_cost: f64, max_plan_rows: u64) -> RoleBudget {
        RoleBudget {
            max_bytes: 1_000_000,
            max_rows: 10_000,
            max_plan_cost,
            max_plan_rows,
            per_window: WindowBudget {
                window_secs: 60,
                max_bytes: 100_000_000,
                max_rows: 1_000_000,
            },
        }
    }

    #[test]
    fn parses_total_cost_and_rows_off_a_real_plan_line() {
        // The exact shape PG18 text EXPLAIN emits for the top node.
        let line = "Seq Scan on rca_read  (cost=0.00..22.70 rows=1270 width=36)";
        let est = parse_plan_estimate(line).expect("must parse");
        assert_eq!(est.total_cost, 22.70);
        assert_eq!(est.rows, 1270);
    }

    #[test]
    fn parses_indented_and_complex_plan_lines() {
        // Leading whitespace + a higher cost/row plan (the heavy case).
        let line = "  ->  Gather  (cost=1000.00..123456.78 rows=9999999 width=200) (actual ...)";
        let est = parse_plan_estimate(line).unwrap();
        assert_eq!(est.total_cost, 123456.78);
        assert_eq!(est.rows, 9_999_999);
    }

    #[test]
    fn unparseable_plan_line_returns_none() {
        assert!(parse_plan_estimate("not a plan line at all").is_none());
        // A cost token with no `..TOTAL` is unparseable.
        assert!(parse_plan_estimate("X (cost=0.00 rows=5)").is_none());
        // A missing rows token is unparseable.
        assert!(parse_plan_estimate("X (cost=0.00..10.0 width=4)").is_none());
    }

    #[test]
    fn cheap_plan_within_ceiling_is_allowed() {
        let gate = ExplainGate::new(ExplainCeiling::for_role(&role_budget(1_000.0, 10_000)));
        let line = "Seq Scan on rca_read  (cost=0.00..22.70 rows=3 width=36)";
        match gate.decide_plan_line(line) {
            EstimateDecision::Within(est) => {
                assert_eq!(est.total_cost, 22.70);
                assert_eq!(est.rows, 3);
            }
            other => panic!("expected Within, got {other:?}"),
        }
    }

    #[test]
    fn plan_over_cost_ceiling_is_blocked_before_execution() {
        // Ceiling: cost 100, rows 1_000_000. The plan's cost (123456.78) breaches.
        let gate = ExplainGate::new(ExplainCeiling::new(100.0, 1_000_000));
        let line = "Seq Scan  (cost=0.00..123456.78 rows=5 width=8)";
        match gate.decide_plan_line(line) {
            EstimateDecision::Exceeded { dim, estimate } => {
                assert_eq!(dim, EstimateDim::Cost);
                assert_eq!(estimate.total_cost, 123456.78);
            }
            other => panic!("expected Exceeded(Cost), got {other:?}"),
        }
    }

    #[test]
    fn plan_over_row_ceiling_is_blocked_before_execution() {
        // Cost within (10 ≤ 1e9) but rows (9_999_999) over the 100-row ceiling.
        let gate = ExplainGate::new(ExplainCeiling::new(1e9, 100));
        let line = "Seq Scan  (cost=0.00..10.0 rows=9999999 width=8)";
        match gate.decide_plan_line(line) {
            EstimateDecision::Exceeded { dim, estimate } => {
                assert_eq!(dim, EstimateDim::Rows);
                assert_eq!(estimate.rows, 9_999_999);
            }
            other => panic!("expected Exceeded(Rows), got {other:?}"),
        }
    }

    #[test]
    fn estimate_exactly_at_ceiling_is_within() {
        // Both ceilings are inclusive.
        let gate = ExplainGate::new(ExplainCeiling::new(22.70, 1270));
        let line = "Seq Scan  (cost=0.00..22.70 rows=1270 width=8)";
        assert!(matches!(
            gate.decide_plan_line(line),
            EstimateDecision::Within(_)
        ));
    }

    #[test]
    fn unparseable_explain_output_fails_closed() {
        // Fail-closed: if we can't parse an estimate, BLOCK (don't execute).
        let gate = ExplainGate::new(ExplainCeiling::new(1e9, 1_000_000));
        match gate.decide_plan_line("ERROR: relation does not exist") {
            EstimateDecision::FailClosed(reason) => {
                assert!(reason.contains("fail-closed"), "{reason}");
            }
            other => panic!("expected FailClosed, got {other:?}"),
        }
    }

    #[test]
    fn explain_wrap_does_not_use_analyze() {
        // ANALYZE would EXECUTE the statement — must never appear.
        let wrapped = explain_wrap("SELECT * FROM t");
        assert_eq!(wrapped, "EXPLAIN SELECT * FROM t");
        assert!(!wrapped.to_uppercase().contains("ANALYZE"));
    }

    #[test]
    fn ceiling_is_derived_from_role_budget() {
        let c = ExplainCeiling::for_role(&role_budget(4_242.0, 777));
        assert_eq!(c.max_cost, 4_242.0);
        assert_eq!(c.max_rows, 777);
    }
}
