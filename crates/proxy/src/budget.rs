//! The per-statement **byte/row mid-stream cutoff** (SPEC §3 layer 2, §4).
//!
//! A single read must not be allowed to drain the database: the proxy counts the
//! bytes and rows of every `DataRow` streamed back from the backend and **cuts
//! the stream off** the moment either the single-shot byte cap or the row cap
//! from the role's `policy.yaml` budget would be exceeded. This is one of the
//! three un-foolable backstops (with the WALL role and `statement_timeout`), so
//! it is fail-closed: at or past the bound, the row that would breach is *not*
//! forwarded and the statement is terminated with an error.
//!
//! The cumulative per-window budget (anti slow-drip) is S4; this is the
//! single-shot cutoff (`RoleBudget::max_bytes` / `max_rows`).

use pgb_policy::RoleBudget;

/// What charging a `DataRow` against the budget yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetOutcome {
    /// The row fits; forward it. Carries the running totals after charging.
    Within {
        /// Total bytes streamed so far (including this row).
        bytes: u64,
        /// Total rows streamed so far (including this row).
        rows: u64,
    },
    /// Forwarding this row would breach the byte or row cap — cut off. The row
    /// is **not** counted/forwarded; the carried totals are the pre-row values.
    Exceeded {
        /// Which cap was hit.
        cap: Cap,
        /// Bytes streamed *before* this (refused) row.
        bytes: u64,
        /// Rows streamed *before* this (refused) row.
        rows: u64,
    },
}

/// Which budget dimension tripped the cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// The single-shot byte cap (`RoleBudget::max_bytes`).
    Bytes,
    /// The single-shot row cap (`RoleBudget::max_rows`).
    Rows,
}

impl Cap {
    /// A short machine-readable code for audit/error reasons.
    pub fn code(self) -> &'static str {
        match self {
            Cap::Bytes => "byte_budget_exceeded",
            Cap::Rows => "row_budget_exceeded",
        }
    }
}

/// A live single-shot budget meter for one executing statement.
///
/// `max_bytes`/`max_rows` are inclusive caps: streaming exactly the cap is fine;
/// the row that would push *past* it is refused (the cutoff). Reset per
/// statement via [`Budget::for_role`].
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    max_bytes: u64,
    max_rows: u64,
    used_bytes: u64,
    used_rows: u64,
}

impl Budget {
    /// A fresh meter for a role's single-shot caps.
    pub fn for_role(budget: &RoleBudget) -> Self {
        Budget {
            max_bytes: budget.max_bytes,
            max_rows: budget.max_rows,
            used_bytes: 0,
            used_rows: 0,
        }
    }

    /// A fresh meter from explicit caps (test/utility constructor).
    pub fn new(max_bytes: u64, max_rows: u64) -> Self {
        Budget {
            max_bytes,
            max_rows,
            used_bytes: 0,
            used_rows: 0,
        }
    }

    /// Bytes charged so far.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Rows charged so far.
    pub fn used_rows(&self) -> u64 {
        self.used_rows
    }

    /// Try to charge one `DataRow` of `row_bytes` wire bytes.
    ///
    /// Returns [`BudgetOutcome::Within`] (and commits the charge) if both caps
    /// still hold afterwards, or [`BudgetOutcome::Exceeded`] (leaving the meter
    /// unchanged) if forwarding the row would breach either cap — the
    /// fail-closed mid-stream cutoff. The row cap is checked first so an empty
    /// row still counts against the row budget.
    pub fn charge_row(&mut self, row_bytes: u64) -> BudgetOutcome {
        // Row cap: one more row must not exceed max_rows.
        let next_rows = self.used_rows.saturating_add(1);
        if next_rows > self.max_rows {
            return BudgetOutcome::Exceeded {
                cap: Cap::Rows,
                bytes: self.used_bytes,
                rows: self.used_rows,
            };
        }
        // Byte cap: the running byte total must not exceed max_bytes.
        let next_bytes = self.used_bytes.saturating_add(row_bytes);
        if next_bytes > self.max_bytes {
            return BudgetOutcome::Exceeded {
                cap: Cap::Bytes,
                bytes: self.used_bytes,
                rows: self.used_rows,
            };
        }
        self.used_rows = next_rows;
        self.used_bytes = next_bytes;
        BudgetOutcome::Within {
            bytes: self.used_bytes,
            rows: self.used_rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_budget(max_bytes: u64, max_rows: u64) -> RoleBudget {
        use pgb_policy::WindowBudget;
        RoleBudget {
            max_bytes,
            max_rows,
            max_plan_cost: RoleBudget::DEFAULT_MAX_PLAN_COST,
            max_plan_rows: RoleBudget::DEFAULT_MAX_PLAN_ROWS,
            per_window: WindowBudget {
                window_secs: 60,
                max_bytes: max_bytes * 100,
                max_rows: max_rows * 100,
            },
        }
    }

    #[test]
    fn rows_within_budget_are_forwarded() {
        let mut b = Budget::for_role(&role_budget(1_000, 10));
        for i in 1..=10 {
            assert_eq!(
                b.charge_row(10),
                BudgetOutcome::Within {
                    bytes: 10 * i,
                    rows: i
                }
            );
        }
        assert_eq!(b.used_rows(), 10);
        assert_eq!(b.used_bytes(), 100);
    }

    #[test]
    fn cutoff_on_row_cap_refuses_the_breaching_row() {
        let mut b = Budget::new(1_000_000, 3);
        assert!(matches!(b.charge_row(1), BudgetOutcome::Within { .. }));
        assert!(matches!(b.charge_row(1), BudgetOutcome::Within { .. }));
        assert!(matches!(b.charge_row(1), BudgetOutcome::Within { .. }));
        // The 4th row would breach the 3-row cap → refused; meter unchanged.
        assert_eq!(
            b.charge_row(1),
            BudgetOutcome::Exceeded {
                cap: Cap::Rows,
                bytes: 3,
                rows: 3
            }
        );
        assert_eq!(b.used_rows(), 3, "refused row must not be counted");
    }

    #[test]
    fn cutoff_on_byte_cap_refuses_the_breaching_row() {
        let mut b = Budget::new(100, 1_000_000);
        assert!(matches!(b.charge_row(60), BudgetOutcome::Within { .. }));
        assert!(matches!(b.charge_row(40), BudgetOutcome::Within { .. })); // exactly at cap
        // One more byte over the cap → refused.
        assert_eq!(
            b.charge_row(1),
            BudgetOutcome::Exceeded {
                cap: Cap::Bytes,
                bytes: 100,
                rows: 2
            }
        );
        assert_eq!(b.used_bytes(), 100, "byte cap is inclusive");
    }

    #[test]
    fn exactly_at_byte_cap_is_within() {
        let mut b = Budget::new(100, 1_000_000);
        assert_eq!(
            b.charge_row(100),
            BudgetOutcome::Within {
                bytes: 100,
                rows: 1
            }
        );
    }
}
