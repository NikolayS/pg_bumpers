//! pg_bumpers proxy binary (stub).
//!
//! The proxy is the inline enforcement point and the only endpoint the agent
//! role may reach (SPEC §3 layer 2): read-only, replica routing, EXPLAIN-cost
//! gate (advisory), row/byte mid-stream cutoff, cumulative per-role budgets,
//! timeout injection, hash-chained audit, extended-protocol-only. This S0 stub
//! only prints its identity and carries the per-role budget seam + a test; the
//! real FE/BE loop lands in S1.

/// A cumulative per-role volume budget (bytes) over a window (SPEC §3 layer 2).
///
/// Fail-closed: once the budget is exhausted the proxy cuts the stream off.
#[derive(Debug, Clone, Copy)]
struct ByteBudget {
    limit: u64,
    used: u64,
}

impl ByteBudget {
    fn new(limit: u64) -> Self {
        ByteBudget { limit, used: 0 }
    }

    /// Try to charge `n` bytes. Returns `false` (and refuses) if it would
    /// exceed the budget — the mid-stream cutoff.
    fn try_charge(&mut self, n: u64) -> bool {
        match self.used.checked_add(n) {
            Some(total) if total <= self.limit => {
                self.used = total;
                true
            }
            _ => false,
        }
    }
}

fn main() {
    // Exercise the local seam plus the workspace deps the proxy is built on,
    // so the stub is live, wired code rather than dead scaffolding.
    let mut budget = ByteBudget::new(1 << 20);
    let charged = budget.try_charge(0);
    let trust = pgb_core::TrustLevel::default_floor();
    let verdict = pgb_policy::StubRiskEngine.evaluate();
    let proto_ok = pgb_pgwire::ProtocolMode::Extended.is_allowed_for_agent();
    // Exercise the audit seam: an empty hash chain's head is the defined
    // genesis (the real FE/BE loop appends recorded statements in S1).
    let audit_head = pgb_audit::AuditChain::new().head_hash();
    println!(
        "pgb-proxy: stub — inline read enforcement lands in S1 (see SPEC.md §3). \
         seams ready (budget_limit={}, charged={charged}, trust={trust:?}, \
         verdict={verdict:?}, extended_only={proto_ok}, audit_head={audit_head}).",
        budget.limit
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_cuts_off_on_overrun() {
        let mut budget = ByteBudget::new(100);
        assert!(budget.try_charge(60));
        assert!(budget.try_charge(40)); // exactly at the limit
                                        // Any further byte exceeds the budget -> cutoff (fail-closed).
        assert!(!budget.try_charge(1));
    }
}
