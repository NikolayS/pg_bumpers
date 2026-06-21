//! pg_bumpers warden binary (stub).
//!
//! The warden runs out-of-band (SPEC §3 layer 2, §4): it polls
//! `pg_stat_activity`/`pg_stat_statements`/lag plus replication-slot creation,
//! and **only** cancels/terminates proxy-tagged / agent-role sessions to avoid
//! false-positive outages on shared roles. It owns the authenticated circuit
//! breaker. This S0 stub carries the targeting predicate + a test; the live
//! polling loop (interval mockable) lands in S4.

/// Decide whether the warden may terminate a backend.
///
/// Safety rule (SPEC §3): kill **only** agent-tagged sessions. A non-agent
/// (e.g. shared application) session is never terminated, even if busy.
fn may_terminate(is_agent_tagged: bool) -> bool {
    is_agent_tagged
}

fn main() {
    // Exercise the targeting predicate plus the core dep so the stub is wired.
    let would_kill_shared = may_terminate(false);
    let floor = pgb_core::TrustLevel::default_floor();
    println!(
        "pgb-warden: stub — out-of-band watchdog lands in S4 (see SPEC.md §3). \
         targeting seam ready (terminates shared sessions={would_kill_shared}, floor={floor:?})."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_agent_tagged_sessions_are_terminable() {
        assert!(may_terminate(true));
        // Never terminate non-agent sessions (avoid false-positive outages).
        assert!(!may_terminate(false));
    }
}
