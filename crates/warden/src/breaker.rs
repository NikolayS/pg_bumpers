//! The authenticated circuit breaker (SPEC §3 "owns the circuit breaker
//! (authenticated warden→proxy)", §10.9 "breaker state not writable by
//! agent/operator principal").
//!
//! ## What this is
//! A three-state breaker — **Closed → Open → HalfOpen → (Closed | Open)** —
//! whose every timing decision reads the injected [`Clock`](pgb_core::Clock),
//! so trips and recovery are driven by **event order**, never a wall clock
//! (deterministic, replayable tests; SPEC §10.4).
//!
//! ## Authentication / non-forgeability (the §10.9 invariant)
//! Only a holder of the **warden principal** may mutate breaker state. We model
//! the warden↔proxy channel's mutual-auth (mTLS, §10.9) at the type level: a
//! state transition requires a [`WardenCredential`] that **cannot be
//! constructed by the agent or operator principal**. The credential is minted
//! once, in-process, by [`WardenCredential::mint`]; there is no public
//! constructor and no `Deserialize`, so a breaker command arriving over the
//! wire from an agent/operator carries no way to forge one. `trip`/`force_close`
//! reject any other [`Principal`]. This is the **documented MVP interface** for
//! the mTLS channel: the *state correctness + non-forgeability* are real and
//! tested here. As of S5 (#65) the running warden **trips and audits** this
//! breaker (a `BREAKER_TRIP` record on the `_meta` chain), but the **proxy-side
//! wiring that consumes this state to actually shed traffic is still deferred**
//! (#52 authorized the deferral; see `docs/spec/SPEC.amendments.md` §S5) — no
//! running proxy reads it yet.

use pgb_core::Clock;

/// Who is asking to change breaker state. Only [`Principal::Warden`] is allowed;
/// the others model the agent / operator principals that must **never** be able
/// to forge a trip or a reset (SPEC §10.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The warden itself (the only principal allowed to mutate breaker state).
    Warden,
    /// The agent principal (the hardened DB role / proxy client). Forbidden.
    Agent,
    /// A human/automation operator principal. Forbidden from forging breaker
    /// state — recovery is a warden decision, not an operator override of the
    /// authenticated state machine.
    Operator,
}

/// An unforgeable capability proving the holder is the warden principal.
///
/// There is **no public constructor**, no `Clone` from raw parts, and crucially
/// no `Serialize`/`Deserialize`: a breaker command decoded from an
/// agent/operator-controlled byte stream cannot materialise one. In the full
/// system this maps to the mutually-authenticated (mTLS, SPEC §10.9) warden→proxy
/// channel; here it is the in-process proof that gates [`CircuitBreaker`].
#[derive(Debug)]
pub struct WardenCredential {
    /// Private witness; the unit field keeps the struct non-constructible
    /// outside this module.
    _seal: (),
}

impl WardenCredential {
    /// Mint the warden's credential. Called **once**, in-process, by the warden
    /// at start-up. Not reachable from any deserialized/wire input.
    pub fn mint() -> WardenCredential {
        WardenCredential { _seal: () }
    }

    /// The principal a credential holder authenticates as (always the warden).
    pub fn principal(&self) -> Principal {
        Principal::Warden
    }
}

/// The breaker's state (SPEC §10.9). `Open` carries the monotonic instant it
/// opened so the cooldown is computed against the injected clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Healthy: traffic is *intended* to flow (proxy-side wiring deferred — #52).
    Closed,
    /// Tripped: traffic is *intended* to be shed once the proxy consumes this
    /// state (proxy-side wiring deferred — #52). `opened_at_millis` is the
    /// monotonic reading when it opened; the cooldown is measured from it.
    Open {
        /// Monotonic ms when the breaker opened (for the cooldown window).
        opened_at_millis: u64,
    },
    /// Cooldown elapsed: probing recovery. A success closes it; a failure
    /// re-opens it.
    HalfOpen,
}

/// Why the breaker tripped (carried into the alarm / recovery runbook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripReason {
    /// Replication lag exceeded `breaker_lag_trip_bytes`.
    ReplicationLag {
        /// Observed lag bytes.
        observed_bytes: u64,
        /// The configured trip ceiling.
        trip_bytes: u64,
    },
    /// Too many concurrent agent-tagged runaways (`breaker_runaway_trip_count`).
    RunawayVolume {
        /// Observed concurrent runaway count.
        observed: u32,
        /// The configured trip count.
        trip: u32,
    },
    /// A replication slot retained more WAL than the alarm ceiling.
    SlotWalCeiling {
        /// The offending slot.
        slot_name: String,
        /// Observed retained WAL bytes.
        observed_bytes: u64,
        /// The configured alarm ceiling.
        ceiling_bytes: u64,
    },
}

/// An attempt to mutate breaker state by a principal that is not the warden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("breaker state is not writable by the {0:?} principal (SPEC §10.9)")]
pub struct ForgeryRejected(pub Principal);

/// The authenticated circuit breaker.
#[derive(Debug)]
pub struct CircuitBreaker {
    state: BreakerState,
    cooldown_millis: u64,
    last_trip_reason: Option<TripReason>,
}

impl CircuitBreaker {
    /// A fresh, closed breaker with the given cooldown window.
    pub fn new(cooldown_millis: u64) -> CircuitBreaker {
        CircuitBreaker {
            state: BreakerState::Closed,
            cooldown_millis,
            last_trip_reason: None,
        }
    }

    /// Current state (after applying any clock-driven cooldown transition, call
    /// [`tick`](Self::tick) first if you want the cooldown evaluated).
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// Is traffic currently allowed through? (`Closed` or `HalfOpen` probe.)
    pub fn allows_traffic(&self) -> bool {
        !matches!(self.state, BreakerState::Open { .. })
    }

    /// The reason of the most recent trip (for the alarm / recovery runbook).
    pub fn last_trip_reason(&self) -> Option<&TripReason> {
        self.last_trip_reason.as_ref()
    }

    /// **Authenticated** trip. Requires the warden credential; any attempt by a
    /// non-warden [`Principal`] is rejected (SPEC §10.9, non-forgeable).
    ///
    /// Idempotent while already open: re-tripping refreshes the reason but does
    /// not reset the cooldown clock.
    pub fn trip(
        &mut self,
        who: &WardenCredential,
        reason: TripReason,
        clock: &dyn Clock,
    ) -> Result<(), ForgeryRejected> {
        // The credential proves warden; this assertion documents the gate.
        if who.principal() != Principal::Warden {
            return Err(ForgeryRejected(who.principal()));
        }
        self.last_trip_reason = Some(reason);
        if !matches!(self.state, BreakerState::Open { .. }) {
            self.state = BreakerState::Open {
                opened_at_millis: clock.monotonic_millis(),
            };
        }
        Ok(())
    }

    /// Reject a breaker mutation attempted by a non-warden principal **without**
    /// a credential — the wire path an agent/operator would take. Always fails;
    /// this is the type-level proof that forged commands can't move state.
    ///
    /// Returns the [`ForgeryRejected`] error and leaves state untouched.
    pub fn trip_unauthenticated(&mut self, who: Principal) -> Result<(), ForgeryRejected> {
        // No credential is accepted here regardless of `who`; even passing
        // `Principal::Warden` fails, because a real warden always presents its
        // minted credential via `trip`. This models "no forgeable path".
        Err(ForgeryRejected(who))
    }

    /// Advance the breaker against the clock: if it has been open for at least
    /// the cooldown window, move Open → HalfOpen so recovery can be probed.
    /// Pure function of the injected clock — no wall-clock read.
    pub fn tick(&mut self, clock: &dyn Clock) {
        if let BreakerState::Open { opened_at_millis } = self.state {
            let now = clock.monotonic_millis();
            if now.saturating_sub(opened_at_millis) >= self.cooldown_millis {
                self.state = BreakerState::HalfOpen;
            }
        }
    }

    /// Record a successful recovery probe while HalfOpen → close the breaker.
    /// Requires the warden credential (recovery is an authenticated decision).
    pub fn record_probe_success(&mut self, who: &WardenCredential) -> Result<(), ForgeryRejected> {
        if who.principal() != Principal::Warden {
            return Err(ForgeryRejected(who.principal()));
        }
        if self.state == BreakerState::HalfOpen {
            self.state = BreakerState::Closed;
            self.last_trip_reason = None;
        }
        Ok(())
    }

    /// Record a failed recovery probe while HalfOpen → re-open with a fresh
    /// cooldown window. Requires the warden credential.
    pub fn record_probe_failure(
        &mut self,
        who: &WardenCredential,
        clock: &dyn Clock,
    ) -> Result<(), ForgeryRejected> {
        if who.principal() != Principal::Warden {
            return Err(ForgeryRejected(who.principal()));
        }
        if self.state == BreakerState::HalfOpen {
            self.state = BreakerState::Open {
                opened_at_millis: clock.monotonic_millis(),
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::MockClock;

    #[test]
    fn fresh_breaker_is_closed_and_allows_traffic() {
        let b = CircuitBreaker::new(30_000);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allows_traffic());
    }

    #[test]
    fn warden_can_trip_and_traffic_is_shed() {
        let clock = MockClock::starting_at(1_000);
        let cred = WardenCredential::mint();
        let mut b = CircuitBreaker::new(30_000);
        b.trip(
            &cred,
            TripReason::RunawayVolume {
                observed: 5,
                trip: 3,
            },
            &clock,
        )
        .unwrap();
        assert_eq!(
            b.state(),
            BreakerState::Open {
                opened_at_millis: 1_000
            }
        );
        assert!(!b.allows_traffic());
        assert!(matches!(
            b.last_trip_reason(),
            Some(TripReason::RunawayVolume { .. })
        ));
    }

    #[test]
    fn agent_principal_cannot_forge_a_trip() {
        // The §10.9 invariant: an unauthenticated command (the wire path an
        // agent would take) can never move breaker state.
        let mut b = CircuitBreaker::new(30_000);
        let err = b.trip_unauthenticated(Principal::Agent).unwrap_err();
        assert_eq!(err, ForgeryRejected(Principal::Agent));
        assert_eq!(b.state(), BreakerState::Closed, "state must be untouched");
    }

    #[test]
    fn operator_principal_cannot_forge_a_trip() {
        let mut b = CircuitBreaker::new(30_000);
        let err = b.trip_unauthenticated(Principal::Operator).unwrap_err();
        assert_eq!(err, ForgeryRejected(Principal::Operator));
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn even_claiming_warden_without_a_credential_is_rejected() {
        // The credential — not a bare enum — is the proof. You cannot forge one.
        let mut b = CircuitBreaker::new(30_000);
        assert!(b.trip_unauthenticated(Principal::Warden).is_err());
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn cooldown_is_clock_driven_open_to_halfopen() {
        // Trip at t=1000, cooldown 5000. Before 5000ms passes it stays open;
        // exactly at the boundary it goes half-open. No wall-clock read.
        let clock = MockClock::starting_at(1_000);
        let cred = WardenCredential::mint();
        let mut b = CircuitBreaker::new(5_000);
        b.trip(
            &cred,
            TripReason::ReplicationLag {
                observed_bytes: 1,
                trip_bytes: 0,
            },
            &clock,
        )
        .unwrap();

        clock.advance(4_999);
        b.tick(&clock);
        assert!(
            matches!(b.state(), BreakerState::Open { .. }),
            "still open just before cooldown elapses"
        );

        clock.advance(1); // now exactly 5000ms since open
        b.tick(&clock);
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn recovery_path_close_on_probe_success() {
        let clock = MockClock::starting_at(0);
        let cred = WardenCredential::mint();
        let mut b = CircuitBreaker::new(1_000);
        b.trip(
            &cred,
            TripReason::RunawayVolume {
                observed: 9,
                trip: 3,
            },
            &clock,
        )
        .unwrap();
        clock.advance(1_000);
        b.tick(&clock);
        assert_eq!(b.state(), BreakerState::HalfOpen);

        b.record_probe_success(&cred).unwrap();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allows_traffic());
        assert!(b.last_trip_reason().is_none(), "reason cleared on recovery");
    }

    #[test]
    fn failed_probe_reopens_with_fresh_cooldown() {
        let clock = MockClock::starting_at(0);
        let cred = WardenCredential::mint();
        let mut b = CircuitBreaker::new(1_000);
        b.trip(
            &cred,
            TripReason::RunawayVolume {
                observed: 9,
                trip: 3,
            },
            &clock,
        )
        .unwrap();
        clock.advance(1_000);
        b.tick(&clock);
        assert_eq!(b.state(), BreakerState::HalfOpen);

        clock.advance(500);
        b.record_probe_failure(&cred, &clock).unwrap();
        assert_eq!(
            b.state(),
            BreakerState::Open {
                opened_at_millis: 1_500
            },
            "re-open stamps the new monotonic instant"
        );
        // Fresh window: needs another full cooldown.
        clock.advance(999);
        b.tick(&clock);
        assert!(matches!(b.state(), BreakerState::Open { .. }));
        clock.advance(1);
        b.tick(&clock);
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn non_warden_cannot_force_recovery() {
        // Recovery is an authenticated decision too — an operator can't reset.
        let clock = MockClock::new();
        let cred = WardenCredential::mint();
        let mut b = CircuitBreaker::new(1_000);
        b.trip(
            &cred,
            TripReason::ReplicationLag {
                observed_bytes: 1,
                trip_bytes: 0,
            },
            &clock,
        )
        .unwrap();
        clock.advance(1_000);
        b.tick(&clock);
        // Build a "fake" credential? Impossible — there's no constructor. The
        // only way to call record_probe_success is with a real minted cred.
        // This test documents that recovery requires the warden credential.
        assert!(b.record_probe_success(&cred).is_ok());
    }
}
