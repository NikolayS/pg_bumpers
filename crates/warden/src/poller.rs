//! The warden poll loop + the **pure** assessment that decides which backends
//! to kill, which slots to alarm, and whether the breaker trips (SPEC §3, §4).
//!
//! Everything that touches a live database is behind two seams so the gating
//! logic is unit-testable with no DB and no wall-clock:
//!
//! - [`ActivitySource`] — yields an [`Observation`] per tick (production reads
//!   `pg_stat_activity` / `pg_replication_slots`; tests use a scripted source).
//! - [`Killer`] — issues `pg_cancel_backend` / `pg_terminate_backend`
//!   (production runs the SQL; tests record the pids and assert *only*
//!   agent-tagged ones are passed).
//!
//! The poll **cadence** is read from the injected [`Clock`](pgb_core::Clock):
//! [`WardenLoop::run_ticks`] advances a [`MockClock`](pgb_core::MockClock) by
//! exactly `poll_interval_millis` each tick, so the cadence is asserted by
//! event order with no real sleeping (SPEC §4 "interval mockable for tests").

use pgb_core::Clock;

use crate::breaker::{CircuitBreaker, TripReason, WardenCredential};
use crate::model::{Backend, Observation, ReplicationSlot};
use crate::thresholds::WardenThresholds;

/// A source of warden observations (the `pg_stat_activity` /
/// `pg_replication_slots` seam). Production queries PG18; tests script ticks.
pub trait ActivitySource {
    /// Observe the cluster once (one poll tick).
    fn observe(&mut self) -> Observation;
}

/// Issues the actual cancel/terminate against the cluster (the
/// `pg_cancel_backend` / `pg_terminate_backend` seam). Production runs SQL;
/// tests record the pids to assert the targeting invariant.
pub trait Killer {
    /// Terminate (`pg_terminate_backend`) the given agent-tagged backend pid.
    /// The caller has **already** proven the pid is agent-tagged.
    fn terminate(&mut self, pid: i32);
}

/// What one warden tick decided — the auditable outcome (SPEC §4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickOutcome {
    /// Agent-tagged backends terminated this tick (the runaways).
    pub terminated_pids: Vec<i32>,
    /// Backends a naive "long query" rule would have killed but the warden
    /// **spared** because they are not agent-tagged (no false-positive outage).
    /// This is the explicit evidence that shared roles are left alone.
    pub spared_non_agent_pids: Vec<i32>,
    /// Replication slots over the WAL alarm ceiling (the slot-exfil/WAL-DoS
    /// alarm), as `(slot_name, retained_wal_bytes)`.
    pub slot_alarms: Vec<(String, u64)>,
    /// Whether the breaker tripped (or remained tripped) this tick.
    pub breaker_open: bool,
}

/// A pure assessment of one [`Observation`] against the thresholds: which
/// agent-tagged backends are runaways, which non-agent ones were spared, and
/// the slot/lag/volume breaker conditions. No DB, no clock, no side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Agent-tagged backends to terminate (runaway, over the runtime ceiling).
    pub to_terminate: Vec<i32>,
    /// Non-agent backends that exceeded the runtime ceiling but are **spared**
    /// (never killed — avoid false-positive outages on shared roles).
    pub spared_non_agent: Vec<i32>,
    /// Slots over the WAL alarm ceiling: `(slot_name, retained_wal_bytes)`.
    pub slot_alarms: Vec<(String, u64)>,
    /// The breaker trip reason, if any condition is met this tick.
    pub trip: Option<TripReason>,
}

/// Assess one observation against the thresholds (the pure core, SPEC §3/§4).
pub fn assess(obs: &Observation, t: &WardenThresholds) -> Assessment {
    let mut to_terminate = Vec::new();
    let mut spared_non_agent = Vec::new();
    let mut runaway_agent_count: u32 = 0;

    for b in &obs.backends {
        let over_runtime = is_runaway(b, t.max_query_runtime_millis);
        if !over_runtime {
            continue;
        }
        if b.is_agent_tagged() {
            // Agent-tagged + over the runtime ceiling → terminate.
            to_terminate.push(b.pid);
            runaway_agent_count += 1;
        } else {
            // Over the ceiling but a shared role → SPARE it (SPEC §3: never
            // kill shared-role backends; avoid false-positive outages).
            spared_non_agent.push(b.pid);
        }
    }

    // Slot/WAL alarm: any slot retaining more WAL than the ceiling.
    let mut slot_alarms = Vec::new();
    for s in &obs.slots {
        if is_slot_over_ceiling(s, t.slot_retained_wal_alarm_bytes) {
            slot_alarms.push((s.slot_name.clone(), s.retained_wal_bytes));
        }
    }

    // Breaker trip conditions, in priority order: lag, then slot-WAL ceiling,
    // then runaway volume. The first matched reason trips.
    let trip = if obs.replication_lag_bytes > t.breaker_lag_trip_bytes {
        Some(TripReason::ReplicationLag {
            observed_bytes: obs.replication_lag_bytes,
            trip_bytes: t.breaker_lag_trip_bytes,
        })
    } else if let Some((name, bytes)) = slot_alarms.first() {
        Some(TripReason::SlotWalCeiling {
            slot_name: name.clone(),
            observed_bytes: *bytes,
            ceiling_bytes: t.slot_retained_wal_alarm_bytes,
        })
    } else if runaway_agent_count >= t.breaker_runaway_trip_count {
        Some(TripReason::RunawayVolume {
            observed: runaway_agent_count,
            trip: t.breaker_runaway_trip_count,
        })
    } else {
        None
    };

    Assessment {
        to_terminate,
        spared_non_agent,
        slot_alarms,
        trip,
    }
}

/// Is this backend a runaway: actively running a query longer than the ceiling?
/// Idle backends (no running query) are never runaways regardless of duration.
fn is_runaway(b: &Backend, max_runtime_millis: u64) -> bool {
    b.state == "active" && b.query_runtime_millis > max_runtime_millis
}

/// Is a slot retaining more WAL than the alarm ceiling?
fn is_slot_over_ceiling(s: &ReplicationSlot, ceiling_bytes: u64) -> bool {
    s.retained_wal_bytes > ceiling_bytes
}

/// The warden loop: drives an [`ActivitySource`] on the clock cadence, applies
/// the [`assess`] decision, terminates only agent-tagged runaways via the
/// [`Killer`], and trips the breaker on a tripped condition (SPEC §3/§4).
pub struct WardenLoop<S, K> {
    source: S,
    killer: K,
    thresholds: WardenThresholds,
    breaker: CircuitBreaker,
    credential: WardenCredential,
}

impl<S: ActivitySource, K: Killer> WardenLoop<S, K> {
    /// Build a loop from its seams + thresholds. The breaker cooldown is taken
    /// from the thresholds; the warden mints its own (unforgeable) credential.
    pub fn new(source: S, killer: K, thresholds: WardenThresholds) -> WardenLoop<S, K> {
        let cooldown = thresholds.breaker_cooldown_millis;
        WardenLoop {
            source,
            killer,
            thresholds,
            breaker: CircuitBreaker::new(cooldown),
            credential: WardenCredential::mint(),
        }
    }

    /// Borrow the breaker (for the proxy-facing state read / tests).
    pub fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }

    /// Run **one** poll tick at the current clock instant: observe, assess, kill
    /// the agent-tagged runaways, raise slot alarms, and (authenticated) trip
    /// the breaker if a condition fired. Returns the auditable [`TickOutcome`].
    pub fn tick(&mut self, clock: &dyn Clock) -> TickOutcome {
        // Let any cooldown elapse first (Open → HalfOpen).
        self.breaker.tick(clock);

        let obs = self.source.observe();
        let a = assess(&obs, &self.thresholds);

        for pid in &a.to_terminate {
            self.killer.terminate(*pid);
        }

        if let Some(reason) = a.trip {
            // Authenticated trip — the warden's own credential. Never forgeable
            // by the agent/operator principal (SPEC §10.9).
            self.breaker
                .trip(&self.credential, reason, clock)
                .expect("warden credential always authenticates");
        }

        TickOutcome {
            terminated_pids: a.to_terminate,
            spared_non_agent_pids: a.spared_non_agent,
            slot_alarms: a.slot_alarms,
            breaker_open: !self.breaker.allows_traffic(),
        }
    }

    /// Run `n` ticks on the **injected clock cadence**: advance the clock by
    /// `poll_interval_millis` and run a tick, `n` times. This is how tests drive
    /// the poll interval deterministically — no real sleeping, no wall clock
    /// (SPEC §4 "interval mockable for tests").
    ///
    /// Requires a [`MockClock`](pgb_core::MockClock) handle so the loop can
    /// advance it. The production driver that advances a real
    /// [`SystemClock`](pgb_core::SystemClock) on a wall-clock cadence (a
    /// `run_with_sleep`-style loop) is **not implemented yet** — the warden
    /// binary does not run a live loop in S4 (deferred to S5, #65; see
    /// `docs/spec/SPEC.amendments.md` §S4).
    pub fn run_ticks(&mut self, clock: &pgb_core::MockClock, n: usize) -> Vec<TickOutcome> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.tick(clock));
            clock.advance(self.thresholds.poll_interval_millis);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AGENT_ROLE, PROXY_APP_NAME};
    use pgb_core::MockClock;

    fn agent_runaway(pid: i32, runtime_ms: u64) -> Backend {
        Backend {
            pid,
            usename: AGENT_ROLE.to_string(),
            application_name: PROXY_APP_NAME.to_string(),
            state: "active".to_string(),
            query_runtime_millis: runtime_ms,
            query: "SELECT pg_sleep(9999)".to_string(),
        }
    }

    fn shared_runaway(pid: i32, runtime_ms: u64) -> Backend {
        Backend {
            pid,
            usename: "app_shared".to_string(),
            application_name: "some_app".to_string(),
            state: "active".to_string(),
            query_runtime_millis: runtime_ms,
            query: "SELECT pg_sleep(9999)".to_string(),
        }
    }

    /// A scripted source that yields a fixed list of observations, one per tick.
    struct ScriptedSource {
        ticks: std::collections::VecDeque<Observation>,
    }
    impl ScriptedSource {
        fn new(obs: Vec<Observation>) -> Self {
            ScriptedSource {
                ticks: obs.into_iter().collect(),
            }
        }
    }
    impl ActivitySource for ScriptedSource {
        fn observe(&mut self) -> Observation {
            self.ticks.pop_front().unwrap_or_default()
        }
    }

    /// A killer that just records the pids it was asked to terminate.
    #[derive(Default)]
    struct RecordingKiller {
        killed: Vec<i32>,
    }
    impl Killer for RecordingKiller {
        fn terminate(&mut self, pid: i32) {
            self.killed.push(pid);
        }
    }

    fn thresholds() -> WardenThresholds {
        WardenThresholds {
            poll_interval_millis: 2_000,
            max_query_runtime_millis: 60_000,
            slot_retained_wal_alarm_bytes: 64 * 1024 * 1024,
            breaker_lag_trip_bytes: 128 * 1024 * 1024,
            breaker_runaway_trip_count: 3,
            breaker_cooldown_millis: 10_000,
        }
    }

    #[test]
    fn agent_runaway_terminated_shared_runaway_spared() {
        // The headline acceptance: an agent-tagged long query is killed; a
        // shared-role long query over the same ceiling is LEFT ALONE.
        let obs = Observation {
            backends: vec![
                agent_runaway(101, 120_000),  // 2 min > 60s ceiling → kill
                shared_runaway(202, 120_000), // also 2 min, but shared → spare
            ],
            ..Default::default()
        };
        let a = assess(&obs, &thresholds());
        assert_eq!(a.to_terminate, vec![101]);
        assert_eq!(a.spared_non_agent, vec![202], "shared role NEVER killed");
    }

    #[test]
    fn agent_query_under_ceiling_is_not_killed() {
        let obs = Observation {
            backends: vec![agent_runaway(101, 5_000)], // 5s < 60s ceiling
            ..Default::default()
        };
        let a = assess(&obs, &thresholds());
        assert!(a.to_terminate.is_empty());
    }

    #[test]
    fn idle_agent_backend_is_not_a_runaway() {
        // An idle (not "active") agent backend is never a runaway, however long.
        let mut b = agent_runaway(101, 999_999);
        b.state = "idle".to_string();
        let obs = Observation {
            backends: vec![b],
            ..Default::default()
        };
        assert!(assess(&obs, &thresholds()).to_terminate.is_empty());
    }

    #[test]
    fn loop_terminates_only_agent_tagged_pids() {
        // End-to-end through the loop + killer seam: only the agent pid reaches
        // the killer; the shared pid is recorded as spared.
        let obs = Observation {
            backends: vec![agent_runaway(101, 120_000), shared_runaway(202, 120_000)],
            ..Default::default()
        };
        let clock = MockClock::new();
        let mut wl = WardenLoop::new(
            ScriptedSource::new(vec![obs]),
            RecordingKiller::default(),
            thresholds(),
        );
        let outcome = wl.tick(&clock);
        assert_eq!(outcome.terminated_pids, vec![101]);
        assert_eq!(outcome.spared_non_agent_pids, vec![202]);
        assert_eq!(wl.killer.killed, vec![101], "killer only saw the agent pid");
    }

    #[test]
    fn slot_over_ceiling_raises_alarm() {
        let obs = Observation {
            slots: vec![ReplicationSlot {
                slot_name: "agent_exfil".to_string(),
                slot_type: "logical".to_string(),
                active: true,
                retained_wal_bytes: 200 * 1024 * 1024, // 200 MiB > 64 MiB ceiling
            }],
            ..Default::default()
        };
        let a = assess(&obs, &thresholds());
        assert_eq!(
            a.slot_alarms,
            vec![("agent_exfil".to_string(), 200 * 1024 * 1024)]
        );
    }

    #[test]
    fn breaker_trips_on_lag_over_threshold() {
        let obs = Observation {
            replication_lag_bytes: 200 * 1024 * 1024, // > 128 MiB trip
            ..Default::default()
        };
        let a = assess(&obs, &thresholds());
        assert!(matches!(a.trip, Some(TripReason::ReplicationLag { .. })));
    }

    #[test]
    fn breaker_trips_on_runaway_volume() {
        // Three concurrent agent runaways → volume trip.
        let obs = Observation {
            backends: vec![
                agent_runaway(1, 120_000),
                agent_runaway(2, 120_000),
                agent_runaway(3, 120_000),
            ],
            ..Default::default()
        };
        let a = assess(&obs, &thresholds());
        assert!(matches!(
            a.trip,
            Some(TripReason::RunawayVolume {
                observed: 3,
                trip: 3
            })
        ));
    }

    #[test]
    fn poll_cadence_is_driven_by_the_injected_clock() {
        // Drive 3 ticks; assert the clock advanced by exactly the interval each
        // time (no wall clock). The breaker trips on the lag tick (#2) and the
        // outcome reflects event order, not real time.
        let ticks = vec![
            Observation::default(),
            Observation {
                replication_lag_bytes: 500 * 1024 * 1024,
                ..Default::default()
            },
            Observation::default(),
        ];
        let clock = MockClock::starting_at(1_000);
        let mut wl = WardenLoop::new(
            ScriptedSource::new(ticks),
            RecordingKiller::default(),
            thresholds(),
        );
        let outcomes = wl.run_ticks(&clock, 3);
        // 3 ticks * 2000ms interval, starting at 1000.
        assert_eq!(clock.monotonic_millis(), 1_000 + 3 * 2_000);
        assert!(!outcomes[0].breaker_open, "closed before the lag tick");
        assert!(outcomes[1].breaker_open, "open on the lag tick");
        assert!(outcomes[2].breaker_open, "stays open through cooldown");
    }

    #[test]
    fn breaker_recovers_after_cooldown_when_condition_clears() {
        // Tick 1 trips (lag); subsequent ticks are healthy; once the cooldown
        // (10_000ms = 5 ticks of 2000ms) elapses the breaker goes HalfOpen.
        let mut ticks = vec![Observation {
            replication_lag_bytes: 500 * 1024 * 1024,
            ..Default::default()
        }];
        ticks.extend(std::iter::repeat_with(Observation::default).take(6));
        let clock = MockClock::starting_at(0);
        let mut wl = WardenLoop::new(
            ScriptedSource::new(ticks),
            RecordingKiller::default(),
            thresholds(),
        );
        let outcomes = wl.run_ticks(&clock, 7);
        assert!(outcomes[0].breaker_open, "tripped on tick 0 (t=0)");
        // Cooldown is 10_000ms; tick k runs at t = 2000*k. The Open→HalfOpen
        // transition happens at the first tick where t >= 10_000, i.e. tick 5
        // (t=10_000). tick() calls breaker.tick() FIRST, so that tick reports
        // traffic allowed again.
        assert!(
            !outcomes[5].breaker_open,
            "half-open (traffic allowed) once cooldown elapsed"
        );
    }
}
