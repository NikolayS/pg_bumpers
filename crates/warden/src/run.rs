//! The **live** warden watchdog wiring (SPEC §3 layer 2, §4, §10.9).
//!
//! The gating *logic* (targeting, slot/WAL alarms, the authenticated breaker)
//! lives in [`crate::poller`] / [`crate::breaker`] and is fully DB-free and
//! unit-tested on a [`MockClock`](pgb_core::MockClock). This module is the thin
//! mortar that makes the shipped binary an actual running, **audited** watchdog:
//!
//! 1. [`PgActivitySource`] / [`PgKiller`] — the production
//!    [`ActivitySource`](crate::ActivitySource) / [`Killer`](crate::Killer) seams
//!    over a real PG18 admin connection (`pg_stat_activity` /
//!    `pg_replication_slots` / `pg_terminate_backend`).
//! 2. [`audit_entries_for`] — the **pure** mapping from one auditable
//!    [`TickOutcome`](crate::TickOutcome) to the
//!    `WARDEN_TERMINATE` / `BREAKER_TRIP` / `SLOT_ALARM` audit records. No DB,
//!    no clock — so the record shape is unit-tested without a database.
//! 3. [`run_loop`] — drives a [`WardenLoop`](crate::WardenLoop) over the live
//!    seams on a [`SystemClock`](pgb_core::SystemClock) cadence (poll 1–5s per
//!    SPEC §4), appending every enforcement action to the **same** `_meta` audit
//!    chain the rest of the system writes (via [`pgb_audit::Sink`]).
//!
//! Keeping the audit-record *construction* pure (and tested) is deliberate: the
//! deterministic, safety-relevant decisions stay covered by DB-free tests; only
//! the raw socket I/O (the `postgres` calls) is exercised by the env-gated
//! real-PG18 integration test.

use pgb_audit::{Decision, NewEntry, Principal as AuditPrincipal, Sink};
use pgb_core::Clock;
use pgb_policy::{DsnTarget, TargetResolutionError, TargetResolver};

use crate::poller::{ActivitySource, Killer, TickOutcome, WardenLoop};
use crate::thresholds::{ThresholdError, WardenThresholds};

/// Load the warden thresholds from a `policy.yaml` at `path`, **fail-closed**.
///
/// The warden refuses to start unless its thresholds are coherent (SPEC §4):
///   * the file must exist and be readable — a missing/unreadable policy is a
///     hard error, not a silent fall-back to defaults (an operator who pointed
///     the warden at a config meant that config to apply);
///   * a present-but-**invalid** `warden:` section (a zero ceiling, a disabling
///     poll interval, …) is **rejected** — never accepted as "good enough".
///
/// A document with **no** `warden:` section yields the conservative
/// [`WardenThresholds::default`] (a missing section is never an un-guarded
/// warden — that policy is in [`WardenThresholds::from_policy_yaml`]). This
/// function only adds the "the file must be present and readable" guard on top,
/// so the binary fails closed on both a bad path and a bad `warden:` block.
pub fn load_thresholds_fail_closed(path: &str) -> Result<WardenThresholds, String> {
    let yaml = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read warden policy `{path}` (fail-closed: refusing to start \
             without a policy): {e}"
        )
    })?;
    WardenThresholds::from_policy_yaml(&yaml).map_err(|e: ThresholdError| {
        format!("invalid warden policy `{path}` (fail-closed: refusing to start): {e}")
    })
}

/// The audited principal recorded as the **subject** of warden actions.
///
/// The warden acts *on* agent-tagged sessions, so the audit subject is the
/// hardened agent role (mirrors the proxy's audited principal). The audit chain
/// is written as the separate `pgb_audit_writer` role — "the audited cannot
/// write audit" (SPEC §3/§4/§10.9).
pub const WARDEN_AUDIT_ROLE: &str = "pgb_agent";

/// The audit `reason_code` for an agent-tagged runaway terminated by the warden.
pub const REASON_WARDEN_TERMINATE: &str = "WARDEN_TERMINATE";
/// The audit `reason_code` for the authenticated circuit breaker tripping.
pub const REASON_BREAKER_TRIP: &str = "BREAKER_TRIP";
/// The audit `reason_code` for a replication-slot WAL alarm.
pub const REASON_SLOT_ALARM: &str = "SLOT_ALARM";

/// Build the audit records for one warden [`TickOutcome`] (the **pure** core).
///
/// One record per auditable action, in a stable order so the chain is
/// deterministic across runs and machines:
///   1. one `WARDEN_TERMINATE` per terminated agent-tagged pid (the runaways);
///   2. one `SLOT_ALARM` per replication slot over the WAL ceiling;
///   3. one `BREAKER_TRIP` if the authenticated breaker opened this tick.
///
/// A tick with no action produces no records (the warden does not spam the chain
/// with no-ops). Spared shared sessions are *not* recorded as actions — the
/// warden took no action on them — which keeps "spare-shared" exactly as #52
/// proved it: a non-event, never a kill.
///
/// Every record is a [`Decision::Block`] (an enforcement action that prevented /
/// curtailed work), names the audited [`WARDEN_AUDIT_ROLE`] as its subject, and
/// has an empty (default) intent — the warden gates sessions, not statements.
pub fn audit_entries_for(outcome: &TickOutcome, session_id: &str) -> Vec<NewEntry> {
    let mut entries = Vec::new();

    for pid in &outcome.terminated_pids {
        entries.push(warden_entry(
            session_id,
            format!("pg_terminate_backend({pid})"),
            REASON_WARDEN_TERMINATE,
            Some(format!(
                "warden terminated agent-tagged runaway backend pid={pid}"
            )),
        ));
    }

    for (slot_name, retained) in &outcome.slot_alarms {
        entries.push(warden_entry(
            session_id,
            format!("replication slot `{slot_name}` retained_wal_bytes={retained}"),
            REASON_SLOT_ALARM,
            Some(format!(
                "warden slot/WAL alarm: slot `{slot_name}` retaining {retained} bytes over ceiling"
            )),
        ));
    }

    if outcome.breaker_open {
        entries.push(warden_entry(
            session_id,
            "circuit breaker OPEN".to_string(),
            REASON_BREAKER_TRIP,
            Some("warden authenticated circuit breaker tripped/open".to_string()),
        ));
    }

    entries
}

/// One warden audit entry: a `BLOCK` decision subject-tagged to the agent role.
fn warden_entry(
    session_id: &str,
    statement_text: String,
    reason_code: &str,
    reason: Option<String>,
) -> NewEntry {
    NewEntry {
        statement_text,
        decision: Decision::Block,
        reason_code: reason_code.to_string(),
        reason,
        principal: AuditPrincipal {
            role: WARDEN_AUDIT_ROLE.to_string(),
            session_id: Some(session_id.to_string()),
            principal: Some("pgb_warden".to_string()),
        },
        intent: Default::default(),
        write_safety: Default::default(),
    }
}

/// The number of distinct auditable actions a tick produced (terminations +
/// slot alarms + an optional breaker trip). Pure; used by the loop to know
/// whether anything needs appending and by tests to assert action counts.
pub fn action_count(outcome: &TickOutcome) -> usize {
    outcome.terminated_pids.len() + outcome.slot_alarms.len() + usize::from(outcome.breaker_open)
}

/// Run **one** warden tick and append its auditable actions to `sink`.
///
/// This is the per-tick step the live loop performs: drive the [`WardenLoop`]
/// (observe → assess → terminate agent-tagged runaways → trip the breaker), then
/// append each resulting action to the audit chain stamped from `clock`. It is
/// generic over the seams so the env-gated PG18 integration test drives it with
/// the live [`PgActivitySource`] / [`PgKiller`] + a [`pgb_audit::PgSink`], while
/// the deterministic logic stays in the (DB-free, unit-tested) [`WardenLoop`].
///
/// Returns the [`TickOutcome`] (for the runbook / tests) or the **first** audit
/// append error — a failed audit append is fatal to the guarantee that every
/// enforcement action leaves tamper-evident evidence, so it is surfaced, never
/// swallowed.
pub fn tick_and_audit<S, K>(
    loop_: &mut WardenLoop<S, K>,
    sink: &mut dyn Sink,
    clock: &dyn Clock,
    session_id: &str,
) -> Result<TickOutcome, String>
where
    S: ActivitySource,
    K: Killer,
{
    let outcome = loop_.tick(clock);
    let ts = clock.now_unix_millis();
    for entry in audit_entries_for(&outcome, session_id) {
        sink.append(entry, ts).map_err(|e| e.to_string())?;
    }
    Ok(outcome)
}

/// Resolved connection settings for the live warden binary (the env-derived
/// wiring `main()` assembles). Kept here, with the DSN builders, so the
/// (otherwise DB-only) binary's *configuration* logic is unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WardenSettings {
    /// Host of the watched primary (and the `_meta` DB) — **never** 5432.
    pub host: String,
    /// Port of the watched primary.
    pub port: String,
    /// The database the warden polls (`pg_stat_activity` / slots).
    pub backend_db: String,
    /// The `_meta` database holding the audit chain.
    pub audit_db: String,
    /// The admin role the warden polls + terminates as.
    pub admin_role: String,
    /// The admin role's password.
    pub admin_password: String,
    /// The audit-WRITER role the chain is appended as (never the agent role).
    pub writer_role: String,
    /// The audit-writer role's password.
    pub writer_password: String,
}

impl WardenSettings {
    /// Resolve settings from the BYO `policy.yaml` `primary:` target + an
    /// environment reader (`getenv("KEY") -> Option`), with the §0.5 precedence
    /// **env override > policy.yaml `primary:` target > FAIL-CLOSED**.
    ///
    /// Taking the policy target + the env reader as plain arguments (no process
    /// env, no DB) keeps this **pure + unit-testable** so the binary's
    /// configuration logic is covered:
    ///   * `host`/`port` resolve through the shared [`TargetResolver`] — there is
    ///     **NO** throwaway-cluster default (no hardcoded `54321`): with neither
    ///     an env override nor a policy `primary:` target the warden refuses to
    ///     start (fail-closed). **Never** 5432 unless that is the user's own DB;
    ///   * `backend_db` falls back to the policy target's database, then the
    ///     conventional `postgres`; `admin_role`/`audit_db`/`writer_role` keep
    ///     their conservative defaults (the warden polls as an admin role and
    ///     appends the chain as the audit-WRITER role, never the audited agent);
    ///   * the two **secrets** (`PGB_WARDEN_ADMIN_PASSWORD` /
    ///     `PGB_AUDIT_WRITER_PASSWORD`) have **no** default — a missing one is a
    ///     fail-closed error, never an empty password (the warden ships no
    ///     credential literals, mirroring the proxy's posture).
    pub fn resolve(
        policy_primary: Option<&DsnTarget>,
        getenv: impl Fn(&str) -> Option<String>,
    ) -> Result<WardenSettings, String> {
        let or = |key: &str, default: &str| getenv(key).unwrap_or_else(|| default.to_string());
        let required = |key: &str| {
            getenv(key).ok_or_else(|| {
                format!(
                    "{key} is required and has no default; source it from the secret store / env \
                     (the warden ships no credential literals)"
                )
            })
        };
        // The BYO primary target (SPEC §0.5): env override > policy.yaml `primary:`
        // target > FAIL-CLOSED. No throwaway-cluster default (no silent `54321`).
        // The warden's poll/admin role is NOT the connect role on the target, so the
        // resolver's role fallback is unused here (admin_role is resolved separately);
        // `default_role` is set to the conventional admin `postgres` for completeness.
        let target = TargetResolver {
            policy_target: policy_primary,
            host_override: getenv("PGB_BACKEND_HOST"),
            port_override: getenv("PGB_BACKEND_PORT"),
            db_override: getenv("PGB_BACKEND_DB"),
            role_override: None,
            default_database: "postgres",
            default_role: "postgres",
            host_env_key: "PGB_BACKEND_HOST",
            port_env_key: "PGB_BACKEND_PORT",
            policy_hint: "policy.yaml `primary:` (the BYO primary target the warden watches, \
                          SPEC §0.5)",
        }
        .resolve()
        .map_err(|e: TargetResolutionError| e.to_string())?;
        Ok(WardenSettings {
            host: target.host,
            port: target.port.to_string(),
            backend_db: target.database,
            audit_db: or("PGB_AUDIT_DB", "postgres"),
            admin_role: or("PGB_WARDEN_ADMIN_ROLE", "postgres"),
            admin_password: required("PGB_WARDEN_ADMIN_PASSWORD")?,
            writer_role: or("PGB_AUDIT_WRITER_ROLE", "pgb_audit_writer"),
            writer_password: required("PGB_AUDIT_WRITER_PASSWORD")?,
        })
    }

    /// The DSN the warden polls + terminates with (admin role on `backend_db`).
    /// `PgActivitySource` / `PgKiller` append `application_name=pgb_warden_admin`
    /// so the warden never observes/kills itself.
    pub fn observe_dsn(&self) -> String {
        kv_dsn(
            &self.host,
            &self.port,
            &self.backend_db,
            &self.admin_role,
            &self.admin_password,
        )
    }

    /// The DSN the warden appends the `_meta` audit chain with (the **writer**
    /// role on `audit_db`). NEVER the audited agent role — "the audited cannot
    /// write audit" (SPEC §3/§4/§10.9).
    pub fn writer_dsn(&self) -> String {
        kv_dsn(
            &self.host,
            &self.port,
            &self.audit_db,
            &self.writer_role,
            &self.writer_password,
        )
    }
}

/// Build a keyword/value DSN for a role on a given database (no TLS keyword —
/// the dev/local-stack clusters use loopback `NoTls`; production injects TLS via
/// the connection string from the secret store).
pub fn kv_dsn(host: &str, port: &str, db: &str, user: &str, password: &str) -> String {
    format!("host={host} port={port} dbname={db} user={user} password={password}")
}

/// The human-readable one-line summary of an auditable tick (the body the live
/// loop logs when anything happened). Pure + testable so the loop driver itself
/// stays a thin, DB-only sleep loop.
pub fn format_tick_log(outcome: &TickOutcome) -> String {
    format!(
        "pgb-warden: tick — terminated={:?} spared={:?} slot_alarms={:?} breaker_open={}",
        outcome.terminated_pids,
        outcome.spared_non_agent_pids,
        outcome.slot_alarms,
        outcome.breaker_open,
    )
}

/// Drive the live watchdog loop forever on a `SystemClock` cadence (SPEC §4 poll
/// 1–5s). Each iteration runs [`tick_and_audit`] then sleeps `poll_interval`.
///
/// This is the production driver `main()` calls; it never returns under normal
/// operation. It is **not** unit-tested (it sleeps on a real clock and talks to
/// a real DB) — the deterministic per-tick behavior is covered by
/// [`tick_and_audit`]'s DB-free tests and the env-gated PG18 integration test.
/// The cadence is read from the injected [`Clock`] only for the audit timestamp;
/// the sleep duration comes from the validated [`WardenThresholds`].
pub fn run_loop<S, K>(
    mut loop_: WardenLoop<S, K>,
    mut sink: Box<dyn Sink>,
    thresholds: &WardenThresholds,
    clock: &dyn Clock,
    session_id: &str,
) -> Result<std::convert::Infallible, String>
where
    S: ActivitySource,
    K: Killer,
{
    let interval = std::time::Duration::from_millis(thresholds.poll_interval_millis);
    loop {
        let outcome = tick_and_audit(&mut loop_, sink.as_mut(), clock, session_id)?;
        if action_count(&outcome) > 0 {
            eprintln!("{}", format_tick_log(&outcome));
        }
        std::thread::sleep(interval);
    }
}

#[cfg(feature = "pg")]
pub use pg::{PgActivitySource, PgKiller};

/// The live PG18-backed seams. Behind the default-on `pg` feature so the pure
/// logic + audit-record construction build/test without a `postgres` client.
#[cfg(feature = "pg")]
mod pg {
    use postgres::{Client, NoTls};

    use crate::model::{Backend, Observation, ReplicationSlot};
    use crate::poller::{ActivitySource, Killer};

    /// The `application_name` the warden's own admin connections carry so the
    /// source can exclude them and never target itself.
    pub(super) const WARDEN_ADMIN_APP_NAME: &str = "pgb_warden_admin";

    /// Reads `pg_stat_activity` + `pg_replication_slots` from a live cluster
    /// (the production [`ActivitySource`]). Connects as an admin role with a
    /// distinct `application_name` so the warden never observes/kills itself.
    pub struct PgActivitySource {
        admin: Client,
    }

    impl PgActivitySource {
        /// Open the admin connection used to poll the cluster. The DSN should
        /// carry `application_name=pgb_warden_admin` (the source filters it out);
        /// [`connect`](Self::connect) appends it if absent.
        pub fn connect(dsn: &str) -> Result<Self, String> {
            let dsn = with_warden_admin_app_name(dsn);
            Ok(PgActivitySource {
                admin: Client::connect(&dsn, NoTls).map_err(|e| e.to_string())?,
            })
        }
    }

    impl ActivitySource for PgActivitySource {
        fn observe(&mut self) -> Observation {
            // Exclude our own admin connections (by app_name) and the warden's
            // backend pid so the warden never targets itself.
            let backend_rows = self
                .admin
                .query(
                    "SELECT pid,
                            coalesce(usename, '') AS usename,
                            coalesce(application_name, '') AS application_name,
                            coalesce(state, '') AS state,
                            coalesce(
                              (extract(epoch FROM (now() - query_start)) * 1000)::bigint, 0
                            ) AS runtime_ms,
                            coalesce(query, '') AS query
                       FROM pg_stat_activity
                      WHERE pid <> pg_backend_pid()
                        AND backend_type = 'client backend'
                        AND application_name <> $1",
                    &[&WARDEN_ADMIN_APP_NAME],
                )
                .unwrap_or_default();
            let backends = backend_rows
                .iter()
                .map(|r| {
                    let runtime_ms: i64 = r.get("runtime_ms");
                    Backend {
                        pid: r.get("pid"),
                        usename: r.get("usename"),
                        application_name: r.get("application_name"),
                        state: r.get("state"),
                        query_runtime_millis: runtime_ms.max(0) as u64,
                        query: r.get("query"),
                    }
                })
                .collect();

            let slot_rows = self
                .admin
                .query(
                    "SELECT slot_name,
                            slot_type,
                            coalesce(active, false) AS active,
                            coalesce(
                              pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0
                            )::bigint AS retained
                       FROM pg_replication_slots",
                    &[],
                )
                .unwrap_or_default();
            let slots = slot_rows
                .iter()
                .map(|r| {
                    let retained: i64 = r.get("retained");
                    ReplicationSlot {
                        slot_name: r.get("slot_name"),
                        slot_type: r.get("slot_type"),
                        active: r.get("active"),
                        retained_wal_bytes: retained.max(0) as u64,
                    }
                })
                .collect();

            Observation {
                backends,
                slots,
                replication_lag_bytes: 0,
            }
        }
    }

    /// Terminates a backend via `pg_terminate_backend` on a live cluster (the
    /// production [`Killer`]). The caller has already proven the pid is
    /// agent-tagged (the targeting invariant lives in the pure `assess`).
    pub struct PgKiller {
        admin: Client,
    }

    impl PgKiller {
        /// Open the admin connection used to terminate backends.
        pub fn connect(dsn: &str) -> Result<Self, String> {
            let dsn = with_warden_admin_app_name(dsn);
            Ok(PgKiller {
                admin: Client::connect(&dsn, NoTls).map_err(|e| e.to_string())?,
            })
        }
    }

    impl Killer for PgKiller {
        fn terminate(&mut self, pid: i32) {
            // pg_terminate_backend returns bool; ignore the (rare) race where the
            // backend already exited.
            let _ = self.admin.query("SELECT pg_terminate_backend($1)", &[&pid]);
        }
    }

    /// Ensure the DSN carries the warden admin `application_name` so the source
    /// can exclude the warden's own connections.
    pub(super) fn with_warden_admin_app_name(dsn: &str) -> String {
        if dsn.contains("application_name=") {
            dsn.to_string()
        } else {
            format!("{dsn} application_name={WARDEN_ADMIN_APP_NAME}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_audit::{InMemorySink, verify_chain};
    use pgb_core::MockClock;

    fn outcome(
        terminated: Vec<i32>,
        spared: Vec<i32>,
        slots: Vec<(&str, u64)>,
        breaker_open: bool,
    ) -> TickOutcome {
        TickOutcome {
            terminated_pids: terminated,
            spared_non_agent_pids: spared,
            slot_alarms: slots.into_iter().map(|(n, b)| (n.to_string(), b)).collect(),
            breaker_open,
        }
    }

    /// Write `contents` to a uniquely-named temp policy file and return its path.
    fn temp_policy(tag: &str, contents: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "pgb-warden-policy-{tag}-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn fail_closed_on_present_but_invalid_warden_config() {
        // A present-but-INVALID `warden:` section (a 0ms poll = busy-loop) must
        // make the warden REFUSE to start — never silently accept it.
        let bad = "warden:\n  poll_interval_millis: 0\n  max_query_runtime_millis: 1\n  \
                   slot_retained_wal_alarm_bytes: 1\n  breaker_lag_trip_bytes: 1\n  \
                   breaker_runaway_trip_count: 1\n  breaker_cooldown_millis: 1\n";
        let path = temp_policy("invalid", bad);
        let err = load_thresholds_fail_closed(path.to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("invalid warden policy") && err.contains("busy-loop"),
            "must refuse a busy-loop poll config: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fail_closed_on_missing_policy_file() {
        // A missing/unreadable policy is a hard error — the warden does not
        // silently fall back to defaults when pointed at a config that isn't there.
        let missing = std::env::temp_dir().join("pgb-warden-NO-SUCH-policy-file.yaml");
        let _ = std::fs::remove_file(&missing);
        let err = load_thresholds_fail_closed(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("cannot read warden policy"), "{err}");
    }

    #[test]
    fn valid_policy_loads_with_its_warden_thresholds() {
        let good = "version: 1\nwarden:\n  poll_interval_millis: 1500\n  \
                    max_query_runtime_millis: 30000\n  slot_retained_wal_alarm_bytes: 33554432\n  \
                    breaker_lag_trip_bytes: 67108864\n  breaker_runaway_trip_count: 2\n  \
                    breaker_cooldown_millis: 15000\n";
        let path = temp_policy("valid", good);
        let t = load_thresholds_fail_closed(path.to_str().unwrap()).unwrap();
        assert_eq!(t.poll_interval_millis, 1_500);
        assert_eq!(t.breaker_runaway_trip_count, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_warden_section_uses_conservative_default() {
        // The file exists but has no `warden:` block → conservative defaults
        // (a missing section is never an UN-guarded warden), still validated.
        let path = temp_policy("nowarden", "version: 1\nroles: {}\n");
        let t = load_thresholds_fail_closed(path.to_str().unwrap()).unwrap();
        assert_eq!(t, WardenThresholds::default());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn terminate_action_becomes_a_block_record() {
        let o = outcome(vec![101], vec![202], vec![], false);
        let entries = audit_entries_for(&o, "warden-1");
        assert_eq!(entries.len(), 1, "exactly the one kill is recorded");
        let e = &entries[0];
        assert_eq!(e.decision, Decision::Block);
        assert_eq!(e.reason_code, REASON_WARDEN_TERMINATE);
        assert!(e.statement_text.contains("101"), "names the killed pid");
        assert_eq!(e.principal.role, WARDEN_AUDIT_ROLE);
        assert_eq!(e.principal.principal.as_deref(), Some("pgb_warden"));
    }

    #[test]
    fn spared_shared_session_produces_no_record() {
        // The crux: a spared (non-agent) session is a NON-EVENT — the warden
        // took no action, so it must leave NO audit action (never a kill record).
        let o = outcome(vec![], vec![202, 303], vec![], false);
        assert!(
            audit_entries_for(&o, "warden-1").is_empty(),
            "spared shared sessions must produce zero action records"
        );
        assert_eq!(action_count(&o), 0);
    }

    #[test]
    fn slot_alarm_becomes_a_record() {
        let o = outcome(
            vec![],
            vec![],
            vec![("agent_exfil", 200 * 1024 * 1024)],
            false,
        );
        let entries = audit_entries_for(&o, "warden-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason_code, REASON_SLOT_ALARM);
        assert!(entries[0].statement_text.contains("agent_exfil"));
    }

    #[test]
    fn breaker_trip_becomes_a_record() {
        let o = outcome(vec![], vec![], vec![], true);
        let entries = audit_entries_for(&o, "warden-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason_code, REASON_BREAKER_TRIP);
    }

    #[test]
    fn all_three_actions_in_one_tick_record_in_stable_order() {
        // terminate(s) → slot alarm(s) → breaker trip, deterministically.
        let o = outcome(vec![101, 102], vec![202], vec![("slot_a", 999)], true);
        let entries = audit_entries_for(&o, "warden-1");
        let codes: Vec<&str> = entries.iter().map(|e| e.reason_code.as_str()).collect();
        assert_eq!(
            codes,
            vec![
                REASON_WARDEN_TERMINATE,
                REASON_WARDEN_TERMINATE,
                REASON_SLOT_ALARM,
                REASON_BREAKER_TRIP,
            ]
        );
        assert_eq!(action_count(&o), 4);
    }

    #[test]
    fn no_action_tick_appends_nothing() {
        let o = outcome(vec![], vec![], vec![], false);
        assert!(audit_entries_for(&o, "warden-1").is_empty());
    }

    #[test]
    fn tick_and_audit_appends_each_action_to_the_chain() {
        // Drive a real WardenLoop over scripted seams into an InMemorySink and
        // assert the actions land on a verifiable chain (the DB-free analogue of
        // the env-gated _meta IT: same Sink API, same records).
        use crate::model::{AGENT_ROLE, Backend, Observation, PROXY_APP_NAME, ReplicationSlot};

        struct OneShot(Option<Observation>);
        impl ActivitySource for OneShot {
            fn observe(&mut self) -> Observation {
                self.0.take().unwrap_or_default()
            }
        }
        struct NoopKiller;
        impl Killer for NoopKiller {
            fn terminate(&mut self, _pid: i32) {}
        }

        let obs = Observation {
            backends: vec![Backend {
                pid: 101,
                usename: AGENT_ROLE.to_string(),
                application_name: PROXY_APP_NAME.to_string(),
                state: "active".to_string(),
                query_runtime_millis: 120_000,
                query: "SELECT pg_sleep(9999)".to_string(),
            }],
            slots: vec![ReplicationSlot {
                slot_name: "agent_exfil".to_string(),
                slot_type: "logical".to_string(),
                active: true,
                retained_wal_bytes: 500 * 1024 * 1024,
            }],
            replication_lag_bytes: 0,
        };
        let thresholds = WardenThresholds {
            poll_interval_millis: 1_000,
            max_query_runtime_millis: 200,
            slot_retained_wal_alarm_bytes: 1,
            breaker_lag_trip_bytes: 1,
            breaker_runaway_trip_count: 99,
            breaker_cooldown_millis: 5_000,
        };
        let mut wl = WardenLoop::new(OneShot(Some(obs)), NoopKiller, thresholds);
        let clock = MockClock::starting_at(1_700_000_000_000);
        let mut sink = InMemorySink::new();

        let outcome = tick_and_audit(&mut wl, &mut sink, &clock, "warden-1").unwrap();
        assert_eq!(outcome.terminated_pids, vec![101]);

        let chain = sink.chain().records().to_vec();
        // terminate + slot alarm + breaker trip (the slot trips the breaker).
        let codes: Vec<&str> = chain
            .iter()
            .map(|r| r.payload.reason_code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                REASON_WARDEN_TERMINATE,
                REASON_SLOT_ALARM,
                REASON_BREAKER_TRIP
            ]
        );
        verify_chain(&chain).expect("the warden's audit chain must verify");
    }

    // ---- The binary's configuration logic (DB-free, so it stays covered) ----

    /// An env reader backed by a fixed map (no process env).
    fn fake_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// A minimal BYO `primary:` target for the resolver tests.
    fn primary_target(host: &str, port: u16, db: &str) -> DsnTarget {
        DsnTarget {
            host: host.to_string(),
            port,
            database: db.to_string(),
            role: "pgb_agent".to_string(),
            secret_ref: None,
        }
    }

    /// HEADLINE (RED #2, warden): with NO env override, the warden resolves its
    /// watched host/port from the BYO `policy.yaml` `primary:` target — NOT the
    /// removed `54321` default.
    #[test]
    fn settings_resolve_from_byo_policy_target_not_54321() {
        let primary = primary_target("byo.db.internal", 6543, "appdb");
        let s = WardenSettings::resolve(
            Some(&primary),
            fake_env(&[
                ("PGB_WARDEN_ADMIN_PASSWORD", "admin_pw"),
                ("PGB_AUDIT_WRITER_PASSWORD", "writer_pw"),
            ]),
        )
        .unwrap();
        assert_eq!(s.host, "byo.db.internal");
        assert_eq!(s.port, "6543");
        assert_ne!(s.port, "54321", "must NOT fall back to the throwaway 54321");
        // backend_db falls back to the policy target's database.
        assert_eq!(s.backend_db, "appdb");
        assert_eq!(s.admin_role, "postgres");
        assert_eq!(s.writer_role, "pgb_audit_writer");
        assert_eq!(
            s.observe_dsn(),
            "host=byo.db.internal port=6543 dbname=appdb user=postgres password=admin_pw"
        );
        assert_eq!(
            s.writer_dsn(),
            "host=byo.db.internal port=6543 dbname=postgres user=pgb_audit_writer password=writer_pw"
        );
    }

    /// FAIL-CLOSED: with NEITHER a policy `primary:` target NOR an env override,
    /// resolution errors — the warden refuses to start rather than silently
    /// default the watched host/port to the throwaway 54321 cluster.
    #[test]
    fn settings_resolve_fails_closed_with_no_policy_target_and_no_env() {
        let err = WardenSettings::resolve(
            None,
            fake_env(&[
                ("PGB_WARDEN_ADMIN_PASSWORD", "admin_pw"),
                ("PGB_AUDIT_WRITER_PASSWORD", "writer_pw"),
            ]),
        )
        .unwrap_err();
        assert!(err.contains("NO throwaway-cluster default"), "{err}");
        assert!(!err.contains("54321"), "no 54321 anywhere: {err}");
    }

    #[test]
    fn settings_resolve_env_override_wins_over_policy_target() {
        // The env override beats the policy target (the existing ITs / up.sh path).
        let primary = primary_target("byo.db.internal", 6543, "appdb");
        let s = WardenSettings::resolve(
            Some(&primary),
            fake_env(&[
                ("PGB_BACKEND_HOST", "db.internal"),
                ("PGB_BACKEND_PORT", "54399"),
                ("PGB_BACKEND_DB", "appdb2"),
                ("PGB_AUDIT_DB", "meta"),
                ("PGB_WARDEN_ADMIN_ROLE", "warden_admin"),
                ("PGB_WARDEN_ADMIN_PASSWORD", "a"),
                ("PGB_AUDIT_WRITER_ROLE", "auditw"),
                ("PGB_AUDIT_WRITER_PASSWORD", "w"),
            ]),
        )
        .unwrap();
        assert_eq!(
            s.observe_dsn(),
            "host=db.internal port=54399 dbname=appdb2 user=warden_admin password=a"
        );
        assert_eq!(
            s.writer_dsn(),
            "host=db.internal port=54399 dbname=meta user=auditw password=w"
        );
    }

    #[test]
    fn settings_resolve_fail_closed_on_missing_admin_secret() {
        // No `PGB_WARDEN_ADMIN_PASSWORD` → refuse (no empty-password fallback).
        let primary = primary_target("h", 6543, "db");
        let err = WardenSettings::resolve(
            Some(&primary),
            fake_env(&[("PGB_AUDIT_WRITER_PASSWORD", "writer_pw")]),
        )
        .unwrap_err();
        assert!(err.contains("PGB_WARDEN_ADMIN_PASSWORD"), "{err}");
        assert!(err.contains("no credential literals"), "{err}");
    }

    #[test]
    fn settings_resolve_fail_closed_on_missing_writer_secret() {
        let primary = primary_target("h", 6543, "db");
        let err = WardenSettings::resolve(
            Some(&primary),
            fake_env(&[("PGB_WARDEN_ADMIN_PASSWORD", "admin_pw")]),
        )
        .unwrap_err();
        assert!(err.contains("PGB_AUDIT_WRITER_PASSWORD"), "{err}");
    }

    #[test]
    fn kv_dsn_is_a_keyword_value_string() {
        assert_eq!(
            kv_dsn("h", "5499", "db", "u", "p"),
            "host=h port=5499 dbname=db user=u password=p"
        );
    }

    #[test]
    fn format_tick_log_summarizes_the_actions() {
        let o = outcome(vec![101], vec![202], vec![("slot_a", 9)], true);
        let line = format_tick_log(&o);
        assert!(line.contains("terminated=[101]"));
        assert!(line.contains("spared=[202]"));
        assert!(line.contains("slot_a"));
        assert!(line.contains("breaker_open=true"));
    }

    #[cfg(feature = "pg")]
    #[test]
    fn warden_admin_app_name_is_appended_when_absent_and_preserved_when_present() {
        use super::pg::with_warden_admin_app_name;
        let dsn = "host=127.0.0.1 port=54321 user=postgres";
        assert_eq!(
            with_warden_admin_app_name(dsn),
            format!("{dsn} application_name=pgb_warden_admin")
        );
        // An explicit application_name is preserved (never double-tagged).
        let tagged = "host=127.0.0.1 application_name=custom";
        assert_eq!(with_warden_admin_app_name(tagged), tagged);
    }
}
