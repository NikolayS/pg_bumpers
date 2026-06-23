//! Warden thresholds — the kill criteria + slot/WAL ceilings + breaker trip
//! points (SPEC §4 "Warden", §10.10 `policy.yaml`).
//!
//! These live in the `warden:` section of `policy.yaml`. They are kept here in
//! `crates/warden` (not in `crates/policy`'s `PolicyConfig`) so the warden owns
//! its own operational knobs without widening the policy crate's schema; the
//! warden reads `crates/policy` for the role model and adds this section. The
//! parse is **fail-closed**: a malformed or over-permissive (zero-ceiling /
//! never-tripping) config is rejected rather than silently accepted.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The warden's operational thresholds (SPEC §4, §10.10).
///
/// `deny_unknown_fields`: a MISSPELLED threshold key inside the `warden:` section
/// (e.g. `breaker_cooldwn_millis`) is a **parse error**, not a silently-ignored
/// field that leaves the default in place — so a typo in `policy.yaml` fails closed
/// (and the shipped-example drift test catches it). This only rejects unknown keys
/// *within* this struct; the surrounding document's other top-level keys (`version`,
/// `roles`, …) are parsed by `pgb_policy::PolicyConfig` and are unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WardenThresholds {
    /// Poll cadence in milliseconds (SPEC §4: 1–5s; **mockable** via the
    /// injected [`Clock`](pgb_core::Clock)). Bounds keep an operator from
    /// setting a busy-loop (0) or an effectively-disabled (hours) cadence.
    pub poll_interval_millis: u64,

    /// Kill an **agent-tagged** backend whose single query has run longer than
    /// this (the runaway `pg_sleep` / long-scan case). Only ever applied to
    /// agent-tagged sessions — never shared roles (SPEC §3).
    pub max_query_runtime_millis: u64,

    /// Alarm ceiling for retained WAL on **any** replication slot (the WAL-DoS
    /// magnitude). A slot retaining more than this trips the slot/WAL alarm.
    pub slot_retained_wal_alarm_bytes: u64,

    /// Breaker trips when replication lag exceeds this many bytes.
    pub breaker_lag_trip_bytes: u64,

    /// Breaker trips when the number of concurrently-active agent-tagged
    /// backends running over [`max_query_runtime_millis`](Self::max_query_runtime_millis)
    /// reaches this count (the "volume" trip — many runaways at once).
    pub breaker_runaway_trip_count: u32,

    /// How long (ms) the breaker stays OPEN before it may transition to
    /// HALF-OPEN to probe recovery (read through the injected clock).
    pub breaker_cooldown_millis: u64,
}

impl Default for WardenThresholds {
    /// Conservative defaults used by the binary when no `warden:` section is
    /// present. Documented, not magic: a 2s poll, 60s runaway-kill, 64 MiB slot
    /// alarm, 128 MiB lag trip, 3 concurrent runaways to trip, 30s cooldown.
    fn default() -> Self {
        WardenThresholds {
            poll_interval_millis: 2_000,
            max_query_runtime_millis: 60_000,
            slot_retained_wal_alarm_bytes: 64 * 1024 * 1024,
            breaker_lag_trip_bytes: 128 * 1024 * 1024,
            breaker_runaway_trip_count: 3,
            breaker_cooldown_millis: 30_000,
        }
    }
}

/// A warden-threshold load/validation failure (fail-closed).
#[derive(Debug, Error)]
pub enum ThresholdError {
    /// The YAML could not be parsed into the typed model.
    #[error("warden policy failed to parse: {0}")]
    Parse(#[from] serde_yaml_ng::Error),
    /// Parsed but failed a validation rule (a value that would disable a guard).
    #[error("invalid warden policy: {0}")]
    Invalid(String),
}

/// The top-level shape we parse a `policy.yaml` into to pull the `warden:`
/// section. Everything else in the document is ignored here (the role model is
/// parsed by `pgb_policy::PolicyConfig`), so the warden and policy crates can
/// share one file without coupling their schemas.
#[derive(Debug, Deserialize)]
struct PolicyDocWardenView {
    warden: Option<WardenThresholds>,
}

impl WardenThresholds {
    /// Parse + validate the `warden:` section out of a full `policy.yaml`.
    ///
    /// If the document has no `warden:` section, the conservative
    /// [`Default`](Self::default) is returned (a missing section never means an
    /// un-guarded warden). A present-but-invalid section is **rejected**.
    pub fn from_policy_yaml(yaml: &str) -> Result<WardenThresholds, ThresholdError> {
        let doc: PolicyDocWardenView = serde_yaml_ng::from_str(yaml)?;
        let t = doc.warden.unwrap_or_default();
        t.validate()?;
        Ok(t)
    }

    /// Validate the thresholds, rejecting any value that would disable a guard
    /// (fail-closed; SPEC §4 poll 1–5s bound, non-zero ceilings).
    pub fn validate(&self) -> Result<(), ThresholdError> {
        // Poll cadence must be a real cadence: a 0ms poll is a busy-loop; a
        // multi-hour poll is an effectively-disabled warden. Bound to (0, 1h].
        if self.poll_interval_millis == 0 {
            return Err(ThresholdError::Invalid(
                "poll_interval_millis must be > 0 (a 0ms poll is a busy-loop)".to_string(),
            ));
        }
        if self.poll_interval_millis > 3_600_000 {
            return Err(ThresholdError::Invalid(format!(
                "poll_interval_millis {} exceeds 1h — that disables the warden",
                self.poll_interval_millis
            )));
        }
        if self.max_query_runtime_millis == 0 {
            return Err(ThresholdError::Invalid(
                "max_query_runtime_millis must be > 0 (0 would kill every agent query instantly)"
                    .to_string(),
            ));
        }
        if self.slot_retained_wal_alarm_bytes == 0 {
            return Err(ThresholdError::Invalid(
                "slot_retained_wal_alarm_bytes must be > 0".to_string(),
            ));
        }
        if self.breaker_lag_trip_bytes == 0 {
            return Err(ThresholdError::Invalid(
                "breaker_lag_trip_bytes must be > 0".to_string(),
            ));
        }
        if self.breaker_runaway_trip_count == 0 {
            return Err(ThresholdError::Invalid(
                "breaker_runaway_trip_count must be >= 1".to_string(),
            ));
        }
        if self.breaker_cooldown_millis == 0 {
            return Err(ThresholdError::Invalid(
                "breaker_cooldown_millis must be > 0 (the breaker would never cool down)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH_WARDEN: &str = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
warden:
  poll_interval_millis: 1500
  max_query_runtime_millis: 30000
  slot_retained_wal_alarm_bytes: 33554432
  breaker_lag_trip_bytes: 67108864
  breaker_runaway_trip_count: 2
  breaker_cooldown_millis: 15000
"#;

    #[test]
    fn parses_warden_section_from_policy_yaml() {
        let t = WardenThresholds::from_policy_yaml(WITH_WARDEN).unwrap();
        assert_eq!(t.poll_interval_millis, 1_500);
        assert_eq!(t.max_query_runtime_millis, 30_000);
        assert_eq!(t.breaker_runaway_trip_count, 2);
    }

    #[test]
    fn missing_warden_section_yields_conservative_default() {
        // A policy with no `warden:` block is never an unguarded warden.
        let yaml = "version: 1\nroles: {}\n";
        let t = WardenThresholds::from_policy_yaml(yaml).unwrap();
        assert_eq!(t, WardenThresholds::default());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let yaml = "warden:\n  poll_interval_millis: 0\n  max_query_runtime_millis: 1\n  slot_retained_wal_alarm_bytes: 1\n  breaker_lag_trip_bytes: 1\n  breaker_runaway_trip_count: 1\n  breaker_cooldown_millis: 1\n";
        let err = WardenThresholds::from_policy_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("busy-loop"), "{err}");
    }

    #[test]
    fn rejects_disabling_poll_interval() {
        let yaml = "warden:\n  poll_interval_millis: 99999999\n  max_query_runtime_millis: 1\n  slot_retained_wal_alarm_bytes: 1\n  breaker_lag_trip_bytes: 1\n  breaker_runaway_trip_count: 1\n  breaker_cooldown_millis: 1\n";
        let err = WardenThresholds::from_policy_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("disables the warden"), "{err}");
    }

    #[test]
    fn rejects_zero_runaway_trip_count() {
        let t = WardenThresholds {
            breaker_runaway_trip_count: 0,
            ..WardenThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn rejects_zero_cooldown() {
        let t = WardenThresholds {
            breaker_cooldown_millis: 0,
            ..WardenThresholds::default()
        };
        let err = t.validate().unwrap_err();
        assert!(err.to_string().contains("cool down"), "{err}");
    }

    #[test]
    fn rejects_zero_slot_and_lag_ceilings() {
        let t = WardenThresholds {
            slot_retained_wal_alarm_bytes: 0,
            ..WardenThresholds::default()
        };
        assert!(t.validate().is_err());
        let t = WardenThresholds {
            breaker_lag_trip_bytes: 0,
            ..WardenThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn default_validates() {
        assert!(WardenThresholds::default().validate().is_ok());
    }

    /// The SHIPPED policy example now documents a `warden:` section (S5 #77 item 2).
    /// Assert it parses, validates, AND equals the conservative built-in default — so
    /// the example is HONEST (a deployment sees exactly what the warden enforces) and a
    /// drift between the doc'd numbers and the code default would fail CI.
    ///
    /// STRUCTURAL drift, not just value drift (S5 #77 review fix): the value-equality
    /// check ALONE is blind to a *missing/misspelled* section or field — because a
    /// renamed `warden:` key (or, before `deny_unknown_fields`, a typo'd threshold field)
    /// silently falls back to `default()`, so `default == default` would still pass and
    /// hide the drift. We therefore ALSO assert the example string literally CONTAINS a
    /// `warden:` section header and every expected field name before/alongside the value
    /// comparison. Combined with `#[serde(deny_unknown_fields)]` on `WardenThresholds`
    /// (a misspelled threshold key now fails to PARSE), the test fails if the section is
    /// renamed OR any field is misspelled — not only if a value drifts.
    #[test]
    fn shipped_policy_example_warden_section_matches_the_default() {
        const EXAMPLE: &str = include_str!("../../policy/policy.example.yaml");

        // (1) STRUCTURE: the section header + every field name must be literally present.
        // Catches a renamed `warden:` key (which would otherwise fall back to default()
        // and pass the value check) and a renamed/dropped field. We match the `<field>:`
        // form so a *value* edit can't accidentally satisfy a *field-name* assertion.
        assert!(
            EXAMPLE.contains("\nwarden:"),
            "policy.example.yaml must document a top-level `warden:` section \
             (a renamed key silently falls back to WardenThresholds::default())"
        );
        for field in [
            "poll_interval_millis:",
            "max_query_runtime_millis:",
            "slot_retained_wal_alarm_bytes:",
            "breaker_lag_trip_bytes:",
            "breaker_runaway_trip_count:",
            "breaker_cooldown_millis:",
        ] {
            assert!(
                EXAMPLE.contains(field),
                "policy.example.yaml `warden:` section is missing the `{field}` field \
                 (a misspelled/dropped field would silently use the default)"
            );
        }

        // (2) PARSE + VALIDATE: `deny_unknown_fields` means a typo'd threshold key here
        // is a hard parse error, not a silently-defaulted field.
        let t = WardenThresholds::from_policy_yaml(EXAMPLE)
            .expect("the shipped policy.example.yaml `warden:` section must parse + validate");

        // (3) VALUES: the documented numbers must match the conservative built-in default.
        assert_eq!(
            t,
            WardenThresholds::default(),
            "the documented `warden:` values must match WardenThresholds::default() — \
             update both together if you change a threshold"
        );
    }

    /// `deny_unknown_fields` teeth: a MISSPELLED threshold key inside `warden:` is a
    /// parse error (fail-closed), not a silently-ignored field that leaves the default.
    /// This is what makes the structural half of the drift test bite for a field typo.
    #[test]
    fn rejects_unknown_warden_threshold_key() {
        // A full, otherwise-valid warden section with ONE misspelled key.
        let yaml = "warden:\n  \
            poll_interval_millis: 2000\n  \
            max_query_runtime_millis: 60000\n  \
            slot_retained_wal_alarm_bytes: 67108864\n  \
            breaker_lag_trip_bytes: 134217728\n  \
            breaker_runaway_trip_count: 3\n  \
            breaker_cooldwn_millis: 30000\n"; // typo: cooldwn
        let err = WardenThresholds::from_policy_yaml(yaml).expect_err(
            "a misspelled warden threshold key must FAIL to parse (deny_unknown_fields)",
        );
        // It is a parse error (not a validation error).
        assert!(
            matches!(err, ThresholdError::Parse(_)),
            "expected a Parse error for the unknown key, got: {err}"
        );
    }
}
