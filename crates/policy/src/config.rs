//! The single `policy.yaml` model + validation (SPEC §10.10, §12.2, §15.1).
//!
//! One `policy.yaml` drives the per-role certified-action surface and autonomy.
//! This module is the **typed serde schema** plus a [`validate`](PolicyConfig::validate)
//! pass that rejects malformed or **over-permissive** configs — most importantly
//! an autonomy level above the MVP ceiling (**L0–L2 only**, §15.1) and negative
//! / nonsensical budgets. Validation is *fail-closed*: anything it can't make
//! sense of is rejected rather than silently accepted.
//!
//! The example config shipped in the crate root (`policy.example.yaml`) loads
//! and validates; tests pin both that and the rejection cases.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Autonomy level for a role (SPEC §15.1: **L0–L2 only** in the MVP).
///
/// - **L0** — no autonomy: every action requires human approval.
/// - **L1** — human-in-the-loop: the agent proposes; a human approves before
///   apply.
/// - **L2** — bounded autonomy: the agent may auto-apply actions inside the
///   certified action set + budgets, no human in the loop.
///
/// L3+ (full autonomy) is **out of MVP scope** and is rejected by validation —
/// it deserializes (so we can give a precise error) but never validates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutonomyLevel {
    /// L0 — no autonomy; every action needs approval.
    L0,
    /// L1 — human-in-the-loop; propose then approve.
    L1,
    /// L2 — bounded autonomy within the certified set + budgets.
    L2,
    /// L3 — full autonomy. **Not allowed in the MVP** (validation rejects it).
    L3,
}

impl AutonomyLevel {
    /// The highest autonomy level permitted in the MVP (SPEC §15.1).
    pub const MVP_MAX: AutonomyLevel = AutonomyLevel::L2;
}

/// Per-window cumulative budget (the slow-drip / R4a gate — SPEC §13.4, §11.6).
///
/// A single-shot cutoff alone can't stop exfiltration split across many small
/// reads, so each role also carries a cumulative budget over a rolling window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBudget {
    /// The rolling window length, in seconds.
    pub window_secs: u64,
    /// Maximum cumulative bytes returned within the window.
    pub max_bytes: u64,
    /// Maximum cumulative rows returned within the window.
    pub max_rows: u64,
}

/// A role's budgets: a single-shot cap, a per-window cumulative cap, and the
/// EXPLAIN-cost ceiling (SPEC §3, §11.6 / §13.2 bounded disclosure).
///
/// `PartialEq`/`Eq` are derived manually because [`f64`] (`max_plan_cost`) is not
/// `Eq`; the manual impls treat the cost field by bit pattern, which is exactly
/// what the round-trip equality tests need (no NaN ceilings are valid anyway —
/// validation rejects a non-finite / non-positive cost).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBudget {
    /// Single-shot maximum bytes a single statement may return.
    pub max_bytes: u64,
    /// Single-shot maximum rows a single statement may return.
    pub max_rows: u64,
    /// The **EXPLAIN-cost ceiling**: the maximum estimated *total plan cost*
    /// (planner cost units) a read may have before the advisory EXPLAIN gate
    /// blocks it pre-flight (SPEC §3 "EXPLAIN-cost gate (advisory)"). Defaults
    /// (when omitted from `policy.yaml`) to [`RoleBudget::DEFAULT_MAX_PLAN_COST`].
    #[serde(default = "RoleBudget::default_max_plan_cost")]
    pub max_plan_cost: f64,
    /// The **EXPLAIN row ceiling**: the maximum *estimated* row count a read's
    /// plan may have before the advisory EXPLAIN gate blocks it pre-flight.
    ///
    /// Deliberately **independent** of the single-shot `max_rows` cutoff: the
    /// EXPLAIN gate is *advisory* (planner estimates), whereas `max_rows` is the
    /// un-foolable mid-stream cutoff. Coupling them would let an *estimate* pre-
    /// empt the real cutoff (e.g. an un-analyzed table the planner over-estimates
    /// would be blocked even though the actual result is tiny). So this defaults
    /// generously high ([`RoleBudget::DEFAULT_MAX_PLAN_ROWS`]) — the cost ceiling
    /// is the primary EXPLAIN dimension; tighten this only when a role should
    /// refuse plans the planner predicts will be huge.
    #[serde(default = "RoleBudget::default_max_plan_rows")]
    pub max_plan_rows: u64,
    /// Cumulative per-window budget (slow-drip gate).
    pub per_window: WindowBudget,
}

impl PartialEq for RoleBudget {
    fn eq(&self, other: &Self) -> bool {
        self.max_bytes == other.max_bytes
            && self.max_rows == other.max_rows
            && self.max_plan_cost.to_bits() == other.max_plan_cost.to_bits()
            && self.max_plan_rows == other.max_plan_rows
            && self.per_window == other.per_window
    }
}

impl Eq for RoleBudget {}

/// A role's policy: its certified read surface, budgets, and autonomy
/// (SPEC §15.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePolicy {
    /// The SELECT whitelist — the `schema.table` relations this role may read.
    /// Empty ⇒ the role may read nothing (fail-closed default).
    #[serde(default)]
    pub select_whitelist: Vec<String>,
    /// The role's byte/row budgets (single-shot + per-window cumulative).
    pub budget: RoleBudget,
    /// The role's autonomy level (**L0–L2** in MVP).
    pub autonomy: AutonomyLevel,
}

/// Clone-provider selection (SPEC §12.2: `clone.provider: none|dblab`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloneProvider {
    /// No clone provider — baseline guarded-apply path (SPEC §12).
    #[default]
    None,
    /// Database Lab Engine clones (the moat upgrade — SPEC §12).
    Dblab,
}

/// Clone configuration (SPEC §12.2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CloneConfig {
    /// Which clone provider is active.
    #[serde(default)]
    pub provider: CloneProvider,
}

/// Replica configuration (SPEC §12.2: `replica.dsn?`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReplicaConfig {
    /// Optional replica DSN. Absent ⇒ reads route to the primary under stricter
    /// budgets (degraded mode, SPEC §10.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,
}

/// PITR configuration (SPEC §12.2: `pitr.enabled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PitrConfig {
    /// Whether WAL archiving / PITR is available as a last-resort fence.
    #[serde(default)]
    pub enabled: bool,
}

/// Approver-set placeholder (SPEC §14.1, §14.3 MVP = CLI signing key).
///
/// The MVP approval mechanism is a CLI-held signing key; the full tiered
/// approver set + dual-control is fast-follow (§14.3). This struct pins the
/// **signing-key id** the grant verifier trusts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApproverSet {
    /// The id of the CLI signing key authorized to issue grants (§14.3). The
    /// public key material itself is resolved out-of-band (KMS / keyring,
    /// §10.9); this is the reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_signing_key_id: Option<String>,
}

/// Audit-anchor placeholder (SPEC §10.9, §14.3 audit-key-grade handling).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditAnchorConfig {
    /// The external append-only / WORM anchor endpoint (placeholder; wired in
    /// S4). Absent ⇒ local-only audit (documented downgrade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_endpoint: Option<String>,
}

/// The full `policy.yaml` model (SPEC §10.10, §12.2, §15.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Schema version of this policy document (forward-compat guard).
    pub version: u32,
    /// Per-role policies, keyed by role name. [`BTreeMap`] for deterministic
    /// serialization.
    pub roles: BTreeMap<String, RolePolicy>,
    /// Replica configuration.
    #[serde(default)]
    pub replica: ReplicaConfig,
    /// Clone-provider configuration.
    #[serde(default)]
    pub clone: CloneConfig,
    /// PITR configuration.
    #[serde(default)]
    pub pitr: PitrConfig,
    /// Approver-set placeholder (CLI signing-key id).
    #[serde(default)]
    pub approvers: ApproverSet,
    /// Audit-anchor placeholder.
    #[serde(default)]
    pub audit: AuditAnchorConfig,
}

/// A policy validation / load failure.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The YAML could not be parsed into the typed model.
    #[error("policy.yaml failed to parse: {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    /// The policy parsed but failed a validation rule (over-permissive or
    /// malformed).
    #[error("invalid policy: {0}")]
    Invalid(String),
}

impl PolicyConfig {
    /// Parse **and validate** a `policy.yaml` document from a string.
    ///
    /// This is the entry point production code should use — it never returns an
    /// unvalidated config.
    pub fn load_from_yaml(yaml: &str) -> Result<PolicyConfig, PolicyError> {
        let cfg: PolicyConfig = serde_yaml_ng::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the policy, rejecting malformed or **over-permissive** configs
    /// (SPEC §15.1: L0–L2 only; non-negative, coherent budgets).
    ///
    /// Fail-closed: every rule rejects rather than coerces. Returns the first
    /// violation found.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version == 0 {
            return Err(PolicyError::Invalid(
                "version must be >= 1 (got 0)".to_string(),
            ));
        }
        if self.roles.is_empty() {
            return Err(PolicyError::Invalid(
                "at least one role must be defined".to_string(),
            ));
        }
        for (name, role) in &self.roles {
            role.validate(name)?;
        }
        Ok(())
    }
}

impl RolePolicy {
    /// Validate a single role's policy.
    fn validate(&self, role_name: &str) -> Result<(), PolicyError> {
        // §15.1: autonomy is capped at L2 in the MVP. L3+ is over-permissive.
        if self.autonomy > AutonomyLevel::MVP_MAX {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: autonomy {:?} exceeds the MVP ceiling {:?} \
                 (only L0–L2 are permitted, SPEC §15.1)",
                self.autonomy,
                AutonomyLevel::MVP_MAX,
            )));
        }
        self.budget.validate(role_name)?;
        Ok(())
    }
}

impl RoleBudget {
    /// The default EXPLAIN-cost ceiling when `max_plan_cost` is omitted from a
    /// role's `policy.yaml` budget. Chosen as a large-but-finite cost so the
    /// gate is *advisory-on* by default (it still blocks an obviously heavy plan)
    /// without surprising existing configs that predate the field.
    pub const DEFAULT_MAX_PLAN_COST: f64 = 1_000_000.0;

    /// The default EXPLAIN **row** ceiling when `max_plan_rows` is omitted. Set
    /// very high so the advisory row dimension does not pre-empt the un-foolable
    /// single-shot row cutoff by default (see [`RoleBudget::max_plan_rows`]).
    pub const DEFAULT_MAX_PLAN_ROWS: u64 = 1_000_000_000;

    /// serde default hook for [`RoleBudget::max_plan_cost`].
    fn default_max_plan_cost() -> f64 {
        RoleBudget::DEFAULT_MAX_PLAN_COST
    }

    /// serde default hook for [`RoleBudget::max_plan_rows`].
    fn default_max_plan_rows() -> u64 {
        RoleBudget::DEFAULT_MAX_PLAN_ROWS
    }

    /// Validate budgets: every cap must be positive and the per-window window
    /// must be non-zero. A zero or "negative" budget is nonsensical and, since
    /// YAML numbers can't be negative in a `u64`, a negative literal fails to
    /// deserialize (also a rejection) — both paths are tested.
    fn validate(&self, role_name: &str) -> Result<(), PolicyError> {
        if self.max_bytes == 0 || self.max_rows == 0 {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: single-shot budget caps must be > 0 \
                 (max_bytes={}, max_rows={})",
                self.max_bytes, self.max_rows
            )));
        }
        // The EXPLAIN-cost ceiling must be a positive, finite cost (a zero /
        // negative / NaN ceiling would either block everything or be incoherent).
        if !(self.max_plan_cost.is_finite() && self.max_plan_cost > 0.0) {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: max_plan_cost must be a finite value > 0 \
                 (got {})",
                self.max_plan_cost
            )));
        }
        // The EXPLAIN row ceiling must be positive (zero would block everything).
        if self.max_plan_rows == 0 {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: max_plan_rows must be > 0"
            )));
        }
        let w = &self.per_window;
        if w.window_secs == 0 {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: per_window.window_secs must be > 0"
            )));
        }
        if w.max_bytes == 0 || w.max_rows == 0 {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: per_window cumulative caps must be > 0 \
                 (max_bytes={}, max_rows={})",
                w.max_bytes, w.max_rows
            )));
        }
        // A cumulative window cap below the single-shot cap is contradictory
        // (one statement could exceed the whole window) — reject as malformed.
        if w.max_bytes < self.max_bytes || w.max_rows < self.max_rows {
            return Err(PolicyError::Invalid(format!(
                "role `{role_name}`: per_window caps must be >= single-shot caps \
                 (window bytes/rows {}/{} < single-shot {}/{})",
                w.max_bytes, w.max_rows, self.max_bytes, self.max_rows
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped example config — must load and validate.
    const EXAMPLE: &str = include_str!("../policy.example.yaml");

    #[test]
    fn example_policy_loads_and_validates() {
        let cfg = PolicyConfig::load_from_yaml(EXAMPLE).expect("example must load");
        assert!(cfg.version >= 1);
        assert!(cfg.roles.contains_key("app_writer"));
        // An analytics role with broader budget and L2 autonomy.
        let analytics = &cfg.roles["analytics"];
        assert_eq!(analytics.autonomy, AutonomyLevel::L2);
        assert!(!analytics.select_whitelist.is_empty());
        // §12.2 fields parsed.
        assert_eq!(cfg.clone.provider, CloneProvider::Dblab);
        assert!(cfg.pitr.enabled);
        assert!(cfg.replica.dsn.is_some());
        assert!(cfg.approvers.cli_signing_key_id.is_some());
    }

    #[test]
    fn example_round_trips_through_serde() {
        let cfg = PolicyConfig::load_from_yaml(EXAMPLE).unwrap();
        let yaml = serde_yaml_ng::to_string(&cfg).unwrap();
        let reparsed = PolicyConfig::load_from_yaml(&yaml).unwrap();
        assert_eq!(cfg, reparsed);
    }

    #[test]
    fn rejects_autonomy_level_l3() {
        // The headline over-permissive case: L3 is out of MVP scope (§15.1).
        let yaml = r#"
version: 1
roles:
  rogue:
    select_whitelist: ["public.t"]
    autonomy: L3
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("autonomy"), "{msg}");
        assert!(msg.contains("L3") || msg.contains("ceiling"), "{msg}");
    }

    #[test]
    fn rejects_negative_budget() {
        // A negative budget literal cannot fit the unsigned model → parse error
        // (still a rejection, fail-closed).
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: -5
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        assert!(PolicyConfig::load_from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_zero_budget() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 0
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("must be > 0"), "{err}");
    }

    #[test]
    fn rejects_window_cap_below_single_shot() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 100000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains(">= single-shot"), "{err}");
    }

    #[test]
    fn rejects_empty_roles() {
        let yaml = "version: 1\nroles: {}\n";
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("at least one role"), "{err}");
    }

    #[test]
    fn rejects_version_zero() {
        let yaml = r#"
version: 0
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn clone_provider_defaults_to_none() {
        // Omitting `clone:` yields the baseline (no DBLab) — never silently
        // upgraded.
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L0
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).unwrap();
        assert_eq!(cfg.clone.provider, CloneProvider::None);
        assert!(!cfg.pitr.enabled);
        assert!(cfg.replica.dsn.is_none());
    }

    #[test]
    fn max_plan_cost_defaults_when_omitted() {
        // Existing configs that predate the EXPLAIN ceiling still load: the
        // field defaults rather than failing to parse.
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).unwrap();
        assert_eq!(
            cfg.roles["app"].budget.max_plan_cost,
            RoleBudget::DEFAULT_MAX_PLAN_COST
        );
    }

    #[test]
    fn explicit_max_plan_cost_parses() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      max_plan_cost: 5000.0
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).unwrap();
        assert_eq!(cfg.roles["app"].budget.max_plan_cost, 5000.0);
    }

    #[test]
    fn rejects_zero_or_negative_max_plan_cost() {
        for bad in ["0", "0.0", "-1.0"] {
            let yaml = format!(
                r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      max_plan_cost: {bad}
      per_window: {{ window_secs: 60, max_bytes: 10000, max_rows: 1000 }}
"#
            );
            let err = PolicyConfig::load_from_yaml(&yaml).unwrap_err();
            assert!(err.to_string().contains("max_plan_cost"), "{err} ({bad})");
        }
    }

    #[test]
    fn max_plan_rows_defaults_and_rejects_zero() {
        // Defaults when omitted.
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).unwrap();
        assert_eq!(
            cfg.roles["app"].budget.max_plan_rows,
            RoleBudget::DEFAULT_MAX_PLAN_ROWS
        );
        // Zero is rejected (would block everything).
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      max_plan_rows: 0
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("max_plan_rows"), "{err}");
    }

    #[test]
    fn autonomy_levels_are_ordered() {
        assert!(AutonomyLevel::L0 < AutonomyLevel::L1);
        assert!(AutonomyLevel::L1 < AutonomyLevel::L2);
        assert!(AutonomyLevel::L2 < AutonomyLevel::L3);
        assert_eq!(AutonomyLevel::MVP_MAX, AutonomyLevel::L2);
    }
}
