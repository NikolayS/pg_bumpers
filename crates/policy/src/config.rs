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

/// A **credential-less** connection target (SPEC §0.5 BYO Postgres). The user
/// declares *where* to connect — host/port/database/role — in `policy.yaml`, but
/// **never** a literal password. In this version the password resolves from the
/// **conventional env var** (`PGB_BACKEND_PASSWORD` / `PGB_META_PASSWORD` /
/// `PGB_DOCTOR_PASSWORD`), matching the existing "no literal passwords in files"
/// posture. The optional [`secret_ref`](DsnTarget::secret_ref) is a
/// **forward-compatibility placeholder** — it is parsed but **not** resolved by any
/// daemon today; the env var is required.
///
/// This is the BYO surface: `policy.yaml` is **authoritative** for the targets;
/// the `PGB_BACKEND_*` / `PGB_PROXY_*` / `PGB_META_DSN` env vars become
/// **overrides** layered on top (env override > policy.yaml target > fail-closed —
/// there is **no** silent throwaway-cluster default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsnTarget {
    /// The target host (e.g. `db.internal` — the user's existing primary). This
    /// is the user's own database; there is no throwaway-cluster assumption.
    pub host: String,
    /// The target port.
    pub port: u16,
    /// The database to connect to.
    pub database: String,
    /// The role to connect as (e.g. `pgb_agent` on the primary, `pgb_applier`
    /// for the applier, `pgb_audit_writer` for `_meta`). Credential-less: the
    /// **password is not here** — it resolves from the conventional env var.
    pub role: String,
    /// Optional **forward-compatibility placeholder** for a secret-store reference
    /// (e.g. `kms://pg-bumpers/primary-pw/v1`). **This version does NOT resolve it**:
    /// no daemon reads `secret_ref` — the password always comes from the conventional
    /// env var (`PGB_BACKEND_PASSWORD` / `PGB_META_PASSWORD` / `PGB_DOCTOR_PASSWORD`).
    /// It is parsed + kept credential-less so a future release can wire a resolver
    /// without a schema change. The literal secret is **never** stored in
    /// `policy.yaml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
}

impl DsnTarget {
    /// Build a **credential-less** keyword/value DSN string (host/port/db/user, no
    /// `password=`). The daemon appends the password resolved from the conventional
    /// env var before connecting; this never carries a literal secret.
    ///
    /// SAFETY: the `host`/`database`/`role` fields are concatenated UNQUOTED into
    /// the libpq keyword/value DSN, so a value carrying a space or `=` would inject
    /// extra keywords (e.g. `database: "app sslmode=disable"` would silently turn
    /// TLS off). [`DsnTarget::validate`] (run by [`PolicyConfig::validate`] on load)
    /// rejects exactly those characters for the **policy.yaml** path. The parallel
    /// **env-override** path is checked separately by [`TargetResolver::resolve`]
    /// (same [`reject_dsn_injection`] rule, on the env-merged values) before it
    /// builds a [`ResolvedTarget`]. So **both** the policy.yaml and the env-override
    /// values are proven injection-safe before any DSN is built — fail-closed.
    pub fn to_credential_less_dsn(&self) -> String {
        format!(
            "host={} port={} dbname={} user={}",
            self.host, self.port, self.database, self.role
        )
    }

    /// Fail-closed validation of a BYO DSN target (SPEC §0.5, §2). Because
    /// [`to_credential_less_dsn`](DsnTarget::to_credential_less_dsn) concatenates
    /// these fields UNQUOTED into a libpq keyword/value DSN, any value carrying
    /// whitespace, `=`, a quote, a backslash, or a control char could **inject an
    /// extra DSN keyword** (e.g. a TLS-disabling `sslmode=disable`, an `options=…`,
    /// or a host redirect). An operator's `policy.yaml` never legitimately needs
    /// those in a host / database / role / secret_ref, so we **reject** them on load
    /// rather than risk a silent downgrade. The env override path (`PGB_BACKEND_*`)
    /// remains available for the rare edge case that needs an exotic value.
    pub fn validate(&self, where_: &str) -> Result<(), PolicyError> {
        reject_dsn_injection(where_, "host", &self.host)?;
        reject_dsn_injection(where_, "database", &self.database)?;
        reject_dsn_injection(where_, "role", &self.role)?;
        if let Some(secret_ref) = &self.secret_ref {
            reject_dsn_injection(where_, "secret_ref", secret_ref)?;
        }
        Ok(())
    }
}

/// Reject a DSN-target field value that could inject an extra libpq keyword. The
/// banned characters are whitespace (the keyword/value separator), `=` (the
/// key/value separator), single/double quotes (libpq value quoting), a backslash
/// (libpq value escaping), and any ASCII control char. Empty is also rejected — a
/// blank host/db/role is meaningless and fail-closed.
fn reject_dsn_injection(where_: &str, field: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::Invalid(format!(
            "{where_}: `{field}` must not be empty (fail-closed, SPEC §0.5)"
        )));
    }
    if let Some(bad) = value
        .chars()
        .find(|c| c.is_whitespace() || c.is_control() || matches!(c, '=' | '\'' | '"' | '\\'))
    {
        return Err(PolicyError::Invalid(format!(
            "{where_}: `{field}` contains the illegal character {bad:?} — a host/database/role/\
             secret_ref must not carry whitespace, `=`, a quote, a backslash, or a control char \
             (they would inject extra libpq DSN keywords, e.g. a TLS-disabling `sslmode=disable`; \
             fail-closed, SPEC §0.5/§2). Value: {value:?}"
        )));
    }
    Ok(())
}

/// A **resolved** connection target — the host/port/db/role a daemon will actually
/// connect to, after layering env overrides on top of the `policy.yaml` BYO target
/// (SPEC §0.5). Credential-less: the password is resolved separately from the
/// secret store / env and is **never** carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The resolved host.
    pub host: String,
    /// The resolved port.
    pub port: u16,
    /// The resolved database.
    pub database: String,
    /// The resolved role.
    pub role: String,
}

impl ResolvedTarget {
    /// Build a credential-less keyword/value DSN (no `password=`).
    ///
    /// SAFETY: `host`/`database`/`role` are concatenated UNQUOTED, exactly like
    /// [`DsnTarget::to_credential_less_dsn`]. The only constructor of a
    /// `ResolvedTarget` is [`TargetResolver::resolve`], which runs
    /// [`reject_dsn_injection`] on these env-merged values before returning, so a
    /// target reaching this method is injection-safe — fail-closed at resolve time.
    pub fn to_credential_less_dsn(&self) -> String {
        format!(
            "host={} port={} dbname={} user={}",
            self.host, self.port, self.database, self.role
        )
    }
}

/// The error a fail-closed target resolution returns. Two fail-closed cases:
///
/// * [`Missing`](TargetResolutionError::Missing) — **neither** the env override
///   **nor** the `policy.yaml` BYO target supplies a required field (§0.5 / §2: no
///   silent throwaway-cluster default, no hardcoded `54321` — a daemon with no
///   target refuses to start).
/// * [`Injection`](TargetResolutionError::Injection) — a **resolved** host /
///   database / role value (after env-override layering) carries a libpq DSN
///   metacharacter (whitespace, `=`, quote, backslash, control char) that would
///   inject an extra keyword into the credential-less DSN (e.g. a TLS-disabling
///   `sslmode=disable`). The env-override path is checked with the **same**
///   [`reject_dsn_injection`] rule as the `policy.yaml` path, so an operator
///   setting `PGB_BACKEND_DB="app sslmode=disable"` gets a clear error rather than
///   a silently-downgraded connection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetResolutionError {
    /// Neither the env override nor the policy target supplied a required field.
    #[error(
        "no connection target for `{field}`: set it via the env override `{env_key}`, or declare \
         the BYO target in policy.yaml ({policy_hint}). There is NO throwaway-cluster default \
         (fail-closed, SPEC §0.5)."
    )]
    Missing {
        /// Which logical field was unresolvable (`host` / `port`).
        field: &'static str,
        /// The env var the operator can set to override.
        env_key: &'static str,
        /// A hint pointing at the policy.yaml section that would supply it.
        policy_hint: &'static str,
    },
    /// A resolved field value (env override or policy target) carries a DSN
    /// metacharacter that would inject an extra libpq keyword (fail-closed).
    #[error(
        "resolved connection target field `{field}` is unsafe (would inject a libpq DSN \
         keyword): {detail}"
    )]
    Injection {
        /// Which logical field was unsafe (`host` / `database` / `role`).
        field: &'static str,
        /// The underlying [`reject_dsn_injection`] rejection detail.
        detail: String,
    },
}

impl TargetResolutionError {
    /// The logical field this error is about (`host` / `port` / `database` /
    /// `role`). Convenience accessor over both variants.
    pub fn field(&self) -> &'static str {
        match self {
            TargetResolutionError::Missing { field, .. } => field,
            TargetResolutionError::Injection { field, .. } => field,
        }
    }
}

/// Layered resolution of a connection target: **env override > policy.yaml BYO
/// target > fail-closed** (SPEC §0.5, §2). This is the single helper every daemon
/// (proxy / applyd / warden / mcp) uses so the precedence is identical and there is
/// exactly one place the (now-removed) `54321` default used to live.
///
/// `host`/`port` are the connection essentials and are **fail-closed**: if neither
/// the env override nor the policy target provides them, resolution errors (the
/// daemon refuses to start). `database`/`role` fall back to the supplied
/// `default_database` / `default_role` (conventional, non-secret, non-targeting
/// values like `postgres` / `pgb_agent`) when neither source names them, because a
/// missing db/role is not a *targeting* hole the way a missing host/port is.
///
/// Every argument is taken explicitly (no process-env reads) so this is **pure and
/// unit-testable** — the daemon binaries pass `std::env::var(..).ok()` for the
/// overrides and the loaded `policy.yaml` target.
pub struct TargetResolver<'a> {
    /// The BYO target from `policy.yaml` (authoritative when no env override).
    pub policy_target: Option<&'a DsnTarget>,
    /// env override for the host (e.g. `PGB_BACKEND_HOST`).
    pub host_override: Option<String>,
    /// env override for the port (e.g. `PGB_BACKEND_PORT`).
    pub port_override: Option<String>,
    /// env override for the database (e.g. `PGB_BACKEND_DB`).
    pub db_override: Option<String>,
    /// env override for the role (e.g. `PGB_BACKEND_ROLE`).
    pub role_override: Option<String>,
    /// Conventional default database when neither env nor policy names one.
    pub default_database: &'a str,
    /// Conventional default role when neither env nor policy names one.
    pub default_role: &'a str,
    /// The env var name reported in the fail-closed error for host.
    pub host_env_key: &'static str,
    /// The env var name reported in the fail-closed error for port.
    pub port_env_key: &'static str,
    /// The policy.yaml section hint reported in the fail-closed error.
    pub policy_hint: &'static str,
}

impl<'a> TargetResolver<'a> {
    /// Resolve the target, fail-closed on a missing host/port **or** on a resolved
    /// host/database/role that carries a libpq DSN metacharacter.
    ///
    /// The host/database/role of the *resolved* target (after env-override layering)
    /// are concatenated UNQUOTED into the credential-less DSN by
    /// [`ResolvedTarget::to_credential_less_dsn`], so we run the **same**
    /// [`reject_dsn_injection`] guard the `policy.yaml` path uses
    /// ([`DsnTarget::validate`]) on the *env-merged* values before building the
    /// target — an env override like `PGB_BACKEND_DB="app sslmode=disable"` fails
    /// closed here rather than silently injecting a TLS-disabling keyword. `port` is
    /// typed (`u16`) and so cannot carry a metacharacter.
    pub fn resolve(&self) -> Result<ResolvedTarget, TargetResolutionError> {
        let host = self
            .host_override
            .clone()
            .or_else(|| self.policy_target.map(|t| t.host.clone()))
            .ok_or(TargetResolutionError::Missing {
                field: "host",
                env_key: self.host_env_key,
                policy_hint: self.policy_hint,
            })?;
        let port = match &self.port_override {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| TargetResolutionError::Missing {
                    field: "port",
                    env_key: self.port_env_key,
                    policy_hint: self.policy_hint,
                })?,
            None => self
                .policy_target
                .map(|t| t.port)
                .ok_or(TargetResolutionError::Missing {
                    field: "port",
                    env_key: self.port_env_key,
                    policy_hint: self.policy_hint,
                })?,
        };
        let database = self
            .db_override
            .clone()
            .or_else(|| self.policy_target.map(|t| t.database.clone()))
            .unwrap_or_else(|| self.default_database.to_string());
        let role = self
            .role_override
            .clone()
            .or_else(|| self.policy_target.map(|t| t.role.clone()))
            .unwrap_or_else(|| self.default_role.to_string());

        // Fail-closed DSN-injection guard on the RESOLVED (env-merged) string
        // fields, mirroring `DsnTarget::validate`. Covers every value that gets
        // concatenated into `ResolvedTarget::to_credential_less_dsn` (port is typed).
        Self::reject_resolved_injection("host", &host)?;
        Self::reject_resolved_injection("database", &database)?;
        Self::reject_resolved_injection("role", &role)?;

        Ok(ResolvedTarget {
            host,
            port,
            database,
            role,
        })
    }

    /// Apply the shared [`reject_dsn_injection`] rule to a resolved field value,
    /// mapping its rejection onto [`TargetResolutionError::Injection`] so the
    /// resolver surfaces a fail-closed error to the daemon.
    fn reject_resolved_injection(
        field: &'static str,
        value: &str,
    ) -> Result<(), TargetResolutionError> {
        reject_dsn_injection("resolved target", field, value).map_err(|e| {
            TargetResolutionError::Injection {
                field,
                detail: e.to_string(),
            }
        })
    }
}

/// Replica configuration (SPEC §12.2: `replica.dsn?`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReplicaConfig {
    /// Optional replica DSN. Absent ⇒ reads route to the primary under stricter
    /// budgets (degraded mode, SPEC §10.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,
    /// Optional **credential-less** replica target (SPEC §0.5 BYO). The typed BYO
    /// form of [`dsn`](ReplicaConfig::dsn) — host/port/db/role + a secret
    /// reference, no literal password. Either form may be present; the typed
    /// target is the BYO-first surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DsnTarget>,
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

/// Audit configuration (SPEC §10.9, §14.3 audit-key-grade handling) — carries the
/// `_meta` **location** AND the external WORM anchor endpoint, two distinct things:
///
/// - [`target`](AuditAnchorConfig::target) is the **credential-less `_meta` DSN
///   target** (SPEC §0.5 BYO — host/port/db/role of the database holding the
///   hash-chained `_meta` audit chain; commonly co-located on the primary, or a
///   separate audit DB). This is where the daemons append + verify the chain.
/// - [`anchor_endpoint`](AuditAnchorConfig::anchor_endpoint) is the **external
///   append-only / WORM anchor endpoint** that pins the chain *head* — a different
///   sink entirely (object-lock / transparency log), NOT a Postgres DSN.
///
/// Both are optional and orthogonal; adding the `_meta` target did not disturb the
/// pre-existing anchor field.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditAnchorConfig {
    /// The **credential-less `_meta` DSN target** (SPEC §0.5 BYO): where the
    /// hash-chained audit chain lives. Host/port/db/role + an optional secret
    /// reference; no literal password. Absent ⇒ the `_meta` DSN comes from the
    /// `PGB_META_DSN` env (the existing posture).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DsnTarget>,
    /// The external append-only / WORM anchor endpoint (placeholder; wired in
    /// S4). Absent ⇒ local-only audit (documented downgrade). NOT a Postgres DSN —
    /// distinct from [`target`](AuditAnchorConfig::target).
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
    /// The **primary** BYO connection target (SPEC §0.5): the WALL/agent +
    /// applier connection target — the user's existing production database the
    /// proxy and applyd connect to. **Credential-less** (host/port/db/role +
    /// optional secret reference; no literal password). Absent ⇒ the daemons read
    /// the target from the `PGB_BACKEND_*` env (which then must be set — there is
    /// **no** silent throwaway-cluster default; resolution is env override >
    /// policy.yaml target > fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<DsnTarget>,
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
        // §0.5 fail-closed: every BYO DSN target must be injection-safe (its
        // host/db/role/secret_ref are concatenated UNQUOTED into a libpq DSN).
        if let Some(primary) = &self.primary {
            primary.validate("policy.yaml `primary:` target")?;
        }
        if let Some(replica) = &self.replica.target {
            replica.validate("policy.yaml `replica.target:`")?;
        }
        if let Some(audit) = &self.audit.target {
            audit.validate("policy.yaml `audit.target:`")?;
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

    // ---------------------------------------------------------------------------
    // SPEC §0.5 BYO Postgres — the typed DSN-target surface + layered resolution.
    // ---------------------------------------------------------------------------

    /// RED #1: `PolicyConfig` parses a BYO `policy.yaml` carrying the THREE §0.5
    /// DSN targets — `primary`, `replica` (typed `target`), and the `audit`/`_meta`
    /// location — as credential-less host/port/db/role + a secret reference (no
    /// literal password). Before the BYO fields exist this fails to parse.
    #[test]
    fn parses_the_three_byo_dsn_targets() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
primary:
  host: db.internal
  port: 5432
  database: app
  role: pgb_agent
  secret_ref: "kms://pg-bumpers/primary-pw/v1"
replica:
  target:
    host: replica.internal
    port: 5432
    database: app
    role: pgb_agent
audit:
  target:
    host: db.internal
    port: 5432
    database: app_meta
    role: pgb_audit_writer
    secret_ref: "kms://pg-bumpers/meta-pw/v1"
  anchor_endpoint: "https://audit-anchor.internal/v1/append"
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).expect("BYO targets must parse");

        // primary — credential-less, with a secret reference (NOT a literal pw).
        let primary = cfg.primary.as_ref().expect("primary target present");
        assert_eq!(primary.host, "db.internal");
        assert_eq!(primary.port, 5432);
        assert_eq!(primary.database, "app");
        assert_eq!(primary.role, "pgb_agent");
        assert_eq!(
            primary.secret_ref.as_deref(),
            Some("kms://pg-bumpers/primary-pw/v1")
        );
        // The credential-less DSN carries NO password keyword.
        let dsn = primary.to_credential_less_dsn();
        assert!(
            !dsn.contains("password"),
            "no literal password in DSN: {dsn}"
        );
        assert!(dsn.contains("user=pgb_agent"), "{dsn}");

        // replica — the typed BYO target alongside the legacy `dsn` string form.
        let replica = cfg.replica.target.as_ref().expect("replica target present");
        assert_eq!(replica.host, "replica.internal");
        assert!(replica.secret_ref.is_none());

        // audit/_meta — the DSN location is distinct from the WORM anchor endpoint.
        let meta = cfg
            .audit
            .target
            .as_ref()
            .expect("audit/_meta target present");
        assert_eq!(meta.database, "app_meta");
        assert_eq!(meta.role, "pgb_audit_writer");
        assert_eq!(
            cfg.audit.anchor_endpoint.as_deref(),
            Some("https://audit-anchor.internal/v1/append")
        );
    }

    /// The BYO targets round-trip through serde unchanged (so a re-emitted
    /// `policy.yaml` is byte-stable and still credential-less).
    #[test]
    fn byo_targets_round_trip_through_serde() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L1
    budget:
      max_bytes: 1000
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 10000, max_rows: 1000 }
primary:
  host: db.internal
  port: 5432
  database: app
  role: pgb_agent
audit:
  target:
    host: db.internal
    port: 5432
    database: app
    role: pgb_audit_writer
"#;
        let cfg = PolicyConfig::load_from_yaml(yaml).unwrap();
        let reemitted = serde_yaml_ng::to_string(&cfg).unwrap();
        let reparsed = PolicyConfig::load_from_yaml(&reemitted).unwrap();
        assert_eq!(cfg, reparsed);
        // The re-emitted document still contains NO literal password.
        assert!(
            !reemitted.to_lowercase().contains("password"),
            "policy.yaml must never carry a literal password: {reemitted}"
        );
    }

    /// RED (FIX 2, security/fail-closed): a BYO DSN target whose `database` value
    /// carries an embedded space + `=` would, when concatenated UNQUOTED into the
    /// libpq keyword/value DSN, inject an extra keyword (here a TLS-disabling
    /// `sslmode=disable`). `PolicyConfig::validate()` (run on load) must REJECT it.
    /// Before the per-field validation existed this loaded clean (the injection
    /// rode silently into the DSN); now it is a load-time error.
    #[test]
    fn rejects_dsn_target_with_keyword_injection() {
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L0
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
primary:
  host: db.internal
  port: 5432
  database: "app sslmode=disable"
  role: pgb_agent
"#;
        let err = PolicyConfig::load_from_yaml(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("database"), "names the offending field: {msg}");
        assert!(msg.contains("primary"), "names the offending target: {msg}");
        assert!(
            msg.contains("illegal character") || msg.contains("inject"),
            "explains the injection risk: {msg}"
        );
    }

    /// Every illegal character class is rejected, on every field, on every BYO
    /// target slot (primary / replica.target / audit.target) — fail-closed.
    #[test]
    fn rejects_dsn_target_illegal_chars_on_every_field() {
        // A whitespace, an `=`, a quote, a backslash, and a control char.
        let bad_values = [
            "has space",
            "has=eq",
            "has'quote",
            "has\"dquote",
            "has\\backslash",
            "has\tcontrol",
        ];
        // host / database / role each rejected.
        for field in ["host", "database", "role"] {
            for bad in bad_values {
                let mut t = target("db.internal", 5432, "app", "pgb_agent");
                match field {
                    "host" => t.host = bad.to_string(),
                    "database" => t.database = bad.to_string(),
                    "role" => t.role = bad.to_string(),
                    _ => unreachable!(),
                }
                let err = t.validate("primary").unwrap_err();
                assert!(
                    err.to_string().contains(field),
                    "field {field} value {bad:?} must be rejected naming the field: {err}"
                );
            }
        }
        // secret_ref rejected too.
        let mut t = target("db.internal", 5432, "app", "pgb_agent");
        t.secret_ref = Some("kms ref with space".to_string());
        let err = t.validate("primary").unwrap_err();
        assert!(err.to_string().contains("secret_ref"), "{err}");

        // Empty is also fail-closed.
        let mut t = target("", 5432, "app", "pgb_agent");
        t.host = String::new();
        assert!(t.validate("primary").is_err());

        // The replica.target and audit.target slots are validated too (not just primary).
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L0
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
replica:
  target: { host: "r host", port: 5432, database: app, role: pgb_agent }
"#;
        assert!(PolicyConfig::load_from_yaml(yaml).is_err());
        let yaml = r#"
version: 1
roles:
  app:
    autonomy: L0
    budget:
      max_bytes: 100
      max_rows: 100
      per_window: { window_secs: 60, max_bytes: 1000, max_rows: 1000 }
audit:
  target: { host: db.internal, port: 5432, database: "meta=evil", role: pgb_audit_writer }
"#;
        assert!(PolicyConfig::load_from_yaml(yaml).is_err());
    }

    /// GREEN guard: the legitimately-shaped BYO targets (the ones the example +
    /// the parse test use) still PASS validation — the injection guard does not
    /// reject ordinary host/db/role identifiers (dots, underscores, hyphens).
    #[test]
    fn accepts_legitimate_dsn_targets() {
        for t in [
            target("db.internal", 5432, "app", "pgb_agent"),
            target("replica.internal", 6543, "app_prod-1", "pgb_audit_writer"),
            target("127.0.0.1", 54321, "postgres", "postgres"),
        ] {
            t.validate("primary").expect("legitimate target must pass");
        }
        // With an ordinary secret_ref (a URI with `:` and `/`, no banned chars).
        let mut t = target("db.internal", 5432, "app", "pgb_agent");
        t.secret_ref = Some("kms://pg-bumpers/primary-pw/v1".to_string());
        t.validate("primary")
            .expect("ordinary secret_ref must pass");
    }

    /// The BYO targets are all OPTIONAL — a policy with none still loads (the
    /// daemons then resolve targets purely from env; see the resolver tests).
    #[test]
    fn byo_targets_are_optional() {
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
        assert!(cfg.primary.is_none());
        assert!(cfg.replica.target.is_none());
        assert!(cfg.audit.target.is_none());
    }

    // ---------------------------------------------------------------------------
    // RED #2 (HEADLINE): layered target resolution — env override > policy.yaml BYO
    // target > FAIL-CLOSED. There is NO throwaway-cluster 54321 default anywhere.
    // ---------------------------------------------------------------------------

    fn target(host: &str, port: u16, db: &str, role: &str) -> DsnTarget {
        DsnTarget {
            host: host.to_string(),
            port,
            database: db.to_string(),
            role: role.to_string(),
            secret_ref: None,
        }
    }

    fn resolver<'a>(
        policy_target: Option<&'a DsnTarget>,
        host: Option<&str>,
        port: Option<&str>,
    ) -> TargetResolver<'a> {
        TargetResolver {
            policy_target,
            host_override: host.map(String::from),
            port_override: port.map(String::from),
            db_override: None,
            role_override: None,
            default_database: "postgres",
            default_role: "pgb_agent",
            host_env_key: "PGB_BACKEND_HOST",
            port_env_key: "PGB_BACKEND_PORT",
            policy_hint: "policy.yaml `primary:`",
        }
    }

    #[test]
    fn resolve_uses_policy_target_when_no_env_override() {
        let t = target("db.internal", 6543, "app", "pgb_agent");
        let r = resolver(Some(&t), None, None).resolve().unwrap();
        assert_eq!(r.host, "db.internal");
        assert_eq!(r.port, 6543);
        assert_eq!(r.database, "app");
        assert_eq!(r.role, "pgb_agent");
        // CRITICAL: the resolved port is the BYO target's, NEVER the removed 54321.
        assert_ne!(r.port, 54321, "must not fall back to the throwaway 54321");
    }

    #[test]
    fn resolve_env_override_wins_over_policy_target() {
        let t = target("db.internal", 6543, "app", "pgb_agent");
        let r = resolver(Some(&t), Some("other.host"), Some("7000"))
            .resolve()
            .unwrap();
        assert_eq!(r.host, "other.host");
        assert_eq!(r.port, 7000);
    }

    #[test]
    fn resolve_fails_closed_when_no_env_and_no_policy_target() {
        // The headline §0.5 / §2 assertion: with NEITHER an env override NOR a
        // policy.yaml target, resolution FAILS CLOSED — it does NOT silently
        // default the host/port to the throwaway 54321 cluster.
        let err = resolver(None, None, None).resolve().unwrap_err();
        assert_eq!(err.field(), "host");
        let msg = err.to_string();
        assert!(msg.contains("NO throwaway-cluster default"), "{msg}");
        assert!(msg.contains("fail-closed"), "{msg}");
        assert!(!msg.contains("54321"), "no 54321 anywhere: {msg}");

        // Host from env but port missing entirely ⇒ still fail-closed on the port
        // (no 54321 fallback for the port either).
        let err = resolver(None, Some("h"), None).resolve().unwrap_err();
        assert_eq!(err.field(), "port");
    }

    #[test]
    fn resolve_db_and_role_fall_back_to_conventional_defaults() {
        // host/port come from env; db/role unspecified anywhere ⇒ the conventional
        // (non-targeting) defaults, not a fail-closed error (a missing db/role is
        // not a targeting hole the way a missing host/port is).
        let r = resolver(None, Some("h"), Some("6000")).resolve().unwrap();
        assert_eq!(r.database, "postgres");
        assert_eq!(r.role, "pgb_agent");
    }

    #[test]
    fn resolve_rejects_dsn_injection_in_env_overrides() {
        // The §0.5 fail-closed assertion for the ENV-OVERRIDE path (the gap PR #106
        // closes): an operator-set env value carrying a libpq metacharacter
        // (whitespace / `=`) must be REJECTED by the resolver — NOT spliced into the
        // credential-less DSN where `PGB_BACKEND_DB="app sslmode=disable"` would
        // silently downgrade TLS. The resolved host/database/role get the SAME
        // `reject_dsn_injection` guard as the policy.yaml path.
        let base = || TargetResolver {
            policy_target: None,
            host_override: Some("h".into()),
            port_override: Some("6000".into()),
            db_override: None,
            role_override: None,
            default_database: "postgres",
            default_role: "pgb_agent",
            host_env_key: "PGB_BACKEND_HOST",
            port_env_key: "PGB_BACKEND_PORT",
            policy_hint: "policy.yaml `primary:`",
        };

        // database: the canonical TLS-downgrade injection.
        let mut r = base();
        r.db_override = Some("app sslmode=disable".into());
        let err = r.resolve().unwrap_err();
        assert!(
            matches!(
                err,
                TargetResolutionError::Injection {
                    field: "database",
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.field(), "database");
        let msg = err.to_string();
        assert!(msg.contains("inject"), "{msg}");
        assert!(msg.contains("database"), "{msg}");

        // host: a value with an `=` (e.g. a host=... redirect).
        let mut r = base();
        r.host_override = Some("evil=1".into());
        let err = r.resolve().unwrap_err();
        assert!(
            matches!(err, TargetResolutionError::Injection { field: "host", .. }),
            "{err:?}"
        );

        // role: a value with a space.
        let mut r = base();
        r.role_override = Some("pgb_agent options=-csearch_path=evil".into());
        let err = r.resolve().unwrap_err();
        assert!(
            matches!(err, TargetResolutionError::Injection { field: "role", .. }),
            "{err:?}"
        );

        // Legitimate env values still resolve cleanly (behavior-preserving).
        let mut r = base();
        r.db_override = Some("app".into());
        r.role_override = Some("pgb_agent".into());
        r.host_override = Some("db.internal".into());
        let ok = r.resolve().unwrap();
        assert_eq!(ok.host, "db.internal");
        assert_eq!(ok.database, "app");
        assert_eq!(ok.role, "pgb_agent");
        // And the built DSN carries no injected keyword.
        assert_eq!(
            ok.to_credential_less_dsn(),
            "host=db.internal port=6000 dbname=app user=pgb_agent"
        );
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
