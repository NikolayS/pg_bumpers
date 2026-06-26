//! Proxy runtime configuration (SPEC §3 layer 2, §7 S1).
//!
//! Two sources, kept separate on purpose:
//! - the **per-role budgets** come from `policy.yaml` ([`pgb_policy::PolicyConfig`]),
//!   the single source of truth for byte/row caps;
//! - the **deployment wiring** (listen address, TLS material, the backend DSN,
//!   the agent credential the proxy authenticates, the injected
//!   `statement_timeout`) comes from this struct, which a binary builds from
//!   env/flags.
//!
//! The proxy is the *only* network path to the DB (SPEC §3 layer 0), so the
//! backend DSN here points at PG18 as the hardened WALL role `pgb_agent`.

use std::net::SocketAddr;
use std::path::PathBuf;

use pgb_policy::RoleBudget;

/// The backend connection target: where the proxy originates the PG18 session as
/// the hardened WALL role.
#[derive(Debug, Clone)]
pub struct BackendTarget {
    /// Backend host — the BYO primary (SPEC §0.5). Resolved env override >
    /// `policy.yaml` `primary:` target > fail-closed; no throwaway-cluster default.
    pub host: String,
    /// Backend port — the BYO primary port. **Never** 5432 unless that is the
    /// user's own database; there is no hardcoded `54321` default.
    pub port: u16,
    /// Database name to connect to.
    pub database: String,
    /// The WALL role the proxy connects as (`pgb_agent`).
    pub role: String,
    /// The WALL role's password (dev: `pgb_agent_dev_pw`; prod: secret store).
    pub password: String,
}

/// TLS material for the agent-facing listener (PEM-encoded files).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the server certificate chain (PEM).
    pub cert_pem: PathBuf,
    /// Path to the server private key (PEM, PKCS#8 or PKCS#1).
    pub key_pem: PathBuf,
}

/// The full proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// The agent-facing listen address.
    pub listen: SocketAddr,
    /// Optional TLS on the listener. `None` ⇒ plaintext (dev/test only, and only
    /// when [`ProxyConfig::require_tls`] is `false`).
    pub tls: Option<TlsConfig>,
    /// Whether the agent endpoint **requires** TLS. Defaults to `true` whenever
    /// TLS material is configured (see [`ProxyConfig::resolve_require_tls`]).
    ///
    /// When `true` the proxy never serves an agent in cleartext: a client
    /// `SSLRequest` is answered `'S'` and upgraded; a client that opens with a
    /// direct `StartupMessage` (no `SSLRequest`) is **rejected**; and the session
    /// refuses to proceed to auth/queries unless the stream is actually
    /// encrypted. There is **no silent cleartext downgrade**.
    ///
    /// When `false` *and* [`ProxyConfig::tls`] is `None`, the proxy runs in an
    /// explicit, documented **dev-only no-TLS mode** (plaintext). Requiring TLS
    /// with no TLS material configured is a hard error (fail-closed) — see
    /// [`ProxyConfig::validate_tls`].
    pub require_tls: bool,
    /// The backend PG18 target (the WALL role connection).
    pub backend: BackendTarget,
    /// The username an agent must present to the proxy (terminate side). The
    /// proxy authenticates this via SCRAM-SHA-256.
    pub agent_user: String,
    /// The password the proxy expects for `agent_user` (used to verify the
    /// agent's SCRAM proof and as the SCRAM verifier secret). Dev material;
    /// production resolves this from the secret store.
    pub agent_password: String,
    /// The role this connection's budgets are looked up under in `policy.yaml`.
    pub policy_role: String,
    /// The single-shot byte/row budget for `policy_role` (resolved from
    /// `policy.yaml`).
    pub budget: RoleBudget,
    /// The `statement_timeout` (milliseconds) injected on every backend session.
    /// `0` disables the injection (not recommended).
    pub statement_timeout_ms: u64,
    /// The `search_path` pinned on **every** brokered backend session (SPEC §3
    /// layer-1 WALL: "search_path pinned"). The proxy is the *authoritative*
    /// per-session pin: because each agent connection originates a **fresh**
    /// backend session and the proxy `SET search_path = <this>` before any agent
    /// statement runs, an agent that ran `SET search_path = 'evil'` (or
    /// `ALTER ROLE self …` / `RESET ALL`) can never carry a chosen path into a new
    /// brokered session — the proxy re-pins it every time.
    ///
    /// Defense-in-depth only: the WALL's read guarantee is grant-based and
    /// `search_path`-invariant (proven by `deploy/test/wall_matrix.sh` §I), so this
    /// pin can never *widen* access; it makes the proxy match the SPEC/WALL docs and
    /// gives a deterministic, minimal path. Defaults to
    /// [`ProxyConfig::DEFAULT_SEARCH_PATH`] (matching `deploy/sql/10_hardened_role.sql`);
    /// an empty value disables the injection (not recommended).
    pub search_path: String,
}

impl ProxyConfig {
    /// The default pinned `search_path`: the minimal fixed path the WALL role
    /// intends — `pg_catalog` first (built-ins resolve as expected) then the one
    /// whitelisted application schema `public`. This MUST match the value
    /// `deploy/sql/10_hardened_role.sql` pins at the role level
    /// (`ALTER ROLE pgb_agent SET search_path = pg_catalog, "public"`), so the
    /// proxy pin and the role pin agree. Deliberately **not** wide-open and with
    /// **no** `"$user"` element (no per-user schema shadowing).
    pub const DEFAULT_SEARCH_PATH: &'static str = "pg_catalog, \"public\"";

    /// Resolve a `policy_role`'s single-shot budget from a loaded policy.
    pub fn budget_for(
        policy: &pgb_policy::PolicyConfig,
        role: &str,
    ) -> Result<RoleBudget, ConfigError> {
        policy
            .roles
            .get(role)
            .map(|r| r.budget.clone())
            .ok_or_else(|| ConfigError::UnknownRole(role.to_string()))
    }

    /// The default `require_tls` for a deployment: **TLS is required whenever TLS
    /// material is configured** (no silent cleartext downgrade), unless an
    /// explicit opt-out is given.
    ///
    /// `tls_present` is whether cert+key were configured; `explicit_override` is
    /// an operator-supplied value (e.g. from `PGB_PROXY_REQUIRE_TLS`). The
    /// override wins when present; otherwise the secure default is `tls_present`.
    pub fn resolve_require_tls(tls_present: bool, explicit_override: Option<bool>) -> bool {
        explicit_override.unwrap_or(tls_present)
    }

    /// Fail-closed validation of the TLS posture: requiring TLS with no TLS
    /// material configured is a hard configuration error (the proxy must never
    /// be told to require encryption it cannot provide).
    pub fn validate_tls(&self) -> Result<(), ConfigError> {
        if self.require_tls && self.tls.is_none() {
            return Err(ConfigError::TlsRequiredButUnconfigured);
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The requested policy role is not present in `policy.yaml`.
    #[error("role `{0}` is not defined in policy.yaml")]
    UnknownRole(String),
    /// `require_tls` is set but no TLS material is configured — fail-closed: the
    /// proxy refuses to start rather than serve plaintext while claiming TLS.
    #[error(
        "require_tls is enabled but no TLS cert/key is configured; \
         set PGB_PROXY_TLS_CERT + PGB_PROXY_TLS_KEY, or explicitly opt out of TLS \
         (dev only) with PGB_PROXY_REQUIRE_TLS=false"
    )]
    TlsRequiredButUnconfigured,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_lookup_resolves_and_fails_closed() {
        let policy = pgb_policy::PolicyConfig::load_from_yaml(include_str!(
            "../../policy/policy.example.yaml"
        ))
        .unwrap();
        let b = ProxyConfig::budget_for(&policy, "analytics").unwrap();
        assert!(b.max_bytes > 0 && b.max_rows > 0);
        // An undefined role is a hard error (fail-closed), never a default.
        assert!(matches!(
            ProxyConfig::budget_for(&policy, "does_not_exist"),
            Err(ConfigError::UnknownRole(_))
        ));
    }

    #[test]
    fn require_tls_defaults_on_when_tls_configured() {
        // The secure default: with TLS material present and no explicit override,
        // TLS is REQUIRED (no silent cleartext downgrade).
        assert!(ProxyConfig::resolve_require_tls(true, None));
        // With no TLS material and no override, TLS is not required (dev no-TLS).
        assert!(!ProxyConfig::resolve_require_tls(false, None));
        // An explicit override always wins (e.g. dev opt-out / prod opt-in).
        assert!(!ProxyConfig::resolve_require_tls(true, Some(false)));
        assert!(ProxyConfig::resolve_require_tls(false, Some(true)));
    }

    fn cfg_with(tls: Option<TlsConfig>, require_tls: bool) -> ProxyConfig {
        use pgb_policy::WindowBudget;
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls,
            require_tls,
            backend: BackendTarget {
                host: "127.0.0.1".into(),
                port: 54321,
                database: "postgres".into(),
                role: "pgb_agent".into(),
                password: "x".into(),
            },
            agent_user: "pgb_agent".into(),
            agent_password: "x".into(),
            policy_role: "analytics".into(),
            budget: RoleBudget {
                max_bytes: 1000,
                max_rows: 10,
                max_plan_cost: RoleBudget::DEFAULT_MAX_PLAN_COST,
                max_plan_rows: RoleBudget::DEFAULT_MAX_PLAN_ROWS,
                per_window: WindowBudget {
                    window_secs: 60,
                    max_bytes: 100000,
                    max_rows: 1000,
                },
            },
            statement_timeout_ms: 30000,
            search_path: ProxyConfig::DEFAULT_SEARCH_PATH.to_string(),
        }
    }

    #[test]
    fn validate_tls_rejects_require_without_material() {
        // Fail-closed: require TLS but no cert/key ⇒ hard error, never plaintext.
        let cfg = cfg_with(None, true);
        assert!(matches!(
            cfg.validate_tls(),
            Err(ConfigError::TlsRequiredButUnconfigured)
        ));
        // Not requiring TLS with no material is the explicit dev no-TLS mode: ok.
        let cfg = cfg_with(None, false);
        assert!(cfg.validate_tls().is_ok());
    }
}
