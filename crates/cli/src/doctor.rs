//! `pgb-cli doctor` — the **fail-closed BYO preflight** (SPEC §0.5, §3, §4, §12).
//!
//! Given the `policy.yaml` DSN targets (+ secret-store / env credentials), the
//! doctor verifies — before you point an agent at your database — that the
//! deterministic floor is actually in place on the user's existing PostgreSQL:
//!
//!   1. **reachability** — the primary (+ optional replica + the `_meta` audit DB)
//!      accept a connection at the resolved target;
//!   2. **`pgb_agent` WALL-hardened** — NOT superuser, member-of-nothing (no
//!      predefined-role memberships), and no write grant anywhere (mirrors the
//!      `deploy/test/wall_matrix.sh` role-attribute + member-of-nothing rows);
//!   3. **`pgb_applier` DML-only** — NOT superuser, member-of-nothing, and has no
//!      CREATE privilege on the application schema (it may DML rows but never DDL);
//!   4. **pg_hba origin restricted** — the agent role is permitted only from the
//!      proxy host (best-effort via `pg_hba_file_rules` when readable; advisory
//!      otherwise — the catalog view requires elevated privileges);
//!   5. **`_meta` audit chain installed + verifying** — the hash-chained audit log
//!      is present and verifies (reuses the same `crates/audit` verify the daemons
//!      boot against).
//!
//! **Fail-closed:** any failed (or, for the load-bearing checks, indeterminate)
//! result makes the doctor exit non-zero with a structured report; it exits zero
//! ONLY when every load-bearing check passes. The catalog-result → verdict logic
//! is factored into the **pure** functions below so it is unit-tested without a
//! database; the binary (`crates/cli/src/main.rs`) is the thin shell that opens the
//! connections, runs the queries, and feeds the rows in. The env-gated
//! `crates/cli/tests/doctor_it.rs` proves the end-to-end fail-closed behavior
//! against a real hardened vs. un-hardened role.

use std::fmt;

/// The status of a single preflight check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// The check failed — the floor is NOT in place (fail-closed: this aborts).
    Fail,
    /// The check could not be determined (e.g. an unreadable catalog view). For a
    /// **load-bearing** check this is treated as a failure (fail-closed: absence of
    /// signal is least privilege); for an **advisory** check it is reported but does
    /// not by itself abort. Whether a `Warn` aborts is decided by
    /// [`CheckResult::advisory`].
    Warn,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Fail => write!(f, "FAIL"),
            CheckStatus::Warn => write!(f, "WARN"),
        }
    }
}

/// One preflight check's outcome: a stable name, a status, a human detail, and
/// whether the check is **advisory** (a non-`Pass` is reported but does not abort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// A short, stable name (e.g. `agent_not_superuser`).
    pub name: String,
    /// The check's status.
    pub status: CheckStatus,
    /// A human-readable detail line (what was observed / why it failed).
    pub detail: String,
    /// Advisory checks (e.g. the best-effort pg_hba boundary) report a `Warn`
    /// without aborting; load-bearing checks abort on anything but `Pass`.
    pub advisory: bool,
}

impl CheckResult {
    /// A passing load-bearing check.
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
        CheckResult {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
            advisory: false,
        }
    }

    /// A failing load-bearing check.
    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
        CheckResult {
            name: name.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            advisory: false,
        }
    }

    /// An advisory check result (any status; a non-`Pass` does not abort).
    pub fn advisory(
        name: impl Into<String>,
        status: CheckStatus,
        detail: impl Into<String>,
    ) -> CheckResult {
        CheckResult {
            name: name.into(),
            status,
            detail: detail.into(),
            advisory: true,
        }
    }

    /// Whether this result, on its own, makes the doctor fail-closed: a non-`Pass`
    /// status on a NON-advisory check. (An advisory `Warn`/`Fail` is reported but
    /// does not abort.)
    pub fn is_blocking(&self) -> bool {
        !self.advisory && self.status != CheckStatus::Pass
    }
}

/// The full preflight report: the ordered per-check results.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorReport {
    /// Every check, in the order they were run.
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    /// An empty report.
    pub fn new() -> DoctorReport {
        DoctorReport { checks: Vec::new() }
    }

    /// Append a check result.
    pub fn push(&mut self, c: CheckResult) {
        self.checks.push(c);
    }

    /// Whether the overall preflight PASSED: **every load-bearing check passed**
    /// (advisory `Warn`/`Fail` do not flip this). Fail-closed: an empty report does
    /// NOT pass (there was nothing to prove the floor is in place).
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && !self.checks.iter().any(|c| c.is_blocking())
    }

    /// Render the report as a stable, line-per-check block for stdout/stderr.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            let tag = if c.advisory && c.status != CheckStatus::Pass {
                format!("{} (advisory)", c.status)
            } else {
                c.status.to_string()
            };
            out.push_str(&format!("  [{tag:>16}] {}: {}\n", c.name, c.detail));
        }
        let verdict = if self.passed() {
            "doctor: PREFLIGHT PASSED — the deterministic floor is in place; safe to point an \
             agent at this database."
        } else {
            "doctor: PREFLIGHT FAILED (fail-closed) — do NOT point an agent at this database \
             until every check above passes."
        };
        out.push_str(verdict);
        out
    }
}

// ---------------------------------------------------------------------------
// The PURE catalog-result → verdict logic (DB-free, unit-tested). The binary
// runs the queries and passes the observed rows in.
// ---------------------------------------------------------------------------

/// The role-attribute row the doctor reads from `pg_roles` for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAttrs {
    /// `rolsuper` — superuser bit (must be `false` for a WALL/applier role).
    pub is_superuser: bool,
    /// `rolcreatedb`.
    pub can_create_db: bool,
    /// `rolcreaterole`.
    pub can_create_role: bool,
    /// `rolreplication`.
    pub can_replicate: bool,
    /// `rolbypassrls`.
    pub can_bypass_rls: bool,
}

/// Verify a role is **WALL-hardened** from its catalog attributes + its
/// predefined-role membership count + its count of write grants on user tables.
///
/// Fail-closed: ANY of {superuser, member-of-anything, ≥1 write grant,
/// createdb/createrole/replication/bypassrls} fails the check. This mirrors the
/// `deploy/test/wall_matrix.sh` role-attribute + member-of-nothing rows for
/// `pgb_agent` (the read WALL role).
pub fn check_agent_hardening(
    role: &str,
    attrs: Option<RoleAttrs>,
    membership_count: i64,
    write_grant_count: i64,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let Some(a) = attrs else {
        out.push(CheckResult::fail(
            "agent_role_present",
            format!("role `{role}` does NOT exist (apply deploy/sql/10_hardened_role.sql)"),
        ));
        return out;
    };
    out.push(CheckResult::pass(
        "agent_role_present",
        format!("role `{role}` exists"),
    ));
    push_attr_checks(&mut out, role, &a);
    if membership_count == 0 {
        out.push(CheckResult::pass(
            "agent_member_of_nothing",
            format!("`{role}` is a member of no roles (no predefined-role grants)"),
        ));
    } else {
        out.push(CheckResult::fail(
            "agent_member_of_nothing",
            format!(
                "`{role}` is a member of {membership_count} role(s) — the WALL requires \
                 member-of-nothing (strip every pg_* predefined role)"
            ),
        ));
    }
    if write_grant_count == 0 {
        out.push(CheckResult::pass(
            "agent_no_write_grant",
            format!("`{role}` holds NO INSERT/UPDATE/DELETE/TRUNCATE grant on any user table"),
        ));
    } else {
        out.push(CheckResult::fail(
            "agent_no_write_grant",
            format!(
                "`{role}` holds {write_grant_count} write grant(s) on user tables — the read \
                 WALL must have NO write grant anywhere"
            ),
        ));
    }
    out
}

/// Verify the applier role is **DML-only**: NOT superuser, member-of-nothing, and
/// holds NO CREATE privilege on the application schema (it may mutate rows via DML
/// grants but can never DDL). Mirrors the `pgb_applier` (S5 #77) posture.
pub fn check_applier_dml(
    role: &str,
    attrs: Option<RoleAttrs>,
    membership_count: i64,
    has_create_on_schema: bool,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let Some(a) = attrs else {
        out.push(CheckResult::fail(
            "applier_role_present",
            format!("role `{role}` does NOT exist (apply deploy/sql/10_hardened_role.sql)"),
        ));
        return out;
    };
    out.push(CheckResult::pass(
        "applier_role_present",
        format!("role `{role}` exists"),
    ));
    push_attr_checks(&mut out, role, &a);
    if membership_count == 0 {
        out.push(CheckResult::pass(
            "applier_member_of_nothing",
            format!("`{role}` is a member of no roles"),
        ));
    } else {
        out.push(CheckResult::fail(
            "applier_member_of_nothing",
            format!(
                "`{role}` is a member of {membership_count} role(s) — the applier must be \
                     member-of-nothing"
            ),
        ));
    }
    if has_create_on_schema {
        out.push(CheckResult::fail(
            "applier_no_ddl",
            format!(
                "`{role}` has CREATE on the application schema — the applier is DML-only and \
                 must NOT be able to DDL (REVOKE CREATE ON SCHEMA … FROM {role})"
            ),
        ));
    } else {
        out.push(CheckResult::pass(
            "applier_no_ddl",
            format!("`{role}` has NO CREATE on the application schema (cannot DDL)"),
        ));
    }
    out
}

/// The shared role-attribute checks (NOT superuser + the four escalation bits off).
fn push_attr_checks(out: &mut Vec<CheckResult>, role: &str, a: &RoleAttrs) {
    let name = format!("{role}_not_superuser");
    if a.is_superuser {
        out.push(CheckResult::fail(
            name,
            format!("`{role}` is SUPERUSER — the floor requires NOSUPERUSER"),
        ));
    } else {
        out.push(CheckResult::pass(name, format!("`{role}` is NOSUPERUSER")));
    }
    // The escalation bits (createdb / createrole / replication / bypassrls) must
    // all be off; collapse into one check with a precise detail on failure.
    let mut bad = Vec::new();
    if a.can_create_db {
        bad.push("CREATEDB");
    }
    if a.can_create_role {
        bad.push("CREATEROLE");
    }
    if a.can_replicate {
        bad.push("REPLICATION");
    }
    if a.can_bypass_rls {
        bad.push("BYPASSRLS");
    }
    let name = format!("{role}_no_escalation_attrs");
    if bad.is_empty() {
        out.push(CheckResult::pass(
            name,
            format!("`{role}` is NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS"),
        ));
    } else {
        out.push(CheckResult::fail(
            name,
            format!(
                "`{role}` still has: {} (all must be cleared)",
                bad.join(", ")
            ),
        ));
    }
}

/// One `pg_hba_file_rules` row relevant to the agent boundary: the type, the
/// database/user lists, and the address (CIDR / keyword).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbaRule {
    /// `type` — `host` / `local` / `hostssl` / …
    pub conn_type: String,
    /// The roles this rule applies to (the `user_name` array, lower-cased).
    pub user_name: Vec<String>,
    /// The address/CIDR the rule permits (e.g. `10.0.0.5/32`, `0.0.0.0/0`,
    /// `all`, or empty for `local`).
    pub address: String,
}

/// **Advisory** pg_hba boundary check (SPEC §3 layer 0): the agent role must not be
/// reachable from a wide-open origin. This is best-effort — `pg_hba_file_rules`
/// requires elevated privileges, so an empty/unreadable rule set yields a `Warn`
/// (advisory, does not abort), and the operator is pointed at the boundary docs.
///
/// When rules ARE readable, a `host`/`hostssl` rule that names the agent role (or
/// `all`) from a wide-open address (`0.0.0.0/0`, `::/0`, or the `all` keyword) is a
/// `Warn` (the boundary is the deploy-time pg_hba's job; the doctor flags an
/// obviously-open rule but cannot fully validate the deployment's network policy).
pub fn check_hba_boundary(agent_role: &str, rules: Option<&[HbaRule]>) -> CheckResult {
    let Some(rules) = rules else {
        return CheckResult::advisory(
            "hba_origin_restricted",
            CheckStatus::Warn,
            "pg_hba_file_rules is not readable here (needs elevated privileges) — verify the \
             agent role is permitted ONLY from the proxy host out-of-band (deploy/hba/)"
                .to_string(),
        );
    };
    if rules.is_empty() {
        return CheckResult::advisory(
            "hba_origin_restricted",
            CheckStatus::Warn,
            "no readable pg_hba host rules — verify the agent-role boundary out-of-band \
             (deploy/hba/)"
                .to_string(),
        );
    }
    let agent = agent_role.to_ascii_lowercase();
    let wide_open = |addr: &str| {
        let a = addr.trim();
        a == "0.0.0.0/0" || a == "::/0" || a.eq_ignore_ascii_case("all")
    };
    let offending: Vec<&HbaRule> = rules
        .iter()
        .filter(|r| {
            (r.conn_type == "host" || r.conn_type == "hostssl" || r.conn_type == "hostnossl")
                && r.user_name
                    .iter()
                    .any(|u| u == &agent || u.eq_ignore_ascii_case("all"))
                && wide_open(&r.address)
        })
        .collect();
    if offending.is_empty() {
        CheckResult::advisory(
            "hba_origin_restricted",
            CheckStatus::Pass,
            format!(
                "no wide-open pg_hba host rule reaches `{agent_role}` (the proxy-host boundary \
                 is the deploy-time pg_hba's job; this is a best-effort sanity check)"
            ),
        )
    } else {
        CheckResult::advisory(
            "hba_origin_restricted",
            CheckStatus::Warn,
            format!(
                "a wide-open pg_hba host rule appears to reach `{agent_role}` ({} rule(s) from \
                 0.0.0.0/0 · ::/0 · all) — restrict the agent role to the proxy host (deploy/hba/)",
                offending.len()
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardened() -> RoleAttrs {
        RoleAttrs {
            is_superuser: false,
            can_create_db: false,
            can_create_role: false,
            can_replicate: false,
            can_bypass_rls: false,
        }
    }

    #[test]
    fn agent_hardened_passes_when_locked_down() {
        let checks = check_agent_hardening("pgb_agent", Some(hardened()), 0, 0);
        assert!(
            checks.iter().all(|c| c.status == CheckStatus::Pass),
            "{checks:?}"
        );
        // None blocking ⇒ the agent block passes.
        assert!(!checks.iter().any(|c| c.is_blocking()));
    }

    #[test]
    fn agent_superuser_fails_closed() {
        let mut a = hardened();
        a.is_superuser = true;
        let checks = check_agent_hardening("pgb_agent", Some(a), 0, 0);
        let su = checks
            .iter()
            .find(|c| c.name == "pgb_agent_not_superuser")
            .unwrap();
        assert_eq!(su.status, CheckStatus::Fail);
        assert!(su.is_blocking());
    }

    #[test]
    fn agent_member_of_a_predefined_role_fails_closed() {
        let checks = check_agent_hardening("pgb_agent", Some(hardened()), 1, 0);
        let m = checks
            .iter()
            .find(|c| c.name == "agent_member_of_nothing")
            .unwrap();
        assert_eq!(m.status, CheckStatus::Fail);
        assert!(m.is_blocking());
    }

    #[test]
    fn agent_with_a_write_grant_fails_closed() {
        let checks = check_agent_hardening("pgb_agent", Some(hardened()), 0, 3);
        let w = checks
            .iter()
            .find(|c| c.name == "agent_no_write_grant")
            .unwrap();
        assert_eq!(w.status, CheckStatus::Fail);
        assert!(w.is_blocking());
    }

    #[test]
    fn missing_agent_role_fails_closed() {
        let checks = check_agent_hardening("pgb_agent", None, 0, 0);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].is_blocking());
    }

    #[test]
    fn applier_dml_only_passes_when_no_create() {
        let checks = check_applier_dml("pgb_applier", Some(hardened()), 0, false);
        assert!(
            checks.iter().all(|c| c.status == CheckStatus::Pass),
            "{checks:?}"
        );
    }

    #[test]
    fn applier_with_create_on_schema_fails_closed() {
        let checks = check_applier_dml("pgb_applier", Some(hardened()), 0, true);
        let d = checks.iter().find(|c| c.name == "applier_no_ddl").unwrap();
        assert_eq!(d.status, CheckStatus::Fail);
        assert!(d.is_blocking());
    }

    #[test]
    fn applier_superuser_fails_closed() {
        let mut a = hardened();
        a.is_superuser = true;
        let checks = check_applier_dml("pgb_applier", Some(a), 0, false);
        assert!(checks.iter().any(|c| c.is_blocking()));
    }

    #[test]
    fn report_passes_only_when_all_load_bearing_checks_pass() {
        let mut r = DoctorReport::new();
        r.push(CheckResult::pass("a", "ok"));
        r.push(CheckResult::pass("b", "ok"));
        assert!(r.passed());
        // One blocking fail flips it.
        r.push(CheckResult::fail("c", "bad"));
        assert!(!r.passed());
    }

    #[test]
    fn empty_report_does_not_pass_fail_closed() {
        // Fail-closed: nothing proven ⇒ NOT a pass.
        assert!(!DoctorReport::new().passed());
    }

    #[test]
    fn advisory_warn_does_not_flip_the_verdict() {
        let mut r = DoctorReport::new();
        r.push(CheckResult::pass("a", "ok"));
        r.push(CheckResult::advisory(
            "hba",
            CheckStatus::Warn,
            "best-effort",
        ));
        // The advisory Warn is reported but does not abort.
        assert!(r.passed());
        assert!(r.render().contains("WARN (advisory)"));
    }

    #[test]
    fn hba_wide_open_rule_warns_but_does_not_block() {
        let rules = vec![HbaRule {
            conn_type: "host".to_string(),
            user_name: vec!["pgb_agent".to_string()],
            address: "0.0.0.0/0".to_string(),
        }];
        let c = check_hba_boundary("pgb_agent", Some(&rules));
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(!c.is_blocking(), "advisory: does not abort");
    }

    #[test]
    fn hba_restricted_rule_passes_advisory() {
        let rules = vec![HbaRule {
            conn_type: "host".to_string(),
            user_name: vec!["pgb_agent".to_string()],
            address: "10.0.0.5/32".to_string(),
        }];
        let c = check_hba_boundary("pgb_agent", Some(&rules));
        assert_eq!(c.status, CheckStatus::Pass);
    }

    #[test]
    fn hba_unreadable_warns_advisory() {
        let c = check_hba_boundary("pgb_agent", None);
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(!c.is_blocking());
    }
}
