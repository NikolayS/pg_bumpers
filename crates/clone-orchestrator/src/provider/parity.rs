//! RLS / column-grant parity between prod and a clone (SPEC §4 "clone governance
//! (blocking): … RLS/column-grant parity with prod").
//!
//! The clone is **prod-classified PII**, so it must enforce the *same* row-level
//! security policies and the *same* per-column privileges as prod — otherwise the
//! clone is a hole in the access model (more visible on the clone than on prod).
//!
//! A physical `pg_basebackup` clone inherits the catalog byte-for-byte, so parity
//! is *inherent* — but "inherent" is not "asserted". This module is the
//! **comparator**: it diffs a captured set of [`RlsPolicy`] + [`ColumnGrant`]
//! rows from prod against the same set captured from the clone and reports any
//! drift ([`ParityReport`]). The capture itself (querying `pg_policies` /
//! `information_schema.column_privileges`) lives in the env-gated integration
//! test against real PG18; this comparator is DB-free and unit-testable, and is
//! what the integration test calls to assert parity holds (and to prove it would
//! catch a divergence).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One row-level-security policy, as captured from `pg_policies`. Equality across
/// prod/clone is the parity condition for RLS.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RlsPolicy {
    /// Schema of the table the policy is on.
    pub schema: String,
    /// Table the policy is on.
    pub table: String,
    /// Policy name.
    pub policy: String,
    /// `permissive` / `restrictive`.
    pub permissive: String,
    /// Roles the policy applies to (sorted, joined) — captured verbatim.
    pub roles: String,
    /// Command the policy covers (`ALL`/`SELECT`/…).
    pub cmd: String,
    /// The `USING` expression text (empty if none).
    pub using_expr: String,
    /// The `WITH CHECK` expression text (empty if none).
    pub check_expr: String,
    /// Whether RLS is *enabled* (forced) on the table — captured alongside the
    /// policy so a clone with policies present but RLS disabled is caught.
    pub rls_enabled: bool,
}

/// One per-column privilege grant, as captured from
/// `information_schema.column_privileges`. Equality across prod/clone is the
/// parity condition for column grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ColumnGrant {
    /// Grantee role.
    pub grantee: String,
    /// Schema of the table.
    pub schema: String,
    /// Table.
    pub table: String,
    /// Column the privilege is on.
    pub column: String,
    /// Privilege type (`SELECT`/`UPDATE`/`INSERT`/`REFERENCES`).
    pub privilege: String,
}

/// The result of a prod↔clone parity check (SPEC §4). `is_parity()` is the gate:
/// a clone may only be used for a rehearsal if it has full parity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParityReport {
    /// RLS policies present on prod but missing on the clone.
    pub rls_missing_on_clone: Vec<RlsPolicy>,
    /// RLS policies present on the clone but not on prod (clone is *looser* or
    /// just divergent — equally a parity failure).
    pub rls_extra_on_clone: Vec<RlsPolicy>,
    /// Column grants present on prod but missing on the clone.
    pub grants_missing_on_clone: Vec<ColumnGrant>,
    /// Column grants present on the clone but not on prod.
    pub grants_extra_on_clone: Vec<ColumnGrant>,
}

impl ParityReport {
    /// Whether prod and clone are in full RLS + column-grant parity (SPEC §4).
    pub fn is_parity(&self) -> bool {
        self.rls_missing_on_clone.is_empty()
            && self.rls_extra_on_clone.is_empty()
            && self.grants_missing_on_clone.is_empty()
            && self.grants_extra_on_clone.is_empty()
    }

    /// A human-readable summary of the drift (empty when in parity).
    pub fn summary(&self) -> String {
        if self.is_parity() {
            return "RLS/column-grant parity: OK (clone matches prod)".to_string();
        }
        format!(
            "RLS/column-grant parity FAILED: rls(-{}/+{}) grants(-{}/+{})",
            self.rls_missing_on_clone.len(),
            self.rls_extra_on_clone.len(),
            self.grants_missing_on_clone.len(),
            self.grants_extra_on_clone.len(),
        )
    }
}

/// Compute the prod↔clone parity report from the two captured snapshots
/// (SPEC §4). Pure set-difference, order-independent — the capture order on
/// either side does not matter.
pub fn check_parity(
    prod_rls: &[RlsPolicy],
    clone_rls: &[RlsPolicy],
    prod_grants: &[ColumnGrant],
    clone_grants: &[ColumnGrant],
) -> ParityReport {
    let prod_rls_set: BTreeSet<&RlsPolicy> = prod_rls.iter().collect();
    let clone_rls_set: BTreeSet<&RlsPolicy> = clone_rls.iter().collect();
    let prod_grant_set: BTreeSet<&ColumnGrant> = prod_grants.iter().collect();
    let clone_grant_set: BTreeSet<&ColumnGrant> = clone_grants.iter().collect();

    ParityReport {
        rls_missing_on_clone: prod_rls_set
            .difference(&clone_rls_set)
            .map(|p| (*p).clone())
            .collect(),
        rls_extra_on_clone: clone_rls_set
            .difference(&prod_rls_set)
            .map(|p| (*p).clone())
            .collect(),
        grants_missing_on_clone: prod_grant_set
            .difference(&clone_grant_set)
            .map(|g| (*g).clone())
            .collect(),
        grants_extra_on_clone: clone_grant_set
            .difference(&prod_grant_set)
            .map(|g| (*g).clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(table: &str, name: &str, using: &str) -> RlsPolicy {
        RlsPolicy {
            schema: "public".into(),
            table: table.into(),
            policy: name.into(),
            permissive: "PERMISSIVE".into(),
            roles: "{pgb_agent}".into(),
            cmd: "ALL".into(),
            using_expr: using.into(),
            check_expr: String::new(),
            rls_enabled: true,
        }
    }

    fn grant(grantee: &str, table: &str, column: &str, priv_: &str) -> ColumnGrant {
        ColumnGrant {
            grantee: grantee.into(),
            schema: "public".into(),
            table: table.into(),
            column: column.into(),
            privilege: priv_.into(),
        }
    }

    #[test]
    fn identical_snapshots_are_parity() {
        let rls = vec![policy(
            "accounts",
            "tenant_isolation",
            "owner = current_user",
        )];
        let grants = vec![grant("pgb_agent", "accounts", "owner", "SELECT")];
        let report = check_parity(&rls, &rls, &grants, &grants);
        assert!(report.is_parity(), "{}", report.summary());
        assert!(report.summary().contains("OK"));
    }

    #[test]
    fn order_does_not_matter() {
        let prod = vec![policy("accounts", "p1", "a"), policy("entries", "p2", "b")];
        let clone = vec![policy("entries", "p2", "b"), policy("accounts", "p1", "a")];
        let report = check_parity(&prod, &clone, &[], &[]);
        assert!(report.is_parity());
    }

    #[test]
    fn missing_rls_policy_on_clone_breaks_parity() {
        let prod = vec![policy(
            "accounts",
            "tenant_isolation",
            "owner = current_user",
        )];
        let clone: Vec<RlsPolicy> = vec![];
        let report = check_parity(&prod, &clone, &[], &[]);
        assert!(!report.is_parity());
        assert_eq!(report.rls_missing_on_clone.len(), 1);
        assert!(report.summary().contains("FAILED"));
    }

    #[test]
    fn rls_disabled_on_clone_is_caught_even_with_same_policy_text() {
        // Same policy NAME/expr, but clone has RLS disabled → rls_enabled differs
        // → the row differs → parity fails. This is the dangerous case: a clone
        // with the policy defined but not enforced.
        let prod = vec![policy(
            "accounts",
            "tenant_isolation",
            "owner = current_user",
        )];
        let mut weakened = prod[0].clone();
        weakened.rls_enabled = false;
        let report = check_parity(&prod, &[weakened], &[], &[]);
        assert!(!report.is_parity());
        assert_eq!(report.rls_missing_on_clone.len(), 1);
        assert_eq!(report.rls_extra_on_clone.len(), 1);
    }

    #[test]
    fn extra_column_grant_on_clone_breaks_parity() {
        // The clone grants a column prod does not → the clone is LOOSER → fail.
        let prod = vec![grant("pgb_agent", "accounts", "owner", "SELECT")];
        let clone = vec![
            grant("pgb_agent", "accounts", "owner", "SELECT"),
            grant("pgb_agent", "accounts", "balance", "SELECT"), // leak!
        ];
        let report = check_parity(&[], &[], &prod, &clone);
        assert!(!report.is_parity());
        assert_eq!(report.grants_extra_on_clone.len(), 1);
        assert_eq!(report.grants_extra_on_clone[0].column, "balance");
    }
}
