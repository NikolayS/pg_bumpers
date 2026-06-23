//! Shared test-support for pg_bumpers' env-gated PG18 integration tests
//! (issue #44).
//!
//! The integration tests live in **separate test binaries across several crates**
//! (`dbsafe-bench` gate_it, `clone-orchestrator` cluster, `warden_it`, `mcp`
//! write_path_e2e). Each needs the SAME rule for finding the PG18 client/server
//! binaries (`initdb`, `pg_ctl`, `psql`, …). Before this crate that rule was
//! copy-pasted four times and had **drifted**: only one copy treated a
//! *set-but-empty* `PG_BUMPERS_PG18_BIN` as fall-through; the others did
//! `env::var(NEW).or_else(|_| env::var(LEGACY))`, which only falls through when
//! `NEW` is **unset** — so with `PG_BUMPERS_PG18_BIN=""` they selected `""` and
//! broke cluster bootstrap (a fail-OPEN footgun: an empty bin dir silently
//! resolves tools to `/initdb` etc.).
//!
//! [`resolve_pg18_bin`] is now the ONE implementation. Every IT resolver calls
//! it, and the precedence is unit-tested against the **exact** function the
//! callers use (see the `tests` module) — including the empty-string
//! fall-through that the old per-resolver `or_else` form got wrong.

use std::path::PathBuf;

/// The Homebrew keg path — the macOS dev fallback shared by every IT resolver.
pub const HOMEBREW_PG18_BIN: &str = "/opt/homebrew/opt/postgresql@18/bin";

/// Resolve the PG18 bin dir for an integration test, unified across every IT
/// (issue #44). Precedence, matching the shell `${VAR:-…}` semantics
/// (a *set-but-empty* var falls through, it does NOT win):
///
/// 1. `PG_BUMPERS_PG18_BIN` — the ONE cross-IT/CI variable (set on the runner),
///    when **non-empty**.
/// 2. `legacy_var` — the calling crate's legacy var (back-compat for local dev),
///    when **non-empty**. This differs per crate, so it is passed in:
///    `PG_BUMPERS_PGBIN` (gate_it / cluster / warden_it) or `PG_BUMPERS_PG_BINDIR`
///    (mcp write_path_e2e).
/// 3. [`HOMEBREW_PG18_BIN`] — the macOS dev fallback.
///
/// This is the public entry point the four IT resolvers call; it reads the
/// process env and delegates the ordering to [`resolve_pg18_bin_from`] so the
/// precedence is unit-testable without mutating process-global env.
pub fn resolve_pg18_bin(legacy_var: &str) -> PathBuf {
    PathBuf::from(resolve_pg18_bin_from(
        std::env::var("PG_BUMPERS_PG18_BIN").ok().as_deref(),
        std::env::var(legacy_var).ok().as_deref(),
    ))
}

/// Pure precedence for [`resolve_pg18_bin`], factored out so the ordering — and
/// the *set-but-empty* fall-through in particular — is unit-tested without
/// touching process-global env. `pg18` is `PG_BUMPERS_PG18_BIN`, `legacy` is the
/// caller's legacy var; `None` = unset, `Some("")` = set-but-empty (must fall
/// through, never win).
fn resolve_pg18_bin_from(pg18: Option<&str>, legacy: Option<&str>) -> String {
    pg18.filter(|s| !s.is_empty())
        .or(legacy.filter(|s| !s.is_empty()))
        .unwrap_or(HOMEBREW_PG18_BIN)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DB-FREE unit test (issue #44): the unified PG18 bin-dir precedence —
    /// `PG_BUMPERS_PG18_BIN` (the ONE cross-IT/CI var) wins over the legacy var,
    /// which wins over the Homebrew fallback; **empty strings are ignored**
    /// (the bug FIX 1 closes: the old `or_else` form let `PG_BUMPERS_PG18_BIN=""`
    /// shadow the legacy var and break bootstrap). Runs in the fast (DB-free)
    /// job, so a regression in the resolver ordering is caught even without a
    /// live PG18, and it exercises the EXACT precedence logic all four callers
    /// reach through [`resolve_pg18_bin`].
    #[test]
    fn pg18_bin_precedence_is_unified() {
        // 1. The cross-IT/CI var wins over the legacy var.
        assert_eq!(
            resolve_pg18_bin_from(Some("/ci/pg18"), Some("/legacy")),
            "/ci/pg18",
            "PG_BUMPERS_PG18_BIN must take precedence over the legacy var"
        );
        // 2. The legacy var is honored when the cross-IT/CI var is absent (local dev).
        assert_eq!(
            resolve_pg18_bin_from(None, Some("/legacy")),
            "/legacy",
            "the legacy var is the local-dev back-compat fallback"
        );
        // 3. The Homebrew keg path is the final fallback when neither is set.
        assert_eq!(
            resolve_pg18_bin_from(None, None),
            HOMEBREW_PG18_BIN,
            "the Homebrew keg path is the macOS dev fallback"
        );
        // 4. An empty cross-IT/CI var falls through to the legacy var (not "").
        //    This is the case the old per-resolver `or_else` form got WRONG.
        assert_eq!(
            resolve_pg18_bin_from(Some(""), Some("/legacy")),
            "/legacy",
            "an empty PG_BUMPERS_PG18_BIN must not shadow the legacy var"
        );
        // 5. An empty legacy var also falls through (to Homebrew here).
        assert_eq!(
            resolve_pg18_bin_from(Some(""), Some("")),
            HOMEBREW_PG18_BIN,
            "an empty legacy var must not be selected either"
        );
        // 6. A set legacy var with an UNSET cross-IT/CI var is honored even if
        //    the cross-IT/CI var would have been empty — covers None vs Some("").
        assert_eq!(
            resolve_pg18_bin_from(None, Some("")),
            HOMEBREW_PG18_BIN,
            "empty legacy + unset cross-IT/CI var → Homebrew, never an empty bin dir"
        );
    }
}
