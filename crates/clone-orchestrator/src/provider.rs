//! The clone-provider abstraction + governance (SPEC §4, §10.7, §12).
//!
//! The dry-run engine ([`crate::dry_run`]) rehearses a proposed write against a
//! [`crate::Rehearsal`] backend. *Where* that rehearsal runs is the clone
//! provider's concern, and it is the moat: the baseline runs the rehearsal in a
//! rolled-back txn **on the primary** (holding its locks for the duration, SPEC
//! §12); the `local` provider runs it on an **isolated `pg_basebackup` clone**
//! (a separate PG18 cluster on a dedicated port) so the rehearsal has **zero
//! write/lock impact on the primary** — the preview the product sells (§12,
//! "clone rehearsal — the moat").
//!
//! # The seam
//!
//! - [`CloneProvider::provision`] → a [`CloneHandle`]: a libpq DSN to rehearse
//!   against, the clone's LSN + staleness vs prod, and the **governance facts**
//!   the clone is required to carry (SPEC §4: prod-classified, encryption-at-rest,
//!   access-logged, documented owner/location).
//! - [`CloneProvider::destroy`] → **mandatory teardown** (SPEC §4): every clone is
//!   destroyed after the dry-run, success **or** failure. The success/failure
//!   paths funnel through [`with_clone`], which always tears down.
//!
//! # Governance (SPEC §4 "clone governance (blocking)")
//!
//! A clone is **prod-classified PII**. The non-negotiables, each represented in
//! [`CloneHandle::governance`]:
//!
//! - **Mandatory teardown** — [`with_clone`] tears down on both arms; a
//!   [`CloneLedger`] entry is removed only once the cluster is gone.
//! - **Orphan-reaper + alarm** (SPEC §10.7) — a clone must NOT survive a killed
//!   orchestrator. Every provisioned clone is recorded in an **out-of-process
//!   ledger** ([`CloneLedger`]) that survives the orchestrator's death; a
//!   [`reap_orphans`] pass destroys any clone whose entry is still present (its
//!   owner died without tearing down) and raises an [`OrphanAlarm`]. The
//!   integration test kills an orchestrator mid-rehearsal and asserts the reaper
//!   leaves no cluster/process/dir.
//! - **RLS/column-grant parity** — the clone must enforce the same RLS policies
//!   and column grants as prod ([`parity::ParityReport`]); a physical
//!   `pg_basebackup` clone inherits them byte-for-byte, and the parity check
//!   proves it (and would catch divergence).
//! - **Encryption-at-rest / access-logging / documented owner+location** — carried
//!   on [`CloneGovernance`] and asserted present before a handle is handed out.

use std::fmt;

use crate::dry_run::Rehearsal;

pub mod ledger;
pub mod local;
pub mod parity;

pub use ledger::{
    CloneLedger, LedgerEntry, OWNER_MARKER, OrphanAlarm, OwnerIdentity, ReapOutcome, reap_orphans,
    reap_orphans_with_sweep, write_owner_marker,
};
pub use local::{LocalCloneConfig, LocalCloneProvider, PrimaryRef};
pub use parity::{ColumnGrant, ParityReport, RlsPolicy, check_parity};

/// Which clone provider backs the rehearsal (SPEC §12.2 `clone.provider`, plus
/// the founder-approved `local` pivot used for the MVP moat demo).
///
/// This mirrors [`pgb_policy::CloneProvider`] (`none` | `dblab`) and adds
/// [`ProviderKind::Local`], the `pg_basebackup` isolated-clone provider that
/// stands in for DBLab where DBLab/Docker is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// `none` — the in-txn baseline on the primary (SPEC §12). The "clone" is the
    /// primary itself, rehearsing in a rolled-back txn; staleness is 0 and there
    /// is no isolated cluster to tear down.
    None,
    /// `local` — an isolated `pg_basebackup` clone cluster on a dedicated port
    /// (the moat: zero prod write/lock impact).
    Local,
    /// `dblab` — Database Lab Engine clones. Runtime-detected; a stub here (not
    /// required to work in this environment).
    Dblab,
}

impl ProviderKind {
    /// Whether this provider isolates the rehearsal from the primary (so a
    /// rehearsal has zero prod write/lock impact). Only `none` runs on the
    /// primary itself.
    pub const fn is_isolated(self) -> bool {
        matches!(self, ProviderKind::Local | ProviderKind::Dblab)
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProviderKind::None => "none",
            ProviderKind::Local => "local",
            ProviderKind::Dblab => "dblab",
        };
        f.write_str(s)
    }
}

impl From<pgb_policy::CloneProvider> for ProviderKind {
    fn from(p: pgb_policy::CloneProvider) -> Self {
        match p {
            pgb_policy::CloneProvider::None => ProviderKind::None,
            pgb_policy::CloneProvider::Dblab => ProviderKind::Dblab,
        }
    }
}

/// The governance facts a clone is **required** to carry before a rehearsal may
/// run against it (SPEC §4 "clone governance (blocking)"): a clone is
/// prod-classified PII, so it must be encrypted at rest, access-logged, and have
/// a documented owner + location. [`CloneGovernance::assert_compliant`] is
/// fail-closed: a handle missing any of these is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneGovernance {
    /// Whether the clone's storage is encrypted at rest (SPEC §4). For the local
    /// `pg_basebackup` provider this reflects the documented on-disk posture of
    /// the git-ignored clone dir (see [`local::LocalCloneProvider`] docs).
    ///
    /// **MVP scope (documentary flag):** for the local pivot this is `chmod 0700`
    /// on the clone dir **plus** the documented deployment posture (production
    /// mounts the clone root on an encrypted volume); it is **not** full-disk
    /// encryption enforced in-process, so `assert_compliant` cannot itself detect
    /// an unencrypted volume. This is intentional and disclosed; real FDE is a
    /// deploy-time control. The honest leaked-PII control here is the
    /// reaper/sweep (SPEC §10.7), not this flag.
    pub encryption_at_rest: bool,
    /// Where the clone's access is logged (a path / sink id). Empty ⇒ not
    /// access-logged ⇒ non-compliant.
    pub access_log: String,
    /// The documented human/team owner of the clone (SPEC §4 "documented owner").
    pub owner: String,
    /// The documented location of the clone (datadir / host:port). Empty ⇒
    /// non-compliant.
    pub location: String,
    /// The data classification. A clone of prod is always prod-classified PII.
    pub classification: DataClassification,
}

/// The data classification of a clone. A clone of prod inherits prod's
/// classification (SPEC §4 "clone = prod-classified").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    /// Production data (PII). The only classification a real clone may carry.
    ProdPii,
    /// Synthetic / non-prod data (used only by DB-free unit fixtures).
    Synthetic,
}

impl CloneGovernance {
    /// Why a governance record is non-compliant, if it is (SPEC §4, fail-closed).
    pub fn noncompliance(&self) -> Option<String> {
        if !self.encryption_at_rest {
            return Some("clone is not encrypted at rest (SPEC §4)".into());
        }
        if self.access_log.trim().is_empty() {
            return Some("clone is not access-logged (SPEC §4)".into());
        }
        if self.owner.trim().is_empty() {
            return Some("clone has no documented owner (SPEC §4)".into());
        }
        if self.location.trim().is_empty() {
            return Some("clone has no documented location (SPEC §4)".into());
        }
        if self.classification != DataClassification::ProdPii {
            return Some(
                "a clone of prod must be prod-PII-classified (SPEC §4 clone = prod-classified)"
                    .into(),
            );
        }
        None
    }

    /// Fail-closed compliance gate: `Ok(())` only when every blocking governance
    /// requirement is met (SPEC §4).
    pub fn assert_compliant(&self) -> Result<(), CloneError> {
        match self.noncompliance() {
            Some(reason) => Err(CloneError::Governance(reason)),
            None => Ok(()),
        }
    }
}

/// A provisioned clone: a DSN to rehearse against, its LSN + staleness vs prod,
/// and the governance facts it carries (SPEC §4, §10.7, §12).
#[derive(Debug, Clone)]
pub struct CloneHandle {
    /// Which provider produced this handle.
    pub provider: ProviderKind,
    /// A stable id for the clone (used as the ledger key + in alarms/logs).
    pub clone_id: String,
    /// The libpq connection string the rehearsal runs against. For `none` this is
    /// the primary's DSN (rehearsal is in-txn there); for `local` it is the
    /// isolated clone cluster's DSN on its dedicated port.
    pub conn: String,
    /// The clone's WAL LSN at provision time (the consistent point it was taken).
    pub lsn: String,
    /// How far behind prod the clone is, in WAL bytes, at provision time. 0 for
    /// the in-txn `none` baseline (it *is* prod).
    pub staleness_lsn_bytes: u64,
    /// The governance facts (SPEC §4) — asserted compliant before use.
    pub governance: CloneGovernance,
}

/// Errors from a clone provider (provision / destroy / governance).
#[derive(Debug, thiserror::Error)]
pub enum CloneError {
    /// A required external tool (`pg_basebackup` / `pg_ctl` / `initdb`) was
    /// missing or failed. Carries the captured stderr/context.
    #[error("clone tooling failed: {0}")]
    Tooling(String),

    /// Provisioning failed (base-backup, cluster start, seed, …).
    #[error("clone provisioning failed: {0}")]
    Provision(String),

    /// Teardown failed — the clone may have leaked; the reaper is the backstop.
    #[error("clone teardown failed: {0}")]
    Teardown(String),

    /// A blocking governance requirement is unmet (SPEC §4) — fail-closed.
    #[error("clone governance violation: {0}")]
    Governance(String),

    /// The provider is recognized but not available in this environment (e.g.
    /// `dblab` with no DBLab reachable). Fail-closed; the caller falls back per
    /// SPEC §12.2 ("never silently downgrade").
    #[error("clone provider `{0}` is unavailable in this environment")]
    Unavailable(ProviderKind),
}

/// The clone-provider seam (SPEC §12). An implementor provisions an isolated
/// rehearsal target and tears it down on demand.
///
/// Implementations:
/// - [`local::LocalCloneProvider`] — `pg_basebackup` isolated clone (the moat).
/// - [`NoneProvider`] — the in-txn baseline (the "clone" is the primary itself).
/// - [`DblabProvider`] — runtime-detected DBLab stub (not required here).
///
/// **Governance contract:** [`provision`](CloneProvider::provision) MUST return a
/// handle whose [`CloneHandle::governance`] is compliant
/// ([`CloneGovernance::assert_compliant`]) and MUST record the clone in the
/// provider's [`CloneLedger`] *before any prod PII exists on disk* — i.e. before
/// creating the datadir / running `pg_basebackup`, not merely before handing the
/// handle out — so a crash anywhere from datadir creation through teardown
/// (including mid-`pg_basebackup`) leaves a reapable orphan record (SPEC §10.7,
/// fail-closed ordering). The ledger-independent
/// [`reap_orphans_with_sweep`](ledger::reap_orphans_with_sweep) is the backstop if
/// the ledger itself is lost/relocated.
/// [`destroy`](CloneProvider::destroy) MUST be idempotent and remove the ledger
/// entry only once the clone is physically gone.
pub trait CloneProvider {
    /// Provision an isolated rehearsal target from the configured primary.
    fn provision(&mut self) -> Result<CloneHandle, CloneError>;

    /// Tear down a previously-provisioned clone (mandatory teardown, SPEC §4).
    /// Idempotent: destroying an already-gone clone is `Ok`.
    fn destroy(&mut self, handle: &CloneHandle) -> Result<(), CloneError>;
}

/// Run `body` against a freshly-provisioned clone, **always tearing it down**
/// afterward — the mandatory-teardown guarantee (SPEC §4), on both the success
/// and the failure arm.
///
/// This is the funnel the dry-run wiring uses: provision → assert governance →
/// run the rehearsal closure → **teardown regardless of outcome**. If teardown
/// itself fails the body's result is still returned, but the teardown error is
/// surfaced via `on_teardown_err` (the orphan-alarm hook) so the reaper/alarm
/// path (SPEC §10.7) is triggered rather than the failure being swallowed.
pub fn with_clone<P, T, F>(
    provider: &mut P,
    body: F,
    on_teardown_err: impl FnOnce(&CloneError),
) -> Result<T, CloneError>
where
    P: CloneProvider,
    F: FnOnce(&CloneHandle) -> Result<T, CloneError>,
{
    let handle = provider.provision()?;
    // Fail-closed governance gate before any rehearsal touches the clone.
    if let Err(e) = handle.governance.assert_compliant() {
        // Still tear down the non-compliant clone we just made.
        let _ = provider.destroy(&handle);
        return Err(e);
    }
    let result = body(&handle);
    // MANDATORY TEARDOWN — runs on both arms.
    if let Err(te) = provider.destroy(&handle) {
        on_teardown_err(&te);
    }
    result
}

/// The baseline `none` provider (SPEC §12): the rehearsal runs in a rolled-back
/// txn on the primary itself, so there is no isolated cluster to create or tear
/// down. `provision` just wraps the primary DSN as the "clone" (staleness 0);
/// `destroy` is a no-op. Governance still applies (the primary *is* prod-PII).
///
/// This delegates to the engine's existing rolled-back-txn path: the caller
/// hands the returned [`CloneHandle::conn`] to a [`Rehearsal`] (e.g. the in-txn
/// `PgRehearsal`) exactly as before. The provider exists so the `none` path is a
/// first-class [`CloneProvider`] alongside `local`/`dblab`.
pub struct NoneProvider {
    primary_dsn: String,
    owner: String,
    access_log: String,
}

impl NoneProvider {
    /// A `none` provider over `primary_dsn`. `owner` / `access_log` document the
    /// primary (which the baseline rehearses against in-txn).
    pub fn new(
        primary_dsn: impl Into<String>,
        owner: impl Into<String>,
        access_log: impl Into<String>,
    ) -> Self {
        NoneProvider {
            primary_dsn: primary_dsn.into(),
            owner: owner.into(),
            access_log: access_log.into(),
        }
    }
}

impl CloneProvider for NoneProvider {
    fn provision(&mut self) -> Result<CloneHandle, CloneError> {
        Ok(CloneHandle {
            provider: ProviderKind::None,
            clone_id: "primary-intxn".to_string(),
            conn: self.primary_dsn.clone(),
            // The in-txn baseline runs on prod itself; LSN is read lazily by the
            // rehearsal and staleness is 0 by definition.
            lsn: "0/0".to_string(),
            staleness_lsn_bytes: 0,
            governance: CloneGovernance {
                // The primary is the production DB; its at-rest posture is the
                // deployment's, documented as the prod posture.
                encryption_at_rest: true,
                access_log: self.access_log.clone(),
                owner: self.owner.clone(),
                location: self.primary_dsn.clone(),
                classification: DataClassification::ProdPii,
            },
        })
    }

    fn destroy(&mut self, _handle: &CloneHandle) -> Result<(), CloneError> {
        // Nothing to tear down — the baseline never created a cluster. The
        // rolled-back txn already discarded all rehearsal state.
        Ok(())
    }
}

/// Runtime-detected DBLab provider stub (SPEC §12.2). DBLab is unavailable in
/// this build environment (founder-approved local-PG18 pivot), so this provider
/// reports [`CloneError::Unavailable`] from `provision` unless a detection hook
/// declares DBLab reachable. It exists so `clone.provider: dblab` resolves to a
/// real, fail-closed [`CloneProvider`] rather than a panic, and so the wiring is
/// ready when a DBLab endpoint is present.
pub struct DblabProvider {
    detected: bool,
}

impl DblabProvider {
    /// A DBLab provider that auto-detects availability from the environment
    /// (`DBLAB_API_URL` present and non-empty ⇒ detected). No network call is
    /// made here; actual DBLab wiring is out of scope for the local pivot.
    pub fn detect_from_env() -> Self {
        let detected = std::env::var("DBLAB_API_URL")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        DblabProvider { detected }
    }

    /// Construct with an explicit detection result (for tests).
    pub fn with_detected(detected: bool) -> Self {
        DblabProvider { detected }
    }
}

impl CloneProvider for DblabProvider {
    fn provision(&mut self) -> Result<CloneHandle, CloneError> {
        if !self.detected {
            return Err(CloneError::Unavailable(ProviderKind::Dblab));
        }
        // A real implementation would POST /clone to the DBLab API here. Not
        // wired in the local pivot; reaching this with detection on is a
        // configuration we do not support yet, so fail closed.
        Err(CloneError::Unavailable(ProviderKind::Dblab))
    }

    fn destroy(&mut self, _handle: &CloneHandle) -> Result<(), CloneError> {
        Ok(())
    }
}

/// Bind a [`CloneHandle`] to a concrete [`Rehearsal`] backend. The dry-run engine
/// is provider-agnostic — it only sees a [`Rehearsal`] — so a provider's handle
/// is turned into a rehearsal by a factory the caller supplies (the real PG
/// backend lives in the env-gated integration tests; production grows a tokio
/// backend). This trait keeps that binding explicit at the seam.
pub trait RehearsalFor {
    /// The rehearsal backend type produced for a handle.
    type Backend<'h>: Rehearsal
    where
        Self: 'h;

    /// Build a rehearsal backend that runs against `handle.conn`.
    fn rehearsal_for<'h>(&'h mut self, handle: &'h CloneHandle) -> Self::Backend<'h>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_governance() -> CloneGovernance {
        CloneGovernance {
            encryption_at_rest: true,
            access_log: "audit:_meta.clone_access".into(),
            owner: "data-platform@pg-bumpers".into(),
            location: "host=127.0.0.1 port=54361".into(),
            classification: DataClassification::ProdPii,
        }
    }

    #[test]
    fn provider_kind_maps_from_policy_and_isolation_is_correct() {
        assert_eq!(
            ProviderKind::from(pgb_policy::CloneProvider::None),
            ProviderKind::None
        );
        assert_eq!(
            ProviderKind::from(pgb_policy::CloneProvider::Dblab),
            ProviderKind::Dblab
        );
        assert!(!ProviderKind::None.is_isolated());
        assert!(ProviderKind::Local.is_isolated());
        assert!(ProviderKind::Dblab.is_isolated());
        assert_eq!(ProviderKind::Local.to_string(), "local");
    }

    #[test]
    fn governance_is_fail_closed() {
        good_governance().assert_compliant().expect("good is ok");

        let mut g = good_governance();
        g.encryption_at_rest = false;
        assert!(matches!(
            g.assert_compliant(),
            Err(CloneError::Governance(_))
        ));
        assert!(g.noncompliance().unwrap().contains("encrypted at rest"));

        let mut g = good_governance();
        g.access_log = "  ".into();
        assert!(g.noncompliance().unwrap().contains("access-logged"));

        let mut g = good_governance();
        g.owner = String::new();
        assert!(g.noncompliance().unwrap().contains("owner"));

        let mut g = good_governance();
        g.location = String::new();
        assert!(g.noncompliance().unwrap().contains("location"));

        let mut g = good_governance();
        g.classification = DataClassification::Synthetic;
        assert!(g.noncompliance().unwrap().contains("prod"));
    }

    #[test]
    fn none_provider_wraps_primary_and_destroy_is_noop() {
        let mut p = NoneProvider::new(
            "host=127.0.0.1 port=5432 dbname=prod",
            "dba@corp",
            "audit:_meta.clone_access",
        );
        let h = p.provision().unwrap();
        assert_eq!(h.provider, ProviderKind::None);
        assert_eq!(h.staleness_lsn_bytes, 0);
        h.governance.assert_compliant().unwrap();
        // Idempotent no-op teardown.
        p.destroy(&h).unwrap();
        p.destroy(&h).unwrap();
    }

    #[test]
    fn dblab_provider_is_unavailable_without_detection() {
        let mut p = DblabProvider::with_detected(false);
        assert!(matches!(
            p.provision(),
            Err(CloneError::Unavailable(ProviderKind::Dblab))
        ));
        // Even "detected" is unsupported in the local pivot — fail closed, never
        // a silent success.
        let mut p = DblabProvider::with_detected(true);
        assert!(matches!(
            p.provision(),
            Err(CloneError::Unavailable(ProviderKind::Dblab))
        ));
    }

    /// A trivial in-memory provider proving `with_clone` always tears down — on
    /// both the success and the failure arm.
    struct CountingProvider {
        provisioned: u32,
        destroyed: u32,
        gov: CloneGovernance,
    }
    impl CloneProvider for CountingProvider {
        fn provision(&mut self) -> Result<CloneHandle, CloneError> {
            self.provisioned += 1;
            Ok(CloneHandle {
                provider: ProviderKind::Local,
                clone_id: format!("c{}", self.provisioned),
                conn: "host=127.0.0.1 port=54361".into(),
                lsn: "0/1000000".into(),
                staleness_lsn_bytes: 0,
                governance: self.gov.clone(),
            })
        }
        fn destroy(&mut self, _h: &CloneHandle) -> Result<(), CloneError> {
            self.destroyed += 1;
            Ok(())
        }
    }

    #[test]
    fn with_clone_tears_down_on_success() {
        let mut p = CountingProvider {
            provisioned: 0,
            destroyed: 0,
            gov: good_governance(),
        };
        let out: Result<u8, CloneError> =
            with_clone(&mut p, |_h| Ok(7u8), |_| panic!("no teardown err"));
        assert_eq!(out.unwrap(), 7);
        assert_eq!(p.provisioned, 1);
        assert_eq!(p.destroyed, 1, "teardown must run on success");
    }

    #[test]
    fn with_clone_tears_down_on_failure() {
        let mut p = CountingProvider {
            provisioned: 0,
            destroyed: 0,
            gov: good_governance(),
        };
        let out: Result<u8, CloneError> = with_clone(
            &mut p,
            |_h| Err(CloneError::Provision("boom".into())),
            |_| panic!("no teardown err"),
        );
        assert!(matches!(out, Err(CloneError::Provision(_))));
        assert_eq!(p.destroyed, 1, "teardown MUST run even when the body fails");
    }

    #[test]
    fn with_clone_rejects_noncompliant_clone_and_still_tears_down() {
        let mut bad = good_governance();
        bad.encryption_at_rest = false;
        let mut p = CountingProvider {
            provisioned: 0,
            destroyed: 0,
            gov: bad,
        };
        let out: Result<u8, CloneError> =
            with_clone(&mut p, |_h| Ok(1u8), |_| panic!("no teardown err"));
        assert!(matches!(out, Err(CloneError::Governance(_))));
        assert_eq!(
            p.destroyed, 1,
            "a non-compliant clone must still be torn down"
        );
    }
}
