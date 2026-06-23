//! The **production grant-gated apply path** (SPEC §14.3, §10.1, §12.2, #66, #45).
//!
//! [`crate::apply::guarded_apply`] is the reversible half of the moat — the §4
//! guards (apply-time PK-set re-check, per-op-type reconciliation, fail-closed
//! reversible pre-image coverage). But until now it had **no production caller**:
//! every call site was a test, and the §14.3 signed [`pgb_policy::GrantToken`]
//! (minted when a human approves a blocked action) was consumed *only* by the
//! CLI's in-process approval demo. The signed grant therefore never gated a real
//! apply — the "approval is theater" gap the S4 sprint review (#51) flagged.
//!
//! This module closes that gap. [`guarded_apply_with_grant`] is the
//! **generic-schema production caller** (#45) that:
//!
//! 1. **bridges** a [`pgb_policy::PolicyConfig`] onto the engine's knobs —
//!    `clone.provider` → [`ProviderKind`] (via the existing `From<CloneProvider>`)
//!    and `pitr.enabled` → the apply's [`ApplyPitrConfig`] (via the
//!    `From<PitrConfig>` bridge added here);
//! 2. **consumes the §14.3 grant at apply time** — it re-derives the *live*
//!    [`pgb_policy::GrantBinding`] from the current request **plus the apply-time
//!    recomputed target PK-set checksum** and re-verifies the signed grant
//!    ([`pgb_policy::GrantToken::verify_for_apply`], reused — no crypto is
//!    reimplemented here): signature, exact binding match, single-use nonce, and
//!    expiry. The signed `blast_radius_checksum` is thereby **bound to the exact
//!    proposal** the approver authorized: a swapped statement / param / session /
//!    proposal, a reused nonce, an expired TTL, **or a drifted data set** (the
//!    apply-time PK-set no longer equals the signed one) all REJECT;
//! 3. only on a valid, single-use, unexpired, proposal-bound grant does it reach
//!    [`guarded_apply`], whose own §10.1 apply-time PK-set re-check then re-pins
//!    the same checksum **inside** the apply txn (defense in depth).
//!
//! **Fail-closed / tighten-only.** The grant gate can only ADD an abort condition;
//! it never loosens a `guarded_apply` guard. No valid grant ⇒ **abort, no
//! mutation** — the apply txn is never opened (the grant is checked before any
//! `begin`). The `NonceStore` and approver `VerifyingKey` are injected so a
//! shared/durable store and the policy-resolved approver key gate every apply.
//!
//! Single source of truth: the binding hash, the Ed25519 verify, the nonce store,
//! and the PK-set checksum all come from `pgb_core` / `pgb_policy` — this module
//! only orchestrates them at the apply seam.

use pgb_core::{ApplyBarrier, BlastRadius, Clock};
use pgb_policy::{GrantBinding, GrantError, GrantToken, NonceStore, PolicyConfig};

use crate::apply::{
    AppliedWrite, ApplyConn, ApplyError, PitrConfig as ApplyPitrConfig, guarded_apply,
};
use crate::dry_run::WriteKind;
use crate::provider::ProviderKind;

/// Bridge the §12.2 policy [`pgb_policy::PitrConfig`] (`pitr.enabled`) onto the
/// apply engine's [`ApplyPitrConfig`] (which decides the §1 `RecoveryFence`).
///
/// Single source of truth: production reads `pitr.enabled` from one
/// `policy.yaml`; this is the only place that bit becomes the apply's fence
/// decision. (The `RecoveryFence` is selected inside [`guarded_apply`] from this.)
impl From<pgb_policy::PitrConfig> for ApplyPitrConfig {
    fn from(p: pgb_policy::PitrConfig) -> Self {
        if p.enabled {
            ApplyPitrConfig::enabled()
        } else {
            ApplyPitrConfig::disabled()
        }
    }
}

/// The **live apply-time request** facts the grant gate re-derives the binding
/// from (SPEC §14.3). These are the bound fields the approver's signature
/// committed to that are *not* recomputed from the DB at apply time: the exact
/// statement text, the normalized params, the role, the session/principal id, and
/// the proposal id.
///
/// The two remaining bound fields — `dry_run_lsn` and `blast_radius_checksum` —
/// come from the [`BlastRadius`] grant (`clone_lsn`) and the **apply-time
/// recomputed** target PK-set checksum respectively, so they cannot be forged
/// from the live request alone: the checksum is read from the live DB at apply
/// time, pinning the grant to the exact data set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRequest {
    /// The exact statement text being applied right now.
    pub statement_text: String,
    /// The normalized prepared-statement params for this apply, in order.
    pub normalized_params: Vec<String>,
    /// The database role this apply runs as.
    pub role: String,
    /// The session / principal id this apply originates from (defeats
    /// cross-session replay — it is in the binding hash).
    pub session_id: String,
    /// The proposal id this apply belongs to (must match the grant + blast
    /// radius).
    pub proposal_id: String,
}

/// Why a grant-gated apply was refused. Either the §14.3 grant verification
/// failed (the apply txn is **never opened** — fail-closed before any DB write),
/// or `guarded_apply`'s own §4 guards aborted (the apply txn rolled back). Every
/// variant means **nothing was committed**.
#[derive(Debug, thiserror::Error)]
pub enum GrantedApplyError {
    /// The §14.3 grant did not verify against the live request at apply time
    /// (bad signature, binding mismatch — incl. SQL/param/session/proposal swap
    /// **or apply-time data drift** — replayed nonce, or expiry). Carries the
    /// typed [`GrantError`]. **No apply txn was opened.**
    #[error("GRANT REJECTED at apply: {0}")]
    Grant(#[from] GrantError),

    /// The grant verified but `guarded_apply`'s §4 guards aborted (or refused).
    /// The apply txn was rolled back (or never opened for a refusal). Carries the
    /// typed [`ApplyError`].
    #[error("{0}")]
    Apply(#[from] ApplyError),

    /// The grant, the blast radius, and the live request are internally
    /// inconsistent in a way that is not a tamper case but still cannot authorize
    /// an apply (e.g. the grant's signed `blast_radius_checksum` is not the
    /// blast-radius's target checksum, or the blast radius has no target
    /// checksum). Fail-closed: refuse rather than guess. **No apply txn opened.**
    #[error("INVALID GRANT BINDING: {0}")]
    Inconsistent(String),
}

/// Which provider the policy selects for the apply path, and the apply's PITR
/// fence — bridged from one [`PolicyConfig`] (SPEC §12.2). Returned alongside the
/// apply so the caller can record what the policy resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgedApplyConfig {
    /// `clone.provider` → [`ProviderKind`] (via `From<CloneProvider>`).
    pub provider: ProviderKind,
    /// `pitr.enabled` → the apply's [`ApplyPitrConfig`] (via `From<PitrConfig>`).
    pub pitr: ApplyPitrConfig,
}

impl BridgedApplyConfig {
    /// Bridge a [`PolicyConfig`] onto the apply engine's knobs (the two §12.2
    /// bits the apply path consumes). This is the single place `clone.provider`
    /// and `pitr.enabled` cross from policy into the engine.
    pub fn from_policy(policy: &PolicyConfig) -> Self {
        BridgedApplyConfig {
            provider: ProviderKind::from(policy.clone.provider),
            pitr: ApplyPitrConfig::from(policy.pitr),
        }
    }
}

/// Apply a dry-run-validated proposal on the primary **only if** the §14.3 signed
/// grant re-verifies at apply time, under the §4 [`guarded_apply`] guards
/// (SPEC §14.3, §10.1, §12.2; #66, #45).
///
/// This is the production apply caller. It:
///
/// 1. bridges `policy` → provider + PITR fence ([`BridgedApplyConfig`]);
/// 2. cross-checks the grant is internally consistent with `blast_radius` (the
///    signed `blast_radius_checksum` MUST be the blast radius's target PK-set
///    checksum, and the bound `proposal_id` must match) — else
///    [`GrantedApplyError::Inconsistent`];
/// 3. **recomputes the apply-time target PK-set checksum** via the same
///    [`ApplyConn::recompute_pk_checksum`] seam `guarded_apply` uses, and builds
///    the *live* [`GrantBinding`] from `live` + `blast_radius.clone_lsn` + that
///    apply-time checksum;
/// 4. **re-verifies the grant** ([`GrantToken::verify_for_apply`]) — signature,
///    exact binding match, single-use nonce (consumed in `nonces`), expiry —
///    against the injected approver `verifying_key` and `clock`. Any divergence
///    REJECTS **before the apply txn is opened** (fail-closed, no mutation);
/// 5. on success, calls [`guarded_apply`], whose §10.1 apply-time PK-set re-check
///    re-pins the same checksum inside the apply txn (defense in depth).
///
/// The grant gate is **tighten-only**: it can only refuse; it never loosens a
/// `guarded_apply` guard.
#[allow(clippy::too_many_arguments)]
pub fn guarded_apply_with_grant(
    policy: &PolicyConfig,
    grant: &GrantToken,
    live: &LiveRequest,
    verifying_key: &ed25519_dalek::VerifyingKey,
    nonces: &mut dyn NonceStore,
    kind: WriteKind,
    relation: &str,
    blast_radius: &BlastRadius,
    conn: &mut dyn ApplyConn,
    barrier: &dyn ApplyBarrier,
    clock: &dyn Clock,
) -> Result<(AppliedWrite, BridgedApplyConfig), GrantedApplyError> {
    let bridged = BridgedApplyConfig::from_policy(policy);

    // (a) The blast radius must be the one this apply is for, and carry the target
    //     PK-set checksum. (guarded_apply re-checks proposal_id too, but we need
    //     the target checksum HERE to build the live binding.)
    if blast_radius.proposal_id != live.proposal_id {
        return Err(GrantedApplyError::Inconsistent(format!(
            "blast-radius proposal_id `{}` != live proposal_id `{}`",
            blast_radius.proposal_id, live.proposal_id
        )));
    }
    let target_checksum = blast_radius
        .affected
        .pk_set_checksum
        .get(relation)
        .cloned()
        .ok_or_else(|| {
            GrantedApplyError::Inconsistent(format!(
                "blast-radius has no pk_set_checksum for target `{relation}`"
            ))
        })?;

    // (b) The grant's SIGNED blast_radius_checksum MUST be the blast radius's
    //     target checksum. If they differ, the grant authorizes a DIFFERENT data
    //     set than the blast radius this apply will re-check against — refuse
    //     (fail-closed) rather than let the two diverge.
    if grant.binding.blast_radius_checksum != target_checksum {
        return Err(GrantedApplyError::Inconsistent(format!(
            "grant blast_radius_checksum `{}` != blast-radius target checksum `{}` \
             (the grant does not authorize this blast radius)",
            grant.binding.blast_radius_checksum, target_checksum
        )));
    }

    // (c) Recompute the apply-time target PK-set checksum on the SAME predicate,
    //     via the SAME seam guarded_apply uses. This is the live data fact that
    //     pins the grant to the exact proposal: if a row drifted in/out of the
    //     predicate since the dry-run, this differs from the signed checksum and
    //     the binding-hash match below FAILS (REJECT, no mutation). We do NOT
    //     compare it ourselves — verify_for_apply compares the whole binding hash,
    //     so this drift is just one more bound field that must match.
    let apply_time_checksum = conn.recompute_pk_checksum(relation)?.as_prefixed();

    // (d) Build the LIVE binding from the live request + the grant's dry_run_lsn
    //     + the APPLY-TIME checksum, and re-verify the grant against it. This is
    //     the single §14.3 re-verify-at-apply (reused crypto, no reimpl).
    let live_binding = GrantBinding {
        statement_text: live.statement_text.clone(),
        normalized_params: live.normalized_params.clone(),
        role: live.role.clone(),
        session_id: live.session_id.clone(),
        proposal_id: live.proposal_id.clone(),
        dry_run_lsn: blast_radius.clone_lsn.clone(),
        blast_radius_checksum: apply_time_checksum,
        nonce: grant.binding.nonce.clone(),
        expiry_unix_millis: grant.binding.expiry_unix_millis,
    };
    grant.verify_for_apply(&live_binding, verifying_key, nonces, clock)?;

    // (e) Grant verified + nonce consumed → reach the §4 guarded apply. Its own
    //     §10.1 apply-time PK-set re-check re-pins the same checksum inside the
    //     apply txn (defense in depth). The grant gate is tighten-only: we only
    //     reach here on a fully-valid grant; otherwise we already returned above.
    let applied = guarded_apply(
        &live.proposal_id,
        kind,
        relation,
        blast_radius,
        bridged.pitr,
        conn,
        barrier,
        clock,
    )?;
    Ok((applied, bridged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{CapturedRow, ForwardResult, RelationChange};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use pgb_core::blast_radius::Affected;
    use pgb_core::{
        InverseKind, LockMode, MockClock, NoopBarrier, OpCounts, PkChecksum, PkSetBuilder, PkTuple,
        PkValue,
    };
    use pgb_policy::{CloneConfig, CloneProvider, InMemoryNonceStore, PitrConfig as PolicyPitr};
    use rand_core::OsRng;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    const REL: &str = "public.orders";

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn checksum_of(rel: &str, ids: &[i64]) -> PkChecksum {
        let mut b = PkSetBuilder::for_relation(rel);
        for &id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().unwrap()
    }

    /// A blast radius for `rel` over `ids`, as an UPDATE footprint (`upd`).
    fn blast_radius_for(proposal_id: &str, rel: &str, ids: &[i64]) -> BlastRadius {
        let mut pk_set_checksum = BTreeMap::new();
        pk_set_checksum.insert(rel.to_string(), checksum_of(rel, ids).as_prefixed());
        let mut by_table = BTreeMap::new();
        by_table.insert(rel.to_string(), ids.len() as u64);
        let mut effect_by_table = BTreeMap::new();
        effect_by_table.insert(rel.to_string(), OpCounts::new(0, ids.len() as u64, 0));
        BlastRadius {
            proposal_id: proposal_id.to_string(),
            clone_lsn: "3A/7F00C8".into(),
            staleness_lsn_bytes: 0,
            affected: Affected {
                by_table,
                cascade_by_table: BTreeMap::new(),
                pk_set_checksum,
                effect_by_table,
                total_rows: ids.len() as u64,
            },
            triggers_fired: vec![],
            locks: vec![],
            max_lock_mode: LockMode::RowExclusiveLock,
            duration_ms: 5,
            wal_bytes: 0,
            constraint_violations: vec![],
            reversible: true,
            inverse_kind: InverseKind::PreimageUpsert,
            predicate_volatile: false,
        }
    }

    fn live_for(proposal_id: &str) -> LiveRequest {
        LiveRequest {
            statement_text: "UPDATE public.orders SET status='fixed' WHERE id % 2 = 0".to_string(),
            normalized_params: vec![],
            role: "app_writer".to_string(),
            session_id: "sess-abc".to_string(),
            proposal_id: proposal_id.to_string(),
        }
    }

    /// Sign a grant whose binding matches `live` + the blast radius (the honest
    /// happy-path grant the approver would sign over the dry-run checksum).
    fn sign_grant(
        sk: &SigningKey,
        live: &LiveRequest,
        br: &BlastRadius,
        rel: &str,
        nonce: &str,
        expiry: u64,
    ) -> GrantToken {
        let binding = GrantBinding {
            statement_text: live.statement_text.clone(),
            normalized_params: live.normalized_params.clone(),
            role: live.role.clone(),
            session_id: live.session_id.clone(),
            proposal_id: live.proposal_id.clone(),
            dry_run_lsn: br.clone_lsn.clone(),
            blast_radius_checksum: br.affected.pk_set_checksum[rel].clone(),
            nonce: nonce.to_string(),
            expiry_unix_millis: expiry,
        };
        GrantToken::sign(binding, sk)
    }

    fn policy_with(provider: CloneProvider, pitr_enabled: bool) -> PolicyConfig {
        use pgb_policy::{AutonomyLevel, RoleBudget, RolePolicy, WindowBudget};
        let mut roles = BTreeMap::new();
        roles.insert(
            "app_writer".to_string(),
            RolePolicy {
                select_whitelist: vec![],
                budget: RoleBudget {
                    max_bytes: 1000,
                    max_rows: 100,
                    max_plan_cost: 1000.0,
                    max_plan_rows: 1000,
                    per_window: WindowBudget {
                        window_secs: 60,
                        max_bytes: 10_000,
                        max_rows: 1000,
                    },
                },
                autonomy: AutonomyLevel::L1,
            },
        );
        PolicyConfig {
            version: 1,
            roles,
            replica: Default::default(),
            clone: CloneConfig { provider },
            pitr: PolicyPitr {
                enabled: pitr_enabled,
            },
            approvers: Default::default(),
            audit: Default::default(),
        }
    }

    // ---- the scripted in-memory ApplyConn (same shape as apply.rs's) ----------

    #[derive(Default)]
    struct MockConnInner {
        recompute_ids: BTreeMap<String, Vec<i64>>,
        written_ids: Vec<i64>,
        began: bool,
        committed: bool,
        rolled_back: bool,
    }

    #[derive(Clone)]
    struct MockConn(Arc<Mutex<MockConnInner>>);

    impl MockConn {
        fn new(rel: &str, ids: &[i64]) -> Self {
            let mut recompute_ids = BTreeMap::new();
            recompute_ids.insert(rel.to_string(), ids.to_vec());
            MockConn(Arc::new(Mutex::new(MockConnInner {
                recompute_ids,
                written_ids: ids.to_vec(),
                ..Default::default()
            })))
        }
        fn inner(&self) -> std::sync::MutexGuard<'_, MockConnInner> {
            self.0.lock().unwrap()
        }
    }

    impl ApplyConn for MockConn {
        fn create_restore_point(&mut self, _label: &str) -> Result<String, ApplyError> {
            Ok("0/16B6358".to_string())
        }
        fn begin(&mut self, _timeout_ms: u64) -> Result<(), ApplyError> {
            self.inner().began = true;
            Ok(())
        }
        fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
            let ids = self
                .inner()
                .recompute_ids
                .get(relation)
                .cloned()
                .unwrap_or_default();
            Ok(checksum_of(relation, &ids))
        }
        fn apply_forward(
            &mut self,
            _kind: WriteKind,
            _relation: &str,
            _cascade: &[String],
        ) -> Result<ForwardResult, ApplyError> {
            let ids = self.inner().written_ids.clone();
            let written = ids
                .iter()
                .map(|&id| CapturedRow {
                    pk: PkTuple::single(PkValue::Int(id)),
                    before_image: vec![("status".into(), PkValue::Text("open".into()))],
                })
                .collect();
            Ok(ForwardResult::new(written))
        }
        fn xact_tuple_deltas(&mut self) -> Result<Vec<RelationChange>, ApplyError> {
            let n = self.inner().written_ids.len() as u64;
            Ok(vec![RelationChange {
                relation: REL.to_string(),
                ins: 0,
                upd: n,
                del: 0,
            }])
        }
        fn commit(&mut self) -> Result<(), ApplyError> {
            self.inner().committed = true;
            Ok(())
        }
        fn rollback(&mut self) -> Result<(), ApplyError> {
            self.inner().rolled_back = true;
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run(
        policy: &PolicyConfig,
        grant: &GrantToken,
        live: &LiveRequest,
        vk: &VerifyingKey,
        nonces: &mut dyn NonceStore,
        br: &BlastRadius,
        conn: &mut MockConn,
        clock: &dyn Clock,
    ) -> Result<(AppliedWrite, BridgedApplyConfig), GrantedApplyError> {
        guarded_apply_with_grant(
            policy,
            grant,
            live,
            vk,
            nonces,
            WriteKind::Update,
            REL,
            br,
            conn,
            &NoopBarrier::new(),
            clock,
        )
    }

    // =======================================================================
    //  HAPPY PATH — a CLI-minted grant verifies at the real apply path and the
    //  bounded write commits (reversibly).
    // =======================================================================

    #[test]
    fn valid_grant_verifies_and_apply_commits() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-1", REL, &[2, 4, 6, 8]);
        let live = live_for("p-1");
        let grant = sign_grant(&sk, &live, &br, REL, "nonce-1", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);
        let probe = conn.clone();

        let (applied, bridged) = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .expect("a valid grant must verify and the apply must commit");

        assert_eq!(applied.rows_written, 4);
        assert_eq!(applied.inverse.kind, InverseKind::PreimageUpsert);
        assert_eq!(applied.inverse.rows.len(), 4, "typed-inverse captured");
        assert_eq!(bridged.provider, ProviderKind::None);
        assert_eq!(bridged.pitr, ApplyPitrConfig::disabled());
        assert!(probe.inner().committed, "the bounded write committed");
        assert!(!probe.inner().rolled_back);
        // The nonce was consumed — a replay now fails.
        assert!(!nonces.consume("nonce-1"), "nonce consumed by the apply");
    }

    #[test]
    fn policy_bridges_provider_and_pitr() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-br", REL, &[2, 4]);
        let live = live_for("p-br");
        let grant = sign_grant(&sk, &live, &br, REL, "n-br", 10_000);
        // dblab provider + pitr enabled → bridged to ProviderKind::Dblab + PITR on.
        let policy = policy_with(CloneProvider::Dblab, true);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(1);
        let mut conn = MockConn::new(REL, &[2, 4]);

        let (applied, bridged) = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap();
        assert_eq!(bridged.provider, ProviderKind::Dblab);
        assert_eq!(bridged.pitr, ApplyPitrConfig::enabled());
        // PITR enabled → a restore-point fence was created.
        assert!(matches!(
            applied.fence,
            crate::apply::RecoveryFence::PitrRestorePoint { .. }
        ));
    }

    // =======================================================================
    //  NO-GRANT / TAMPER — every case fail-closed ABORTS with NO mutation
    //  (the apply txn is never even opened: the grant is checked first).
    // =======================================================================

    fn assert_no_mutation(conn: &MockConn) {
        let p = conn.inner();
        assert!(!p.began, "the apply txn must NOT open on a rejected grant");
        assert!(!p.committed, "nothing committed");
    }

    #[test]
    fn no_grant_minted_by_attacker_wrong_key_aborts_fail_closed() {
        // An attacker mints a grant with their OWN key; the verifier trusts the
        // approver's key → BadSignature → REJECT, no mutation.
        let (attacker_sk, _) = keypair();
        let (_approver_sk, approver_vk) = keypair();
        let br = blast_radius_for("p-nok", REL, &[2, 4, 6, 8]);
        let live = live_for("p-nok");
        let grant = sign_grant(&attacker_sk, &live, &br, REL, "n-nok", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        let err = run(
            &policy,
            &grant,
            &live,
            &approver_vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BadSignature)),
            "{err:?}"
        );
        assert_no_mutation(&conn);
    }

    #[test]
    fn t_grant_sql_swap_aborts() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-sql", REL, &[2, 4, 6, 8]);
        let live = live_for("p-sql");
        let grant = sign_grant(&sk, &live, &br, REL, "n-sql", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        // The attacker presents a DIFFERENT statement at apply time.
        let mut tampered = live.clone();
        tampered.statement_text = "DELETE FROM public.orders".to_string();
        let err = run(
            &policy,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BindingMismatch)),
            "{err:?}"
        );
        assert_no_mutation(&conn);
        // The nonce was NOT burned by a rejected verify.
        assert!(nonces.consume("n-sql"));
    }

    #[test]
    fn t_grant_param_swap_aborts() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-par", REL, &[2, 4, 6, 8]);
        let mut live = live_for("p-par");
        live.normalized_params = vec!["42".to_string()];
        let grant = sign_grant(&sk, &live, &br, REL, "n-par", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        let mut tampered = live.clone();
        tampered.normalized_params = vec!["99".to_string()]; // swapped prepared param
        let err = run(
            &policy,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BindingMismatch)),
            "{err:?}"
        );
        assert_no_mutation(&conn);
    }

    #[test]
    fn t_grant_cross_session_replay_aborts() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-ses", REL, &[2, 4, 6, 8]);
        let live = live_for("p-ses");
        let grant = sign_grant(&sk, &live, &br, REL, "n-ses", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        // Same approved statement + nonce, replayed from ANOTHER session.
        let mut tampered = live.clone();
        tampered.session_id = "sess-attacker".to_string();
        let err = run(
            &policy,
            &grant,
            &tampered,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BindingMismatch)),
            "{err:?}"
        );
        assert_no_mutation(&conn);
    }

    #[test]
    fn t_grant_proposal_swap_aborts() {
        // The grant is for p-A; the attacker tries to apply it onto proposal p-B's
        // blast radius. The proposal_id is a bound field → BindingMismatch. (We
        // make both blast radii carry the SAME target checksum so the inconsistency
        // check passes and the tamper is caught by the binding hash, not the
        // cross-check — proving the proposal binding itself gates it.)
        let (sk, vk) = keypair();
        let br_a = blast_radius_for("p-A", REL, &[2, 4, 6, 8]);
        let live_a = live_for("p-A");
        let grant = sign_grant(&sk, &live_a, &br_a, REL, "n-prop", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        // Apply onto proposal p-B (same data set / checksum, different proposal).
        let br_b = blast_radius_for("p-B", REL, &[2, 4, 6, 8]);
        let live_b = live_for("p-B");
        let err = run(
            &policy,
            &grant,
            &live_b,
            &vk,
            &mut nonces,
            &br_b,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BindingMismatch)),
            "{err:?}"
        );
        assert_no_mutation(&conn);
    }

    #[test]
    fn t_grant_data_drift_apply_time_checksum_mismatch_aborts() {
        // THE MOAT POINT: the grant is signed for the data set {2,4,6,8}, but at
        // apply time a row drifted into the predicate so the recompute sees
        // {2,4,6,8,10}. The apply-time PK-set checksum differs from the signed
        // blast_radius_checksum → the live binding hash mismatches → REJECT, no
        // mutation. A grant only authorizes the EXACT proposal it was signed for.
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-drift", REL, &[2, 4, 6, 8]);
        let live = live_for("p-drift");
        let grant = sign_grant(&sk, &live, &br, REL, "n-drift", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        // The apply-time recompute sees a DRIFTED set (extra row 10).
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);

        let err = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::BindingMismatch)),
            "apply-time data drift must REJECT via binding mismatch, got {err:?}"
        );
        assert_no_mutation(&conn);
    }

    #[test]
    fn t_grant_replay_nonce_reuse_aborts() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-rep", REL, &[2, 4, 6, 8]);
        let live = live_for("p-rep");
        let grant = sign_grant(&sk, &live, &br, REL, "n-rep", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);

        // First apply: legitimate, commits, consumes the nonce.
        let mut conn1 = MockConn::new(REL, &[2, 4, 6, 8]);
        run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn1,
            &clock,
        )
        .expect("first apply commits");
        assert!(conn1.inner().committed);

        // Second apply with the SAME grant: nonce already used → replay → REJECT.
        let mut conn2 = MockConn::new(REL, &[2, 4, 6, 8]);
        let err = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn2,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::ReplayedNonce)),
            "{err:?}"
        );
        assert_no_mutation(&conn2);
    }

    #[test]
    fn t_grant_expiry_aborts() {
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-exp", REL, &[2, 4, 6, 8]);
        let live = live_for("p-exp");
        let grant = sign_grant(&sk, &live, &br, REL, "n-exp", 10_000);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        clock.advance(5_000); // now = 10_000 == expiry → expired (>=)
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        let err = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(err, GrantedApplyError::Grant(GrantError::Expired { .. })),
            "{err:?}"
        );
        assert_no_mutation(&conn);
        // Expiry checked before the nonce is burned.
        assert!(nonces.consume("n-exp"));
    }

    // =======================================================================
    //  Internal-consistency cross-check (fail-closed, not a tamper case).
    // =======================================================================

    #[test]
    fn grant_for_different_blast_radius_checksum_is_refused() {
        // The grant's signed blast_radius_checksum does not match the blast
        // radius's target checksum → Inconsistent (the grant authorizes a
        // different data set). No mutation.
        let (sk, vk) = keypair();
        let br = blast_radius_for("p-inc", REL, &[2, 4, 6, 8]);
        let live = live_for("p-inc");
        // Sign over a DIFFERENT checksum than the blast radius carries.
        let binding = GrantBinding {
            statement_text: live.statement_text.clone(),
            normalized_params: live.normalized_params.clone(),
            role: live.role.clone(),
            session_id: live.session_id.clone(),
            proposal_id: live.proposal_id.clone(),
            dry_run_lsn: br.clone_lsn.clone(),
            blast_radius_checksum: checksum_of(REL, &[1, 3, 5]).as_prefixed(),
            nonce: "n-inc".into(),
            expiry_unix_millis: 10_000,
        };
        let grant = GrantToken::sign(binding, &sk);
        let policy = policy_with(CloneProvider::None, false);
        let mut nonces = InMemoryNonceStore::new();
        let clock = MockClock::starting_at(5_000);
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8]);

        let err = run(
            &policy,
            &grant,
            &live,
            &vk,
            &mut nonces,
            &br,
            &mut conn,
            &clock,
        )
        .unwrap_err();
        assert!(matches!(err, GrantedApplyError::Inconsistent(_)), "{err:?}");
        assert_no_mutation(&conn);
    }

    // =======================================================================
    //  Bridges exercised directly (single source of truth, From impls used).
    // =======================================================================

    #[test]
    fn pitr_bridge_maps_both_ways() {
        assert_eq!(
            ApplyPitrConfig::from(PolicyPitr { enabled: true }),
            ApplyPitrConfig::enabled()
        );
        assert_eq!(
            ApplyPitrConfig::from(PolicyPitr { enabled: false }),
            ApplyPitrConfig::disabled()
        );
    }

    #[test]
    fn provider_bridge_uses_existing_from_impl() {
        let p = policy_with(CloneProvider::Dblab, false);
        assert_eq!(
            BridgedApplyConfig::from_policy(&p).provider,
            ProviderKind::Dblab
        );
        let p = policy_with(CloneProvider::None, false);
        assert_eq!(
            BridgedApplyConfig::from_policy(&p).provider,
            ProviderKind::None
        );
    }
}
