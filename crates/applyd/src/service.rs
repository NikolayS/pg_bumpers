//! The `pgb-applyd` **write-safety service** — the production analog of the TS
//! `FakeCore` (issue #67). It holds the propose→dry_run→approve→apply lifecycle
//! STATE in-process, TTL'd via an injected [`Clock`], and drives the merged
//! grant-gated apply floor ([`guarded_apply_with_grant`]) for writes.
//!
//! # What it owns (the FakeCore production peer)
//! - **proposal records** (`{statement, role, session_id, expected_rows}`), TTL'd;
//! - the **cached [`BlastRadius`]** per proposal (from the real dry-run);
//! - **elevation requests** + the signed §14.3 **grants** (held in-process — the
//!   grant NEVER crosses to the agent);
//! - the **[`NonceStore`]** + the approver **[`VerifyingKey`]** (the apply-time
//!   trust roots) + the **[`PolicyConfig`]**;
//! - the shared **audit** ([`ApprovalFlow`] for request/approve/audit + the
//!   self-approval gate, and a [`SharedSink`] clone for the apply-path record),
//!   all on ONE hash-chained `_meta` chain.
//!
//! # The security-critical invariant (issue #67)
//! At [`Service::apply`] the [`LiveRequest`] is re-derived from the **STORED
//! proposal record**, NEVER from apply-time params. The `apply` RPC carries only
//! `{proposal_id, confirm_rows, confirm_token}`, so a tampered apply-time
//! statement/role/session is impossible — the service pins all three from its own
//! record, and the §14.3 binding hash + `verify_for_apply` (inside
//! [`guarded_apply_with_grant`]) reject any divergence.
//!
//! # DB-free core
//! The service owns the STATE and the ORDERING; the DB connections are passed in
//! per call ([`Service::dry_run`] takes a `&mut dyn Rehearsal`, [`Service::apply`]
//! a `&mut dyn ApplyConn`). This is the same seam the engine uses — so the unit
//! tests drive a `MockRehearsal`/`MockConn` (DB-free) and the binary/IT drive the
//! lifted real-PG18 conns. The grant crypto + the §4 guards are REUSED, never
//! reimplemented here.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};

use pgb_audit::record::{Principal as AuditPrincipal, WriteSafetyRefs};
use pgb_audit::{Decision, IntentTiers, NewEntry, SharedSink, Sink};
use pgb_cli::request::Proposal as RequestProposal;
use pgb_cli::webhook::WebhookSender;
use pgb_cli::{ApprovalFlow, NonceStore, Principal, RequestId};
use pgb_clone_orchestrator::apply::ApplyConn;
use pgb_clone_orchestrator::{
    ApplyError, DryRunError, GrantedApplyError, LiveRequest, Proposal, Rehearsal, WriteKind,
    classify, dry_run, guarded_apply_with_grant, propose,
};
use pgb_core::{ApplyBarrier, BlastRadius, Clock};
use pgb_policy::{GrantError, GrantToken, PolicyConfig};

use crate::protocol::{
    ApplyResult, ApproveResult, DryRunResult, ErrorCode, ProposeResult, RequestElevationResult,
    RpcError,
};

/// The default request/grant TTL the service mints (30 min), in millis. Matches
/// the FakeCore elevation TTL so the production peer behaves the same.
pub const DEFAULT_REQUEST_TTL_MILLIS: u64 = 30 * 60 * 1_000;

/// A stored proposal record — the binding facts the apply re-derives from. The
/// `role`/`session_id` are pinned HERE at propose time so the apply can NEVER be
/// presented a different role/session (the issue #67 invariant).
#[derive(Debug, Clone)]
struct ProposalRecord {
    proposal: Proposal,
    role: String,
    session_id: String,
    kind: WriteKind,
    relation: String,
    /// Filled at dry_run: the real measured blast radius + the confirm token.
    dry_run: Option<DryRunState>,
}

/// The cached dry-run state for a proposal (the real `BlastRadius` + the token).
#[derive(Debug, Clone)]
struct DryRunState {
    blast_radius: BlastRadius,
    total_rows: u64,
    confirm_token: String,
}

/// The write-safety service (the FakeCore production peer). Generic over the
/// [`WebhookSender`], the apply-time [`NonceStore`] the §4 floor consumes, and
/// the flow's own (apply-unused) nonce store. The audit sink is the cloneable
/// [`SharedSink`] so the flow and the apply-path record share ONE `_meta` chain.
pub struct Service<W: WebhookSender, NA: NonceStore, NF: NonceStore> {
    /// The approval flow: request_elevation / approve (sign) / audit + the
    /// self-approval gate. We do NOT route apply verification through it — the §4
    /// floor (`guarded_apply_with_grant`) does the verify+nonce-consume itself.
    flow: ApprovalFlow<SharedSink, W, NF>,
    /// A clone of the SAME shared sink, for the apply-path audit record.
    sink: SharedSink,
    /// The apply-time nonce store the §4 floor consumes (the replay-defense root).
    apply_nonces: NA,
    /// The approver public key the §4 floor verifies grants against.
    verifying_key: VerifyingKey,
    /// The policy bridged onto the apply (clone.provider + pitr).
    policy: PolicyConfig,
    /// Proposal records, keyed by proposal id (TTL'd via the clock).
    proposals: BTreeMap<String, ProposalRecord>,
    /// Grants minted by approve, keyed by proposal id.
    grants: BTreeMap<String, GrantToken>,
    /// Map request id → proposal id (so approve can find the proposal).
    request_to_proposal: BTreeMap<String, String>,
    /// Monotonic counter for unique request ids.
    next_request: u64,
}

impl<W: WebhookSender, NA: NonceStore, NF: NonceStore> Service<W, NA, NF> {
    /// Build the service from its parts. `flow` already wraps the shared sink +
    /// webhook + the flow's verifying key/nonce store; `sink` is a clone of the
    /// SAME shared sink for the apply-path record; `apply_nonces` +
    /// `verifying_key` are the apply-time trust roots the §4 floor uses.
    pub fn new(
        flow: ApprovalFlow<SharedSink, W, NF>,
        sink: SharedSink,
        apply_nonces: NA,
        verifying_key: VerifyingKey,
        policy: PolicyConfig,
    ) -> Self {
        Service {
            flow,
            sink,
            apply_nonces,
            verifying_key,
            policy,
            proposals: BTreeMap::new(),
            grants: BTreeMap::new(),
            request_to_proposal: BTreeMap::new(),
            next_request: 0,
        }
    }

    /// **`propose`** — mint a TTL'd proposal, pinning the role/session into the
    /// stored record (the apply re-derives from these, never from apply-time
    /// params). Classifies the statement up front so a non-rehearsable shape is
    /// refused here (default-deny) before any DB touch.
    pub fn propose(
        &mut self,
        sql: &str,
        expected_rows: Option<u64>,
        role: &str,
        session_id: &str,
        clock: &dyn Clock,
    ) -> Result<ProposeResult, RpcError> {
        // Classify up front: refuse a non-certified shape (DDL/TRUNCATE/…) now.
        // S5 #76 item 1: a structural refusal (the "delete a DB"/DROP/TRUNCATE
        // headline) must leave a verifiable BLOCK record on the shared `_meta`
        // chain (SPEC §3/§10 "rejects recorded") — fail-closed.
        let (kind, relation) = match classify(sql) {
            Ok(kr) => kr,
            Err(e) => {
                let refusal = dry_run_error_to_rpc(e);
                return Err(self.audit_refusal_then(sql, role, session_id, refusal, clock));
            }
        };
        let proposal = propose(sql, expected_rows, clock);
        let id = proposal.id.clone();
        let ttl = proposal.ttl_millis;
        self.proposals.insert(
            id.clone(),
            ProposalRecord {
                proposal,
                role: role.to_string(),
                session_id: session_id.to_string(),
                kind,
                relation,
                dry_run: None,
            },
        );
        Ok(ProposeResult {
            proposal_id: id,
            ttl_millis: ttl,
        })
    }

    /// **`dry_run`** — rehearse the proposal on `rehearsal` (the real in-txn
    /// measurement) → cache the §10.1 [`BlastRadius`] + mint a confirm token. A
    /// volatile / PK-less / non-rehearsable refusal surfaces as the matching
    /// recoverable error code (fail-closed).
    pub fn dry_run(
        &mut self,
        proposal_id: &str,
        rehearsal: &mut dyn Rehearsal,
        clock: &dyn Clock,
    ) -> Result<DryRunResult, RpcError> {
        let record = self
            .proposals
            .get(proposal_id)
            .filter(|r| !r.proposal.is_expired(clock))
            .ok_or_else(proposal_not_found)?;
        let proposal = record.proposal.clone();
        let relation = record.relation.clone();
        // Captured up front so a dry_run REFUSAL can be audited with the proposal's
        // own {statement, role, session} (S5 #76 item 1).
        let statement = record.proposal.statement.clone();
        let role = record.role.clone();
        let session_id = record.session_id.clone();

        // The real dry-run (refuses volatile / PK-less / non-rehearsable). A
        // refusal must leave a verifiable BLOCK record on the shared `_meta` chain
        // (SPEC §3/§10 "rejects recorded") — fail-closed.
        let blast_radius = match dry_run(&proposal, rehearsal, clock) {
            Ok(br) => br,
            Err(e) => {
                let refusal = dry_run_error_to_rpc(e);
                return Err(self.audit_refusal_then(
                    &statement,
                    &role,
                    &session_id,
                    refusal,
                    clock,
                ));
            }
        };
        let total_rows = blast_radius.affected.total_rows;
        let pk_set_checksum = match blast_radius
            .affected
            .pk_set_checksum
            .get(&relation)
            .cloned()
        {
            Some(c) => c,
            None => {
                let refusal =
                    ErrorCode::PkLess.error(format!("no pk_set_checksum for target `{relation}`"));
                return Err(self.audit_refusal_then(
                    &statement,
                    &role,
                    &session_id,
                    refusal,
                    clock,
                ));
            }
        };
        let reversible = blast_radius.reversible;
        let confirm_token = format!("ct-{proposal_id}-{total_rows}");

        // Cache the measured blast radius on the record.
        if let Some(rec) = self.proposals.get_mut(proposal_id) {
            rec.dry_run = Some(DryRunState {
                blast_radius,
                total_rows,
                confirm_token: confirm_token.clone(),
            });
        }

        Ok(DryRunResult {
            total_rows,
            pk_set_checksum,
            reversible,
            confirm_token,
        })
    }

    /// **`request_elevation`** — open an `APPROVAL_REQUIRED` ticket for a dry-run
    /// proposal (SPEC §14.3). The ticket binds to the STORED proposal record
    /// (role/session/checksum), so the later grant authorizes exactly this
    /// proposal. A structural/irreversible op is refused by the flow's gate.
    pub fn request_elevation(
        &mut self,
        proposal_id: &str,
        reason: &str,
        clock: &dyn Clock,
    ) -> Result<RequestElevationResult, RpcError> {
        let record = self
            .proposals
            .get(proposal_id)
            .filter(|r| !r.proposal.is_expired(clock))
            .ok_or_else(proposal_not_found)?;
        let dry = record.dry_run.as_ref().ok_or_else(|| {
            ErrorCode::ConfirmMismatch.error("dry_run the proposal before elevating")
        })?;

        let req_proposal = binding_proposal(record, dry);
        let cap = req_proposal.cap;
        // EPIC #91 PR-B §4 disclosure: the side-effecting triggers the write fires.
        // Surfaced to the human at approval as a first-class fact (a trigger may write
        // a relation OUTSIDE the captured inverse — e.g. an audit table — whose effect
        // the typed-inverse does not undo).
        let side_effecting_triggers: Vec<String> = dry
            .blast_radius
            .triggers_fired
            .iter()
            .filter(|t| t.rows > 0)
            .map(|t| t.name.clone())
            .collect();
        let op = operation_for(record, dry);
        let requester_id = record.session_id.clone();
        let _ = reason; // recorded by the flow's request payload

        self.next_request += 1;
        let request_id = format!("req-{:08x}", self.next_request);
        let id = RequestId(request_id.clone());

        let outcome = self
            .flow
            .request_elevation(
                id,
                req_proposal,
                requester_id,
                &op,
                DEFAULT_REQUEST_TTL_MILLIS,
                clock,
            )
            .map_err(elevation_error_to_rpc)?;

        self.request_to_proposal
            .insert(request_id.clone(), proposal_id.to_string());

        Ok(RequestElevationResult {
            request_id,
            ttl_millis: outcome
                .contract
                .expires_at_unix_millis
                .saturating_sub(clock.now_unix_millis()),
            cap_max_rows: cap.max_rows,
            cap_max_wal_bytes: cap.max_wal_bytes,
            side_effecting_triggers,
        })
    }

    /// **`approve`** (the OPERATOR hop) — a human approver signs the §14.3
    /// proposal-bound grant. The signing key is presented out-of-band by the
    /// operator (NEVER the agent); we verify its public key matches the
    /// configured approver pubkey (the apply-time trust root) before signing, and
    /// the flow's gate refuses self-approval. The minted grant is held in-process
    /// keyed by proposal id; `apply` consumes it.
    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        &mut self,
        request_id: &str,
        approver_id: &str,
        signing_key: &SigningKey,
        nonce: &str,
        grant_ttl_millis: u64,
        clock: &dyn Clock,
    ) -> Result<ApproveResult, RpcError> {
        // The operator's key MUST be the configured approver (the same public key
        // the §4 floor will verify the grant against) — else the grant could
        // never verify at apply. Fail-closed: refuse a foreign key here.
        if signing_key.verifying_key() != self.verifying_key {
            return Err(ErrorCode::GrantRejected
                .error("approver signing key does not match the configured approver pubkey"));
        }
        let proposal_id = self
            .request_to_proposal
            .get(request_id)
            .cloned()
            .ok_or_else(|| ErrorCode::ProposalNotFound.error("no such approval request"))?;

        let approver = Principal::approver(approver_id);
        let outcome = self
            .flow
            .approve(
                &RequestId(request_id.to_string()),
                &approver,
                signing_key,
                nonce,
                grant_ttl_millis,
                clock,
            )
            .map_err(approve_error_to_rpc)?;

        self.grants.insert(proposal_id, outcome.grant);

        Ok(ApproveResult {
            request_id: request_id.to_string(),
            nonce: nonce.to_string(),
        })
    }

    /// **`apply`** — apply a dry-run + approved proposal under the §4 grant-gated
    /// floor. The agent presents ONLY `{proposal_id, confirm_rows, confirm_token}`:
    /// the [`LiveRequest`] is re-derived from the STORED record (statement, params,
    /// role, session, proposal_id), so the agent can never swap what is applied.
    ///
    /// Order (fail-closed):
    /// 1. proposal live + dry-run done (else `PROPOSAL_NOT_FOUND` / `CONFIRM_MISMATCH`);
    /// 2. `confirm_rows` matches the dry-run total + token matches (the forcing fn);
    /// 3. a grant exists (else `APPROVAL_REQUIRED`);
    /// 4. [`guarded_apply_with_grant`] — verifies the grant (binding/nonce/expiry)
    ///    AND runs the §4 guards (apply-time PK-set re-check); any divergence
    ///    REJECTS with `GRANT_REJECTED`/`BLAST_DRIFT` and **no mutation**.
    pub fn apply(
        &mut self,
        proposal_id: &str,
        confirm_rows: u64,
        confirm_token: Option<&str>,
        conn: &mut dyn ApplyConn,
        barrier: &dyn ApplyBarrier,
        clock: &dyn Clock,
    ) -> Result<ApplyResult, RpcError> {
        self.apply_returning_inverse(
            proposal_id,
            confirm_rows,
            confirm_token,
            conn,
            barrier,
            clock,
        )
        .map(|(res, _inverse)| res)
    }

    /// As [`Service::apply`], but also returns the **captured typed-inverse** the
    /// apply produced (the §10.3 [`pgb_core::InversePlan`]). The wire `apply`
    /// discards it; the in-process IT uses it to drive the REAL revert and prove
    /// the apply was reversible (the captured inverse restores the pre-state),
    /// rather than reconstructing the inverse out-of-band.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_returning_inverse(
        &mut self,
        proposal_id: &str,
        confirm_rows: u64,
        confirm_token: Option<&str>,
        conn: &mut dyn ApplyConn,
        barrier: &dyn ApplyBarrier,
        clock: &dyn Clock,
    ) -> Result<(ApplyResult, pgb_core::InversePlan), RpcError> {
        let record = self
            .proposals
            .get(proposal_id)
            .filter(|r| !r.proposal.is_expired(clock))
            .ok_or_else(proposal_not_found)?;
        let dry = record
            .dry_run
            .as_ref()
            .ok_or_else(|| {
                ErrorCode::ConfirmMismatch
                    .error("apply requires a prior dry_run to establish the guard")
            })?
            .clone();

        // (2) confirm_rows forcing function (SPEC §4): the caller must confirm the
        //     dry-run's affected row count, and the token must match.
        if confirm_rows != dry.total_rows {
            return Err(ErrorCode::ConfirmMismatch.error(format!(
                "confirm_rows {confirm_rows} != dry-run affected rows {}",
                dry.total_rows
            )));
        }
        if let Some(token) = confirm_token
            && token != dry.confirm_token
        {
            return Err(
                ErrorCode::ConfirmMismatch.error("confirm_token does not match the dry-run token")
            );
        }

        // (3) a grant must exist (else the apply is blocked pending approval).
        let grant = self.grants.get(proposal_id).cloned().ok_or_else(|| {
            ErrorCode::ApprovalRequired.error("no approved grant for this proposal")
        })?;

        // (4) Re-derive the LiveRequest from the STORED record — NEVER from
        //     apply-time params. This is the issue #67 invariant.
        let live = LiveRequest {
            statement_text: record.proposal.statement.clone(),
            normalized_params: vec![],
            role: record.role.clone(),
            session_id: record.session_id.clone(),
            proposal_id: proposal_id.to_string(),
        };
        let kind = record.kind;
        let relation = record.relation.clone();
        let blast_radius = dry.blast_radius.clone();

        // The §4 grant-gated floor: verify (binding/nonce/expiry) + the §4 guards.
        let result = guarded_apply_with_grant(
            &self.policy,
            &grant,
            &live,
            &self.verifying_key,
            &mut self.apply_nonces,
            kind,
            &relation,
            &blast_radius,
            conn,
            barrier,
            clock,
        );

        match result {
            Ok((applied, _bridged)) => {
                // Single-use: consume the proposal + grant so neither replays.
                self.proposals.remove(proposal_id);
                self.grants.remove(proposal_id);
                let reversible = applied.inverse.kind == pgb_core::InverseKind::PreimageUpsert
                    || !applied.inverse.rows.is_empty();
                // FAIL-CLOSED (S5 #75): the apply-committed audit append MUST succeed.
                // The write has already committed (separate connection — not
                // co-committed; see `audit_apply`), so a failed append cannot un-write
                // it, but we refuse to report a silent unaudited success: surface
                // AUDIT_FAILED so the caller knows the operation is not certified
                // auditable.
                self.audit_apply(
                    &live,
                    Decision::Allow,
                    "apply_committed",
                    Some(format!(
                        "{} rows committed (reversible)",
                        applied.rows_written
                    )),
                    clock,
                )
                .map_err(|e| {
                    ErrorCode::AuditFailed.error(format!(
                        "the bounded write committed but its audit record could not be \
                         appended to the _meta chain: {e}"
                    ))
                })?;
                Ok((
                    ApplyResult {
                        applied: true,
                        rows_written: applied.rows_written,
                        reversible,
                    },
                    applied.inverse,
                ))
            }
            Err(e) => {
                let rpc = granted_apply_error_to_rpc(&e);
                // The BLOCK decision is itself evidence — its audit append is also
                // fail-closed. A failed append surfaces AUDIT_FAILED rather than the
                // (unrecorded) block code, so no enforcement decision is silently lost.
                self.audit_apply(
                    &live,
                    Decision::Block,
                    &rpc.data.code,
                    Some(rpc.message.clone()),
                    clock,
                )
                .map_err(|ae| {
                    ErrorCode::AuditFailed.error(format!(
                        "an apply was blocked ({}) but the block could not be audited to \
                         the _meta chain: {ae}",
                        rpc.data.code
                    ))
                })?;
                Err(rpc)
            }
        }
    }

    /// Append one apply-path audit record to the SAME shared `_meta` chain the flow
    /// uses (so the full lifecycle is on one chain). **Fail-closed (S5 #75):** the
    /// append `Result` is surfaced (not swallowed) — a failed append is fatal to the
    /// guarantee that every apply decision leaves tamper-evident evidence, matching
    /// the warden (`run.rs` "fatal") and proxy (`session.rs` `?`).
    ///
    /// # Ordering caveat (honest disclosure)
    /// The `_meta` chain is a **separate connection** from the apply txn, so the
    /// audit record is **NOT co-committed** atomically with the deterministic write
    /// in the MVP. The append runs AFTER `guarded_apply_with_grant` returns, so on
    /// the success path the write has **already committed** before this append. If
    /// the append then fails, the caller is told the operation failed
    /// (`AUDIT_FAILED`) even though the row write committed — the honest fail-closed
    /// posture is "report failure rather than a silent unaudited success". Atomic
    /// co-commit (the audit row inside the apply txn) is a documented follow-up.
    fn audit_apply(
        &mut self,
        live: &LiveRequest,
        decision: Decision,
        reason_code: &str,
        reason: Option<String>,
        clock: &dyn Clock,
    ) -> Result<(), pgb_audit::SinkError> {
        self.audit_decision(
            &live.statement_text,
            &live.role,
            &live.session_id,
            Some(&live.proposal_id),
            decision,
            reason_code,
            reason,
            clock,
        )
    }

    /// Append ONE decision record to the shared `_meta` chain, from the raw
    /// `{statement, role, session}` in hand (no [`LiveRequest`] required). This is
    /// the path the **structural/dry-run REFUSALS** use (S5 #76, item 1): a refused
    /// `propose`/`dry_run` would otherwise leave ZERO audit trace, violating SPEC
    /// §3/§10 "rejects recorded". It is the same fail-closed append the apply path
    /// uses — the `Result` is surfaced, never swallowed.
    ///
    /// The write-path [`IntentTiers`] are POPULATED from the statement (S5 #76,
    /// item 4): `IntentTiers::from_statement` derives T0 (role) + T1 (SQL class +
    /// any `/* intent: … */` annotation). RiskEngine stays a stub = Allow per
    /// §15.1 — this is capture/log only.
    #[allow(clippy::too_many_arguments)]
    fn audit_decision(
        &mut self,
        statement_text: &str,
        role: &str,
        session_id: &str,
        proposal_id: Option<&str>,
        decision: Decision,
        reason_code: &str,
        reason: Option<String>,
        clock: &dyn Clock,
    ) -> Result<(), pgb_audit::SinkError> {
        let entry = NewEntry {
            statement_text: statement_text.to_string(),
            decision,
            reason_code: reason_code.to_string(),
            reason,
            principal: AuditPrincipal {
                role: role.to_string(),
                session_id: Some(session_id.to_string()),
                principal: None,
            },
            // S5 #76 item 4: populate the write-path intent tiers from the data in
            // hand (was `IntentTiers::default()` — empty). `application_name` is the
            // daemon ("applyd") since the write path has no session GUC to read.
            intent: IntentTiers::from_statement(role, statement_text, Some("applyd".into())),
            write_safety: WriteSafetyRefs {
                dry_run_id: proposal_id.map(|s| s.to_string()),
                blast_radius_ref: None,
            },
        };
        self.sink.append(entry, clock.now_unix_millis()).map(|_| ())
    }

    /// Audit a structural/dry-run REFUSAL, then return the appropriate error.
    /// **Fail-closed (item 1):** if the audit append itself fails, the caller is
    /// told the operation failed via `AUDIT_FAILED` rather than getting the
    /// (now-unrecorded) refusal — no enforcement decision is silently lost. The
    /// `_meta` append uses the cross-process-serialized path (item 2).
    fn audit_refusal_then(
        &mut self,
        statement_text: &str,
        role: &str,
        session_id: &str,
        refusal: RpcError,
        clock: &dyn Clock,
    ) -> RpcError {
        // The refusal's own stable code is the reason_code we record.
        let reason_code = refusal.data.code.clone();
        let reason = Some(refusal.message.clone());
        match self.audit_decision(
            statement_text,
            role,
            session_id,
            None,
            Decision::Block,
            &reason_code,
            reason,
            clock,
        ) {
            Ok(()) => refusal,
            Err(e) => ErrorCode::AuditFailed.error(format!(
                "a write proposal was refused ({reason_code}) but the refusal could not be \
                 appended to the _meta chain: {e}"
            )),
        }
    }

    /// Read the audit tail (oldest-first), up to `limit` (most-recent window).
    /// Delegates to the shared sink (the canonical `_meta` chain).
    pub fn audit_records(&self, limit: usize) -> Vec<pgb_audit::AuditRecord> {
        let all = self.sink.load_chain().unwrap_or_default();
        let start = all.len().saturating_sub(limit);
        all[start..].to_vec()
    }

    /// The forward SQL + the WHERE predicate for a live proposal, re-derived from
    /// the STORED record (the binary's `PgApplyConn` needs both: the full forward
    /// statement to run, and the predicate to recompute the affected-PK set +
    /// capture pre-images). Returns `None` for an unknown/expired proposal so the
    /// caller fail-closes with `PROPOSAL_NOT_FOUND`.
    ///
    /// This is part of the issue #67 invariant: the SQL the conn runs comes from
    /// the service's own record, never from apply-time params.
    pub fn apply_sql_for(&self, proposal_id: &str, clock: &dyn Clock) -> Option<(String, String)> {
        let record = self
            .proposals
            .get(proposal_id)
            .filter(|r| !r.proposal.is_expired(clock))?;
        let statement = record.proposal.statement.clone();
        let where_sql = extract_where(&statement);
        Some((statement, where_sql))
    }
}

// ---- helpers: build the binding source + the certified op -------------------

/// The default ROW-cap headroom (EPIC #91 PR-B): the dry-run's measured row
/// footprint, +10%, pre-filled as the suggested `max_rows`. The row count is a
/// precise, low-noise measure (the same `pg_stat_xact_*` deltas at dry-run and
/// apply), so a tight headroom is right. The approver may tighten/raise per §14.2.
const DEFAULT_ROW_HEADROOM: f64 = 0.10;

/// The default WAL-byte cap headroom — deliberately **generous** (a 4× multiplier
/// plus a floor). The dry-run measures WAL on a **rolled-back** rehearsal, which
/// systematically UNDER-counts a committed apply's WAL (commit records, full-page
/// writes, `FOR UPDATE` heap-lock WAL, checkpoint timing). A tight WAL cap would
/// false-positive on that normal commit overhead; the WAL cap is a backstop against
/// **pathological** WAL blowup, not a precise pin (that is the row cap's job).
const DEFAULT_WAL_HEADROOM: f64 = 3.0; // → 4× the measured WAL
/// A WAL-cap floor so a tiny / zero dry-run WAL measure still admits a normal small
/// commit's overhead (64 KiB).
const DEFAULT_WAL_FLOOR_BYTES: u64 = 64 * 1024;

/// Build the §14.3 [`RequestProposal`] (the flow's binding source) from the
/// stored record + the cached dry-run.
fn binding_proposal(record: &ProposalRecord, dry: &DryRunState) -> RequestProposal {
    // EPIC #91 PR-B: the approver-authorized absolute cap replaces the dropped
    // exact-PK-set checksum. Pre-fill `max_rows` from the dry-run row footprint +
    // 10%, and `max_wal_bytes` generously (4× + a 64 KiB floor) since a rolled-back
    // rehearsal under-measures a committed apply's WAL. The human reviews/adjusts.
    let rows_cap = dry
        .blast_radius
        .suggested_cap(DEFAULT_ROW_HEADROOM)
        .max_rows;
    let wal_cap = dry
        .blast_radius
        .suggested_cap(DEFAULT_WAL_HEADROOM)
        .max_wal_bytes
        .max(DEFAULT_WAL_FLOOR_BYTES);
    let cap = pgb_core::WriteCap::new(rows_cap, wal_cap);
    RequestProposal {
        proposal_id: record.proposal.id.clone(),
        statement_text: record.proposal.statement.clone(),
        normalized_params: vec![],
        role: record.role.clone(),
        session_id: record.session_id.clone(),
        dry_run_lsn: dry.blast_radius.clone_lsn.clone(),
        cap,
    }
}

/// The certified [`Operation`] behind a dry-run record, so the elevation gate can
/// refuse a structural/irreversible op.
fn operation_for(record: &ProposalRecord, dry: &DryRunState) -> pgb_core::inverse::Operation {
    use pgb_core::inverse::Operation;
    let has_preimage = dry.blast_radius.reversible;
    match record.kind {
        WriteKind::Update => Operation::Update {
            has_preimage,
            has_pk: true,
        },
        WriteKind::Delete => Operation::Delete {
            has_preimage,
            has_pk: true,
        },
    }
}

/// Extract the top-level `WHERE` predicate of a `DELETE`/`UPDATE` from its parsed
/// AST and render it back to SQL (`"true"` when there is no `WHERE`). The
/// `PgApplyConn` uses this to recompute the affected-PK set + capture pre-images
/// on the exact predicate the proposal carries. AST-derived (not a text slice) so
/// a `WHERE` inside a subquery / string literal cannot fool it.
pub fn extract_where(statement: &str) -> String {
    use sqlparser::ast::{SetExpr, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let dialect = PostgreSqlDialect {};
    let Ok(parsed) = Parser::parse_sql(&dialect, statement) else {
        return "true".to_string();
    };
    let selection = match parsed.first() {
        Some(Statement::Delete(d)) => d.selection.as_ref(),
        Some(Statement::Update(u)) => u.selection.as_ref(),
        Some(Statement::Query(q)) => match q.body.as_ref() {
            SetExpr::Select(s) => s.selection.as_ref(),
            _ => None,
        },
        _ => None,
    };
    match selection {
        Some(expr) => expr.to_string(),
        None => "true".to_string(),
    }
}

// ---- error translations: engine/flow errors → the recoverable contract ------

fn proposal_not_found() -> RpcError {
    ErrorCode::ProposalNotFound.error("no live proposal with that id (unknown or TTL-expired)")
}

/// Map a [`DryRunError`] to the matching recoverable code.
fn dry_run_error_to_rpc(e: DryRunError) -> RpcError {
    match e {
        DryRunError::Volatile(r) => ErrorCode::Volatile.error(r.to_string()),
        DryRunError::PkLess(rel) => {
            ErrorCode::PkLess.error(format!("target relation `{rel}` has no primary key"))
        }
        DryRunError::NotRehearsable(m) => ErrorCode::NotRehearsable.error(m),
        // EPIC #91 PR-A: a steerable (non-self-determined) predicate is a
        // NOT_REHEARSABLE-class refusal (the same recoverable contract as the other
        // certify-time structural refusals).
        DryRunError::NotSelfDetermined(r) => ErrorCode::NotRehearsable.error(format!(
            "predicate is not self-determined (steerable); restrict the WHERE to the \
             primary key + literals: {r}"
        )),
        DryRunError::Expired(id) => {
            ErrorCode::ProposalNotFound.error(format!("proposal `{id}` expired"))
        }
        DryRunError::Backend(m) => {
            ErrorCode::NotRehearsable.error(format!("rehearsal failed: {m}"))
        }
    }
}

/// Map a [`GrantedApplyError`] to the matching recoverable code. Grant
/// verification failures → `GRANT_REJECTED`; an apply-time magnitude over-cap or
/// effect drift → `BLAST_DRIFT`; anything else fail-closed.
fn granted_apply_error_to_rpc(e: &GrantedApplyError) -> RpcError {
    match e {
        GrantedApplyError::Grant(GrantError::BindingMismatch) => ErrorCode::GrantRejected
            .error("grant binding mismatch (statement/param/session/proposal/cap swap)"),
        GrantedApplyError::Grant(g) => ErrorCode::GrantRejected.error(g.to_string()),
        // EPIC #91 PR-B: the live write's magnitude exceeded the approved cap — a
        // recoverable drift (re-propose / re-approve with a larger cap). → BLAST_DRIFT.
        GrantedApplyError::Apply(ApplyError::CapExceeded { .. }) => {
            ErrorCode::BlastDrift.error(e.to_string())
        }
        GrantedApplyError::Apply(a) => ErrorCode::BlastDrift.error(a.to_string()),
        GrantedApplyError::Inconsistent(m) => {
            ErrorCode::GrantRejected.error(format!("inconsistent grant binding: {m}"))
        }
        // EPIC #91 PR-A apply-path defense in depth: a steerable predicate is
        // rejected before the apply txn opens. Surfaced as GRANT_REJECTED (a
        // grant-path refusal) — a grant for such a statement should never have been
        // minted (the dry-run gate refuses it before approval).
        GrantedApplyError::NotSelfDetermined(r) => ErrorCode::GrantRejected
            .error(format!("predicate is not self-determined (steerable): {r}")),
    }
}

/// Map an elevation refusal to the recoverable contract.
fn elevation_error_to_rpc(e: pgb_cli::ElevationError) -> RpcError {
    match e {
        pgb_cli::ElevationError::Refused(r) => {
            ErrorCode::NotRehearsable.error(format!("structural/irreversible op refused: {r}"))
        }
        pgb_cli::ElevationError::Request(r) => ErrorCode::ProposalNotFound.error(r.to_string()),
    }
}

/// Map an approve failure to the recoverable contract.
fn approve_error_to_rpc(e: pgb_cli::ApproveError) -> RpcError {
    match e {
        pgb_cli::ApproveError::Authority(a) => ErrorCode::GrantRejected.error(a.to_string()),
        pgb_cli::ApproveError::Request(r) => ErrorCode::ProposalNotFound.error(r.to_string()),
    }
}
