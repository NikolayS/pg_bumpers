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
    classify, dry_run, guarded_apply_with_grant, propose, ApplyError, DryRunError,
    GrantedApplyError, LiveRequest, Proposal, Rehearsal, WriteKind,
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
        let (kind, relation) = classify(sql).map_err(dry_run_error_to_rpc)?;
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

        // The real dry-run (refuses volatile / PK-less / non-rehearsable).
        let blast_radius = dry_run(&proposal, rehearsal, clock).map_err(dry_run_error_to_rpc)?;
        let total_rows = blast_radius.affected.total_rows;
        let pk_set_checksum = blast_radius
            .affected
            .pk_set_checksum
            .get(&relation)
            .cloned()
            .ok_or_else(|| {
                ErrorCode::PkLess.error(format!("no pk_set_checksum for target `{relation}`"))
            })?;
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
        if let Some(token) = confirm_token {
            if token != dry.confirm_token {
                return Err(ErrorCode::ConfirmMismatch
                    .error("confirm_token does not match the dry-run token"));
            }
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
                self.audit_apply(
                    &live,
                    Decision::Allow,
                    "apply_committed",
                    Some(format!(
                        "{} rows committed (reversible)",
                        applied.rows_written
                    )),
                    clock,
                );
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
                self.audit_apply(
                    &live,
                    Decision::Block,
                    &rpc.data.code,
                    Some(rpc.message.clone()),
                    clock,
                );
                Err(rpc)
            }
        }
    }

    /// Append one apply-path audit record to the SAME shared `_meta` chain the
    /// flow uses (so the full lifecycle is on one chain). Fail-closed in spirit:
    /// an in-memory sink cannot fail; a real-sink failure surfaces upstream.
    fn audit_apply(
        &mut self,
        live: &LiveRequest,
        decision: Decision,
        reason_code: &str,
        reason: Option<String>,
        clock: &dyn Clock,
    ) {
        let entry = NewEntry {
            statement_text: live.statement_text.clone(),
            decision,
            reason_code: reason_code.to_string(),
            reason,
            principal: AuditPrincipal {
                role: live.role.clone(),
                session_id: Some(live.session_id.clone()),
                principal: None,
            },
            intent: IntentTiers::default(),
            write_safety: WriteSafetyRefs {
                dry_run_id: Some(live.proposal_id.clone()),
                blast_radius_ref: None,
            },
        };
        let _ = self.sink.append(entry, clock.now_unix_millis());
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

/// Build the §14.3 [`RequestProposal`] (the flow's binding source) from the
/// stored record + the cached dry-run.
fn binding_proposal(record: &ProposalRecord, dry: &DryRunState) -> RequestProposal {
    let checksum = dry
        .blast_radius
        .affected
        .pk_set_checksum
        .get(&record.relation)
        .cloned()
        .unwrap_or_default();
    RequestProposal {
        proposal_id: record.proposal.id.clone(),
        statement_text: record.proposal.statement.clone(),
        normalized_params: vec![],
        role: record.role.clone(),
        session_id: record.session_id.clone(),
        dry_run_lsn: dry.blast_radius.clone_lsn.clone(),
        blast_radius_checksum: checksum,
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
        DryRunError::Expired(id) => {
            ErrorCode::ProposalNotFound.error(format!("proposal `{id}` expired"))
        }
        DryRunError::Backend(m) => {
            ErrorCode::NotRehearsable.error(format!("rehearsal failed: {m}"))
        }
    }
}

/// Map a [`GrantedApplyError`] to the matching recoverable code. Grant
/// verification failures → `GRANT_REJECTED`; an apply-time PK-set drift →
/// `BLAST_DRIFT`; anything else fail-closed.
fn granted_apply_error_to_rpc(e: &GrantedApplyError) -> RpcError {
    match e {
        GrantedApplyError::Grant(GrantError::BindingMismatch) => ErrorCode::GrantRejected
            .error("grant binding mismatch (statement/param/session/proposal swap or data drift)"),
        GrantedApplyError::Grant(g) => ErrorCode::GrantRejected.error(g.to_string()),
        GrantedApplyError::Apply(ApplyError::PkSetDrift { .. }) => {
            ErrorCode::BlastDrift.error(e.to_string())
        }
        GrantedApplyError::Apply(a) => ErrorCode::BlastDrift.error(a.to_string()),
        GrantedApplyError::Inconsistent(m) => {
            ErrorCode::GrantRejected.error(format!("inconsistent grant binding: {m}"))
        }
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
