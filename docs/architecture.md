# pg_bumpers — Architecture

> Companion to the spec. Source of truth for *intent* is [`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8, build-frozen); recorded deviations live in [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md). This document describes the system **as it exists in the tree today** and flags what is stubbed or fast-follow.

## What this is

pg_bumpers lets AI agents read and write **production Postgres** safely. The honest guarantee is split by damage class (SPEC §1):

- **Writes (reversible damage):** 0 catastrophic false-negatives **by construction** — every applied write is bounded + reversible (data-loss prevented or undoable).
- **Reads (disclosure):** *not* zero, never "impossible." The structural guarantee is **bounded disclosure** (≤ a per-role byte/row budget, then cutoff/kill) + **best-effort detection**. The audit log is **tamper-evident**, not tamper-proof.

The safety guarantee is the **deterministic floor** — role wall + bounded blast radius + reversibility + byte/timeout cutoffs. It **never** depends on an LLM. The LLM risk-gate is tighten-only and is **fast-follow**; in the MVP the `RiskEngine` is a stub that always returns `Allow` (SPEC §11.5).

### Status snapshot (sprint plan, SPEC §7)

| Sprint | Scope | State |
|---|---|---|
| **S0** | Skeleton, WALL/network boundary, core seams, contracts, fidelity gate | **Merged, green on PG18** |
| **S1** | pgwire codec, read enforcement, audit chain, proxy | **Merged, green on PG18** |
| **S2** | Clone-orchestrator dry-run + clone governance | **Merged, green on PG18** |
| **S3** | Guarded apply + typed-inverse (reversibility vs golden state) | **In progress** |
| **S4** | Warden, MCP, policy wiring, audit anchor, deferred read gates (EXPLAIN/cumulative budget), CLI approval | **Upcoming** |
| **S5** | Focused deterministic benchmark + marquee MCP-bypass repro | **Upcoming** |
| — | LLM gating engine (read-path, trust, calibration) | **Fast-follow** (SPEC §15.2) |

---

## 1. The four layers + the mandatory network boundary

Architecture is **four layers plus one blocking network boundary** (SPEC §3). The boundary is layer 0 because without it an agent connects direct-to-DB and bypasses every other layer.

0. **NETWORK BOUNDARY (blocking).** The agent role's `pg_hba.conf` + network policy permit connections **only from the proxy host**. This is what makes the proxy meaningful — it closes the direct-to-DB hole that defeats app-layer-only protection.
1. **WALL — native Postgres roles/RLS (hardened).** The agent role is `NOINHERIT`, member of nothing, no superuser, no write grant, SELECT-whitelisted; `pg_read_all_data` + all `pg_*` predefined roles + `REPLICATION` + `PUBLIC EXECUTE` are revoked; `search_path` pinned; `dblink`/`postgres_fdw`/`COPY … PROGRAM`/`lo_*`/`pg_read_file` denied. "Not superuser" is insufficient. This is the un-foolable backstop.
2. **ENFORCEMENT — the Rust proxy (inline, agent-only endpoint) + the out-of-band warden.** The proxy forces the extended protocol (kills statement-stacking), rejects simple-query/COPY, is read-only, meters a byte/row mid-stream cutoff, injects `statement_timeout`, and hash-chains an audit record for every statement. The warden (out-of-band) kills only proxy-tagged / agent-role sessions and owns the circuit breaker.
3. **INTENT/UX — MCP server (cooperative).** Intent-typed tools that execute *through* the proxy. Not a security boundary by itself.
4. **WRITE-SAFETY (two impls, one guarantee = bounded + reversible).** *Baseline* **guarded apply** (no deps) — apply in a txn on the primary with a PITR fence + PK-set/row-count guard (abort before commit on overrun) + typed-inverse. *Upgrade* **DBLab thin-clone dry-run** (OPTIONAL, the moat) — rehearse on an isolated clone, preview the measured blast radius at zero prod impact, then guarded apply. A clone is **prod-classified data** and is governed (encryption, RLS/grant parity, mandatory teardown).

### The boundary diagram (SPEC §3)

```
   AI agent (MCP)         hostile/raw client
        |                        |
   (MCP tools)              (raw libpq)
        v                        v
  +-----------+   exec-thru  +==================+   pg_hba: ONLY from proxy host
  | MCP server|------------->|  Apache PROXY    |  read-only, replica-route,
  | propose/  |              |  EXPLAIN(advisory)|  byte+cumulative cutoff,
  | dry_run/  |              |  timeout, audit  |  extended-proto only, NO COPY
  | apply/... |              +========+=========+
  +-----+-----+                       | reads
        | dry_run/apply               v
        v                      +---------------+      +----------------+
  +-------------------+ clone  | DBLab CLONE   |      | Postgres REPLICA|
  | clone-orchestr.   |------> | (prod-PII!    |      +-------+--------+
  | PK-set guard,     |        |  governed:    |              |
  | PITR fence,       |        |  enc, RLS-par,|              |
  | typed-inverse,    |        |  teardown)    |     guarded apply
  | drift re-check    |        +---------------+        |  (fence+guard)
  +---------+---------+                                 v
            ^                                    Postgres PRIMARY
   WALL (hardened roles, member-of-nothing) ----------^  ^
            ^         +--------------+  watch+slots     |
            +---------|  WARDEN (oob)|--kill agent-tagged backends only
                      |  breaker(authn)|
                      +------+-------+
                             v
              hash-chained AUDIT + EXTERNAL ANCHOR (WORM/transparency log;
              signing key separated from operator; audited cannot write audit)
```

---

## 2. The crate map (as built)

A Cargo workspace (root [`Cargo.toml`](../Cargo.toml), resolver 2, edition 2024, rust 1.90, Apache-2.0). All crates are `publish = false`. The MCP server is the native Rust `pgb-mcp` ([`crates/mcp`](../crates/mcp)) — a workspace member, single-language (the old TS `mcp/server` was removed in EPIC #83); `proto/` is a placeholder.

```
crates/
  core/                 pgb-core      — DB-free domain types + one-way-door seams
  policy/               pgb-policy    — policy.yaml model, RiskEngine seam, intent, grant token
  pgwire/               pgb-pgwire    — clean-room FE/BE v3 codec + classifier + detector
  audit/                pgb-audit     — append-only hash-chained tamper-evident records
  clone-orchestrator/   pgb-clone-orchestrator — dry-run, blast radius, PK-set guard, providers
  proxy/                pgb-proxy     — inline enforcement endpoint (lib + pgb-proxy bin)
  warden/               pgb-warden    — out-of-band watchdog (STUB; live loop = S4)
  cli/                  pgb-cli       — operator approval flow (STUB; live flow = S4)
  mcp/                  pgb-mcp       — the deployable stdio MCP server (the nine §11 tools)
  applyd/               pgb-applyd    — the write-path Unix-socket daemon (guarded_apply floor)
spikes/fidelity/        — throwaway S0 fidelity-spike harness (publish=false, env-gated DB tests)
proto/                  — placeholder; no IDL generated in S0
deploy/                 — docker-compose.yml, local-stack.sh, smoke.sh, hba/, init/, sql/
```

### `pgb-core` — the contracts every crate builds on

DB-free and dependency-light by design ([`crates/core/src/lib.rs`](../crates/core/src/lib.rs)). These are the §15.3 **one-way-door seams** — expensive to retrofit, so they were pinned in S0:

- `clock` — the `Clock` trait + advanceable `MockClock` and `SystemClock`. No wall-clock read ever leaks into gating logic, so warden polls, time-to-auto-stop, and breaker timing are deterministic in tests (SPEC §10.4).
- `barrier` — `ApplyBarrier::pause_point()`, the deterministic hook between dry-run and apply that drift tests use to inject divergence (`NoopBarrier` in prod, `ClosureBarrier` in tests).
- `session` — `SessionState`/`TrustLevel` plus the **pure** `trust_transition(events, clock)` function. It is *tighten-only*: benign reads can only raise friction, never raise a floor bound (SPEC §11.1 anti ramp-and-strike).
- `blast_radius` — the `BlastRadius` dry-run record (`LockHeld`, `LockMode`, `TriggerFired`) — the §10.1 JSON shape.
- `pk_checksum` — `PkChecksum`/`PkSetBuilder`/`PkTuple`/`PkValue`: the affected-PK-**set** checksum that is the guard's basis. It catches row-identity drift a row count cannot (same count, different rows → abort).
- `inverse` — the typed-inverse capture format (`InverseKind`, `InversePlan`, `InverseRow`), the `CertifiedAction` set, and `RefusedOp`/`NotRestored` (the default-deny refused-op list; sequences/trigger-side-effects/NOTIFY are explicitly *not* restored).

### `pgb-policy` — policy model + the contracts seam

[`crates/policy/src/lib.rs`](../crates/policy/src/lib.rs). Pins the one-way-door policy contracts even though the engines behind them are fast-follow:

- `config` — the single **`policy.yaml`** model + validation: per-role SELECT whitelist, single-shot + per-window (`WindowBudget`) byte/row budgets, autonomy `L0–L2` (`AutonomyLevel`), the §12.2 component config (`ReplicaConfig`, `CloneConfig` with `CloneProvider: none|dblab`, `PitrConfig`), and the §14/§10.9 placeholders (`ApproverSet`, `AuditAnchorConfig`). Over-permissive configs (autonomy L3, negative/zero budgets) are **rejected**.
- `verdict` — the `Verdict` total order `ALLOW < ESCALATE < HOLD < BLOCK` (SPEC §13.4 R2) — the basis of *tighten-only*.
- `risk` — the `RiskEngine` trait (`{sql, schema, measured_stats, intent_tiers}` → `{verdict, reason, confidence}` via `RiskInput`/`RiskVerdict`/`MeasuredStats`). The only MVP impl is **`AllowStub`** (returns `Allow`). `RiskVerdict::clamp_to_floor` enforces tighten-only *at the seam*, so even a buggy or prompt-injected engine cannot loosen the outcome.
- `intent` — the **T0–T2** intent-capture schema (`TierT0`/`TierT1`/`TierT2`, `IntentTiers`, `ObservedStep`), the `/* intent: ticket: actor: */` annotation parser (`parse_intent_annotation`), and `statement_class`. **Captured/logged only** in the MVP — not acted on.
- `grant` — the §14.3 signed, single-use, time-boxed, **proposal-bound** grant: `GrantBinding` (the canonical binding hash), `GrantToken` (Ed25519 sign/verify), and a `NonceStore`/`InMemoryNonceStore` for single-use. The binding + re-verify-at-apply defeats SQL-swap, param-swap, cross-session replay, nonce-replay, and expiry (the five `T-grant-*` tests).

### `pgb-pgwire` — the wire-protocol codec

[`crates/pgwire/src/lib.rs`](../crates/pgwire/src/lib.rs). A **clean-room** v3 FE/BE codec (built from the protocol spec + the public `sqlparser` AST; no pgDog/AGPL code). Gives the proxy byte-level control so it can enforce the floor:

- `codec` — async length-prefixed framing (`RawFrame`, `read_tagged_frame`, `read_startup_body`, `write_frame`, `MAX_FRAME_LEN`).
- `frontend` / `backend` — typed FE and BE messages (`StartupMessage`, `SslRequest`, `FrontendMessage`, `BackendMessage`).
- `scram` — SASL/SCRAM-SHA-256 message bodies.
- `detector` — tag-only rejection of simple-query/COPY frames (`classify_frontend_tag`, `backend_starts_copy`, `RejectReason`).
- `classifier` — advisory, **fail-closed** read-only classification (`classify`, `Classification`, `NotReadReason`).
- `ProtocolMode::{Simple, Extended}` with `is_allowed_for_agent()` — fail-closed: only the **extended** protocol is allowed (kills `COMMIT; DROP SCHEMA …` statement-stacking).

### `pgb-audit` — tamper-evident hash chain

[`crates/audit/src/lib.rs`](../crates/audit/src/lib.rs). Append-only, hash-chained records for *every* statement (including blocked/rejected ones), linked by `record_hash = sha256(prev_hash ∥ canonical_encoding(record))` from `GENESIS_PREV_HASH`. Editing/deleting any mid-chain record breaks the chain; `verify_chain` returns the **first** broken link (`ChainBreak`).

- `record` — `AuditRecord`/`AuditPayload`, `Decision` (`ALLOW`/`BLOCK`/`REJECT`), `Principal`, `WriteSafetyRefs`, and the embedded `IntentTiers`.
- `chain` — `AuditChain` builder + `verify_chain` (the tamper detector).
- `sink` — the `Sink` trait + `InMemorySink`.
- `pg` (default-on `pg` feature) — `PgSink`, the Postgres `_meta` sink on an append-only table whose grants REVOKE write from the audited principal.

Time is always read from `core::Clock` upstream and passed in as a millisecond stamp, so the crate touches no wall clock. **Fast-follow (S4):** the external WORM **anchor** + KMS **key separation**.

### `pgb-clone-orchestrator` — dry-run, blast radius, guard, providers

[`crates/clone-orchestrator/src/lib.rs`](../crates/clone-orchestrator/src/lib.rs). The dry-run blast-radius engine, the PK-set guard, and the clone-governance providers:

- `proposal` — `propose` / `propose_with_ttl` → a `Proposal` (stable id + TTL measured against the injected `Clock`; `DEFAULT_TTL_MILLIS`).
- `dry_run` — `dry_run` against a `Rehearsal` backend: refuses volatile predicates and PK-less targets *before* executing, otherwise runs the statement in a `BEGIN … ROLLBACK` txn, measures the affected-PK set + cascades + triggers + locks + WAL + duration + LSN/staleness into a `BlastRadius`, then rolls back so nothing is persisted (`classify`, `AffectedTable`, `Measurement`, `WriteKind`, `DryRunError`).
- `predicate` — AST-walks the WHERE clause; nondeterministic keywords (`NONDETERMINISTIC_KEYWORDS`) are refused by name, every other function is resolved against `pg_proc.provolatile` (volatile/unknown ⇒ refuse, fail-closed): `predicate_volatile_reason`, `FunctionVolatility`, `Volatility`.
- `provider` — the clone-governance surface: `with_clone`, `LocalCloneProvider`/`DblabProvider`/`NoneProvider` (mapping the `clone.provider: none|dblab` selector), `CloneGovernance`/`DataClassification`/`OwnerIdentity`/`OWNER_MARKER`, RLS/column-grant **parity** checks (`check_parity`, `ParityReport`, `RlsPolicy`, `ColumnGrant`), and the orphan-clone reaper + alarm (`reap_orphans`, `OrphanAlarm`, `ReapOutcome`, `CloneLedger`). Two illustrative failure-path examples ship under [`crates/clone-orchestrator/examples/`](../crates/clone-orchestrator/examples) (`orphan_orchestrator.rs`, `crash_during_basebackup.rs`).

**The guard (top-level):** `guard_decision(dry_run_checksum, apply_checksum) -> DriftDecision::{Proceed, Abort}` — the guard is the PK-set **checksum**, not cardinality; identical counts with different rows still abort. This is the seam the S3 guarded-apply path drives.

> **S3 (in progress):** the guarded-apply path itself (PITR fence → txn with `statement_timeout ≈ 3× dry-run` → apply-time PK-set re-check → commit → typed-inverse from captured pre-image), wired against the `ApplyBarrier` seam and verified against a golden prod state, is being built now. The `dry_run`, `guard_decision`, `BlastRadius`, `PkChecksum`, and `InversePlan` pieces it composes are merged.

### `pgb-proxy` — the inline enforcement endpoint (the core IP)

[`crates/proxy/src/lib.rs`](../crates/proxy/src/lib.rs) (lib) + [`crates/proxy/src/main.rs`](../crates/proxy/src/main.rs) (the `pgb-proxy` binary). Terminates the agent's SCRAM-SHA-256-over-TLS connection, opens a **separate** backend connection as the hardened WALL role `pgb_agent`, and drives the FE/BE loop with the floor hooks wired in:

- `auth` — SCRAM-SHA-256 server side (clean-room RFC 5802/7677).
- `tls` — `rustls` (ring) termination on the agent endpoint.
- `config` — `ProxyConfig`, `BackendTarget`, `TlsConfig` (read from env in `main.rs`).
- `enforce` — `Enforcement`, `GateDecision`, `RejectKind`: extended-protocol-only, read-only classification, fail-closed.
- `budget` — `Budget`, `BudgetOutcome`: the single-shot byte/row mid-stream cutoff.
- `session` — `serve_connection`, `SessionError`: the per-connection FE/BE relay, including `relay_until_ready` which meters **every** bulk path (DataRow **and** COPY-out) against the budget.
- `recorder` — `Recorder`: wires each decision onto the `pgb-audit` chain.

**S1 deviations (recorded in SPEC.amendments.md, founder-approved):**
- SCRAM is **terminate-and-originate**, not passthrough — the proxy must own both wire sides to enforce; the backend session is the WALL role reachable only via the proxy.
- Agent-endpoint TLS is **required when configured** (no silent downgrade; direct `StartupMessage` without `SSLRequest` is rejected). The proxy→backend hop is plaintext over loopback, relying on the layer-0 boundary. A dev-only no-TLS mode is opt-in via `PGB_PROXY_REQUIRE_TLS=false`.
- The shipped binary's audit sink is the in-memory chain (`InMemorySink`); wiring `PgSink` into the running proxy is a follow-up.
- **Per-window cumulative budgets** are parsed into config but **inert in S1** — only the single-shot per-query cutoff is active. Cumulative rolling-window enforcement is **S4**. Do not claim per-window enforcement is live today.

The classifier is **advisory and foolable** (e.g. `pg_sleep`/`nextval` classify as reads). The un-foolable backstops the proxy relies on — WALL role, `statement_timeout`, byte/row cutoff — are all fail-closed and are exercised end-to-end against live PG18 in [`crates/proxy/tests/proxy_it.rs`](../crates/proxy/tests/proxy_it.rs), including the marquee `COMMIT; DROP SCHEMA public CASCADE` block (schema intact).

### `pgb-warden` and `pgb-cli` — stubs today

- **`pgb-warden`** ([`crates/warden/src/main.rs`](../crates/warden/src/main.rs)) is an **S0 stub**. It carries the targeting predicate (`may_terminate` — kill **only** agent-tagged sessions, never shared roles) plus its test. The live polling loop (`pg_stat_activity`/`pg_stat_statements`/lag + replication-slot monitoring, mockable interval) and the authenticated circuit breaker land in **S4**.
- **`pgb-cli`** ([`crates/cli/src/main.rs`](../crates/cli/src/main.rs)) is an **S0 stub** for the SPEC §14 MVP approval surface. It carries the single-use, proposal-bound grant-consumption seam (`consume_for` — wrong proposal id refused, replay refused) plus its test. The live operator approval flow (issuing the signed grant via the `pgb-policy` grant token + one generic webhook) lands in **S4**.

### MCP server and `proto/`

- **`crates/mcp`** (binary `pgb-mcp`) is the native Rust MCP server — the one and only deployable MCP server after EPIC #83 (the TS `mcp/server` is removed). It serves the nine §11 tools (`whoami`, `discover_schema`, `query`, `explain_plan`, `propose_write`, `dry_run`, `apply_write`, `request_elevation`, `get_audit`) over stdio via the `rmcp` SDK, with the fail-closed block contract `{status, code, reason, remedy, retryable}` (`retryable` defaults to false). It is cooperative, not a security boundary — the read path executes *through* `pgb-proxy`, the write path *through* the `pgb-applyd` socket, and result data can never widen capability. The binary entrypoint is [`crates/mcp/src/bin/pgb_mcp.rs`](../crates/mcp/src/bin/pgb_mcp.rs).
- **`proto/`** is a placeholder ([`proto/README.md`](../proto/README.md)). Nothing is generated from it in S0; the warden↔proxy breaker protocol and any cross-process schemas are added incrementally as the consuming code lands.

---

## 3. Request and data flow

### Read path (agent → proxy → WALL backend)

1. An agent connects to the proxy's agent endpoint (SCRAM-SHA-256 over TLS) — the **only** network path to the DB (layer 0 `pg_hba`: only-from-proxy host).
2. The proxy terminates SCRAM/TLS and opens a separate backend connection as the hardened WALL role `pgb_agent` (terminate-and-originate).
3. Each statement must use the **extended protocol**; simple-query and COPY frames are rejected (kills statement-stacking). The SQL is classified read-only (advisory); non-reads are blocked.
4. `statement_timeout` is injected on the backend session. The result stream (`DataRow` **and** COPY-out) is metered against the per-role single-shot byte/row budget and **cut off mid-stream** at the cap.
5. Every decision — allow, block, reject — is appended to the tamper-evident hash chain.

The un-foolable guarantees are the **WALL role + `statement_timeout` + byte/row cutoff**, all fail-closed. The classifier is defense-in-depth.

### Write path (propose → dry_run → guarded apply → revert)

1. **propose** — the candidate statement becomes a `Proposal` (stable id + TTL, measured against the injected `Clock`).
2. **dry_run** — rehearsed on a DBLab clone if present, else in a `BEGIN … ROLLBACK` txn on the rehearsal backend (the `clone.provider: none` baseline). Volatile/nondeterministic predicates and PK-less targets are **refused before executing**. Otherwise the affected-PK set, cascades, triggers, locks, WAL, duration, and LSN/staleness are folded into a `BlastRadius` and the txn is rolled back — nothing is persisted. Non-certified shapes (DDL/`TRUNCATE`/`INSERT`/…) are refused (default-deny).
3. **guarded apply** *(S3, in progress)* — `pg_create_restore_point` PITR fence → txn with `statement_timeout ≈ 3× dry-run` → **re-check** the apply-time affected-PK-set checksum against the dry-run checksum via `guard_decision` (any drift → `Abort` before commit; 0-tolerance) → commit. A typed-inverse is captured from the pre-image.
4. **revert** — the typed-inverse (`InversePlan`) undoes the write FK-ordered from the captured `{pk, before_image}` rows. **Documented gaps (tested):** sequences, trigger side-effects, and NOTIFY are explicitly *not* restored by the inverse.

The **guard is the PK-set checksum, not the row count** — identical cardinality with different rows still aborts (the predicate-flip blind spot). This is what makes "0 catastrophic write FN by construction" hold independent of any model.

---

## 4. Substrate: local Postgres 18 + graceful degradation

### The local-PG18 substrate (founder-approved pivot)

The SPEC's S0 plan called for a docker-compose stack as the test substrate. Docker image pulls are non-functional in this build environment (a host-level daemon networking fault — see SPEC.amendments.md for the full diagnosis). The **founder-approved** decision keeps `deploy/docker-compose.yml` as the **shipped user-facing artifact** (bumped to `postgres:18`), while the **live integration tests run against local Postgres 18** clusters via [`deploy/local-stack.sh`](../deploy/local-stack.sh) + [`deploy/smoke.sh`](../deploy/smoke.sh):

- Isolated throwaway PG18 clusters under a git-ignored `./.localstack/` on dedicated high ports (primary `54321`, replica `54322`, meta `54323`) so they never touch a cluster on 5432.
- Real streaming replication (`pg_basebackup -R` → `standby.signal` + `primary_conninfo`, verified via `pg_stat_replication` + a replicated row round-trip).
- A separate `meta` cluster hosts the append-only `_meta` audit DB.
- `deploy/smoke.sh` is env-gated on `PG_BUMPERS_IT=1`; the orchestrator/proxy/audit integration tests are likewise env-gated and skipped by a plain `cargo test`.

The deviation is **scoped to the test/dev substrate only** — it does not touch the deterministic floor (§11.1), the bounded + reversible guarantee (§12.1), or any product behavior. The graceful-degradation **bare-primary** baseline is still proven (default path runs no replica; replica added only when requested — exactly as `docker compose` vs `--profile replica` would behave). The shipped compose is statically validated with `docker compose config -q`; re-validating it live requires a Docker-healthy machine.

### Graceful degradation (SPEC §12)

pg_bumpers works against a **bare primary** (no replica, no DBLab); each added component upgrades capability without becoming a gate. The bounded + reversible guarantee is **invariant** across every configuration — only the preview/isolation *experience* improves. Components are runtime-detected from `policy.yaml`; the system states the active mode plainly and **never silently downgrades**.

| Component | Absent (baseline) | Present (upgrade) |
|---|---|---|
| **Replica** | reads route to the primary under stricter budgets/timeouts/warden (§10.8) | isolated reads on the replica |
| **DBLab** | **guarded apply** — txn on primary + PITR fence + PK-set/row-count guard + typed-inverse; bounded + reversible, no clone-drift (same txn) | **clone rehearsal (the moat)** — pre-flight blast-radius preview on an isolated clone, zero prod impact, then guarded apply |
| **WAL archiving / PITR** | typed-inverse is the undo (cheap) | + PITR restore-point as a last-resort fence |

**Honest recovery model (SPEC §1):** two distinct mechanisms — (a) **typed-inverse** = the cheap, fast default undo (UPDATE/DELETE pre-image); (b) **PITR restore-point** = last-resort, **requires the customer to run continuous WAL archiving + a tested restore**, with large RTO on big DBs. Do not market both as cheap "nine lives."

---

## 5. The deterministic floor vs the RiskEngine stub

This is the load-bearing posture of the whole system (SPEC §11.1, §11.5):

- **The floor is the guarantee.** Role wall (layer 1) + bounded blast radius + reversibility (layer 4) + byte/timeout cutoffs (layer 2). It is deterministic, non-bypassable, and involves **no model**. The benchmark/CI gates on the floor (SPEC §13.5).
- **The RiskEngine is a stub in the MVP.** `pgb_policy::AllowStub` (aliased `StubRiskEngine`) always returns `Allow`. The trait signature (`{sql, schema, measured_stats, intent_tiers}` → tighten-only verdict) and the T0–T2 intent schema are pinned now because they are §15.3 one-way doors that MVP code already touches — but the LLM gating engine itself (gating, read-path, trust level, calibration) is **fast-follow** (SPEC §15.2).
- **Tighten-only, enforced at the seam.** When the real engine lands it can only push toward `BLOCK` (using the `ALLOW < ESCALATE < HOLD < BLOCK` order); `RiskVerdict::clamp_to_floor` enforces this so even a buggy or prompt-injected engine cannot loosen the outcome. The risk asymmetry: an engine error is at worst a false-positive (blocked legitimate action), never a breach. That is precisely why a foolable model is acceptable *here* and nowhere load-bearing.

In the MVP, **T0–T2 intent is captured and logged only** (into the blast-radius/audit record) — never acted on. The honest claim is: writes are bounded + reversible by the floor; reads are bounded-disclosure by the floor; the LLM is not yet in the loop.

---

## References

- [`docs/spec/SPEC.md`](spec/SPEC.md) — the spec (v0.8). §1 (claim), §3 (architecture + diagram), §4 (impl), §7 (sprints), §10 (S0 artifacts), §11 (intent/risk), §12 (degradation), §13 (FP/FN), §14 (authorization), §15 (scope triage).
- [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md) — recorded deviations: the local-PG18 substrate pivot and the S1 proxy SCRAM/TLS/audit-sink decisions.
- [`docs/spec/decisions.md`](spec/decisions.md), [`docs/spec/fidelity-spike-report.md`](spec/fidelity-spike-report.md) — supporting records.
- [`deploy/README.md`](../deploy/README.md) — the dev/test stack runbook.
- [`docs/README.md`](README.md) — the docs index. [`docs/components.md`](components.md), [`docs/quickstart.md`](quickstart.md), [`docs/development.md`](development.md), [`docs/demo.md`](demo.md).
