# pg_bumpers — Components

A per-crate map of what exists in the tree today. Source of truth: [`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8); the docker→local-PG18 pivot is in [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md).

**Status.** S0 (skeleton/WALL/core/contracts/gate) + S1 (pgwire/audit/proxy) + S2 (clone dry-run + governance) are merged and green on Postgres 18. S3 (guarded apply + typed-inverse) is in progress. S4 (warden/MCP/policy-wiring/audit-anchor/read-gates/CLI-approval), S5 (benchmark + marquee MCP-bypass repro), and the real LLM gating engine are upcoming/fast-follow. The `RiskEngine` is an `Allow`-only stub in the MVP — the **deterministic floor**, not the risk plane, is the v1 safety guarantee.

**Honesty posture (SPEC §1).** Writes are bounded + reversible (zero catastrophic data-loss false-negatives *by construction*, via the closed certified-action set and PK-set guard). Reads are **bounded disclosure** — a per-role byte/row budget then a hard cutoff — plus best-effort detection; never "zero", never "impossible". The audit chain is **tamper-evident**, not tamper-proof.

The Cargo workspace (`Cargo.toml`) members: `crates/{proxy,warden,core,policy,clone-orchestrator,pgwire,audit,cli,mcp,applyd}` plus the throwaway `spikes/fidelity` harness. The MCP server (`crates/mcp`, binary `pgb-mcp`) is a Rust workspace member — single-language (the old TS `mcp/server` was removed in EPIC #83). SQL + pg_hba assets live under `deploy/` and `crates/audit/sql/`.

---

## core (`crates/core`)

The dependency-light, **DB-free** crate holding the one-way-door contracts every other crate builds on (`crates/core/src/lib.rs`). All gating-relevant types are deterministic and test-injectable.

- **`clock`** — the `Clock` trait with `now_unix_millis()` (stamping only) and `monotonic_millis()` (gating). `SystemClock` is the only place a real clock is read; `MockClock` (with `starting_at`/`advance`/`set_unix_millis`) is the advanceable test clock. Tests assert the monotonic reading never moves on a wall-clock jump and that clones share one counter.
- **`barrier`** — the `ApplyBarrier` seam (`pause_point(label)`) that sits between the dry-run checksum and the apply-time checksum. `NoopBarrier` is the production zero-sized no-op; `ClosureBarrier` (an `FnMut`, crossing-counted) lets the drift/TOCTOU tests mutate world state mid-flight to prove the guard aborts.
- **`blast_radius`** — the `BlastRadius` dry-run record plus `Affected`, `TriggerFired`, `LockHeld`, `LockMode` (ordered weakest→strongest), `ConstraintViolation`. Pure data + serde; a round-trip test pins the §10.1 sample JSON byte-shape, and `computed_max_lock_mode`/`computed_total_rows` cross-check the record.
- **`pk_checksum`** — the affected-PK-set checksum (the guard's basis, §10.2): `PkValue` (typed: `Int`/`Text`/`Bytes`/`Null`), `PkTuple` (ordered composite key), `PkSetBuilder` (`for_relation`/`pk_less`/`push`/`finalize`), `PkChecksum` (`sha256:…`), `ChecksumError`. Typed + length-prefixed SHA-256 encoding; order-independent over rows, order-significant within a tuple. The headline test: same row *count*, different PKs ⇒ different checksum. PK-less ⇒ `ChecksumError::Refused`, **no `ctid` fallback**.
- **`inverse`** — typed-inverse capture + the **default-deny certified-action set** (§10.3). `InverseKind` (`PreimageUpsert`/`Insert`/`None`, serde-pinned), `InverseRow`/`InversePlan` (per-row pre-image + FK order), `NotRestored` (sequences / trigger side-effects / NOTIFY — documented + asserted). `certify(&Operation) -> Result<CertifiedAction, RefusedOp>` is the single choke point: only `BoundedUpdate`/`BoundedDelete`/`NonVolatileInsert` are allowed; the default arm refuses (`Truncate`/`Drop`/`Alter`/`VolatileDefaultInsert`/`DeleteWithoutPreimage`/`PkLessTable`/`NotCertified`). A property test sweeps the op space and asserts exactly three shapes pass.
- **`session`** — `TrustLevel` (`Untrusted < Agent < Operator`, fail-closed floor = `Untrusted`), `TrustEvent`, and the **pure, tighten-only** `trust_transition(events, clock)` (folds with `min`; benign events impose no ceiling, so no ramp-and-strike). `SessionState` accumulates byte/row totals (saturating) and caps trust by the granted identity, never re-raising. A brute-force sweep over event sequences proves no sequence unlocks a bigger budget.

---

## policy (`crates/policy`)

The policy model + risk-plane **contracts** (`crates/policy/src/lib.rs`). The engines behind them are fast-follow; the safety guarantee in v1 is the deterministic floor, not this crate.

- **`config`** — the single `policy.yaml` model: `PolicyConfig` (`version`, per-role `RolePolicy` with `select_whitelist` + `RoleBudget` (single-shot + `WindowBudget` cumulative) + `AutonomyLevel`), plus §12.2 component config (`CloneConfig`/`CloneProvider` `none|dblab`, `ReplicaConfig`, `PitrConfig`) and the §14.3/§10.9 placeholders `ApproverSet` (CLI signing-key id) and `AuditAnchorConfig`. `load_from_yaml` parses **and** validates fail-closed: autonomy is capped at **L2** (L3 rejected, §15.1), budgets must be positive and coherent (window ≥ single-shot). The shipped `policy.example.yaml` loads and validates; tests pin the L3/zero/negative/empty-roles rejection cases.
- **`verdict`** — `Verdict` with the total order `ALLOW < ESCALATE < HOLD < BLOCK` (§13.4 R2). `tighter` = `max`, `is_at_least_as_tight_as` expresses the tighten-only floor check, `FLOOR_DEFAULT = Allow`. Serde round-trips uppercase.
- **`risk`** — the `RiskEngine` seam (`assess(&RiskInput) -> RiskVerdict`, signature `{sql, schema, measured_stats, intent_tiers}` → `{verdict, reason, confidence}`). `AllowStub` (aliased `StubRiskEngine`) **always returns `Allow`** (§11.5). `RiskVerdict::clamp_to_floor` enforces tighten-only *at the seam* — a buggy/prompt-injected engine that tries to loosen below the floor is clamped up. Tests cover the stub, object-safety, and both clamp directions.
- **`intent`** — the **T0–T2** intent-capture schema (§11.2): `IntentTiers` (`TierT0` role/purpose, `TierT1` SQL/class/application_name/GUCs/`IntentAnnotation`, `TierT2` observed session context), `parse_intent_annotation` (the `/* intent: … ticket: … actor: … */` parser, best-effort, never errors), `statement_class`. **Captured/logged only** in MVP — never a gate. Round-trip + best-effort-parse tests.
- **`grant`** — the §14.3 signed, single-use, time-boxed, **proposal-bound** grant. `GrantBinding` (statement, normalized params, role, session id, proposal id, dry-run LSN, blast-radius checksum, nonce, expiry) with a domain-separated, length-prefixed `binding_hash`. `GrantToken::{sign, verify_signature, verify_for_apply}` re-derives the binding from the live request and checks signature (Ed25519 `verify_strict`) + binding-equality + expiry (injected `Clock`) + single-use nonce (`NonceStore`/`InMemoryNonceStore`), consuming the nonce last. The five `T-grant-*` tests defeat SQL-swap, param-swap, cross-session replay, nonce-replay, and expiry.

---

## pgwire (`crates/pgwire`)

A **clean-room** PostgreSQL v3 wire codec (`crates/pgwire/src/lib.rs`) giving the proxy byte-level control of the FE/BE loop. Built from the protocol spec + the public `sqlparser` AST; no pgDog (AGPL) code consulted.

- **`codec`** — async length-prefixed framing over a `tokio` stream: `RawFrame`, `read_tagged_frame` (clean-EOF-aware), `read_startup_body`, `write_frame`, `MAX_FRAME_LEN` (1 GiB; over-length rejected fail-closed). `codec_async.rs` tests round-trips and truncated-frame errors.
- **`frontend`** — client→server messages: `StartupMessage`, `SslRequest`, and `FrontendMessage` (Query / Parse / Bind / Describe / Execute / Sync / Flush / Close / Terminate / SCRAM `p`-frames / PasswordMessage / Copy*). `Parse` exposes SQL + param types; `Bind` keeps the body raw for verbatim forwarding.
- **`backend`** — server→client `BackendMessage` (Authentication* incl. SASL, ParameterStatus, BackendKeyData, ReadyForQuery, ErrorResponse, NoticeResponse, RowDescription, DataRow, CommandComplete, PortalSuspended, Parse/Bind/CloseComplete, NoData, EmptyQueryResponse, Copy*) plus `TransactionStatus`.
- **`scram`** — SASL/SCRAM-SHA-256 message bodies: `AuthenticationSasl`/`SaslContinue`/`SaslFinal`, `SaslInitialResponse`, `SaslResponse`, and the `auth_type` discriminators. Models just the SASL payloads; enveloping lives in frontend/backend.
- **`detector`** — tag-only, allocation-free rejection: `classify_frontend_tag`/`classify_frontend_frame` reject simple `Query` ('Q', statement-stacking) and `Copy*` ('d'/'c'/'f') with `RejectReason`; `backend_starts_copy` flags 'G'/'H'/'W'. Fail-closed.
- **`classifier`** — advisory, **fail-closed** read-only SQL classification (`sqlparser-rs`, PostgreSQL dialect): `classify`/`classify_with_reason` → `Classification::{Read, NotRead}` + `NotReadReason`. Only a single provable SELECT/read-only CTE is `Read`; parse error, ≥2 statements, `SELECT … INTO`, data-modifying CTEs, and anything not positively proven read-only are `NotRead`.
- **`error`** — `ProtocolError`: every malformed frame is a hard error.
- `ProtocolMode::is_allowed_for_agent` enforces **extended-protocol-only**. Tests: `roundtrip.rs` (every message round-trips), `classifier.rs` (read/not-read corpus incl. stacking + data-modifying CTE), `detector.rs` (tag rejection).

---

## proxy (`crates/proxy`)

The inline, agent-only enforcement point — the project's core IP (`crates/proxy/src/lib.rs`). It terminates the agent's PostgreSQL connection (SCRAM-SHA-256 over TLS), originates a **separate** PG18 backend session as the WALL role `pgb_agent`, and drives the FE/BE loop with the deterministic-floor hooks wired in.

- **`tls`** — TLS termination on the agent listener via `rustls` (`server_config` from PEM, fail-closed on bad material; `rustls-pki-types` PEM parser).
- **`auth`** — clean-room **server-side SCRAM-SHA-256** (RFC 5802/7677, channel-binding `n`): `ScramVerifier`, `ScramServer` (`handle_client_first`/`handle_client_final`), `ScramError`. Constant-time proof compare; wrong password / tampered nonce fail closed. (MVP stores the agent password as configured material; storing only the verifier is a noted refinement.)
- **`enforce`** — the **pure, synchronous frontend-frame gate** `Enforcement::gate` → `GateDecision::{Allow, Reject, Block}` (`RejectKind::{SimpleQuery, Copy}`). Two layers: the tag gate (extended-only) rejects 'Q'/Copy*; the SQL gate classifies `Parse` text read-only. The **marquee block** is proven here as a plain call — `COMMIT; DROP SCHEMA public CASCADE` over simple-query is `Reject(SimpleQuery)`, and the same text smuggled into one `Parse` body is `Block(stacked_statement)` (belt-and-suspenders). A test documents the honest blind spot: `SELECT pg_sleep(30)` classifies as `Read` and is allowed, relying on `statement_timeout` downstream.
- **`session`** — `serve_connection`: startup + TLS negotiation (enforcing `require_tls`, no silent cleartext downgrade), agent SCRAM auth, backend origination with injected `SET statement_timeout`, then the enforced query loop with PostgreSQL extended-protocol skip-until-Sync error recovery.
- **`budget`** — the per-statement **byte/row mid-stream cutoff** (`Budget::charge_row` → `BudgetOutcome::{Within, Exceeded}`, `Cap::{Bytes, Rows}`). Inclusive caps; the breaching row is refused, not forwarded. `relay_until_ready` meters **both** `DataRow` ('D') and backend-COPY `CopyData` ('d') against the same budget and tears a metered COPY-out down on cutoff (proven by an in-memory backend test, no live PG needed).
- **`recorder`** — `Recorder` records every gate outcome (`allow`/`block`/`reject`) onto the shared hash-chained `pgb_audit` sink, stamped from `core::Clock`; a failed append is fatal (audit is evidence).
- **`config`/`main`** — `ProxyConfig`/`BackendTarget`/`TlsConfig`, budget lookup from `policy.yaml` (fail-closed on unknown role), and `resolve_require_tls`/`validate_tls` (TLS-required-but-unconfigured is a hard error). The binary is env-driven (`PGB_PROXY_LISTEN`, `PGB_PROXY_TLS_CERT`/`PGB_PROXY_TLS_KEY`, `PGB_PROXY_REQUIRE_TLS`, …).

**The six enforcement hooks** (lib.rs module docs): (1) extended-protocol-only; (2) read-only classification; (3) byte/row mid-stream cutoff; (4) `statement_timeout` injection; (5) fail-closed on any parse/enforcement uncertainty; (6) audit of every statement incl. rejects. The classifier is **advisory and foolable** (e.g. `nextval`/`pg_sleep`); the un-foolable backstops the proxy relies on are the WALL role, `statement_timeout`, and the byte/row cutoff.

**Testing.** Unit tests in `enforce`/`budget`/`config`/`auth`/`recorder` (incl. the metered-COPY-out cutoff against an in-memory backend). `tests/proxy_it.rs` (env-gated `PG_BUMPERS_IT=1`) drives the whole stack against PG18 — including the marquee `COMMIT; DROP SCHEMA public CASCADE` being blocked end-to-end.

---

## audit (`crates/audit`)

Append-only, **hash-chained**, tamper-evident audit of every statement incl. rejects (`crates/audit/src/lib.rs`). `record_hash = sha256(prev_hash ∥ canonical(payload))`.

- **`record`** — `AuditRecord` (sealed) / `AuditPayload` (the hashed part), `Decision` (`ALLOW`/`BLOCK`/`REJECT`, all recorded), `Principal`, `WriteSafetyRefs`, embedded `IntentTiers` (re-exported from policy), `GENESIS_PREV_HASH` (64 hex zeros). `canonical_bytes` is deterministic serde-JSON (fixed field order, `BTreeMap`s) so the same logical record always hashes identically.
- **`chain`** — `AuditChain` (stamps `seq`/`prev_hash`, seals) + `verify_chain` returning the **first** `ChainBreak` (`BadGenesis`/`HashMismatch`/`BrokenLink`/`SeqGap`). Two independent invariants: per-record self-consistency and linkage/sequence. `NewEntry` is the caller-facing "what happened" shape.
- **`sink`** — the append-only `Sink` trait (no update/delete by design) + `InMemorySink` (wraps an `AuditChain`), `SinkError`.
- **`pg`** — the Postgres **`_meta` sink** `PgSink` (default-on `pg` feature). Writes the **verbatim canonical bytes** (as `text`, not `jsonb`, to keep the digest reproducible) to `pgb_audit.audit_log`, reads back via `load_chain_mut`/`verify_mut`. Connects as the audit-**writer** role, never the audited principal. The DDL is `crates/audit/sql/10_audit_meta.sql`: append-only table (`UNIQUE(seq)`, `UNIQUE(record_hash)`), a BEFORE-UPDATE/DELETE deny trigger, and grants that `REVOKE` INSERT/UPDATE/DELETE from `pgb_agent` ("the audited cannot write audit", §3/§4/§10.9). The external WORM anchor + KMS key-separation are S4.

**Testing.** `tests/chain.rs` (tamper-injection / first-break detection). `tests/pg_meta_it.rs` (env-gated) proves the `_meta` sink appends, verifies, detects in-table tampering on read-back, and that the agent role's write attempt is denied (SQLSTATE 42501).

---

## clone-orchestrator (`crates/clone-orchestrator`)

The dry-run blast-radius engine + clone governance (`crates/clone-orchestrator/src/lib.rs`).

- **`proposal`** — `propose`/`propose_with_ttl` → `Proposal` (stable id, verbatim statement, optional `expected_rows`, TTL measured against the injected `Clock`; `DEFAULT_TTL_MILLIS` = 15 min). Expiry reads the monotonic clock only.
- **`predicate`** — AST-based volatile-predicate detection (`predicate_volatile_reason`, `VolatileReason`, `Volatility`, `FunctionVolatility` seam, `NONDETERMINISTIC_KEYWORDS`). Walks the WHERE AST; the non-deterministic special keywords (`now`/`CURRENT_TIMESTAMP`/…) are refused by name, every other function is resolved against `pg_proc.provolatile` (volatile/unknown ⇒ refuse, fail-closed); known catalog-less special forms (`coalesce`/`nullif`/…) are accepted.
- **`dry_run`** — `dry_run(proposal, &mut dyn Rehearsal, clock)` → `BlastRadius`. Pipeline (all fail-closed): TTL → `classify` (certified `Update`/`Delete` only via `WriteKind`; DDL/TRUNCATE/INSERT/unknown ⇒ `DryRunError::NotRehearsable`) → volatile-predicate refusal *before* any execution → rehearse in a `BEGIN … ROLLBACK` (nothing persisted) → **PK-less guard** (`DryRunError::PkLess`, no `ctid` fallback) → assemble the §10.1 record. The `Rehearsal` trait is the clone-provider seam.
- **guarded-apply seam** — `guard_decision(dry_run_checksum, apply_checksum)` → `DriftDecision::{Proceed, Abort}`: the guard is the **PK-set checksum, not the row count** (identical counts, different rows ⇒ abort). This is the drift-decision seam the S3 guarded-apply path builds on.
- **`provider`** — the clone-provider abstraction + **governance**:
  - `CloneProvider` trait (`provision`/`destroy`), `CloneHandle`, and `with_clone` — the funnel that asserts governance then **always tears down** (mandatory teardown on success *and* failure, §4). `CloneError`.
  - `CloneGovernance` (`assert_compliant`, fail-closed): a clone is prod-classified PII — encryption-at-rest, access-logged, documented owner + location, `DataClassification::ProdPii`. The local provider's `encryption_at_rest` is an honestly-disclosed documentary/`0700` flag, not in-process FDE.
  - Providers: `NoneProvider` (in-txn baseline on the primary, holds its locks for the rehearsal — the no-clone tradeoff), `LocalCloneProvider` (`provider/local.rs`, the moat: isolated `pg_basebackup` clone on a dedicated port, zero prod write/lock impact, `PrimaryRef`/`LocalCloneConfig`, ledger-first provision), `DblabProvider` (runtime-detected stub, fail-closed `Unavailable` — DBLab is out of scope for the local pivot).
  - **Reaper** (`provider/ledger.rs`, §10.7): an out-of-process `CloneLedger` recorded *before* any prod PII hits disk; `reap_orphans` (ledger-driven) and `reap_orphans_with_sweep` (+ filesystem sweep of `clone_root`) destroy any clone whose owner is dead and raise an `OrphanAlarm` (`ReapOutcome`). PID-reuse-hardened via `OwnerIdentity` (pid + start-time); the sweep gates on the owned `local-clone-*` name (not datadir content) so partial/empty mid-basebackup datadirs are reaped too. `OWNER_MARKER`, `write_owner_marker`.
  - **Parity** (`provider/parity.rs`, §4): `check_parity` diffs prod↔clone `RlsPolicy` + `ColumnGrant` snapshots → `ParityReport` (`is_parity`). Pure set-difference; catches missing/extra RLS *and* RLS-disabled-with-same-text, and looser column grants.

**Testing.** Rich unit tests against a mock `Rehearsal` (refusals, cascade rollups, assembly, the marquee no-WHERE UPDATE) and over the ledger/parity logic. Env-gated `tests/dry_run_it.rs` and `tests/clone_governance_it.rs` run against PG18: marquee preview leaving the primary unchanged, rehearse-on-clone with zero primary impact, and **killed-orchestrator / SIGKILL-during-basebackup leaves no surviving clone** (with the `examples/` orchestrator harnesses).

---

## WALL (`deploy/sql`, `deploy/hba`)

The deterministic floor's lowest two layers, asserted by attempting the denied action.

- **Layer 1 — hardened role** (`deploy/sql/10_hardened_role.sql`, idempotent, also mirrored under `deploy/init/`): the `pgb_agent` role is `LOGIN, NOSUPERUSER, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS`, **member of nothing** (every `pg_*` predefined role revoked, incl. `pg_read_all_data`/`pg_execute_server_program`/`pg_read_server_files`), no CREATE on `public`, PUBLIC EXECUTE revoked, no write grant anywhere (incl. database `TEMP` and the in-DB large-object write built-ins), and **SELECT only on an explicit whitelist** (`public.allowed_read` granted; `public.secret_data` not). The honest caveats are spelled out in-file: the role-level `search_path` pin is best-effort defense-in-depth (the authoritative pin is the proxy), and the WALL's real guarantee does not rely on `search_path`. `deploy/test/wall_matrix.sh` asserts each deny by attempting it.
- **Layer 0 — network boundary** (`deploy/hba/pg_hba.agent-boundary.conf.template`, rendered by `render-hba.sh`): the agent role may connect **only from the proxy host** (`PROXY_CIDR`); every other origin — including loopback and local sockets — is `reject` at `pg_hba` before auth. First-match ordering puts the allow line above the explicit default-deny rejects. The harness models "proxy host vs elsewhere" with `::1` (allowed) vs `127.0.0.1` (rejected). `deploy/hba/NETWORK-POLICY.md` documents the rule; without it a direct-to-DB agent bypasses all proxy enforcement + audit.

---

## pgb-mcp (`crates/mcp`)

The agent-facing intent/UX layer (SPEC §3 layer 3) — **cooperative, not a security boundary**; every tool executes *through* the deterministic floor. This is the native Rust **`pgb-mcp`**, the one and only deployable MCP server after EPIC #83 (the old TS `mcp/server` is removed). It serves the nine §11 tools over stdio via the `rmcp` SDK; the read path (`query`/`explain_plan`/`discover_schema`/`get_audit`) executes through `pgb-proxy`, the write path (`propose_write`/`dry_run`/`request_elevation`/`apply_write`) through the `pgb-applyd` Unix socket. The structured, recoverable block contract `{status:"blocked", code, reason, remedy, retryable}` defaults `retryable` to `false` (fail-closed). The catalog (`src/catalog.rs`) pins exactly nine tools (no `approve` — the signing-key hop stays out of the agent stdio); env-gated e2e tests (`tests/{write_path_e2e,read_path_e2e}.rs`) drive it end-to-end against a throwaway PG18. The deployable entrypoint is `src/bin/pgb_mcp.rs`.

---

## Other crates / harnesses

- **warden** (`crates/warden/src/main.rs`) — **stub**. Carries the S0 targeting predicate `may_terminate(is_agent_tagged)` (kill only agent-tagged sessions, never shared roles) + a test. The out-of-band polling loop + authenticated circuit breaker land in S4.
- **cli** (`crates/cli/src/main.rs`) — **stub**. Carries the single-use, proposal-bound `Grant::consume_for` seam + a test. The live operator approval flow lands in S4; the real grant cryptography already lives in `policy::grant`.
- **spikes/fidelity** (`spikes/fidelity`) — throwaway S0 fidelity-spike harness (`publish = false`); DB tests env-gated. Not production.

---

See also: [`docs/architecture.md`](architecture.md) (the four layers + data flow), [`docs/demo.md`](demo.md) (the marquee walkthrough with real test references), and [`docs/quickstart.md`](quickstart.md) (how to run each suite).
