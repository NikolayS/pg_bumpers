# pg_bumpers — SPEC amendments

Intentional, recorded deviations from `docs/spec/SPEC.md` (v0.8, build-frozen), per
`CLAUDE.md` §8 ("Intentional deviations: record in `docs/spec/SPEC.amendments.md` with
rationale") and the process spec (#1, sprint-review step). The SPEC is **not** edited in
feature PRs; deviations are logged here instead.

---

## S0 integration substrate — docker-compose retained as shipped artifact; live tests run on local Postgres 18

**SPEC sections touched:** §7 (S0: "compose — primary + replica + dblab") and §12
(graceful degradation: replica/DBLab/PITR all OPTIONAL; the bounded + reversible
guarantee is invariant). Also relevant: §4 (`_meta` audit DB), §10.8 (degraded mode, no
replica).

**Issue:** #4 (S0 dev/test stack).

### Deviation

The SPEC's S0 plan (§7) calls for a `docker-compose` stack as the substrate that every
integration test and the fidelity gate (#8) run against. We **keep
`deploy/docker-compose.yml` as the shipped artifact** for real users — and **bump its
image from the SPEC's example `postgres:16` to `postgres:18`** — but the **live**
integration tests in this build environment run against **local Postgres 18** clusters
(`postgresql@18` via Homebrew: `initdb` / `pg_basebackup` / `pg_ctl`), driven by
`deploy/local-stack.sh` + `deploy/smoke.sh`, **not** against docker containers.

### Rationale

Docker image pulls are **non-functional** in the pg_bumpers build environment. The
Docker Desktop VM (4.23.0) **and** a freshly-installed Colima VM (engine 27.4.0) both
hang `docker pull` at **zero blob bytes**, even though `curl https://registry-1.docker.io/v2/`
succeeds (HTTP 401) from inside the same VM. Ruled out: HTTP proxy (none), Tailscale
(not an exit node; Docker Hub routes via `en0`, and bringing Tailscale fully down did
not help), MTU (lowering the VM `eth0` to 1280 did not help), and dockerd
proxy/mirror config (clean). It is a **host-level Docker daemon networking fault**, not
fixable from the build session.

Founder-approved decision: rather than block S0, keep the compose as the user-facing
artifact and run S0's live tests on local Postgres 18. This keeps **every test real** —
real streaming replication (`pg_basebackup -R` → `standby.signal` + `primary_conninfo`,
verified via `pg_stat_replication` and a replicated row round-trip), real apply/inverse
— and unblocks S0 immediately. The fidelity GATE (#8) likewise runs for real against
local PG 18.

The deviation is **scoped to the test/dev substrate only**. It does not touch the
deterministic floor (§11.1), the bounded + reversible guarantee (§12.1), or any
product behavior. The graceful-degradation baseline (§12) is still proven: the default
path runs a **bare primary** (no replica), with the replica added only when requested —
exactly as `docker compose` (no profiles) vs. `--profile replica` would behave.

### What was built (issue #4, re-scoped)

- **`deploy/docker-compose.yml`** — shipped artifact. `postgres:18`; `primary` + `meta`
  always on; `replica` under profile `replica` (off by default → bare-primary baseline);
  `dblab` placeholder under profile `dblab`; healthchecks; `depends_on` ordering;
  `wal_level=replica` + replication-ready knobs. Statically validated with
  `docker compose -f deploy/docker-compose.yml config -q`.
- **`deploy/local-stack.sh`** (`up` / `down` / `status`) — isolated throwaway PG 18
  clusters under a git-ignored `./.localstack/` on **dedicated high ports**
  (primary 54321, replica 54322, meta 54323) so they never touch any cluster already on
  5432. Primary configured for streaming replication; replica built via `pg_basebackup
  -R`; `meta` a separate cluster hosting the append-only `_meta` audit DB. A
  clearly-marked include point reserves where the issue-#5 hardened-role WALL SQL
  attaches (no duplication of that work here).
- **`deploy/smoke.sh`** — env-gated on `PG_BUMPERS_IT=1`: asserts primary + meta
  reachable, replica in recovery and streaming (`pg_stat_replication`), and a replicated
  row round-trip within a bound. Non-zero exit on any failure; skips (exit 0) when the
  gate is unset.

### How to re-validate the compose live (on a docker-healthy machine)

On any machine with a working Docker daemon (can `docker pull postgres:18`):

```sh
# 1. Static parse (no pulls) — already enforced here:
docker compose -f deploy/docker-compose.yml config -q && echo COMPOSE_OK

# 2. Baseline — primary + meta healthy, replica absent (bare-primary baseline):
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps          # primary + meta healthy

# 3. Streaming replica — write on primary visible on replica; standby in pg_stat_replication:
docker compose -f deploy/docker-compose.yml --profile replica up -d
docker compose -f deploy/docker-compose.yml exec primary \
  psql -U postgres -c "SELECT application_name, state FROM pg_stat_replication;"

# 4. Tear down:
docker compose -f deploy/docker-compose.yml --profile replica --profile dblab down -v
```

When the compose is confirmed live, this amendment can be narrowed to "image bumped to
`postgres:18`; both substrates supported" — the local-PG substrate remains useful as the
fast, Docker-free dev/CI path.

---

## S1 proxy — SCRAM terminate-and-originate; TLS to the backend deferred (MVP-minimal)

**SPEC sections touched:** §3 (layer 2 proxy + layer 0 network boundary), §4 (proxy
enforcement hooks; "un-foolable guarantees = network-boundary + hardened role + read-only
+ statement_timeout + byte-cutoff"), §7 S1 ("pgwire termination incl. SCRAM auth
passthrough + TLS").

**Issue:** #22 (S1 proxy).

### Deviation

1. **SCRAM is terminated-and-originated, not passed through.** The SPEC's S1 line says
   "SCRAM auth **passthrough**." The proxy instead **terminates** the agent's
   SCRAM-SHA-256 handshake (authenticating the agent against the proxy's configured agent
   credential) and then **originates a separate backend connection** as the WALL role
   `pgb_agent`. True passthrough (relaying the agent's SCRAM proof to the backend so the
   backend authenticates the original principal) is not done in the MVP.

2. **Agent-endpoint TLS is *required when configured* (no silent downgrade); the
   proxy→backend hop is not TLS in the MVP.** The agent endpoint is TLS-terminated with
   `rustls` (ring). When TLS material (cert+key) is configured, TLS is **required**
   (`require_tls`, default-on whenever TLS is configured): a client `SSLRequest` is answered
   `'S'` and the connection proceeds over TLS — the proxy **never** answers `'N'` to
   downgrade to cleartext — and a client that opens with a **direct `StartupMessage`** (no
   `SSLRequest`) is **rejected** (FATAL `ErrorResponse` + close) rather than served in
   plaintext. A post-handshake check additionally refuses to proceed to auth/queries unless
   the stream is actually encrypted (fail-closed). Requiring TLS with no TLS material
   configured is a hard startup error.
   - **Dev-only no-TLS mode (explicit, not a fallback):** `PGB_PROXY_REQUIRE_TLS=false` (or
     simply running with no cert/key and `require_tls=false`) serves the agent endpoint in
     plaintext. This is an **opt-in** developer/test mode; it is never a silent downgrade of
     a TLS-configured deployment. Production sets cert+key and leaves `require_tls` on.
   - **Backend-hop TLS remains deferred (§3 layer-0 boundary):** the proxy→backend
     connection is plaintext over loopback, relying on the §3 layer-0 network boundary
     (pg_hba: only-from-proxy) for confidentiality/integrity on that hop. This is the **only**
     remaining TLS deferral.

3. **Audit sink is the in-memory hash chain in the binary.** The proxy records every
   statement (allow/block/reject) on a `pgb_audit` hash chain, but the shipped binary keeps
   that chain **in-process** (`InMemorySink`). Wiring the Postgres `_meta` sink
   (`pgb_audit::PgSink`, already built in #21) into the running proxy is a follow-up.

### Rationale

- **Terminate-and-originate is the natural shape of an enforcing proxy** and is what makes
  the enforcement hooks possible at all: to gate the extended protocol, classify SQL,
  meter the result stream, and inject `statement_timeout`, the proxy must own both wire
  sides. Passthrough would hand the backend a connection the proxy cannot fully mediate.
  The security guarantee does **not** weaken: the agent still proves a SCRAM credential to
  reach the proxy, and the backend session is the **hardened WALL role** reachable **only**
  via the proxy (the un-foolable backstops — WALL role + `statement_timeout` + byte/row
  cutoff — all hold). The agent→backend principal mapping is fixed (agent ⇒ `pgb_agent`),
  which is exactly the least-privilege intent.

- **Backend TLS is redundant with the network boundary on the loopback/private-link hop**
  the SPEC already mandates (layer 0). It is a config addition (point `rustls` at the
  backend) with no enforcement-logic impact, so it is deferred without weakening the model.

- **The in-memory chain proves the audit contract end-to-end** (allow + blocks/rejects
  recorded, the marquee `COMMIT; DROP SCHEMA` captured verbatim, `verify_chain()` holds —
  see the issue-#22 integration evidence). Persisting to `_meta` reuses the already-merged,
  already-tested `PgSink` and changes no proxy logic.

### Un-foolable enforcement actually proven (issue #22, against live PG18)

The classifier is **advisory and foolable** (e.g. `pg_sleep` classifies as a read). The
proxy therefore relies on the un-foolable backstops, all exercised in the env-gated
`crates/proxy/tests/proxy_it.rs` against the local-stack WALL role: extended-protocol-only
(the marquee `COMMIT; DROP SCHEMA public CASCADE` simple-query **BLOCKED**, schema intact),
read-only gate (UPDATE/DELETE/DDL/COPY blocked), byte/row **mid-stream cutoff** (large
SELECT cut at the per-role budget), `statement_timeout` (fires on `pg_sleep`), fail-closed
(parse failure blocked), and the hash-chained audit recording all of it.

**COPY-out cutoff — delivered, not deferred (label correction):** the byte/row cutoff is
enforced on **every** bulk path, not just `DataRow`. A backend-initiated COPY-out
(`CopyOutResponse` 'H' / `CopyData` 'd') is metered against the **same** per-role budget
and cut off (ErrorResponse to the client + the backend COPY torn down, fail-closed) the
moment it would exceed the cap. So even a classifier-mis-allowed `COPY … TO STDOUT`, or a
misbehaving/compromised backend, cannot stream bytes outside the budget — the cutoff is
genuinely un-foolable-via-classifier on the COPY message path
(`crates/proxy/src/session.rs::relay_until_ready`; unit-tested in `session.rs` and
exercised end-to-end in `proxy_it.rs`). Any prior reference to "CopyData-cutoff deferral"
is stale and should be disregarded.

**`per_window` budget caps — loaded into config, inert in S1:** the `RoleBudget::per_window`
struct fields (`window_secs`, `max_bytes`, `max_rows`) are parsed from config and appear in
the policy type, but the S1 proxy applies **only the single-shot per-query cutoff**
(`max_bytes` / `max_rows` on the `RoleBudget` root). The cumulative rolling-window
enforcement is a **Sprint 4 (S4) feature**; no session-level byte/row accumulator exists
yet. Demos and descriptions must not claim per-window enforcement is active in S1.

**SCRAM implementation notes (S1, in `crates/proxy/src/auth.rs`):** the proxy stores the
agent password as configured cleartext and derives the `SaltedPassword` / `StoredKey` /
`ServerKey` per-handshake (RFC 5802 §3). A production deployment should store **only the
SCRAM verifier** (salt + `StoredKey` + `ServerKey`), never the plaintext password; that
hardening is noted as a follow-up, not done in S1. Channel binding is not negotiated: the
`gs2-cbind-flag` in the `client-first-message` is `n` (no binding, per RFC 5802 §6), which
is correct since TLS is terminated at the proxy and the agent→proxy hop is already
encrypted at the transport layer — there is no inner `tls-server-end-point` to bind.

---

## S2 clone-orchestrator — no production generic-schema `ApplyConn`; the real impl is the hardcoded seed-schema seam

**SPEC sections touched:** §4 (guarded apply — the §4 flow runs against a real
`ApplyConn`), §7 S2/S3, §10.1–§10.3 (dry-run grant → guarded apply → typed-inverse).

**Issue:** #45 (production generic-schema `ApplyConn` — remains OPEN, scheduled for S4).

### Deviation

The `guarded_apply` engine (`crates/clone-orchestrator/src/apply.rs`) is **schema-agnostic
by construction**: it owns the §4 ordering and guard decisions and drives an `ApplyConn`
seam that owns the SQL. The SPEC implies a **production, generic-schema** `ApplyConn` that
works against an arbitrary customer schema. **No such production connection exists yet.**
The shipped real implementation is the **hardcoded seed-schema test seam** —
`PgApplyConn` in the env-gated integration tests (`crates/clone-orchestrator/tests/`,
`PG_BUMPERS_IT=1`) — bound to a **2-level seed schema** (`public.accounts` /
`public.entries`, single-int / composite-int PKs). The in-memory `MockConn` (unit tests)
is likewise hand-scripted per scenario. There is **no** generic SQL generator that maps an
arbitrary relation + predicate + cascade graph onto the §4 calls.

### Rationale

S2/S3 deliberately proved the **engine** (ordering, guards, fail-closed reconciliation,
typed-inverse, FK-ordered revert vs golden state) against a real but **bounded** schema,
rather than building a generic schema-introspecting `ApplyConn` (a large, separable piece
of work). The safety properties the engine enforces are schema-agnostic and are tested via
both the seed-schema `PgApplyConn` (real PG18) and the `MockConn` (every drift/timeout
injected deterministically). Productionizing the generic `ApplyConn` is tracked in **#45**
and scheduled for S4.

### Implication for the moat claim

"bounded + reversible by construction" is **honest and proven** for the certified op set
**restricted to the schemas the shipped `ApplyConn` supports** (single-target + the seed
schema's cascades). It is **not** yet a general production claim for an arbitrary customer
schema — that awaits the #45 generic `ApplyConn`. Marketing/demos must not imply a working
schema-agnostic production apply path until #45 lands.

---

## S3 cascade pre-image capture — DIRECT children only; multi-level cascades are fail-closed (ABORT), full N-level capture deferred

**SPEC sections touched:** §4 (guarded apply step 5/6/8 — full-blast-radius re-check +
reversible pre-image capture), §10.3 (typed-inverse `{pk, before_image}`), §5/§10.6
(reversibility vs golden state).

**Issue:** #48 (capture N-level cascade pre-images — apply walks DIRECT children only;
**fail-closed** part CLOSED here, full N-level capture remains OPEN for S4).

### Deviation

`guarded_apply` discovers and **captures cascade pre-images for DIRECT (1-level) children
only** (`cascade_by_table`). A deeper `parent → child → grandchild ON DELETE CASCADE` would
destroy grandchild rows whose pre-images are **not** captured by `build_inverse` — those
rows appear in the dry-run's FULL `pg_stat_xact_*` footprint (`effect_by_table`, populated
from `full_effect`) but **not** in `cascade_by_table`/`predicted.cascades`.

### What changed in this amendment (the S3 sprint-review BLOCKER fix)

The sprint review on EPIC #35 found that, before this fix, such a multi-level cascade was
**not fail-closed**: the grandchild's `del` reconciled cleanly (it *is* in `effect_by_table`
and actual == predicted), step 8 iterated only `predicted.cascades`, so `guarded_apply`
**COMMITTED** with the grandchild rows destroyed and **no captured pre-image** → permanent
silent data loss on revert. This contradicted the engine's own "0 catastrophic data-loss
FN by construction" claim.

**Fix (this PR):** step 8 (`assert_reversible_preimage_coverage` in `apply.rs`) now
reconciles **every relation in the ACTUAL footprint (`pg_stat_xact_*` deltas), not just
`predicted.cascades`**. For each relation that destroyed rows (`del > 0`, or an
identity-changing `upd` on a non-target relation), the captured typed-inverse MUST cover at
least that many rows:

- the **target** is covered by the `RETURNING` pre-image (`forward.written`);
- a **direct cascade** is covered by `forward.cascade_preimages[rel]`;
- **anything else** — a grandchild present in `effect_by_table` but absent from the captured
  set, or a trigger-deleted in-radius side relation — has **no** captured pre-image →
  `ApplyError::IrreversibleChange` → **ABORT / ROLLBACK** (nothing committed, rows intact).

So a multi-level cascade can no longer commit with an incomplete inverse. The 3-level-cascade
red→green test
(`apply::tests::multilevel_grandchild_cascade_delete_aborts_fail_closed`) proves it: with the
old direct-children-only step 8 it COMMITTED (grandchild rows missing from the inverse);
with the fix it ABORTS.

### What remains deferred (#48, OPEN for S4)

This is the **minimum correct bar**: **refuse** (fail-closed ABORT) the un-capturable
multi-level case. It does **not** add N-level pre-image *capture*, so a legitimate
multi-level `ON DELETE CASCADE` is **refused** rather than applied-and-revertible. Full
N-level discovery + capture (so such cascades can be applied and fully reverted) stays
deferred under **#48** for S4. A future N-level capture seam can supply the deeper
pre-images via `cascade_preimages`, at which point the same step-8 coverage check passes
and the apply commits (proven by
`apply::tests::multilevel_grandchild_with_captured_preimages_commits`).

---

## S4 components — each shipped and individually proven; the END-TO-END running system is NOT wired yet (deferred-and-now-disclosed)

**SPEC sections touched:** §3 (layer 2 warden + the authenticated breaker), §4 / §11
(the MCP toolset + the propose→dry_run→apply path), §10.9 (warden↔proxy mTLS / breaker
state), §14.3 (the signed proposal-bound grant), §4 (`_meta` audit DB + the external
anchor / KMS key separation). Build target: §7 S4.

**Issues:** #51 (S4 EPIC, the source of this disclosure), #62 (this disclosure-honesty
PR). Carry-forwards into S5: #65 (runnable+audited warden), #66 (production apply path +
§14.3 grant consumption), #64 (unify+persist+anchor the audit chain), #45 (production
generic-schema `ApplyConn`), #52 (warden / breaker, CLOSED — proxy-side breaker wiring
deferral authorized there), #26 (wire `PgSink` `_meta` into the proxy — an S1 follow-up,
now also an S4 carry), #18 (S0/S3 carry-forwards). The S5 assembly EPIC is #63.

### Deviation

S4 **built every deterministic-floor component the sprint called for, and proved each one
individually** (unit + env-gated real-PG18 integration, plus the CLI's in-process grant
demo). What S4 did **not** do is **join those components into one running system**: the
seams that connect agent → MCP → proxy → `guarded_apply` → audit, and warden → proxy
(breaker), **do not exist yet**. The components are real and tested; the wiring is S5
(#63). Concretely:

1. **Warden — logic + env-gated test seams shipped; the binary does NOT run a live
   loop.** `pgb_warden` (poller / breaker / thresholds / targeting) is exhaustively unit-
   tested on a `MockClock`, and a real `PgActivitySource` / `PgKiller` is proven against
   PG18 in the env-gated integration test (`crates/warden/tests/warden_it.rs`). But the
   shipped binary's `main()` only **prints and validates** the threshold config (fail-
   closed on a bad config); it does **not** poll. The `postgres` client is a
   **dev-dependency** (`crates/warden/Cargo.toml`), so the binary cannot even open a
   backend connection. The live watchdog (`main()` driving a `WardenLoop` over
   `PgActivitySource` / `PgKiller` on a `SystemClock` cadence) is **deferred to S5**
   (#65). Tracking: #18 (carry-forwards) and #65 (the filed S5 warden-wiring issue).

2. **Circuit breaker — a warden-side state machine only; NOT consumed by the proxy.**
   `pgb_warden::CircuitBreaker` is a real, clock-driven, non-forgeable state machine
   (Closed → Open → HalfOpen), with the §10.9 authentication modelled at the type level
   (`WardenCredential`, no public constructor / no `Deserialize`). Its state correctness
   and forgery-resistance are tested. But **no running proxy reads this state** to
   actually shed traffic — the `Open`/`Closed` "traffic shed/flows" semantics are the
   *intended* proxy-side effect, and that wiring is **deferred** (authorized in **#52**).

3. **MCP server — §11 toolset + block contract + RiskEngine seam shipped; NO deployable
   wire, NO live `Core`.** `mcp/server` ships the exactly-nine §11 tools, the block
   contract on every denial, the `confirm_rows` forcing function, the
   result-data-can-never-widen-capability defense, and the RiskEngine seam (the MVP
   `AllowStub`, T0–T2 captured/logged). But there is **no deployable JSON-RPC/stdio
   entrypoint** (the `McpServer` surface is driven by tests, not served over a transport),
   and it is **not wired to a production `Core`** — in the shipped tests the write path
   terminates in the test **`FakeCore`** (`src/testing/fakes.ts`), not a live Core driving
   the real propose→dry_run→`guarded_apply` path. The full **MCP → proxy →
   `guarded_apply`** wiring is **deferred to S5** (#63; the live `Core` is part of the
   #66 apply-path work).

4. **§14.3 signed grant — minted & verified end-to-end ONLY in the CLI's in-process
   demo.** `pgb_policy::GrantToken` (Ed25519, binding hash over the §14.3 fields, single-
   use nonce, expiry, `verify_for_apply` re-verify-at-apply) is real and tested, and the
   CLI approval flow (`pgb_cli::flow`) mints a grant and calls `verify_for_apply` in
   process. But **no production apply path consumes it**: `guarded_apply`
   (`crates/clone-orchestrator`) has no caller that threads a `GrantToken` through, and
   the proxy never calls `verify_for_apply`. Binding the signed grant into the production
   apply path is **deferred to S5** (#66) and is **blocked on the generic-schema
   `ApplyConn`** (#45). Until then the approval ceremony is proven as a mechanism, not as
   an end-to-end production gate (the "approval-theater" gap the S5 work closes).

5. **Audit `_meta` `PgSink` + external WORM anchor + KMS — library-only; the running
   proxy still uses an in-memory chain.** `pgb_audit` ships the `PgSink` (`_meta`
   persistence), the external WORM/transparency anchor, the KMS key-separation seam
   (`Kms` trait — the audited principal cannot materialize the signing key), and the
   secret-store seam — each tested at the library level. But the **shipped proxy binary
   still records to the in-memory hash chain** (`InMemorySink`,
   `crates/proxy/src/main.rs`); the persistent, anchored `_meta` chain is **not** injected
   into the running proxy (or shared with the CLI). This is the open **S1 follow-up #26**,
   now also an **S4 carry**; unifying + persisting + anchoring one chain across proxy/CLI
   is **deferred to S5** (#64).

### Rationale

S4 deliberately built and **independently proved** each deterministic-floor component
before spending effort on the cross-component wiring, so that S5 assembles known-good
parts rather than debugging logic and wiring at once. The safety *properties* each
component enforces are real and tested in isolation; what is **not** yet true is any
claim that they enforce those properties **as one running system** on a live agent→DB
write path. The honest posture is: the floor's **bricks** are built and load-tested; the
**mortar** joining them into a single guarded path is S5 work (#63). This record exists
because several modules asserted present-tense behavior (a live warden loop, the proxy
consuming the breaker, every MCP write going through a real Core, the proxy calling
`verify_for_apply`, the proxy persisting to `_meta`) that the **binaries do not perform**.

### What this amendment changed (doc/comment-only; zero behavior change — #62)

To make the in-tree record match reality, the following **doc-comments / banners /
header comments** were corrected from affirmative present tense to honest intended/future
tense, each pointing here and at the tracking issue. **No runtime logic was touched.**

- `crates/warden/src/main.rs` — the module doc + the runtime banner no longer claim a
  "Live ActivitySource/Killer wired at start-up"; they state plainly that `main()`
  validates config and the live loop is deferred to S5 (#65).
- `crates/warden/src/poller.rs` — the `run_ticks` doc no longer links a **nonexistent**
  `run_with_sleep` method (a broken intra-doc reference); it states the production driver
  is not implemented yet (S5, #65).
- `crates/warden/src/lib.rs` + `crates/warden/src/breaker.rs` — "the proxy sheds agent
  traffic" / "traffic is shed/flows" reworded to "*intended* to … (proxy-side wiring
  deferred — #52)".
- `mcp/server/src/server.ts` + `mcp/server/README.md` — the "every write goes through
  Core's propose→dry_run→apply path" claim qualified as the **intended** design, with a
  "Not yet wired (S4 → S5)" disclosure (no JSON-RPC/stdio wire; `FakeCore` only; #63).
- `crates/policy/src/grant.rs` — "the proxy re-derives … / the single entry point the
  proxy calls" reworded to intended/future tense, noting the only caller today is the CLI
  demo and production consumption is deferred to S5 (#66, blocked on #45).

The §10.1 BlastRadius "grant" that `guarded_apply` (`crates/clone-orchestrator/src/apply.rs`)
**does** cross-check at apply time is a *different* artifact and that claim is accurate;
it was **not** changed. (The unwired one is the §14.3 *signed* `GrantToken`.)
