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

   > **RESOLVED in S5 (#65) — the warden is now a RUNNING, AUDITED watchdog.** The
   > §S5 "Runnable + audited warden" section below supersedes this item: `postgres`
   > is now a real (feature-gated) `[dependencies]` entry, `PgActivitySource` /
   > `PgKiller` live in the `pgb_warden` library, and `main()` loads its policy
   > **fail-closed** (`PGB_POLICY_PATH`), builds the live seams + a `PgSink`-backed
   > `_meta` audit chain, and drives the proven `WardenLoop` on a `SystemClock`
   > cadence. Every enforcement action (`WARDEN_TERMINATE` / `BREAKER_TRIP` /
   > `SLOT_ALARM`) is appended to the same `_meta` chain the rest of the system uses
   > and verified read-back by the env-gated PG18 IT. The deterministic kill /
   > breaker / slot logic proven in #52 is **unchanged**.

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
   is **deferred to S5** (#64). **→ RESOLVED in S5 (#64): see the `## S5` section below —
   the proxy + CLI now share ONE persistent, anchored `_meta` chain, with a fail-closed
   startup verify; this S4 deferral no longer holds.**

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

---

## S5 — the §14.3 signed grant is now consumed at a REAL apply path (closes the "approval-theater" gap; updates the S4 disclosure point 4)

**SPEC sections touched:** §14.3 (the signed, single-use, time-boxed, proposal-bound
grant — now re-verified at a production apply), §10.1 (the apply-time PK-set checksum the
grant is bound to), §12.2 (`clone.provider` / `pitr.enabled` bridged from one
`policy.yaml` onto the apply engine).

**Issue:** #66 (S5: production apply path + §14.3 grant consumption at apply). Subsumes
the #45 generic-schema `ApplyConn` follow-up for the apply-caller surface.

### What changed (this is a behavior addition, not a doc-only correction)

S4's disclosure (point 4 above) recorded that `pgb_policy::GrantToken` was minted +
verified **only** in the CLI's in-process demo and that **no production apply path
consumed it** — `guarded_apply` had no caller threading a `GrantToken`, so an
attacker-minted or absent grant was never checked on a real apply ("approval theater").

This sprint adds **`pgb_clone_orchestrator::guarded_apply_with_grant`**
(`crates/clone-orchestrator/src/apply_grant.rs`) — a generic-schema production apply
caller that:

1. **bridges one `pgb_policy::PolicyConfig`** onto the apply engine's knobs:
   `clone.provider` → `ProviderKind` (via the existing, previously-unused
   `From<CloneProvider>`) and `pitr.enabled` → the apply's `PitrConfig` (via a new
   `From<pgb_policy::PitrConfig>` bridge). Single source of truth: those two §12.2 bits
   cross from policy into the engine in exactly one place;
2. **consumes the §14.3 grant at apply time** — it recomputes the **apply-time target
   PK-set checksum** via the same `ApplyConn::recompute_pk_checksum` seam `guarded_apply`
   uses, re-derives the *live* `GrantBinding` from the live request + that checksum, and
   calls **`pgb_policy::GrantToken::verify_for_apply`** (the existing Ed25519 verify +
   binding-hash match + single-use nonce + expiry — **reused, no crypto reimplemented**).
   The signed `blast_radius_checksum` is thereby **bound to the exact proposal**: a
   swapped statement / param / session / proposal, a reused nonce, an expired TTL, **or a
   drifted data set** (a row in/out of the predicate since signing) all REJECT;
3. only on a valid, single-use, unexpired, proposal-bound grant does it reach
   `guarded_apply`, whose own §10.1 apply-time PK-set re-check re-pins the same checksum
   **inside** the apply txn (defense in depth).

The grant gate is **tighten-only / fail-closed**: it can only ADD an abort condition; it
never loosens a `guarded_apply` guard. **No valid grant ⇒ abort, no mutation** — the apply
txn is never opened (the grant is checked before any `begin`). A shared/durable
`NonceStore` and the policy-resolved approver `VerifyingKey` are injected, so the same
single-use store and the trusted approver key gate every apply.

Proven red→green with unit tests (`apply_grant.rs`) **and** real-PG18 integration tests
(`crates/clone-orchestrator/tests/apply_grant_it.rs`, env-gated `PG_BUMPERS_IT=1`): a
CLI-minted grant verifies at the real apply and the bounded write commits **reversibly**
(revert restores the pre-state); the **5 T-grant-\* tamper cases**
(sql-swap/param-swap/cross-session/proposal-swap → `BindingMismatch`; nonce reuse →
`ReplayedNonce`; past-expiry → `Expired`), **no-grant** (attacker key → `BadSignature`),
and **apply-time data-drift** (→ `BindingMismatch`) all ABORT end-to-end with **no
mutation**; and the S3 guards still fire under the grant path (a barrier-injected
post-gate drift still trips `guarded_apply`'s apply-time PK-set re-check → abort).

### What is now true vs. what REMAINS a gap (honest scope)

**Now true:** a §14.3 signed grant is a real, enforced gate at a production apply path —
`guarded_apply_with_grant` is a non-test caller that fails closed without a valid grant.
The "approval theater" gap (an absent/forged grant never checked on a real apply) is
**closed** at the apply-caller boundary. S4 disclosure point 4 is **superseded** by this
section for the apply path.

**Still a documented gap (deferred):** the wiring **above** this caller — the live agent →
MCP → proxy path that would *invoke* `guarded_apply_with_grant` with the live statement,
params, session, role, and the policy-resolved approver key — is **not** built yet. No
running proxy/MCP binary calls this function today; it is exercised by the unit + real-PG18
integration tests, not yet by a served transport. That end-to-end assembly (and unifying
the audit chain that records the grant decision) stays under the S5 assembly EPIC (#63),
with the audit unification under #64. So: the grant is now a real gate **at the apply
seam**; making the whole running system route through that seam is the remaining S5 wiring.

## S5 — Runnable + audited warden (the live, audited watchdog) — #65

**SPEC sections touched:** §3 (layer-2 warden), §4 (poll 1–5s; cancel/terminate only
agent-tagged; `_meta` audit), §10.9 (authenticated breaker; "the audited cannot write
audit"). Build target: §7 S5. **Issues:** #65 (closes), building on #52 (the proven
deterministic kill/breaker/slot logic) and coordinating with #64 (one unified `_meta`
chain across proxy/CLI/warden).

### What changed (behavior — the S4 stub is gone)

S4 disclosed (item 1 above) that the warden **binary** was a print-only stub: `main()`
only validated config and printed; `postgres` was a **dev-dependency**, so the binary
could not open a connection; and no warden action was audited. **#65 makes the binary a
real, running, audited watchdog**, without touching the deterministic enforcement
semantics #52 proved:

- **Runnable binary.** `postgres` moved from a dev-dependency to a real, **feature-gated**
  (`pg`, default-on) `[dependencies]` entry. The live `PgActivitySource` (`pg_stat_activity`
  / `pg_replication_slots`) and `PgKiller` (`pg_terminate_backend`) now live in the
  `pgb_warden` **library** (`crates/warden/src/run.rs`, `pg` module). `main()` reads
  `PGB_POLICY_PATH` → `WardenThresholds::from_policy_yaml` **fail-closed** (a
  present-but-invalid `warden:` section, a missing/unreadable file, or a missing required
  secret → refuse to start, **non-zero exit**), builds the live seams over real admin
  connections, and drives the **existing** `WardenLoop` on a `SystemClock` cadence
  (poll 1–5s, §4). The proven `WardenLoop` / `ActivitySource` / `Killer` seams are reused
  verbatim — the gating logic was **not** forked.

- **Audited actions.** `pgb-audit` is now a warden dependency. Every enforcement action is
  appended to a `PgSink`-backed `_meta` hash-chained audit chain via the `crates/audit`
  public API (`PgSink` / `Sink::append`): `WARDEN_TERMINATE` (one per terminated
  agent-tagged pid), `SLOT_ALARM` (one per slot over the WAL ceiling), `BREAKER_TRIP` (when
  the authenticated breaker opens). The records are `BLOCK` decisions subject-tagged to the
  audited `pgb_agent` role and **written as the `pgb_audit_writer` role** (never the agent)
  to the **same** `pgb_audit.audit_log` table the proxy/CLI use — so #64's external anchor
  covers them. A **spared** shared session is a non-event: it produces **no** audit action
  (the "spare-shared" invariant of #52 is preserved exactly).

- **Moat unchanged.** Kill-only-agent-tagged, spare-shared, the deterministic breaker, and
  the non-forgeable `WardenCredential` are **byte-for-byte** the #52 logic. #65 added only
  the live wiring + the audit append.

### Evidence (red→green; real PG18, env-gated, NEVER 5432)

- **Unit (DB-free, red→green):** the pure `audit_entries_for` / `tick_and_audit` mapping is
  TDD'd — a stub returning no records fails 5 tests (RED); the real mapping passes (GREEN).
  Fail-closed config + the env-derived `WardenSettings` (defaults + the two required
  secrets, no credential literals) are unit-tested.
- **Integration (`PG_BUMPERS_IT=1`, dedicated port 54362):** the running watchdog over the
  live `PgActivitySource` / `PgKiller` **terminates** a real agent-tagged runaway,
  **spares** a shared session, **alarms** on a replication slot, **trips** the breaker —
  and **each action lands on the `_meta` chain** (`["WARDEN_TERMINATE","SLOT_ALARM",
  "BREAKER_TRIP"]`), which **`verify_chain`s** on read-back. A RED run with the audit append
  neutered proves the assertion bites (the `_meta` chain is empty `[]`). The throwaway
  cluster is torn down; **:5432 was verified untouched** before and after.

### Coverage-floor note (honest)

`pgb-warden`'s DB-free line coverage moved from 95.18% (S4) to ~86.6%. This is **not logic
rot** — every gating module + the pure audit-record construction + the binary's config/DSN
assembly remain >95% covered. The drop is the **new, inherently-DB-only** live seams
(`run.rs`'s `pg` module, `run_loop`'s real sleep driver, the thin `main.rs`), which are 0%
DB-free and proven **only** under the env-gated PG18 IT — exactly like `pgb-audit`'s `pg.rs`
and `pgb-proxy`'s session loop. The floor (`.github/scripts/coverage_floor.py`) was
adjusted 90% → 85% with that documented rationale; ratchet up as logic coverage grows.

### Still deferred (not in #65's scope)

The **proxy-side** consumption of the breaker (shedding agent traffic when `Open`) remains
deferred (authorized in #52); #65 makes the warden *trip and audit* the breaker, but no
running proxy reads that state yet. Unifying the warden/proxy/CLI onto one persisted +
anchored `_meta` chain is #64 (the warden already appends via the shared `crates/audit`
API to the same table, so it rebases cleanly onto #64).

---

## S5 audit — ONE shared, persistent, anchored `_meta` chain wired into the proxy + CLI (S4 deferral #5 CLOSED)

**SPEC sections touched:** §3 (hash-chained AUDIT, external anchor, "audited cannot write
audit"), §4 (`_meta` DB append-only hash-chain), §10.9 (root-of-trust: external WORM anchor,
KMS key separation, audited principal REVOKEd from writing audit). Build target: §7 S5.

**Issues:** #64 (this work — unify + persist + anchor the audit chain), epic #63. This
**closes** the S4 disclosure item 5 above (audit `_meta` `PgSink`/anchor were library-only)
and the S1 follow-up #26 (wire `PgSink` `_meta` into the proxy).

### What this changed — the wiring is now real (not a deferral)

The S4 amendment (item 5) honestly recorded that the `PgSink`/anchor/KMS were **library-only**:
the proxy (`crates/proxy/src/main.rs`) and the CLI (`crates/cli/src/main.rs`) each built a
**separate** ephemeral `InMemorySink` chain with an **independent genesis**, the `pg`
feature/`PgSink` were **not compiled in**, and the external WORM anchor pinned nothing real.
S5 (#64) wires those known-good libraries into the running binaries:

1. **One shared, persistent chain.** A new `pgb_audit::AuditBoot` (behind the audit crate's
   `pg` feature, now enabled on both consumers) constructs a single `PgSink`-backed `_meta`
   chain and wraps it in a new cloneable `pgb_audit::SharedSink`. The proxy `Recorder` is
   injected with the **exact** `Arc<Mutex<dyn Sink + Send>>` the boot handle wraps
   (`AuditBoot::sink_arc()`), and the CLI `ApprovalFlow` takes a **clone** of the same
   `SharedSink` (`AuditBoot::shared_sink()`). A proxy reject and a CLI approve therefore
   hash-chain into the **same** `_meta` table — **one genesis** (proven end-to-end in
   `crates/cli/tests/shared_meta_it.rs`: a real proxy `Recorder` REJECT + a real
   `ApprovalFlow` approve land on one chain with contiguous seqs from a single genesis;
   `verify_chain` passes).

2. **The chain is anchored.** `AuditBoot` runs the existing `Anchorer` over the **records
   read back from `_meta`** (a new slice-based `Anchorer::maybe_anchor_records` +
   `pgb_audit::verify_records_against_anchor`, sharing the identical head extraction
   `head_of` so an in-memory and a persisted chain pin the same head). The proxy spawns a
   background tick loop driven by `core::Clock::monotonic_millis` on the configured interval
   (`PGB_ANCHOR_INTERVAL_MS`, default 60 s); the cadence is mockable (no wall clock — proven
   in the `AuditBoot` unit tests).

3. **Fail-closed startup verification (verify-BEFORE-anchor over a DURABLE anchor — see the
   #71 follow-up below for the corrected, cross-restart-safe form).** On boot the proxy/CLI
   load the persisted chain, check within-chain integrity, and check the head matches the
   validly-signed WORM-anchored head; a **full-chain rewrite** caught as a head mismatch →
   `BootError::AnchorHeadMismatch` → **refuse to start** (proven against real PG18 in
   `crates/proxy/tests/audit_meta_it.rs`). A missing anchor is likewise fail-closed.

### S1 invariants preserved

The "audited principal cannot write audit" REVOKE (SPEC §3/§10.9), the within-chain
tamper detection, and the canonical-JSON hashing are **unchanged**: the `_meta` schema
(`crates/audit/sql/10_audit_meta.sql`), the `PgSink` INSERT-as-writer path, and
`AuditPayload::canonical_bytes`/`compute_hash` were **not** touched. The existing
`crates/audit/tests/pg_meta_it.rs` (including the 42501 REVOKE proof) and the S4 anchor
tests all stay green. The deterministic floor is untouched — this is audit-coverage
wiring, it weakens no enforcement.

### Configuration added (proxy `main.rs`; fail-closed)

- `PGB_META_DSN` — the `_meta` **writer** DSN (`pgb_audit_writer` role; never the audited
  agent). **Required**, no literal default — the proxy refuses to start without somewhere to
  persist + anchor the canonical chain.
- `PGB_AUDIT_SIGNING_KEY` — the chain-head signing key material (secret-store seam; prod
  addresses a KMS key version under the same id). **Required**, no literal default.
- `PGB_ANCHOR_INTERVAL_MS` — the WORM anchoring cadence in millis (default 60000).
- `PGB_ANCHOR_PATH` — the **durable**, file-backed WORM anchor path (added in the #71
  follow-up below). **Required**, no literal default.

The CLI `demo` runs against the shared `_meta` chain when `PGB_META_DSN` +
`PGB_AUDIT_SIGNING_KEY` (+ `PGB_ANCHOR_PATH`) are set (otherwise it stays an in-memory
DB-free smoke, unchanged).

### What remains (honest scope)

The local `WormAnchor` is still the in-memory/file append-only **stand-in**; the production
S3-Object-Lock / transparency-log target and the asymmetric KMS remain the documented
production swaps behind the `WormAnchor`/`Kms` seams (unchanged from S4). The anchor is now
**driven by the running binary over the real `_meta` chain**, which is the gap #64 closed.

### #71 follow-up — DURABLE WORM + verify-BEFORE-anchor: `_meta` tampering is now caught ACROSS a restart

A non-author review of PR #71 found that the external-anchor startup verify, as first
landed, did **not** fail closed across a **process restart** — so the headline "full-chain
rewrite caught on boot" was only true *within* a single process. Two holes:

1. **The durable anchor was unreachable from the boot path.** `AuditBoot` hardcoded an
   in-memory `WormAnchor::new()`; the file-backed `WormAnchor::open_file` (the only durable
   retention the crate has) was never wired in. Every fresh process started with an **empty**
   anchor, so it had nothing from a prior run to verify against.
2. **The proxy anchored BEFORE it verified.** `main` called `maybe_anchor()` then
   `startup_verify()`. A fresh process therefore re-pinned whatever head was now in `_meta`
   — *including an offline-forged head* — and the verify trivially passed against the
   head it had just re-anchored. The IT also did not exercise the real path: it asserted
   refusal via a test-local mirror fed the honest prior run's in-memory WORM, not the real
   `boot.startup_verify()`.

The fix (scope `crates/audit`, `crates/proxy`, `crates/cli`):

- **Durable WORM reachable from `AuditBoot`.** New `AuditBoot::connect_with_anchor(.., anchor_path)`
  / `with_sink_and_worm(.., worm)` wire `WormAnchor::open_file(path)` into the boot/proxy/CLI
  path (`PGB_ANCHOR_PATH`). The anchored head now **persists across restarts**. `AuditBoot`
  also retains the KMS **verifier** so a *file-loaded* anchor (whose embedded verifier does
  not serialize) can still be checked after a restart.
- **Verify-BEFORE-anchor.** New `AuditBoot::verify_then_anchor(now)` is the boot sequence the
  proxy + CLI now call: if the durable WORM already holds an anchor (a prior boot), it
  **verifies the persisted chain against that prior durable head FIRST** and, on mismatch,
  refuses to start (`BootError::AnchorHeadMismatch`); only after a clean verify does it anchor
  the current head **forward**. A legitimate first boot / genesis (empty durable WORM) has
  nothing to verify against yet and anchors the baseline without opening a hole — the durable
  WORM's own integrity (object-lock / transparency-log retention) is the §10.9 trust anchor.
- **Real restart-path IT.** `crates/proxy/tests/audit_meta_it.rs` now boots a real
  `AuditBoot` over a durable WORM **file**, writes honest records + anchors (persisted),
  offline-rewrites the `_meta` rows into a consistent forged chain, then runs a **fresh boot2**
  over the **same** durable WORM file calling the **actual** `verify_then_anchor` — and asserts
  it **refuses** (`AnchorHeadMismatch`). A positive control boots2 over an *untampered* chain
  and **starts**. DB-free `AuditBoot` unit tests cover the same restart logic
  (`verify_then_anchor_refuses_forged_chain_across_durable_restart` /
  `…_accepts_untampered_durable_restart`).

So the headline claim is now accurate: a full-chain `_meta` rewrite is caught on boot
**across a process restart**, because the anchored head is durable and the boot verifies
against the *prior* durable head before re-anchoring. The `WormAnchor` file remains the
append-only **stand-in** (S3 Object Lock / transparency log is the documented production
swap — the file is not itself true WORM). The preserved-and-passed reviewer items are
unchanged: concurrent-appender fork-safety (`SharedSink` mutex + `PgSink` re-reads the
persisted tail as `prev_hash`), the 42501 audited-can't-write invariant, env-secret handling
(the key never logged), and the single shared `_meta` chain.

---

## S5 — MCP production wire + live Core (#67)

**SPEC sections touched:** §3 (layer 3 MCP is cooperative, NOT a security boundary; the
deterministic floor stays in Rust), §4 (the MCP toolset; propose→dry_run→apply; the
`_meta` audit chain), §11 (the toolset), §14.3 (the signed grant consumed at apply),
§10.1/§10.2/§10.3 (blast radius + PK-set guard + typed-inverse), §12 (clone.provider).

**Issue:** #67 (S5: MCP production wire + live Core). Builds on #66 (the production
grant-gated apply path `guarded_apply_with_grant`) and #64 (the shared anchored `_meta`
chain).

### What is wired (now real, end-to-end)

The MCP server is now a **deployable, real-Core** server. A new Rust write-path daemon
owns the apply floor; a TS `ApplydCore` + a stdio MCP shell wire the MCP server to it;
reads go through the live proxy. Concretely:

- **`pgb-applyd` (new crate `crates/applyd`, binary `pgb-applyd`)** — a long-lived process
  that binds a **Unix-domain socket** (`PGB_APPLYD_SOCKET`; dir `0700`, socket `0600` —
  NOT a TCP port, NOT agent-reachable) and speaks **line-delimited JSON-RPC 2.0**. It holds
  the write-safety STATE in-process, TTL'd via an injected `Clock` (the production analog
  of the TS `FakeCore`): proposal records, the cached `BlastRadius` per proposal, elevation
  requests + the signed grants (held in-process; the grant NEVER crosses to the agent), the
  `NonceStore`, the approver `VerifyingKey`, the `PolicyConfig`, and the shared `_meta`
  audit chain. Methods: `propose` / `dry_run` / `request_elevation` / `approve` / `apply` /
  `get_audit`. Reuses the merged primitives verbatim — `clone_orchestrator::{propose,
  dry_run, guarded_apply_with_grant}`, the `pgb_cli` approval flow (request/approve/audit +
  the self-approval gate), `pgb_audit::AuditBoot::connect_with_anchor` (the proxy's
  env/audit-boot wiring) — and **reimplements no crypto, no §4 guards, no audit chain**.

- **The SECURITY-CRITICAL apply invariant** — at `apply`, the daemon re-derives the
  `LiveRequest{statement_text, normalized_params, role, session_id, proposal_id}` from the
  **STORED proposal record**, NEVER from apply-time params. The `apply` RPC takes only
  `{proposal_id, confirm_rows, confirm_token}`, so the agent/MCP cannot present a different
  statement/role/session at apply than what was proposed + dry-run + approved. (Proven by
  `apply_rederives_from_stored_record_*` in `tests/service_unit.rs`: a grant minted for
  proposal-A's session can never be redirected onto proposal-B, because there are no
  apply-time fields to redirect.) The §14.3 binding hash + `verify_for_apply` enforce this.

- **`ApplydCore` (TS, `mcp/server/src/applydCore.ts`)** — a thin Unix-socket JSON-RPC client
  implementing the `Core` interface; the production peer of `FakeCore`. It maps
  `propose/dryRun/apply/requestElevation/getAudit` onto `pgb-applyd` and translates a
  JSON-RPC error into the existing `ApplyResult{outcome:"blocked", block}` / `{notFound}`
  shape so every denial stays a recoverable contract. Node `net` + `readline` only — NO new
  dependencies (`license-check` stays green).

- **The stdio MCP shell (TS, `mcp/server/src/bin/mcpStdio.ts`, bin `pgb-mcp`)** — the single
  new deployable entrypoint. It speaks MCP `initialize`/`tools/list`/`tools/call` over
  stdin/stdout (line-delimited JSON-RPC 2.0) and constructs `createServer({ transport:
  PgProxyTransport.connect({...proxy...}), core: new ApplydCore({socketPath}), role })`,
  dispatching `tools/call → server.call`. `package.json` gains the `bin` + a real emitting
  build (`tsconfig.build.json`, `outDir:dist`).

- **Reads go through the live proxy** (`PgProxyTransport` → the proxy endpoint) — unchanged.

- **The full lifecycle is AUDITED** to the shared, anchored `_meta` chain: `request_elevation`
  (BLOCK), `grant_signed` (ALLOW, at approve), and `apply_committed`/the apply-block code
  (at apply) all hash-chain into one `_meta` chain (single genesis), the same chain the
  proxy and CLI write to.

### DEFERRED (honest scope — disclosed, not silently dropped)

- **Generic-schema `ApplyConn` beyond single-int-PK** — `pgb-applyd`'s apply is constrained
  to the **single-integer-PK `UPDATE`/`DELETE`** shape on a `(id, owner, balance)` table the
  existing IT impl already proves (the lifted `PgApplyConn`/`PgRevertConn`). This is the #1
  risk honored deliberately: a hand-rolled generic-schema apply could mis-read the PK or
  skip a pre-image column and silently break reversibility while looking green. Anything
  wider is gated out by the dry-run's existing PK-less / volatile / irreversible REFUSALS
  (fail-closed). Generic-schema apply is DEFERRED.

- **Cross-process session attestation (T4)** — the proxy read session and the applyd
  proposal are tied by the `session_id` the shell PASSES, not by a cryptographic binding
  between the two processes. The applyd binds the apply to whatever `session_id` it stored
  at propose (defeating cross-session GRANT replay), but the link from the *proxy read
  session* to the *applyd proposal session* is not yet cryptographically attested. DEFERRED.

- **KMS approver-key resolution** — the approver `VerifyingKey` is loaded from
  `PGB_APPROVER_PUBKEY` (hex); production resolves it from a KMS key version (§10.9). The
  signing key is presented out-of-band by the operator at `approve` (it never enters the
  daemon's config or the agent path). DEFERRED.

- **dblab clone provider** — the dry-run runs the baseline `clone.provider: none` in-txn
  rehearsal (`PgRehearsal`); the dblab clone provider is the existing separate deferral.

### Not a security boundary (the honesty contract)

The MCP server, the stdio shell, and `ApplydCore` are **cooperative, NOT a security
boundary** (SPEC §3). They add no privilege: every read passes the proxy/WALL and every
write passes `pgb-applyd`'s deterministic floor (`guarded_apply_with_grant` — bounded,
reversible, grant-verified, fail-closed). A compromised MCP server cannot invent privilege,
because the daemon re-derives the apply from its own stored proposal record. We do **not**
claim generic-schema apply works.

### One-impl conn lift (refactor, no behavior change)

`PgApplyConn` (from `crates/clone-orchestrator/tests/apply_grant_it.rs`) and `PgRehearsal`
(from `tests/common/mod.rs`) were **lifted into reusable library code** at
`pgb_clone_orchestrator::conn` (behind the new `pg` feature), with `PgRevertConn` added
alongside, so the integration tests AND `pgb-applyd` share exactly ONE implementation of
each conn — no second, unproven copy. The existing clone-orchestrator IT tests now reuse the
lifted impls (re-verified green: 16 IT tests).
