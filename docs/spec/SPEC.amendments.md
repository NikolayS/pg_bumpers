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

> **HISTORICAL (EPIC #83): the TS files below are DELETED.** This entry records what
> shipped at #67. The Rust equivalents are `crates/mcp/src/applyd.rs` (`ApplydCore` →
> `ApplydClient`) and `crates/mcp/src/bin/pgb_mcp.rs` (the stdio shell). See the EPIC #83
> amendment at the end of this file.

- **`ApplydCore` (original non-Rust impl — now Rust `crates/mcp/src/applyd.rs`)** —
  a thin Unix-socket JSON-RPC client
  implementing the `Core` interface; the production peer of `FakeCore`. It maps
  `propose/dryRun/apply/requestElevation/getAudit` onto `pgb-applyd` and translates a
  JSON-RPC error into the existing `ApplyResult{outcome:"blocked", block}` / `{notFound}`
  shape so every denial stays a recoverable contract. Standard-library sockets + line
  reader only — NO new dependencies (the license-check stayed green).

- **The stdio MCP shell (original non-Rust impl, bin `pgb-mcp` — now Rust
  `crates/mcp/src/bin/pgb_mcp.rs`)** — the single
  new deployable entrypoint. It speaks MCP `initialize`/`tools/list`/`tools/call` over
  stdin/stdout (line-delimited JSON-RPC 2.0) and constructs `createServer({ transport:
  PgProxyTransport.connect({...proxy...}), core: new ApplydCore({socketPath}), role })`,
  dispatching `tools/call → server.call`. The package manifest gained the `bin` + a real
  emitting build (a build config emitting into a `dist` output dir).

- **Reads go through the live proxy** (`PgProxyTransport` → the proxy endpoint) — unchanged.

- **The full lifecycle is AUDITED** to the shared, anchored `_meta` chain: `request_elevation`
  (BLOCK), `grant_signed` (ALLOW, at approve), and `apply_committed`/the apply-block code
  (at apply) all hash-chain into one `_meta` chain (single genesis), the same chain the
  proxy and CLI write to.

### DEFERRED (honest scope — disclosed, not silently dropped)

- **Generic-schema `ApplyConn` beyond single-`int4`-PK** — `pgb-applyd`'s apply is
  constrained to the **single-`int4`-PK `UPDATE`/`DELETE`** shape the lifted
  `PgApplyConn`/`PgRevertConn` prove. A wider/composite PK (`int8`/`text`/`uuid`/multi-col)
  is gated out **cleanly at dry-run** (`NOT_REHEARSABLE`, no panic) — see the S5 #75
  amendment below. Generic-schema apply (wider PK types/cardinalities) is DEFERRED.
  **CORRECTION (S5 #75):** the prior wording — "skip a pre-image column and silently break
  reversibility … anything wider is gated out" — conflated PK *width* with the *columns* a
  write touches. A single-`int4`-PK `UPDATE` that writes ANY column was **not** gated out;
  the hardcoded `(id, owner, balance)` capture silently dropped any other written column (a
  catastrophic FN). That hole is **CLOSED** in the S5 #75 amendment: the apply now captures
  the exact SET-clause columns and a defense-in-depth column-coverage guard aborts an
  uncaptured written column before commit. Such a write is genuinely reversible — accepted,
  not refused.

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

---

## S5 — the MARQUEE: "delete a DB through the official MCP" repro + bench breadth + KNOWN_BYPASSES (#68)

The headline demonstration of the moat **as a running system**: a REAL MCP client drives the
deployable stdio shell against the now-assembled stack (live proxy read path + `pgb-applyd` +
live `pgb-warden` + anchored `_meta` audit) and the system's behavior is shown **split by
damage class** — honestly, no overclaim.

### What ran LIVE (end-to-end, `PG_BUMPERS_IT=1`, dedicated high port 54341; NEVER 5432)

`mcp/server/test/marquee.integration.test.ts` (**HISTORICAL — now the env-gated Rust e2e
`crates/mcp/tests/{write_path_e2e,read_path_e2e}.rs`** per EPIC #83; run + transcript-captured by
`deploy/marquee.sh`, evidence in `deploy/marquee.transcript.txt`) drives a REAL MCP client over
`pgb-mcp` and asserts, per damage class:

- **Irreversible / structural** (DROP DATABASE/TABLE, TRUNCATE, ALTER) → **REFUSED**,
  default-deny (`NOT_REHEARSABLE` at the applyd classify choke); a DROP on the read tool →
  `READ_ONLY`. The "delete a DB" headline = the attempt is **neutralized by refusal**, not run.
- **Bounded reversible write** (no-WHERE-shaped wide UPDATE on the single-int-PK table) →
  bounded by blast radius; no grant → `APPROVAL_REQUIRED`; operator-approved §14.3 grant →
  **applied reversibly**; a drifted apply → `GRANT_REJECTED`/`BLAST_DRIFT` **abort, no mutation**.
- **Runaway read** (agent-tagged long `pg_sleep`) → **killed by the live `pgb-warden` binary**,
  a non-agent session **spared**, the kill **audited** to `_meta`.
- **Every decision** lands on **ONE anchored `_meta` chain** — `pgb-cli verify` runs
  `verify_chain` over the unified chain AND asserts the durable anchored head matches.

### What this amendment WIRED (behavior additions, each red→green)

- **The MCP read session now carries the proxy `application_name` tag** (`pgb_proxy`, env
  `PGB_PROXY_APP_NAME`) so the out-of-band warden recognizes + can terminate an agent-tagged
  runaway read. NOT a security control — the un-strippable anchor remains the hardened agent
  role; this is purely the warden's tag. (`mcp/server/src/pgProxy.ts`, `bin/mcpStdio.ts`.)
- **A propose-time structural REFUSAL is now surfaced as a recoverable BLOCK**, never an opaque
  error: `createServer().propose_write` catches the `ApplydError` the production `ApplydCore`
  throws when applyd's classify choke refuses a DROP/TRUNCATE/ALTER, and returns the
  `{status:blocked, code, reason, remedy, retryable}` contract (SPEC §4: every denial is
  recoverable). (`mcp/server/src/server.ts`; tested in `mcp/server/test/tools.test.ts`.)
- **`pgb-cli verify`** — a new read-only subcommand (`crates/cli/src/verify.rs` + `main.rs`)
  that loads the shared `_meta` chain, runs `verify_chain`, then `verify_then_anchor`s to a
  caller-supplied (fresh) `PGB_ANCHOR_PATH` and asserts the durable anchored head equals the
  chain head — the marquee's "one anchored chain" proof, reusing #64's machinery (it does NOT
  disturb the running daemon's anchor; the verify step uses its own anchor file).

### Deterministic benchmark breadth (`dbsafe-bench`)

The frozen corpus grew from 22 → **35** scenarios (26 dangerous + 9 adversarial-legit) toward
the frozen scenario set: more refused-ops (`refused-drop-database`, `refused-insert-no-pk`,
`refused-update-no-preimage`, `refused-unknown-op`), more statement-stacking / smuggling
(`stacking-drop-database`, `copy-on-read-path-obfuscated`, `delete-on-read-path-naive`), a
slow-drip row-cap exfil (`exfil-slow-drip-row-cap`), the COPY…PROGRAM bypass variant, and more
adversarial-legit FP-denominator reads/writes. The golden 0-FN / 0-FP gate stays green and
`gate_has_teeth` is untouched (it still FAILs on a deliberately-broken engine). The
catastrophic-FN ledger (`dbsafe-bench/golden/known_bypasses.json`) remains **empty**.

### KNOWN_BYPASSES ledger

`KNOWN_BYPASSES.md` (new, repo root) documents the residual, honestly-disclosed **scope**
limits — bounded (≤ B, not zero) read disclosure; the cooperative-MCP caveat; single-int-PK
apply; deferred T4 cross-process attestation; the file-`WormAnchor` stand-in (delete-the-file
re-baselines); the `Allow`-stub RiskEngine — each with a repro note tied to its SPEC.amendments
entry. These are NOT floor false-negatives (the catastrophic-FN JSON ledger stays empty); they
bound what the guarantees COVER.

### Honest scope (what was harness-gated vs. fully live)

- **Fully LIVE in the marquee:** the MCP client → stdio shell → `ApplydCore` → `pgb-applyd` →
  `guarded_apply_with_grant` write path; the live `pgb-warden` kill/spare/audit; the unified
  `_meta` chain `verify_chain` + anchored-head match via `pgb-cli verify`; the structural
  refusals; the bounded apply + drift abort.
- **Proven in a sibling IT, referenced by the marquee:** the **byte-for-byte revert restores
  the pre-state** is asserted against real PG18 in `crates/applyd/tests/applyd_it.rs`
  (`lifecycle_apply_commits_bounded_update_and_revert_restores_prestate`); the marquee asserts
  the bounded commit + the `reversible:true` flag (it does not re-drive the revert in TS).
- **The reads point straight at PG18** standing in for the proxied backend (same honest split
  as `integration.test.ts`): the full Apache Rust proxy binary in front (SCRAM/TLS/WALL) is
  covered by `crates/proxy/tests/`. The MCP layer is cooperative, not the boundary.

---

## S5 #75 — write-floor column coverage + clean PK-type refusal + applyd audit fail-closed

**SPEC sections touched:** §3/§4 (deterministic floor, guarded apply, "0 catastrophic
data-loss FN by construction"), §10.2 (PK-set identity), §10.3 (typed-inverse
`{pk, before_image}`), §5/§10.6 (reversibility vs golden state).

**Issue:** #75 (S5 release blocker — the one undisclosed hole in the write-safety moat).

### The bug (a write escaped the floor)

The apply-time PK-set checksum (`guarded_apply`) caught *which-rows* (identity) drift but
**not** *which-columns* drift. The production `PgApplyConn`/`PgRevertConn`
(`crates/clone-orchestrator/src/conn.rs`) hardcoded the pre-image to `(id, owner, balance)`
and the revert to `SET owner = …, balance = …`. So a single-`int4`-PK
`UPDATE t SET notes = 'x' WHERE id = …` on a `(id, owner, balance, notes)` table **committed
`reversible:true` but was permanently un-revertable** — the captured inverse held no `notes`
pre-image, so the revert silently left the written column unchanged. A silent catastrophic
false-negative. `KNOWN_BYPASSES.md` B3 and the DEFERRED note above affirmatively (and
falsely) claimed "wider shapes are gated out, fail-closed". Two adjacent footguns shared the
root cause: an unguarded `let id: i32 = row.get(0)` would **panic** on a non-`int4` PK, and
the applyd apply-path `_meta` append was best-effort (`let _ =`), so a committed write whose
audit append failed returned success with **no** record.

### What changed (fail-closed, tighten-only — every change only ADDS a refusal/abort)

1. **Column coverage — captured + restored by name (the fix, not a refusal).** `apply_forward`
   now parses the **SET-clause target columns** out of the forward `UPDATE` and captures the
   pre-image of **exactly those columns** (a `DELETE` captures the full row from
   `pg_attribute`); `PgRevertConn::{restore_update,restore_insert}` restore **exactly the
   captured columns** (no hardcoded list). So a single-`int4`-PK UPDATE is **genuinely
   reversible regardless of which columns it writes** — accepted, not refused. The pre-image is
   captured **losslessly** (typed `int2/4/8` / `text`/`varchar`/`bpchar`/`name` / `bytea`,
   NULLs faithful); an unsupported column type fails closed.
2. **Defense-in-depth apply-time COLUMN-coverage guard (step 8b).**
   `assert_written_column_coverage` (`apply.rs`) verifies **every written column has a captured
   pre-image** in each written row; a declared-but-uncaptured column (or, with none declared, an
   empty non-PK pre-image) → `ApplyError::UncapturedColumn` → **ABORT / ROLLBACK** before
   commit. Even if the dry-run column gate were bypassed, a write can **never** commit
   `reversible:true` with an incomplete inverse.
3. **Clean wider-PK-type refusal, no panic (dry-run gate).** `PgRehearsal::certify_apply_shape`
   (a `pg_index`/`pg_type`/`pg_attribute` read only, before any rehearsal) refuses a target
   whose PK is **not a single `int4`** (`int8`/`text`/`uuid`/composite) with a clean
   `NOT_REHEARSABLE`, and refuses an UPDATE whose SET columns are not losslessly capturable. A
   genuinely PK-less target stays the distinct `PK_LESS` refusal. The unguarded `row.get(0)`
   calls became `try_get → ApplyError::Backend`, so even a PK that slips past the gate aborts
   the open apply txn cleanly (rolled back) rather than panicking — the resident applyd apply
   `Client` is never poisoned, and the daemon serves the next request (asserted by IT).
4. **applyd apply-path audit fail-closed.** `Service::audit_apply` now surfaces the `_meta`
   append `Result` (was `let _ =`), matching the warden ("fatal") and proxy (`?`). On both the
   success and block paths a failed append returns `AUDIT_FAILED` rather than a silent
   unaudited success.

### Honest ordering caveat (NOT atomic co-commit)

The `_meta` chain is a **separate connection** from the apply txn, so the audit record is
**NOT co-committed** atomically with the write in the MVP. The apply-committed append runs
**after** `guarded_apply_with_grant` returns, so on the success path the row write has already
committed before the append; if the append then fails, the caller is told `AUDIT_FAILED`
(honest: "the write may have committed but is not certified auditable") rather than a clean
success. Atomic co-commit (the audit row inside the apply txn) is a documented follow-up.

### Red→green evidence

- **(a) column coverage:** `apply_it::t_wide_column_update_is_fully_reversible_revert_restores_all_columns`
  (real PG18) — a `SET notes = …` UPDATE: RED captured only `(owner, balance)` so the inverse
  dropped `notes`; GREEN captures + reverts **every** written column byte-for-byte. Engine-level
  unit tests `apply::tests::{uncaptured_written_column_aborts_before_commit,
  captured_written_column_commits, empty_preimage_floor_aborts_when_no_columns_declared}`.
- **(b) PK type:** `dry_run_it::non_int4_pk_is_refused_not_rehearsable_no_panic_conn_survives`
  (bigint/text/uuid → clean `NOT_REHEARSABLE`, NO panic, the conn serves the next request) and
  `dry_run_it::update_with_uncapturable_set_column_is_refused` (jsonb SET → refused).
- **(c) audit fail-closed:** `service_unit::apply_does_not_report_success_when_the_audit_append_fails`
  (an injected failing `_meta` sink → the apply returns `AUDIT_FAILED`, no silent success).
- **Bench:** the golden corpus gains `wide-column-update-uncaptured-column` (REVERTED) +
  `legit-wide-column-update-captured` (ALLOW); `gate_has_teeth::flipping_the_wide_column_coverage_trips_the_gate`
  proves the green scenario depends on the #75 guard. The catastrophic-FN ledger stays empty.
- **Marquee:** CLASS 2 now applies the wide-column `SET notes = 'audited'` shape end-to-end
  through the assembled stack (bounded, approval-gated, reversibly committed).

---

## S5 #76 — audit-completeness + honesty fast-follow (refusals audited · cross-process appends serialized · single anchor owner · write-path intent populated · README truthful)

**SPEC sections touched:** §3/§4 (deterministic floor, "records every statement
incl. rejects"), §10 ("rejects recorded"), §10.9 (one anchored chain, root-of-trust),
§15.1 (intent capture T0–T2, **captured/logged only** — RiskEngine stays a stub=Allow).

**Issue:** #76 (S5 sprint-review fast-follow — five undisclosed audit-completeness +
honesty gaps; none loosens the floor — every change is tighten-only / fail-closed).

### Item 1 — propose/dry_run REFUSALS are now audited (was: ZERO trace)

`Service::{propose,dry_run}` (`crates/applyd/src/service.rs`) returned a structural
refusal (the "delete a DB"/DROP/TRUNCATE headline, a volatile/PK-less dry_run) with
**no** `_meta` record — violating §3/§10 "rejects recorded". Now each refusal appends a
`Decision::Block` record (carrying the refusal's stable `reason_code` + the verbatim
statement + principal) to the SAME shared `_meta` chain BEFORE returning, via the same
fail-closed append the apply path uses (`audit_refusal_then` → `audit_decision`). If the
append itself fails, the caller gets `AUDIT_FAILED` (the refusal is reported as unrecorded
rather than silently lost). Tests: `service_unit::{refused_propose_leaves_a_verifiable_meta_block_record,
refused_dry_run_leaves_a_verifiable_meta_block_record}`.

### Item 2 — cross-process audit appends serialized (was: a `UNIQUE(seq)` race)

warden + applyd + proxy are **separate processes**, each with its own `PgSink`/`Client`.
The in-process `SharedSink` mutex orders one process' appends, but two processes could both
read head `N` and both INSERT seq `N+1`, colliding on `UNIQUE(seq)` → fatal to the live
warden (`run.rs` treats an append failure as fatal) or a dropped record. `PgSink::append`
(`crates/audit/src/pg.rs`) now wraps the head-read + insert in **one transaction** holding a
fixed `pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)`, serializing the read-then-insert across
every appender. The lock auto-releases at commit/abort, so a crashing appender never wedges
the chain; `UNIQUE(seq)`/`UNIQUE(record_hash)` remain as a loud last-resort backstop. IT:
`concurrent_append_it::concurrent_appenders_from_two_connections_produce_a_contiguous_verifying_chain`
(80 concurrent cross-connection appends → contiguous chain seq 0..79, verifies, no crash, no
lost record; RED without the lock = backend error / lost record).

### Item 3 — single anchor OWNER over the one shared chain (was: N uncoordinated anchorers)

Proxy and applyd each ran their OWN anchorer with SEPARATE anchor files + SEPARATE signing
keys over the ONE shared chain — so "one anchored chain" was really N uncoordinated
anchorers, and a restart could fail-closed-deadlock against the other's head or re-baseline a
tampered chain by anchoring first. **Decision:** designate exactly ONE anchor OWNER via a
`PGB_ANCHOR_ROLE=owner|verify` flag (`AnchorRole` in `crates/audit/src/boot.rs`). The
**proxy** is the default `owner` (the sole anchorer; it runs the interval anchorer + the
verify-before-anchor boot). **applyd** (and any other consumer) is `verify` — it runs
`AuditBoot::verify_only`: verify the persisted chain against the owner's durable anchored head
(fail-closed on a mismatch) but **never anchor**, so a verify-only binary over a tampered
chain REFUSES and crucially cannot re-baseline it. The `deploy/{proxy,applyd}.env.example`
defaults are now COHERENT: the SAME signing key (`pgb-audit-signing-key-dev-000001`) + the
SAME anchor file + an explicit `PGB_ANCHOR_ROLE` (proxy=`owner`, applyd=`verify`). Why the
proxy is owner: it is the long-lived, always-on inline endpoint; applyd is the write-path
daemon that may restart more often, so making it verify-only avoids anchor churn. The
cross-restart fail-closed property from #64/#71 is preserved (the owner still
verify-before-anchors; the verifier still refuses a forged head). Tests:
`boot::tests::{anchor_role_parse_defaults_and_values, verify_only_does_not_anchor_when_no_owner_baseline_exists,
verify_only_refuses_a_tampered_chain_and_never_rebaselines}` + the real-PG18 IT
`single_anchor_owner_it::single_owner_anchors_verifier_verifies_concurrent_restart_clean_tamper_refused`
(owner anchors one head; verify-only verifies WITHOUT anchoring across a concurrent restart;
a tampered chain is REFUSED with no re-baseline).

### Item 4 — write-path intent tiers POPULATED (was: `IntentTiers::default()` — empty)

`Service::audit_apply` logged `IntentTiers::default()` (EMPTY) on every write, while the read
path (`crates/proxy/src/recorder.rs`) populated it. The write path now populates the tiers
from the data in hand via `IntentTiers::from_statement(role, statement, Some("applyd"))` (T0
role + T1 SQL class + any `/* intent: … ticket: … actor: … */` annotation), matching the read
path. This is **capture/log only** per §15.1 — the RiskEngine stays a stub=Allow and is NOT
given teeth. The optional explicit-intent passthrough (MCP client → `intent` field) was left
out: the statement-derived default is sufficient and works without it (disclosed as a
non-requirement, not silently dropped). Test:
`service_unit::apply_committed_meta_record_carries_populated_intent_tiers` (the apply-committed
`_meta` record carries non-empty T0–T2, NOT the empty default).

### Item 5 — README accuracy (honesty — the inverse of the S4 "doc != reality" lesson)

`README.md` described S3/S4/S5 as in-progress/skeleton/upcoming, contradicting merged
reality (underclaiming). Marked S0–S5 **merged · green on PG18**; present-tensed the wired
layers (proxy is the audit anchor owner; reads through the proxy, writes through `pgb-applyd`;
the warden is the runnable audited watchdog; one shared, persistent, anchored `_meta` chain);
added `crates/applyd` (`pgb-applyd`), the `pgb-mcp` stdio shell, and `pgb-cli verify` to the
component layout. The honest split-by-damage-class guarantee language (writes = 0 catastrophic
FN by construction; reads = bounded ≤ B not zero; audit = tamper-evident) and the disclosed
carve-outs are unchanged — no overclaim.

### Honest scope (what this did NOT change)

The deterministic floor is untouched — these are audit-completeness + serialization +
topology + honesty fixes, every one tighten-only. The `_meta` audit append is still NOT
atomically co-committed with the apply txn (the documented #75 ordering caveat stands). The
RiskEngine is still a stub=Allow (§15.1). The optional MCP-passed explicit intent remains a
disclosed non-requirement.

---

## #80 — MVP spec-faithfulness closeout: proxy `search_path` pin WIRED + `replica.dsn`/§10.8-degraded-budgets recorded as inert

**SPEC sections touched:** §3 (layer-1 WALL "search_path pinned"; layer-2 proxy injection),
§10.8 (degraded mode, no replica), §12 / §12.1–§12.2 (replica is OPTIONAL; the bounded +
reversible invariant holds regardless of the replica).

**Issue:** #80 (final-audit LOW-gap closeout → 0 undisclosed gaps). Tracks the deferred
read-routing/degraded-budget work under **#77**.

### Gap 1 — proxy `search_path` pin: WIRED (code now matches the docs)

SPEC §3's layer-1 WALL lists "search_path pinned", and both
`deploy/sql/10_hardened_role.sql` and `deploy/README.md` named the **proxy** as the
*authoritative* per-session pin — but `crates/proxy/src` injected ONLY `statement_timeout`
on backend originate; it never `SET search_path`. That was a **true-in-docs / absent-in-code**
claim (the only enforcement was the role-level GUC, which a non-superuser can defeat on its
own session).

**Fix (tighten-only, defense-in-depth):** the proxy now `SET search_path = <pin>` on **every**
brokered backend session, run in `connect_backend` (`crates/proxy/src/session.rs`
`inject_search_path`) right beside the existing `statement_timeout` injection, over the same
self-issued extended-protocol unit, fail-closed on a backend error. The pin is config-driven
(`ProxyConfig::search_path`, env `PGB_SEARCH_PATH`) and defaults to
`ProxyConfig::DEFAULT_SEARCH_PATH = pg_catalog, "public"` — the **same minimal fixed value**
`deploy/sql/10_hardened_role.sql` pins at the role level (no `"$user"`, not wide-open).
Because each brokered session is a fresh origination the proxy re-pins, an agent-chosen
`search_path` can never carry into a new session.

This is **not** a new guarantee — the WALL's read guarantee is grant-based and already
`search_path`-invariant (`deploy/test/wall_matrix.sh` §I proves the agent can mutate / `RESET
ALL` its path yet STILL cannot read non-whitelisted data or write). The pin cannot *widen*
access; it makes the code match the SPEC/WALL docs and gives a deterministic minimal path.

**Red→green (real PG18, high ports via `deploy/local-stack.sh`; NEVER 5432):**
`crates/proxy/tests/proxy_it.rs::proxy_pins_search_path_on_every_brokered_session`. The pin
used in the test (`pg_catalog, public, pg_temp`) is deliberately DISTINCT from the role-level
pin so a pass proves the **proxy** set it. RED (injection disabled):
`current_setting('search_path')` on a brokered session returns the role-level `pg_catalog,
public` — assertion fails. GREEN (injection wired): it equals the proxy pin; the agent's own
`SET search_path` is blocked by the proxy; a fresh brokered session is re-pinned.

`deploy/sql/10_hardened_role.sql:67` and `deploy/README.md` were updated from "the proxy is
authoritative (intended)" to "the proxy **is wired** (`inject_search_path`), proven by the
IT" — closing the doc-vs-code gap in both directions.

### Gap 2 — `replica.dsn` is INERT and §10.8 degraded budgets are NOT differential (RECORDED, deferred → #77)

`replica.dsn` parses into `pgb_policy::ReplicaConfig` (`crates/policy/src/config.rs`) and is
validated/round-tripped, but it is **not consumed** by any enforcement path: the proxy always
originates its backend against the configured `PGB_BACKEND_*` target (the primary in the local
stack), there is **no read-routing to a replica**, and the per-role budgets are **not** made
differentially stricter when no replica is present (no SPEC §10.8 degraded-mode budget switch).
Today the same `policy.yaml` budgets apply whether or not a replica DSN is set.

This is recorded, not wired, by design and matches the SPEC's §12-optional posture: §12 makes
the replica (and DBLab and PITR) **OPTIONAL**, and §12.1 states the bounded-blast-radius +
reversibility **invariant holds regardless of the replica**. The deterministic floor (WALL +
single-shot byte/row cutoff + cumulative per-window budget + `statement_timeout` + warden +
EXPLAIN-cost gate) already bounds reads to ≤ B and refuses irreversible/structural writes on
the **primary** path — so routing reads to a replica and tightening budgets in degraded mode
is a **preview/isolation-experience upgrade** (SPEC §12 "Graceful degradation" table), not a
safety prerequisite. Wiring read-routing + a stricter degraded budget profile is tracked
**post-MVP under #77**.

**Honest scope:** no degraded-mode budget differential and no replica read-routing exist yet;
`replica.dsn` being set does **not** change runtime behavior. Disclosed in `KNOWN_BYPASSES.md`
as **B7**. (This is a scope/disclosure note, NOT a deterministic-floor false-negative — the
`dbsafe-bench` catastrophic-FN ledger stays empty.)

---

## #87 — moat-seam fix: close the fail-OPEN pre-image hole, RR apply isolation, and correct the over-claimed PK-set-checksum framing

**SPEC sections touched:** §3 (deterministic floor: bounded-&-reversible writes), §4 (guarded
apply — step 4 pre-image capture / step 5 PK-set re-check / step 6 reconciliation), §13.2
(what makes a guarded write "capped and undoable"), §14.3 (the signed, proposal-bound grant —
the apply-time PK-set checksum binds it to the exact approved row-identity set), §10.1/§10.3
(blast radius + typed-inverse). **Issue:** #87.

### Behavior changes (tighten-only — every change only ADDS an abort)

1. **P1 — the fail-OPEN pre-image seam is CLOSED.**
   `crates/clone-orchestrator/src/conn.rs::apply_forward` previously substituted an **id-only**
   image for a `RETURNING` row that was **not** in the `FOR UPDATE` pre-image snapshot
   (`preimage.get(&id).cloned().unwrap_or_else(|| vec![("id", id)])`). Under READ COMMITTED a
   row that commits **into** the predicate between the capture and the write (a concurrent-insert
   TOCTOU) got this id-only image; for a **DELETE** it then passed the count-only coverage guard
   and committed `reversible:true` with an **un-revertable** restore (a re-insert holding only the
   PK). That was a catastrophic, by-construction false-negative against the "0 catastrophic
   data-loss FN" claim. **Now** a written row with no captured pre-image is a typed
   `ApplyError::MissingPreImage` ⇒ the apply **ROLLBACKs** (no mutation). Proven against real
   PG18 (a helper holds a `FOR UPDATE` lock on the max approved row so the apply's FOR UPDATE
   blocks on it; while blocked the helper commits a racing row INTO the predicate): RED — the
   id-only fallback committed (or aborted only incidentally on a footprint-amplifying audit
   trigger); GREEN — `MissingPreImage` abort, row intact.

2. **P2 — the apply txn now opens at REPEATABLE READ (not READ COMMITTED, not SERIALIZABLE).**
   `conn.rs::begin` issues `BEGIN ISOLATION LEVEL REPEATABLE READ` (keeping
   `SET LOCAL statement_timeout`). One stable snapshot spans the step-5 recompute, the FOR UPDATE
   capture, the RETURNING write, and the `pg_stat_xact_*` reconciliation — closing the window in
   which a row could commit into the predicate between the capture and the write **at the source**
   (the P1 `MissingPreImage` becomes the defense-in-depth backstop). A concurrent change the
   snapshot cannot serialize raises SQLSTATE **40001**, now classified as
   `ApplyError::SerializationFailure` (previously swallowed into `Backend`). **Policy: abort, do
   NOT retry** — a retry would burn the already-consumed single-use §14.3 grant nonce and re-open
   the TOCTOU. SERIALIZABLE is deliberately not used (its extra predicate locking buys nothing
   here and would only widen the abort surface). Proven against real PG18: a concurrent INSERT
   into the predicate is now invisible to BOTH the capture and the write (the approved set commits
   + reverts byte-for-byte); a concurrent UPDATE of a target row raises 40001 ⇒ clean
   `SerializationFailure` abort, no mutation. RED — pre-fix the concurrent INSERT reproduced the
   `MissingPreImage` gap and the concurrent UPDATE **COMMITTED** while the inverse captured the
   *concurrent* value as the "old" value (a wrong, un-revertable restore).

### Documentation correction — the over-claimed PK-set-checksum framing (the WHY of this issue)

SPEC §13.2 (~L585) attributes "capped and undoable" to the affected-PK-set re-check. An
adversarial code analysis showed this **mis-attributes** the bound/undo guarantees:

- **Bounded (capped)** is carried by the **`pg_stat_xact_*` per-op-type reconciliation**
  (step 6) **+ the `statement_timeout` budget** (step 2) — a write that touches an unpredicted
  relation, exceeds a predicted op channel, or runs too long aborts.
- **Reversible (undoable)** is carried by the **apply-time pre-image capture**
  (`FOR UPDATE`+`RETURNING`, step 4) **+ the coverage guards** (step 8 row coverage / step 8b
  column coverage, and now the P1 `MissingPreImage` seam).
- The **apply-time PK-set re-check is an anti-TOCTOU authorization-freshness binding**, not the
  bound/undo guard: it binds the human's §14.3 grant to the **exact approved row-identity set**
  (catching same-count/different-PK drift that a row-count guard misses), and fails closed on
  drift (re-approve required). It is load-bearing only for stable, explicitly-keyed writes; over
  a high-churn predicate it is a no-op (quiescent) or a self-abort (busy) — by design.
  SPEC §14.3 (L697–700) already states this binding correctly and is **not** changed; only the
  §13.2 framing is re-attributed here.

Per `CLAUDE.md` §8 the build-frozen SPEC body is **not** edited; this amendment records the
re-attribution. The in-tree comments corrected to match: `CLAUDE.md` §2 (the bound/undo vs
freshness-gate distinction), `apply.rs` step-5 docstring ("freshness/authorization re-check
(not the bound/undo guard)"), and `KNOWN_BYPASSES.md` **B8** (the exact-set re-check makes
guarded writes a low-churn / re-review-on-drift instrument, not a bulk applier).

### Evidence (red→green; real PG18 + the deterministic gate)

- **Real PG18 (env-gated `PG_BUMPERS_IT=1`, dedicated high port, NEVER :5432):**
  `crates/clone-orchestrator/tests/apply_it.rs` adds the deterministic race (helper holds a
  `FOR UPDATE` lock so the apply blocks; the racing change commits during the block):
  `t_concurrent_insert_into_predicate_delete_aborts_missing_preimage_read_committed`,
  `…_update_…` (P1 `MissingPreImage`),
  `t_repeatable_read_closes_the_concurrent_insert_gap_production_conn_commits_reversibly`
  (P2 RR clean commit + byte-for-byte revert), and
  `t_repeatable_read_concurrent_update_of_target_row_serialization_failure_aborts` (P2 40001).
- **Deterministic gate (`dbsafe-bench`):** a new golden scenario
  `concurrent-drift-delete-missing-preimage` (the pre-image seam is the SOLE catch — all other
  guards reconcile) is CI-locked at `REVERTED`, with a `gate_has_teeth` flip
  (`flipping_the_preimage_seam_trips_the_gate`) proving the gate catches the catastrophic
  un-revertable commit when the seam is fail-OPEN. The catastrophic-FN ledger
  (`golden/known_bypasses.json`) stays **empty** (0 FN, 0 FP).

---

## EPIC #91 — the exact-PK-set checksum is DROPPED; identity → predicate gate, magnitude → absolute cap (PR-A self-determined gate + PR-B WriteCap)

**SPEC sections touched:** §10.1 (`affected.pk_set_checksum`), §10.2 (the affected-PK-set
checksum as "the guard's basis"), §14.3 (the signed grant binding fields), §4 (bounded +
reversible apply guards). **Issue:** #91 (EPIC); PR-A (#92, self-determined-predicate gate,
already merged) + **PR-B (this change, WriteCap + checksum drop, atomic).**

### Deviation (founder decision)

The build-frozen SPEC frames the **exact affected-PK-set checksum** (§10.2) as the guard's
basis — bound into the §14.3 grant (`blast_radius_checksum`) and re-derived from the live DB
at apply time to pin a human's approval to the **exact approved row-identity set** (catching
same-count/different-PK drift a row count misses). The founder **dropped** that checksum. It
was the **only absolute-magnitude anchor** on an approved write (reconciliation is *relative*
to the dry-run prediction, `statement_timeout` is wall-clock, and `RoleBudget.max_rows` is
read-path only), so it is replaced — **atomically, in one change** — by two orthogonal pins:

- **Identity (PR-A, #92):** the **self-determined-predicate gate** — a grant-bound
  `UPDATE`/`DELETE`'s WHERE may reference **only the immutable single-column primary key +
  literals + immutable functions on it**. A row's immutable PK cannot be re-pointed at a
  chosen sensitive row by any other write, so the approved `statement_text` itself pins the
  row set; the checksum becomes redundant for identity-steerability. PR-B **extends** the
  gate to refuse **`UPDATE … FROM other`** / **`DELETE … USING other`** (and any JOIN on the
  target) — a join-correlation (`UPDATE t SET … FROM other WHERE other.id = t.id`) is
  steerable by the joined table's content and was only *incidentally* fail-closed by the
  now-removed apply-time PK-set recompute (`NotSelfDetermined::JoinCorrelation`).
- **Magnitude (PR-B, this change):** the human-approved absolute **`WriteCap { max_rows,
  max_wal_bytes }`** (`pgb_core::WriteCap`), a **bound field of the §14.3 binding** (replacing
  `blast_radius_checksum`), enforced **inside the apply txn** from the summed `pg_stat_xact_*`
  row deltas + a `pg_current_wal_insert_lsn()` WAL-byte measure → `ApplyError::CapExceeded`
  abort. The CLI pre-fills it from the dry-run footprint + headroom
  (`BlastRadius::suggested_cap`); the approver may tighten or raise it per §14.2.

### `GrantBinding` v2 (cap replaces `blast_radius_checksum`)

The signed binding now commits to `{ statement_text, normalized_params, role, session_id,
proposal_id, dry_run_lsn, cap, nonce, expiry }`. **`BINDING_DOMAIN` is bumped to
`pg_bumpers.grant.binding.v2`**, so any old **v1** token (which signed over
`blast_radius_checksum`, not `cap`, under the `…v1` domain) **fails closed** under v2
verification — old grants cannot authorize a write on the new floor (`t_grant_v1_token_
fails_closed_under_v2`). A swapped/raised cap is a binding mismatch (`t_grant_cap_swap_*`).

### §14.3's "defeats data-drift since approval" — amended

§14.3's claim that re-verifying the binding "defeats data-drift since approval" is **amended**:
**identity** data-drift steering is now foreclosed by the **predicate gate** (immutable-PK
predicates — an attacker cannot re-point an immutable PK at a chosen row), and **magnitude**
drift (e.g. concurrent inserts swelling an `id`-range / `id % 2 = 0` predicate) is bounded by
the **cap**, **not** by re-deriving an exact-set checksum. The five surviving §14.3 tamper
cases (sql-swap, param-swap, cross-session, proposal-swap, replay, expiry) still REJECT via
the binding hash; the old exact-set data-drift tamper case is **re-scoped** to the cap
(`apply_time_magnitude_drift_rejects_via_cap_no_mutation`).

### What is KEPT (so the change is net tighten-only)

- the `pg_stat_xact_*` **reconciliation** (the *relative* per-op-channel effect check) —
  with the target's **primary** write channel (`upd` for UPDATE / `del` for DELETE) now
  governed by the **cap** rather than exact prediction-equality; every other channel on the
  target and **all** channels on non-target relations stay strict (so out-of-predicate target
  deletes, op-type substitution, cascade over-deletes, and `UnpredictedRelationWrite` still
  abort);
- the **pre-image capture** + `assert_reversible_preimage_coverage` + `assert_written_
  column_coverage` (reversibility — mandatory; a write that cannot be undone aborts);
- the **full §14.3 grant verification** (signature, every bound field incl. the cap,
  single-use nonce, expiry) and the **#87 fail-closed pre-image seam** + REPEATABLE READ apply
  isolation.

**Net tighten-only argument:** the cap is enforced in the **same** change that removes the
checksum — at no point is absolute magnitude unpinned. Identity (predicate gate) + magnitude
(cap) + relative effect (reconciliation) + reversibility (pre-image coverage) together carry
the floor without the exact-set checksum.

### Residual (disclosed)

A grant authorizes "**this statement, up to N rows / W WAL bytes, reversibly, with a
self-determined immutable-PK predicate**". Two honest residuals: (1) side-effecting
**AFTER-triggers** fire on the *approved* rows — a trigger writing a relation OUTSIDE the
captured inverse (e.g. an audit table) is **not effect-undone** by the typed-inverse; this is
**surfaced at approval** as a first-class fact (`RequestElevationResult.side_effecting_
triggers`). (2) The predicate gate is restricted to the **single-`int4`-PK** MVP shape; a
composite/wider PK is refused upstream, not gated here.

### Evidence (red→green; real PG18 + the deterministic gate)

- **Cap unit + real PG18 (env-gated `PG_BUMPERS_IT=1`, dedicated high port, NEVER :5432):**
  `apply::tests::cap_exceeded_on_rows_aborts_no_mutation` / `…_on_wal_bytes_aborts` /
  `within_cap_write_commits` / `cap_below_dry_run_footprint_is_refused_before_txn`; and
  `crates/clone-orchestrator/tests/apply_grant_it.rs`:
  `apply_time_magnitude_drift_rejects_via_cap_no_mutation` (concurrent inserts swell
  `id % 2 = 0` past the cap → `CapExceeded`, no mutation),
  `within_cap_concurrent_insert_still_commits_reversibly` (headroom commit + revert),
  `join_correlated_update_from_is_refused_before_txn` (the carried PR-A finding).
- **Binding v2:** `grant::tests::t_grant_v1_token_fails_closed_under_v2`,
  `t_grant_cap_swap_rejected`, `binding_hash_covers_every_field` (now covers `cap.*`).
- **Deterministic gate (`dbsafe-bench`):** the former `no-where-write-drift` golden (which
  depended on the dropped step-5 checksum) is **re-pointed** to `magnitude-drift-over-cap`
  (cap=5, live=8 → `CapExceeded` → REVERTED), with a `gate_has_teeth` flip
  (`flipping_the_absolute_cap_trips_the_gate`) proving the gate catches the over-cap commit
  when the cap is disabled, plus the positive `magnitude_drift_is_fail_closed_via_cap_
  exceeded`. The #89 `concurrent-drift-delete-missing-preimage` golden (the pre-image seam) is
  unaffected. The catastrophic-FN ledger (`golden/known_bypasses.json`) stays **empty**
  (0 FN, 0 FP).

---

## EPIC #83 — "Rust for all": the deployable MCP server is now the native Rust `pgb-mcp`; the original non-Rust MCP server is REMOVED

> **Token note (issue #101):** this historical entry was reworded to drop the literal
> non-Rust technology tokens (the scripting runtime, its package manager, and its typed
> compiler) while preserving the fact of record. The deleted server was written in a
> non-Rust scripting language with its own package manager; the specifics are not
> load-bearing — what shipped is that it was replaced by the Rust `pgb-mcp`.

**SPEC sections touched:** §1 / §3 layer 3 (the agent-facing MCP intent/UX layer — the
implementation language, not the contract), and the repo-layout note in §7 (the prior
"Cargo workspace **+ a second toolchain**" / "the original non-Rust `mcp/server`"
phrasing). The tool *contract* (the exactly-nine §11 tools, the block contract, the
`confirm_rows` forcing function, the result-data-can-never-widen-capability defense) is
**unchanged** — this is an implementation-language consolidation, not a behavior change
to the floor.

**Issue:** EPIC #83 ("Rust for all"), PR4 (final). PR1 (skeleton), PR2 (read path, #95),
PR3 (write path, #96) ported the original server to Rust; this PR4 deletes the
now-redundant original implementation and repoints the dev stack at the Rust binary.

### Deviation

The original build shipped the agent-facing MCP server as a **non-Rust scripting-language
package** under the old `mcp/server` tree (recorded in the S4 and the "S5 — MCP production
wire + live Core (#67)" sections above — the original `ApplydCore`, the original stdio
shell `bin pgb-mcp`, the original `PgProxyTransport`, the original contract + integration
tests). EPIC #83 ported that surface, **verbatim in contract**, to a native Rust crate. As
of this PR the repo is **single-language Rust**:

- The one and only deployable MCP server is the Rust **`pgb-mcp`** (crate `crates/mcp`,
  binary target `pgb-mcp`). Its stdio entrypoint is `crates/mcp/src/bin/pgb_mcp.rs` (it
  serves MCP `initialize`/`tools/list`/`tools/call` over stdin/stdout via the `rmcp` SDK).
  Full **nine-tool parity** with the deleted original server is verified (identical
  `TOOL_NAMES`; no `approve` tool — the signing-key hop stays out of the agent stdio).
- The **original `mcp/server` tree is deleted in its entirety** (its sources, tests,
  package manifest + lockfile + workspace file, compiler config, test-runner config, its
  license-check script, and the README). No artifact of the original non-Rust toolchain
  remains in the repo.
- **The dev stack now launches the Rust binary.** `deploy/up.sh` builds `pgb-mcp` via
  `cargo build` (no more second-toolchain install + build step) and its printed
  `claude mcp add` line ends with `-- <repo>/target/debug/pgb-mcp` (a Rust binary, not a
  scripting-runtime invocation), forwarding the `PGB_*` env (proxy host/port/db/user/password,
  the applyd socket, and the `_meta` DSN). `deploy/marquee.sh` runs the env-gated Rust e2e
  (`crates/mcp/tests/{write_path_e2e,read_path_e2e}.rs`) in place of the deleted original
  marquee test.
- **CI:** the dedicated job for the original server is removed from `.github/workflows/ci.yml`.
  `crates/mcp` is a workspace member, so the existing `rust` job builds + tests it
  (`cargo {build,test} --workspace`) and `cargo deny check` license-checks its deps — there
  is no longer a separate scripting-language license-check script.

### Rationale

The founder's standing ask is **"Rust for all"**: a single-language control plane is
simpler to build, test, license-check (one `cargo deny` gate instead of two), and ship.
Two language toolchains for one process was redundant once the Rust port reached parity.
**`pgb-applyd` stays a separate daemon** (crate `crates/applyd`) — the write-credential
boundary is deliberate and unchanged; the MCP server is still cooperative, NOT a security
boundary (every read passes the proxy/WALL, every write passes applyd's deterministic
floor). Removing the original surface changes the *implementation language*, never the
*floor*.

### Historical-pointer corrections (the prior non-Rust file refs above are SUPERSEDED)

The earlier amendment entries describe the now-deleted original files. Their Rust
equivalents are:

- the original Unix-socket `Core` client → **`crates/mcp/src/applyd.rs`**
  (the `ApplydClient`/`ApplydConfig`).
- the original stdio shell (`bin pgb-mcp`) → **`crates/mcp/src/bin/pgb_mcp.rs`**
  (the `pgb-mcp` binary).
- the original read transport → **`crates/mcp/src/proxy.rs`**
  (the `ProxyTransport`/`ProxyConfig`).
- the original tool dispatcher → **`crates/mcp/src/server.rs`**
  (the `PgBumpersMcp` handler).
- the original `Allow` stub → the Rust **`AllowStub`** in
  `crates/policy/src/risk.rs`, captured by `crates/mcp/src/server.rs`.
- the original live-stack tests → the env-gated Rust e2e
  **`crates/mcp/tests/{write_path_e2e,read_path_e2e}.rs`** (run by `deploy/marquee.sh`).

The historical entries are left in place as a record of what shipped at the time; this entry
is the authoritative pointer to the current (Rust) reality.

### Evidence (red→green)

- **RED:** `git grep -n 'mcp/server'` returns no hit in code/scripts (only historical notes in
  this file); the original scripting-runtime stdio path no longer exists; the tracked tree has
  no remaining original-toolchain artifact.
- **GREEN:** the §7 Rust gate (`cargo fmt --check` · `clippy -D warnings` · `build --locked` ·
  `test --locked` · `deny check`) is green with `crates/mcp` building the `pgb-mcp` binary; the
  dev stack stands up (throwaway PG18 on a high port; NEVER :5432) and `pgb-mcp` is driven live
  end-to-end (`initialize` → `tools/list` = 9 tools → a read through `pgb-proxy` → a bounded,
  operator-approved write through `pgb-applyd` read back from PG18 → `get_audit`).
