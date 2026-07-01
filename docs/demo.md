# pg_brakes — the marquee demo

> **The pitch in one line.** Let an AI agent run against *production Postgres*
> with `--dangerously-skip-permissions` and it still can't cause disaster — every
> **write** is bounded + reversible (rehearsed on a zero-impact clone first), and
> every **read** is bounded-disclosure + best-effort-detected, cut off at a
> per-role budget.

This page is a grounded walkthrough of the two headline scenarios, written
against the **real code in this tree**. It is honest about status:

| Sprint | What | Status |
|---|---|---|
| **S0** | skeleton · WALL · core · contracts · fidelity gate | **merged, green across the 14-18 CI matrix** |
| **S1** | pgwire · audit hash-chain · enforcing proxy | **merged, green across the 14-18 CI matrix** |
| **S2** | clone dry-run (blast radius) · clone governance + orphan-reaper | **merged, green across the 14-18 CI matrix** |
| **S3** | guarded apply · typed-inverse capture · auto-revert | **in progress / in review** |
| **S4** | warden · MCP wiring · policy wiring · audit→`_meta` · read-gate roll-up · CLI approval | upcoming / fast-follow |
| **S5** | deterministic benchmark · marquee MCP-bypass repro | upcoming / fast-follow |
| — | LLM risk-gating engine | upcoming (the MVP `RiskEngine` is a **stub returning `Allow`**) |

> **Substrate.** Live tests run against **local Postgres** (any supported major,
> **14–18**; spec v0.8.1 §0.5) via Homebrew kegs (`initdb` / `pg_basebackup` /
> `pg_ctl`), the founder-approved docker→local-PG pivot. The shipped
> `deploy/docker-compose.yml` parameterizes the image as `postgres:${PG_MAJOR:-16}`
> and is kept as the user-facing artifact; the CI matrix exercises all five majors.
> See [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md).

Source of truth: [`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8).

---

## Part 1 — write-safety: the no-`WHERE` `UPDATE`

The killer demo. An agent proposes a fat-fingered, unbounded write:

```sql
UPDATE accounts SET balance = 0   -- no WHERE: every row
```

Instead of running it on prod, pg_brakes **rehearses** it, **measures the blast
radius**, and (S3) **applies it under guards** so a slipped write **auto-reverts**.

### 1a · Propose → dry-run → blast radius (S2, MERGED)

The dry-run engine lives in
[`crates/clone-orchestrator/src/dry_run.rs`](../crates/clone-orchestrator/src/dry_run.rs).
Its pipeline is **fail-closed** at every step (`dry_run()`):

1. **TTL** — an expired proposal is refused (`propose` stamps a 15-min TTL
   against an injected monotonic clock; SPEC §10.4).
2. **Classify** (advisory `sqlparser` parse) — only `UPDATE`/`DELETE` on a plain
   table are rehearsable; `TRUNCATE`/`DROP`/`ALTER`/`INSERT`/`SELECT`/`MERGE` are
   `NotRehearsable` (default-deny).
3. **Volatile-predicate refusal** — the `WHERE` AST is walked; non-deterministic
   keywords (`now()`, `CURRENT_TIMESTAMP`, `LOCALTIMESTAMP`, `CURRENT_DATE`, …)
   are refused by name and every other function is resolved against
   `pg_proc.provolatile` (`volatile` **or** `unknown` ⇒ refuse). This is a
   `pg_proc` *read* only — **the candidate is never executed**.
4. **Rehearse** — the backend runs the statement in a `BEGIN … ROLLBACK` txn and
   measures the affected-PK set (via `RETURNING <pk cols>`), cascades, triggers,
   locks, WAL, and duration.
5. **PK-less guard** — a target (or any cascade) with **no primary key** is
   refused: `DryRunError::PkLess`, **no `ctid` fallback** (SPEC §10.2).
6. **Assemble** — fold into the §10.1 [`BlastRadius`](../crates/core/src/blast_radius.rs) record.

#### Where the rehearsal runs — two real providers

The measurement backend is the `Rehearsal` trait — the clone-provider seam
([`crates/clone-orchestrator/src/provider.rs`](../crates/clone-orchestrator/src/provider.rs)):

- **Baseline (`clone.provider: none`)** — `NoneProvider`: rehearse in a
  rolled-back txn **on the primary itself**. It holds the write's locks
  (`RowExclusiveLock`, …) for the rehearsal's duration, then rolls back. Zero
  *persistence* impact, but it does touch the primary (SPEC §12 tradeoff).
- **The moat (`local` provider, the DBLab stand-in)** — `LocalCloneProvider`
  ([`provider/local.rs`](../crates/clone-orchestrator/src/provider/local.rs)):
  take a `pg_basebackup` of the primary into an **isolated Postgres cluster on a
  dedicated port**, rehearse *there*, then tear it down. **Zero write/lock impact
  on the primary** — the clone inherits prod's catalog, RLS policies, and column
  grants byte-for-byte (parity is *inherent*).

Both are proven against the live backend (env-gated `PG_BRAKES_IT=1`; now exercised across the 14-18 CI matrix). The clone path's
zero-prod-impact is asserted in
[`tests/clone_governance_it.rs::marquee_rehearses_on_clone_with_zero_primary_impact`](../crates/clone-orchestrator/tests/clone_governance_it.rs)
— the primary's balances are **byte-identical** before/after and the *same*
primary backend PID served both reads (the rehearsal never opened a txn on prod).

#### Run it

```sh
# Baseline (in-txn) dry-run against a throwaway Postgres cluster:
PG_BRAKES_IT=1 cargo test -p pgb-clone-orchestrator --test dry_run_it -- --nocapture

# The clone-provider path (real pg_basebackup → isolated clone → zero prod impact):
PG_BRAKES_IT=1 cargo test -p pgb-clone-orchestrator --test clone_governance_it -- --nocapture
```

(DSN defaults: the dry-run IT defaults to a dedicated throwaway port — override
with `PG_BRAKES_PGURL`; the clone-governance IT spins its own clusters. See
[`docs/quickstart.md`](quickstart.md) §4.)

#### What you see — the blast-radius record (real shape, real values)

The seed is 8 accounts with distinct, non-zero balances, an `AFTER UPDATE OR
DELETE` row trigger (`accounts_audit_aud`) writing an audit table, and an FK child
`entries` with `ON DELETE CASCADE` (2 entries per account)
([`tests/common/mod.rs`](../crates/clone-orchestrator/tests/common/mod.rs)). The
marquee `UPDATE public.accounts SET balance = 0` (no `WHERE`) produces, on the
clone:

```json
{
  "proposal_id": "p-1f3c9a0b7e4d2c81",
  "clone_lsn": "0/1A2B3C8",
  "staleness_lsn_bytes": 0,
  "affected": {
    "by_table":         { "public.accounts": 8 },
    "cascade_by_table": {},
    "pk_set_checksum":  { "public.accounts": "sha256:5e1b…<64 hex>" },
    "total_rows": 8
  },
  "triggers_fired": [ { "name": "accounts_audit_aud", "rows": 8 } ],
  "locks":          [ { "relation": "public.accounts", "mode": "RowExclusiveLock", "held_ms": 0 } ],
  "max_lock_mode": "RowExclusiveLock",
  "duration_ms": 13,
  "wal_bytes": 4096,
  "constraint_violations": [],
  "reversible": true,
  "inverse_kind": "PREIMAGE_UPSERT",
  "predicate_volatile": false
}
```

The numbers (`8` rows, the trigger firing 8 times, `RowExclusiveLock`,
`reversible: true`, `inverse_kind: PREIMAGE_UPSERT`, `predicate_volatile: false`)
are exactly what
[`marquee_no_where_update_previews_and_leaves_primary_unchanged`](../crates/clone-orchestrator/tests/dry_run_it.rs)
asserts against the live backend. The record round-trips through serde (the §10.1 wire
contract is pinned by a test). `clone_lsn` / `pk_set_checksum` digest values are
illustrative; the row counts, trigger, lock mode, and flags are real.

> **The point.** The operator (or the `confirm_rows` forcing function — the
> proposal carries `expected_rows: Some(8)`) sees **"this touches all 8 rows"**
> *before* anything hits prod. On the clone path, the primary is provably
> untouched. At production scale, the same preview reports the full row count
> before a single row is changed.

A `DELETE` shows cascades too —
[`delete_cascade_measures_child_pk_set`](../crates/clone-orchestrator/tests/dry_run_it.rs)
deletes 4 parent accounts and reports `cascade_by_table: {"public.entries": 8}`
(2 children each), `total_rows: 12`, `inverse_kind: INSERT`.

#### Refusals you can watch fail-closed (all MERGED)

Every one of these is exercised against the live backend in `dry_run_it.rs`, and the DB
is asserted **byte-for-byte untouched** afterward:

| Proposed statement | Outcome | Why |
|---|---|---|
| `… WHERE balance > now()` | `REFUSED: Volatile` | non-deterministic keyword |
| `… WHERE owner < CURRENT_TIMESTAMP::text` | `REFUSED: Volatile` | parenless keyword behind a cast |
| `… WHERE owner > public.evil_now()::text` | `REFUSED: Volatile` | volatile UDF caught via `pg_proc.provolatile='v'` |
| `… WHERE id = (CASE WHEN random() < 0.5 …)` | `REFUSED: Volatile` | volatile built-in nested in `CASE` |
| `DELETE FROM public.event_log WHERE kind='seed'` | `REFUSED: PkLess` | no primary key, **no `ctid` fallback** |
| `… WHERE coalesce(owner,'')='owner-3'` | **proceeds** | special form, deterministic (allow-set), `predicate_volatile=false` |
| `… WHERE id = 5` / `lower(owner) = 'x'` | **proceeds** | immutable predicate, no over-refusal |

The classifier is **advisory** — the un-foolable guarantees are downstream (the
rolled-back txn here; the WALL role + timeout + cutoff on the read path). Honesty
note: the volatile-refusal is fail-closed (unknown ⇒ refuse), but it is
*best-effort* recognition, not a proof of determinism.

### 1b · Guarded apply + typed-inverse + auto-revert (S3, IN PROGRESS / IN REVIEW)

> **Status: this lands in S3, currently in review.** The pieces below describe
> the *designed and partially-built* apply path. What is **merged today** is the
> drift-decision seam and the typed-inverse/certified-action *types*; the
> end-to-end PITR-fenced apply loop is the in-flight work. Don't demo this as
> shipped.

The apply path (SPEC §10.3) is built from real, merged building blocks:

- **The drift guard — already merged.**
  [`guard_decision(dry_run_checksum, apply_checksum)`](../crates/clone-orchestrator/src/lib.rs)
  compares the dry-run **affected-PK-set checksum** to a re-computed apply-time
  checksum and returns `DriftDecision::Abort` on *any* mismatch. Critically, the
  guard is the **PK set**, not the row *count*: a predicate that flips to a
  different set of rows with the *same* cardinality still drifts and aborts
  (`predicate_flip_same_count_different_rows_aborts`).
- **The typed inverse — types merged.**
  [`crates/core/src/inverse.rs`](../crates/core/src/inverse.rs) captures, per
  affected row, `{pk, before_image}`. For an `UPDATE` the inverse is a
  pre-image re-apply (`InverseKind::PreimageUpsert`); for a `DELETE` it's a
  re-insert (`InverseKind::Insert`), applied in **FK order**.
- **Default-deny certified action set — merged.** `certify()` is the single
  choke point: only `BoundedUpdate` / `BoundedDelete` / `NonVolatileInsert` (each
  requiring a usable PK and a captured pre-image) are auto-appliable; `TRUNCATE`,
  `DROP`, `ALTER`, volatile-default `INSERT`, pre-image-less `DELETE`, PK-less
  writes, and anything unknown are `RefusedOp`. A property test sweeps the op
  space and proves the allow-list is **exactly closed**.

The intended apply sequence (S3):

```
restore-point fence (PITR)         ← reversibility floor: a named restore point before the write
  → re-measure affected-PK set
  → guard_decision(dry_run_pks, apply_pks)   ← Abort on ANY drift (fail-closed)
  → apply inside a txn under statement_timeout
  → commit
  → typed-inverse captured
  → if a guard slips post-commit → AUTO-REVERT via the captured inverse,
    then emit a VERIFIABLE DIFF (PK-set before/after)
```

**Honestly scoped reversibility.** The inverse restores **table row state only**.
[`NotRestored`](../crates/core/src/inverse.rs) names — and a test asserts — exactly
what it does **not** undo: **sequence advances** (`nextval` gaps stay), **trigger
side-effects** (e.g. the `account_audit` rows the trigger wrote), and **`NOTIFY`**
messages already delivered. The promise is **bounded + reversible with 0
catastrophic data-loss false-negatives *by construction*** (a write that can't be
certified bounded+reversible is refused, never applied) — not "magically undo
everything."

---

## Part 2 — read-safety: bounded disclosure, no statement-stacking

The enforcing proxy ([`crates/proxy`](../crates/proxy)) is the **only** network
path to the DB (SPEC §3 layer 0). It terminates the agent's TLS + SCRAM-SHA-256
handshake and **originates** a fresh backend session as the hardened WALL role
`pgb_agent` (terminate-and-originate; see
[`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md) S1). On that session it
applies the un-foolable backstops. **All of this is merged (S1).**

### The marquee block: `COMMIT; DROP SCHEMA public CASCADE`

This is the attack that bypassed a well-known read-only Postgres MCP:
statement-stacking over the **simple-query** protocol.

pg_brakes kills it structurally. The gate
([`crates/proxy/src/enforce.rs`](../crates/proxy/src/enforce.rs)) is
**extended-protocol-only**: a simple `Query` ('Q') frame — the *only* wire path
that permits multiple statements in one message — is **rejected outright**, before
the body is even parsed:

```
GateDecision::Reject {
  kind: SimpleQuery,
  code: "simple_query_rejected",
  message: "simple query protocol is not permitted for agent connections;
            use the extended protocol (Parse/Bind/Execute) — this blocks
            statement-stacking such as `COMMIT; DROP SCHEMA …`"
}
```

Proven end-to-end against the live backend in
[`tests/proxy_it.rs::proxy_enforcement_end_to_end_against_pg18`](../crates/proxy/tests/proxy_it.rs):
`batch_execute("COMMIT; DROP SCHEMA public CASCADE")` (a simple `Query` frame) is
**blocked**, and the test then proves the `public` schema **still exists** — the
`DROP` never reached the backend. The statement is captured **verbatim** in the
audit hash-chain.

Belt **and** suspenders: even if the stacked statement is smuggled into a single
extended-protocol `Parse` body, the read-only classifier blocks it
(`stacked_statement`) — see
[`marquee_commit_drop_schema_is_blocked_even_via_extended_parse`](../crates/proxy/src/enforce.rs).

### The read-only gate

A `Parse`'s SQL is classified (`pgb_pgwire::classify`); anything not provably a
**single read** is blocked. From `proxy_it.rs`, all proven against the live backend:

- `UPDATE` / `DELETE` / `CREATE TABLE` / `DROP TABLE` → **blocked**
  (`write_on_readonly`) — and the WALL role is the un-foolable backstop even if
  the classifier were fooled.
- `COPY … TO STDOUT` → **blocked** (`COPY … PROGRAM` is an RCE vector; no
  per-statement gate on the bulk path).
- Unparseable SQL (`SELEKT * FRM nonsense !!!`) → **blocked** (`parse_failed`),
  fail-closed.
- A legit read-only `SELECT` → **allowed** (still subject to the WALL role,
  budget, and timeout downstream). The session **survives** every recoverable
  block (`SELECT 42` still works after the storm).

### Bounded disclosure: the byte/row cutoff

A single read must not be allowed to drain the database. The proxy meters **every
bulk path** against the role's single-shot budget and **cuts off mid-stream**
([`crates/proxy/src/budget.rs`](../crates/proxy/src/budget.rs) +
`session.rs::relay_until_ready`):

- **`DataRow` ('D')** and **backend-COPY `CopyData` ('d')** are charged against
  the *same* per-role `max_bytes` / `max_rows`. The row that would breach is **not
  forwarded**; an `ErrorResponse` (`53400`) goes to the agent and the cutoff is
  audited as a `BLOCK`.
- A metered COPY-out cutoff **fails the session closed** (the backend COPY is torn
  down, never proxied unmetered) — so even a classifier-mis-allowed `COPY` or a
  misbehaving/compromised backend cannot stream bytes outside the budget. This is
  un-foolable *via the classifier*. Unit-tested in `session.rs`
  (`copy_out_copydata_is_metered_and_cut_at_budget`) and exercised end-to-end in
  `proxy_it.rs` (a 5000-row × ~200-byte table cut at a 100-row / ~50 KiB budget).

The cap is inclusive: streaming *exactly* the cap is fine; the next row trips it.

> **Honesty (SPEC §1).** Reads are **bounded disclosure** — `≤` a per-role
> byte/row budget, then cutoff — **plus best-effort detection**. Disclosure
> already streamed within budget *can't* be un-happened. We never claim
> "impossible." The audit chain is **tamper-EVIDENT** (`verify_chain()` detects
> any edit/reorder), not tamper-proof.
>
> **S1 scope note.** The **single-shot per-query** cutoff above is active. The
> **cumulative per-window** budget (`per_window` / anti-slow-drip) is parsed into
> config but **inert in S1** — it is an **S4** feature. Don't claim per-window
> enforcement is live.

### `statement_timeout`: the runaway backstop

The proxy injects `SET statement_timeout` on the backend session
(`session.rs::connect_backend`). Since **M2a (#114/#115)** the read-only
classifier is a **fail-closed allowlist gate**, so `SELECT pg_sleep(30)` no longer
classifies as a read — `pg_sleep` is not on the read-safe allowlist, so the
statement is `NotRead` → **Blocked at the read-only floor** before it reaches the
backend (proven in `enforce.rs::function_call_writes_are_blocked_at_the_floor_gate`,
which asserts `SELECT pg_sleep(30)` is `Block`ed, and end-to-end in `proxy_it.rs`,
where `SELECT pg_sleep(5)` through the proxy returns a `read-only`-gate block, not a
timeout). The `statement_timeout` remains the **un-foolable DoS backstop** for
anything that *does* slip past the classifier — a genuinely slow *allowlisted* read
is still bounded by the injected timeout, so DoS-by-runtime is capped regardless of
classification.

### TLS is required (no silent downgrade)

When TLS material is configured, TLS is **required** (`require_tls`, default-on):
a client that opens with a direct plaintext `StartupMessage` (no `SSLRequest`) is
**rejected**; there is no cleartext auth path. Proven in
[`tls_is_required_when_configured`](../crates/proxy/tests/proxy_it.rs):
`sslmode=disable` is refused, `sslmode=require` works. (Dev-only no-TLS mode is an
explicit opt-in via `PGB_PROXY_REQUIRE_TLS=false`, never a fallback. The
proxy→backend loopback hop relies on the §3 layer-0 network boundary; backend-hop
TLS is the one remaining deferral — SPEC.amendments S1.)

#### Run it

```sh
deploy/local-stack.sh up
PG_BRAKES_IT=1 cargo test -p pgb-proxy --test proxy_it -- --nocapture
deploy/local-stack.sh down
```

The audit assertions at the end verify the chain holds (`verify_chain()`) and
that it recorded at least one `ALLOW`, the read-only/cutoff `BLOCK`s, and the
simple-query `REJECT` — with the marquee `COMMIT; DROP SCHEMA` captured verbatim.

> **S1 audit-sink note.** The shipped proxy keeps the hash-chain **in-process**
> (`InMemorySink`). Persisting it to the Postgres `_meta` sink (the already-built,
> already-tested `pgb_audit::PgSink`) is wired in a follow-up — it reuses merged
> code and changes no proxy logic.

---

## What this demo proves — and what it doesn't

**Proven, merged, green across the 14-18 CI matrix:**

- A no-`WHERE` `UPDATE` is **measured** (rows, cascades, triggers, locks, WAL,
  affected-PK set, reversibility) **without touching prod** — in a rolled-back
  txn (baseline) *or* on a real `pg_basebackup` clone with **zero primary impact**.
- Volatile predicates and PK-less targets are **refused fail-closed**, never run.
- `COMMIT; DROP SCHEMA public CASCADE` over simple-query is **blocked**; the
  schema survives.
- Reads are **bounded** at the byte/row budget (`DataRow` *and* COPY), and
  `statement_timeout` **fires** on the classifier's blind spot.
- Every decision is on a **tamper-evident** hash-chain that verifies.

**In progress (S3) — describe as designed, not shipped:**

- PITR-fenced **guarded apply**, apply-time PK-set re-check, post-commit
  **auto-revert** with a verifiable diff. The drift guard, typed-inverse capture,
  and default-deny certification *types* are merged; the end-to-end apply loop is
  in review.

**Upcoming / fast-follow (S4/S5 + the LLM gate):**

- Warden, MCP wiring, policy wiring, audit→`_meta`, per-window read budgets, CLI
  approval; the deterministic benchmark and the marquee MCP-bypass repro.
- The **LLM risk-gating engine**. Today the `RiskEngine` is a **stub returning
  `Allow`** — the guarantees above are the **deterministic floor**, not a model.

---

## Appendix — file map for this demo

| Concern | File |
|---|---|
| Dry-run engine (classify → refuse → measure → assemble) | [`crates/clone-orchestrator/src/dry_run.rs`](../crates/clone-orchestrator/src/dry_run.rs) |
| Proposal + TTL | [`crates/clone-orchestrator/src/proposal.rs`](../crates/clone-orchestrator/src/proposal.rs) |
| Drift guard (`guard_decision`) | [`crates/clone-orchestrator/src/lib.rs`](../crates/clone-orchestrator/src/lib.rs) |
| Clone providers (`NoneProvider`, `LocalCloneProvider`) | [`crates/clone-orchestrator/src/provider.rs`](../crates/clone-orchestrator/src/provider.rs), [`provider/local.rs`](../crates/clone-orchestrator/src/provider/local.rs) |
| Blast-radius record (§10.1) | [`crates/core/src/blast_radius.rs`](../crates/core/src/blast_radius.rs) |
| Typed inverse + certified action set | [`crates/core/src/inverse.rs`](../crates/core/src/inverse.rs) |
| Proxy gate (extended-only + read-only) | [`crates/proxy/src/enforce.rs`](../crates/proxy/src/enforce.rs) |
| Byte/row budget cutoff | [`crates/proxy/src/budget.rs`](../crates/proxy/src/budget.rs) |
| FE/BE session loop (TLS, SCRAM, timeout, COPY metering) | [`crates/proxy/src/session.rs`](../crates/proxy/src/session.rs) |
| Dry-run IT (live backend) | [`crates/clone-orchestrator/tests/dry_run_it.rs`](../crates/clone-orchestrator/tests/dry_run_it.rs) |
| Clone-governance IT (zero-impact clone, orphan-reaper) | [`crates/clone-orchestrator/tests/clone_governance_it.rs`](../crates/clone-orchestrator/tests/clone_governance_it.rs) |
| Proxy IT (live backend) | [`crates/proxy/tests/proxy_it.rs`](../crates/proxy/tests/proxy_it.rs) |
| Local Postgres stack | [`deploy/local-stack.sh`](../deploy/local-stack.sh), [`deploy/smoke.sh`](../deploy/smoke.sh) |
| Spec amendments (docker→local Postgres, S1 proxy) | [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md) |
