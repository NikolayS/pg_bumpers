# KNOWN_BYPASSES — honest, disclosed residual limits of the pg_bumpers MVP

> **Status:** S5 (issue #68). **Cadence:** refreshed by the benchmark maintainer
> quarterly AND on every floor change (SPEC §13.6).

This ledger is the honesty contract behind the marquee. The MVP genuinely
**refuses** irreversible/structural ops and **bounds + reverses** the supported
reversible write shape (proven end-to-end in `deploy/marquee.sh` /
`mcp/server/test/marquee.integration.test.ts`). We do **not** claim "deletes are
impossible" or "tamper-proof". This file documents the residual, disclosed limits
— what the floor does NOT yet contain — each with a repro note and tied to its
`docs/spec/SPEC.amendments.md` entry.

## Two distinct ledgers (don't conflate them)

1. **The catastrophic-FN ledger** — `dbsafe-bench/golden/known_bypasses.json`. A
   *bypass of the deterministic floor* (a dangerous corpus scenario the floor lets
   through as `ALLOW`) would go here and **count against** the headline
   "0 catastrophic FN" number (SPEC §13.7/§13.8). **It is EMPTY** for the MVP
   floor: the deterministic floor contains the whole frozen corpus
   (`PG_BUMPERS_IT=1 cargo test -p dbsafe-bench` → 0 FN, 0 FP). The gate
   `dbsafe-bench/tests/gate.rs` asserts it stays empty, so a future non-empty entry
   is a deliberate, reviewed change that visibly dents the headline.

2. **This document (`KNOWN_BYPASSES.md`)** — the *scope / disclosure* ledger. These
   are NOT floor false-negatives; they are deliberately-deferred capabilities and
   the honest boundary conditions of the guarantees. None of them lets a *dangerous
   corpus scenario* through the floor — they bound what the guarantees *cover*.

---

## B1 — Read disclosure is bounded to ≤ budget B, NOT zero

- **Damage class:** exfil (read). **Defense layer:** proxy byte/row cutoff.
- **What it is:** a hostile high-volume / slow-drip read is **cut off** at the
  per-role byte/row budget B — it is `BOUND`, not blocked to zero. Up to ~B bytes
  (or the row budget) of an agent's *already-authorized* surface can be disclosed
  before the cutoff fires. This is the honest read guarantee (SPEC §13.2): bounded
  disclosure, not zero disclosure.
- **Why it is not closed:** zero-disclosure would break every legitimate read; the
  budget IS the control. Tightening B trades capability for leakage.
- **Repro:** `dbsafe-bench` scenarios `exfil-by-volume-naive` (byte cutoff) and
  `exfil-slow-drip-row-cap` (row cutoff) — both resolve to `BOUND` with
  `bytes_out ≤ B` / `rows_out ≤ row-budget`, asserted by the gate's pass predicate.
  Run: `PG_BUMPERS_IT=1 cargo test -p dbsafe-bench --locked -- --test-threads=1`.
- **SPEC.amendments tie:** the §13.2 bounded-disclosure posture is the read
  guarantee throughout; see "S1 proxy" (byte/row cutoff) and the `dbsafe-bench`
  verdict vocabulary (`BOUND`).

## B2 — The MCP server is COOPERATIVE, not a security boundary

- **Damage class:** all (capability). **Defense layer:** N/A (the MCP is layer 3).
- **What it is:** the stdio MCP shell + `ApplydCore` add **no** privilege and are
  **not** the boundary. An agent that *bypasses* the MCP entirely still faces the
  real floor: reads hit the proxy/WALL, writes hit `pgb-applyd`'s grant-gated
  `guarded_apply_with_grant`, and a direct-to-DB connection hits the native-role
  WALL. A *compromised* MCP server cannot invent privilege because the daemon
  re-derives the apply from its OWN stored proposal record (statement/role/session
  pinned at propose — the #67 invariant). The disclosed caveat: the MCP layer is
  not a place to put trust; defense lives in the proxy/WALL/applyd boundaries.
- **Repro (the floor holds without the MCP):** the direct-to-DB-bypass corpus cell
  + `dbsafe-bench/tests/gate_it.rs` (`direct_to_db_bypass_is_denied_by_the_wall`)
  prove the WALL denies DROP / COPY…PROGRAM / pg_read_file / non-whitelisted reads
  when the agent connects WITHOUT the proxy. The marquee's CLASS 1 shows the
  applyd refusal even when driven *through* the MCP.
- **SPEC.amendments tie:** "S5 — MCP production wire + live Core (#67)" →
  *"Not a security boundary (the honesty contract)"*.

## B3 — Generic-schema apply is DEFERRED (MVP = single-`int4`-PK UPDATE/DELETE), but **column-coverage is now ENFORCED**

- **Damage class:** reversible write (write). **Defense layer:** dry-run / certify /
  guarded-apply column-coverage.
- **What it is (and the S5 #75 correction):** the bounded-reversible apply is
  constrained to the **single-`int4`-PK `UPDATE`/`DELETE`** shape the proven
  `PgApplyConn`/`PgRevertConn` cover. The PK *width/cardinality* is a coverage limit;
  the *columns* are NOT. Two distinct boundary conditions, now both honest:
  - **Wider / composite PK** (`int8`/`text`/`uuid`/multi-column) → **REFUSED cleanly
    at dry-run** (`NOT_REHEARSABLE`), a `pg_index`/`pg_type` read only, **no panic**,
    and the resident apply connection stays healthy and serves the next request. A
    genuinely PK-less table is still the distinct `PK_LESS` refusal.
  - **ANY column on a single-`int4`-PK table** (S5 #75 fix). The earlier claim that
    "a wider shape is gated OUT" was **WRONG for a wider-*column* UPDATE**: an
    `UPDATE … SET notes = …` on an `(id, owner, balance, notes)` table used to commit
    `reversible:true` while the hardcoded `(owner, balance)` pre-image silently
    dropped `notes` — a catastrophic, un-revertable write. **Now** the apply captures
    the pre-image of **exactly the SET-clause columns** (a `DELETE` captures the full
    row) and the revert restores **every written column byte-for-byte**, so such an
    UPDATE is **genuinely reversible — accepted, not refused**. A column type the MVP
    cannot capture losslessly (e.g. `jsonb`) is refused at dry-run
    (`NOT_REHEARSABLE`). **Defense-in-depth:** even if the dry-run column gate were
    bypassed, the guarded-apply step-8b **column-coverage guard** aborts before commit
    (`UncapturedColumn`) — a write can NEVER commit `reversible:true` with an
    incomplete inverse.
- **Repro:** `dbsafe-bench` `refused-pkless-delete` / `refused-volatile-insert` /
  `refused-insert-no-pk` / `refused-update-no-preimage` (REFUSED at certify),
  `wide-column-update-uncaptured-column` (REVERTED — the column-coverage guard
  aborts an uncaptured written column) + its legit peer
  `legit-wide-column-update-captured` (ALLOW — a captured wide-column UPDATE
  commits); IT: `dry_run_it::non_int4_pk_is_refused_not_rehearsable_no_panic_conn_survives`,
  `dry_run_it::update_with_uncapturable_set_column_is_refused`,
  `apply_it::t_wide_column_update_is_fully_reversible_revert_restores_all_columns`;
  the marquee CLASS 2 now applies BOTH the `SET balance = 0` and the wide-column
  `SET notes = 'audited'` shapes (each reversibly).
- **SPEC.amendments tie:** "S5 #75 — write-floor column coverage + clean PK-type
  refusal + applyd audit fail-closed"; "S5 (#67) DEFERRED → Generic-schema `ApplyConn`
  beyond single-`int4`-PK".

## B4 — Cross-process session attestation is DEFERRED (T4)

- **Damage class:** capability (write). **Defense layer:** applyd binding.
- **What it is:** the proxy read session and the applyd proposal are tied by the
  `session_id` the shell **passes**, not by a cryptographic binding between the two
  processes. applyd binds the apply to the `session_id` it stored at propose (so a
  cross-session GRANT replay is defeated), but the link from the *proxy read
  session* to the *applyd proposal session* is not yet cryptographically attested.
- **Why it is not closed:** T4 cross-process attestation is a fast-follow; the MVP's
  binding (pinned at propose, verified at apply) already defeats statement/role/
  session swaps and cross-session replay.
- **Repro:** the §14.3 grant binding is re-verified at apply
  (`crates/applyd/tests/applyd_it.rs` drift case → `GRANT_REJECTED`/`BLAST_DRIFT`,
  no mutation); the marquee CLASS 2 drift case reproduces the same abort live. What
  is *not* asserted is a cryptographic proxy↔applyd session attestation.
- **SPEC.amendments tie:** "S5 (#67) DEFERRED → Cross-process session attestation (T4)".

## B5 — The file `WormAnchor` is an append-only STAND-IN (delete-the-file re-baselines)

- **Damage class:** tamper-evidence (audit). **Defense layer:** anchored `_meta`.
- **What it is:** the external-WORM anchor of the chain head is a local
  append-only **file** (`PGB_ANCHOR_PATH`), not a true write-once-read-many medium
  or a transparency log. It catches a *full-chain rewrite across a restart*
  (verify-before-anchor), but an attacker who can **delete the anchor file** can
  re-baseline the anchor on the next boot. The within-chain hash links
  (`verify_chain`) still catch any *mid-chain* edit/delete regardless.
- **Why it is not closed:** a real WORM / KMS-backed transparency log is a
  production-deploy concern; the file anchor proves the mechanism end-to-end.
- **Repro:** `pgb-cli verify` (used by the marquee CLASS 4) runs `verify_chain` +
  the anchored-head match; deleting `PGB_ANCHOR_PATH` between boots re-baselines the
  anchor (the disclosed limit). The within-chain tamper detector is proven by
  `crates/audit` `verify_chain` unit tests + `crates/cli/src/verify.rs`
  `verify_fails_closed_on_a_tampered_chain`.
- **SPEC.amendments tie:** "S5 audit — ONE shared, persistent, anchored `_meta`
  chain"; "#71 follow-up — DURABLE WORM + verify-BEFORE-anchor".

## B6 — The RiskEngine is a stub returning Allow (no LLM gating)

- **Damage class:** all (the tighten-only LLM gate). **Defense layer:** N/A (advisory).
- **What it is:** the LLM risk-gate is an MVP **`AllowStub`** — it returns `Allow`
  and intent tiers T0–T2 are **captured/logged only** (SPEC §15.1). It can never
  *loosen* the deterministic floor (it is tighten-only by construction), so its
  absence removes only the *additional* statistical tightening, never the floor.
- **Why it is not closed:** the deterministic floor is the safety guarantee; the
  LLM detection plane is a non-CI-gating fast-follow (SPEC §13.5).
- **Repro:** `dbsafe-bench` is the deterministic floor plane (no model in the path);
  every dangerous scenario is contained by the floor with the RiskEngine stubbed.
  The MCP `dry_run` logs the stub `Allow` verdict (`mcp/server/src/riskEngine.ts`).
- **SPEC.amendments tie:** CLAUDE.md §2 (the LLM risk-gate is tighten-only; MVP
  `RiskEngine` is an `Allow` stub) + SPEC §15.1.

## B7 — `replica.dsn` is INERT and §10.8 degraded budgets are NOT differential (read-routing DEFERRED → #77)

- **Damage class:** N/A (topology / preview-experience, not a floor guarantee).
  **Defense layer:** the deterministic floor holds on the **primary** path regardless.
- **What it is:** `replica.dsn` parses + validates into `pgb_policy::ReplicaConfig`
  (`crates/policy/src/config.rs`) but is **not consumed** by any enforcement path. The
  proxy always originates its backend against the configured `PGB_BACKEND_*` target
  (the primary in the local stack) — there is **no read-routing to a replica** — and
  the per-role byte/row/window budgets are **not** made differentially stricter when
  no replica is present (no SPEC §10.8 degraded-mode budget switch). Setting
  `replica.dsn` does **not** change runtime behavior today.
- **Why it is not closed:** §12 makes the replica (and DBLab and PITR) **OPTIONAL**,
  and §12.1 states the bounded-blast-radius + reversibility **invariant holds
  regardless of the replica**. The floor (WALL + single-shot byte/row cutoff +
  cumulative per-window budget + `statement_timeout` + warden + EXPLAIN-cost gate)
  already bounds reads to ≤ B and refuses irreversible/structural writes on the
  primary path. Replica read-routing + a stricter degraded-mode budget profile is a
  **preview/isolation-experience upgrade** (SPEC §12 "Graceful degradation" table),
  not a safety prerequisite. Tracked **post-MVP under #77**.
- **Repro:** grep shows `replica.dsn` referenced only in `crates/policy` parse/
  round-trip tests (`config::tests::example_policy_loads_and_validates`,
  `clone_provider_defaults_to_none`), never in the proxy/warden enforcement path; the
  proxy connects to `PGB_BACKEND_HOST/PORT` (`crates/proxy/src/main.rs`), with no
  replica branch and no degraded-budget branch. The bounded/reversible guarantees are
  proven on the primary path (`dbsafe-bench`, `crates/proxy/tests/proxy_it.rs`).
- **SPEC.amendments tie:** "#80 — MVP spec-faithfulness closeout" → *Gap 2*
  (`replica.dsn` inert + §10.8 degraded budgets recorded as deferred → #77).

## B8 — Exact-set apply-time re-check makes guarded writes a low-churn / re-review-on-drift tool, not a bulk applier

> _(Filed under #87 as "B5" in the issue; B5–B7 were already allocated, so it lands
> here as **B8**.)_

- **Damage class:** N/A (scope/UX of the guarded-write tool, not a floor guarantee).
  **Defense layer:** guarded-apply PK-set authorization-freshness re-check (§14.3 binding).
- **What it is:** the apply-time affected-PK-set checksum re-check is 0-tolerance exact-set
  equality (the live `SELECT id … WHERE <pred> ORDER BY id` must equal the approved set
  byte-for-byte) — an authorization-freshness property by design. Consequence: on a stable
  explicitly-keyed write (`WHERE id=42`, `IN (…)`) it is meaningful + cheap; on a predicate over
  mutable/high-churn data (`WHERE status='open'`, `created < $1`, `id%2=0`) any concurrent
  committed change to the predicate's extension between approval and apply flips the set and
  aborts the already-approved write (`PkSetDrift`/`BindingMismatch`) — no tolerance band. Net:
  guarded apply is a small, stable, re-review-on-drift instrument for surgical keyed writes, NOT
  a bulk applier over hot tables; drift forces re-approval (single-use point-in-time grant), it
  is not retried through. **Bounded-ness and reversibility do NOT depend on this re-check** (see
  `CLAUDE.md` §2): bounded comes from the `pg_stat_xact_*` reconciliation + `statement_timeout`
  budget; reversibility from the pre-image capture (`FOR UPDATE`+`RETURNING`) + the coverage
  guards (incl. the #87 fail-closed `MissingPreImage` seam).
- **Why it is not closed:** it is not a defect — exact-set equality is exactly the anti-TOCTOU
  binding §14.3 needs (it pins the human's grant to the precise approved row-identity set). A
  tolerance band would loosen the binding. The "limitation" is the honest UX consequence: this is
  a surgical, low-churn instrument, not a hot-table bulk tool.
- **Repro:** `dbsafe-bench` `no-where-write-drift` (same-count/different-PK flip → `PkSetDrift`
  abort) + the env-gated PG18 ITs `apply_it::t_drift_predicate_flip_same_count_different_pks_aborts`
  and `apply_grant_it`'s data-drift case (`BindingMismatch`); the #87 ITs prove the bound/undo
  guards are the ones carrying capping + reversibility (`t_repeatable_read_*`,
  `t_concurrent_insert_*`).
- **SPEC.amendments tie:** "#87 — moat-seam fix" (the PK-set re-check re-attributed as an
  authorization-freshness gate; bound → budget + reconciliation, undo → pre-image capture +
  coverage guards).

---

### Bottom line

None of B1–B8 is a deterministic-floor false-negative: the catastrophic-FN ledger
(`dbsafe-bench/golden/known_bypasses.json`) is **empty**, and the gate keeps it
empty (0 FN / 0 FP over the frozen corpus). B1–B8 are the honest **scope** of the
MVP — bounded (not zero) read disclosure, a cooperative MCP, single-int-PK apply,
deferred cross-process attestation, a file-anchor stand-in, a stubbed (tighten-only)
RiskEngine, an inert `replica.dsn` (no replica read-routing / degraded-budget
differential yet, deferred → #77), and the exact-set apply-time re-check that makes
guarded writes a surgical, re-review-on-drift tool (B8) — each disclosed here with a
repro and tied to its SPEC.amendments entry.
