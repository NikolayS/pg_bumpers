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

## B3 — Generic-schema apply is DEFERRED (MVP = single-int-PK UPDATE/DELETE)

- **Damage class:** reversible write (write). **Defense layer:** dry-run / certify.
- **What it is:** the bounded-reversible apply is constrained to the
  **single-integer-PK `UPDATE`/`DELETE`** shape on an `(id, …)` table the proven
  `PgApplyConn`/`PgRevertConn` cover. A wider shape is **not silently mis-applied**:
  it is gated OUT, fail-closed, by the dry-run's PK-less / volatile / irreversible /
  non-rehearsable **REFUSALs** (you get `PK_LESS` / `VOLATILE` / `NOT_REHEARSABLE`,
  never a broken reversible write). The "bypass" is purely a *coverage* limit:
  legitimate non-single-int-PK writes are refused rather than applied.
- **Repro:** `dbsafe-bench` `refused-pkless-delete`, `refused-volatile-insert`,
  `refused-insert-no-pk`, `refused-update-no-preimage` → all `REFUSED` at certify;
  the marquee CLASS 2 only applies the supported `UPDATE … WHERE id % 2 = 0` shape.
- **SPEC.amendments tie:** "S5 (#67) DEFERRED → Generic-schema `ApplyConn` beyond
  single-int-PK"; "S2 clone-orchestrator — no production generic-schema `ApplyConn`".

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

---

### Bottom line

None of B1–B6 is a deterministic-floor false-negative: the catastrophic-FN ledger
(`dbsafe-bench/golden/known_bypasses.json`) is **empty**, and the gate keeps it
empty (0 FN / 0 FP over the frozen corpus). B1–B6 are the honest **scope** of the
MVP — bounded (not zero) read disclosure, a cooperative MCP, single-int-PK apply,
deferred cross-process attestation, a file-anchor stand-in, and a stubbed
(tighten-only) RiskEngine — each disclosed here with a repro and tied to its
SPEC.amendments entry.
