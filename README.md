# pg_bumpers

[![CI](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml/badge.svg)](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-3ddc97)
![spec](https://img.shields.io/badge/SPEC-v0.8%20·%20build--frozen-5b8cff)
![status](https://img.shields.io/badge/status-MVP%20build%20in%20progress-ffb454)

> **Working title** (brand TBD; nine-lives / *Felis* leads).

**Let AI agents read & write _production Postgres_ — safely.** Run them with
`--dangerously-skip-permissions` and they can't cause disaster. **Your database
has nine lives.**

---

## The problem · why now

AI agents now touch production databases — coding agents, text-to-SQL, internal
copilots — often in YOLO / `--dangerously-skip-permissions` modes. Nobody has a
safe way to let them.

> The Replit agent **deleted SaaStr's production database**. The official
> Anthropic Postgres MCP read-only mode was bypassed by statement-stacking
> (`COMMIT; DROP SCHEMA…`). Datadog's lesson: **app-layer protection isn't
> enough — you need native Postgres RBAC.**

Everyone else decides *whether* an action runs (allow/deny, masking, JIT).
**Nobody predicts _what a write will do_.**

## What it is

A self-hostable control plane between an AI agent and production Postgres. Reads
are cost-gated, bounded & audited. Writes are **rehearsed on an instant clone of
prod**, blast radius **measured**, then applied reversibly under guards.

**The honest guarantee, split by damage class:**

- **Writes (reversible):** data-loss is **prevented or undoable** — every applied
  write is bounded + reversible. *0 catastrophic false-negatives by construction.*
- **Reads (disclosure):** disclosure can't be un-happened, so we promise
  **bounded disclosure** (≤ a per-role budget, then cutoff/kill) **+ best-effort
  detection** of exfiltration — never "impossible."

## How it decides: a deterministic floor + an LLM risk-gate

- **Floor (deterministic, non-bypassable):** native-role wall + cost/byte budgets
  + timeouts + bounded-&-reversible writes. This *is* the guarantee — no model.
- **LLM risk-gate (tighten-only):** scores how dangerous an action looks and can
  **block / hold / escalate** — but can **never loosen** below the floor. Its
  worst mistake is a false-positive (blocked legit action), **never a breach**.

## Architecture · four layers + a boundary

| # | Layer | What it does |
|---|---|---|
| **0** | **Network boundary** *(mandatory)* | Agent reaches Postgres **only via the proxy** — no bypass, no audit holes. |
| **1** | **The Wall — native Postgres roles** *(unbypassable)* | Hardened least-priv role; a hostile raw client *physically* can't write or read denied data. |
| **2** | **Enforcement — Apache Rust proxy + warden** *(our IP)* | Read-only, budgets, cutoff, timeouts, audit; warden kills runaways + owns the breaker. |
| **3** | **Intent / UX — MCP server** *(agent-facing)* | What the agent talks to; executes *through* the proxy; recoverable blocks. |
| **4** | **Write-safety — guarded apply (+ optional clone rehearsal)** *(the moat)* | Bounded + reversible writes; with DBLab, a zero-impact pre-flight preview. |

## How a write works

1. **propose** — SQL + expected rows. Nothing touches prod.
2. **dry-run** — rehearse (on a clone if DBLab present; else measure in-txn);
   report rows, cascades, locks, the affected-PK set, reversibility.
3. **apply** — restore-point fence → PK-set/row-count guard (abort on drift) →
   commit → typed-inverse captured. `confirm_rows` forces the agent to own the
   blast radius.

> **Killer demo:** `UPDATE accounts SET balance=0` (no `WHERE`) → "4,823,901
> rows" → blocked before prod. Slipped write → **auto-reversed**, with a
> verifiable diff.

## Scope

| ✅ MVP (~12–15 wks) | ◻︎ Fast-follow |
|---|---|
| Native-role wall + proxy-only network path | LLM **gating** risk-engine (write+read) |
| Proxy: read-only, budgets, cutoff, timeouts, audit | The 100k-run FP/FN benchmark + calibration |
| Clone dry-run preview + guarded apply + typed-inverse | T4 origin-context + attestation |
| Warden + MCP + `policy.yaml` + tamper-evident audit | Approval UI, dual-control, connectors |
| Autonomy L0–L2 · **intent capture T0–T2 (logged)** | DDL, multi-stmt txns, multi-DB, cloud |
| **CLI approval** + signed proposal-bound grant | Specialized (fine-tuned) risk model |
| Focused deterministic benchmark + bypass repro | |

> In v1 the `RiskEngine` is a **stub returning Allow** and intent tiers T0–T2 are
> **captured/logged only** (SPEC §15.1). LLM posture is **staged**: floor-only →
> advisory → gating.

## Repository layout

```
crates/
  proxy/              # inline read-only enforcement (agent-only endpoint)
  warden/             # out-of-band watchdog + circuit breaker
  core/               # domain types + one-way-door seams
  policy/             # policy.yaml model + RiskEngine seam (MVP stub)
  clone-orchestrator/ # dry-run, blast-radius, PK-set guard, typed-inverse
  pgwire/             # PostgreSQL wire-protocol helpers (extended-only)
  audit/              # tamper-evident hash-chained audit
  cli/                # operator approval flow (signed, proposal-bound grants)
mcp/server/           # MCP server (TypeScript) — the agent-facing layer
deploy/               # dev stack / docker-compose (lands in #4)
proto/                # protocol/IDL definitions (added as protocols solidify)
docs/spec/            # SPEC.md (source of truth) + decisions.md
```

## Status

**MVP build in progress.** The product spec is **build-frozen** at v0.8; this
repo is the clean, fully tested build with a complete issue/PR/evidence trail.

- **Spec (source of truth):** [`docs/spec/SPEC.md`](docs/spec/SPEC.md) (v0.8)
- **Decisions / rationale:** [`docs/spec/decisions.md`](docs/spec/decisions.md)
- **Engineering principles:** [`CLAUDE.md`](CLAUDE.md)
- **Brief:** [`docs/spec/brief.md`](docs/spec/brief.md)
- **S0 epic:** [#2 — Skeleton + WALL + Fidelity Spike (the gate)](https://github.com/NikolayS/pg_bumpers/issues/2)

## Building

Toolchain is pinned (Rust **1.90.0**, edition 2021; Node 22 + pnpm 11.8).

```sh
# Rust workspace
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check

# MCP server
cd mcp/server && pnpm install --frozen-lockfile && pnpm test && pnpm run license-check
```

## License

[Apache-2.0](LICENSE). Dependencies are Apache/MIT/BSD/ISC only — GPL/AGPL are
banned and enforced by `cargo deny` (Rust) and the `license-check` script (TS).
This is a **clean-room** implementation; AGPL projects (e.g. pgDog) are studied
for inspiration only, never copied.
