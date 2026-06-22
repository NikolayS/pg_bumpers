# pg_bumpers

[![CI](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml/badge.svg)](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-3ddc97)
![spec](https://img.shields.io/badge/SPEC-v0.8%20·%20build--frozen-5b8cff)
![status](https://img.shields.io/badge/build-S0·S1·S2%20merged%20·%20S3%20in%20progress-ffb454)
![substrate](https://img.shields.io/badge/substrate-local%20Postgres%2018-336791)

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
> Anthropic Postgres MCP read-only mode was **bypassed by statement-stacking**
> (`COMMIT; DROP SCHEMA …`). Datadog's lesson: **app-layer protection isn't
> enough — you need native Postgres RBAC.**

Everyone else decides *whether* an action runs (allow/deny, masking, JIT).
**Nobody predicts _what a write will do_** before it hits prod.

## What it is

A self-hostable control plane between an AI agent and production Postgres. Reads
are cost-gated, bounded & audited. Writes are **rehearsed first** (on an instant
clone of prod if available, else measured in a rolled-back transaction), blast
radius **measured**, then applied reversibly under guards.

## The honest guarantee — split by damage class

We do **not** claim "impossible to break." We claim two precise, testable things:

- **Writes (reversible damage):** data-loss is **prevented or undoable** — every
  applied write is **bounded + reversible by construction**. The deterministic
  floor (PK-set checksum guard + typed-inverse + restore-point fence) aims for
  **zero catastrophic data-loss false-negatives by construction**, not by a model
  getting it right.
- **Reads (irreversible damage):** disclosure can't be un-happened, so we promise
  **bounded disclosure** — at most a per-role byte/row budget, then a hard
  **cutoff/kill** — **plus best-effort detection** of exfiltration. This is
  **tamper-evident, bounded, and detected — never "zero," "impossible," or
  "tamper-proof."**

## How it decides: a deterministic floor + an LLM risk-gate

- **Floor (deterministic, non-bypassable):** native-role WALL + cost/byte budgets
  + `statement_timeout` + bounded-&-reversible writes. **This is the guarantee —
  no model is in this path.**
- **LLM risk-gate (tighten-only):** scores how dangerous an action looks and can
  **block / hold / escalate** — but can **never loosen** below the floor. Its
  worst mistake is a false-positive (a blocked legit action), **never a breach**.

> **MVP posture:** the `RiskEngine` is currently a **stub returning `Allow`**
> (`crates/policy`), and intent tiers **T0–T2 are captured/logged only**
> (SPEC §15.1). The safety today comes entirely from the **deterministic floor**.
> LLM posture is **staged**: floor-only → advisory → gating.

## Status

The product spec is **build-frozen at v0.8**. The build runs in sprints; this is
the live, fully-tested implementation.

| Sprint | Scope | State |
|--------|-------|-------|
| **S0** | Skeleton · WALL (hardened role + network boundary) · core seams · contracts · fidelity gate | **merged · green on PG18** |
| **S1** | pgwire termination · read enforcement (read-only / byte-row cutoff / `statement_timeout`) · audit · proxy | **merged · green on PG18** |
| **S2** | Clone-orchestrator dry-run (blast-radius preview) · clone governance | **merged · green on PG18** |
| **S3** | Guarded apply + typed-inverse (PITR fence · apply-time PK-set re-check · `RETURNING` written-set) | **in progress** ([#35](https://github.com/NikolayS/pg_bumpers/issues/35)) |
| **S4** | Warden · MCP server · `policy.yaml` wiring · external audit anchor · deferred read gates · CLI approval | **upcoming** |
| **S5** | Focused deterministic benchmark breadth + the marquee "delete a DB through the official MCP" end-to-end repro (per damage class, live stack) + `KNOWN_BYPASSES.md` | **in progress** ([#68](https://github.com/NikolayS/pg_bumpers/issues/68)) — run `deploy/marquee.sh`; evidence in `deploy/marquee.transcript.txt` |
| — | **LLM gating engine** (the risk model that tightens) | **fast-follow** |

**Substrate:** live integration tests run against **local Postgres 18** (Homebrew
`postgresql@18`: `initdb` / `pg_basebackup` / `pg_ctl`), not Docker — a
founder-approved pivot because `docker pull` is non-functional in the build
environment. `deploy/docker-compose.yml` is retained as the **shipped artifact**
(image bumped to `postgres:18`) and statically validated. Full rationale:
[`docs/spec/SPEC.amendments.md`](docs/spec/SPEC.amendments.md).

## Architecture · four layers + a boundary

| # | Layer | What it does | Where it lives |
|---|-------|--------------|----------------|
| **0** | **Network boundary** *(mandatory)* | Agent reaches Postgres **only via the proxy** — `pg_hba` permits the agent role **only from the proxy host**; every other origin is rejected. | `deploy/hba/`, `deploy/init/` |
| **1** | **The WALL — native Postgres roles** *(unbypassable)* | Hardened least-priv role `pgb_agent` (NOSUPERUSER · NOINHERIT · member-of-nothing · no write grant anywhere · SELECT-whitelist only); a hostile *raw* client physically can't write or read denied data. | `deploy/sql/10_hardened_role.sql`, `deploy/test/wall_matrix.sh` |
| **2** | **Enforcement — Rust proxy + warden** | Extended-protocol-only, read-only gate, byte/row **mid-stream cutoff**, `statement_timeout`, hash-chained audit. Warden is the out-of-band watchdog (S4). | `crates/proxy`, `crates/pgwire`, `crates/audit`, `crates/warden` |
| **3** | **Intent / UX — MCP server** *(agent-facing)* | What the agent talks to; executes *through* the proxy; recoverable blocks. **Skeleton today; tools land in S4.** | `mcp/server` |
| **4** | **Write-safety — guarded apply (+ optional clone rehearsal)** *(the moat)* | Bounded + reversible writes; with a clone (DBLab), a zero-impact pre-flight preview. **Dry-run shipped (S2); guarded apply in progress (S3).** | `crates/clone-orchestrator`, `crates/core` |

A full architecture write-up is in [`docs/architecture.md`](docs/architecture.md).
The authoritative references for *intent* remain
[`docs/spec/SPEC.md`](docs/spec/SPEC.md) (§3–§4) and
[`deploy/README.md`](deploy/README.md).

## How a write works

1. **propose** — SQL + expected rows → a stable `Proposal` (id + TTL). Nothing
   touches prod (`crates/clone-orchestrator/src/proposal.rs`).
2. **dry-run** — rehearse on a clone if present, **else measure in a
   `BEGIN … ROLLBACK` txn**; refuse volatile predicates and PK-less targets
   *before* executing; fold rows / cascades / triggers / locks / WAL / the
   affected-PK set into a `BlastRadius` record, then roll back so **nothing is
   persisted** (`crates/clone-orchestrator/src/dry_run.rs`). **Shipped (S2).**
3. **apply** — restore-point fence → PK-set/row-count guard (abort on drift) →
   commit → typed-inverse captured. The drift-decision seam (`guard_decision`)
   exists today; the full **guarded-apply engine is S3 (in progress)**.

> **Killer demo (the marquee):** `UPDATE accounts SET balance=0` (no `WHERE`) is
> **rehearsed**, the affected-PK set is **measured**, and the operator sees the
> blast radius *before* it touches prod — the test fixture is 8 rows, and at
> production scale the same preview reports the full row count. And
> `COMMIT; DROP SCHEMA public CASCADE` sent as a simple-query is **blocked** by
> the extended-protocol-only proxy gate (the statement-stacking bypass that
> defeated the off-the-shelf MCP) — proven against live PG18 in
> `crates/proxy/tests/proxy_it.rs`. Full walkthrough: [`docs/demo.md`](docs/demo.md).

## Quickstart

Full guide: [`docs/quickstart.md`](docs/quickstart.md). The working path
(macOS / Homebrew, local PG18 — no Docker required):

```sh
brew install postgresql@18                       # the substrate (PG18)
deploy/local-stack.sh up                          # primary 54321 · replica 54322 · meta 54323
PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh        # WALL: every deny proven against real PG18
PG_BUMPERS_IT=1 bash deploy/smoke.sh              # replication + _meta smoke
deploy/local-stack.sh down                        # clean teardown (verifies ports freed)
```

The full stack contract, ports, the `PG_BUMPERS_IT` integration-gate convention,
and the docker-compose shipped artifact are documented in
[`deploy/README.md`](deploy/README.md).

## Scope · MVP vs fast-follow

| ✅ MVP (~12–15 wks) | ◻︎ Fast-follow |
|---|---|
| Native-role WALL + proxy-only network path | LLM **gating** risk-engine (write + read) |
| Proxy: read-only, budgets, byte/row cutoff, `statement_timeout`, audit | The 100k-run FP/FN benchmark + calibration |
| Clone dry-run preview + guarded apply + typed-inverse | T4 origin-context + attestation |
| Warden + MCP + `policy.yaml` + tamper-evident audit | Approval UI, dual-control, connectors |
| Autonomy L0–L2 · **intent capture T0–T2 (logged)** | DDL, multi-stmt txns, multi-DB, cloud |
| **CLI approval** + signed proposal-bound grant | Specialized (fine-tuned) risk model |
| Focused deterministic benchmark + bypass repro | |

> In the MVP the `RiskEngine` is a **stub returning `Allow`** and intent tiers
> T0–T2 are **captured/logged only** (SPEC §15.1). The CLI and MCP server are
> **skeletons** wiring their core seams (single-use proposal-bound grant; block
> contract); the live operator-approval and MCP-tool flows land in **S4**.

## Repository layout

```
crates/
  proxy/              # S1: inline read-only enforcement (agent-only endpoint); binary `pgb-proxy`
  pgwire/             # PostgreSQL wire-protocol helpers (extended-protocol-only)
  audit/              # tamper-evident hash-chained audit (+ Postgres _meta sink)
  core/               # domain types + one-way-door seams (BlastRadius, PK-checksum, inverse, clock, barrier)
  policy/             # policy.yaml model + RiskEngine seam (MVP stub: Allow) + grant/intent/verdict
  clone-orchestrator/ # S2: propose/dry-run, blast-radius, PK-set guard seam; S3 guarded apply (in progress)
  warden/             # out-of-band watchdog + circuit breaker (S4 — skeleton)
  cli/                # operator approval flow (signed, single-use, proposal-bound grant — S4; seam today)
mcp/server/           # MCP server (TypeScript) — agent-facing layer (S4; skeleton + block contract)
spikes/fidelity/      # S0 throwaway fidelity-spike harness (gate; publish=false)
deploy/               # local-stack.sh (live substrate) + docker-compose (shipped artifact) + WALL SQL/hba
proto/                # protocol/IDL definitions (added as protocols solidify)
docs/spec/            # SPEC.md (source of truth) + decisions.md + SPEC.amendments.md
```

## Build & test

Toolchain is pinned: **Rust 1.90.0** (edition 2021, `rust-toolchain.toml`),
**Node 22 + pnpm 11.8**. CI (`.github/workflows/ci.yml`) mirrors these on every
push + PR.

```sh
# Rust workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check                     # licenses + bans + advisories (RUSTSEC) + sources

# MCP server (TypeScript)
cd mcp/server
pnpm install --frozen-lockfile
pnpm run build                        # tsc --noEmit
pnpm test                             # vitest
pnpm run license-check                # Apache/MIT/BSD/ISC only; bans GPL/AGPL
```

Integration tests are **env-gated**: they **skip** (exit 0) unless
`PG_BUMPERS_IT=1`, and run for real against the local PG18 stack when it is set.
See [`docs/development.md`](docs/development.md) for the full process.

## Docs & decisions

- **Docs index:** [`docs/README.md`](docs/README.md) — architecture · quickstart · development · components · demo
- **Spec (source of truth):** [`docs/spec/SPEC.md`](docs/spec/SPEC.md) (v0.8, build-frozen)
- **Intentional deviations:** [`docs/spec/SPEC.amendments.md`](docs/spec/SPEC.amendments.md) (incl. the docker→local-PG18 substrate pivot)
- **Decisions / rationale:** [`docs/spec/decisions.md`](docs/spec/decisions.md)
- **Engineering principles:** [`CLAUDE.md`](CLAUDE.md) (red/green TDD · fail-closed · clean-room)
- **Brief:** [`docs/spec/brief.md`](docs/spec/brief.md)
- **Dev/test stack:** [`deploy/README.md`](deploy/README.md)
- **Sprint epics:** [S0 #2](https://github.com/NikolayS/pg_bumpers/issues/2) · [S1 #19](https://github.com/NikolayS/pg_bumpers/issues/19) · [S2 #28](https://github.com/NikolayS/pg_bumpers/issues/28) · [S3 #35](https://github.com/NikolayS/pg_bumpers/issues/35)

## What we deliberately do **not** claim

- Not "physically impossible to break" / not "tamper-proof" — the audit chain is
  **tamper-evident**, and read disclosure is **bounded + detected**, not prevented.
- Reads can't be un-disclosed — exfiltration is bounded ≤ a per-role budget and
  best-effort detected, **never zero**.
- Full-auto write is a **narrow, certified, reversible** action set, not open-ended.
- The LLM **reduces friction & catches more**, but is **never the safety guarantee
  — the deterministic floor is.**

## License

[Apache-2.0](LICENSE). Dependencies are Apache/MIT/BSD/ISC only — GPL/AGPL are
banned and enforced by `cargo deny` (Rust) and the `license-check` script (TS).
This is a **clean-room** implementation; AGPL projects (e.g. pgDog) are studied
for inspiration only, never copied (`CLAUDE.md` §6).
