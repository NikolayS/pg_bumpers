# CLAUDE.md — engineering principles for pg_bumpers

Concise operating rules for everyone (humans and agents) building this repo.
The authoritative **product** spec is [`docs/spec/SPEC.md`](docs/spec/SPEC.md)
(v0.8, build-frozen); the **why** is in [`docs/spec/decisions.md`](docs/spec/decisions.md).
The **process** spec lives in GitHub issue #1.

---

## 1. Red/green TDD — the failing test comes first, always

- Write the **failing test first**, watch it fail (RED), then make it pass (GREEN).
  Capture both states in the PR (paste the RED output and the GREEN output).
- Every crate and every behavior change ships with at least one real test.
- No production code without a test that motivated it.

## 2. Engineering posture: deterministic floor + fail-closed

- The **deterministic floor** is the safety guarantee — native-role WALL, cost/byte
  budgets, timeouts, bounded-&-reversible writes (SPEC §3). No model is in that path.
- **Fail closed:** absence of signal means least privilege; on any doubt, deny/abort.
  The guard is the **PK-set checksum**, not row count (catches identity drift).
- The LLM risk-gate is **tighten-only** — it can block/hold/escalate but can **never
  loosen** below the floor. In the MVP the `RiskEngine` is a stub returning `Allow`
  and intent tiers T0–T2 are captured/logged only (SPEC §15.1).

## 3. Roles

- **Manager** (engineering manager): coordinates only — never writes code, tests, or
  reviews personally. Creates issues, dispatches agents, drives the PR lifecycle.
- **Implementer:** picks up one issue in its **own git worktree**, builds it red/green,
  verifies all CI commands locally, opens a **draft PR**, posts evidence. **No self-merge.**
- **Reviewer:** a **different** agent (never the author) reviews every PR using the
  REV methodology and posts a verdict. Reviews are mandatory.

## 4. PR lifecycle — enforce in order, loop until satisfied

1. **CI green** — all jobs pass on the PR (paste the run link).
2. **REV review** — apply the review checklists from
   <https://gitlab.com/postgres-ai/rev/> to the GitHub diff. **Ignore all SOC2 items.**
3. **Real testing with evidence on the PR** — command outputs, integration runs,
   numbers. Docker/integration tests are env-gated but **actually run** with evidence.
4. **Verdict by a non-author reviewer** — a formal GitHub **APPROVE**, or (if the bot
   identity authored the PR and APPROVE is blocked) a COMMENT review starting
   **"REVIEWER VERDICT: APPROVE"** / **"REQUEST CHANGES"**.
5. On approve + green + evidence → **squash-merge + delete the branch**.
   Otherwise → author fixes → **LOOP**.

> **No self-merge. Never claim green if it isn't. Never fabricate evidence.**
> If a step is skipped, say so.

## 5. License hygiene — Apache-2.0 only, GPL/AGPL banned

- The project ships under **Apache-2.0** (`LICENSE`). Dependencies must be
  **Apache-2.0 / MIT / BSD / ISC** only (SPEC §4).
- Rust: **`cargo deny check`** gates licenses, bans, advisories (RUSTSEC), and
  sources. `deny.toml` is the **AGPL guard** — GPL/AGPL/LGPL deps make the check FAIL.
- TS (`mcp/server`): the `license-check` script walks the full pnpm tree and fails
  on any non-permissive license.

## 6. pgDog clean-room rule (AGPL — inspiration only)

[pgDog](https://github.com/pgdogdev/pgdog) is **AGPL**. You may **study its approach
for inspiration**, but you must **NEVER copy its code** — not a line, not a snippet.
Everything here is a **clean-room** implementation. When in doubt, don't look; design
from the SPEC.

## 7. Local CI commands — run ALL of these green before pushing

```sh
# Rust workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check                     # licenses + bans + advisories + sources

# MCP server (TypeScript)
cd mcp/server
pnpm install --frozen-lockfile
pnpm run build                        # tsc --noEmit
pnpm test                             # vitest
pnpm run license-check                # Apache/MIT/BSD/ISC only; bans GPL/AGPL
```

CI mirrors these in `.github/workflows/ci.yml` (triggers: push + pull_request).
Toolchain is pinned by `rust-toolchain.toml` (Rust **1.90.0**, edition 2021).

## 8. Where things live

- **Product spec:** `docs/spec/SPEC.md` (v0.8) — build exactly to it; do not edit it
  in feature PRs.
- **Decisions / rationale:** `docs/spec/decisions.md`.
- **Intentional deviations:** record in `docs/spec/SPEC.amendments.md` with rationale.
- **Crates:** `crates/{proxy,warden,core,policy,clone-orchestrator,pgwire,audit,cli}`.
- **MCP server (TS):** `mcp/server`. **Deploy/dev-stack:** `deploy/`. **Protocols:** `proto/`.
