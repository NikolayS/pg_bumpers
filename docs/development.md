# Development guide

How we build pg_bumpers: the TDD discipline, the CI gates, the integration-test
convention, license hygiene, the clean-room rule, and the issue-to-merge
lifecycle. This is the engineering process; the **product** spec is
[`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8, build-frozen) and the operating rules are
in [`CLAUDE.md`](../CLAUDE.md). When this guide and `CLAUDE.md` disagree, `CLAUDE.md`
wins; when either disagrees with `SPEC.md` on product behavior, the SPEC wins.

> **Substrate note.** Live DB tests run against **local Postgres 18** (Homebrew
> `postgresql@18`: `initdb` / `pg_basebackup` / `pg_ctl`), not Docker. This is the
> founder-approved docker→local-PG18 pivot; `deploy/docker-compose.yml` remains the
> shipped artifact for users. Full rationale: [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md),
> "S0 integration substrate".

---

## Build status (what's merged vs. upcoming)

So you document and test against what actually exists:

| Sprint | Scope | Status |
|---|---|---|
| **S0** | skeleton · the Wall (hardened role) · `core` · contracts/seams · CI gate | **merged, green on PG18** |
| **S1** | pgwire termination · audit hash-chain · enforcing proxy | **merged, green on PG18** |
| **S2** | clone dry-run (blast radius) · clone governance | **merged, green on PG18** |
| **S3** | guarded apply · typed-inverse capture | **merged, green on PG18** |
| **S4** | warden loop · MCP tools · policy wiring · audit anchoring · read-gates · CLI approval | **merged, green on PG18** |
| **S5** | `pgb-applyd` write daemon · runnable MCP stdio shell · `deploy/up.sh` end-to-end · marquee MCP-bypass repro | **merged, green on PG18** |
| — | LLM gating risk-engine (write + read) · Rust `pgb-mcp` port ([#83](https://github.com/NikolayS/pg_bumpers/issues/83)) | fast-follow |

What this means in the tree today:

- `crates/{core,pgwire,audit,policy,proxy,clone-orchestrator}` carry merged,
  tested behavior. `crates/warden/src/main.rs` and `crates/cli/src/main.rs` are
  **explicitly-labelled stubs** (the targeting predicate / single-use-grant seams
  plus a test each); their live loops land in S4.
- The **`RiskEngine` is a stub** (`crates/policy/src/risk.rs::AllowStub`) that
  **always returns `Allow`**. The deterministic floor — not this engine — is the
  v1 safety guarantee. Don't write code, tests, or docs that assume the engine
  decides anything yet.
- The guarded-apply **drift seam** exists on `main`
  (`clone_orchestrator::guard_decision` in `crates/clone-orchestrator/src/lib.rs`,
  plus `pgb_core::pk_checksum` and `pgb_core::inverse`); the full S3 apply path is
  being built on a branch, not yet on `main`.
- `proto/` is an intentional **placeholder** — nothing is generated from it in S0
  (see `proto/README.md`).

Mark anything not-yet-built clearly in code and prose. Never invent a command, a
flag, or an API that the tree doesn't have.

---

## The honesty contract (SPEC §1) — keep it exact in code and copy

This is load-bearing; getting the wording wrong is a correctness bug, not a style
nit.

- **Writes are bounded + reversible.** Every applied write is rehearsed, guarded
  on the affected-**PK-set checksum** (not row count — that catches row-*identity*
  drift), fenced by a restore point, and reversible via a captured typed inverse.
  The target is **0 catastrophic data-loss false-negatives _by construction_**.
- **Reads are bounded disclosure + best-effort detection.** Disclosure can't be
  un-happened, so the promise is a **per-role byte/row budget, then cutoff/kill**,
  plus best-effort exfiltration detection — **not** zero, **never** "impossible".
- The audit chain is **tamper-EVIDENT**, never "tamper-proof". Say "evident".
- The typed inverse restores **table row state only**. It does **not** restore
  sequence advances, trigger side-effects, or already-delivered `NOTIFY`s — these
  are enumerated in `pgb_core::inverse::NotRestored` and must be named explicitly,
  not glossed over (SPEC §10.3).

When in doubt, under-claim. "Best-effort", "bounded", and "tamper-evident" are the
right words.

---

## 1. Red/green TDD — the failing test comes first, always

The non-negotiable loop (`CLAUDE.md` §1):

1. **RED** — write the failing test first and watch it fail. Capture the output.
2. **GREEN** — write the minimum code to pass. Capture the output.
3. Paste **both** RED and GREEN states into the PR.

Rules:

- Every crate and every behavior change ships with at least one real test. No
  production code without a test that motivated it.
- Tests encode the SPEC contract, not the implementation's current shape — e.g.
  `crates/policy/src/risk.rs` tests that a loosening engine is **clamped to the
  floor** (tighten-only), and `crates/core/src/inverse.rs` property-tests that
  every op outside the certified allow-list is **refused** (fail-closed).
- Fail-closed is itself a test target: absence of signal must mean least
  privilege. Assert the deny/abort path, not just the happy path.

---

## 2. CI gates

Two jobs run on **every push and every pull_request**
(`.github/workflows/ci.yml`). Both must be green before merge. Superseded runs on
the same ref are auto-cancelled (concurrency group), so only push when you mean it.

### Job `rust` — fmt · clippy · build · test · deny

Toolchain is pinned to **Rust 1.90.0** (`rust-toolchain.toml`, edition 2024) via
`dtolnay/rust-toolchain@1.90.0` with `rustfmt` + `clippy`. The steps, in order:

| Step | Command | Gate |
|---|---|---|
| rustfmt | `cargo fmt --all --check` | formatting |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **zero warnings** |
| build | `cargo build --workspace --locked` | `Cargo.lock` honored, no drift |
| test | `cargo test --workspace --locked` | unit/contract tests |
| deny | `EmbarkStudios/cargo-deny-action@v2` → `cargo deny check` | licenses · bans · advisories · sources |

`clippy -D warnings` means a warning fails the build — fix it, don't `#[allow]`
it away without a reason. `--locked` means the lockfile must already satisfy the
build; if you changed deps, commit the updated `Cargo.lock`.

### The MCP server is a Rust workspace member (no separate CI job)

The deployable MCP server is the native Rust **`pgb-mcp`** (crate `crates/mcp`,
binary `pgb-mcp`) — the one and only MCP server after
[EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83) (the old TS
`mcp/server` and its pnpm/Node CI job are removed). Because `crates/mcp` is a
workspace member, the `rust` job above already builds + tests it
(`cargo {build,test} --workspace`), and `cargo deny` license-checks its deps — so
there is **no** dedicated MCP CI job.

It is a **runnable stdio shell** with the nine §11 tools, a live read path through
`pgb-proxy`, and a write path through the `pgb-applyd` socket. The env-gated Rust
e2e tests `crates/mcp/tests/{write_path_e2e,read_path_e2e}.rs` drive the shipped
`PgBumpersMcp` handler end-to-end against a throwaway PG18 (`PG_BUMPERS_IT=1`); the
catalog test pins the fail-closed surface (exactly nine tools, no `approve`).

### Run all gates locally before pushing

Reproduce CI exactly (also in `CLAUDE.md` §7). Get these green **before** opening
or updating a PR:

```sh
# Rust workspace (single-language; the MCP server `pgb-mcp` is a workspace member
# in crates/mcp, so these build, test, and license-check it too).
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check
```

> **Pages.** A separate workflow (`.github/workflows/pages.yml`) deploys the
> public brief to GitHub Pages on push to `main`, but **only** when
> `docs/spec/brief.html` or the workflow itself changes. It runs
> `scripts/build-site.sh` (copies `brief.html` → `site/index.html`, plus
> `SPEC.md` / `decisions.md`). It is not part of the per-PR merge gate.

---

## 3. The `PG_BUMPERS_IT` integration convention

Two test tiers, by design:

- **Fast tier (always-on).** Plain `cargo test` runs unit and contract tests
  (across the whole workspace, including `crates/mcp`) with **no live database**.
  This is what CI runs, so CI stays fast and DB-free. Integration test files still
  **build and link** under the fast job (the crate compiles); they just **skip**
  their assertions.
- **Integration tier (gated, real).** Tests that need a live Postgres 18 are
  gated behind the env var **`PG_BUMPERS_IT=1`**. When the gate is unset, they
  print a `[skip]` line and exit success; when it's set, they run for **real**
  against live PG18 and produce evidence.

The contract used everywhere (see `crates/proxy/tests/proxy_it.rs`,
`crates/clone-orchestrator/tests/common/mod.rs`,
`crates/clone-orchestrator/tests/clone_governance_it.rs`, and `deploy/smoke.sh`):

```rust
fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT").map(|v| v == "1").unwrap_or(false)
}
```

`deploy/smoke.sh` follows the same rule at the shell level: with `PG_BUMPERS_IT`
unset or `!= 1` it **skips (exit 0)**; with it set it asserts and exits non-zero
on any failure.

### Running the integration tier

Stand up the throwaway local stack, run the gated tests with `--nocapture` so the
evidence prints, then tear down:

```sh
deploy/local-stack.sh up      # initdb + start primary(54321) + meta(54323),
                              # base-backup + stream replica(54322)

# proxy end-to-end against live PG18 (read-only gate, byte/row cutoff,
# statement_timeout, the marquee COMMIT; DROP SCHEMA block, audit chain):
PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test proxy_it -- --nocapture

# clone dry-run (blast radius / affected-PK set):
PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test dry_run_it -- --nocapture

# clone governance:
PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test clone_governance_it -- --nocapture

# S0 substrate smoke (replication round-trip, _meta reachable):
PG_BUMPERS_IT=1 deploy/smoke.sh

deploy/local-stack.sh down    # stop all clusters, remove ./.localstack/
```

The PG18 bin dir defaults to `/opt/homebrew/opt/postgresql@18/bin`; override with
`PGBIN` (shell scripts) or `PG_BUMPERS_PGBIN` (Rust ITs). The dry-run IT defaults
its admin DSN to a dedicated throwaway port (`54341`) and the audit/fidelity ITs
to `55432`/`55431` — override each with `PG_BUMPERS_PGURL` /
`PG_BUMPERS_AUDIT_PGURL` to point at the running local-stack primary (see
[`docs/quickstart.md`](quickstart.md) §4). The clone-governance tests stand up
their **own** primary cluster on disk (so the `local` provider can `pg_basebackup`
it); see `crates/clone-orchestrator/tests/common/cluster.rs`.

### Evidence is mandatory

Per `CLAUDE.md` §4, integration runs are env-gated but **actually run** — paste
real command output, integration runs, and numbers on the PR. **Never** claim
green if it isn't, and **never** fabricate evidence. If a step was skipped, say
so explicitly.

---

## 4. Test-port discipline — never touch 5432

Live tests run on **dedicated high ports** and **never** use the default
PostgreSQL port `5432`, so they cannot collide with a developer's real cluster:

| Cluster | Port | Source |
|---|---|---|
| local-stack primary | `54321` | `deploy/local-stack.sh` |
| local-stack replica | `54322` | `deploy/local-stack.sh` |
| local-stack meta (`_meta` audit DB) | `54323` | `deploy/local-stack.sh` |
| WALL matrix cluster | `54331` | `deploy/test/wall_matrix.sh` |
| dry-run IT default admin | `54341` | `tests/common/mod.rs` (override `PG_BUMPERS_PGURL`) |
| clone-governance primary | `54360 + offset` | `tests/common/cluster.rs` |
| clone-governance clone | `54370 + offset` | `tests/common/cluster.rs` |
| audit `_meta` IT default admin | `55432` | `tests/pg_meta_it.rs` (override `PG_BUMPERS_AUDIT_PGURL`) |
| fidelity spike default admin | `55431` | `spikes/fidelity/src/lib.rs` (override `PG_BUMPERS_PGURL`) |
| proxy IT agent endpoint | ephemeral (OS-assigned) | `tests/proxy_it.rs` |

Everything is **throwaway** and **loopback-only**: the local stack lives under a
git-ignored `./.localstack/` (`.gitignore`), the proxy IT binds an ephemeral
listener, and clusters are torn down cleanly (`Drop` for the Rust harnesses,
`down` for the script). The local-stack `down` can stop our postmasters even after
the data dir is deleted, via an out-of-tree PID ledger keyed by a digest of the
stack root. When adding a DB test: pick a high, dedicated port; never hard-code
`5432`; clean up after yourself.

---

## 5. License hygiene — Apache-2.0 only, GPL/AGPL banned

The project ships under **Apache-2.0** (`LICENSE`). Dependencies must be
**Apache-2.0 / MIT / BSD / ISC** only (SPEC §4). Copyleft (GPL / AGPL / LGPL) is
**banned** and makes the build fail, by design.

### Rust — `cargo deny` is the AGPL guard

`deny.toml` is a fail-closed **allow-list**: only the listed SPDX licenses pass;
anything else (e.g. `GPL-3.0`, `AGPL-3.0`, `LGPL-3.0`) makes `cargo deny check`
**FAIL**. The allow-list is intentionally minimal — Apache-2.0 (incl. the strictly
more-permissive `Apache-2.0 WITH LLVM-exception`), MIT, BSD-2/3-Clause, ISC, and
the permissive `Unicode-*` data licenses. `cargo deny check` also gates **bans**
(wildcard external deps denied; intra-workspace `path` deps exempt), **advisories**
(RUSTSEC; yanked = deny), and **sources** (crates.io only). Every allow-list entry
carries a comment explaining why — keep that hygiene if you add one, and prefer
**not** adding one.

### The MCP server's deps are covered by `cargo deny`

The MCP server is the Rust `pgb-mcp` (`crates/mcp`), a workspace member — so its
dependency tree is gated by the same `cargo deny check` above (there is no longer
a separate TS `license-check.mjs`; it was removed with the TS `mcp/server` in
EPIC #83).

If a new dependency trips the gate, the fix is **drop the dependency**, not widen
the allow-list. A copyleft dep is a no-go, full stop.

---

## 6. The pgDog clean-room rule (AGPL — inspiration only)

[pgDog](https://github.com/pgdogdev/pgdog) is **AGPL**. You may **study its
approach for inspiration**, but you must **NEVER copy its code — not a line, not a
snippet**. Everything in this repo is a **clean-room** implementation built from
`SPEC.md`. When in doubt, **don't look** — design from the spec. This protects the
Apache-2.0 license of the whole project; an AGPL contamination is unacceptable.

---

## 7. PR lifecycle — issue → worktree → draft PR → green → review → merge

The flow, enforced in order (`CLAUDE.md` §§3–4). It loops until satisfied.

1. **Issue.** Work is tracked as a GitHub issue. The **Manager** role creates and
   dispatches issues and drives the lifecycle, but never writes code, tests, or
   reviews personally.
2. **Branch / worktree.** An **Implementer** picks up **one** issue in its **own
   git worktree** (this repo uses per-agent worktrees under `.claude/worktrees/`),
   so parallel work never collides. Branch off `main`.
3. **Build red/green.** TDD per §1 above; verify all CI gates locally (§2).
4. **Draft PR.** Open a **draft** PR via the `gh` CLI and post evidence: the RED
   and GREEN test output, the local gate results, and (for DB-touching work) the
   `PG_BUMPERS_IT=1` integration run output.
5. **CI green.** All jobs pass on the PR; paste the run link. **Never claim green
   if it isn't.**
6. **Adversarial review by a non-author.** A **different** agent (never the PR
   author — **no self-merge**, **no self-review**) reviews every PR using the REV
   methodology from <https://gitlab.com/postgres-ai/rev/>, applied to the GitHub
   diff. **Ignore all SOC2 items.** The verdict is a formal GitHub **APPROVE**, or
   — if the bot identity authored the PR and APPROVE is blocked — a COMMENT review
   starting **"REVIEWER VERDICT: APPROVE"** / **"REQUEST CHANGES"**.
7. **Squash-merge + delete branch.** On approve **and** green **and** evidence →
   squash-merge and delete the branch. Otherwise → author fixes → **LOOP**.

> **No self-merge. Never claim green if it isn't. Never fabricate evidence.** If a
> step is skipped, say so.

---

## 8. Where things live

- **Crates:** `crates/{proxy,warden,core,policy,clone-orchestrator,pgwire,audit,cli,mcp,applyd}`.
- **MCP server (Rust):** `crates/mcp`, binary `pgb-mcp` (the one deployable MCP server).
- **Deploy / dev-stack:** `deploy/` (`local-stack.sh`, `smoke.sh`,
  `docker-compose.yml`, `hba/`, `init/`, `sql/`).
- **Protocols (placeholder):** `proto/`.
- **Spikes (throwaway, `publish = false`):** `spikes/fidelity` — kept in the
  workspace only so it compiles under the fast CI job; its DB tests are
  `PG_BUMPERS_IT`-gated.
- **Product spec:** `docs/spec/SPEC.md` (v0.8) — build exactly to it; **do not
  edit it in feature PRs**.
- **Decisions / rationale:** `docs/spec/decisions.md`.
- **Intentional deviations:** `docs/spec/SPEC.amendments.md` (record with
  rationale; the SPEC is not edited in feature PRs).
- **Operating rules:** `CLAUDE.md` (root).
- **Docs:** [`docs/README.md`](README.md) — index of architecture / quickstart /
  development / components / demo.
