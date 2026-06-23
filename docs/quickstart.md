# pg_bumpers — Quickstart

Get a local checkout building, bring up the dev substrate, and run the env-gated
integration suite against **real PostgreSQL 18**.

> **Source of truth:** [`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8). The dev-substrate
> deviation (docker → local PG 18) is logged in
> [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md) → *"S0 integration substrate"*.
> License: Apache-2.0.

## What works today (status)

This is an MVP under active construction. Honest status as of this writing:

- **Merged & green on PG 18:** S0 (skeleton, the native-role WALL, `core`/contracts,
  the fidelity gate), S1 (`pgwire`, `audit`, `proxy`), S2 (clone dry-run + governance).
- **In progress:** S3 (guarded apply + typed-inverse).
- **Upcoming / fast-follow:** S4 (warden, MCP wiring, policy wiring, audit-anchor,
  read-gates, CLI approval), S5 (benchmark + the marquee MCP-bypass repro), and the
  LLM gating engine. In the MVP the `RiskEngine` is a **stub returning `Allow`** —
  the deterministic floor (WALL + budgets + timeouts + bounded/reversible writes) is
  the guarantee, not any model.

### What the guarantee is — and is not

- **Writes:** bounded + reversible by construction — zero catastrophic data-loss false
  negatives. The guard is the **affected-PK-set checksum**, recomputed inside the apply
  txn, not a row count.
- **Reads:** **bounded disclosure** — a per-role byte/row budget, then a hard cutoff,
  plus best-effort detection. Not zero, never "impossible." The audit chain is
  **tamper-evident**, not tamper-proof.

---

## 1. Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | **1.90.0** | Pinned by [`rust-toolchain.toml`](../rust-toolchain.toml) (rustfmt + clippy). `rustup` auto-selects it. |
| PostgreSQL | **18** | Client + server binaries (`initdb`, `pg_ctl`, `pg_basebackup`, `psql`, `pg_isready`). |
| `cargo-deny` | latest | License/advisory gate: `cargo install cargo-deny`. |
| Node | Node 22 | Only used by `deploy/up.sh` to generate a throwaway Ed25519 approver keypair for the demo. Not needed to build/test (the MCP server `pgb-mcp` is pure Rust). |

### Install PostgreSQL 18 (macOS, Homebrew)

`postgresql@18` is **keg-only**, so its binaries are not symlinked onto `PATH`. They
live at `/opt/homebrew/opt/postgresql@18/bin` — the path every dev script defaults to
(override with the unified `PG_BUMPERS_PG18_BIN` — the one variable CI sets, honored by
every shell script *and* every Rust IT and taking precedence over the legacy `PGBIN=` /
`PG_BUMPERS_PGBIN=`).

```sh
brew install postgresql@18

# Verify the keg-only binaries are present (this is the path the scripts use):
/opt/homebrew/opt/postgresql@18/bin/pg_ctl --version     # -> pg_ctl (PostgreSQL) 18.x
```

> You do **not** need to start a system Postgres service or add it to `PATH`. The dev
> stack (`deploy/local-stack.sh`) calls these binaries by absolute path and runs
> throwaway clusters on dedicated high ports — it never touches a cluster on 5432.

---

## 2. Clone + build

```sh
git clone https://github.com/NikolayS/pg_bumpers.git
cd pg_bumpers

# The fast, DB-free build/test loop — exactly what CI runs (.github/workflows/ci.yml).
# Integration tests are env-gated OFF here, so this stays fast and needs no database.
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check
```

The MCP server (`pgb-mcp`, crate `crates/mcp`) is a workspace member, so the
commands above already build, test, and license-check it — there is no separate
Node/pnpm step (the old TS `mcp/server` was removed in EPIC #83).

---

## 3. The local dev stack

`deploy/local-stack.sh` is the **live dev/CI substrate** here: isolated, throwaway PG 18
clusters under a git-ignored `./.localstack/`, built from the keg-only Homebrew binaries
(no Docker). It models the same shape as the shipped compose: a streaming-replication
**primary**, a streaming **replica**, and a separate append-only **`_meta`** audit DB.

```sh
deploy/local-stack.sh up      # initdb + start primary + meta; pg_basebackup + stream replica
deploy/local-stack.sh status  # pg_isready snapshot for all three
deploy/local-stack.sh down    # stop all clusters, remove ./.localstack/ (verifies ports free)
```

`up` applies the idempotent hardened-role WALL SQL (`deploy/sql/10_hardened_role.sql`)
against the primary on every run.

### Ports (never 5432)

| Cluster | Port | Role |
|---------|------|------|
| primary | **54321** | `wal_level=replica`, replication + PITR-ready; the WALL role `pgb_agent` lives here |
| replica | **54322** | streaming standby (`pg_basebackup -R`), read-only |
| meta    | **54323** | separate cluster hosting the append-only `_meta` audit DB (§4) |

Override per-cluster with `PG_BUMPERS_PRIMARY_PORT` / `PG_BUMPERS_REPLICA_PORT` /
`PG_BUMPERS_META_PORT`, the bin dir with the unified `PG_BUMPERS_PG18_BIN` (the one
variable CI sets, taking precedence over the legacy `PGBIN`), and the data dir with
`PG_BUMPERS_LOCALSTACK_DIR`.

Connect (trust auth, loopback only — throwaway dev clusters; `-X` bypasses your `~/.psqlrc`):

```sh
PGBIN=/opt/homebrew/opt/postgresql@18/bin
$PGBIN/psql -X "host=localhost port=54321 user=postgres dbname=postgres"   # primary
$PGBIN/psql -X "host=localhost port=54322 user=postgres dbname=postgres"   # replica (read-only)
$PGBIN/psql -X "host=localhost port=54323 user=postgres dbname=_meta"      # meta / audit
```

> **Teardown is truthful.** `down` doesn't just delete the data dir — it stops *our*
> postmasters (matched by a PID ledger that survives `rm -rf ./.localstack/`, and as a
> backstop by the `-D` data dir of whatever LISTENs on our port) and then **errors
> non-zero** if any of 54321/54322/54323 is still bound. It never touches a process it
> can't prove is ours, so the founder's 5432 cluster and unrelated processes are safe.

---

## 4. Running the env-gated integration tests

Integration tests are gated by **`PG_BUMPERS_IT`** so the default `cargo test` and CI
stay fast and DB-free:

- `PG_BUMPERS_IT` unset / `!= 1` → integration assertions **skip** (exit 0).
- `PG_BUMPERS_IT=1` → they **run for real** against a live PG 18 stack.

> **DSN defaults differ by suite.** Some suites default to the local-stack primary
> (`54321`); others default to a *dedicated* throwaway port (e.g. dry-run `54341`,
> audit `55432`, fidelity `55431`) and create their own fresh databases there. Each
> default is overridable by env — the per-suite values are called out below. None of
> them ever defaults to `5432`.

Bring the stack up first, run the suites, then tear it down:

```sh
deploy/local-stack.sh up
# ... run the suites below ...
deploy/local-stack.sh down
```

### 4a. Smoke harness — `deploy/smoke.sh`

Asserts the substrate is genuinely wired: primary + meta reachable, replica reachable
**and in recovery**, primary sees a **streaming** standby, and a row written on the
primary **replicates** to the standby within a bounded wait. Exits non-zero on any
failure.

```sh
# GREEN — stack up → smoke passes (exit 0):
deploy/local-stack.sh up
PG_BUMPERS_IT=1 bash deploy/smoke.sh

# RED — with the stack DOWN, the assertions fail (exit 1):
deploy/local-stack.sh down
PG_BUMPERS_IT=1 bash deploy/smoke.sh

# Gate proof — with PG_BUMPERS_IT unset it SKIPS (exit 0):
bash deploy/smoke.sh
```

### 4b. The WALL matrix — `deploy/test/wall_matrix.sh`

The role-hardening test matrix (SPEC §3 layers 0–1). It spins its **own** dedicated
throwaway PG 18 cluster on **54331** (you do *not* need `local-stack` up for this one),
applies the hardened-role SQL + the Layer 0 boundary `pg_hba`, then asserts one row per
matrix item by **attempting each denied action as the `pgb_agent` role and proving it
fails with a permission error** (plus: whitelisted SELECT succeeds, member-of-nothing,
boundary refused/allowed).

```sh
# GREEN — every matrix row passes against real PG18 (exit 0):
PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh

# RED — an UN-hardened role CAN do denied things; assertions fail (exit non-0):
PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh --red

# Gate proof — with PG_BUMPERS_IT unset it SKIPS (exit 0):
deploy/test/wall_matrix.sh
```

### 4c. Crate integration suites (against PG 18)

```sh
# Proxy end-to-end against PG18 (TLS + SCRAM, WALL role, byte/row cutoff,
# statement-stacking block, read-only gate). Default admin DSN: 54321 (local-stack primary).
PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test proxy_it -- --nocapture
#   override: PG_BUMPERS_PROXY_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres"

# Clone dry-run (S2): no-WHERE UPDATE preview, PK-set measurement, volatile-predicate refusal.
# Default admin DSN: 54341 (its OWN dedicated throwaway port; it CREATEs fresh DBs there).
# Point it at the running local-stack primary with the override below if you prefer 54321.
PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test dry_run_it -- --nocapture
#   override: PG_BUMPERS_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres"
```

The **clone-governance** suite is self-contained — it spins its *own* throwaway PG 18
clusters (primary on `54360 + offset`, clone on `54370 + offset`) via
`PG_BUMPERS_PG18_BIN` (or the legacy `PG_BUMPERS_PGBIN`; both default to the keg
path), so `local-stack` does not need to be up:

```sh
PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test clone_governance_it -- --nocapture
```

The **`_meta` audit sink** suite (`pgb-audit`, default feature `pg`) needs an
admin/superuser PG 18 cluster; it creates fresh databases via `CREATE DATABASE`. Its
default DSN is `127.0.0.1:55432`, so point it at the local-stack primary (or any PG 18):

```sh
PG_BUMPERS_AUDIT_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres" \
  PG_BUMPERS_IT=1 cargo test -p pgb-audit --test pg_meta_it -- --nocapture
```

### 4d. The fidelity gate — `spikes/fidelity` (issue #8)

The throwaway S0 spike that red-tests the two riskiest assumptions against real PG 18:
clone↔prod PK-set prediction fidelity (any drift is caught by the `pgb_core` checksum)
and typed-inverse restore (with the documented honest gaps: sequences / trigger
side-effects / NOTIFY are *not* restored). It creates databases on an admin cluster;
its default DSN is `127.0.0.1:55431`, so override it onto the local-stack primary:

```sh
PG_BUMPERS_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres" \
  PG_BUMPERS_IT=1 cargo test -p fidelity-spike -- --nocapture
```

> The whole env-gated suite can also be driven straight from the workspace
> (`PG_BUMPERS_IT=1 cargo test --workspace --locked`) once the stack is up and the
> override DSNs above are exported — each suite skips cleanly if it can't reach its DB.

---

## 5. The shipped artifact — docker-compose

`deploy/docker-compose.yml` (image `postgres:18`) is the **shipped artifact** for real
users and for CI on a docker-healthy machine: `primary` + `meta` always on, `replica`
behind the `replica` profile, `dblab` behind the `dblab` profile (a documented
placeholder; a real Database Lab Engine is OPTIONAL per §12). The
hardened-role WALL SQL drops in via `deploy/init/` on first boot.

> **Live container runs are blocked in this dev environment** — `docker pull` hangs at
> zero blob bytes (host-level daemon networking fault; see the amendments log). Here the
> compose is only **statically validated**. It must be re-validated with a live `up` on a
> docker-healthy machine.

```sh
# Static validation (parses config; does NOT pull images):
docker compose -f deploy/docker-compose.yml config -q && echo COMPOSE_OK
```

On a docker-healthy machine you can bring it up — but note the host-port **5432**
conflict (the founder, and many hosts, already run Postgres on 5432), so override the
host ports:

```sh
# Baseline (primary + meta), with non-conflicting host ports:
PGB_PRIMARY_HOST_PORT=15432 PGB_META_HOST_PORT=15433 PGB_REPLICA_HOST_PORT=15434 \
  docker compose -f deploy/docker-compose.yml up -d

# With the streaming replica:
PGB_PRIMARY_HOST_PORT=15432 PGB_META_HOST_PORT=15433 PGB_REPLICA_HOST_PORT=15434 \
  docker compose -f deploy/docker-compose.yml --profile replica up -d

# Tear down (and drop volumes):
docker compose -f deploy/docker-compose.yml --profile replica --profile dblab down -v
```

| Service | Profile  | Host port | Override env | Role |
|---------|----------|-----------|--------------|------|
| primary | (always) | 5432 | `PGB_PRIMARY_HOST_PORT` | primary, `wal_level=replica`, replication + PITR-ready |
| meta    | (always) | 5433 | `PGB_META_HOST_PORT` | separate instance hosting the `_meta` audit DB |
| replica | `replica`| 5434 | `PGB_REPLICA_HOST_PORT` | streaming standby of `primary` |
| dblab   | `dblab`  | — | — | clone-provider PLACEHOLDER (OPTIONAL) |

For the full deploy reference (the WALL artifacts, the `pg_hba` boundary, §10.8 degraded
mode), see [`deploy/README.md`](../deploy/README.md).

---

## 6. Before you push

Run the full CI loop green locally (mirrors `.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check
```

(The MCP server `pgb-mcp` lives in `crates/mcp` and is covered by the
`--workspace` build/test + `cargo deny` above — no separate Node/pnpm step.)

Engineering rules (red/green TDD, fail-closed, PR lifecycle) are in
[`CLAUDE.md`](../CLAUDE.md) and [`docs/development.md`](development.md).
