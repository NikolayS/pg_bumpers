# pg_brakes — Quickstart

**The first-run path is "point pg_brakes at YOUR existing PostgreSQL."** You bring
your own production database (any supported major, **14–18**; spec v0.8.1 §0.5);
pg_brakes never asks you to spin one up. This page LEADS with that BYO flow
(§[Get started — BYO](#get-started--point-pg_brakes-at-your-existing-postgresql-byo)),
then — far below, and clearly labelled **CI/dev/test fixtures only** — covers the
throwaway local stack / docker-compose / `up.sh` substrate the project uses for its
own tests, the benchmark, and the env-gated integration suite.

> **The throwaway stack is a fixture, not a shipped artifact.** The
> `deploy/local-stack.sh` / `deploy/docker-compose.yml` / `deploy/up.sh` clusters are a
> deterministic CI/dev/test substrate — **never** the onboarding flow. A real user
> follows the BYO steps below; they do **not** spin up a throwaway cluster.

> **Source of truth:** [`docs/spec/SPEC.md`](spec/SPEC.md) (v0.8); the BYO onboarding is
> §0.5. The dev-substrate deviation (docker → local PG) is logged in
> [`docs/spec/SPEC.amendments.md`](spec/SPEC.amendments.md) → *"S0 integration substrate"*.
> License: Apache-2.0. The README mirrors this BYO flow as the project's headline
> quickstart.

## What works today (status)

This is an MVP under active construction. Honest status as of this writing:

- **Works now:** the BYO-first onboarding (`policy.yaml` DSN targets + the canonical
  role hardening + the `pgb-cli doctor` fail-closed preflight); the native-role WALL +
  proxy-only network path; the enforcing proxy (read-only, byte/row cutoff,
  `statement_timeout`, anti-statement-stacking, audit); clone dry-run blast-radius
  preview; guarded apply with typed-inverse + operator approval; the live warden; the
  tamper-evident, externally-anchored audit chain; and the MCP tool surface.
- **Deferred / fast-follow:** the LLM gating engine (in the MVP the `RiskEngine` is a
  **stub returning `Allow`** — the deterministic floor is the guarantee, not any model);
  DDL / multi-statement / multi-DB; an operator approval UI; a managed clone provider.

### What the guarantee is — and is not

- **Writes:** bounded + reversible by construction — zero catastrophic data-loss false
  negatives. The floor is three orthogonal pins (not a checksum): **bounded** by the
  human-approved absolute **`WriteCap`** (`max_rows` + `max_wal_bytes`, enforced inside
  the apply txn from the `pg_stat_xact_*` deltas + a WAL-byte measure) + the
  `pg_stat_xact_*` reconciliation + a `statement_timeout`; **reversible** via the
  apply-time pre-image capture (`FOR UPDATE` + `RETURNING`) + row/column coverage guards;
  and **row-identity** foreclosed by the self-determined-predicate gate (the approved
  `WHERE` references only the immutable primary key + literals). Structural/irreversible
  ops (`DROP`, `TRUNCATE`, DDL) are refused outright.
- **Reads:** **bounded disclosure** — a per-role byte/row budget, then a hard cutoff,
  plus best-effort detection. Not zero, never "impossible." The audit chain is
  **tamper-evident**, not tamper-proof.

---

## Get started — point pg_brakes at YOUR existing PostgreSQL (BYO)

This is the real onboarding flow. You declare where your database lives in
`policy.yaml`, apply the canonical role hardening to it, verify with one command, then
launch the daemons + connect your agent — all against **your** DSNs. No throwaway
cluster required. (This mirrors the README's headline quickstart.)

### Prerequisites (BYO)

| Tool | Version | Notes |
|------|---------|-------|
| Rust | **1.90.0** | Pinned by [`rust-toolchain.toml`](../rust-toolchain.toml). `rustup` auto-selects it. |
| PostgreSQL | **14–18** | Your existing database — the proxy + native-role WALL are version-agnostic. You also need a `psql` client to apply the hardening SQL. |
| `cargo-deny` | latest | License/advisory gate (dev only): `cargo install cargo-deny`. |

Build the binaries once (the daemons + the CLI + the MCP server):

```sh
git clone https://github.com/NikolayS/pg_brakes.git
cd pg_brakes
cargo build --locked -p pgb-proxy -p pgb-applyd -p pgb-warden -p pgb-cli -p pgb-mcp
```

### 1. Declare your DSN targets in `policy.yaml`

`policy.yaml` is **authoritative** for the connection *targets* — the host/port/
database/role of (a) your primary, (b) an optional read replica, and (c) the audit
`_meta` location. Credentials stay **out** of the file (resolved from your secret
store / env); a target is *credential-less* (host/port/db/role + an optional
`secret_ref`). The `PGB_BACKEND_*` / `PGB_PROXY_*` / `PGB_META_DSN` env vars are
**overrides** layered on top (precedence: env override → `policy.yaml` target →
**fail-closed**; there is **no** throwaway-cluster default). See
[`crates/policy/policy.example.yaml`](../crates/policy/policy.example.yaml):

```yaml
# policy.yaml — point at YOUR database (no literal passwords in this file)
primary:
  host: db.internal          # your existing primary
  port: 5432                 # your real port — pg_brakes never touches a throwaway cluster
  database: app
  role: pgb_agent            # the hardened WALL role (step 2)
  secret_ref: "kms://pg-brakes/primary-pw/v1"   # OPTIONAL forward-compat placeholder; see step 4
replica:                     # OPTIONAL read replica (reads route here under §12)
  target: { host: replica.internal, port: 5432, database: app, role: pgb_agent }
audit:
  target:                    # the credential-less `_meta` DSN location (audit chain)
    host: db.internal
    port: 5432
    database: app_meta
    role: pgb_audit_writer
```

> Host/database/role/secret_ref values are validated **fail-closed** on load: a value
> carrying whitespace, `=`, a quote, a backslash, or a control char is **rejected**
> (those would inject extra libpq DSN keywords — e.g. a TLS-disabling `sslmode=disable`).

### 2. Apply the role hardening (+ your own GRANTs) to your database

Apply the **canonical, version-agnostic, AGENT-ROLE-ONLY** role hardening — it creates and
hardens the read WALL role `pgb_agent` (NOSUPERUSER · NOINHERIT · member-of-nothing · no
DML grant · default-deny on data) and the DML-only apply role `pgb_applier`, and revokes
every inherited/default privilege **from those two roles only**. It **NEVER mutates
`PUBLIC`**, so it is **safe to apply to an existing application database** (issue #108 — see
[`KNOWN_DANGERS.md`](../KNOWN_DANGERS.md) D1):

```sh
psql "host=db.internal port=5432 dbname=app" -f deploy/sql/10_hardened_role.sql
```

Then grant the agent/applier **only your own** allow-listed relations (the WALL is
default-deny on all data until you do — that is the point):

```sql
-- the agent's READ whitelist (SELECT only; never INSERT/UPDATE/DELETE):
GRANT SELECT ON app.your_read_table TO pgb_agent;
-- the applier's WRITE surface (DML only; never DDL; ownership stays unchanged):
GRANT SELECT, INSERT, UPDATE, DELETE ON app.your_write_table TO pgb_applier;
```

> **`deploy/sql/10_hardened_role.sql` is the agent-only default — safe on a shared DB.** It
> no longer seeds any demo schema (the demo tables live in the fixture-only
> `deploy/sql/20_demo_seed.sql`; CI/dev/test only). Also set up the `_meta` audit chain in
> your audit DB ([`crates/audit/sql/10_audit_meta.sql`](../crates/audit/sql/10_audit_meta.sql))
> and **restrict the agent role to the proxy host in `pg_hba.conf`** (see
> [`deploy/hba/`](../deploy/hba/)) — this network boundary is **load-bearing** on the
> agent-only default: it plus the proxy read-only floor is what contains the agent.
>
> **Optional, DEDICATED DBs only — the strict `PUBLIC` lockdown.** On a shared DB the agent
> keeps `PUBLIC`'s default `EXECUTE`/`TEMP`/large-object-write surfaces at the DB level —
> contained **through the proxy** by the fail-closed read classifier (a `SELECT lo_create()`/
> write-function / qualified cast classifies `NotRead` → Blocked at the proxy floor) and
> **direct-to-DB** by the network boundary (see [`KNOWN_BYPASSES.md`](../KNOWN_BYPASSES.md)
> B-lo). If your database is **dedicated to pg_brakes** you MAY add the DB-level belt-and-
> suspenders by applying [`deploy/sql/21_public_lockdown.sql`](../deploy/sql/21_public_lockdown.sql)
> — ⚠️ it revokes `… FROM PUBLIC` and **can break an existing application**, so do this ONLY
> on a dedicated DB or after rehearsing on a thin clone (M3 rehearsal coming). See
> [`KNOWN_DANGERS.md`](../KNOWN_DANGERS.md) D1.

### 3. Verify with `pgb-cli doctor` (fail-closed preflight)

Before you point an agent at the database, run the **fail-closed preflight**. The doctor
connects with a **catalog-readable role** (set `PGB_BACKEND_ROLE` to it — e.g.
`postgres`, an admin/monitoring role; it reads `pg_roles` + grant catalogs, which the
member-of-nothing `pgb_agent` cannot) and verifies the primary (+ optional replica +
`_meta`) are reachable, that `pgb_agent` is WALL-hardened, that `pgb_applier` is DML-only,
the pg_hba origin boundary (best-effort), and the `_meta` audit chain:

```sh
PGB_POLICY_PATH=policy.yaml \
PGB_BACKEND_ROLE=postgres \
PGB_DOCTOR_PASSWORD=…       \
  cargo run -p pgb-cli -- doctor
```

```text
pgb-cli doctor — BYO preflight (SPEC §0.5):
  [            PASS] primary_reachable: connected to the primary at db.internal:5432/app as `postgres`
  [            PASS] pgb_agent_not_superuser: `pgb_agent` is NOSUPERUSER
  [            PASS] agent_member_of_nothing: `pgb_agent` is a member of no roles
  [            PASS] agent_no_write_grant: `pgb_agent` holds NO write grant on any user table
  [            PASS] applier_no_ddl: `pgb_applier` has NO CREATE on the application schema (cannot DDL)
  …
doctor: PREFLIGHT PASSED — the deterministic floor is in place; safe to point an agent at this database.
```

It **exits non-zero on any failure** (a superuser agent, a missing role, a stray write
grant, an unreachable target) — fail-closed: do not connect an agent until every check
passes. (`PGB_BACKEND_ROLE` overrides only the role the doctor *connects* as; it always
CHECKS `pgb_agent` / `pgb_applier` by their conventional names.)

### 4. Launch the daemons against your DSNs

Each daemon resolves its connection target from your `policy.yaml` (env override
allowed); none of them defaults to a throwaway cluster. **The password comes from the
conventional env var** (this version does **not** resolve `secret_ref` — see the note
below): the proxy/applyd primary password from `PGB_BACKEND_PASSWORD`, the `_meta`
password from `PGB_META_PASSWORD`, sourced from your secret store / env:

```sh
# the inline read enforcement endpoint (the agent's ONLY network path):
PGB_POLICY_PATH=policy.yaml PGB_BACKEND_PASSWORD=… PGB_AGENT_PASSWORD=… \
PGB_META_DSN='host=db.internal port=5432 dbname=app_meta user=pgb_audit_writer password=…' \
PGB_AUDIT_SIGNING_KEY=… PGB_ANCHOR_PATH=/var/lib/pgb/anchor.worm \
  cargo run -p pgb-proxy

# the write-path daemon (owner-only Unix socket; the write credential lives here):
PGB_POLICY_PATH=policy.yaml PGB_BACKEND_PASSWORD=… PGB_APPROVER_PUBKEY=… \
PGB_META_DSN=… PGB_AUDIT_SIGNING_KEY=… PGB_ANCHOR_PATH=… PGB_APPLYD_SOCKET=/run/pgb/applyd.sock \
  cargo run -p pgb-applyd

# the out-of-band watchdog (kills runaway agent sessions; audits every action):
PGB_POLICY_PATH=policy.yaml PGB_WARDEN_ADMIN_PASSWORD=… PGB_AUDIT_WRITER_PASSWORD=… \
  cargo run -p pgb-warden
```

> **`secret_ref` is a forward-compatibility placeholder.** In this version the daemons
> do **not** resolve `secret_ref` from any secret store — the password MUST come from the
> conventional env var (`PGB_BACKEND_PASSWORD` for the primary/applyd, `PGB_META_PASSWORD`
> for `_meta`, `PGB_DOCTOR_PASSWORD` for the doctor, etc.). `secret_ref` is parsed and
> kept credential-less in `policy.yaml` so a future release can wire a resolver without a
> schema change; today it is documentation only.

> Production posture: enable **TLS** on the proxy (`PGB_PROXY_TLS_CERT` /
> `PGB_PROXY_TLS_KEY`; required whenever TLS material is configured — no silent cleartext
> downgrade) and source every secret from your secret store, not literals.

### 5. Connect your agent (the `claude mcp add` form, against your DSNs)

The agent-facing MCP server is the native Rust **`pgb-mcp`** (crate `crates/mcp`). Point
it at the **proxy** (not the raw database) and the `_meta` reader:

```sh
claude mcp add pg-brakes \
  --env PGB_PROXY_HOST=127.0.0.1 \
  --env PGB_PROXY_PORT=6432 \
  --env PGB_PROXY_DB=app \
  --env PGB_PROXY_USER=pgb_agent \
  --env PGB_PROXY_PASSWORD=… \
  --env PGB_PROXY_REQUIRE_TLS=true \
  --env PGB_PROXY_TLS_CA=/etc/pgb/proxy-ca.pem \
  --env PGB_APPLYD_SOCKET=/run/pgb/applyd.sock \
  --env PGB_POLICY_PATH=policy.yaml \
  --env PGB_META_PASSWORD=… \
  -- /path/to/target/release/pgb-mcp
```

Claude Code now has the pg_brakes tools, all flowing through the deterministic floor: a
`DROP TABLE` is **refused**, a no-`WHERE` `DELETE` is **bounded + held for approval**,
runaway reads are **killed**, and every action lands on the tamper-evident `_meta` chain
you can `pgb-cli verify`.

---

# CI / dev / test fixtures (NOT the onboarding flow)

> **Everything below this line is a throwaway fixture**, not how you onboard. The
> `local-stack.sh` / `docker-compose.yml` / `up.sh` clusters and the env-gated
> integration suites are the project's own deterministic CI/dev/test substrate — they
> spin throwaway Postgres clusters on dedicated high ports (never `5432`). Real users
> follow the **BYO** flow above; this section is for contributors and CI.

---

## Fixture prerequisites (contributors/CI)

| Tool | Version | Notes |
|------|---------|-------|
| Rust | **1.90.0** | Pinned by [`rust-toolchain.toml`](../rust-toolchain.toml) (rustfmt + clippy). `rustup` auto-selects it. |
| PostgreSQL | **14–18** | Client + server binaries (`initdb`, `pg_ctl`, `pg_basebackup`, `psql`, `pg_isready`) — to stand up the **throwaway** fixture clusters. |
| `cargo-deny` | latest | License/advisory gate: `cargo install cargo-deny`. |

### Install PostgreSQL 14–18 (macOS, Homebrew)

Any supported major (14, 15, 16, 17, 18) works — the proxy and the native-role WALL are
version-agnostic (spec v0.8.1 §0.5). Homebrew kegs are **keg-only**, so their binaries
are not symlinked onto `PATH`. The dev scripts default to the **version-neutral**
`postgresql` keg at `/opt/homebrew/opt/postgresql/bin`; override with the unified
`PG_BRAKES_PG_BIN` (the one variable CI sets per-major in the matrix, honored by every
shell script *and* every Rust IT and taking precedence over the legacy `PGBIN=` /
`PG_BRAKES_PGBIN=`) to point at a specific major's keg.

```sh
brew install postgresql          # latest stable; or `postgresql@17`, `postgresql@16`, …

# Verify the keg-only binaries are present (this is the path the scripts default to):
/opt/homebrew/opt/postgresql/bin/pg_ctl --version        # -> pg_ctl (PostgreSQL) 1x.y

# To pin a specific major for the scripts/ITs:
#   export PG_BRAKES_PG_BIN=/opt/homebrew/opt/postgresql@17/bin
```

> You do **not** need to start a system Postgres service or add it to `PATH`. The dev
> stack (`deploy/local-stack.sh`) calls these binaries by absolute path and runs
> throwaway clusters on dedicated high ports — it never touches a cluster on 5432.

---

## Fixture: clone + the fast DB-free build/test loop

```sh
git clone https://github.com/NikolayS/pg_brakes.git
cd pg_brakes

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
non-Rust toolchain step (the original non-Rust MCP server was removed in EPIC #83;
the build is Rust-only).

---

## Fixture: the local dev stack (`local-stack.sh`)

`deploy/local-stack.sh` is the **live dev/CI substrate** here: isolated, throwaway PG
clusters (any supported major, 14–18) under a git-ignored `./.localstack/`, built from
the keg-only Homebrew binaries
(no Docker). It models the same shape as the docker-compose fixture: a streaming-
replication **primary**, a streaming **replica**, and a separate append-only **`_meta`**
audit DB.

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

Override per-cluster with `PG_BRAKES_PRIMARY_PORT` / `PG_BRAKES_REPLICA_PORT` /
`PG_BRAKES_META_PORT`, the bin dir with the unified `PG_BRAKES_PG_BIN` (the one
variable CI sets, taking precedence over the legacy `PGBIN`), and the data dir with
`PG_BRAKES_LOCALSTACK_DIR`.

Connect (trust auth, loopback only — throwaway dev clusters; `-X` bypasses your `~/.psqlrc`):

```sh
PGBIN=/opt/homebrew/opt/postgresql/bin   # version-neutral keg; or a pinned @NN keg
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

## Fixture: running the env-gated integration tests

Integration tests are gated by **`PG_BRAKES_IT`** so the default `cargo test` and CI
stay fast and DB-free:

- `PG_BRAKES_IT` unset / `!= 1` → integration assertions **skip** (exit 0).
- `PG_BRAKES_IT=1` → they **run for real** against a live PG stack (any supported major, 14–18).

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
PG_BRAKES_IT=1 bash deploy/smoke.sh

# RED — with the stack DOWN, the assertions fail (exit 1):
deploy/local-stack.sh down
PG_BRAKES_IT=1 bash deploy/smoke.sh

# Gate proof — with PG_BRAKES_IT unset it SKIPS (exit 0):
bash deploy/smoke.sh
```

### 4b. The WALL matrix — `deploy/test/wall_matrix.sh`

The role-hardening test matrix (SPEC §3 layers 0–1). It spins its **own** dedicated
throwaway PG cluster (any supported major, 14-18) on **54331** (you do *not* need `local-stack` up for this one),
applies the hardened-role SQL + the Layer 0 boundary `pg_hba`, then asserts one row per
matrix item by **attempting each denied action as the `pgb_agent` role and proving it
fails with a permission error** (plus: whitelisted SELECT succeeds, member-of-nothing,
boundary refused/allowed).

```sh
# GREEN — every matrix row passes against the real PG (any supported major, exit 0):
PG_BRAKES_IT=1 deploy/test/wall_matrix.sh

# RED — an UN-hardened role CAN do denied things; assertions fail (exit non-0):
PG_BRAKES_IT=1 deploy/test/wall_matrix.sh --red

# Gate proof — with PG_BRAKES_IT unset it SKIPS (exit 0):
deploy/test/wall_matrix.sh
```

### 4c. Crate integration suites (against PG 14–18)

```sh
# Proxy end-to-end against the live PG (TLS + SCRAM, WALL role, byte/row cutoff,
# statement-stacking block, read-only gate). Default admin DSN: 54321 (local-stack primary).
PG_BRAKES_IT=1 cargo test -p pgb-proxy --test proxy_it -- --nocapture
#   override: PG_BRAKES_PROXY_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres"

# Clone dry-run (S2): no-WHERE UPDATE preview, PK-set measurement, volatile-predicate refusal.
# Default admin DSN: 54341 (its OWN dedicated throwaway port; it CREATEs fresh DBs there).
# Point it at the running local-stack primary with the override below if you prefer 54321.
PG_BRAKES_IT=1 cargo test -p pgb-clone-orchestrator --test dry_run_it -- --nocapture
#   override: PG_BRAKES_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres"
```

The **clone-governance** suite is self-contained — it spins its *own* throwaway PG
clusters (primary on `54360 + offset`, clone on `54370 + offset`) via
`PG_BRAKES_PG_BIN` (or the legacy `PG_BRAKES_PGBIN`; both default to the
version-neutral keg path), so `local-stack` does not need to be up:

```sh
PG_BRAKES_IT=1 cargo test -p pgb-clone-orchestrator --test clone_governance_it -- --nocapture
```

The **`_meta` audit sink** suite (`pgb-audit`, default feature `pg`) needs an
admin/superuser PG cluster (any supported major); it creates fresh databases via
`CREATE DATABASE`. Its default DSN is `127.0.0.1:55432`, so point it at the local-stack
primary (or any supported PG):

```sh
PG_BRAKES_AUDIT_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres" \
  PG_BRAKES_IT=1 cargo test -p pgb-audit --test pg_meta_it -- --nocapture
```

### 4d. The fidelity gate — `spikes/fidelity` (issue #8)

The throwaway S0 spike that red-tests the two riskiest assumptions against real PG:
clone↔prod PK-set prediction fidelity (the dry-run blast-radius preview the apply then
bounds with the `WriteCap` + `pg_stat_xact_*` reconciliation; the affected-PK-set
checksum was dropped in EPIC #91, so identity is foreclosed by the self-determined-
predicate gate, not a checksum) and typed-inverse restore (with the documented honest
gaps: sequences / trigger side-effects / NOTIFY are *not* restored). It creates
databases on an admin cluster;
its default DSN is `127.0.0.1:55431`, so override it onto the local-stack primary:

```sh
PG_BRAKES_PGURL="host=127.0.0.1 port=54321 user=postgres dbname=postgres" \
  PG_BRAKES_IT=1 cargo test -p fidelity-spike -- --nocapture
```

> The whole env-gated suite can also be driven straight from the workspace
> (`PG_BRAKES_IT=1 cargo test --workspace --locked`) once the stack is up and the
> override DSNs above are exported — each suite skips cleanly if it can't reach its DB.

---

## The docker-compose fixture (CI/dev/test only — NOT how you onboard)

> **This compose stack is a CI/dev/test fixture, not a shipped artifact for real users.**
> A real user follows the **[BYO flow](#get-started--point-pg_brakes-at-your-existing-postgresql-byo)**
> against their own database; this throwaway stack just gives contributors and CI a
> self-contained substrate to watch the floor work end-to-end.

`deploy/docker-compose.yml` (image `postgres:${PG_MAJOR:-16}`, any supported major
14–18) is the throwaway CI/dev/test compose: `primary` + `meta` always on, `replica`
behind the `replica` profile, `dblab` behind the `dblab` profile (a documented
placeholder; a real Database Lab Engine is OPTIONAL per §12). The
hardened-role WALL SQL drops in via `deploy/init/` on first boot (the fixture also
applies the demo seed `deploy/sql/20_demo_seed.sql`; a BYO deployment does not).

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

## Before you push (contributors)

Run the full CI loop green locally (mirrors `.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test  --workspace --locked
cargo deny  check
```

(The MCP server `pgb-mcp` lives in `crates/mcp` and is covered by the
`--workspace` build/test + `cargo deny` above — the build is Rust-only, with no
separate non-Rust toolchain step.)

Engineering rules (red/green TDD, fail-closed, PR lifecycle) are in
[`CLAUDE.md`](../CLAUDE.md) and [`docs/development.md`](development.md).
