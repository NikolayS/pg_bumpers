# `deploy/` — local dev/test stack & deployment assets

The dev/test substrate for pg_bumpers (SPEC §3, §7, §12). There are **two paths**:

1. **`docker-compose.yml`** — the **shipped artifact** for real users (and CI on a
   docker-healthy machine). Postgres **18**, primary + optional replica + `_meta`
   audit DB + a DBLab placeholder, behind compose **profiles**.
2. **`local-stack.sh`** — the **live dev/CI substrate used here**. It builds the same
   topology out of local Postgres 18 clusters (`initdb` / `pg_basebackup` / `pg_ctl`),
   no Docker. This exists because `docker pull` is non-functional in the build
   environment (host-level daemon networking fault). See
   [`docs/spec/SPEC.amendments.md`](../docs/spec/SPEC.amendments.md) → *"S0 integration
   substrate"* for the deviation, rationale, and how to re-validate compose live.

Both paths model the same shape: a streaming-replication **primary**, an OPTIONAL
streaming **replica** (off by default → proves the bare-primary baseline, SPEC §12),
and a separate append-only **`_meta`** audit DB (SPEC §4).

---

## Path A — docker-compose (shipped artifact, for users)

Image: `postgres:18`. Services: `primary` + `meta` (always on), `replica` (profile
`replica`), `dblab` (profile `dblab`, a documented placeholder — a real Database Lab
Engine is OPTIONAL per §12 and lands in S2).

```sh
# Baseline — proves the bare-primary path (primary + meta only):
docker compose -f deploy/docker-compose.yml up -d

# With the streaming replica:
docker compose -f deploy/docker-compose.yml --profile replica up -d

# With the dblab placeholder:
docker compose -f deploy/docker-compose.yml --profile dblab up -d

# Static validation (parses config; does NOT pull images):
docker compose -f deploy/docker-compose.yml config -q && echo COMPOSE_OK

# Tear down (and drop volumes):
docker compose -f deploy/docker-compose.yml --profile replica --profile dblab down -v
```

| Service | Profile    | Host port | Override env             | Role |
|---------|------------|-----------|--------------------------|------|
| primary | (always)   | **5432**  | `PGB_PRIMARY_HOST_PORT`  | primary, `wal_level=replica`, replication+PITR-ready |
| meta    | (always)   | **5433**  | `PGB_META_HOST_PORT`     | separate instance hosting the `_meta` audit DB (§4) |
| replica | `replica`  | **5434**  | `PGB_REPLICA_HOST_PORT`  | streaming standby of `primary` (`pg_basebackup -R`) |
| dblab   | `dblab`    | —         | —                        | clone-provider PLACEHOLDER (OPTIONAL; S2) |

> **⚠️ Host-port 5432 conflict.** The shipped compose publishes host port **5432** for
> `primary` — and **the founder runs Postgres on 5432**. Running `docker compose up` on
> the founder's host (or any host with something on 5432) would **collide** and fail to
> bind. Override the host ports before bringing it up:
>
> ```sh
> PGB_PRIMARY_HOST_PORT=15432 PGB_META_HOST_PORT=15433 PGB_REPLICA_HOST_PORT=15434 \
>   docker compose -f deploy/docker-compose.yml up -d
> ```
>
> (The local substrate — **Path B** below — never has this problem: it uses dedicated
> high ports 54321/54322/54323 and never touches 5432.)

> **Live container runs are blocked in the pg_bumpers build environment** (`docker pull`
> hangs at zero blob bytes — host-level daemon fault). Here, the compose is only
> **statically validated** (`docker compose config -q`). It must be re-validated with a
> live `up` on a docker-healthy machine. The live substrate in this env is **Path B**.

Init hooks live in `deploy/init/` and run once on first boot of `primary`
(`/docker-entrypoint-initdb.d`). The hardened-role WALL SQL (issue #5, SPEC §3 layer
0–1) drops in there at a clearly-marked include point — see `deploy/init/00_README.sql`.

---

## Path B — `local-stack.sh` (live dev/CI substrate here)

Uses the keg-only Homebrew Postgres 18 binaries
(`/opt/homebrew/opt/postgresql@18/bin`; override with `PGBIN=`). Brings up isolated,
throwaway clusters under a git-ignored `./.localstack/` dir, on **dedicated high
ports** that never touch any cluster already running on 5432.

```sh
deploy/local-stack.sh up      # initdb + start primary + meta; pg_basebackup + stream replica
deploy/local-stack.sh status  # pg_isready snapshot for all three
deploy/local-stack.sh down    # stop all clusters, remove ./.localstack/ (clean teardown)
```

(Ordered primary / meta / replica to match the Path A table above.)

| Cluster | Port      | Role |
|---------|-----------|------|
| primary | **54321** | `wal_level=replica`, `max_wal_senders=10`, `wal_keep_size=128MB`, replication+PITR-ready |
| meta    | **54323** | separate cluster hosting the append-only `_meta` audit DB (§4) |
| replica | **54322** | streaming standby (`pg_basebackup -R` → `standby.signal` + `primary_conninfo`) |

Connection strings (trust auth, loopback only — throwaway dev clusters):

```sh
psql -X "host=localhost port=54321 user=postgres dbname=postgres"   # primary
psql -X "host=localhost port=54322 user=postgres dbname=postgres"   # replica (read-only)
psql -X "host=localhost port=54323 user=postgres dbname=_meta"      # meta / audit
```

> Use `psql -X` to bypass any user `~/.psqlrc` that might inject banners/timing into
> scripted output (the smoke harness and the script already do this).

The hardened-role WALL SQL (issue #5) attaches at a marked include point in
`start_primary` — this script intentionally does the WAL/replication wiring only and
does **not** duplicate the role work.

`./.localstack/` is git-ignored (root `.gitignore`), so `git status` stays clean.

### Truthful, robust teardown

`down` does not just delete the data dir — it **stops OUR postmasters and verifies the
ports are actually free**, then fails loudly if any are still bound:

- On `up`, each started postmaster's PID is recorded in an out-of-tree ledger
  (`$TMPDIR/pg_bumpers-localstack/<root-digest>/<port>.pid`) that **survives**
  `rm -rf ./.localstack/`. So even if the data dir is deleted out-of-band (e.g.
  `git clean -fdx`, since the dir is gitignored), `down` can still stop the orphaned
  postmasters — matching on the **recorded PID** and, as a backstop, on any postmaster
  LISTENing on our port whose `-D` data dir is one of ours. It **never** touches a
  process it can't prove is ours (5432 and unrelated processes are safe).
- `down` re-checks the ports with `lsof` afterward and **errors non-zero** if any of
  54321/54322/54323 is still bound — it never claims success while a port stays occupied.
- `up` stamps a per-run **identity sentinel** (a `pgb_localstack_sentinel` DB with a
  unique `run_id`); `wait_ready` and `smoke.sh` verify it, so a stale orphan squatting a
  port can never read as "our freshly-started cluster." `up` also refuses to start onto a
  port held by a process it doesn't own.
- A partial/failed `up` self-cleans via an `EXIT`/`ERR` trap (no leaked clusters).
- `PG_BUMPERS_LOCALSTACK_DIR` is validated (non-empty, absolute, not `/` or `$HOME`,
  confined under the repo or a `*localstack*` dir) before any `rm -rf`.

---

## Integration tests: the `PG_BUMPERS_IT` gate

Integration tests are **env-gated** so plain test runs and the cargo CI job stay fast
and DB-independent. The convention for the whole project:

- `PG_BUMPERS_IT` unset / `!= 1` → integration assertions are **skipped** (exit 0).
- `PG_BUMPERS_IT=1` → they **run for real** against a live stack.

### Smoke harness — `deploy/smoke.sh`

Asserts: (1) primary reachable, (2) meta reachable + `_meta` queryable, (3) replica
reachable **and in recovery** (`pg_is_in_recovery() = t`), (4) primary reports a
**streaming** standby in `pg_stat_replication`, (5) a row written on the primary is
**replicated** to the standby within a bounded wait. Exits non-zero on any failure.

```sh
# RED — with the stack DOWN, the assertions fail (exit 1):
PG_BUMPERS_IT=1 bash deploy/smoke.sh

# GREEN — bring the stack up, then the smoke passes (exit 0):
bash deploy/local-stack.sh up
PG_BUMPERS_IT=1 bash deploy/smoke.sh

# (Gate proof) — with PG_BUMPERS_IT unset, it SKIPS and exits 0:
bash deploy/smoke.sh
```

The smoke harness targets the **Path B** ports by default; override via
`PG_BUMPERS_PRIMARY_PORT` / `PG_BUMPERS_REPLICA_PORT` / `PG_BUMPERS_META_PORT` (and
`PGBIN`) to point it at any equivalent stack.

---

## The WALL — Layer 1 hardened role + Layer 0 network boundary (issue #5)

The deterministic floor's first layer (SPEC §3 layer 0–1, §4 "Network/roles — do FIRST",
§5 role-hardening matrix). It makes a hostile *raw* libpq client (no proxy, no MCP)
physically unable to read non-whitelisted data or to write/escalate — **even before the
proxy** — and refuses any agent connection that doesn't originate from the proxy host.

| Artifact | What it is |
|----------|------------|
| `sql/10_hardened_role.sql` | **Canonical, idempotent** hardened-role migration: creates `pgb_agent` (LOGIN, NOSUPERUSER, NOINHERIT, member-of-nothing, NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS), revokes all `pg_*` predefined roles + PUBLIC EXECUTE, **revokes TEMP on the database + the in-DB large-object write built-ins** (so there is **no write grant ANYWHERE**), sets a **best-effort** role-level `search_path` pin (see note below), grants **SELECT-whitelist only**, default-deny everywhere. |
| `init/10_hardened_role.sql` | Byte-for-byte **synced copy** of the canonical SQL, picked up by the docker entrypoint (`/docker-entrypoint-initdb.d`, runs after `00_README.sql`). `sql/check-init-sync.sh` guards against drift. |
| `hba/pg_hba.agent-boundary.conf.template` | **Layer 0** `pg_hba` rules: agent role permitted **only from the proxy host's CIDR**; every other origin `reject`ed. |
| `hba/render-hba.sh` | Generator that substitutes the template's placeholders (`--proxy-cidr 10.0.0.5/32 …`). Append its output to `$PGDATA/pg_hba.conf` **above** any catch-all. |
| `hba/NETWORK-POLICY.md` | The network-policy companion (firewall / security-group / k8s NetworkPolicy half of the boundary) + how the local test models "proxy host vs. elsewhere". |
| `test/wall_matrix.sh` | The **role-hardening test matrix** (env-gated `PG_BUMPERS_IT=1`): spins a dedicated throwaway PG18 cluster on **54331**, applies the SQL + the boundary `pg_hba`, then asserts **one row per matrix item** by *attempting* each denied action as the agent and proving it fails (+ whitelisted SELECT succeeds, member-of-nothing, boundary refused/allowed). |

Wired in: `local-stack.sh` applies `sql/10_hardened_role.sql` against the primary on every
`up` (idempotent); the docker compose picks up `init/10_hardened_role.sql` on first boot.

```sh
# GREEN — every matrix row passes against real PG18 (exit 0):
PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh

# RED — a freshly-created, UN-hardened role CAN do denied things; assertions fail (exit 1):
PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh --red

# Gate proof — with PG_BUMPERS_IT unset it SKIPS (exit 0):
deploy/test/wall_matrix.sh

# Render the Layer 0 boundary for a real deployment:
deploy/hba/render-hba.sh --agent-role pgb_agent --proxy-cidr 10.0.0.5/32 >> "$PGDATA/pg_hba.conf"
```

> **Local boundary model (no root needed).** The harness can't add a second loopback alias
> without `sudo`, so it models "proxy host vs. elsewhere" with two real loopback addresses:
> agent **from `::1`** (the proxy-host stand-in) → **ALLOWED**; agent **from `127.0.0.1`**
> (a non-proxy origin) → **REJECTED** at `pg_hba`. A real deployment keys `@PROXY_CIDR@` on
> the proxy's actual IP/CIDR. See `hba/NETWORK-POLICY.md`.

> **Honest enforcement note.** Some denies (`dblink`/`postgres_fdw`/`COPY … PROGRAM`/
> `lo_import`/`lo_export`/`pg_read_file`/server-files) cannot be expressed as a `REVOKE`
> because the capability was never granted to a non-superuser, member-of-nothing role —
> PostgreSQL gates them on a predefined-role membership or the superuser bit this role does
> not hold. The migration documents these as `[NO-GRANT]` and the harness proves each by
> **attempting the action as the agent and asserting a permission error** (not by a paper
> REVOKE). The harness's `assert_denied` requires a **permission/insufficient-privilege
> error class** — a typo or connection error cannot masquerade as a deny.

> **`search_path` honesty (defense-in-depth, NOT immutable).** The role-level `search_path`
> pin in the migration is **best-effort only**. PostgreSQL lets ANY non-superuser role change
> its **own** role-level GUCs, so the agent itself can run `ALTER ROLE pgb_agent SET
> search_path = …` or `RESET ALL` and defeat the pin (until the migration re-applies). **The
> authoritative search_path pin is the proxy (S1)**, which sets it per session on every
> brokered connection. The WALL's real guarantee does **not** depend on `search_path`: reads
> are via fully-qualified **explicit SELECT grants** only, and the agent can neither CREATE
> schemas/objects (so no trojan-shadowing) nor write anywhere — therefore **no `search_path`
> the agent chooses can widen its read surface or escalate**. The matrix proves this
> **invariant** directly (section I): it shows the agent CAN mutate its path + `RESET ALL`
> (documented PG behavior) yet **STILL** cannot read non-whitelisted data or write anywhere.

> **"No write grant ANYWHERE" — now enforced.** PostgreSQL grants two write paths to PUBLIC
> by default: `TEMPORARY` on the database (`CREATE TEMP TABLE … INSERT`) and EXECUTE on the
> in-DB large-object write built-ins (`lo_create`/`lowrite`/`lo_from_bytea`/`lo_put`/…). The
> migration now **REVOKEs both** (from PUBLIC and the agent), and the matrix asserts
> `CREATE TEMP TABLE` and `lo_create`/`lowrite`/`lo_from_bytea`/`lo_put` are **DENIED**. The
> server-file LO paths (`lo_import`/`lo_export`) remain `[NO-GRANT]`-gated as above.

> **Boundary has an independent RED path.** Beyond `--red` (which un-hardens the ROLE only),
> the harness runs an inline **BOUNDARY-RED** self-test: it swaps in a deliberately-permissive
> `pg_hba`, proves the agent then CONNECTS from the non-proxy origin (so the strict-boundary
> assertion *would* fail when misconfigured → it has teeth), then restores the strict rules
> and re-confirms the reject. This proves the boundary test is not passing vacuously.

> **Catalog/role/DB-name enumeration is readable** by the agent (PostgreSQL default; the
> system catalogs are world-readable). This is **in-scope-acceptable**: it exposes no
> application data (other backends' query text correctly shows `<insufficient privilege>`),
> and the WALL's guarantee is about *non-whitelisted data reads* and *writes/escalation*,
> not hiding the schema shape. Left as-is by design.

## §10.8 degraded mode (no replica)

The replica is **OPTIONAL** (SPEC §12). With **no replica** (the default baseline `up`
without the `replica` profile / before `local-stack.sh` builds the standby), the system
runs in **degraded mode** (SPEC §10.8): reads route to the **primary** under *stricter*
budgets + `statement_timeout` + warden, and the write path (clone/guarded-apply) is
unchanged. The bounded-blast-radius + reversibility guarantee is **invariant** across
every configuration (SPEC §12.1) — only the preview/isolation experience improves when
a replica (and DBLab) are present. Run the baseline (no `replica` profile) to exercise
this path.

> Source of truth: `docs/spec/SPEC.md` (v0.8). Deviation log:
> `docs/spec/SPEC.amendments.md`. License: Apache-2.0.
