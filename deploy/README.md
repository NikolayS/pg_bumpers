# `deploy/` — CI/dev/test fixtures & the canonical deployment assets

> **These are CI/dev/test FIXTURES, not the onboarding flow (SPEC §0.5).** The
> first-run path for real users is **bring-your-own Postgres** — point pg_brakes at
> your existing database via `policy.yaml` DSN targets, apply
> [`sql/10_hardened_role.sql`](sql/10_hardened_role.sql), verify with `pgb-cli
> doctor`, and launch the daemons against your DSNs (see the **README's BYO
> quickstart**). Everything below — `docker-compose.yml`, `local-stack.sh`, `up.sh` —
> is a **throwaway** substrate for our own integration tests and the benchmark. It is
> NOT a "shipped artifact for real users"; it never replaces your own database.

> **One command to a connected demo (fixture):** `deploy/up.sh` launches the FULL
> assembled stack — `pgb-proxy` (the agent read endpoint, in front of Postgres),
> `pgb-applyd` (the write-path socket), and `pgb-warden` (the live watchdog) — against
> a *throwaway* cluster and prints a ready-to-paste `claude mcp add` line. Connect a
> real Claude Code, then watch a `DROP TABLE` get REFUSED, a no-`WHERE` `UPDATE` get
> bounded + approval-gated, and the audit chain verify. Tear it all down with
> `deploy/down.sh`. See [Path C](#path-c--upsh--the-one-command-runnable-demo). The
> MCP read path genuinely traverses `pgb-proxy` (extended-protocol-only,
> WALL-enforced) — not raw Postgres.

The CI/dev/test substrate for pg_brakes (SPEC §3, §7, §12) — **three fixture
paths**, all throwaway, none of them the user onboarding flow (that is BYO, above):

1. **`docker-compose.yml`** — the **CI/dev fixture** for a docker-healthy machine (a
   reproducible throwaway, NOT a shipped artifact for real users — real users BYO
   their own database, SPEC §0.5). Postgres (any supported major 14–18), primary +
   optional replica + `_meta` audit DB + a DBLab placeholder, behind compose
   **profiles**. Its init mounts `init/10_hardened_role.sql` (the agent-only canonical
   hardening), `init/21_public_lockdown.sql` (the opt-in strict `PUBLIC` lockdown — the
   docker primary is itself a throwaway fixture, so it applies it), **and**
   `init/20_demo_seed.sql` (the FIXTURE-ONLY demo schema).
2. **`local-stack.sh`** — the **live dev/CI fixture used here**. It builds the same
   topology out of local Postgres clusters (`initdb` / `pg_basebackup` / `pg_ctl`),
   no Docker. This exists because `docker pull` is non-functional in the build
   environment (host-level daemon networking fault). See
   [`docs/spec/SPEC.amendments.md`](../docs/spec/SPEC.amendments.md) → *"S0 integration
   substrate"* for the deviation, rationale, and how to re-validate compose live.

Paths A and B model the same shape: a streaming-replication **primary**, an OPTIONAL
streaming **replica** (off by default → proves the bare-primary baseline, SPEC §12),
and a separate append-only **`_meta`** audit DB (SPEC §4). (Path C — the one-command
`up.sh` demo — co-locates the `_meta` chain on the **primary** instead; see below.)

The **canonical, version-agnostic, AGENT-ROLE-ONLY** role hardening a BYO user applies to
their OWN database is [`sql/10_hardened_role.sql`](sql/10_hardened_role.sql) — it hardens
`pgb_agent` + `pgb_applier`, **NEVER mutates `PUBLIC`** (issue #108 — safe on an existing
DB), and grants **nothing** application-specific (the user grants their own relations). The
strict `… FROM PUBLIC` lockdown is split out into the **opt-in**
[`sql/21_public_lockdown.sql`](sql/21_public_lockdown.sql) (⚠️ dedicated/greenfield DB ONLY —
the fixtures apply it; a BYO user does NOT unless their DB is dedicated). The demo schema
(`allowed_read` / `secret_data`) is split out into the fixture-only
[`sql/20_demo_seed.sql`](sql/20_demo_seed.sql), which ONLY the fixtures (`up.sh`,
docker-compose, `wall_matrix.sh`) apply.

---

## Path A — docker-compose (CI/dev fixture; throwaway, NOT a user artifact)

Image: `postgres:${PG_MAJOR:-16}` (any supported major 14–18; override with
`PG_MAJOR`). Services: `primary` + `meta` (always on), `replica` (profile
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

> **Live container runs are blocked in the pg_brakes build environment** (`docker pull`
> hangs at zero blob bytes — host-level daemon fault). Here, the compose is only
> **statically validated** (`docker compose config -q`). It must be re-validated with a
> live `up` on a docker-healthy machine. The live substrate in this env is **Path B**.

Init hooks live in `deploy/init/` and run once on first boot of `primary`
(`/docker-entrypoint-initdb.d`). The hardened-role WALL SQL (issue #5, SPEC §3 layer
0–1) drops in there at a clearly-marked include point — see `deploy/init/00_README.sql`.

---

## Path B — `local-stack.sh` (live dev/CI substrate here)

Uses the keg-only Homebrew Postgres binaries (any supported major, 14–18; the
version-neutral `/opt/homebrew/opt/postgresql/bin` by default — override with the
unified `PG_BRAKES_PG_BIN=` the variable CI sets per-major, or the legacy
`PGBIN=`). Brings up isolated,
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
  (`$TMPDIR/pg_brakes-localstack/<root-digest>/<port>.pid`) that **survives**
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
- `PG_BRAKES_LOCALSTACK_DIR` is validated (non-empty, absolute, not `/` or `$HOME`,
  confined under the repo or a `*localstack*` dir) before any `rm -rf`.

---

## Path C — `up.sh` — the one-command runnable demo (CI/dev/test fixture)

> **A throwaway demo fixture, not the onboarding flow.** Real users BYO their own
> database (README quickstart); `up.sh` spins a *throwaway* cluster so you can watch
> the floor work without a database of your own.

`deploy/up.sh` is the launcher that makes pg_brakes **actually connectable to a real
Claude Code** against a throwaway cluster. It:

1. builds the binaries + the MCP shell (skip with `--no-build`);
2. brings up the hardened throwaway Postgres via `local-stack.sh up` (primary `54321`,
   meta `54323`, replica `54322`; **never** 5432), seeds a demo DB (`pgb_demo`) on the
   primary with the canonical `_meta` audit chain
   (`crates/audit/sql/10_audit_meta.sql`) and a single-int-PK `accounts` table, and
   `GRANT`s the read surface to the WALL role `pgb_agent`. NOTE: unlike Path A/B
   (which host `_meta` in the **separate** meta cluster on `54323`), this demo
   **co-locates** the `_meta` audit chain on the **primary** (`54321`/`pgb_demo`) so
   the whole stack is one cluster — the chain integrity guarantees are unchanged;
3. generates a **throwaway Ed25519 approver keypair** (the apply-time trust root; the
   seed stays out-of-band in the state dir, never enters the agent path);
4. launches the **real binaries**, health-checking each:
   - **`pgb-proxy`** on `127.0.0.1:6432` — the agent SCRAM endpoint **in front of**
     the primary; it originates the backend session as the WALL role `pgb_agent`.
     Dev-mode **TLS is OFF** (`PGB_PROXY_REQUIRE_TLS=false`) — stated explicitly; the
     proxy still does SCRAM-SHA-256 of the agent and enforces extended-protocol-only /
     read-only / byte-row budgets / `statement_timeout` / the audit chain. The
     **MCP read path is wired through this endpoint** (`PGB_PROXY_*`), not raw Postgres.
     The proxy is the audit-chain anchor **owner**.
   - **`pgb-applyd`** on a Unix socket — the grant-gated `guarded_apply_with_grant`
     write floor. It connects to the primary as the **constrained, DML-only applier
     role `pgb_applier`** (S5 #77) — not the superuser, not the read-only WALL role —
     so a bug in the apply path cannot DDL (defense-in-depth under the §4 floor). Audit
     chain **verify-only**.
   - **`pgb-warden`** — the live out-of-band watchdog, auditing to the **same** chain.
5. prints the **ready-to-paste `claude mcp add`** line with the exact env the server
   needs, plus how to do the operator approve step.

```sh
deploy/up.sh                 # build + launch + print the connect line
deploy/up.sh --no-build      # use prebuilt artifacts
deploy/down.sh               # stop the 3 daemons + local-stack; verify ports freed, :5432 untouched
```

The printed connect line is of the form (values filled in by the launcher):

```sh
claude mcp add pg-brakes \
  --env PGB_PROXY_HOST=127.0.0.1 --env PGB_PROXY_PORT=6432 \
  --env PGB_PROXY_DB=pgb_demo --env PGB_PROXY_USER=pgb_agent \
  --env PGB_PROXY_PASSWORD=pgb_agent_dev_pw --env PGB_PROXY_APP_NAME=pgb_proxy \
  --env PGB_PROXY_REQUIRE_TLS=false \
  --env PGB_ROLE=pgb_agent --env PGB_SESSION_ID=pgb-demo-session \
  --env PGB_APPLYD_SOCKET=<state>/applyd.sock \
  --env PGB_META_DSN='host=127.0.0.1 port=54321 dbname=pgb_demo user=pgb_audit_reader password=...' \
  -- <repo>/target/debug/pgb-mcp
```

The agent-facing `PGB_META_DSN` uses the **SELECT-only** `pgb_audit_reader` role (it can
read the audit tail for `get_audit` but holds no `INSERT`/`UPDATE`/`DELETE`), so no
audit-write credential ever enters the agent process. The INSERT-capable
`pgb_audit_writer` stays only with the proxy/applyd/warden (the path that legitimately
appends the chain).

**The read path genuinely goes through `pgb-proxy`.** Because the proxy is
extended-protocol-only (its statement-stacking defense), the MCP read client
(`PgProxyTransport`) uses the **extended protocol** (named prepared statements); a
plain simple-query is rejected. Two proofs the e2e test asserts: the proxy stamps
`application_name=pgb_proxy` on the backend session as `pgb_agent` (visible in
`pg_stat_activity`), and a read of the **non-granted** `secret_data` is `WALL_DENIED`
(SQLSTATE 42501) — the WALL role denying default-deny, which a raw superuser path
would not. Proven end-to-end by the env-gated Rust e2e `crates/mcp/tests/read_path_e2e.rs`
(`PG_BRAKES_IT=1`); the write path is proven by `crates/mcp/tests/write_path_e2e.rs`.

The operator **approve** hop (the signing key never enters the agent/MCP path) calls
the applyd socket `approve` RPC out-of-band; see the e2e test for the exact shape, and
`pgb-cli verify` (with `PGB_META_DSN` / `PGB_AUDIT_SIGNING_KEY` / `PGB_ANCHOR_PATH` from
the launcher's `connect.env`) proves the unified chain.

---

## Integration tests: the `PG_BRAKES_IT` gate

Integration tests are **env-gated** so plain test runs and the cargo CI job stay fast
and DB-independent. The convention for the whole project:

- `PG_BRAKES_IT` unset / `!= 1` → integration assertions are **skipped** (exit 0).
- `PG_BRAKES_IT=1` → they **run for real** against a live stack.

### Smoke harness — `deploy/smoke.sh`

Asserts: (1) primary reachable, (2) meta reachable + `_meta` queryable, (3) replica
reachable **and in recovery** (`pg_is_in_recovery() = t`), (4) primary reports a
**streaming** standby in `pg_stat_replication`, (5) a row written on the primary is
**replicated** to the standby within a bounded wait. Exits non-zero on any failure.

```sh
# RED — with the stack DOWN, the assertions fail (exit 1):
PG_BRAKES_IT=1 bash deploy/smoke.sh

# GREEN — bring the stack up, then the smoke passes (exit 0):
bash deploy/local-stack.sh up
PG_BRAKES_IT=1 bash deploy/smoke.sh

# (Gate proof) — with PG_BRAKES_IT unset, it SKIPS and exits 0:
bash deploy/smoke.sh
```

The smoke harness targets the **Path B** ports by default; override via
`PG_BRAKES_PRIMARY_PORT` / `PG_BRAKES_REPLICA_PORT` / `PG_BRAKES_META_PORT` (and the
bin dir with the unified `PG_BRAKES_PG_BIN` — the one variable CI sets, taking
precedence over the legacy `PGBIN`) to point it at any equivalent stack.

---

## The WALL — Layer 1 hardened role + Layer 0 network boundary (issue #5)

The deterministic floor's first layer (SPEC §3 layer 0–1, §4 "Network/roles — do FIRST",
§5 role-hardening matrix). It makes a hostile *raw* libpq client (no proxy, no MCP)
physically unable to read non-whitelisted data or to write/escalate — **even before the
proxy** — and refuses any agent connection that doesn't originate from the proxy host.

| Artifact | What it is |
|----------|------------|
| `sql/10_hardened_role.sql` | **Canonical, version-agnostic, BYO-applicable, AGENT-ROLE-ONLY** hardened-role migration (a real deployment applies THIS to its own database — it **NEVER mutates `PUBLIC`**, so it is **safe on an existing DB**; issue #108): creates `pgb_agent` (LOGIN, NOSUPERUSER, NOINHERIT, member-of-nothing, NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS), revokes all `pg_*` predefined roles **from the agent**, revokes EXECUTE on existing `public` functions + CREATE on `public` **from the agent**, sets a **best-effort** role-level `search_path` pin (see note below), and is **default-deny on ALL data** until the user grants their own allow-listed relations. It also creates the **constrained, DML-only applier role `pgb_applier`** (S5 #77 — the role `pgb-applyd` connects as): LOGIN, NOSUPERUSER, NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS, no CREATE on `public`, owns nothing → **cannot DDL**. Issue #103 split the demo seed OUT of this file; issue #108 split the strict `… FROM PUBLIC` lockdown OUT into `sql/21_public_lockdown.sql`. |
| `sql/21_public_lockdown.sql` | **OPT-IN strict `PUBLIC` lockdown** (issue #108; greenfield/dedicated-DB ONLY — ⚠️ it revokes `… FROM PUBLIC` and **can break an existing application**): the `REVOKE EXECUTE ON ALL FUNCTIONS … FROM PUBLIC` + `ALTER DEFAULT PRIVILEGES … FROM PUBLIC`, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, `REVOKE TEMPORARY … FROM PUBLIC`, and the `lo_* … FROM PUBLIC` revokes — the DB-level belt-and-suspenders on top of the agent-only default. The **fixture** (`local-stack.sh`, `up.sh`, `wall_matrix.sh`) applies it so the strict posture stays tested; a **BYO user applies it ONLY on a dedicated DB** (after a clone rehearsal — KNOWN_DANGERS.md D1). |
| `sql/20_demo_seed.sql` | **FIXTURE-ONLY** demo seed (CI/dev/test ONLY — a real BYO deployment does NOT apply it): the `allowed_read` / `secret_data` demo tables + the matching `pgb_agent` SELECT / `pgb_applier` DML grants, so the role-hardening matrix has a positive (granted) + negative (denied) read pair to assert against. Requires `10_hardened_role.sql` to have run first (it needs the roles). |
| `init/10_hardened_role.sql` · `init/20_demo_seed.sql` · `init/21_public_lockdown.sql` | Byte-for-byte **synced copies** of the three canonical SQL files, picked up by the docker entrypoint (`/docker-entrypoint-initdb.d`, alphabetical: `00_README.sql` → `10_` → `20_` → `21_`). The docker primary is itself a throwaway fixture, so it applies the lockdown too. `sql/check-init-sync.sh` guards all three against drift **and** asserts `10_hardened_role.sql` carries NO `… FROM PUBLIC` statement (issue #108). |
| `hba/pg_hba.agent-boundary.conf.template` | **Layer 0** `pg_hba` rules: agent role permitted **only from the proxy host's CIDR**; every other origin `reject`ed. |
| `hba/render-hba.sh` | Generator that substitutes the template's placeholders (`--proxy-cidr 10.0.0.5/32 …`). Append its output to `$PGDATA/pg_hba.conf` **above** any catch-all. |
| `hba/NETWORK-POLICY.md` | The network-policy companion (firewall / security-group / k8s NetworkPolicy half of the boundary) + how the local test models "proxy host vs. elsewhere". |
| `test/wall_matrix.sh` | The **role-hardening test matrix** (env-gated `PG_BRAKES_IT=1`): spins a dedicated throwaway PG cluster (any supported major, 14-18) on **54331** and runs **two phases** (issue #108). **PHASE 1** applies the agent-only `10_hardened_role.sql` **+ the fixture `20_demo_seed.sql`** + the boundary `pg_hba`, then proves the agent stays contained WITHOUT any `… FROM PUBLIC` revoke (attempting each denied action as the agent) AND that `PUBLIC` still HAS its `EXECUTE`/`TEMP`/`lo_*` defaults (the default did not globally revoke). **PHASE 2** applies the opt-in `21_public_lockdown.sql` and proves the `PUBLIC`-globally-revoked rows in their own context. (+ whitelisted SELECT succeeds, member-of-nothing, boundary refused/allowed.) |

Wired in: `local-stack.sh` applies `sql/10_hardened_role.sql` **and the opt-in
`sql/21_public_lockdown.sql`** against the (throwaway) primary on every `up` (idempotent);
`up.sh` applies the lockdown to its throwaway demo DB too; the docker compose picks up
`init/10_hardened_role.sql` → `init/21_public_lockdown.sql` on first boot (the docker primary
is itself a fixture). A real BYO user applies ONLY `sql/10_hardened_role.sql` (agent-only,
safe) and opts into the lockdown only on a dedicated DB.

```sh
# GREEN — every matrix row passes against the live backend (exit 0):
PG_BRAKES_IT=1 deploy/test/wall_matrix.sh

# RED — a freshly-created, UN-hardened role CAN do denied things; assertions fail (exit 1):
PG_BRAKES_IT=1 deploy/test/wall_matrix.sh --red

# Gate proof — with PG_BRAKES_IT unset it SKIPS (exit 0):
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
> authoritative search_path pin is the proxy (S1)**, which **is wired** to `SET search_path`
> per session on every brokered backend connection (`crates/proxy/src/session.rs`
> `inject_search_path`, applied in `connect_backend` alongside the `statement_timeout`
> injection; the default `pg_catalog, "public"` matches the migration). Every brokered session
> is a fresh origination the proxy re-pins, so no agent-chosen path survives into a new session
> — proven by `crates/proxy/tests/proxy_it.rs::proxy_pins_search_path_on_every_brokered_session`
> (env-gated IT against the live backend). The WALL's real guarantee does **not** depend on `search_path`: reads
> are via fully-qualified **explicit SELECT grants** only, and the agent has **no DML write grant**
> on any relation (default-deny on data) — therefore **no `search_path` the agent chooses can
> widen its read surface or reach data it lacks a grant on**. (This is the GRANT-based
> read/DML surface; it does NOT claim "no write/CREATE anywhere" — the agent-only default
> leaves `PUBLIC`'s `TEMP`/`lo_*`/(PG14) CREATE defaults at the DB level, contained by the
> proxy classifier through-proxy + the network boundary direct-to-DB, per the next note.) The
> matrix proves this **invariant** directly (section I): it shows the agent CAN mutate its path
> + `RESET ALL` (documented PG behavior) yet **STILL** cannot read non-whitelisted DATA or
> perform grant-gated DML.

> **`PUBLIC`-default write paths — agent-only default vs. opt-in lockdown (issue #108).**
> PostgreSQL grants two write paths to `PUBLIC` by default: `TEMPORARY` on the database
> (`CREATE TEMP TABLE … INSERT`) and EXECUTE on the in-DB large-object write built-ins
> (`lo_create`/`lowrite`/`lo_from_bytea`/`lo_put`/…). **Verified on real PG 14-18, NEITHER can
> be denied by an agent-scoped revoke** — they flow through the `PUBLIC` grant, and a per-role
> `REVOKE … FROM pgb_agent` cannot subtract a `PUBLIC` grant. So on the **agent-only default**
> they remain a **documented residual** (the agent CAN `CREATE TEMP TABLE` and write a large
> object at the DB level), contained NOT by a DB revoke but, split by path: **through the proxy**
> (the realistic agent path) by the **M2a fail-closed read classifier** (#114/#115 — `SELECT
> lo_create()`/`lowrite()`/any non-allowlisted or qualified function classifies `NotRead` →
> Blocked, and `CREATE TEMP TABLE` is DDL → `NotRead`), and **direct-to-DB** by the **§3 network
> boundary** —
> the matrix PHASE 1 asserts these as residuals (and asserts `PUBLIC` still HAS the defaults).
> The **opt-in `21_public_lockdown.sql`** revokes them `… FROM PUBLIC`; the matrix PHASE 2 then
> asserts `CREATE TEMP TABLE` and `lo_create`/`lowrite`/`lo_from_bytea`/`lo_put` are **DENIED**
> at the DB level. (Same for PG14's `CREATE`-on-`public` `PUBLIC` default; PG15+ already lacks
> it.) The server-file LO paths (`lo_import`/`lo_export`) remain `[NO-GRANT]`-gated as above.
> See `KNOWN_BYPASSES.md` (B-lo) and `docs/spec/SPEC.amendments.md` (A-M2).

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

---

## Audit anchor, KMS key separation & secret store (SPEC §3, §4, §10.9; issue #54)

S1 shipped the append-only, hash-chained `_meta` audit log (`crates/audit`:
`chain.rs`/`record.rs`/`sink.rs`/`pg.rs`) and the `REVOKE` that makes the audited
principal unable to write audit. S1's hash chain detects *within-chain* tampering — but
an attacker who **owns the audit table** can rewrite the *entire* chain consistently
(re-hash + re-link every record), and that rewritten chain verifies clean on its own.

**S4 closes that gap** with three seams in `crates/audit` (all clean-room; no pgDog code):

1. **External WORM/transparency anchor of the chain head** (`anchor.rs`). On an interval
   driven by `core::Clock` (monotonic, mockable — **no wall-clock in tests**), the current
   chain **head** (`record_hash` of the last record) is signed and published to an
   append-only/WORM sink with **independent retention**. To pass off a rewritten chain an
   attacker would need an anchor entry signing *their* head — they cannot mint a valid
   signature (no key) and cannot delete/replace the already-published honest entry
   (append-only). `verify_against_anchor()` flags the rewrite as `HeadMismatch`.
   - **Local stand-in (MVP):** `WormAnchor` — an in-memory, append-only log, optionally
     backed by an append-only **file** (`WormAnchor::open_file`) that survives restarts.
     It exposes **no** mutate/delete method, modelling object-lock.
   - **Production target (documented, not built here):** an **S3 bucket with Object Lock
     (compliance mode)** or a **transparency log** (append-only Merkle log), retention
     **independent of the DB operator**.

2. **KMS-backed signing key, separated from the DB operator** (`kms.rs`). The chain head is
   signed by a key modeled as held by a KMS — **never on the DB host**, and the audited
   (DB-operator) principal **cannot sign**. Key separation is enforced two ways:
   - **Type-level:** the signing capability (`LocalKms`) has **no public byte constructor,
     no `Default`, no `Serialize`/`Deserialize`** — it can only be obtained by loading the
     key from the secret store, and the wrapped key never serializes out.
   - **Runtime:** `LocalKms::for_principal(.., OPERATOR_PRINCIPAL)` is **rejected**
     (`OperatorPrincipalDenied`) — the operator principal can never obtain the signer.
   - **Dev impl:** HMAC-SHA256 over a domain-separated `(head, seq, ts)` input.
     **Production target:** an **asymmetric KMS** (AWS KMS / GCP KMS / Vault transit) whose
     private half never leaves the HSM; the DB host sees only the *signature*, and the
     *public* key verifies. The `Kms` trait is that seam — swapping a real KMS in does not
     touch the anchor logic.

3. **Secret store for DSNs + the audit signing key** (`secret.rs`), with **rotation**.
   - **Dev impl:** `LocalSecretStore` — in-memory; `Debug` **redacts** every value so a
     secret never lands in a log/panic. `put` is create-only; `rotate` replaces existing
     material (a re-derived capability immediately uses the new key).
   - **Rotation (documented):** rotate the audit signing key by `rotate()`-ing
     `audit/signing-key` (or bumping the KMS key **version** in production). Anchors carry
     the **`key_id`** they were signed under, so anchors published before a rotation stay
     verifiable against the matching key/version. DSNs rotate the same way; the proxy reads
     them at boot and the in-memory copy is zeroized after connecting (SPEC §4 "proxy
     memory-handling noted").
   - **Production target:** a cloud secret manager (Vault / AWS Secrets Manager / GCP
     Secret Manager) addressed by id; the audit signing key is never materialized as raw
     bytes (KMS performs the signature itself).

**Where the property is proven:** `crates/audit/tests/anchor.rs` —
`anchored_head_detects_full_chain_rewrite` (the headline: a fully-rewritten,
internally-consistent chain is caught by the anchored head; an honest chain verifies),
`operator_principal_cannot_obtain_the_signer` (runtime key separation),
`tampered_anchor_signature_is_rejected` (a head swapped into the WORM sink without a valid
signature is rejected), `anchoring_respects_the_injected_clock_interval` (clock-driven
cadence, no wall clock), and `worm_file_anchor_persists_and_reloads` (independent retention
across restart). All DB-free and deterministic; the `_meta` PgSink path stays env-gated
(`PG_BRAKES_IT=1`).

---

> Source of truth: `docs/spec/SPEC.md` (v0.8). Deviation log:
> `docs/spec/SPEC.amendments.md`. License: Apache-2.0.
