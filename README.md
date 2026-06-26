# pg_bumpers

[![CI](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml/badge.svg)](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-3ddc97)
![postgres](https://img.shields.io/badge/PostgreSQL-14--18-3ddc97)

**A self-hostable control plane that lets AI agents read and write your
_production_ Postgres — safely.** Your agent connects through a proxy and gets a
least-privilege role; every write is **bounded, reversible, and human-approved**;
runaway reads and sessions are **killed**; and every action lands on a
**tamper-evident audit chain** you can verify.

Point a coding agent (or a text-to-SQL bot, or an internal copilot) at a real
database — even in `--dangerously-skip-permissions` mode — and the floor below it
holds. A `DROP TABLE` gets **refused**. A `DELETE` with no `WHERE` gets
**bounded** and held for approval. Nobody hands the agent superuser.

---

## Why this exists

AI agents now touch production databases directly, often in YOLO modes. The
public failures are not hypothetical:

- The Replit agent **deleted a production database**.
- The official Anthropic Postgres MCP read-only mode was **bypassed by
  statement-stacking** (`COMMIT; DROP SCHEMA …` smuggled through a "read-only"
  path).

App-layer "please be careful" prompts don't stop this. pg_bumpers puts a
**deterministic safety floor** — native Postgres roles, byte/time budgets, and a
bounded-and-reversible write path — between the agent and your data. No language
model sits in that floor; it holds even if the agent is fully compromised.

## The honest guarantee (split by damage class)

We do **not** claim "impossible to break" or "tamper-proof." We claim three
precise, testable things:

- **Writes — 0 catastrophic data-loss false-negatives by construction.** Every
  applied write is **bounded + reversible**: rehearsed first, then pinned by three
  orthogonal guards — **bounded** by the human-approved absolute **`WriteCap`**
  (`max_rows` + `max_wal_bytes`, enforced inside the apply txn from the
  `pg_stat_xact_*` deltas + a WAL-byte measure) plus the `pg_stat_xact_*`
  reconciliation and a `statement_timeout`; **reversible** via the apply-time
  pre-image capture (`FOR UPDATE` + `RETURNING`) + row/column coverage guards (a
  write that can't be certifiably undone aborts); and **row-identity** foreclosed by
  the self-determined-predicate gate (the approved `WHERE` may reference only the
  immutable primary key + literals, so the approved statement itself pins which rows
  are touched). Structural / irreversible operations (`DROP`, `TRUNCATE`, DDL) are
  **refused outright** — they are not rehearsable, so they never run.
- **Reads — bounded disclosure, not zero.** Disclosure can't be un-happened, so
  the promise is a **per-role byte/row budget, then a hard cutoff/kill** — plus
  best-effort detection. Data you never granted the agent stays unreadable
  (default-deny); data you did grant is capped.
- **Audit — tamper-evident, not tamper-proof.** Every decision (including refused
  writes and denied reads) lands on a hash-chained `_meta` log whose head is
  externally anchored. A rewritten chain is **detected** by the anchored head.

The safety guarantee is the **deterministic floor**. An LLM risk-gate is planned
to *tighten* it further (block/hold/escalate, never loosen), but in this MVP that
gate is a stub that returns `Allow` — the floor is doing all the work.

## Get started — point pg_bumpers at YOUR existing PostgreSQL (14–18)

**The first-run path is "point pg_bumpers at your existing database."** You bring
your own production Postgres; pg_bumpers never asks you to spin one up. You declare
where your database lives in `policy.yaml`, apply the canonical role hardening to it,
verify with one command, and launch the daemons against your DSNs (SPEC §0.5).

> **No throwaway cluster required.** The docker-compose / `local-stack.sh` / `up.sh`
> stack below is a **CI/dev/test fixture only** — a deterministic throwaway for our
> own tests and the benchmark, never the onboarding flow. The real onboarding is the
> five BYO steps here.

### 1. Declare your DSN targets in `policy.yaml`

`policy.yaml` is **authoritative** for the connection *targets* — the host/port/
database/role of (a) your primary, (b) an optional read replica, and (c) the audit
`_meta` location. Credentials stay **out** of the file: in this version the password
comes from the **conventional env var** (`PGB_BACKEND_PASSWORD` for the primary/applyd,
`PGB_META_PASSWORD` for `_meta`, `PGB_DOCTOR_PASSWORD` for the doctor). A target is
*credential-less* (host/port/db/role + an optional `secret_ref`); `secret_ref` is a
**forward-compatibility placeholder** — this version does **not** resolve it from any
secret store, so the password must still come from the env var above. The
`PGB_BACKEND_*` / `PGB_PROXY_*` / `PGB_META_DSN` env vars are **overrides** layered on
top (precedence: env override → `policy.yaml` target → **fail-closed**; there is **no**
throwaway-cluster default). The target's host/db/role/`secret_ref` are validated
fail-closed on load (no whitespace / `=` / quote / backslash / control char — they would
inject extra libpq DSN keywords). See
[`crates/policy/policy.example.yaml`](crates/policy/policy.example.yaml):

```yaml
# policy.yaml — point at YOUR database (no literal passwords in this file)
primary:
  host: db.internal          # your existing primary
  port: 5432                 # your real port — pg_bumpers never touches a throwaway cluster
  database: app
  role: pgb_agent            # the hardened WALL role (step 2)
  secret_ref: "kms://pg-bumpers/primary-pw/v1"   # OPTIONAL forward-compat placeholder; NOT
                                                 # resolved yet — password comes from PGB_BACKEND_PASSWORD
replica:                     # OPTIONAL read replica (reads route here under §12)
  target: { host: replica.internal, port: 5432, database: app, role: pgb_agent }
audit:
  target:                    # the credential-less `_meta` DSN location (audit chain)
    host: db.internal
    port: 5432
    database: app_meta
    role: pgb_audit_writer
```

### 2. Apply the role hardening (+ your own GRANTs) to your database

Apply the **canonical, version-agnostic** role hardening to your database — it
creates and hardens the read WALL role `pgb_agent` (NOSUPERUSER · NOINHERIT ·
member-of-nothing · no write grant anywhere) and the DML-only apply role
`pgb_applier`, and revokes every inherited/default privilege:

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

> `deploy/sql/10_hardened_role.sql` is the **canonical hardening** a BYO user
> applies — it no longer seeds any demo schema. The demo tables live in the
> fixture-only `deploy/sql/20_demo_seed.sql` (CI/dev/test only; you do **not** apply
> it). Also set up the `_meta` audit chain in your audit DB
> ([`crates/audit/sql/10_audit_meta.sql`](crates/audit/sql/10_audit_meta.sql)) and
> restrict the agent role to the proxy host in `pg_hba.conf` (see
> [`deploy/hba/`](deploy/hba/)).

### 3. Verify with `pgb-cli doctor` (fail-closed preflight)

Before you point an agent at the database, run the **fail-closed preflight**. The doctor
connects with a **catalog-readable role** — set `PGB_BACKEND_ROLE` to it (e.g. `postgres`
or an admin/monitoring role; it must read `pg_roles` + the grant catalogs, which the
member-of-nothing `pgb_agent` cannot) — and verifies the primary (+ optional replica +
`_meta`) are reachable, that `pgb_agent` is WALL-hardened, that `pgb_applier` is DML-only,
the pg_hba origin boundary (best-effort), and that the `_meta` audit chain is installed
and verifying:

```sh
PGB_POLICY_PATH=policy.yaml \
PGB_BACKEND_ROLE=postgres   \
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

It **exits non-zero on any failure** (a superuser agent, a missing role, a stray
write grant, an unreachable target) — fail-closed: do not connect an agent until
every check passes. (`PGB_BACKEND_ROLE` overrides only the role the doctor *connects*
as; it always CHECKS `pgb_agent` / `pgb_applier` by their conventional names.)

### 4. Launch the daemons against your DSNs

Each daemon resolves its connection target from your `policy.yaml` (env override
allowed); none of them defaults to a throwaway cluster. **The password comes from the
conventional env var, not `secret_ref`** (this version does not resolve `secret_ref` —
the primary/applyd password from `PGB_BACKEND_PASSWORD`, the `_meta` password from
`PGB_META_PASSWORD`), sourced from your secret store / env:

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

> Production posture: enable **TLS** on the proxy (`PGB_PROXY_TLS_CERT` /
> `PGB_PROXY_TLS_KEY`; required whenever TLS material is configured — no silent
> cleartext downgrade) and source every secret from your secret store, not literals.

### 5. Connect your agent (the `claude mcp add` form, against your DSNs)

The agent-facing MCP server is the native Rust **`pgb-mcp`** (crate `crates/mcp`).
Point it at the **proxy** (not the raw database) and the `_meta` reader:

```sh
claude mcp add pg-bumpers \
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

Claude Code now has the nine pg_bumpers tools, all flowing through the
deterministic floor: a `DROP TABLE` is **refused**, a no-`WHERE` `DELETE` is
**bounded + held for approval**, runaway reads are **killed**, and every action
lands on the tamper-evident `_meta` chain you can `pgb-cli verify`.

---

## Local demo stack (CI/dev/test fixture only — NOT the onboarding flow)

> **This is a throwaway fixture, not how you onboard.** `deploy/up.sh` spins a
> *throwaway* Postgres on dedicated high ports (it never touches `5432`), seeds a
> demo schema, and is the deterministic substrate for our own integration tests and
> the benchmark. Real users follow the **BYO** path above; this section just lets you
> watch the floor work end-to-end without a database of your own.

This walkthrough is the real flow, captured from an actual run on a throwaway
PostgreSQL (any supported major, 14–18). It launches the full stack, prints a
`claude mcp add` line you paste into Claude Code, and lets you watch a `DROP TABLE`
get refused and a bounded write get approved.

> **Dev-quickstart honesty.** This local stack runs with **TLS off**
> (`PGB_PROXY_REQUIRE_TLS=false`) — SCRAM-SHA-256 auth is still enforced. It uses
> throwaway Postgres clusters on **dedicated high ports** (it never touches
> `5432`) and tears them down cleanly. The agent-facing MCP server is the native
> Rust **`pgb-mcp`** (crate `crates/mcp`) — the one and only deployable MCP server
> ([EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83) is complete; the
> old TS `mcp/server` is removed).

### 1. Prerequisites

- **Rust 1.90** (pinned by `rust-toolchain.toml`)
- **PostgreSQL 14–18** (any supported major — the proxy + WALL are
  version-agnostic). On macOS, a Homebrew keg works; the launcher resolves
  `initdb` / `pg_ctl` from the version-neutral `postgresql` keg by default, or
  set `PG_BUMPERS_PG_BIN` to a specific keg's `bin`:
  ```sh
  brew install postgresql          # latest stable, or `postgresql@17` etc.
  export PATH="/opt/homebrew/opt/postgresql/bin:$PATH"
  # To pin a specific major for the launcher/ITs:
  #   export PG_BUMPERS_PG_BIN=/opt/homebrew/opt/postgresql@17/bin
  ```
- **[Claude Code](https://claude.com/claude-code)** (the agent you'll connect)

### 2. Clone and build

```sh
git clone https://github.com/NikolayS/pg_bumpers.git
cd pg_bumpers
```

`deploy/up.sh` builds the binaries for you on first run; you can also build them
up front:

```sh
cargo build --locked -p pgb-proxy -p pgb-applyd -p pgb-warden -p pgb-cli -p pgb-mcp
```

### 3. Launch the stack

```sh
bash deploy/up.sh          # add --no-build if you built in step 2
```

It brings up a hardened throwaway Postgres, launches the proxy + write-path daemon +
warden, and prints a ready-to-paste connect line. Real output:

```text
================================================================================
 pg_bumpers stack is UP. Reads route through pgb-proxy (NOT raw Postgres). :5432 untouched.
================================================================================

  pgb-proxy  : 127.0.0.1:6432   (agent SCRAM endpoint, TLS OFF dev-mode, WALL role pgb_agent)
  pgb-applyd : /tmp/pg_bumpers-up/applyd.sock        (write-path Unix socket)
  pgb-warden : live
  Postgres   : primary 54321, meta 54323  (throwaway; NEVER 5432)
  demo DB    : pgb_demo  (accounts read surface + the _meta audit chain)

  Connect a REAL Claude Code to this stack — paste this single line:

  claude mcp add pg-bumpers \
    --env PGB_PROXY_HOST=127.0.0.1 \
    --env PGB_PROXY_PORT=6432 \
    --env PGB_PROXY_DB=pgb_demo \
    --env PGB_PROXY_USER=pgb_agent \
    --env PGB_PROXY_PASSWORD=pgb_agent_dev_pw \
    --env PGB_PROXY_APP_NAME=pgb_proxy \
    --env PGB_PROXY_REQUIRE_TLS=false \
    --env PGB_ROLE=pgb_agent \
    --env PGB_SESSION_ID=pgb-demo-session \
    --env PGB_APPLYD_SOCKET=/tmp/pg_bumpers-up/applyd.sock \
    --env PGB_META_DSN='host=127.0.0.1 port=54321 dbname=pgb_demo user=pgb_audit_writer password=...' \
    -- <repo>/target/debug/pgb-mcp
```

**Paste the exact `claude mcp add` line `up.sh` printed** into your shell (the
paths are filled in for your machine). Claude Code now has nine pg_bumpers tools.

### 4. Drive it from Claude Code

Each step below is "ask your agent X → you'll see Y." The `Y` outputs are
verbatim from a real run against the stack above.

**Ask it to read a table → it works, bounded, through the proxy.**

> "Query `SELECT id, owner, balance FROM public.accounts ORDER BY id`."

```text
status=ok rowCount=8
[{"id":1,"owner":"owner-1","balance":"1000"}, … {"id":8,"owner":"owner-8","balance":"8000"}]
```

The read genuinely traverses `pgb-proxy` as the least-privilege WALL role
`pgb_agent` — not a raw superuser connection.

**Ask it to read something it wasn't granted → default-deny.**

> "Query `SELECT secret FROM public.secret_data`."

```text
status=blocked code=WALL_DENIED
reason=the proxy/WALL denied this read (least-privilege default-deny):
       permission denied for table secret_data (42501)
```

`secret_data` was never granted to the agent's role, so the WALL refuses it. A
raw superuser would have leaked the row; the agent's role can't.

**Ask it to `DROP TABLE` → REFUSED (never executed).**

> "Propose a write: `DROP TABLE public.accounts`."

```text
status=blocked code=NOT_REHEARSABLE
reason=statement kind `DROP` is not a certified rehearsable write
retryable=false
```

`TRUNCATE` is refused the same way. Structural/irreversible ops aren't on the
certified, rehearsable allow-list, so they are neutralized by refusal — the table
keeps all 8 rows.

**Ask it for a bounded write → measured, then held for approval.**

> "Propose `UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0`, then dry-run
> it, then apply it."

```text
propose_write  → status=ok proposal_id=p-9eb291bce874a5af
dry_run        → status=ok total_rows=4 reversible=true     (rehearsed; nothing committed)
apply_write    → status=blocked code=APPROVAL_REQUIRED retryable=true
```

The dry-run rehearses the write, reports the **blast radius** (4 rows, reversible)
without committing anything, and the apply is **held** for a human — the agent
can't self-approve.

**Approve it (operator, out-of-band) → committed + reversible.**

The signing key never enters the agent's path. As the operator, mint a grant on
the write-path socket, then the agent's retry commits:

```text
operator approve → ok           (grant signed out-of-band)
apply_write      → status=ok applied=true reversible=true
```

Only the 4 even-id rows were zeroed; the 4 odd-id rows are untouched — the write
was bounded exactly to its measured radius. (The applyd socket `approve` RPC is
shown in `deploy/README.md`; a `pgb-cli`/operator UI hop is fast-follow.)

**Verify the audit chain → it checks out.**

```sh
PGB_META_DSN='host=127.0.0.1 port=54321 dbname=pgb_demo user=pgb_audit_writer password=pgb_audit_writer_dev_pw' \
PGB_AUDIT_SIGNING_KEY=pgb-audit-signing-key-dev-000001 \
PGB_ANCHOR_PATH=/tmp/pg_bumpers-up/verify.anchor.worm \
  target/debug/pgb-cli verify
```

```text
pgb-cli verify: the shared `_meta` chain VERIFIES and the durable
anchored head MATCHES the chain head.
  decisions by reason_code:
    NOT_REHEARSABLE   x2   (the DROP + TRUNCATE refusals)
    apply_committed   x1   (the approved bounded write)
    approval_required x1
    grant_signed      x1
    ...
```

Every refusal and every approval is on the chain, and the head matches its
external anchor.

### 5. Tear it down

```sh
bash deploy/down.sh
```

Stops the three daemons, drops the throwaway clusters, frees the high ports, and
verifies `:5432` was never touched.

> The same end-to-end flow runs as env-gated Rust integration tests against a
> throwaway Postgres:
> `PG_BUMPERS_IT=1 cargo test -p pgb-mcp --test write_path_e2e --test read_path_e2e`
> drives the shipped `pgb-mcp` handler through the write path (via `pgb-applyd`)
> and the read path (via `pgb-proxy`) — see
> [`deploy/up.transcript.txt`](deploy/up.transcript.txt) for a captured `up.sh` run.

## How it works

pg_bumpers is four layers plus a mandatory network boundary. The first two are
**native Postgres** and hold even against a hostile raw client; the proxy and
write path add enforcement and the agent-facing API.

| Layer | What it does |
|---|---|
| **Network boundary** | `pg_hba` permits the agent role **only from the proxy host**; every other origin is rejected. |
| **WALL — native role** | `pgb_agent` is NOSUPERUSER · NOINHERIT · member-of-nothing · no write grant anywhere · SELECT-whitelist only. A raw client *physically can't* write or read denied data. |
| **Proxy + warden** | `pgb-proxy` is the agent's only endpoint: extended-protocol-only (kills statement-stacking), read-only gate, byte/row mid-stream cutoff, `statement_timeout`, hash-chained audit. `pgb-warden` is an out-of-band watchdog that kills runaway agent sessions. |
| **Write-safety + MCP** | `pgb-applyd` owns the `propose → dry_run → approve → apply` lifecycle behind an owner-only socket; the MCP server is the agent-facing tool surface (cooperative, *not* a security boundary). |

Full write-up: [`docs/architecture.md`](docs/architecture.md). Product spec:
[`docs/spec/SPEC.md`](docs/spec/SPEC.md) (v0.8).

## Status & scope

This is an **MVP**. Supported PostgreSQL: **14, 15, 16, 17, 18** — the wire proxy
and the native-role WALL are version-agnostic, and the CI matrix runs the full
safety integration suite against every major in that range (spec v0.8.1 §0.5).

- **Works now:** the **BYO-first onboarding** (`policy.yaml` DSN targets + the
  canonical role hardening + the `pgb-cli doctor` fail-closed preflight); the
  native-role WALL + proxy-only network path; the enforcing proxy (read-only,
  byte/row cutoff, `statement_timeout`, anti-statement-stacking, audit);
  clone/transaction dry-run blast-radius preview; guarded apply with typed-inverse
  and operator approval; the live warden; the tamper-evident, externally-anchored
  audit chain; and the MCP tool surface — all exercised end-to-end (BYO above; the
  demo fixture below).
- **Deferred / fast-follow:** the LLM risk-gate (the `RiskEngine` is a stub
  returning `Allow`); the native Rust `pgb-mcp` ([EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83));
  DDL / multi-statement transactions / multi-DB; an operator approval UI; and a
  managed clone provider for zero-impact rehearsal.

Known limitations and intentional deviations are documented honestly:
[`KNOWN_BYPASSES.md`](KNOWN_BYPASSES.md) and
[`docs/spec/SPEC.amendments.md`](docs/spec/SPEC.amendments.md).

## Contributing

Building on pg_bumpers? The engineering process — the red/green TDD discipline,
the CI gates, the `PG_BUMPERS_IT` integration convention, the **CI/dev/test fixture
stack** (`local-stack.sh` / `wall_matrix.sh` / `smoke.sh` — a throwaway substrate,
not the onboarding flow), test-port discipline, and the PR lifecycle — lives in
**[`docs/development.md`](docs/development.md)**. The deploy stack (the fixture
`docker-compose.yml` / `local-stack.sh` / `up.sh`, and the canonical WALL SQL/hba a
BYO user applies) is documented in [`deploy/README.md`](deploy/README.md).

## License

[Apache-2.0](LICENSE). Dependencies are Apache / MIT / BSD / ISC only — GPL/AGPL
are banned and enforced by `cargo deny`, the single license gate for the whole
Rust-only workspace (the MCP server is a workspace member, so its deps are covered
too). This is a **clean-room** implementation.
