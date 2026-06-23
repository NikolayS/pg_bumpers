# pg_bumpers

[![CI](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml/badge.svg)](https://github.com/NikolayS/pg_bumpers/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-3ddc97)
![status](https://img.shields.io/badge/status-MVP%20·%20runnable%20on%20PG18-3ddc97)

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
  applied write is **bounded + reversible**: rehearsed first, guarded on the
  affected **primary-key set** (catches row-identity drift, not just row count),
  fenced by a restore point, and undoable via a captured typed-inverse.
  Structural / irreversible operations (`DROP`, `TRUNCATE`, DDL) are **refused
  outright** — they are not rehearsable, so they never run.
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

## Try it in ~5 minutes

This walkthrough is the real flow, captured from an actual run on a throwaway
PostgreSQL 18. It launches the full stack, prints a `claude mcp add` line you
paste into Claude Code, and lets you watch a `DROP TABLE` get refused and a
bounded write get approved.

> **Dev-quickstart honesty.** This local stack runs with **TLS off**
> (`PGB_PROXY_REQUIRE_TLS=false`) — SCRAM-SHA-256 auth is still enforced. It uses
> throwaway Postgres clusters on **dedicated high ports** (it never touches
> `5432`) and tears them down cleanly. The agent-facing MCP server is the native
> Rust **`pgb-mcp`** (crate `crates/mcp`) — the one and only deployable MCP server
> ([EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83) is complete; the
> old TS `mcp/server` is removed).

### 1. Prerequisites

- **Rust 1.90** (pinned by `rust-toolchain.toml`)
- **PostgreSQL 18** — on macOS, the Homebrew keg `postgresql@18` (the launcher
  uses `initdb` / `pg_ctl` from `/opt/homebrew/opt/postgresql@18/bin`):
  ```sh
  brew install postgresql@18
  export PATH="/opt/homebrew/opt/postgresql@18/bin:$PATH"
  ```
- **Node 22** (only used by `deploy/up.sh` to generate a throwaway Ed25519
  approver keypair for the demo; the MCP server itself is pure Rust)
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

It brings up a hardened throwaway PG18, launches the proxy + write-path daemon +
warden, and prints a ready-to-paste connect line. Real output:

```text
================================================================================
 pg_bumpers stack is UP. Reads route through pgb-proxy (NOT raw PG18). :5432 untouched.
================================================================================

  pgb-proxy  : 127.0.0.1:6432   (agent SCRAM endpoint, TLS OFF dev-mode, WALL role pgb_agent)
  pgb-applyd : /tmp/pg_bumpers-up/applyd.sock        (write-path Unix socket)
  pgb-warden : live
  PG18       : primary 54321, meta 54323  (throwaway; NEVER 5432)
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
> throwaway PG18:
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

This is an **MVP**, runnable today on PostgreSQL 18.

- **Works now:** the native-role WALL + proxy-only network path; the enforcing
  proxy (read-only, byte/row cutoff, `statement_timeout`, anti-statement-stacking,
  audit); clone/transaction dry-run blast-radius preview; guarded apply with
  typed-inverse and operator approval; the live warden; the tamper-evident,
  externally-anchored audit chain; and the MCP tool surface — all exercised by the
  end-to-end flow above.
- **Deferred / fast-follow:** the LLM risk-gate (the `RiskEngine` is a stub
  returning `Allow`); the native Rust `pgb-mcp` ([EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83));
  DDL / multi-statement transactions / multi-DB; an operator approval UI; and a
  managed clone provider for zero-impact rehearsal.

Known limitations and intentional deviations are documented honestly:
[`KNOWN_BYPASSES.md`](KNOWN_BYPASSES.md) and
[`docs/spec/SPEC.amendments.md`](docs/spec/SPEC.amendments.md).

## Contributing

Building on pg_bumpers? The engineering process — the red/green TDD discipline,
the CI gates, the `PG_BUMPERS_IT` integration convention, the local test stack
(`local-stack.sh` / `wall_matrix.sh` / `smoke.sh`), test-port discipline, and the
PR lifecycle — lives in **[`docs/development.md`](docs/development.md)**. The deploy
stack (the shipped `docker-compose.yml`, `local-stack.sh`, the `up.sh` runnable
demo, and the WALL SQL/hba) is documented in [`deploy/README.md`](deploy/README.md).

## License

[Apache-2.0](LICENSE). Dependencies are Apache / MIT / BSD / ISC only — GPL/AGPL
are banned and enforced by `cargo deny` (Rust) and a `license-check` script (TS).
This is a **clean-room** implementation.
