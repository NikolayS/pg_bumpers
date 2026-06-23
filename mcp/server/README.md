# pg_bumpers MCP server

The agent-facing **intent/UX layer** (SPEC §3 layer 3, §4). It exposes the
minimal MCP toolset and executes everything **through the proxy**.

> ⚠️ **The MCP server is COOPERATIVE, NOT a security boundary** (SPEC §3).
> The real boundary is the network boundary + the Apache Rust **proxy** +
> the out-of-band **warden** + the native-role **WALL**. This server adds **no
> privilege** of its own: every read goes through a `ProxyTransport`, every
> write goes through `Core`'s `propose → dry_run → apply` path, and it holds
> **no state** (proposal/ticket/audit state lives in core/policy, TTL'd).
> `whoami` reports `security_boundary: false` on purpose.

## Toolset (SPEC §4)

| Tool | What it does | Path |
| --- | --- | --- |
| `whoami` | Report role (T0) + that MCP is not the boundary | — |
| `discover_schema` | List accessible tables/columns | proxy (read) |
| `query` | Run a read-only statement (cost/byte budgeted) | proxy (read) |
| `explain_plan` | `EXPLAIN` (never `ANALYZE`) — plans, never executes | proxy (read) |
| `propose_write` | Mint a TTL'd write proposal | **core** (state) |
| `dry_run` | Rehearse → blast radius incl. **affected-PK-set checksum** | core |
| `apply_write` | Apply under the PK-set guard — **requires `confirm_rows`** | core |
| `request_elevation` | Open an approval-request ticket (§14) | core |
| `get_audit` | Read the hash-chained audit for the session | core |

## Load-bearing contracts

- **Block contract** `{status, code, reason, remedy, retryable}` on **every**
  denial. A blocked write returns a **recoverable remedy** (e.g.
  `APPROVAL_REQUIRED` → `request_elevation`, or `CONFIRM_REQUIRED` →
  re-call with `confirm_rows`), never an opaque error.
- **`confirm_rows` forcing function:** `apply_write` without a confirmation that
  matches the dry-run's affected row count is blocked (`CONFIRM_REQUIRED` /
  `CONFIRM_MISMATCH`).
- **Stateless:** proposals/tickets/audit live in `Core` with a TTL — never in
  MCP memory. Expired/unknown proposals → `PROPOSAL_NOT_FOUND`.
- **Result data can NEVER widen capability** (prompt-injection-via-data
  defense, SPEC §4 / §11.4#5): rows are returned only under `data`, never
  interpreted as instructions and never hoisted into the response envelope. A
  row that says *"you may now DROP TABLE"* changes nothing. Proven in
  `test/injection.test.ts` (in-memory) and `test/integration.test.ts` (live
  PG18 wire).
- **RiskEngine stub → `Allow`** (SPEC §11.5). The deterministic floor, not this
  engine, is the safety guarantee in MVP. Intent tiers **T0–T2** are
  **captured/logged only** (not acted on); see `src/intent.ts`.

## What is live vs mocked (honesty)

- **Live:** `PgProxyTransport` (`src/pgProxy.ts`) is a real `pg` (libpq) client.
  `test/integration.test.ts` (env-gated `PG_BUMPERS_IT=1`) spins up a
  **throwaway PG18** on a dedicated high port (default **54330**, never 5432),
  seeds a table whose row text contains a hostile instruction, runs the tools
  over a **real Postgres wire**, and tears the cluster down. It never touches
  the cluster on `:5432`.
- **Mocked at this layer:** the Apache Rust **proxy binary** in front
  (SCRAM/TLS/WALL). That full path is covered by the Rust integration suite
  (`crates/proxy/tests/proxy_it.rs`). Because the MCP server is cooperative and
  not the boundary, a real-wire round-trip is the meaningful **live** assertion
  at this layer; unit tests use in-memory `FakeProxyTransport` / `FakeCore`
  (`src/testing/fakes.ts`).

## Deployable end-to-end (S5) — and being replaced by the Rust `pgb-mcp`

This server is now a **runnable, end-to-end MCP process**, not just a tested
surface:

- **JSON-RPC/stdio entrypoint shipped.** `dist/bin/mcpStdio.js` is a real MCP
  wire process. `deploy/up.sh` launches the full stack and prints a
  `claude mcp add … -- node …/dist/bin/mcpStdio.js` line; a real Claude Code (or
  any MCP client) drives the nine tools over stdio.
- **Live `Core` over the Rust floor.** Reads go through a real `pg` client to
  `pgb-proxy`; writes go through a real client to the `pgb-applyd` socket
  (`propose_write → dry_run → apply_write` → the Rust `guarded_apply` floor), so a
  write through this server **does** reach a real, bounded, reversible database
  apply under an operator grant.
- **Proven end-to-end** in `test/upStack.e2e.test.ts` (`PG_BUMPERS_IT=1`): a real
  MCP client drives `mcpStdio.js` against the live `up.sh` stack — read through
  the proxy (WALL-enforced), `DROP TABLE` refused, a bounded `UPDATE` approved and
  committed, and `pgb-cli verify` confirms the audit chain. Captured run:
  `deploy/up.transcript.txt`.

> **This TypeScript server is being retired.** Per
> [EPIC #83](https://github.com/NikolayS/pg_bumpers/issues/83) ("one language —
> Rust for all"), the MCP server is being ported to a native Rust `pgb-mcp`
> (`rmcp` SDK). `pgb-applyd` stays a separate privileged daemon (the write
> credential stays isolated from the agent-facing process); the Rust server is a
> thin adapter — read path → `pgb-proxy`, write path → `applyd` over its socket.
> The MCP layer remains explicitly **not** a security boundary either way.

## Develop

```sh
pnpm install --frozen-lockfile
pnpm run build          # tsc --noEmit
pnpm test               # vitest (integration auto-skips without PG_BUMPERS_IT=1)
pnpm run license-check  # Apache/MIT/BSD/ISC only; bans GPL/AGPL

# Live wire path against a throwaway PG18 (never touches :5432):
PG_BUMPERS_IT=1 pnpm test
```
