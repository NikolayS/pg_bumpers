#!/usr/bin/env node
/**
 * `pgb-mcp` — the deployable stdio MCP shell (SPEC §3, §4; issue #67).
 *
 * The single new entrypoint that makes the MCP server a REAL, connectable
 * server. It speaks MCP-flavoured **line-delimited JSON-RPC 2.0** over
 * stdin/stdout — `initialize` / `tools/list` / `tools/call` — and dispatches
 * `tools/call` onto the stateless `createServer(...)` toolset, which:
 *   - reads through the LIVE proxy (`PgProxyTransport` → 127.0.0.1:PGB_PROXY_LISTEN),
 *   - writes through the production `ApplydCore` → `pgb-applyd` over its Unix
 *     socket (the real grant-gated `guarded_apply` floor).
 *
 * Honesty (SPEC §3): this shell is COOPERATIVE, NOT a security boundary. It adds
 * no privilege; every read passes the proxy/WALL and every write passes
 * `pgb-applyd`'s deterministic floor. State lives in those boundaries, never here.
 *
 * Environment:
 *   - PGB_APPLYD_SOCKET   — the applyd Unix socket (write path).
 *   - PGB_PROXY_HOST/PORT — the proxy read endpoint (default 127.0.0.1:6432).
 *   - PGB_PROXY_DB/USER/PASSWORD — the proxied read connection.
 *   - PGB_ROLE            — the authenticated role (T0); also the apply binding role.
 *   - PGB_SESSION_ID      — the session/principal id (apply binding; default a uuid-ish).
 *
 * Transport: Node `readline` over stdin + `process.stdout.write`. NO new
 * dependencies (Node built-ins only) — keeps `license-check` green.
 */
import { createInterface } from "node:readline";

import { createServer, TOOL_NAMES, type McpServer } from "../server.js";
import { PgProxyTransport } from "../pgProxy.js";
import { ApplydCore } from "../applydCore.js";
import { isBlock } from "../blockContract.js";

/** A minimal MCP JSON-RPC request over stdio. */
interface McpRequest {
  jsonrpc: string;
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "pg-bumpers-mcp", version: "0.0.0" };

function env(key: string, fallback?: string): string {
  const v = process.env[key];
  if (v === undefined || v === "") {
    if (fallback !== undefined) return fallback;
    throw new Error(`${key} is required (no default)`);
  }
  return v;
}

/** Write one JSON-RPC response line to stdout. */
function reply(id: number | string | null | undefined, result: unknown): void {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result }) + "\n");
}

/** Write one JSON-RPC error line to stdout. */
function replyError(
  id: number | string | null | undefined,
  code: number,
  message: string,
): void {
  process.stdout.write(
    JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }) + "\n",
  );
}

/** The MCP tool descriptors (name + description) for `tools/list`. */
function toolList(server: McpServer): unknown {
  return {
    tools: server.listTools().map((t) => ({
      name: t.name,
      description: t.description,
      // A permissive schema: the toolset validates/relays args itself.
      inputSchema: { type: "object", additionalProperties: true },
    })),
  };
}

async function main(): Promise<void> {
  const role = env("PGB_ROLE", "pgb_agent");
  const sessionId = env("PGB_SESSION_ID", `mcp-${process.pid}-${Date.now()}`);
  const socketPath = env("PGB_APPLYD_SOCKET");

  // Reads go through the LIVE proxy (a real libpq client to the proxy endpoint).
  const transport = await PgProxyTransport.connect({
    host: env("PGB_PROXY_HOST", "127.0.0.1"),
    port: Number(env("PGB_PROXY_PORT", "6432")),
    database: env("PGB_PROXY_DB", "postgres"),
    user: env("PGB_PROXY_USER", role),
    password: process.env.PGB_PROXY_PASSWORD,
  });

  // Writes go through the production ApplydCore → pgb-applyd (the real floor).
  const core = new ApplydCore({ socketPath, role, sessionId });

  const server = createServer({ transport, core, role });

  const rl = createInterface({ input: process.stdin });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let req: McpRequest;
    try {
      req = JSON.parse(trimmed) as McpRequest;
    } catch {
      replyError(null, -32700, "parse error: invalid JSON line");
      continue;
    }
    await handle(req, server);
  }

  core.close();
  await transport.close().catch(() => undefined);
}

async function handle(req: McpRequest, server: McpServer): Promise<void> {
  switch (req.method) {
    case "initialize":
      reply(req.id, {
        protocolVersion: PROTOCOL_VERSION,
        serverInfo: SERVER_INFO,
        capabilities: { tools: {} },
      });
      return;
    case "notifications/initialized":
      // A notification (no id) — nothing to reply.
      return;
    case "tools/list":
      reply(req.id, toolList(server));
      return;
    case "tools/call": {
      const params = req.params ?? {};
      const name = String((params as { name?: unknown }).name ?? "");
      const args = ((params as { arguments?: Record<string, unknown> }).arguments ?? {}) as Record<
        string,
        unknown
      >;
      if (!TOOL_NAMES.includes(name as (typeof TOOL_NAMES)[number])) {
        replyError(req.id, -32601, `no such tool: ${name}`);
        return;
      }
      try {
        const result = await server.call(name, args);
        // MCP tools/call returns content blocks; we carry the structured result
        // as a single JSON text block plus a top-level isError flag for a block.
        reply(req.id, {
          content: [{ type: "text", text: JSON.stringify(result) }],
          isError: isBlock(result),
          structuredContent: result,
        });
      } catch (err) {
        replyError(req.id, -32000, err instanceof Error ? err.message : String(err));
      }
      return;
    }
    default:
      replyError(req.id, -32601, `method not found: ${req.method}`);
  }
}

main().catch((err) => {
  process.stderr.write(`pgb-mcp fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
