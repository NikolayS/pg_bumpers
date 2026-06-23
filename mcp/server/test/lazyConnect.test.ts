/**
 * Lazy-connect contract for the deployable stdio MCP shell (`pgb-mcp`).
 *
 * Regression guard for the silent "Failed to connect" Claude Code showed when
 * the proxy/backend was down: the shell USED to connect the proxy eagerly BEFORE
 * the JSON-RPC read loop, so a down backend killed the process with zero MCP
 * bytes and the `initialize` handshake never completed.
 *
 * This test drives the BUILT shell (`dist/bin/mcpStdio.js`) as a REAL MCP client
 * over stdio with NO backend up at all — a bogus proxy port AND a bogus applyd
 * socket — and asserts:
 *   1. `initialize` STILL succeeds (the handshake completes regardless of backend
 *      state — this is what lets Claude Code connect);
 *   2. `tools/list` STILL returns the full toolset;
 *   3. a `query` (which forces the first lazy proxy dial) returns a RECOVERABLE
 *      block (PROXY_UNAVAILABLE, retryable) — NOT a crash, NOT a process death.
 *
 * It runs in plain `pnpm test` (no PG_BUMPERS_IT gate) because it deliberately
 * needs NOTHING listening; the bogus endpoints are the point.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));
const MCP_BIN = join(HERE, "../dist/bin/mcpStdio.js");

// A high port nothing is listening on (the lazy proxy dial must FAIL here), and a
// socket path that does not exist (the applyd dial would fail too). NEVER 5432.
const DEAD_PROXY_PORT = 59999;
const DEAD_SOCKET = "/tmp/pgb-nonexistent-applyd-socket.sock";

let mcp: ChildProcess | undefined;
let rpcId = 1;
let mcpStderr = "";
const replies = new Map<number, (v: unknown) => void>();

function call(method: string, params?: Record<string, unknown>): Promise<any> {
  const id = rpcId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      replies.delete(id);
      reject(new Error(`mcp ${method} timed out\nstderr:\n${mcpStderr}`));
    }, 10_000);
    replies.set(id, (v) => {
      clearTimeout(timer);
      resolve(v);
    });
    mcp!.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

async function toolCall(name: string, args: Record<string, unknown>): Promise<any> {
  const resp = await call("tools/call", { name, arguments: args });
  return resp.result?.structuredContent;
}

beforeAll(async () => {
  // The shell must be built; this test asserts the SHIPPED binary's behavior.
  if (!existsSync(MCP_BIN)) {
    spawnSync("pnpm", ["run", "build"], { cwd: join(HERE, ".."), stdio: "ignore" });
  }
  if (!existsSync(MCP_BIN)) throw new Error(`pgb-mcp not built at ${MCP_BIN}; run \`pnpm run build\``);

  mcp = spawn(process.execPath, [MCP_BIN], {
    env: {
      ...process.env,
      // Point every backend at something that is NOT up.
      PGB_APPLYD_SOCKET: DEAD_SOCKET,
      PGB_PROXY_HOST: "127.0.0.1",
      PGB_PROXY_PORT: String(DEAD_PROXY_PORT),
      PGB_PROXY_DB: "postgres",
      PGB_PROXY_USER: "pgb_agent",
      PGB_ROLE: "pgb_agent",
      PGB_SESSION_ID: "lazy-connect-test",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  mcp.stderr!.on("data", (d) => (mcpStderr += d.toString()));
  const rl = createInterface({ input: mcp.stdout! });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg: any;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      return;
    }
    const cb = replies.get(msg.id);
    if (cb) {
      replies.delete(msg.id);
      cb(msg);
    }
  });
}, 30_000);

afterAll(() => {
  if (mcp) mcp.kill();
});

describe("pgb-mcp lazy-connect (no backend up)", () => {
  it("initialize succeeds even with the proxy + applyd both DOWN", async () => {
    const init = await call("initialize", {});
    expect(init.result.serverInfo.name).toBe("pg-bumpers-mcp");
    expect(init.result.protocolVersion).toBeTruthy();
  });

  it("tools/list returns the full toolset with no backend up", async () => {
    const resp = await call("tools/list", {});
    const names = (resp.result.tools as { name: string }[]).map((t) => t.name);
    // The 9 cooperative tools the shell exposes.
    expect(names).toContain("query");
    expect(names).toContain("propose_write");
    expect(names).toContain("apply_write");
    expect(names.length).toBeGreaterThanOrEqual(9);
  });

  it("a query against the DOWN proxy returns a RECOVERABLE block, not a crash", async () => {
    const res = await toolCall("query", { sql: "SELECT 1" });
    expect(res, JSON.stringify(res)).toBeTruthy();
    expect(res.status).toBe("blocked");
    expect(res.code).toBe("PROXY_UNAVAILABLE");
    expect(res.retryable).toBe(true);
    // The process is still alive (it answered) — no silent death.
    expect(mcp!.exitCode).toBeNull();
  });
});
