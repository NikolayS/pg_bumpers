/**
 * END-TO-END proof of the RUNNABLE stack: `deploy/up.sh` launches the REAL
 * pgb-proxy + pgb-applyd + pgb-warden, and a REAL MCP client drives the shipped
 * `mcpStdio.js` against it — with the READ PATH GENUINELY THROUGH pgb-proxy (NOT
 * raw PG18). This is the honesty bar the founder set: the marquee/applyd ITs point
 * reads straight at PG18; THIS test routes them through the proxy binary and
 * proves it.
 *
 * Flow (env-gated PG_BUMPERS_IT=1; NEVER touches :5432):
 *   1. run `deploy/up.sh --no-build` (binaries/dist built by the harness first);
 *   2. read the printed connect env from $PGB_UP_STATE_DIR/connect.env;
 *   3. spawn the SHIPPED mcpStdio.js with EXACTLY that env (PGB_PROXY_* → the
 *      proxy's agent endpoint), and drive it as a real MCP client over stdio:
 *        - initialize + tools/list (9 tools);
 *        - query SELECT on accounts → rows, bounded, AND it genuinely traversed
 *          pgb-proxy (asserted two ways: the proxy STAMPS application_name
 *          'pgb_proxy' on the backend session — visible in pg_stat_activity — and
 *          the proxy enforces the WALL: a SELECT on the non-granted secret_data is
 *          REFUSED by the WALL role the proxy connects as, which a raw-PG18
 *          superuser path would NOT refuse);
 *        - propose_write DROP TABLE / TRUNCATE → REFUSED (NOT_REHEARSABLE);
 *        - a no-WHERE-shaped UPDATE → bounded; apply without a grant →
 *          APPROVAL_REQUIRED; operator approve (signing key out-of-band) →
 *          COMMITTED bounded + reversible;
 *        - get_audit returns the session tail; pgb-cli verify → the chain verifies;
 *   4. `deploy/down.sh` (clean teardown; ports freed; :5432 untouched).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");

const RUN_IT = process.env.PG_BUMPERS_IT === "1";
const PGBIN = process.env.PGBIN ?? "/opt/homebrew/opt/postgresql@18/bin";
const HOST = "127.0.0.1";
// Dedicated state dir for THIS test's stack (isolated from a hand-run up.sh).
const STATE_DIR = process.env.PGB_UP_STATE_DIR ?? "/tmp/pg_bumpers-up-e2e";
const PRIMARY_PORT = Number(process.env.PG_BUMPERS_PRIMARY_PORT ?? 54321);

if (PRIMARY_PORT === 5432) throw new Error("e2e must never use port 5432");

const suite = RUN_IT ? describe : describe.skip;

let mcp: ChildProcess | undefined;
let connectEnv: Record<string, string> = {};
let socketPath = "";
let approverSeed = "";
let demoDb = "";
let mcpStderr = "";
let rpcId = 1;
const replies = new Map<number, (v: unknown) => void>();
const transcript: string[] = [];

function log(line: string): void {
  transcript.push(line);
  // eslint-disable-next-line no-console
  console.error(`[up-e2e] ${line}`);
}

function pg(bin: string): string {
  return join(PGBIN, bin);
}

function psql(sql: string, db: string): string {
  return execFileSync(
    pg("psql"),
    ["-X", "-h", HOST, "-p", String(PRIMARY_PORT), "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
    { encoding: "utf8" },
  ).trim();
}

function mcpCall(method: string, params?: Record<string, unknown>): Promise<any> {
  const id = rpcId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      replies.delete(id);
      reject(new Error(`mcp ${method} timed out\nstderr:\n${mcpStderr}`));
    }, 20_000);
    replies.set(id, (v) => {
      clearTimeout(timer);
      resolve(v);
    });
    mcp!.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

async function toolCall(name: string, args: Record<string, unknown>): Promise<any> {
  const resp = await mcpCall("tools/call", { name, arguments: args });
  return resp.result?.structuredContent;
}

/** Operator approve hop: call applyd's `approve` directly over its Unix socket. */
function applydApprove(params: Record<string, unknown>): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = createConnection(socketPath);
    sock.setEncoding("utf8");
    const rl = createInterface({ input: sock });
    rl.once("line", (line) => {
      try {
        resolve(JSON.parse(line));
      } catch (e) {
        reject(e);
      }
      sock.destroy();
    });
    sock.once("connect", () => {
      sock.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "approve", params }) + "\n");
    });
    sock.once("error", reject);
  });
}

beforeAll(async () => {
  if (!RUN_IT) return;
  if (!existsSync(pg("initdb"))) throw new Error(`PG18 initdb not found at ${PGBIN}; set PGBIN`);

  // The shipped artifacts must exist (the gate builds them first).
  const mcpBin = join(REPO, "mcp/server/dist/bin/mcpStdio.js");
  if (!existsSync(mcpBin)) throw new Error(`pgb-mcp not built at ${mcpBin}; run \`pnpm run build\``);

  // Launch the REAL stack via deploy/up.sh (--no-build: artifacts are prebuilt).
  log("running deploy/up.sh --no-build (launches pgb-proxy + pgb-applyd + pgb-warden)…");
  execFileSync(join(REPO, "deploy/up.sh"), ["--no-build"], {
    env: { ...process.env, PGBIN, PGB_UP_STATE_DIR: STATE_DIR },
    stdio: "inherit",
    timeout: 180_000,
  });

  // Read the connect env the launcher wrote.
  const envText = readFileSync(join(STATE_DIR, "connect.env"), "utf8");
  for (const line of envText.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    connectEnv[line.slice(0, eq)] = line.slice(eq + 1);
  }
  socketPath = connectEnv.PGB_APPLYD_SOCKET;
  approverSeed = connectEnv.PGB_APPROVER_SEED_HEX;
  demoDb = connectEnv.DEMO_DB;
  expect(socketPath, "connect.env must carry the applyd socket").toBeTruthy();
  expect(connectEnv.PGB_PROXY_PORT, "reads must target the PROXY port, not raw PG18").toBeTruthy();
  expect(connectEnv.PGB_PROXY_PORT).not.toBe(String(PRIMARY_PORT)); // proxy ≠ backend
  log(`stack up; MCP read path → pgb-proxy at ${connectEnv.PGB_PROXY_HOST}:${connectEnv.PGB_PROXY_PORT} (backend PG18 is :${PRIMARY_PORT}).`);

  // Spawn the SHIPPED mcpStdio.js with the launcher's exact connect env.
  mcp = spawn(process.execPath, [mcpBin], {
    env: {
      ...process.env,
      PGB_APPLYD_SOCKET: connectEnv.PGB_APPLYD_SOCKET,
      PGB_PROXY_HOST: connectEnv.PGB_PROXY_HOST,
      PGB_PROXY_PORT: connectEnv.PGB_PROXY_PORT,
      PGB_PROXY_DB: connectEnv.PGB_PROXY_DB,
      PGB_PROXY_USER: connectEnv.PGB_PROXY_USER,
      PGB_PROXY_PASSWORD: connectEnv.PGB_PROXY_PASSWORD,
      PGB_PROXY_APP_NAME: connectEnv.PGB_PROXY_APP_NAME,
      PGB_ROLE: connectEnv.PGB_ROLE,
      PGB_SESSION_ID: connectEnv.PGB_SESSION_ID,
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

  const init = await mcpCall("initialize", {});
  expect(init.result.serverInfo.name).toBe("pg-bumpers-mcp");
  log("a REAL MCP client is connected to the shipped stdio shell.");
}, 200_000);

afterAll(async () => {
  if (mcp) mcp.kill();
  if (RUN_IT) {
    // eslint-disable-next-line no-console
    console.error("\n===== UP.SH E2E TRANSCRIPT =====\n" + transcript.join("\n") + "\n================================\n");
    try {
      execFileSync(join(REPO, "deploy/down.sh"), [], {
        env: { ...process.env, PGBIN, PGB_UP_STATE_DIR: STATE_DIR },
        stdio: "inherit",
        timeout: 60_000,
      });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error("down.sh failed:", e);
    }
  }
}, 90_000);

suite("deploy/up.sh runnable stack — MCP reads THROUGH pgb-proxy, write floor enforced", () => {
  it("tools/list exposes the 9 cooperative tools", async () => {
    const resp = await mcpCall("tools/list", {});
    const names = (resp.result.tools as { name: string }[]).map((t) => t.name);
    expect(names.length).toBe(9);
    expect(names).toEqual(
      expect.arrayContaining([
        "whoami",
        "discover_schema",
        "query",
        "explain_plan",
        "propose_write",
        "dry_run",
        "apply_write",
        "request_elevation",
        "get_audit",
      ]),
    );
    log(`tools/list → ${names.length} tools.`);
  });

  it("a read returns rows, bounded, AND genuinely traversed pgb-proxy", async () => {
    const res = await toolCall("query", { sql: "SELECT id, owner, balance FROM public.accounts ORDER BY id" });
    expect(res.status, JSON.stringify(res)).toBe("ok");
    expect(res.data.rowCount).toBe(8);
    expect(res.data.rows[0].owner).toBe("owner-1");
    log(`read: query(accounts) → ${res.data.rowCount} rows through pgb-proxy.`);

    // PROOF #1 the read went through the proxy: the proxy stamps
    // application_name='pgb_proxy' on the backend session it originates as the
    // WALL role. A live agent-tagged backend is visible in pg_stat_activity.
    // (We run another read to keep a session warm, then check.)
    const warmQ = toolCall("query", { sql: "SELECT pg_sleep(0.4), count(*) FROM public.accounts" });
    let sawProxyBackend = "0";
    for (let i = 0; i < 20; i++) {
      sawProxyBackend = psql(
        `SELECT count(*)::int FROM pg_stat_activity
           WHERE application_name = 'pgb_proxy' AND usename = 'pgb_agent'`,
        demoDb,
      );
      if (Number(sawProxyBackend) >= 1) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    await warmQ;
    expect(Number(sawProxyBackend), "proxy must originate the backend session as pgb_agent tagged pgb_proxy").toBeGreaterThanOrEqual(1);
    log(`PROXY PROOF #1: backend session tagged application_name='pgb_proxy' as role 'pgb_agent' seen in pg_stat_activity (the proxy originated it).`);

    // PROOF #2 the WALL is enforced by the proxy's backend role: secret_data is
    // NOT granted to pgb_agent. A SELECT on it through the proxy must be DENIED by
    // the WALL role (SQLSTATE 42501 → WALL_DENIED) — a raw-PG18 superuser path
    // would have returned the row. This is the load-bearing proof the read path is
    // genuinely behind the proxy/WALL, not a raw PG18 connection.
    const denied = await toolCall("query", { sql: "SELECT secret FROM public.secret_data" });
    expect(denied.status, JSON.stringify(denied)).toBe("blocked");
    expect(denied.code).toBe("WALL_DENIED");
    log(`PROXY PROOF #2: query(secret_data) → ${denied.code} — the WALL role the proxy connects as denied the non-granted table (raw superuser would not).`);
  });

  it("DROP TABLE and TRUNCATE through propose_write are REFUSED (NOT_REHEARSABLE)", async () => {
    for (const sql of ["DROP TABLE public.accounts", "TRUNCATE public.accounts"]) {
      const proposed = await toolCall("propose_write", { sql, expected_rows: 0 });
      expect(proposed.status, `${sql} => ${JSON.stringify(proposed)}`).toBe("blocked");
      expect(proposed.code).toBe("NOT_REHEARSABLE");
      log(`REFUSED: propose_write("${sql}") → ${proposed.code} (neutralized by refusal, NOT executed).`);
    }
    // accounts survives intact.
    expect(psql("SELECT count(*)::int FROM public.accounts", demoDb)).toBe("8");
  });

  it("a no-WHERE-shaped UPDATE: no grant → APPROVAL_REQUIRED; operator approve → COMMITTED bounded + reversible", { timeout: 60_000 }, async () => {
    const FORWARD = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";
    const proposed = await toolCall("propose_write", { sql: FORWARD, expected_rows: 4 });
    expect(proposed.status, JSON.stringify(proposed)).toBe("ok");
    const proposalId = proposed.data.proposal_id as string;

    const dry = await toolCall("dry_run", { proposal_id: proposalId });
    expect(dry.status).toBe("ok");
    expect(dry.data.blast_radius.total_rows).toBe(4); // BOUNDED by blast radius
    expect(dry.data.blast_radius.reversible).toBe(true);
    const confirmToken = dry.data.confirm_token as string;
    log(`BOUNDED: dry_run → blast radius ${dry.data.blast_radius.total_rows} rows, reversible=${dry.data.blast_radius.reversible}.`);

    // apply WITHOUT a grant → APPROVAL_REQUIRED (recoverable, retryable).
    const elev = await toolCall("request_elevation", { proposal_id: proposalId, reason: "bounded backfill demo" });
    const requestId = elev.data.request_id as string;
    const blocked = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: 4, confirm_token: confirmToken });
    expect(blocked.status).toBe("blocked");
    expect(blocked.code).toBe("APPROVAL_REQUIRED");
    log(`apply WITHOUT a grant → ${blocked.code} (retryable=${blocked.retryable}).`);

    // OPERATOR approve over the applyd socket (signing key NEVER enters MCP path).
    const approveResp = await applydApprove({
      request_id: requestId,
      approver_id: "operator-1",
      signing_key_hex: approverSeed,
      nonce: `nonce-${Date.now()}`,
      grant_ttl_millis: 60_000,
    });
    expect(approveResp.error, JSON.stringify(approveResp)).toBeUndefined();
    log(`operator approve (out-of-band CLI-minted grant verified at apply).`);

    // apply WITH the grant → guarded_apply_with_grant COMMITS bounded.
    const applied = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: 4, confirm_token: confirmToken });
    expect(applied.status, JSON.stringify(applied)).toBe("ok");
    expect(applied.data.applied).toBe(true);
    expect(applied.data.reversible).toBe(true);
    // BOUNDED: even rows zeroed, odd untouched.
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 0 AND balance = 0", demoDb)).toBe("4");
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 1 AND balance <> 0", demoDb)).toBe("4");
    log(`COMMITTED: apply WITH the grant → bounded (4 even zeroed, 4 odd untouched), reversible=true.`);
  });

  it("get_audit returns the session tail and pgb-cli verify proves the chain", { timeout: 30_000 }, async () => {
    const audit = await toolCall("get_audit", { limit: 10 });
    expect(audit.status).toBe("ok");
    expect(Array.isArray(audit.data.records)).toBe(true);
    log(`get_audit → ${audit.data.records.length} record(s).`);

    const cliBin = join(REPO, "target/debug/pgb-cli");
    if (!existsSync(cliBin)) throw new Error(`pgb-cli not built at ${cliBin}`);
    const out = execFileSync(cliBin, ["verify"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PGB_META_DSN: connectEnv.PGB_META_DSN,
        PGB_AUDIT_SIGNING_KEY: connectEnv.PGB_AUDIT_SIGNING_KEY,
        PGB_ANCHOR_PATH: join(STATE_DIR, "verify.anchor.worm"),
      },
    });
    expect(out).toContain("the shared `_meta` chain VERIFIES");
    log("pgb-cli verify → the shared `_meta` chain VERIFIES.");
    log("--- pgb-cli verify output ---\n" + out.trimEnd());
  });
});
