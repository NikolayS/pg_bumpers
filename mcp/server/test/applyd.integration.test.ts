/**
 * LIVE end-to-end integration: a REAL MCP client → the deployable stdio MCP shell
 * → the LIVE proxy read path + the production `ApplydCore` → `pgb-applyd` → the
 * real grant-gated `guarded_apply` floor on PG18 (SPEC §3, §4; issue #67).
 *
 * Env-gated (PG_BUMPERS_IT=1) so plain `pnpm test` stays fast + DB-free.
 *
 * What is LIVE: a throwaway PG18, the built `pgb-applyd` binary on a temp Unix
 * socket, and the built `pgb-mcp` stdio shell. The test acts as a REAL MCP client
 * over the shell's stdin/stdout (`initialize` / `tools/list` / `tools/call`):
 *   - `query` reads through the proxy read path (PgProxyTransport → the PG18);
 *   - `propose_write` → `dry_run` → `request_elevation` → (operator approve over
 *     the applyd socket) → `apply_write` drives the full write lifecycle through
 *     `guarded_apply_with_grant`. The bounded UPDATE COMMITS (even rows zeroed,
 *     odd untouched) and the apply reports reversible (a typed-inverse was
 *     captured — the byte-for-byte revert-restores-prestate is asserted in the
 *     Rust IT crates/applyd/tests/applyd_it.rs).
 *   - a no-confirm apply and a no-grant apply both return the RECOVERABLE block
 *     contract (CONFIRM_REQUIRED / APPROVAL_REQUIRED), never an opaque error.
 *
 * What is MOCKED: the Apache Rust proxy binary in front (SCRAM/TLS/WALL) — reads
 * point straight at the PG18 standing in for the proxied backend (same honest
 * split as integration.test.ts; the MCP layer is cooperative, not the boundary).
 *
 * SAFETY: spins up its OWN PG18 on a dedicated high port (default 54331; NEVER
 * 5432) and tears it down. Override with PG_BUMPERS_MCP_APPLYD_IT_PORT.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));

const RUN_IT = process.env.PG_BUMPERS_IT === "1";
const PGBIN = process.env.PGBIN ?? "/opt/homebrew/opt/postgresql@18/bin";
const PORT = Number(process.env.PG_BUMPERS_MCP_APPLYD_IT_PORT ?? 54331);
const HOST = "127.0.0.1";
const DB = "pgb_applyd_mcp_it";

// Belt-and-suspenders: never the founder's cluster.
if (PORT === 5432) throw new Error("integration test must never use port 5432");

const suite = RUN_IT ? describe : describe.skip;

let dataDir: string | undefined;
let scratch: string | undefined;
let applyd: ChildProcess | undefined;
let mcp: ChildProcess | undefined;
let socketPath = "";
let rpcId = 1;
let mcpReplies: Map<number, (v: unknown) => void> = new Map();
let mcpStderr = "";

function pg(bin: string): string {
  return join(PGBIN, bin);
}

/** Extract the raw 32-byte ed25519 pub + seed (hex) from a generated keypair. */
function ed25519Hex(): { pubHex: string; seedHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const privDer = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  return {
    pubHex: pubDer.subarray(pubDer.length - 32).toString("hex"),
    seedHex: privDer.subarray(privDer.length - 32).toString("hex"),
  };
}

/** Send one MCP JSON-RPC request to the shell and await its response. */
function mcpCall(method: string, params?: Record<string, unknown>): Promise<any> {
  const id = rpcId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      mcpReplies.delete(id);
      reject(new Error(`mcp ${method} timed out\nstderr:\n${mcpStderr}`));
    }, 15_000);
    mcpReplies.set(id, (v) => {
      clearTimeout(timer);
      resolve(v);
    });
    mcp!.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

/** Call a `tools/call` and return the structuredContent (the tool's result). */
async function toolCall(name: string, args: Record<string, unknown>): Promise<any> {
  const resp = await mcpCall("tools/call", { name, arguments: args });
  return resp.result?.structuredContent;
}

/** Operator hop: call applyd's `approve` directly over its Unix socket. */
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

function psql(sql: string, db = "postgres"): string {
  // -X: ignore ~/.psqlrc (the founder's may print a banner / enable timing,
  // which would pollute the scalar output).
  return execFileSync(
    pg("psql"),
    ["-X", "-h", HOST, "-p", String(PORT), "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
    { encoding: "utf8" },
  );
}

beforeAll(async () => {
  if (!RUN_IT) return;
  if (!existsSync(pg("initdb"))) throw new Error(`PG18 initdb not found at ${PGBIN}; set PGBIN`);
  dataDir = mkdtempSync(join(tmpdir(), "pgb-applyd-mcp-it-"));
  scratch = mkdtempSync(join(tmpdir(), "pgb-applyd-mcp-scratch-"));
  socketPath = join(scratch, "applyd.sock");

  execFileSync(pg("initdb"), ["-D", dataDir, "-U", "postgres", "--auth=trust", "-E", "UTF8"], {
    stdio: "ignore",
  });
  execFileSync(
    pg("pg_ctl"),
    [
      "-D",
      dataDir,
      "-o",
      `-p ${PORT} -c listen_addresses=${HOST} -c unix_socket_directories='${dataDir}'`,
      "-w",
      "-l",
      join(dataDir, "log"),
      "start",
    ],
    { stdio: "ignore" },
  );

  // Seed accounts + the audit `_meta` schema (the daemon anchors into this DB).
  psql(`CREATE DATABASE ${DB}`);
  psql(
    `CREATE TABLE public.accounts (id int PRIMARY KEY, owner text NOT NULL, balance bigint NOT NULL);
     INSERT INTO public.accounts(id, owner, balance)
       SELECT g, 'owner-' || g, (g * 1000)::bigint FROM generate_series(1, 8) AS g;`,
    DB,
  );
  // Apply the canonical _meta schema (strip psql meta-commands).
  const metaSql = readFileSync(join(HERE, "../../../crates/audit/sql/10_audit_meta.sql"), "utf8")
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("\\"))
    .join("\n");
  const metaFile = join(scratch, "meta.sql");
  writeFileSync(metaFile, metaSql);
  execFileSync(
    pg("psql"),
    ["-h", HOST, "-p", String(PORT), "-U", "postgres", "-d", DB, "-v", "ON_ERROR_STOP=1", "-f", metaFile],
    { stdio: "ignore" },
  );

  // Approver keypair (the apply-time trust root).
  const { pubHex, seedHex } = ed25519Hex();
  (globalThis as any).__seedHex = seedHex;

  const url = `host=${HOST} port=${PORT} dbname=${DB} user=postgres`;
  const anchorPath = join(scratch, "anchor.worm");

  // Spawn the built pgb-applyd (cargo-built debug binary).
  const applydBin = join(HERE, "../../../target/debug/pgb-applyd");
  if (!existsSync(applydBin)) {
    throw new Error(`pgb-applyd not built at ${applydBin}; run \`cargo build -p pgb-applyd\` first`);
  }
  applyd = spawn(applydBin, [], {
    env: {
      ...process.env,
      PGB_APPLYD_SOCKET: socketPath,
      PGB_APPROVER_PUBKEY: pubHex,
      PGB_POLICY_PATH: join(HERE, "../../../crates/policy/policy.example.yaml"),
      PGB_META_DSN: url,
      PGB_AUDIT_SIGNING_KEY: "applyd-mcp-it-signing-key-000001",
      PGB_ANCHOR_PATH: anchorPath,
      PGB_ANCHOR_INTERVAL_MS: "60000",
      PGB_BACKEND_HOST: HOST,
      PGB_BACKEND_PORT: String(PORT),
      PGB_BACKEND_DB: DB,
      PGB_BACKEND_ROLE: "postgres",
      PGB_BACKEND_PASSWORD: "unused-trust",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let applydStderr = "";
  applyd.stderr!.on("data", (d) => (applydStderr += d.toString()));

  // Wait for the applyd socket to appear.
  for (let i = 0; i < 100; i++) {
    if (existsSync(socketPath)) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!existsSync(socketPath)) {
    throw new Error(`applyd socket never came up:\n${applydStderr}`);
  }

  // Spawn the built pgb-mcp stdio shell: reads → the PG18 (proxy stand-in),
  // writes → the applyd socket.
  const mcpBin = join(HERE, "../dist/bin/mcpStdio.js");
  if (!existsSync(mcpBin)) {
    throw new Error(`pgb-mcp not built at ${mcpBin}; run \`pnpm run build\` first`);
  }
  mcp = spawn(process.execPath, [mcpBin], {
    env: {
      ...process.env,
      PGB_APPLYD_SOCKET: socketPath,
      PGB_PROXY_HOST: HOST,
      PGB_PROXY_PORT: String(PORT),
      PGB_PROXY_DB: DB,
      PGB_PROXY_USER: "postgres",
      PGB_ROLE: "app_writer",
      PGB_SESSION_ID: "mcp-it-sess",
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
    const cb = mcpReplies.get(msg.id);
    if (cb) {
      mcpReplies.delete(msg.id);
      cb(msg);
    }
  });

  // MCP handshake.
  const init = await mcpCall("initialize", {});
  expect(init.result.serverInfo.name).toBe("pg-bumpers-mcp");
}, 90_000);

afterAll(async () => {
  if (mcp) {
    mcp.kill();
  }
  if (applyd) {
    applyd.kill();
  }
  if (dataDir) {
    spawnSync(pg("pg_ctl"), ["-D", dataDir, "-m", "immediate", "-w", "stop"], { stdio: "ignore" });
    rmSync(dataDir, { recursive: true, force: true });
  }
  if (scratch) rmSync(scratch, { recursive: true, force: true });
}, 30_000);

suite("MCP client → stdio shell → ApplydCore → pgb-applyd → guarded_apply on PG18", () => {
  it("tools/list exposes the nine tools", async () => {
    const resp = await mcpCall("tools/list", {});
    const names = resp.result.tools.map((t: any) => t.name);
    expect(names).toContain("query");
    expect(names).toContain("propose_write");
    expect(names).toContain("apply_write");
    expect(names.length).toBe(9);
  });

  it("query reads through the live proxy read path", async () => {
    const data = await toolCall("query", {
      sql: "SELECT id, owner, balance FROM public.accounts ORDER BY id",
    });
    expect(data.status).toBe("ok");
    expect(data.data.rowCount).toBe(8);
  });

  it("full write lifecycle: propose → dry_run → elevate → approve → apply commits (bounded + reversible)", { timeout: 30_000 }, async () => {
    const FORWARD = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    // propose_write
    const proposed = await toolCall("propose_write", { sql: FORWARD, expected_rows: 4 });
    expect(proposed.status).toBe("ok");
    const proposalId = proposed.data.proposal_id as string;

    // dry_run → real blast radius
    const dry = await toolCall("dry_run", { proposal_id: proposalId });
    expect(dry.status).toBe("ok");
    expect(dry.data.blast_radius.total_rows).toBe(4);
    const confirmToken = dry.data.confirm_token as string;

    // request_elevation → APPROVAL_REQUIRED ticket
    const elev = await toolCall("request_elevation", {
      proposal_id: proposalId,
      reason: "raise the bound for the demo",
    });
    expect(elev.status).toBe("ok");
    const requestId = elev.data.request_id as string;

    // apply BEFORE approve → recoverable APPROVAL_REQUIRED block
    const blocked = await toolCall("apply_write", {
      proposal_id: proposalId,
      confirm_rows: 4,
      confirm_token: confirmToken,
    });
    expect(blocked.status).toBe("blocked");
    expect(blocked.code).toBe("APPROVAL_REQUIRED");
    expect(blocked.retryable).toBe(true);

    // OPERATOR HOP: approve directly over the applyd socket (NOT an MCP tool;
    // the signing key never enters the agent/MCP path).
    const seedHex = (globalThis as any).__seedHex as string;
    const approveResp = await applydApprove({
      request_id: requestId,
      approver_id: "operator-1",
      signing_key_hex: seedHex,
      nonce: `nonce-${Date.now()}`,
      grant_ttl_millis: 60_000,
    });
    expect(approveResp.error, JSON.stringify(approveResp)).toBeUndefined();

    // apply_write → guarded_apply_with_grant COMMITS the bounded write.
    const applied = await toolCall("apply_write", {
      proposal_id: proposalId,
      confirm_rows: 4,
      confirm_token: confirmToken,
    });
    expect(applied.status, JSON.stringify(applied)).toBe("ok");
    expect(applied.data.applied).toBe(true);
    expect(applied.data.reversible).toBe(true);

    // Prove the commit landed + is BOUNDED: even rows zeroed, odd untouched.
    const evenZero = psql(
      "SELECT count(*)::int FROM public.accounts WHERE id % 2 = 0 AND balance = 0",
      DB,
    ).trim();
    expect(evenZero).toBe("4");
    const oddNonZero = psql(
      "SELECT count(*)::int FROM public.accounts WHERE id % 2 = 1 AND balance <> 0",
      DB,
    ).trim();
    expect(oddNonZero).toBe("4");
  });

  it("apply_write WITHOUT confirm_rows is a recoverable CONFIRM_REQUIRED block", async () => {
    const proposed = await toolCall("propose_write", {
      sql: "UPDATE public.accounts SET balance = 1 WHERE id = 1",
      expected_rows: 1,
    });
    const proposalId = proposed.data.proposal_id as string;
    await toolCall("dry_run", { proposal_id: proposalId });
    // No confirm_rows → the server's forcing-function block (never reaches applyd).
    const blocked = await toolCall("apply_write", { proposal_id: proposalId });
    expect(blocked.status).toBe("blocked");
    expect(blocked.code).toBe("CONFIRM_REQUIRED");
    expect(blocked.retryable).toBe(true);
    // id=1 untouched (no write leaked).
    const bal = psql("SELECT balance FROM public.accounts WHERE id = 1", DB).trim();
    expect(bal).toBe("1000");
  });

  it("a write to the query tool is refused (read-only), and injected data can't widen capability", async () => {
    const drop = await toolCall("query", { sql: "DROP TABLE public.accounts" });
    expect(drop.status).toBe("blocked");
    expect(drop.code).toBe("READ_ONLY");
    // The table survives.
    const n = psql("SELECT count(*)::int FROM public.accounts", DB).trim();
    expect(n).toBe("8");
  });
});
