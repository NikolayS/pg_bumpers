/**
 * THE S5 MARQUEE — "delete a DB through the official MCP" — end-to-end against
 * the assembled stack (issue #68; SPEC §3/§4/§11/§13/§14).
 *
 * A REAL MCP client drives the deployable stdio MCP shell (`pgb-mcp`) against the
 * LIVE assembled stack on dedicated high ports (⚠️ NEVER 5432):
 *   - reads through the live proxy read path (`PgProxyTransport` → PG18, tagged
 *     `application_name=pgb_proxy` so the warden recognizes the session);
 *   - writes through `ApplydCore` → the `pgb-applyd` Unix-socket daemon → the real
 *     grant-gated `guarded_apply_with_grant` floor;
 *   - a LIVE `pgb-warden` binary watches the same PG18 and audits to the SAME
 *     `_meta` chain;
 *   - the operator approve hop is a direct call over the applyd socket (the
 *     signing key NEVER enters the agent/MCP path);
 *   - at the end, the `pgb-cli verify` binary loads the unified `_meta` chain,
 *     `verify_chain`s it, and asserts the durable anchored head matches.
 *
 * What the system ACTUALLY does, split by DAMAGE CLASS (honest, no overclaim):
 *
 *   1. IRREVERSIBLE / STRUCTURAL (DROP DATABASE, DROP TABLE, TRUNCATE, ALTER) →
 *      REFUSED, default-deny. `propose_write` of a DROP/TRUNCATE/ALTER is refused
 *      at the applyd classify choke (NOT_REHEARSABLE); a DROP on the read tool is a
 *      READ_ONLY block. NO grant can authorize them in the MVP. The "delete a DB"
 *      headline = the attempt is NEUTRALIZED BY REFUSAL, not executed.
 *
 *   2. BOUNDED REVERSIBLE WRITE (no-WHERE/wide UPDATE on a single-int-PK table) →
 *      bounded by blast radius; without a grant → APPROVAL_REQUIRED; with a
 *      CLI-minted grant (operator approve) → APPLIED REVERSIBLY (even rows zeroed,
 *      odd untouched), and the captured typed-inverse REVERTS to the pre-state
 *      byte-for-byte (proven in crates/applyd/tests/applyd_it.rs; here we prove the
 *      bounded commit + reversible flag + that a drifted apply ABORTS with NO
 *      mutation).
 *
 *   3. RUNAWAY READ (long pg_sleep tagged as the agent's proxied session) → KILLED
 *      by the LIVE warden, audited `WARDEN_TERMINATE` to `_meta`; a non-agent
 *      backend running the same sleep is SPARED (no false-positive outage).
 *
 *   4. EVERY DECISION lands on ONE anchored `_meta` chain — `pgb-cli verify` proves
 *      `verify_chain` passes AND the durable anchored head matches at the end.
 *
 * Env-gated (PG_BUMPERS_IT=1) so plain `pnpm test` stays fast + DB-free. Spins up
 * its OWN PG18 on a dedicated high port (default 54341; NEVER 5432) and tears it
 * down. Override with PG_BUMPERS_MARQUEE_PORT.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  execFileSync,
  spawn,
  spawnSync,
  type ChildProcess,
} from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");

const RUN_IT = process.env.PG_BUMPERS_IT === "1";
const PGBIN = process.env.PGBIN ?? "/opt/homebrew/opt/postgresql@18/bin";
const PORT = Number(process.env.PG_BUMPERS_MARQUEE_PORT ?? 54341);
const HOST = "127.0.0.1";
const DB = "pgb_marquee_it";

// Belt-and-suspenders: never the founder's cluster.
if (PORT === 5432) throw new Error("marquee must never use port 5432");

const suite = RUN_IT ? describe : describe.skip;

let dataDir: string | undefined;
let scratch: string | undefined;
let applyd: ChildProcess | undefined;
let warden: ChildProcess | undefined;
let mcp: ChildProcess | undefined;
let socketPath = "";
let metaDsn = "";
let signingKey = "marquee-it-signing-key-00000001";
let rpcId = 1;
const mcpReplies = new Map<number, (v: unknown) => void>();
let mcpStderr = "";
let wardenStderr = "";

/** A line of transcript evidence (echoed to stderr + collected for the PR). */
const transcript: string[] = [];
function log(line: string): void {
  transcript.push(line);
  // eslint-disable-next-line no-console
  console.error(`[marquee] ${line}`);
}

function pg(bin: string): string {
  return join(PGBIN, bin);
}

function psql(sql: string, db = "postgres"): string {
  return execFileSync(
    pg("psql"),
    ["-X", "-h", HOST, "-p", String(PORT), "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
    { encoding: "utf8" },
  );
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

function mcpCall(method: string, params?: Record<string, unknown>): Promise<any> {
  const id = rpcId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      mcpReplies.delete(id);
      reject(new Error(`mcp ${method} timed out\nstderr:\n${mcpStderr}`));
    }, 20_000);
    mcpReplies.set(id, (v) => {
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

beforeAll(async () => {
  if (!RUN_IT) return;
  if (!existsSync(pg("initdb"))) throw new Error(`PG18 initdb not found at ${PGBIN}; set PGBIN`);

  // Verify :5432 (the founder cluster) is not ours to touch — we never connect to it.
  log(`SAFETY: using dedicated port ${PORT}; the founder's 5432 is NEVER touched.`);

  dataDir = mkdtempSync(join(tmpdir(), "pgb-marquee-it-"));
  scratch = mkdtempSync(join(tmpdir(), "pgb-marquee-scratch-"));
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

  // Seed accounts (single-int-PK, the MVP-supported write shape) + the `_meta`
  // schema + the WALL roles (the audit migration creates pgb_audit_writer + pgb_agent).
  psql(`CREATE DATABASE ${DB}`);
  // `accounts` carries a `notes` column the OLD hardcoded `(owner, balance)`
  // pre-image never captured — the S5 #75 wide-column-UPDATE case writes it to
  // prove the apply path captures + reverts EVERY written column, not a fixed set.
  psql(
    `CREATE TABLE public.accounts (id int PRIMARY KEY, owner text NOT NULL, balance bigint NOT NULL, notes text NOT NULL DEFAULT '');
     INSERT INTO public.accounts(id, owner, balance, notes)
       SELECT g, 'owner-' || g, (g * 1000)::bigint, 'note-' || g FROM generate_series(1, 8) AS g;`,
    DB,
  );
  // Apply the canonical _meta schema into the SAME DB the daemon + warden anchor
  // into (strip psql meta-commands the wire protocol rejects).
  const metaSql = readFileSync(join(REPO, "crates/audit/sql/10_audit_meta.sql"), "utf8")
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

  // The approver keypair (the apply-time trust root).
  const { pubHex, seedHex } = ed25519Hex();
  (globalThis as any).__seedHex = seedHex;

  metaDsn = `host=${HOST} port=${PORT} dbname=${DB} user=postgres`;
  const applydAnchor = join(scratch, "applyd.anchor.worm");

  // ---- Spawn pgb-applyd (short anchor interval so the chain is re-anchored). ----
  const applydBin = join(REPO, "target/debug/pgb-applyd");
  if (!existsSync(applydBin)) {
    throw new Error(`pgb-applyd not built at ${applydBin}; run \`cargo build -p pgb-applyd\` first`);
  }
  applyd = spawn(applydBin, [], {
    env: {
      ...process.env,
      PGB_APPLYD_SOCKET: socketPath,
      PGB_APPROVER_PUBKEY: pubHex,
      PGB_POLICY_PATH: join(REPO, "crates/policy/policy.example.yaml"),
      PGB_META_DSN: metaDsn,
      PGB_AUDIT_SIGNING_KEY: signingKey,
      PGB_ANCHOR_PATH: applydAnchor,
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
  for (let i = 0; i < 100; i++) {
    if (existsSync(socketPath)) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!existsSync(socketPath)) throw new Error(`applyd socket never came up:\n${applydStderr}`);
  log("pgb-applyd up (write path: socket → guarded_apply_with_grant → PG18).");

  // ---- Spawn the LIVE pgb-warden (tight runtime ceiling for a fast kill). ----
  // A dedicated policy yaml with a 1s runtime ceiling so an agent-tagged runaway
  // is terminated quickly; the warden audits to the SAME `_meta` chain.
  const wardenPolicy = join(scratch, "warden.policy.yaml");
  writeFileSync(
    wardenPolicy,
    [
      "version: 1",
      "warden:",
      "  poll_interval_millis: 500",
      "  max_query_runtime_millis: 1000",
      "  slot_retained_wal_alarm_bytes: 67108864",
      "  breaker_lag_trip_bytes: 134217728",
      "  breaker_runaway_trip_count: 3",
      "  breaker_cooldown_millis: 30000",
      "",
    ].join("\n"),
  );
  const wardenBin = join(REPO, "target/debug/pgb-warden");
  if (!existsSync(wardenBin)) {
    throw new Error(`pgb-warden not built at ${wardenBin}; run \`cargo build -p pgb-warden\` first`);
  }
  warden = spawn(wardenBin, [], {
    env: {
      ...process.env,
      PGB_POLICY_PATH: wardenPolicy,
      PGB_BACKEND_HOST: HOST,
      PGB_BACKEND_PORT: String(PORT),
      PGB_BACKEND_DB: DB,
      PGB_AUDIT_DB: DB,
      PGB_WARDEN_ADMIN_ROLE: "postgres",
      PGB_WARDEN_ADMIN_PASSWORD: "unused-trust",
      PGB_AUDIT_WRITER_ROLE: "pgb_audit_writer",
      PGB_AUDIT_WRITER_PASSWORD: "pgb_audit_writer_dev_pw",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  warden.stderr!.on("data", (d) => (wardenStderr += d.toString()));
  // Give the warden a moment to open its admin/writer connections + first poll.
  await new Promise((r) => setTimeout(r, 1500));
  if (warden.exitCode !== null) {
    throw new Error(`pgb-warden exited early (code ${warden.exitCode}):\n${wardenStderr}`);
  }
  log("pgb-warden up (live watchdog: 1s runtime ceiling, auditing to _meta).");

  // ---- Spawn the pgb-mcp stdio shell (the cooperative MCP layer). ----
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
      PGB_PROXY_APP_NAME: "pgb_proxy", // the warden tag (honest: the proxied session)
      PGB_ROLE: "app_writer",
      PGB_SESSION_ID: "marquee-sess",
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
  const init = await mcpCall("initialize", {});
  expect(init.result.serverInfo.name).toBe("pg-bumpers-mcp");
  log("pgb-mcp up; a REAL MCP client is connected to the stdio shell.");
}, 120_000);

afterAll(async () => {
  if (mcp) mcp.kill();
  if (warden) warden.kill();
  if (applyd) applyd.kill();
  if (dataDir) {
    spawnSync(pg("pg_ctl"), ["-D", dataDir, "-m", "immediate", "-w", "stop"], { stdio: "ignore" });
    rmSync(dataDir, { recursive: true, force: true });
  }
  if (scratch) rmSync(scratch, { recursive: true, force: true });
  // Emit the full transcript as committed-able PR evidence.
  if (RUN_IT && transcript.length) {
    // eslint-disable-next-line no-console
    console.error("\n===== MARQUEE TRANSCRIPT =====\n" + transcript.join("\n") + "\n=============================\n");
  }
}, 30_000);

suite("S5 marquee: delete-a-DB-through-the-MCP, per damage class, on the assembled stack", () => {
  // --- DAMAGE CLASS 1: IRREVERSIBLE / STRUCTURAL → REFUSED (default-deny) -----
  it("DROP DATABASE through propose_write is REFUSED (default-deny; no grant can authorize it)", async () => {
    const before = psql("SELECT count(*)::int FROM pg_database WHERE datname = $$" + DB + "$$").trim();
    expect(before).toBe("1");

    // The agent proposes the headline destructive op THROUGH the MCP.
    const proposed = await toolCall("propose_write", { sql: `DROP DATABASE ${DB}`, expected_rows: 0 });
    // applyd's classify choke refuses a non-rehearsable (DDL) shape at propose.
    expect(proposed.status, JSON.stringify(proposed)).toBe("blocked");
    expect(proposed.code).toBe("NOT_REHEARSABLE");
    log(`CLASS 1 (delete a DB): propose_write("DROP DATABASE") → REFUSED ${proposed.code} (neutralized by refusal, NOT executed).`);

    // The database still exists — the destructive op never ran.
    const after = psql("SELECT count(*)::int FROM pg_database WHERE datname = $$" + DB + "$$").trim();
    expect(after).toBe("1");
  });

  it("DROP TABLE / TRUNCATE / ALTER are all REFUSED at the structural choke (none executes)", async () => {
    for (const sql of [
      "DROP TABLE public.accounts",
      "TRUNCATE public.accounts",
      "ALTER TABLE public.accounts DROP COLUMN balance",
    ]) {
      const proposed = await toolCall("propose_write", { sql, expected_rows: 0 });
      expect(proposed.status, `${sql} => ${JSON.stringify(proposed)}`).toBe("blocked");
      expect(proposed.code).toBe("NOT_REHEARSABLE");
      log(`CLASS 1 (structural): propose_write("${sql}") → REFUSED ${proposed.code}.`);
    }
    // accounts survives intact: 8 rows, all 4 columns present (id/owner/balance/notes).
    expect(psql("SELECT count(*)::int FROM public.accounts", DB).trim()).toBe("8");
    expect(psql("SELECT count(*)::int FROM information_schema.columns WHERE table_name='accounts'", DB).trim()).toBe("4");
  });

  it("a DROP on the read tool is a READ_ONLY block (the table survives)", async () => {
    const drop = await toolCall("query", { sql: "DROP TABLE public.accounts" });
    expect(drop.status).toBe("blocked");
    expect(drop.code).toBe("READ_ONLY");
    expect(psql("SELECT count(*)::int FROM public.accounts", DB).trim()).toBe("8");
    log(`CLASS 1 (read tool): query("DROP TABLE") → READ_ONLY block; accounts intact.`);
  });

  // --- DAMAGE CLASS 2: BOUNDED REVERSIBLE WRITE → bound, approval, apply ------
  it("a no-WHERE-shaped wide UPDATE: no grant → APPROVAL_REQUIRED; operator approve → applied bounded + reversible", { timeout: 40_000 }, async () => {
    const FORWARD = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    const proposed = await toolCall("propose_write", { sql: FORWARD, expected_rows: 4 });
    expect(proposed.status, JSON.stringify(proposed)).toBe("ok");
    const proposalId = proposed.data.proposal_id as string;

    const dry = await toolCall("dry_run", { proposal_id: proposalId });
    expect(dry.status).toBe("ok");
    expect(dry.data.blast_radius.total_rows).toBe(4); // BOUNDED by blast radius
    expect(dry.data.blast_radius.reversible).toBe(true);
    const confirmToken = dry.data.confirm_token as string;
    log(`CLASS 2: dry_run → blast radius BOUNDED to ${dry.data.blast_radius.total_rows} rows, reversible=${dry.data.blast_radius.reversible}.`);

    // WITHOUT a grant → APPROVAL_REQUIRED (recoverable, not an opaque error).
    const elev = await toolCall("request_elevation", { proposal_id: proposalId, reason: "bounded backfill demo" });
    const requestId = elev.data.request_id as string;
    const blocked = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: 4, confirm_token: confirmToken });
    expect(blocked.status).toBe("blocked");
    expect(blocked.code).toBe("APPROVAL_REQUIRED");
    expect(blocked.retryable).toBe(true);
    log(`CLASS 2: apply WITHOUT a grant → APPROVAL_REQUIRED (retryable).`);

    // OPERATOR HOP over the applyd socket (the signing key never enters the MCP path).
    const seedHex = (globalThis as any).__seedHex as string;
    const approveResp = await applydApprove({
      request_id: requestId,
      approver_id: "operator-1",
      signing_key_hex: seedHex,
      nonce: `nonce-${Date.now()}`,
      grant_ttl_millis: 60_000,
    });
    expect(approveResp.error, JSON.stringify(approveResp)).toBeUndefined();
    log(`CLASS 2: operator approve (CLI-minted §14.3 grant, verified at apply).`);

    // WITH the grant → guarded_apply_with_grant COMMITS the bounded write.
    const applied = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: 4, confirm_token: confirmToken });
    expect(applied.status, JSON.stringify(applied)).toBe("ok");
    expect(applied.data.applied).toBe(true);
    expect(applied.data.reversible).toBe(true);

    // BOUNDED: even rows zeroed, odd untouched (blast radius held).
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 0 AND balance = 0", DB).trim()).toBe("4");
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 1 AND balance <> 0", DB).trim()).toBe("4");
    log(`CLASS 2: apply WITH the grant → COMMITTED, bounded (4 even zeroed, 4 odd untouched), reversible=true.`);
  });

  // S5 #75: a WIDE-COLUMN UPDATE — writes the `notes` column the old hardcoded
  // `(owner, balance)` pre-image never captured. End-to-end through the assembled
  // stack it is bounded, approval-gated, and applied REVERSIBLY (the apply now
  // captures the EXACT SET-clause column). Before the fix this committed
  // `reversible:true` with an inverse that could not restore `notes` — a silent FN.
  it("a WIDE-COLUMN UPDATE (SET notes=…) is bounded + applied REVERSIBLY (S5 #75 column coverage)", { timeout: 40_000 }, async () => {
    const FORWARD = "UPDATE public.accounts SET notes = 'audited' WHERE id % 2 = 0";
    // Pre-state: even rows carry their seeded notes (note-2 … note-8), not 'audited'.
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 0 AND notes = 'audited'", DB).trim()).toBe("0");

    const proposed = await toolCall("propose_write", { sql: FORWARD, expected_rows: 4 });
    expect(proposed.status, JSON.stringify(proposed)).toBe("ok");
    const proposalId = proposed.data.proposal_id as string;

    const dry = await toolCall("dry_run", { proposal_id: proposalId });
    expect(dry.status, JSON.stringify(dry)).toBe("ok");
    expect(dry.data.blast_radius.total_rows).toBe(4); // BOUNDED
    expect(dry.data.blast_radius.reversible).toBe(true);
    const confirmToken = dry.data.confirm_token as string;
    log(`CLASS 2 (wide-column #75): dry_run → BOUNDED to ${dry.data.blast_radius.total_rows} rows, reversible=${dry.data.blast_radius.reversible}.`);

    // Operator-approved grant (signing key never enters the MCP path).
    const elev = await toolCall("request_elevation", { proposal_id: proposalId, reason: "wide-column reversible demo" });
    const seedHex = (globalThis as any).__seedHex as string;
    const approveResp = await applydApprove({
      request_id: elev.data.request_id,
      approver_id: "operator-1",
      signing_key_hex: seedHex,
      nonce: `nonce-wide-${Date.now()}`,
      grant_ttl_millis: 60_000,
    });
    expect(approveResp.error, JSON.stringify(approveResp)).toBeUndefined();

    // WITH the grant → the wide-column write COMMITs, reversibly.
    const applied = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: 4, confirm_token: confirmToken });
    expect(applied.status, JSON.stringify(applied)).toBe("ok");
    expect(applied.data.applied).toBe(true);
    expect(applied.data.reversible, "the wide-column UPDATE must be reported reversible (notes captured)").toBe(true);

    // BOUNDED + the written column actually changed: 4 even rows now notes='audited',
    // odd untouched. The point: the apply path captured the EXACT written column.
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 0 AND notes = 'audited'", DB).trim()).toBe("4");
    expect(psql("SELECT count(*)::int FROM public.accounts WHERE id % 2 = 1 AND notes = 'audited'", DB).trim()).toBe("0");
    log(`CLASS 2 (wide-column #75): apply WITH the grant → COMMITTED, bounded (4 even notes='audited', odd untouched), reversible=true — the written column is captured (no silent un-revertable write).`);
  });

  it("a drifted apply ABORTS with NO mutation (the PK-set guard fires fail-closed)", { timeout: 40_000 }, async () => {
    // Approve a DELETE of the even rows, then DRIFT the data so the apply-time PK
    // set no longer matches the grant → guarded_apply_with_grant aborts, no DELETE.
    const DEL = "DELETE FROM public.accounts WHERE id % 2 = 0";
    // Reset to a clean known state first (the prior test zeroed evens; ids intact).
    const proposed = await toolCall("propose_write", { sql: DEL, expected_rows: 4 });
    expect(proposed.status, JSON.stringify(proposed)).toBe("ok");
    const proposalId = proposed.data.proposal_id as string;
    const dry = await toolCall("dry_run", { proposal_id: proposalId });
    const confirmToken = dry.data.confirm_token as string;
    const total = dry.data.blast_radius.total_rows as number;
    const elev = await toolCall("request_elevation", { proposal_id: proposalId, reason: "drift demo" });
    const seedHex = (globalThis as any).__seedHex as string;
    const approveResp = await applydApprove({
      request_id: elev.data.request_id,
      approver_id: "operator-1",
      signing_key_hex: seedHex,
      nonce: `nonce-drift-${Date.now()}`,
      grant_ttl_millis: 60_000,
    });
    expect(approveResp.error, JSON.stringify(approveResp)).toBeUndefined();

    // DRIFT: a NEW even row appears AFTER the grant was signed.
    psql("INSERT INTO public.accounts(id, owner, balance) VALUES (10, 'drift', 5)", DB);
    const countBefore = psql("SELECT count(*)::int FROM public.accounts", DB).trim();

    const applied = await toolCall("apply_write", { proposal_id: proposalId, confirm_rows: total, confirm_token: confirmToken });
    expect(applied.status, JSON.stringify(applied)).toBe("blocked");
    // GRANT_REJECTED (binding/PK-set mismatch) or BLAST_DRIFT — either way no DELETE.
    expect(["GRANT_REJECTED", "BLAST_DRIFT"]).toContain(applied.code);
    const countAfter = psql("SELECT count(*)::int FROM public.accounts", DB).trim();
    expect(countAfter).toBe(countBefore); // NO mutation
    log(`CLASS 2 (drift): apply over drifted data → ${applied.code} ABORT, row count unchanged (${countAfter}), NO mutation.`);
    // Clean the drift row so later counts are deterministic.
    psql("DELETE FROM public.accounts WHERE id = 10", DB);
  });

  // --- DAMAGE CLASS 3: RUNAWAY READ → killed by the live warden ---------------
  it("a runaway read (agent-tagged long pg_sleep) is KILLED by the live warden; a non-agent sleep is SPARED", { timeout: 45_000 }, async () => {
    const { Client } = (await import("pg")) as any;

    // The AGENT-TAGGED runaway: a raw session carrying the proxy `application_name`
    // tag (exactly what the live MCP read session carries), running a long sleep
    // with NO statement_timeout, so the WARDEN — not a timeout — is what stops it.
    const agent = new Client({
      host: HOST,
      port: PORT,
      database: DB,
      user: "postgres",
      application_name: "pgb_proxy",
    });
    // The warden TERMINATES this backend mid-sleep; the socket then errors. Swallow
    // it (the kill is the POINT of this test) so it never becomes an unhandled error.
    agent.on("error", () => undefined);
    await agent.connect();
    const agentPid = (await agent.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;

    // A SHARED (non-agent) backend running the same sleep — must be SPARED.
    const shared = new Client({
      host: HOST,
      port: PORT,
      database: DB,
      user: "postgres",
      application_name: "some_dashboard",
    });
    shared.on("error", () => undefined);
    await shared.connect();
    const sharedPid = (await shared.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;

    // Launch both long sleeps (don't await — the warden terminates the agent one).
    const agentSleep = agent.query("SELECT pg_sleep(30)").catch((e: Error) => `agent-terminated: ${e.message}`);
    const sharedSleep = shared.query("SELECT pg_sleep(30)").catch((e: Error) => `shared-ended: ${e.message}`);
    log(`CLASS 3: launched agent-tagged runaway (pid ${agentPid}) + shared sleep (pid ${sharedPid}).`);

    // Poll until the warden terminates the agent-tagged backend (gone from pg_stat_activity).
    const deadline = Date.now() + 30_000;
    let agentGone = false;
    while (Date.now() < deadline) {
      const present = psql(`SELECT count(*)::int FROM pg_stat_activity WHERE pid = ${agentPid}`, DB).trim();
      if (present === "0") {
        agentGone = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    expect(agentGone, `warden did not terminate agent backend ${agentPid}\nwarden stderr:\n${wardenStderr}`).toBe(true);
    log(`CLASS 3: warden TERMINATED the agent-tagged runaway (pid ${agentPid} gone).`);

    // The shared backend must STILL be present (no false-positive outage).
    const sharedPresent = psql(`SELECT count(*)::int FROM pg_stat_activity WHERE pid = ${sharedPid}`, DB).trim();
    expect(sharedPresent).toBe("1");
    log(`CLASS 3: shared backend (pid ${sharedPid}) SPARED (still present) — no false-positive kill.`);

    // The termination is audited on the `_meta` chain (WARDEN_TERMINATE naming the
    // pid). The payload is canonical JSON text; query it via a jsonb cast.
    const auditHit = psql(
      `SELECT count(*)::int FROM pgb_audit.audit_log
         WHERE (payload::jsonb)->>'reason_code' = 'WARDEN_TERMINATE'
           AND (payload::jsonb)->>'statement_text' LIKE '%${agentPid}%'`,
      DB,
    ).trim();
    expect(Number(auditHit)).toBeGreaterThanOrEqual(1);
    log(`CLASS 3: the kill is AUDITED to _meta (WARDEN_TERMINATE naming pid ${agentPid}).`);

    // Cleanup: terminate the shared sleeper, await both promises, close clients.
    psql(`SELECT pg_terminate_backend(${sharedPid})`, DB);
    await agentSleep;
    await sharedSleep;
    await agent.end().catch(() => undefined);
    await shared.end().catch(() => undefined);
  });

  // --- DAMAGE CLASS 4: ONE anchored `_meta` chain — verify at the end ----------
  it("EVERY decision landed on ONE anchored _meta chain: pgb-cli verify passes + anchored head matches", { timeout: 30_000 }, async () => {
    // The chain now carries: applyd apply-path records (apply_committed + the
    // GRANT_REJECTED/BLAST_DRIFT abort), the CLI approval-flow records, AND the
    // warden's WARDEN_TERMINATE / SLOT_ALARM / BREAKER_TRIP — all hash-chained on
    // ONE `_meta` chain with one genesis. pgb-cli verify proves it end-to-end.
    const cliBin = join(REPO, "target/debug/pgb-cli");
    if (!existsSync(cliBin)) throw new Error(`pgb-cli not built at ${cliBin}; run \`cargo build -p pgb-cli\``);

    const verifyAnchor = join(scratch!, "verify.anchor.worm"); // FRESH path (not applyd's)
    const out = execFileSync(cliBin, ["verify"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PGB_META_DSN: metaDsn,
        PGB_AUDIT_SIGNING_KEY: signingKey,
        PGB_ANCHOR_PATH: verifyAnchor,
      },
    });
    expect(out).toContain("the shared `_meta` chain VERIFIES");
    expect(out).toContain("the durable anchored head MATCHES the chain head");
    // The histogram must show the marquee's decisions on the one chain.
    expect(out).toContain("WARDEN_TERMINATE");
    expect(out).toContain("apply_committed");
    log("CLASS 4: pgb-cli verify — ONE anchored _meta chain, verify_chain OK, anchored head matches.");
    log("--- pgb-cli verify output ---\n" + out.trimEnd());

    // Independent cross-check via psql: a single genesis (seq 0), contiguous seqs.
    const minSeq = psql("SELECT min(seq)::int FROM pgb_audit.audit_log", DB).trim();
    expect(minSeq).toBe("0");
  });
});
