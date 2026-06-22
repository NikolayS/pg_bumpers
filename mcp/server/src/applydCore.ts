/**
 * `ApplydCore` — the PRODUCTION `Core` (SPEC §3, §4; issue #67).
 *
 * This is the production peer of the in-memory `FakeCore`: a thin Unix-socket
 * JSON-RPC client that maps the MCP server's `Core` calls
 * (`propose`/`dryRun`/`apply`/`requestElevation`/`getAudit`) onto the Rust
 * `pgb-applyd` daemon, which owns the write-safety STATE and drives the real
 * grant-gated apply floor (`guarded_apply_with_grant`). The MCP server holds NONE
 * of this state — that is the §4 statelessness property.
 *
 * Honesty contract (SPEC §3): the MCP server + this client are COOPERATIVE, NOT a
 * security boundary. The deterministic floor stays in Rust behind the socket; a
 * compromised MCP server cannot invent privilege, because every write effect must
 * pass through `pgb-applyd` (which re-derives the apply from its OWN stored
 * proposal record — the agent cannot swap statement/role/session at apply time).
 *
 * Every applyd denial is a JSON-RPC error carrying the recoverable-block contract
 * `{data.code, message, data.remedy, data.retryable}`; this client translates it
 * into the existing `ApplyResult{outcome:"blocked", block}` / `{notFound:true}`
 * shape so every denial stays a recoverable contract the server relays.
 *
 * Transport: Node `net` (Unix socket) + line framing via `readline`. NO new
 * dependencies — both are Node built-ins (keeps `license-check` green).
 */
import { createConnection, type Socket } from "node:net";
import { createInterface, type Interface } from "node:readline";

import type { BlockBody } from "./blockContract.js";
import type { IntentTiers } from "./intent.js";
import type {
  ApplyResult,
  AuditRecord,
  Core,
  DryRunResult,
  ElevationTicket,
  ProposalHandle,
} from "./transport.js";

/** Config for the applyd socket client. */
export interface ApplydCoreConfig {
  /** The Unix-domain socket path `pgb-applyd` binds (PGB_APPLYD_SOCKET). */
  socketPath: string;
  /** The DB role writes bind to (pinned into the proposal record). */
  role: string;
  /** The session/principal id writes bind to (pinned; defeats cross-session replay). */
  sessionId: string;
  /** Per-call timeout (ms) for a socket round-trip. */
  timeoutMs?: number;
}

/** One pending JSON-RPC call awaiting its response line. */
interface Pending {
  resolve: (value: JsonRpcResponse) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** The JSON-RPC error object applyd returns (with the recoverable block data). */
interface JsonRpcError {
  code: number;
  message: string;
  data?: { code: string; remedy: string; retryable: boolean };
}

/** A JSON-RPC response line. */
interface JsonRpcResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: JsonRpcError;
}

/**
 * A persistent line-framed JSON-RPC connection to `pgb-applyd`. One socket,
 * sequential ids; each response line resolves its pending call.
 */
class ApplydConnection {
  private socket: Socket | undefined;
  private rl: Interface | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private connecting: Promise<void> | undefined;

  constructor(
    private readonly socketPath: string,
    private readonly timeoutMs: number,
  ) {}

  private async ensureConnected(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return;
    if (this.connecting) return this.connecting;
    this.connecting = new Promise<void>((resolve, reject) => {
      const sock = createConnection(this.socketPath);
      sock.setEncoding("utf8");
      sock.once("connect", () => {
        this.socket = sock;
        // Line framing: each '\n'-delimited line is one JSON-RPC response.
        this.rl = createInterface({ input: sock });
        this.rl.on("line", (line) => this.onLine(line));
        sock.on("close", () => this.onClose(new Error("applyd socket closed")));
        sock.on("error", (err) => this.onClose(err));
        resolve();
      });
      sock.once("error", (err) => {
        this.connecting = undefined;
        reject(err);
      });
    });
    try {
      await this.connecting;
    } finally {
      this.connecting = undefined;
    }
  }

  private onLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;
    let resp: JsonRpcResponse;
    try {
      resp = JSON.parse(trimmed) as JsonRpcResponse;
    } catch {
      return; // ignore an unparseable line (fail-closed: the call times out)
    }
    const pend = this.pending.get(resp.id);
    if (!pend) return;
    this.pending.delete(resp.id);
    clearTimeout(pend.timer);
    pend.resolve(resp);
  }

  private onClose(err: Error): void {
    this.socket = undefined;
    this.rl = undefined;
    for (const [, pend] of this.pending) {
      clearTimeout(pend.timer);
      pend.reject(err);
    }
    this.pending.clear();
  }

  /** Send a JSON-RPC request and await its response line. */
  async call(method: string, params: unknown): Promise<JsonRpcResponse> {
    await this.ensureConnected();
    const id = this.nextId++;
    const request = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise<JsonRpcResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`applyd ${method} timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket!.write(request, (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  /** Close the underlying socket. */
  close(): void {
    this.rl?.close();
    this.socket?.destroy();
    this.socket = undefined;
    this.rl = undefined;
  }
}

/**
 * The production `Core`, wired to `pgb-applyd` over its Unix socket. Maps a
 * JSON-RPC error to the existing recoverable-block shape so every denial stays a
 * contract the server relays verbatim.
 */
export class ApplydCore implements Core {
  private readonly conn: ApplydConnection;

  constructor(private readonly config: ApplydCoreConfig) {
    this.conn = new ApplydConnection(config.socketPath, config.timeoutMs ?? 10_000);
  }

  /** Close the socket (deployment teardown). */
  close(): void {
    this.conn.close();
  }

  async propose(
    sql: string,
    expectedRows: number | undefined,
    _intent: IntentTiers,
  ): Promise<ProposalHandle> {
    const resp = await this.conn.call("propose", {
      sql,
      expected_rows: expectedRows,
      role: this.config.role,
      session_id: this.config.sessionId,
    });
    if (resp.error) {
      // propose can refuse a non-rehearsable shape; the server surfaces the
      // proposal-not-found path elsewhere, but propose itself only fails on a
      // refusal. Throw so the caller sees the structured reason.
      throw new ApplydError(resp.error);
    }
    const r = resp.result as { proposal_id: string; ttl_millis: number };
    return { proposal_id: r.proposal_id, ttl_millis: r.ttl_millis };
  }

  async dryRun(proposalId: string): Promise<DryRunResult | { notFound: true }> {
    const resp = await this.conn.call("dry_run", { proposal_id: proposalId });
    if (resp.error) {
      if (resp.error.data?.code === "PROPOSAL_NOT_FOUND") return { notFound: true };
      throw new ApplydError(resp.error);
    }
    const r = resp.result as {
      total_rows: number;
      pk_set_checksum: string;
      reversible: boolean;
      confirm_token: string;
    };
    return {
      blast_radius: {
        total_rows: r.total_rows,
        pk_set_checksum: r.pk_set_checksum,
        reversible: r.reversible,
      },
      risk: {
        verdict: "ALLOW",
        reason: "MVP stub: risk engine returns Allow (SPEC §11.5)",
        confidence: 1.0,
      },
      confirm_token: r.confirm_token,
    };
  }

  async apply(args: {
    proposalId: string;
    confirmRows: number;
    confirmToken?: string;
  }): Promise<ApplyResult | { notFound: true }> {
    const resp = await this.conn.call("apply", {
      proposal_id: args.proposalId,
      confirm_rows: args.confirmRows,
      confirm_token: args.confirmToken,
    });
    if (resp.error) {
      if (resp.error.data?.code === "PROPOSAL_NOT_FOUND") return { notFound: true };
      // Every other denial is a RECOVERABLE block contract (APPROVAL_REQUIRED,
      // GRANT_REJECTED, CONFIRM_MISMATCH, BLAST_DRIFT, …): relay it verbatim.
      return { outcome: "blocked", block: blockBodyOf(resp.error) };
    }
    const r = resp.result as { applied: boolean; rows_written: number; reversible: boolean };
    return { outcome: "applied", reversible: r.reversible };
  }

  async requestElevation(proposalId: string, reason: string): Promise<ElevationTicket> {
    const resp = await this.conn.call("request_elevation", {
      proposal_id: proposalId,
      reason,
    });
    if (resp.error) throw new ApplydError(resp.error);
    const r = resp.result as { request_id: string; ttl_millis: number };
    return { request_id: r.request_id, ttl_millis: r.ttl_millis };
  }

  async getAudit(limit: number): Promise<AuditRecord[]> {
    const resp = await this.conn.call("get_audit", { limit });
    if (resp.error) throw new ApplydError(resp.error);
    const r = resp.result as { records: { seq: number; decision: string; reason_code: string }[] };
    return r.records.map((rec) => ({
      seq: rec.seq,
      decision: rec.decision,
      statement_class: rec.reason_code,
    }));
  }
}

/** Map a JSON-RPC error to the server's recoverable `BlockBody`. */
function blockBodyOf(error: JsonRpcError): BlockBody {
  return {
    code: error.data?.code ?? "APPLYD_ERROR",
    reason: error.message,
    remedy: error.data?.remedy ?? "see the applyd error for the next step",
    retryable: error.data?.retryable ?? false,
  };
}

/** A structured applyd error (carries the recoverable-block fields). */
export class ApplydError extends Error {
  readonly code: string;
  readonly remedy: string;
  readonly retryable: boolean;
  constructor(error: JsonRpcError) {
    super(error.message);
    this.name = "ApplydError";
    this.code = error.data?.code ?? "APPLYD_ERROR";
    this.remedy = error.data?.remedy ?? "";
    this.retryable = error.data?.retryable ?? false;
  }
}
