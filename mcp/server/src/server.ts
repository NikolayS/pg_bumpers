/**
 * The minimal MCP server — the §4/§11 toolset, executing THROUGH the proxy.
 *
 * SPEC §3: layer 3 (MCP) is **cooperative, NOT a security boundary**. This
 * server adds no privilege: every read goes through `ProxyTransport` (proxy +
 * warden + WALL = the real boundary) and every write goes through `Core`'s
 * propose→dry_run→apply path. It is **stateless** — proposal/ticket/audit state
 * lives in Core (TTL'd), never in this process.
 *
 * Invariants this file upholds:
 *   - Every denial returns the block contract {status,code,reason,remedy,
 *     retryable}; a blocked write returns a *recoverable* remedy (e.g.
 *     APPROVAL_REQUIRED + request_elevation), never an opaque error.
 *   - `confirm_rows` is a forcing function: apply_write without a matching
 *     confirmation is blocked.
 *   - Result data can NEVER widen capability: rows are returned only under
 *     `data`, never interpreted as instructions or hoisted into the envelope.
 *   - The RiskEngine is a stub returning Allow; T0–T2 intent is captured/logged.
 */
import {
  block,
  blockFrom,
  isBlock,
  ok,
  type BlockContract,
  type ToolResult,
} from "./blockContract.js";
import { captureIntent, type IntentTiers } from "./intent.js";
import { isReadOnly } from "./classifier.js";
import { AllowStub, type RiskEngine } from "./riskEngine.js";
import type {
  AuditRecord,
  BlastRadius,
  Core,
  ProxyTransport,
  Row,
  SchemaColumn,
} from "./transport.js";

/** The exactly-nine MCP tool names (SPEC §4). */
export const TOOL_NAMES = [
  "whoami",
  "discover_schema",
  "query",
  "explain_plan",
  "propose_write",
  "dry_run",
  "apply_write",
  "request_elevation",
  "get_audit",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

/** A minimal tool descriptor (name + one-line purpose) for listing. */
export interface ToolDescriptor {
  name: ToolName;
  description: string;
}

const TOOL_DESCRIPTIONS: Record<ToolName, string> = {
  whoami: "Report the agent's role and posture (MCP is not a security boundary).",
  discover_schema: "List accessible schema (tables/columns) through the proxy.",
  query: "Run a read-only statement through the proxy (cost/byte budgeted).",
  explain_plan: "EXPLAIN (never ANALYZE) a statement through the proxy.",
  propose_write: "Create a TTL'd write proposal in core (state lives in core).",
  dry_run: "Rehearse a proposal → blast radius incl. affected-PK-set checksum.",
  apply_write: "Apply a dry-run proposal under the PK-set guard (needs confirm_rows).",
  request_elevation: "Open an approval-request ticket for a blocked action (§14).",
  get_audit: "Read the hash-chained audit for this session.",
};

/** Config the server is constructed with. */
export interface ServerConfig {
  transport: ProxyTransport;
  core: Core;
  /** The authenticated role (T0). The server never elevates beyond it. */
  role: string;
  /** Optional risk engine; defaults to the MVP Allow stub (SPEC §11.5). */
  riskEngine?: RiskEngine;
}

/** Typed payloads of each tool's success envelope. */
export interface WhoamiData {
  role: string;
  /** Honesty contract: the MCP server is NOT the security boundary (§3). */
  security_boundary: false;
  tools: ToolName[];
}
export interface QueryData {
  rows: Row[];
  rowCount: number;
}
export interface SchemaData {
  columns: SchemaColumn[];
}
export interface PlanData {
  plan: string;
  cost: number;
}
export interface ProposeData {
  proposal_id: string;
  ttl_millis: number;
}
export interface DryRunData {
  blast_radius: BlastRadius;
  risk: { verdict: string; reason: string; confidence: number };
  confirm_token: string;
}
export interface ApplyData {
  applied: true;
  reversible: boolean;
}
export interface ElevationData {
  request_id: string;
  ttl_millis: number;
}
export interface AuditData {
  records: AuditRecord[];
}

/** The MCP server surface used by tests and the (future) stdio/JSON-RPC shell. */
export interface McpServer {
  listTools(): ToolDescriptor[];
  call(name: "whoami", args: Record<string, never>): Promise<ToolResult<WhoamiData>>;
  call(
    name: "query",
    args: { sql: string; application_name?: string },
  ): Promise<ToolResult<QueryData>>;
  call(name: "discover_schema", args: Record<string, never>): Promise<ToolResult<SchemaData>>;
  call(name: "explain_plan", args: { sql: string }): Promise<ToolResult<PlanData>>;
  call(
    name: "propose_write",
    args: { sql: string; expected_rows?: number; application_name?: string },
  ): Promise<ToolResult<ProposeData>>;
  call(name: "dry_run", args: { proposal_id: string }): Promise<ToolResult<DryRunData>>;
  call(
    name: "apply_write",
    args: { proposal_id: string; confirm_rows?: number; confirm_token?: string },
  ): Promise<ToolResult<ApplyData>>;
  call(
    name: "request_elevation",
    args: { proposal_id: string; reason: string },
  ): Promise<ToolResult<ElevationData>>;
  call(name: "get_audit", args: { limit?: number }): Promise<ToolResult<AuditData>>;
  // Fallback signature for unknown names / dynamic dispatch.
  call(name: string, args: Record<string, unknown>): Promise<ToolResult<unknown>>;
}

/** Construct a stateless MCP server bound to a proxy transport + core. */
export function createServer(config: ServerConfig): McpServer {
  const { transport, core, role } = config;
  const risk: RiskEngine = config.riskEngine ?? new AllowStub();
  // Whether a read has happened this session (T2 reads_before_write signal).
  // This is a tiny per-session *observation* for logged intent only — NOT
  // proposal/ticket state (which lives in core). It never gates anything.
  let sawRead = false;

  function intentFor(sql: string, applicationName?: string): IntentTiers {
    return captureIntent({
      role,
      sql,
      applicationName,
      readsBeforeWrite: sawRead,
    });
  }

  async function whoami(): Promise<ToolResult<WhoamiData>> {
    return ok<WhoamiData>({
      role,
      security_boundary: false,
      tools: [...TOOL_NAMES],
    });
  }

  async function query(args: {
    sql: string;
    application_name?: string;
  }): Promise<ToolResult<QueryData>> {
    const intent = intentFor(args.sql, args.application_name);
    // Cooperative fast-path: an obvious write to the read tool gets a friendly,
    // recoverable block pointing at propose_write. The proxy would reject it too
    // (the real guarantee); this just avoids a pointless round-trip.
    if (!isReadOnly(args.sql)) {
      return block(
        "READ_ONLY",
        "the query tool runs read-only statements; this looks like a write/DDL",
        "use propose_write → dry_run → apply_write for changes",
        false,
      );
    }
    const res = await transport.query(args.sql, intent);
    if (res.outcome === "blocked") {
      // Surface the proxy's deterministic-floor denial verbatim as a contract.
      return blockFrom(res.block);
    }
    sawRead = true;
    return ok<QueryData>({ rows: res.rows, rowCount: res.rowCount });
  }

  async function discoverSchema(): Promise<ToolResult<SchemaData>> {
    sawRead = true;
    return ok<SchemaData>({ columns: await transport.discoverSchema() });
  }

  async function explainPlan(args: { sql: string }): Promise<ToolResult<PlanData>> {
    // explain_plan "plans, never executes" (its contract). Mirror the query tool
    // EXACTLY: a write/DDL or a stacked statement must NEVER reach the proxy's
    // `EXPLAIN ... ${sql}` path (which would EXECUTE the second statement). The
    // classifier is fail-closed: anything not provably a pure read is blocked
    // here with the same recoverable contract the query tool returns.
    if (!isReadOnly(args.sql)) {
      return block(
        "READ_ONLY",
        "explain_plan plans read-only statements; this looks like a write/DDL or stacked statement",
        "use propose_write → dry_run → apply_write for changes",
        false,
      );
    }
    const res = await transport.explain(args.sql);
    if ("blocked" in res) return blockFrom(res.blocked);
    return ok<PlanData>({ plan: res.plan, cost: res.cost });
  }

  async function proposeWrite(args: {
    sql: string;
    expected_rows?: number;
    application_name?: string;
  }): Promise<ToolResult<ProposeData>> {
    const intent = intentFor(args.sql, args.application_name);
    const handle = await core.propose(args.sql, args.expected_rows, intent);
    return ok<ProposeData>({ proposal_id: handle.proposal_id, ttl_millis: handle.ttl_millis });
  }

  async function dryRun(args: { proposal_id: string }): Promise<ToolResult<DryRunData>> {
    const res = await core.dryRun(args.proposal_id);
    if ("notFound" in res) {
      return block(
        "PROPOSAL_NOT_FOUND",
        "no live proposal with that id (unknown or TTL-expired)",
        "call propose_write again to mint a fresh proposal",
        false,
      );
    }
    // The risk verdict is captured here; the MVP stub always returns Allow. It is
    // logged into the record and never loosens the deterministic floor.
    const verdict = risk.assess({
      sql: "",
      measured_stats: { rows_affected: res.blast_radius.total_rows },
    });
    return ok<DryRunData>({
      blast_radius: res.blast_radius,
      risk: verdict,
      confirm_token: res.confirm_token,
    });
  }

  async function applyWrite(args: {
    proposal_id: string;
    confirm_rows?: number;
    confirm_token?: string;
  }): Promise<ToolResult<ApplyData>> {
    // confirm_rows forcing function (SPEC §4): the caller MUST confirm the
    // affected PK-set/row estimate before apply. Absence ≠ "just apply".
    if (args.confirm_rows === undefined) {
      return block(
        "CONFIRM_REQUIRED",
        "apply requires confirm_rows: confirm the dry-run's affected row count first",
        "re-call apply_write with confirm_rows set to the dry_run blast_radius.total_rows",
        true,
      );
    }
    const res = await core.apply({
      proposalId: args.proposal_id,
      confirmRows: args.confirm_rows,
      confirmToken: args.confirm_token,
    });
    if ("notFound" in res) {
      return block(
        "PROPOSAL_NOT_FOUND",
        "no live proposal with that id (unknown or TTL-expired)",
        "call propose_write again, then dry_run, then apply_write",
        false,
      );
    }
    if (res.outcome === "blocked") {
      // A blocked write returns a RECOVERABLE remedy, not an opaque error.
      return blockFrom(res.block);
    }
    return ok<ApplyData>({ applied: true, reversible: res.reversible });
  }

  async function requestElevation(args: {
    proposal_id: string;
    reason: string;
  }): Promise<ToolResult<ElevationData>> {
    const ticket = await core.requestElevation(args.proposal_id, args.reason);
    return ok<ElevationData>({ request_id: ticket.request_id, ttl_millis: ticket.ttl_millis });
  }

  async function getAudit(args: { limit?: number }): Promise<ToolResult<AuditData>> {
    const limit = clampLimit(args.limit);
    return ok<AuditData>({ records: await core.getAudit(limit) });
  }

  const handlers: Record<ToolName, (args: Record<string, unknown>) => Promise<ToolResult<unknown>>> = {
    whoami: () => whoami(),
    query: (a) => query(a as { sql: string; application_name?: string }),
    discover_schema: () => discoverSchema(),
    explain_plan: (a) => explainPlan(a as { sql: string }),
    propose_write: (a) =>
      proposeWrite(a as { sql: string; expected_rows?: number; application_name?: string }),
    dry_run: (a) => dryRun(a as { proposal_id: string }),
    apply_write: (a) =>
      applyWrite(a as { proposal_id: string; confirm_rows?: number; confirm_token?: string }),
    request_elevation: (a) => requestElevation(a as { proposal_id: string; reason: string }),
    get_audit: (a) => getAudit(a as { limit?: number }),
  };

  function call(name: string, args: Record<string, unknown>): Promise<ToolResult<unknown>> {
    const handler = handlers[name as ToolName];
    if (!handler) {
      return Promise.resolve(
        unknownTool(name) satisfies BlockContract as ToolResult<unknown>,
      );
    }
    return handler(args ?? {});
  }

  return {
    listTools: () => TOOL_NAMES.map((name) => ({ name, description: TOOL_DESCRIPTIONS[name] })),
    call: call as McpServer["call"],
  };
}

/** Block for an unknown tool name (fail-closed: unknown ⇒ denied). */
function unknownTool(name: string): BlockContract {
  return block(
    "UNKNOWN_TOOL",
    `no such tool: ${name}`,
    `call one of: ${TOOL_NAMES.join(", ")}`,
    false,
  );
}

/** Bound get_audit's limit to a sane window (fail-closed default). */
function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit) || limit <= 0) return 50;
  return Math.min(Math.floor(limit), 1000);
}

export { isBlock };
