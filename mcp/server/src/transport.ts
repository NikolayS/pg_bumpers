/**
 * The boundaries the MCP server talks to (SPEC §3, §4).
 *
 * The MCP server adds NO privilege of its own. Two collaborators model the real
 * system:
 *
 *   - `ProxyTransport` — the wire to the Apache Rust proxy. EVERY read executes
 *     through this (the proxy + warden + WALL are the actual security boundary).
 *     The transport can return a structured BLOCK (the proxy's deterministic
 *     floor denying a read), which the server surfaces verbatim. A live impl
 *     speaks pgwire to the proxy; tests use an in-memory fake (and one optional
 *     live impl against a throwaway PG18 standing in for the proxied backend).
 *
 *   - `Core` — the stateful authority (crates/{core,policy,clone-orchestrator,
 *     audit}). Proposal/ticket/grant state and the hash-chained audit live HERE,
 *     TTL'd — NEVER in MCP memory (SPEC §4 "stateless"). The MCP server only
 *     forwards typed requests and relays typed results.
 *
 * Keeping these as interfaces (not concrete clients) is what makes the server
 * stateless and the boundary swappable: a buggy/compromised MCP server cannot
 * invent privilege because every effect must pass through one of these seams.
 */
import type { BlockBody } from "./blockContract.js";
import type { IntentTiers } from "./intent.js";
import type { RiskVerdict } from "./riskEngine.js";

/** A row returned by a read. Opaque, untrusted DATA — never an instruction. */
export type Row = Record<string, unknown>;

/** A successful read result from the proxy. */
export interface QueryOk {
  outcome: "rows";
  rows: Row[];
  rowCount: number;
}

/** The proxy denied the read at the deterministic floor. */
export interface QueryBlocked {
  outcome: "blocked";
  block: BlockBody;
}

export type QueryResult = QueryOk | QueryBlocked;

/** One column of schema returned by discover_schema. */
export interface SchemaColumn {
  schema: string;
  table: string;
  column: string;
  type: string;
}

/** An EXPLAIN (never EXPLAIN ANALYZE) plan — the statement is NOT executed. */
export interface PlanResult {
  plan: string;
  cost: number;
}

/** The wire to the proxy. Reads only — writes go through Core's apply path. */
export interface ProxyTransport {
  /** Execute a read-only statement through the proxy. */
  query(sql: string, intent: IntentTiers): Promise<QueryResult>;
  /** Read catalog/schema info through the proxy (a read). */
  discoverSchema(): Promise<SchemaColumn[]>;
  /** EXPLAIN (not ANALYZE) a statement through the proxy. Does not execute it. */
  explain(sql: string): Promise<PlanResult | { blocked: BlockBody }>;
}

/** The blast-radius preview returned by Core's dry-run (SPEC §10.1, subset). */
export interface BlastRadius {
  total_rows: number;
  /** Affected-PK-set checksum — the guard's basis (SPEC §10.2), not row count. */
  pk_set_checksum: string;
  reversible: boolean;
}

/** Core's dry-run output: blast radius + the (stub) risk verdict + a token. */
export interface DryRunResult {
  blast_radius: BlastRadius;
  risk: RiskVerdict;
  /** Opaque token binding this dry-run; the caller echoes it back at apply. */
  confirm_token: string;
}

/** A proposal handle minted by Core (state lives in Core, TTL'd). */
export interface ProposalHandle {
  proposal_id: string;
  ttl_millis: number;
}

/** An approval-request ticket minted by Core (SPEC §14.3). */
export interface ElevationTicket {
  request_id: string;
  ttl_millis: number;
}

/** One audit record (hash-chained in the _meta DB — SPEC §4). */
export interface AuditRecord {
  seq: number;
  decision: string;
  statement_class?: string;
  intent?: IntentTiers;
}

/**
 * Outcome of Core's apply path. Either the write was applied (bounded +
 * reversible) or it was blocked with a recoverable block body (e.g.
 * APPROVAL_REQUIRED, CONFIRM_MISMATCH) the server relays as a contract.
 */
export type ApplyResult =
  | { outcome: "applied"; reversible: boolean }
  | { outcome: "blocked"; block: BlockBody };

/** The stateful authority. The MCP server holds NONE of this state itself. */
export interface Core {
  /** Mint a proposal (statement + optional expected_rows), TTL'd. */
  propose(sql: string, expectedRows: number | undefined, intent: IntentTiers): Promise<ProposalHandle>;
  /** Rehearse a proposal on a clone / guarded path → blast radius preview. */
  dryRun(proposalId: string): Promise<DryRunResult | { notFound: true }>;
  /**
   * Apply a previously dry-run proposal. The caller MUST pass `confirmRows`
   * (the confirm_rows forcing function) matching the dry-run's PK-set/row count;
   * Core re-checks the PK-set guard at apply time.
   */
  apply(args: {
    proposalId: string;
    confirmRows: number;
    confirmToken?: string;
  }): Promise<ApplyResult | { notFound: true }>;
  /** Create an approval-request ticket for a blocked proposal (SPEC §14.3). */
  requestElevation(proposalId: string, reason: string): Promise<ElevationTicket>;
  /** Read the session's hash-chained audit records (through Core/_meta). */
  getAudit(limit: number): Promise<AuditRecord[]>;
}
