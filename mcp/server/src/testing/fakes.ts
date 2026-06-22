/**
 * In-memory fakes for the proxy + core boundaries (test infra).
 *
 * These let the toolset tests run without a live proxy/PG while still proving
 * the load-bearing properties:
 *   - `FakeProxyTransport` models the proxy wire: it can return rows OR a
 *     deterministic-floor BLOCK, and it records what was executed (so a test can
 *     assert NO write ran as a side effect of reading hostile data).
 *   - `FakeCore` IS the state authority: proposals/tickets/audit live here with
 *     a deterministic in-memory clock + a checksum-based PK-set guard. The MCP
 *     server holds none of this — that is the statelessness property (SPEC §4).
 *
 * A separate, optional live transport (`PgProxyTransport`) speaks to a real
 * Postgres endpoint and is exercised in the integration test; see pgProxy.ts.
 */
import type { BlockBody } from "../blockContract.js";
import { isReadOnly } from "../classifier.js";
import type { IntentTiers } from "../intent.js";
import type {
  ApplyResult,
  AuditRecord,
  Core,
  DryRunResult,
  ElevationTicket,
  PlanResult,
  ProposalHandle,
  ProxyTransport,
  QueryResult,
  SchemaColumn,
} from "../transport.js";

/** A scripted in-memory proxy. */
export class FakeProxyTransport implements ProxyTransport {
  private queryAnswers = new Map<string, { rows: Record<string, unknown>[]; rowCount: number }>();
  private plans = new Map<string, PlanResult>();
  private schema: SchemaColumn[] = [];
  private nextBlock: BlockBody | undefined;

  /** Statements forwarded to the proxy as reads (for assertions). */
  readonly executedReads: string[] = [];
  /**
   * Writes the proxy was asked to execute. MUST stay empty in injection tests:
   * the MCP read path never executes a write, no matter what data says.
   */
  readonly executedWrites: string[] = [];

  lastQuery: string | undefined;
  /** The T0–T2 intent captured for the most recent read (logged at the wire). */
  lastIntent: IntentTiers | undefined;

  /** Script a read result for an exact SQL string. */
  onQuery(sql: string, result: { rows: Record<string, unknown>[]; rowCount: number }): void {
    this.queryAnswers.set(sql, result);
  }

  /** Make the NEXT query return a deterministic-floor block. */
  blockNext(block: BlockBody): void {
    this.nextBlock = block;
  }

  setSchema(cols: SchemaColumn[]): void {
    this.schema = cols;
  }

  setPlan(sql: string, plan: PlanResult): void {
    this.plans.set(sql, plan);
  }

  async query(sql: string, intent: IntentTiers): Promise<QueryResult> {
    this.lastQuery = sql;
    this.lastIntent = intent;
    this.executedReads.push(sql);
    if (this.nextBlock) {
      const b = this.nextBlock;
      this.nextBlock = undefined;
      return { outcome: "blocked", block: b };
    }
    const answer = this.queryAnswers.get(sql);
    if (answer) return { outcome: "rows", rows: answer.rows, rowCount: answer.rowCount };
    return { outcome: "rows", rows: [], rowCount: 0 };
  }

  async discoverSchema(): Promise<SchemaColumn[]> {
    return this.schema;
  }

  async explain(sql: string): Promise<PlanResult | { blocked: BlockBody }> {
    // Defence-in-depth, mirroring PgProxyTransport.explain: the transport refuses
    // anything not provably a pure read so a write/stacked statement can never
    // reach the `EXPLAIN ... ${sql}` path (which would execute it on the wire).
    if (!isReadOnly(sql)) {
      return {
        blocked: {
          code: "READ_ONLY",
          reason: "the proxy explain path plans read-only statements",
          remedy: "use propose_write → dry_run → apply_write for changes",
          retryable: false,
        },
      };
    }
    if (this.nextBlock) {
      const b = this.nextBlock;
      this.nextBlock = undefined;
      return { blocked: b };
    }
    const plan = this.plans.get(sql);
    // EXPLAIN must NEVER execute the statement — note we do not push to
    // executedWrites here; that is the whole point of explain_plan.
    return plan ?? { plan: "Result", cost: 0 };
  }
}

interface StoredProposal {
  id: string;
  sql: string;
  expectedRows: number | undefined;
  intent: IntentTiers;
  createdAtMillis: number;
  ttlMillis: number;
  // Filled at dry-run: the computed blast radius + the token bound to it.
  dryRun?: { totalRows: number; checksum: string; token: string };
}

interface StoredElevation {
  id: string;
  proposalId: string;
  reason: string;
  createdAtMillis: number;
  ttlMillis: number;
}

const PROPOSAL_TTL_MILLIS = 15 * 60 * 1000;
const ELEVATION_TTL_MILLIS = 30 * 60 * 1000;

/**
 * The state authority fake. Holds all proposal/ticket/audit state with a manual
 * clock so TTL behavior is deterministic. Mirrors the Rust crates' contracts
 * (clone-orchestrator proposal TTL, PK-set checksum guard, §14 elevation, audit).
 */
export class FakeCore implements Core {
  private proposals = new Map<string, StoredProposal>();
  private elevations = new Map<string, StoredElevation>();
  private audit: AuditRecord[] = [];
  private seq = 0;
  private nowMillis = 0;
  private idCounter = 0;
  private approvalBlock: BlockBody | undefined;
  private lastIntentLogged: IntentTiers | undefined;

  /** Advance the deterministic clock (drives TTL expiry in tests). */
  advance(millis: number): void {
    this.nowMillis += millis;
  }

  /** Force the next apply to be blocked with a recoverable approval remedy. */
  requireApprovalOnApply(code: string, reason: string): void {
    this.approvalBlock = {
      code,
      reason,
      // Recoverable: name request_elevation as the next step (SPEC §14.3).
      remedy: "open an approval ticket via request_elevation, then await the grant",
      retryable: true,
    };
  }

  hasProposal(id: string): boolean {
    const p = this.proposals.get(id);
    return !!p && !this.isExpired(p.createdAtMillis, p.ttlMillis);
  }

  hasElevation(id: string): boolean {
    const e = this.elevations.get(id);
    return !!e && !this.isExpired(e.createdAtMillis, e.ttlMillis);
  }

  /** The most recently logged T0–T2 intent (proves logged-only capture). */
  lastIntent(): IntentTiers | undefined {
    return this.lastIntentLogged;
  }

  async propose(
    sql: string,
    expectedRows: number | undefined,
    intent: IntentTiers,
  ): Promise<ProposalHandle> {
    const id = this.mintId("p");
    this.proposals.set(id, {
      id,
      sql,
      expectedRows,
      intent,
      createdAtMillis: this.nowMillis,
      ttlMillis: PROPOSAL_TTL_MILLIS,
    });
    this.lastIntentLogged = intent;
    this.record("PROPOSE", intent);
    return { proposal_id: id, ttl_millis: PROPOSAL_TTL_MILLIS };
  }

  async dryRun(proposalId: string): Promise<DryRunResult | { notFound: true }> {
    const p = this.proposals.get(proposalId);
    if (!p || this.isExpired(p.createdAtMillis, p.ttlMillis)) return { notFound: true };
    // Model the blast radius: use the caller's expected_rows as the count (a real
    // dry-run measures it on the clone). The checksum is derived from the count +
    // statement so a drift (different count) changes it — the PK-set guard basis.
    const totalRows = p.expectedRows ?? 0;
    const checksum = `sha256:${fnv1a(`${p.sql}|${totalRows}`)}`;
    const token = this.mintId("ct");
    p.dryRun = { totalRows, checksum, token };
    this.record("DRY_RUN", p.intent);
    return {
      blast_radius: { total_rows: totalRows, pk_set_checksum: checksum, reversible: true },
      risk: {
        verdict: "ALLOW",
        reason: "MVP stub: risk engine returns Allow (SPEC §11.5)",
        confidence: 1.0,
      },
      confirm_token: token,
    };
  }

  async apply(args: {
    proposalId: string;
    confirmRows: number;
    confirmToken?: string;
  }): Promise<ApplyResult | { notFound: true }> {
    const p = this.proposals.get(args.proposalId);
    if (!p || this.isExpired(p.createdAtMillis, p.ttlMillis)) return { notFound: true };
    if (!p.dryRun) {
      return {
        outcome: "blocked",
        block: {
          code: "DRY_RUN_REQUIRED",
          reason: "apply requires a prior dry_run to establish the PK-set guard",
          remedy: "call dry_run on this proposal first",
          retryable: true,
        },
      };
    }
    // confirm_rows guard: the caller's confirmation must match the dry-run count
    // (the PK-set/row-estimate forcing function — SPEC §4, §10.2).
    if (args.confirmRows !== p.dryRun.totalRows) {
      return {
        outcome: "blocked",
        block: {
          code: "CONFIRM_MISMATCH",
          reason: `confirm_rows ${args.confirmRows} ≠ dry-run affected rows ${p.dryRun.totalRows}`,
          remedy: "re-run dry_run and confirm the exact reported row count",
          retryable: true,
        },
      };
    }
    // A floor parameter-block (e.g. row-budget) is recoverable via elevation.
    if (this.approvalBlock) {
      const b = this.approvalBlock;
      this.record("BLOCK", p.intent);
      return { outcome: "blocked", block: b };
    }
    this.record("APPLY", p.intent);
    // Single-use: consume the proposal so it cannot be replayed.
    this.proposals.delete(args.proposalId);
    return { outcome: "applied", reversible: true };
  }

  async requestElevation(proposalId: string, reason: string): Promise<ElevationTicket> {
    const id = this.mintId("req");
    this.elevations.set(id, {
      id,
      proposalId,
      reason,
      createdAtMillis: this.nowMillis,
      ttlMillis: ELEVATION_TTL_MILLIS,
    });
    return { request_id: id, ttl_millis: ELEVATION_TTL_MILLIS };
  }

  async getAudit(limit: number): Promise<AuditRecord[]> {
    return this.audit.slice(-limit);
  }

  private record(decision: string, intent: IntentTiers): void {
    this.audit.push({
      seq: this.seq++,
      decision,
      statement_class: intent.t1.statement_class,
      intent,
    });
  }

  private mintId(prefix: string): string {
    this.idCounter += 1;
    return `${prefix}-${this.idCounter.toString(16).padStart(8, "0")}`;
  }

  private isExpired(createdAtMillis: number, ttlMillis: number): boolean {
    return this.nowMillis - createdAtMillis >= ttlMillis;
  }
}

/**
 * A tiny FNV-1a hash (dependency-free), matching the Rust proposal id style.
 * Hashes the UTF-8 bytes of `s`; encoded inline so no platform global (Buffer /
 * TextEncoder) is needed, keeping the build free of @types/node.
 */
function fnv1a(s: string): string {
  let h = 0xcbf29ce4_84222325n;
  const mask = 0xffffffff_ffffffffn;
  for (const b of utf8Bytes(s)) {
    h ^= BigInt(b);
    h = (h * 0x00000100_000001b3n) & mask;
  }
  return h.toString(16).padStart(16, "0");
}

/** Encode a string to UTF-8 bytes without any platform global. */
function utf8Bytes(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let cp = s.charCodeAt(i);
    // Combine a surrogate pair into a single code point.
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        i++;
      }
    }
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    }
  }
  return out;
}
