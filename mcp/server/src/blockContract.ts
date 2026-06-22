/**
 * pg_bumpers MCP server — block contract (skeleton).
 *
 * The MCP server is the agent-facing intent/UX layer (SPEC.md §3 layer 3, §4).
 * It is cooperative, not a security boundary: every tool executes *through* the
 * proxy. Blocks must be recoverable, so every block returns a structured
 * contract `{status, code, reason, remedy, retryable}`. The real tool surface
 * (`whoami`, `query`, `propose_write`, `dry_run`, `apply_write`, ...) lands in S4.
 *
 * This file only carries the block-contract shape + a tiny constructor so the
 * skeleton compiles and is exercised by a real test.
 */

/** Structured, recoverable block returned by an MCP tool (SPEC.md §4). */
export interface BlockContract {
  /** Always "blocked" for this contract. */
  readonly status: "blocked";
  /** Stable machine-readable code (e.g. "READ_ONLY", "BUDGET_EXCEEDED"). */
  readonly code: string;
  /** Human-readable reason. */
  readonly reason: string;
  /** Actionable path out (e.g. "request elevation via pgb-cli"). */
  readonly remedy: string;
  /** Whether retrying the same action could succeed without intervention. */
  readonly retryable: boolean;
}

/**
 * Build a block contract. Fail-closed posture: `retryable` defaults to false so
 * a block never implies "just try again" unless explicitly marked recoverable.
 */
export function block(
  code: string,
  reason: string,
  remedy: string,
  retryable = false,
): BlockContract {
  return { status: "blocked", code, reason, remedy, retryable };
}

/** The non-block fields of a block, as the proxy/core hand them up the stack. */
export type BlockBody = Omit<BlockContract, "status">;

/** Re-wrap a raw block body (e.g. from the proxy boundary) as a full contract. */
export function blockFrom(body: BlockBody): BlockContract {
  return {
    status: "blocked",
    code: body.code,
    reason: body.reason,
    remedy: body.remedy,
    retryable: body.retryable ?? false,
  };
}

/**
 * Success envelope returned by an MCP tool. The payload is parameterized so each
 * tool declares its own typed `data`. Result data lives ONLY under `data` and is
 * never hoisted into the envelope — that separation is the structural half of the
 * prompt-injection-via-data defense (SPEC §4): a row can never masquerade as a
 * control field of the response.
 */
export interface Ok<T> {
  readonly status: "ok";
  readonly data: T;
}

/** Build a success envelope around an opaque, untrusted-data payload. */
export function ok<T>(data: T): Ok<T> {
  return { status: "ok", data };
}

/** Every MCP tool returns either a success envelope or a structured block. */
export type ToolResult<T> = Ok<T> | BlockContract;

/** Narrowing guard: is this tool result a structured block (a denial)? */
export function isBlock<T>(r: ToolResult<T>): r is BlockContract {
  return r.status === "blocked";
}
