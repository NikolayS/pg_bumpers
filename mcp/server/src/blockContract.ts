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
