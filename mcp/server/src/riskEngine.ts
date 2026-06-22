/**
 * The RiskEngine seam (SPEC §10.10, §11.1, §11.5, §15.3) — TS mirror of
 * `crates/policy/src/risk.rs`.
 *
 * One-way door: the interface is pinned now so the rest of the system can depend
 * on it, even though the real LLM gating engine is fast-follow (§15.2). In the
 * MVP the only implementation is `AllowStub`, which ALWAYS returns `Allow`
 * (§11.5) — the deterministic floor (proxy + WALL), not this engine, is the
 * safety guarantee in v1.
 *
 * Tighten-only contract (§11.1): a conforming engine may only return a verdict
 * `>=` the deterministic floor (ALLOW < ESCALATE < HOLD < BLOCK). It can never
 * loosen below the floor. Its inputs are untrusted; its output is structured and
 * tighten-only, so it can never widen capability.
 */
import type { IntentTiers } from "./intent.js";

/** The risk-plane verdict ladder, least → most restrictive (SPEC §13.4 R2). */
export type Verdict = "ALLOW" | "ESCALATE" | "HOLD" | "BLOCK";

/** Numeric rank so callers can take the *tighter* (max) of two verdicts. */
const VERDICT_RANK: Record<Verdict, number> = {
  ALLOW: 0,
  ESCALATE: 1,
  HOLD: 2,
  BLOCK: 3,
};

/** The more restrictive (tighter) of two verdicts. */
export function tighter(a: Verdict, b: Verdict): Verdict {
  return VERDICT_RANK[a] >= VERDICT_RANK[b] ? a : b;
}

/** Measured effects of a proposed action (from dry-run/EXPLAIN). */
export interface MeasuredStats {
  rows_affected?: number;
  bytes?: number;
  estimated_cost?: number;
  wal_bytes?: number;
}

/** Input to a risk assessment ({sql, schema, measured_stats, intent_tiers}). */
export interface RiskInput {
  /** Literals SHOULD be redacted upstream for a hosted engine (§11.4). */
  sql: string;
  schema?: string;
  measured_stats?: MeasuredStats;
  intent_tiers?: IntentTiers;
}

/** Output of a risk assessment ({verdict, reason, confidence}). */
export interface RiskVerdict {
  verdict: Verdict;
  reason: string;
  confidence: number;
}

/** Enforce tighten-only at the seam: never loosen below the floor verdict. */
export function clampToFloor(v: RiskVerdict, floor: Verdict): RiskVerdict {
  if (VERDICT_RANK[v.verdict] >= VERDICT_RANK[floor]) return v;
  return {
    verdict: floor,
    reason: `risk engine attempted to loosen below floor (${v.verdict} < ${floor}); clamped to floor`,
    confidence: v.confidence,
  };
}

/** The risk-engine seam. The real engine swaps in here later. */
export interface RiskEngine {
  assess(input: RiskInput): RiskVerdict;
}

/** The MVP risk engine: ALWAYS returns Allow (SPEC §11.5). */
export class AllowStub implements RiskEngine {
  assess(_input: RiskInput): RiskVerdict {
    return {
      verdict: "ALLOW",
      reason:
        "MVP stub: risk engine returns Allow; the deterministic floor enforces safety (SPEC §11.5)",
      confidence: 1.0,
    };
  }
}
