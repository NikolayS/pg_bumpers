import { describe, it, expect } from "vitest";
import { block, type BlockContract } from "../src/blockContract.js";

describe("MCP block contract", () => {
  it("defaults retryable to false (fail-closed)", () => {
    const b = block("READ_ONLY", "writes are not permitted here", "use propose_write");
    expect(b.status).toBe("blocked");
    expect(b.code).toBe("READ_ONLY");
    expect(b.retryable).toBe(false);
  });

  it("carries an explicit recoverable remedy when retryable", () => {
    const b: BlockContract = block(
      "BUDGET_EXCEEDED",
      "per-role byte budget exhausted",
      "wait for the window to reset or request elevation via pgb-cli",
      true,
    );
    expect(b.retryable).toBe(true);
    expect(b.remedy).toContain("pgb-cli");
  });
});
