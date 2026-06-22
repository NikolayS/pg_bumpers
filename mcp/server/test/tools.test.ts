/**
 * Behavioral tests for the minimal MCP toolset (SPEC §4, §11.2, §11.5, §15.1).
 *
 * The MCP server is the cooperative intent/UX layer (SPEC §3 layer 3): it adds
 * NO privilege of its own — every tool executes *through* the proxy (the real
 * boundary is proxy + warden + WALL). These tests pin:
 *   - the nine-tool surface,
 *   - the block contract on every denial (recoverable remedy on a blocked write),
 *   - the confirm_rows forcing function before apply,
 *   - statelessness (proposal/ticket state lives in core, not MCP memory),
 *   - T0–T2 intent capture (logged-only),
 *   - the RiskEngine stub returning Allow.
 *
 * Prompt-injection-via-data is tested separately in injection.test.ts.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createServer, TOOL_NAMES, type McpServer } from "../src/server.js";
import { FakeProxyTransport, FakeCore } from "../src/testing/fakes.js";
import { isBlock } from "../src/blockContract.js";

const ROLE = "pgb_agent";

function newServer(): { server: McpServer; proxy: FakeProxyTransport; core: FakeCore } {
  const proxy = new FakeProxyTransport();
  const core = new FakeCore();
  const server = createServer({ transport: proxy, core, role: ROLE });
  return { server, proxy, core };
}

describe("MCP toolset surface (SPEC §4)", () => {
  it("exposes exactly the nine §4 tools", () => {
    expect([...TOOL_NAMES].sort()).toEqual(
      [
        "apply_write",
        "discover_schema",
        "dry_run",
        "explain_plan",
        "get_audit",
        "propose_write",
        "query",
        "request_elevation",
        "whoami",
      ].sort(),
    );
  });

  it("the server lists every tool by name", () => {
    const { server } = newServer();
    expect(server.listTools().map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort());
  });
});

describe("whoami (T0 identity)", () => {
  it("reports the role and that MCP is NOT a security boundary", async () => {
    const { server } = newServer();
    const res = await server.call("whoami", {});
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.role).toBe(ROLE);
    // The honesty contract: the server must never claim to be the boundary.
    expect(res.data.security_boundary).toBe(false);
  });
});

describe("query (read through the proxy)", () => {
  let s: ReturnType<typeof newServer>;
  beforeEach(() => {
    s = newServer();
  });

  it("executes a read through the proxy and returns rows", async () => {
    s.proxy.onQuery("SELECT 1 AS n", { rows: [{ n: 1 }], rowCount: 1 });
    const res = await s.server.call("query", { sql: "SELECT 1 AS n" });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.rows).toEqual([{ n: 1 }]);
    // The query actually went through the proxy transport, not around it.
    expect(s.proxy.lastQuery).toBe("SELECT 1 AS n");
  });

  it("returns the proxy's block contract verbatim when the proxy denies a read", async () => {
    // The proxy (the real boundary) blocks; the MCP server must surface that
    // block as a structured, recoverable contract, never an opaque throw.
    s.proxy.blockNext({
      code: "BUDGET_EXCEEDED",
      reason: "per-role byte budget exhausted",
      remedy: "wait for the window to reset or request elevation via pgb-cli",
      retryable: true,
    });
    const res = await s.server.call("query", { sql: "SELECT * FROM big" });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("BUDGET_EXCEEDED");
    expect(res.retryable).toBe(true);
    expect(res.remedy).toContain("pgb-cli");
  });

  it("rejects a write submitted to the read tool with a recoverable remedy", async () => {
    const res = await s.server.call("query", { sql: "UPDATE orders SET total = 0" });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("READ_ONLY");
    // Recoverable: it points at the write path, not a dead end.
    expect(res.remedy).toContain("propose_write");
  });
});

describe("discover_schema + explain_plan (reads through the proxy)", () => {
  it("discover_schema returns catalog info from the proxy", async () => {
    const { server, proxy } = newServer();
    proxy.setSchema([{ schema: "public", table: "orders", column: "id", type: "bigint" }]);
    const res = await server.call("discover_schema", {});
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.columns[0].table).toBe("orders");
  });

  it("explain_plan returns a plan for a read, never executing the statement", async () => {
    const { server, proxy } = newServer();
    proxy.setPlan("SELECT * FROM orders WHERE id = 1", { plan: "Index Scan on orders", cost: 1234 });
    const res = await server.call("explain_plan", { sql: "SELECT * FROM orders WHERE id = 1" });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.cost).toBe(1234);
    // EXPLAIN must NOT have run anything as a real query.
    expect(proxy.executedWrites).toHaveLength(0);
  });

  it("explain_plan blocks a plain write (mirror the query read-only guard)", async () => {
    const { server, proxy } = newServer();
    // The tool's contract is "plans, never executes" — a write must never reach
    // `EXPLAIN ... ${sql}` (which would execute DDL/DML), so it is blocked here
    // exactly as the query tool blocks it.
    const res = await server.call("explain_plan", { sql: "DROP TABLE orders" });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("READ_ONLY");
    // Recoverable: it points at the write path, not a dead end.
    expect(res.remedy).toContain("propose_write");
    // Nothing was forwarded to the proxy as a plan/execution.
    expect(proxy.executedWrites).toHaveLength(0);
  });

  it("explain_plan blocks a stacked statement (anti statement-stacking)", async () => {
    const { server, proxy } = newServer();
    // The classic hole: a stacked arg whose SECOND statement is a write. The raw
    // string must never reach `EXPLAIN (FORMAT JSON) SELECT 1; DROP TABLE orders`.
    const res = await server.call("explain_plan", { sql: "SELECT 1; DROP TABLE orders" });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("READ_ONLY");
    expect(proxy.executedWrites).toHaveLength(0);
  });
});

describe("propose_write → dry_run → apply_write (the write path)", () => {
  it("propose_write mints a proposal in CORE (not MCP memory) and returns its id + TTL", async () => {
    const { server, core } = newServer();
    const res = await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1",
      expected_rows: 1,
    });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.proposal_id).toMatch(/^p-/);
    expect(res.data.ttl_millis).toBeGreaterThan(0);
    // State authority is core, not the server: the proposal exists in core.
    expect(core.hasProposal(res.data.proposal_id)).toBe(true);
  });

  it("a structural/non-rehearsable propose REFUSAL becomes a recoverable block, never an opaque error", async () => {
    // The production ApplydCore.propose THROWS an ApplydError when applyd's
    // classify choke refuses a DROP/TRUNCATE/ALTER. The server MUST convert that
    // into a structured block contract (SPEC §4: every denial is a recoverable
    // block, never an unhandled throw). This is the marquee's "delete a DB through
    // the MCP is neutralized by refusal" behavior at the propose layer.
    const { server, core } = newServer();
    core.refuseOnPropose("NOT_REHEARSABLE", "DROP DATABASE is not a certified rehearsable write");
    const res = await server.call("propose_write", {
      sql: "DROP DATABASE app",
      expected_rows: 0,
    });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("NOT_REHEARSABLE");
    expect(res.reason).toContain("DROP DATABASE");
    expect(res.retryable).toBe(false);
    // No proposal was minted (the refusal is terminal).
  });

  it("dry_run returns the blast radius incl. the affected PK-set checksum", async () => {
    const { server } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1",
      expected_rows: 1,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const res = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.blast_radius.total_rows).toBe(1);
    expect(res.data.blast_radius.pk_set_checksum).toMatch(/^sha256:/);
    expect(res.data.confirm_token).toBeTruthy();
  });

  it("apply_write WITHOUT confirm_rows is blocked (the forcing function)", async () => {
    const { server } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1",
      expected_rows: 1,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const dry = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    if (dry.status !== "ok") throw new Error("dry_run failed");
    // No confirm_rows supplied → must block with a recoverable remedy.
    const res = await server.call("apply_write", {
      proposal_id: proposed.data.proposal_id,
    });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("CONFIRM_REQUIRED");
    expect(res.remedy).toContain("confirm_rows");
    expect(server).toBeDefined();
  });

  it("apply_write with a MISMATCHED confirm_rows is blocked (PK-set/row drift guard)", async () => {
    const { server } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1",
      expected_rows: 1,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const dry = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    if (dry.status !== "ok") throw new Error("dry_run failed");
    const res = await server.call("apply_write", {
      proposal_id: proposed.data.proposal_id,
      confirm_rows: 999, // caller confirms the WRONG count
    });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("CONFIRM_MISMATCH");
  });

  it("apply_write with the correct confirmed count applies through the proxy", async () => {
    const { server } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1",
      expected_rows: 1,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const dry = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    if (dry.status !== "ok") throw new Error("dry_run failed");
    const res = await server.call("apply_write", {
      proposal_id: proposed.data.proposal_id,
      confirm_rows: dry.data.blast_radius.total_rows,
      confirm_token: dry.data.confirm_token,
    });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.applied).toBe(true);
    expect(res.data.reversible).toBe(true);
  });

  it("apply_write on an unknown/expired proposal is blocked (state is in core, TTL'd)", async () => {
    const { server } = newServer();
    const res = await server.call("apply_write", {
      proposal_id: "p-deadbeef",
      confirm_rows: 1,
    });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("PROPOSAL_NOT_FOUND");
  });
});

describe("a write blocked by the floor returns a recoverable remedy (APPROVAL_REQUIRED)", () => {
  it("surfaces APPROVAL_REQUIRED + a request id, not an opaque error", async () => {
    const { server, core } = newServer();
    // Make core's apply path require approval (e.g. a parameter-budget block).
    core.requireApprovalOnApply("APPROVAL_REQUIRED", "row budget exceeded for this action");
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders",
      expected_rows: 5_000_000,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const dry = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    if (dry.status !== "ok") throw new Error("dry_run failed");
    const res = await server.call("apply_write", {
      proposal_id: proposed.data.proposal_id,
      confirm_rows: dry.data.blast_radius.total_rows,
      confirm_token: dry.data.confirm_token,
    });
    expect(isBlock(res)).toBe(true);
    if (!isBlock(res)) return;
    expect(res.code).toBe("APPROVAL_REQUIRED");
    // The remedy is recoverable: it names request_elevation as the next step.
    expect(res.remedy).toContain("request_elevation");
  });
});

describe("request_elevation (the unblock route, §14)", () => {
  it("creates an approval-request ticket in core with a TTL", async () => {
    const { server, core } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders",
      expected_rows: 5_000_000,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const res = await server.call("request_elevation", {
      proposal_id: proposed.data.proposal_id,
      reason: "intended 5M-row backfill",
    });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(res.data.request_id).toMatch(/^req-/);
    expect(res.data.ttl_millis).toBeGreaterThan(0);
    expect(core.hasElevation(res.data.request_id)).toBe(true);
  });
});

describe("get_audit (read the hash-chained audit through the proxy/core)", () => {
  it("returns audit records for the session", async () => {
    const { server } = newServer();
    await server.call("query", { sql: "SELECT 1" }).catch(() => undefined);
    const res = await server.call("get_audit", { limit: 10 });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect(Array.isArray(res.data.records)).toBe(true);
  });
});

describe("RiskEngine stub (SPEC §11.5)", () => {
  it("returns Allow for every input, including a scary wide DELETE", async () => {
    const { server } = newServer();
    const proposed = await server.call("propose_write", {
      sql: "DELETE FROM orders /* no where */",
      expected_rows: 4_800_000,
    });
    if (proposed.status !== "ok") throw new Error("propose failed");
    const dry = await server.call("dry_run", { proposal_id: proposed.data.proposal_id });
    expect(dry.status).toBe("ok");
    if (dry.status !== "ok") return;
    // The risk verdict is captured in the dry-run record and is always ALLOW in MVP.
    expect(dry.data.risk.verdict).toBe("ALLOW");
  });
});

describe("T0–T2 intent capture (logged-only, SPEC §11.2/§11.5)", () => {
  it("captures T0 role, T1 statement class + annotation for a read (logged at the proxy/wire)", async () => {
    // Reads are audited at the proxy/wire (SPEC §3 layer 2 writes the hash-chained
    // audit). The server hands the captured T0–T2 intent to the proxy transport.
    const { server, proxy } = newServer();
    await server.call("query", {
      sql: "SELECT * FROM orders /* intent: rca ticket: INC-9 actor: agent */",
      application_name: "claude-code",
    });
    const logged = proxy.lastIntent;
    expect(logged).toBeTruthy();
    if (!logged) return;
    expect(logged.t0.role).toBe(ROLE);
    expect(logged.t1.statement_class).toBe("SELECT");
    expect(logged.t1.application_name).toBe("claude-code");
    expect(logged.t1.annotation.intent).toBe("rca");
    expect(logged.t1.annotation.ticket).toBe("INC-9");
  });

  it("captures T0 role + T1 statement class for a write (logged in core)", async () => {
    // Write intent is logged in core (the state authority) at propose time.
    const { server, core } = newServer();
    await server.call("propose_write", {
      sql: "DELETE FROM orders WHERE id = 1 /* intent: cleanup ticket: INC-9 */",
      expected_rows: 1,
      application_name: "claude-code",
    });
    const logged = core.lastIntent();
    expect(logged).toBeTruthy();
    if (!logged) return;
    expect(logged.t0.role).toBe(ROLE);
    expect(logged.t1.statement_class).toBe("DELETE");
    expect(logged.t1.annotation.intent).toBe("cleanup");
  });

  it("intent is logged-only: a malformed annotation never blocks (absence ≠ denial)", async () => {
    const { server } = newServer();
    const res = await server.call("query", {
      sql: "SELECT 1 /* intent: */",
    });
    // Logging a malformed annotation must not fail-closed the action itself.
    expect(res.status).toBe("ok");
  });
});
