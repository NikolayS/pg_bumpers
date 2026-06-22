/**
 * Unit tests for the pure building blocks: the read/write classifier (the
 * cooperative fast-path, NOT the security boundary), the T0–T2 intent parser
 * (logged-only, best-effort, never fails the action), and the RiskEngine stub
 * (always Allow, tighten-only seam). SPEC §4, §11.2, §11.5.
 */
import { describe, it, expect } from "vitest";
import { isReadOnly } from "../src/classifier.js";
import { captureIntent, parseAnnotation, statementClass } from "../src/intent.js";
import { AllowStub, clampToFloor, tighter } from "../src/riskEngine.js";

describe("classifier.isReadOnly (cooperative fast-path, fail-closed)", () => {
  it("treats plain SELECT / WITH(read) / VALUES / SHOW as reads", () => {
    expect(isReadOnly("SELECT 1")).toBe(true);
    expect(isReadOnly("  select * from orders where id = 1")).toBe(true);
    expect(isReadOnly("WITH t AS (SELECT 1) SELECT * FROM t")).toBe(true);
    expect(isReadOnly("VALUES (1),(2)")).toBe(true);
    expect(isReadOnly("SHOW search_path")).toBe(true);
    expect(isReadOnly("/* hi */ SELECT 1")).toBe(true);
  });

  it("treats every write/DDL keyword as NOT a read", () => {
    for (const w of [
      "UPDATE orders SET total = 0",
      "DELETE FROM orders",
      "INSERT INTO orders VALUES (1)",
      "DROP TABLE orders",
      "TRUNCATE orders",
      "ALTER TABLE orders ADD c int",
      "CREATE TABLE x (id int)",
      "GRANT ALL ON orders TO public",
      "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
      "CALL do_thing()",
      "DO $$ BEGIN PERFORM 1; END $$",
      "COPY orders TO STDOUT",
    ]) {
      expect(isReadOnly(w), w).toBe(false);
    }
  });

  it("fails closed on statement-stacking (COMMIT; DROP SCHEMA …)", () => {
    expect(isReadOnly("SELECT 1; DROP SCHEMA public CASCADE")).toBe(false);
    expect(isReadOnly("COMMIT; DROP TABLE orders")).toBe(false);
    // A single trailing semicolon is still a clean read.
    expect(isReadOnly("SELECT 1;")).toBe(true);
  });

  it("treats a data-modifying CTE and EXPLAIN ANALYZE as writes", () => {
    expect(isReadOnly("WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d")).toBe(false);
    expect(isReadOnly("EXPLAIN ANALYZE UPDATE orders SET total = 0")).toBe(false);
    // Plain EXPLAIN is a read.
    expect(isReadOnly("EXPLAIN SELECT 1")).toBe(true);
  });

  it("fails closed on empty / unknown-keyword input", () => {
    expect(isReadOnly("")).toBe(false);
    expect(isReadOnly("   ")).toBe(false);
    expect(isReadOnly("FROBNICATE everything")).toBe(false);
  });
});

describe("intent parser (best-effort, logged-only)", () => {
  it("derives the statement class from the leading keyword", () => {
    expect(statementClass("select 1")).toBe("SELECT");
    expect(statementClass("/* c */ -- l\n UPDATE t SET x=1")).toBe("UPDATE");
    expect(statementClass("")).toBeUndefined();
  });

  it("parses /* intent: … ticket: … actor: … */ annotations", () => {
    const a = parseAnnotation("DELETE FROM t /* intent: cleanup ticket: INC-9 actor: agent */");
    expect(a.intent).toBe("cleanup");
    expect(a.ticket).toBe("INC-9");
    expect(a.actor).toBe("agent");
  });

  it("never throws and omits empty/malformed fields (absence ≠ signal)", () => {
    expect(parseAnnotation("SELECT 1 /* intent: */")).toEqual({});
    expect(parseAnnotation("SELECT 1")).toEqual({});
    expect(parseAnnotation("SELECT 1 /* ticket: T-1 */")).toEqual({ ticket: "T-1" });
  });

  it("captureIntent always returns a fully-populated record", () => {
    const t = captureIntent({ role: "pgb_agent", sql: "SELECT * FROM orders" });
    expect(t.t0.role).toBe("pgb_agent");
    expect(t.t1.statement_class).toBe("SELECT");
    expect(t.t1.gucs).toEqual({});
    expect(t.t1.annotation).toEqual({});
    expect(t.t2.reads_before_write).toBe(false);
  });
});

describe("RiskEngine stub (SPEC §11.5) + tighten-only seam", () => {
  it("always returns ALLOW, even for a scary input", () => {
    const stub = new AllowStub();
    expect(stub.assess({ sql: "DELETE FROM orders" }).verdict).toBe("ALLOW");
    expect(
      stub.assess({ sql: "DELETE FROM orders", measured_stats: { rows_affected: 4_800_000 } })
        .verdict,
    ).toBe("ALLOW");
  });

  it("tighter() keeps the more restrictive verdict", () => {
    expect(tighter("ALLOW", "HOLD")).toBe("HOLD");
    expect(tighter("BLOCK", "ESCALATE")).toBe("BLOCK");
  });

  it("clampToFloor enforces tighten-only: an engine cannot loosen below the floor", () => {
    const rogue = { verdict: "ALLOW" as const, reason: "trust me", confidence: 0.99 };
    const clamped = clampToFloor(rogue, "HOLD");
    expect(clamped.verdict).toBe("HOLD");
    expect(clamped.reason).toContain("clamped to floor");
    // A tighter-than-floor verdict passes through untouched.
    const tight = { verdict: "BLOCK" as const, reason: "bad", confidence: 0.9 };
    expect(clampToFloor(tight, "HOLD").verdict).toBe("BLOCK");
  });
});
