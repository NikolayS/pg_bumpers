/**
 * Coarse read/write classification for the MCP layer (SPEC §4).
 *
 * IMPORTANT — this is NOT the security boundary. The proxy + WALL enforce
 * read-only deterministically at the wire (statement-stacking-proof, extended-
 * protocol-only). This classifier exists only so the cooperative MCP `query`
 * tool can give a *fast, friendly* recoverable block ("use propose_write") for
 * an obvious write, instead of forwarding it to the proxy just to be rejected.
 *
 * Fail-closed: anything not provably a pure read is treated as a write here, so
 * the friendly path never under-reports. The real guarantee is downstream.
 */

/** Leading keywords that begin a read-only statement. */
const READ_KEYWORDS = new Set([
  "SELECT",
  "WITH", // CTE — could wrap a write; see the data-modifying-CTE guard below.
  "TABLE",
  "VALUES",
  "EXPLAIN",
  "SHOW",
]);

/** Keywords that always denote a write/DDL/▼ side-effecting statement. */
const WRITE_KEYWORDS = new Set([
  "INSERT",
  "UPDATE",
  "DELETE",
  "MERGE",
  "TRUNCATE",
  "DROP",
  "CREATE",
  "ALTER",
  "GRANT",
  "REVOKE",
  "COPY",
  "CALL",
  "DO",
  "VACUUM",
  "REINDEX",
  "CLUSTER",
  "REFRESH",
  "COMMENT",
  "SECURITY",
  "LOCK",
]);

/** Strip leading/embedded SQL comments so the leading keyword is reachable. */
function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\n]*(\n|$)/g, " ");
}

/**
 * Is `sql` provably a pure read? Conservative: returns false on any doubt
 * (statement-stacking, data-modifying CTEs, unknown keywords).
 */
export function isReadOnly(sql: string): boolean {
  const cleaned = stripComments(sql).trim();
  if (cleaned.length === 0) return false;

  // Statement-stacking: more than one statement → not a clean single read. The
  // proxy rejects this outright at the wire; we mirror conservatively. A single
  // trailing semicolon is fine.
  const withoutTrailing = cleaned.replace(/;\s*$/, "");
  if (withoutTrailing.includes(";")) return false;

  const upper = withoutTrailing.toUpperCase();
  const lead = upper.match(/^\s*([A-Z]+)/)?.[1];
  if (!lead) return false;

  if (WRITE_KEYWORDS.has(lead)) return false;
  if (!READ_KEYWORDS.has(lead)) return false;

  // Data-modifying CTE: WITH ... ( INSERT|UPDATE|DELETE|MERGE ... ) — treat as a
  // write. Cheap keyword scan; the real guarantee is the proxy/WALL.
  if (lead === "WITH" && /\b(INSERT|UPDATE|DELETE|MERGE)\b/.test(upper)) {
    return false;
  }

  // EXPLAIN ANALYZE actually executes the statement → not a safe read for the
  // read tool. Plain EXPLAIN is a read; route EXPLAIN through explain_plan.
  if (lead === "EXPLAIN" && /\bANALYZE\b/.test(upper)) return false;

  return true;
}
