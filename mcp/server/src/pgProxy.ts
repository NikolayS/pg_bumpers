/**
 * `PgProxyTransport` — the LIVE wire to the proxy (SPEC §3 layer 2).
 *
 * Every read the MCP server performs goes through a Postgres wire connection.
 * In production that endpoint is the Apache Rust proxy (proxy + warden + WALL =
 * the real boundary); the proxy is what enforces read-only / budgets / audit.
 * The MCP server only speaks libpq to it and surfaces what it returns. This
 * class is that real client.
 *
 * Honesty note (SPEC §3): the MCP server is cooperative and NOT a security
 * boundary. `PgProxyTransport` adds NO enforcement of its own beyond the
 * cooperative read/write fast-path classifier in the server — the connection it
 * holds is exactly the privilege the proxy/WALL granted, nothing more.
 *
 * The integration test points this at a throwaway PG18 (a dedicated high port,
 * never 5432) standing in for the proxied backend, exercising a real libpq
 * round-trip on PG18. The full proxy binary in front is covered by the Rust
 * `crates/proxy/tests/proxy_it.rs` integration suite.
 *
 * `pg` (MIT) is typed locally (minimal surface) so the build needs no
 * `@types/node` / `@types/pg`.
 */
import type { IntentTiers } from "./intent.js";
import type {
  PlanResult,
  ProxyTransport,
  QueryResult,
  Row,
  SchemaColumn,
} from "./transport.js";
import { isReadOnly } from "./classifier.js";

/** The minimal `pg` Client surface this module uses (avoids @types/pg). */
export interface PgLikeClient {
  query(text: string, values?: unknown[]): Promise<{ rows: Row[]; rowCount: number | null }>;
  end(): Promise<void>;
}

/** Connection details for the proxy endpoint (a Postgres wire endpoint). */
export interface PgProxyConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password?: string;
  /** Statement timeout (ms) set on the session — defence-in-depth, not THE floor. */
  statementTimeoutMs?: number;
  /**
   * The `application_name` stamped on the wire session. In production the proxy
   * stamps `pgb_proxy` on every backend it brokers so the out-of-band warden can
   * recognize + terminate an agent-tagged runaway (SPEC §3 layer 2; the
   * un-strippable anchor is the `pgb_agent` role). Defaults unset (the server's
   * own default applies). NOT a security control — purely the warden's tag.
   */
  applicationName?: string;
}

/**
 * A live proxy transport over `pg`. The caller injects a connected client (so
 * tests own connection lifecycle); use `connect()` to build one from config.
 */
export class PgProxyTransport implements ProxyTransport {
  constructor(private readonly client: PgLikeClient) {}

  /** Connect a `pg` Client to the proxy endpoint and wrap it. */
  static async connect(config: PgProxyConfig): Promise<PgProxyTransport> {
    // Dynamic import keeps `pg` out of the cold path.
    const { Client } = await import("pg");
    const client = new Client({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      statement_timeout: config.statementTimeoutMs ?? 5_000,
      // The warden tags every brokered backend with this `application_name`
      // (SPEC §3 layer 2). When set, the live MCP read session is recognizable to
      // the out-of-band watchdog as an agent-tagged session.
      application_name: config.applicationName,
    });
    await client.connect();
    return new PgProxyTransport(client);
  }

  async query(sql: string, _intent: IntentTiers): Promise<QueryResult> {
    // Defence-in-depth: the live transport refuses anything not provably a read.
    // The real read-only guarantee is the proxy/WALL; this just makes the live
    // client honest about its lane.
    if (!isReadOnly(sql)) {
      return {
        outcome: "blocked",
        block: {
          code: "READ_ONLY",
          reason: "the proxy read path runs read-only statements",
          remedy: "use propose_write → dry_run → apply_write for changes",
          retryable: false,
        },
      };
    }
    const res = await this.client.query(sql);
    return { outcome: "rows", rows: res.rows, rowCount: res.rowCount ?? res.rows.length };
  }

  async discoverSchema(): Promise<SchemaColumn[]> {
    const res = await this.client.query(
      `SELECT table_schema AS schema, table_name AS table,
              column_name AS column, data_type AS type
         FROM information_schema.columns
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY table_schema, table_name, ordinal_position`,
    );
    return res.rows.map((r) => ({
      schema: String(r.schema),
      table: String(r.table),
      column: String(r.column),
      type: String(r.type),
    }));
  }

  async explain(sql: string): Promise<PlanResult | { blocked: import("./blockContract.js").BlockBody }> {
    // Defence-in-depth (mirrors `query` above): the raw caller SQL is about to be
    // interpolated into `EXPLAIN (FORMAT JSON) ${sql}`. Postgres runs that as a
    // simple-query string, so a stacked second statement (`SELECT 1; DROP TABLE
    // victim`) — or a write — WOULD EXECUTE. Refuse anything not provably a pure
    // read before it can reach the wire. The real guarantee is the proxy/WALL.
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
    // EXPLAIN, never EXPLAIN ANALYZE — the statement is planned, not executed.
    const res = await this.client.query(`EXPLAIN (FORMAT JSON) ${sql}`);
    const planRow = res.rows[0] as Record<string, unknown> | undefined;
    const planJson = planRow?.["QUERY PLAN"];
    const top = Array.isArray(planJson) ? (planJson[0] as Record<string, unknown>) : undefined;
    const plan = top?.["Plan"] as Record<string, unknown> | undefined;
    const cost = typeof plan?.["Total Cost"] === "number" ? (plan["Total Cost"] as number) : 0;
    return { plan: JSON.stringify(planJson), cost };
  }

  /** Close the underlying connection. */
  async close(): Promise<void> {
    await this.client.end();
  }
}
