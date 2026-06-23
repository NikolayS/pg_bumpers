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

/**
 * A node-`pg` query config. Passing a `name` (a prepared-statement name) forces
 * node-postgres to use the EXTENDED protocol (Parse/Bind/Execute) instead of the
 * simple-query protocol — which the proxy REQUIRES (extended-protocol-only is its
 * statement-stacking defense; a plain-string `client.query("…")` is sent simple
 * and the proxy rejects it). See `extendedQuery` below.
 */
export interface PgQueryConfig {
  name: string;
  text: string;
  values?: unknown[];
}

/**
 * The minimal `pg` Client surface this module uses (avoids @types/pg). A real
 * node-postgres `Client` is an `EventEmitter`; we include the `on` surface so the
 * transport can attach an `'error'`/`'end'` listener — without one, a lost backend
 * connection re-throws as an uncaught exception and kills the stdio process.
 */
export interface PgLikeClient {
  query(
    config: string | PgQueryConfig,
    values?: unknown[],
  ): Promise<{ rows: Row[]; rowCount: number | null }>;
  end(): Promise<void>;
  on(event: "error", listener: (err: Error) => void): unknown;
  on(event: "end", listener: () => void): unknown;
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
  /** Monotonic counter for unique prepared-statement names (one per query). */
  private stmtSeq = 0;
  /**
   * Set once the underlying connection is lost (the `Client` emitted `'error'`
   * or `'end'` — backend restart, idle TCP reset, or the warden calling
   * `pg_terminate_backend` on the agent-tagged session; SPEC §3 layer 2). A dead
   * transport never touches the wire again: every read short-circuits to a
   * recoverable block, and `LazyProxyTransport` re-dials on the next read.
   */
  private dead = false;
  /** The async error that killed the connection (surfaced in the block detail). */
  private lostError: unknown;
  /** Listeners notified once, when the connection is first lost (the lazy wrapper). */
  private readonly lossListeners: Array<(err: unknown) => void> = [];

  constructor(private readonly client: PgLikeClient) {
    // The node-postgres `Client` is an `EventEmitter`. It emits an ASYNC `'error'`
    // whenever the backend connection is lost (restart / idle TCP reset / the
    // warden's `pg_terminate_backend` on the agent-tagged session). An emitter
    // with NO `'error'` listener re-throws that as an UNCAUGHT exception, which
    // `main().catch()` cannot catch — it kills the entire `pgb-mcp` stdio
    // process (the silent death this whole path exists to prevent). Attaching a
    // listener converts the loss into a recorded, recoverable signal. We also
    // listen for `'end'` (a clean server-side close) for the same reason.
    this.client.on("error", (err) => this.markLost(err));
    this.client.on("end", () => this.markLost(new Error("the proxy connection ended")));
  }

  /** Mark the connection lost (idempotent) and notify the loss listeners once. */
  private markLost(err: unknown): void {
    if (this.dead) return;
    this.dead = true;
    this.lostError = err;
    for (const listener of this.lossListeners) {
      try {
        listener(err);
      } catch {
        // A listener must never re-introduce the crash this method prevents.
      }
    }
  }

  /** True once the underlying connection has been lost. */
  isDead(): boolean {
    return this.dead;
  }

  /**
   * Register a callback invoked once when the connection is lost. If the
   * connection is ALREADY lost, the callback fires synchronously (so a caller
   * registering late still learns of the loss and can re-dial).
   */
  onLost(listener: (err: unknown) => void): void {
    if (this.dead) {
      listener(this.lostError);
      return;
    }
    this.lossListeners.push(listener);
  }

  /**
   * Wrap an already-constructed client (e.g. a test double) in the transport,
   * attaching the same `'error'`/`'end'` listeners `connect()` does. Production
   * code uses `connect()`; this is the seam tests use to drive the loss path.
   */
  static fromClient(client: PgLikeClient): PgProxyTransport {
    return new PgProxyTransport(client);
  }

  /**
   * Run `sql` over the EXTENDED protocol (Parse/Bind/Execute) by giving it a
   * unique prepared-statement `name`. The proxy is **extended-protocol-only**
   * (its statement-stacking defense), so a plain-string `client.query(sql)` —
   * which node-postgres sends as a SIMPLE query — is rejected by the proxy with
   * "simple query protocol is not permitted for agent connections". Forcing the
   * extended protocol is what lets every read genuinely traverse the proxy. The
   * name is unique per call so node-postgres never reuses one name for two SQL
   * texts (which it would reject).
   */
  private extendedQuery(
    sql: string,
  ): Promise<{ rows: Row[]; rowCount: number | null }> {
    const name = `pgb_mcp_${(this.stmtSeq = (this.stmtSeq + 1) & 0x7fffffff)}`;
    return this.client.query({ name, text: sql, values: [] });
  }

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
    // If the connection was already lost, never touch the wire — surface the
    // recoverable block so the lazy wrapper re-dials on the next read.
    if (this.dead) {
      return { outcome: "blocked", block: lostBlock(this.lostError) };
    }
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
    try {
      const res = await this.extendedQuery(sql);
      return { outcome: "rows", rows: res.rows, rowCount: res.rowCount ?? res.rows.length };
    } catch (err) {
      // A query that fails because the CONNECTION itself was lost (the warden's
      // `pg_terminate_backend`, a backend restart, an idle TCP reset) can arrive as
      // a synchronous query rejection BEFORE the async `'error'` event fires. Treat
      // it as a recoverable loss: mark dead so the lazy wrapper re-dials, and
      // surface the retryable `PROXY_UNAVAILABLE` (never a non-retryable brick).
      if (isConnectionLost(err)) {
        this.markLost(err);
        return { outcome: "blocked", block: lostBlock(err) };
      }
      // Otherwise the proxy/WALL denied the read at the deterministic floor (e.g.
      // the WALL role lacks SELECT → permission denied; a budget cutoff; a
      // read-only rejection). Surface it as the RECOVERABLE block contract the
      // server relays verbatim, NOT an opaque thrown error.
      return { outcome: "blocked", block: backendBlock(err) };
    }
  }

  async discoverSchema(): Promise<SchemaColumn[]> {
    // discoverSchema has no block channel; throwing is caught by the server's
    // tool dispatch and relayed as a structured error (the lazy wrapper re-dials
    // on the next read). Never touch a dead wire.
    if (this.dead) {
      throw new Error(lostBlock(this.lostError).reason);
    }
    const res = await this.extendedQuery(
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
    // If the connection was already lost, surface the recoverable block (the lazy
    // wrapper re-dials on the next read) rather than touching a dead wire.
    if (this.dead) {
      return { blocked: lostBlock(this.lostError) };
    }
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
    let res: { rows: Row[]; rowCount: number | null };
    try {
      res = await this.extendedQuery(`EXPLAIN (FORMAT JSON) ${sql}`);
    } catch (err) {
      // A lost connection (warden terminate / restart / reset) is a recoverable
      // loss: mark dead so the lazy wrapper re-dials, and surface the retryable
      // PROXY_UNAVAILABLE. Anything else is a WALL/floor denial during planning.
      if (isConnectionLost(err)) {
        this.markLost(err);
        return { blocked: lostBlock(err) };
      }
      return { blocked: backendBlock(err) };
    }
    const planRow = res.rows[0] as Record<string, unknown> | undefined;
    const planJson = planRow?.["QUERY PLAN"];
    const top = Array.isArray(planJson) ? (planJson[0] as Record<string, unknown>) : undefined;
    const plan = top?.["Plan"] as Record<string, unknown> | undefined;
    const cost = typeof plan?.["Total Cost"] === "number" ? (plan["Total Cost"] as number) : 0;
    return { plan: JSON.stringify(planJson), cost };
  }

  /** Close the underlying connection. Idempotent after a loss. */
  async close(): Promise<void> {
    // Mark dead first so the `'end'`/`'error'` our own `end()` may emit is a no-op.
    this.dead = true;
    await this.client.end();
  }
}

/** A Postgres-shaped error carrying the SQLSTATE on `.code` (node-`pg`). */
interface PgError {
  code?: string;
  message?: string;
}

/**
 * Map a backend/proxy error thrown during a read into the recoverable block
 * contract. A WALL denial (SQLSTATE 42501 — `permission denied`, the hardened
 * role lacking SELECT on a non-whitelisted relation) is the headline case: it is
 * the proxy/WALL enforcing default-deny, which the agent should see as a
 * structured `WALL_DENIED` block, NOT an opaque crash. Other backend errors
 * (syntax, missing relation, a floor cutoff surfaced as an error) become a
 * generic non-retryable `PROXY_BLOCKED`.
 */
function backendBlock(err: unknown): import("./blockContract.js").BlockBody {
  const e = (err ?? {}) as PgError;
  const message = e.message ?? String(err);
  if (e.code === "42501") {
    return {
      code: "WALL_DENIED",
      reason: `the proxy/WALL denied this read (least-privilege default-deny): ${message}`,
      remedy:
        "the hardened agent role has no SELECT on this relation; request access to a whitelisted relation",
      retryable: false,
    };
  }
  return {
    code: "PROXY_BLOCKED",
    reason: `the proxy refused this read at the deterministic floor: ${message}`,
    remedy: "adjust the statement to a permitted read, or use the write lifecycle for changes",
    retryable: false,
  };
}

/**
 * The recoverable block returned when a read hits a connection that was already
 * LOST (the warden's `pg_terminate_backend`, a backend restart, an idle TCP
 * reset). It is `retryable` because the stack typically recovers and the lazy
 * wrapper re-dials on the next read — this is what turns the async EventEmitter
 * `'error'` (which would otherwise crash the process) into a recoverable signal.
 */
function lostBlock(err: unknown): import("./blockContract.js").BlockBody {
  const detail = err instanceof Error ? err.message : err == null ? "connection lost" : String(err);
  return {
    code: "PROXY_UNAVAILABLE",
    reason: `the proxy connection was lost: ${detail}`,
    remedy:
      "the backend session ended (e.g. a warden terminate, restart, or idle reset); retry — the read will re-dial the proxy",
    retryable: true,
  };
}

/**
 * Was this read error caused by the CONNECTION being lost (rather than a
 * proxy/WALL/floor denial of the statement)? A lost connection can surface as a
 * synchronous query rejection BEFORE the async EventEmitter `'error'` fires — the
 * warden's `pg_terminate_backend` on the agent-tagged session, a backend restart,
 * or an idle TCP reset. node-postgres reports these as a connection-terminated
 * message (no SQLSTATE) or one of the connection-class SQLSTATEs / socket errnos.
 * Such an error is RECOVERABLE (re-dial), NOT a permanent `PROXY_BLOCKED` brick.
 */
function isConnectionLost(err: unknown): boolean {
  const e = (err ?? {}) as PgError & { errno?: string };
  // Connection-class SQLSTATEs: 08xxx (connection exception family), and the
  // admin-shutdown / crash-shutdown codes the backend sends on termination.
  const code = e.code ?? "";
  if (code.startsWith("08") || code === "57P01" || code === "57P02" || code === "57P03") {
    return true;
  }
  // node-postgres connection-loss messages / socket errnos (no SQLSTATE).
  const message = (e.message ?? "").toLowerCase();
  return (
    message.includes("connection terminated") ||
    message.includes("connection ended") ||
    message.includes("server closed the connection") ||
    message.includes("econnreset") ||
    message.includes("epipe") ||
    code === "ECONNRESET" ||
    code === "EPIPE"
  );
}
