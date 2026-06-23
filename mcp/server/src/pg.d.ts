/**
 * Minimal ambient declaration for the `pg` (node-postgres, MIT) module.
 *
 * We deliberately do NOT depend on `@types/pg`: `pgProxy.ts` uses only a tiny
 * slice of the client surface, declared here, so the type graph stays small and
 * the license tree stays minimal. This mirrors the `PgLikeClient` interface in
 * pgProxy.ts (kept in sync by hand — the surface is three methods).
 */
declare module "pg" {
  export interface QueryResultRow {
    [column: string]: unknown;
  }
  export interface QueryResult {
    rows: QueryResultRow[];
    rowCount: number | null;
  }
  export interface ClientConfig {
    host?: string;
    port?: number;
    database?: string;
    user?: string;
    password?: string;
    statement_timeout?: number;
    application_name?: string;
  }
  /**
   * A node-postgres query config. Passing a `name` (a prepared-statement name)
   * forces the EXTENDED protocol — which the proxy requires (its statement-
   * stacking defense). See `PgQueryConfig` in pgProxy.ts.
   */
  export interface QueryConfig {
    name?: string;
    text: string;
    values?: unknown[];
  }
  /**
   * A node-postgres `Client` IS an `EventEmitter` (it extends one). It emits an
   * async `'error'` whenever the backend connection is lost (backend restart,
   * idle TCP reset, or the warden calling `pg_terminate_backend` on the
   * agent-tagged session) and `'end'` on a normal close. We declare just the
   * `on`/`once` surface we attach listeners to so a lost connection can never
   * re-throw as an uncaught exception and kill the stdio process.
   */
  export class Client {
    constructor(config?: ClientConfig);
    connect(): Promise<void>;
    query(text: string | QueryConfig, values?: unknown[]): Promise<QueryResult>;
    end(): Promise<void>;
    on(event: "error", listener: (err: Error) => void): this;
    on(event: "end", listener: () => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
  }
}
