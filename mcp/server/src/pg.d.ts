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
  }
  export class Client {
    constructor(config?: ClientConfig);
    connect(): Promise<void>;
    query(text: string, values?: unknown[]): Promise<QueryResult>;
    end(): Promise<void>;
  }
}
