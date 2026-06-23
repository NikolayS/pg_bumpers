/**
 * `LazyProxyTransport` — a lazy-connecting wrapper around `PgProxyTransport`
 * (the live wire to the proxy; SPEC §3 layer 2).
 *
 * Why it exists: the deployable stdio MCP shell (`pgb-mcp`) must let the MCP
 * `initialize` / `tools/list` handshake ALWAYS complete so Claude Code can
 * connect — even when the proxy/backend is down. The previous shell connected
 * the proxy eagerly (a real libpq round-trip) BEFORE the JSON-RPC read loop, so a
 * down backend killed the process with zero MCP bytes and Claude Code only saw a
 * silent "Failed to connect".
 *
 * `ApplydCore` is already lazy (its socket connects on the first RPC). This
 * mirrors that for the read path: the underlying `PgProxyTransport.connect(...)`
 * is deferred to the FIRST read, and a connect failure is surfaced as a
 * RECOVERABLE block (the existing `QueryBlocked` / `{blocked}` contract) — never
 * a process death. The handshake therefore completes regardless of backend state,
 * and a `query`/`explain_plan` against a down backend returns a structured,
 * retryable block the agent can recover from (and that resolves once the stack is
 * up).
 *
 * Honesty (SPEC §3): this adds NO enforcement of its own. When connected it holds
 * exactly the privilege the proxy/WALL granted; the lazy seam only changes WHEN
 * the connection is opened, not what it can do.
 */
import type { IntentTiers } from "./intent.js";
import type { BlockBody } from "./blockContract.js";
import { PgProxyTransport, type PgProxyConfig } from "./pgProxy.js";
import type { PlanResult, ProxyTransport, QueryResult, SchemaColumn } from "./transport.js";

/** The recoverable block returned when the proxy connection cannot be opened. */
function connectBlock(err: unknown): BlockBody {
  const detail = err instanceof Error ? err.message : String(err);
  return {
    code: "PROXY_UNAVAILABLE",
    reason: `the proxy read endpoint is not reachable: ${detail}`,
    remedy:
      "ensure the stack is up (deploy/up.sh) and the proxy is healthy, then retry the read",
    retryable: true,
  };
}

/**
 * How `LazyProxyTransport` opens a live transport. Defaults to the real
 * `PgProxyTransport.connect`; tests inject a fake to drive the connection-loss
 * path (the warden `pg_terminate_backend` / TCP reset / restart) deterministically.
 */
export type ProxyDial = (config: PgProxyConfig) => Promise<PgProxyTransport>;

/**
 * A `ProxyTransport` that defers `PgProxyTransport.connect(...)` to the first
 * read. A failed connect is returned as a recoverable block (per method) instead
 * of throwing, so the MCP handshake is never blocked on backend availability.
 */
export class LazyProxyTransport implements ProxyTransport {
  private connected: PgProxyTransport | undefined;
  /** In-flight connect attempt, so concurrent first-reads share one dial. */
  private dialing: Promise<PgProxyTransport | undefined> | undefined;
  /** The most recent dial error (for the block detail). */
  private lastError: unknown;

  constructor(
    private readonly config: PgProxyConfig,
    private readonly dial: ProxyDial = PgProxyTransport.connect,
  ) {}

  /**
   * Resolve the live transport, dialing once on first use. Returns `undefined`
   * (NOT a throw) if the connection cannot be established, so each caller can
   * surface its own recoverable block. A failed dial is not cached — a later
   * read retries (the stack may have come up in the meantime).
   *
   * When a dial succeeds we register an `onLost` callback on the live transport.
   * node-postgres emits an async `'error'` whenever the backend connection drops
   * (a backend restart, an idle TCP reset, or the warden calling
   * `pg_terminate_backend` on the agent-tagged session; SPEC §3 layer 2). The
   * transport turns that into a `onLost` signal here; we DROP the cached
   * connection so the NEXT read RE-DIALS (reconnect) instead of reusing a dead
   * client — and the lost client never crashes the process.
   */
  private async ensure(): Promise<PgProxyTransport | undefined> {
    // A cached-but-dead transport (its connection was lost) must be re-dialled.
    if (this.connected && this.connected.isDead()) {
      this.connected = undefined;
    }
    if (this.connected) return this.connected;
    if (this.dialing) return this.dialing;
    this.dialing = this.dial(this.config)
      .then((t) => {
        // Drop the cache the moment THIS connection is lost so the next read
        // re-dials. `onLost` fires synchronously if it is already dead.
        t.onLost((err) => {
          this.lastError = err;
          if (this.connected === t) this.connected = undefined;
        });
        // Guard against a loss that landed between connect and listener attach
        // (`onLost` already covers the already-dead case, but be explicit).
        if (!t.isDead()) this.connected = t;
        return t;
      })
      .catch((err) => {
        this.lastError = err;
        return undefined;
      })
      .finally(() => {
        this.dialing = undefined;
      });
    return this.dialing;
  }

  async query(sql: string, intent: IntentTiers): Promise<QueryResult> {
    const t = await this.ensure();
    if (!t) return { outcome: "blocked", block: connectBlock(this.lastError) };
    return t.query(sql, intent);
  }

  async discoverSchema(): Promise<SchemaColumn[]> {
    const t = await this.ensure();
    if (!t) {
      // discoverSchema has no block channel in the interface; throwing here is
      // caught by the server's tool dispatch and relayed as a structured error.
      throw new Error(connectBlock(this.lastError).reason);
    }
    return t.discoverSchema();
  }

  async explain(sql: string): Promise<PlanResult | { blocked: BlockBody }> {
    const t = await this.ensure();
    if (!t) return { blocked: connectBlock(this.lastError) };
    return t.explain(sql);
  }

  /** Close the underlying connection if one was ever opened. */
  async close(): Promise<void> {
    if (this.connected) {
      const t = this.connected;
      this.connected = undefined;
      await t.close().catch(() => undefined);
    }
  }
}
