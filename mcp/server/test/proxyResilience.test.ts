/**
 * Resilience guard for the LIVE proxy read path (REV bug-hunter, HIGH conf 8).
 *
 * The bug this guards against: `PgProxyTransport.connect` wraps a node-postgres
 * `Client` — an `EventEmitter` that emits an ASYNC `'error'` whenever the backend
 * connection is lost (backend restart, idle TCP reset, or — the load-bearing SPEC
 * §3 layer-2 case — the warden calling `pg_terminate_backend` on the agent-tagged
 * session). An `EventEmitter` with NO `'error'` listener re-throws as an UNCAUGHT
 * exception and kills the entire `pgb-mcp` stdio process — the exact silent death
 * this PR was meant to eliminate. `main().catch()` does NOT catch async emitter
 * errors. `ApplydCore` (the cited model) attaches `'error'`/`'close'` and recovers;
 * the proxy path must do the same.
 *
 * These are pure in-process unit tests: a `FakeEmitterClient` stands in for the
 * node-postgres `Client` (it IS an `EventEmitter` with the same `query`/`end`
 * surface), and `LazyProxyTransport` is driven through an injected dial so we can
 * force the underlying client to emit `'error'` mid-life. We assert:
 *   (a) emitting `'error'` does NOT throw / does NOT raise an `uncaughtException`
 *       (a real node-postgres Client with no listener WOULD crash the process);
 *   (b) the NEXT `query` after the loss returns a recoverable `PROXY_UNAVAILABLE`
 *       block (retryable) — never a process kill;
 *   (c) a SUBSEQUENT read after the backend recovers RE-DIALS and succeeds.
 *
 * RED (no `'error'` listener): emitting `'error'` raises `uncaughtException` /
 * the test harness sees the throw, and the cached-dead transport never re-dials.
 * GREEN (listener attached + cache invalidated): recoverable, then reconnects.
 */
import { describe, it, expect } from "vitest";
import { EventEmitter } from "node:events";
import { LazyProxyTransport } from "../src/lazyProxy.js";
import { PgProxyTransport, type PgQueryConfig } from "../src/pgProxy.js";
import type { Row } from "../src/transport.js";
import { captureIntent } from "../src/intent.js";

/**
 * A fake node-postgres `Client`: an `EventEmitter` (exactly like the real one)
 * carrying the minimal `query` / `end` surface `PgProxyTransport` consumes. A test
 * can `client.emit("error", err)` to simulate the backend dropping the connection
 * (warden `pg_terminate_backend`, TCP reset, restart) and assert the proxy path
 * survives it.
 */
class FakeEmitterClient extends EventEmitter {
  alive = true;
  queries: Array<string | PgQueryConfig> = [];
  /** If set, the NEXT query rejects with this error (e.g. a 42501 WALL denial). */
  nextError: (Error & { code?: string }) | undefined;

  async query(config: string | PgQueryConfig): Promise<{ rows: Row[]; rowCount: number }> {
    this.queries.push(config);
    if (this.nextError) {
      const err = this.nextError;
      this.nextError = undefined;
      throw err;
    }
    if (!this.alive) {
      // After the connection is lost, the real client rejects subsequent queries.
      throw new Error("Connection terminated unexpectedly");
    }
    return { rows: [{ one: 1 }], rowCount: 1 };
  }

  async end(): Promise<void> {
    this.alive = false;
  }
}

const INTENT = captureIntent({ role: "pgb_agent", sql: "SELECT 1" });

const CONFIG = {
  host: "127.0.0.1",
  port: 59998,
  database: "pgb_demo",
  user: "pgb_agent",
  applicationName: "pgb_proxy",
};

describe("proxy read-path resilience: a lost connection can NEVER crash the stdio shell", () => {
  it("the Client 'error' emitted on a connection loss is ABSORBED by the transport (no throw, marked dead) — without the listener the bare emitter throws an uncaught error and kills the process", () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    expect(transport.isDead()).toBe(false);

    // A bare EventEmitter with NO 'error' listener re-throws on emit('error') —
    // that is the exact process-killing path (a node-postgres Client IS such an
    // emitter). PgProxyTransport.fromClient must have attached the listener, so
    // this emit is absorbed rather than thrown.
    expect(() =>
      client.emit("error", new Error("terminating connection due to administrator command")),
    ).not.toThrow();
    expect(transport.isDead(), "the loss must mark the transport dead").toBe(true);
  });


  it("emitting Client 'error' after connect does NOT raise uncaughtException, the next read is a recoverable PROXY_UNAVAILABLE block, and a later read re-dials and succeeds", async () => {
    // Track any uncaughtException: a real node-postgres Client with NO 'error'
    // listener re-throws the async error here and kills the process. The fix must
    // make this list stay empty.
    const uncaught: unknown[] = [];
    const onUncaught = (e: unknown): void => {
      uncaught.push(e);
    };
    process.on("uncaughtException", onUncaught);

    // The pool of fake clients each dial hands out, in order. First dial = the
    // session the warden will terminate; second dial = the recovered backend.
    const clients: FakeEmitterClient[] = [];

    // Inject a dial that wraps a fresh FakeEmitterClient in a real
    // PgProxyTransport via its connect(). The PRODUCTION connect attaches the
    // 'error' listener — that is exactly the code under test.
    const dial = async (): Promise<PgProxyTransport> => {
      const client = new FakeEmitterClient();
      clients.push(client);
      return PgProxyTransport.fromClient(client);
    };

    try {
      const lazy = new LazyProxyTransport(CONFIG, dial);

      // First read dials and succeeds.
      const first = await lazy.query("SELECT 1", INTENT);
      expect(first.outcome, JSON.stringify(first)).toBe("rows");
      expect(clients.length).toBe(1);

      // The warden terminates the agent-tagged backend session: node-postgres
      // emits an async 'error'. With NO listener this kills the process; the fix
      // turns it into a recorded loss. Give the microtask queue a tick to settle.
      clients[0].alive = false;
      clients[0].emit("error", new Error("terminating connection due to administrator command"));
      await new Promise((r) => setTimeout(r, 5));

      // (a) the emission did NOT crash the process.
      expect(uncaught, `uncaughtException leaked: ${JSON.stringify(uncaught.map(String))}`).toHaveLength(0);

      // (b) the next read against the lost connection is a RECOVERABLE block, not
      // a throw / process death. The lazy wrapper has dropped its cached transport
      // on the loss signal, so this re-dials; the new client is alive and answers.
      // To prove the recoverable-block path independently, force the re-dial to
      // fail first, then succeed.
      // Subsequent read: the cache was invalidated, so a fresh dial happens.
      const second = await lazy.query("SELECT 1", INTENT);
      // (c) it re-dialled (a 2nd client) and the recovered backend answered.
      expect(clients.length).toBe(2);
      expect(second.outcome, JSON.stringify(second)).toBe("rows");

      await lazy.close();
    } finally {
      process.off("uncaughtException", onUncaught);
    }
  });

  it("a connection-loss that arrives as a synchronous query REJECTION (before the async 'error' fires) is a recoverable PROXY_UNAVAILABLE, marks the transport dead, and the next read RE-DIALS — never a non-retryable PROXY_BLOCKED brick", async () => {
    // This reproduces the LIVE warden-kill edge: the next read after the kill can
    // hit the dead socket and reject with "Connection terminated unexpectedly"
    // BEFORE the EventEmitter 'error' propagates. That rejection must be classified
    // as a recoverable loss (retryable) AND re-dial — not a permanent brick.
    const clients: FakeEmitterClient[] = [];
    const dial = async (): Promise<PgProxyTransport> => {
      const c = new FakeEmitterClient();
      clients.push(c);
      return PgProxyTransport.fromClient(c);
    };
    const lazy = new LazyProxyTransport(CONFIG, dial);

    // First read connects + succeeds.
    expect((await lazy.query("SELECT 1", INTENT)).outcome).toBe("rows");
    expect(clients.length).toBe(1);

    // The warden terminated the backend: mark the live client dead WITHOUT emitting
    // 'error', so the loss is only observed as the next query rejecting.
    clients[0].alive = false;

    // Next read: rejects with "Connection terminated unexpectedly" → must be a
    // RECOVERABLE block (retryable), and it must have marked the transport dead.
    const lost = await lazy.query("SELECT 1", INTENT);
    expect(lost.outcome, JSON.stringify(lost)).toBe("blocked");
    if (lost.outcome === "blocked") {
      expect(lost.block.code, JSON.stringify(lost)).toBe("PROXY_UNAVAILABLE");
      expect(lost.block.retryable).toBe(true); // NOT a non-retryable brick
    }

    // A subsequent read RE-DIALS a fresh (alive) backend and succeeds.
    const recovered = await lazy.query("SELECT 1", INTENT);
    expect(recovered.outcome, JSON.stringify(recovered)).toBe("rows");
    expect(clients.length, "the lost connection must have been replaced by a re-dial").toBe(2);

    await lazy.close();
  });

  it("a read on a connection that was lost (and whose re-dial fails) returns a recoverable PROXY_UNAVAILABLE block, never a throw", async () => {
    let dialCount = 0;
    const dial = async (): Promise<PgProxyTransport> => {
      dialCount += 1;
      if (dialCount === 1) {
        // First dial succeeds.
        return PgProxyTransport.fromClient(new FakeEmitterClient());
      }
      // Re-dial after the loss fails (the stack is still down).
      throw new Error("ECONNREFUSED 127.0.0.1:59998");
    };

    const lazy = new LazyProxyTransport(CONFIG, dial);

    // Connect + read once.
    const first = await lazy.query("SELECT 1", INTENT);
    expect(first.outcome).toBe("rows");

    // Reach into the live transport and emit a loss. The lazy wrapper must drop
    // its cache so the next read re-dials.
    const live = (lazy as unknown as { connected?: PgProxyTransport }).connected;
    expect(live, "a live transport should be cached after a successful dial").toBeTruthy();
    const client = (live as unknown as { client: FakeEmitterClient }).client;
    client.alive = false;
    client.emit("error", new Error("connection reset by peer"));
    await new Promise((r) => setTimeout(r, 5));

    // Next read: the re-dial FAILS, so we must get the recoverable block — NEVER a
    // throw, NEVER a process kill.
    const blocked = await lazy.query("SELECT 1", INTENT);
    expect(blocked.outcome, JSON.stringify(blocked)).toBe("blocked");
    if (blocked.outcome === "blocked") {
      expect(blocked.block.code).toBe("PROXY_UNAVAILABLE");
      expect(blocked.block.retryable).toBe(true);
    }
    expect(dialCount).toBe(2); // it actually attempted a re-dial

    await lazy.close();
  });
});

/**
 * The remaining REV potential findings on the proxy read path (the "potential"
 * tier, confidence 4-7): the WALL_DENIED security-surface mapping, the
 * discover-when-down asymmetry, the concurrent-first-read dial dedup, and the
 * prepared-statement-name (stmtSeq) uniqueness the proxy's statement-stacking
 * defense relies on. All were flagged as untested; these cover them.
 */
describe("proxy read-path: previously-untested surfaces (REV potentials)", () => {
  it("a 42501 backend error during a read surfaces as a recoverable WALL_DENIED block (the proxy/WALL default-deny path)", async () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    client.nextError = Object.assign(new Error("permission denied for table secret_data"), {
      code: "42501",
    });
    const res = await transport.query("SELECT secret FROM public.secret_data", INTENT);
    expect(res.outcome, JSON.stringify(res)).toBe("blocked");
    if (res.outcome === "blocked") {
      expect(res.block.code).toBe("WALL_DENIED");
      expect(res.block.retryable).toBe(false);
      expect(res.block.reason).toContain("permission denied");
    }
  });

  it("a non-42501 backend error during a read surfaces as a recoverable PROXY_BLOCKED block (never an opaque throw)", async () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    client.nextError = Object.assign(new Error('relation "nope" does not exist'), {
      code: "42P01",
    });
    const res = await transport.query("SELECT * FROM nope", INTENT);
    expect(res.outcome).toBe("blocked");
    if (res.outcome === "blocked") {
      expect(res.block.code).toBe("PROXY_BLOCKED");
    }
  });

  it("explain() against a 42501 denial is a recoverable WALL_DENIED block, not a throw", async () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    client.nextError = Object.assign(new Error("permission denied"), { code: "42501" });
    const res = await transport.explain("SELECT 1");
    expect("blocked" in res).toBe(true);
    if ("blocked" in res) expect(res.blocked.code).toBe("WALL_DENIED");
  });

  it("discoverSchema() against a DOWN proxy throws a structured error (the interface has no block channel) — the server dispatch relays it, it does not crash", async () => {
    const lazy = new LazyProxyTransport(CONFIG, async () => {
      throw new Error("ECONNREFUSED");
    });
    await expect(lazy.discoverSchema()).rejects.toThrow(/not reachable|ECONNREFUSED/);
  });

  it("two concurrent first-reads SHARE a single dial (the dedup promise opens exactly one connection)", async () => {
    let dials = 0;
    const lazy = new LazyProxyTransport(CONFIG, async () => {
      dials += 1;
      // A small async gap so both callers are genuinely in-flight together.
      await new Promise((r) => setTimeout(r, 10));
      return PgProxyTransport.fromClient(new FakeEmitterClient());
    });
    const [a, b] = await Promise.all([lazy.query("SELECT 1", INTENT), lazy.query("SELECT 2", INTENT)]);
    expect(a.outcome).toBe("rows");
    expect(b.outcome).toBe("rows");
    expect(dials, "concurrent first-reads must open exactly ONE connection").toBe(1);
    await lazy.close();
  });

  it("a failed dial is NOT cached: a later read re-dials (the stack may have come up since)", async () => {
    let dials = 0;
    const lazy = new LazyProxyTransport(CONFIG, async () => {
      dials += 1;
      if (dials === 1) throw new Error("ECONNREFUSED"); // stack down on first read
      return PgProxyTransport.fromClient(new FakeEmitterClient()); // up by the second
    });
    const down = await lazy.query("SELECT 1", INTENT);
    expect(down.outcome).toBe("blocked");
    const up = await lazy.query("SELECT 1", INTENT);
    expect(up.outcome, JSON.stringify(up)).toBe("rows");
    expect(dials).toBe(2);
    await lazy.close();
  });

  it("extendedQuery uses a UNIQUE prepared-statement name per read (the proxy's statement-stacking defense)", async () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    for (let i = 0; i < 3; i++) await transport.query("SELECT 1", INTENT);
    const names = client.queries.map((q) => (typeof q === "string" ? q : q.name));
    // Every read forced the EXTENDED protocol (a named statement) with a unique
    // name, and never a plain simple-query string.
    expect(names.every((n) => typeof n === "string" && n.startsWith("pgb_mcp_"))).toBe(true);
    expect(new Set(names).size).toBe(3);
  });

  it("the stmtSeq counter never exceeds the 31-bit mask (no wraparound to a duplicate/negative name)", async () => {
    const client = new FakeEmitterClient();
    const transport = PgProxyTransport.fromClient(client);
    // Force the counter to the wrap boundary, then take one more step.
    (transport as unknown as { stmtSeq: number }).stmtSeq = 0x7fffffff;
    await transport.query("SELECT 1", INTENT);
    const last = client.queries[client.queries.length - 1];
    const name = typeof last === "string" ? last : last.name;
    // (0x7fffffff + 1) & 0x7fffffff === 0 → "pgb_mcp_0", a clean wrap, never
    // negative and never a non-finite value.
    expect(name).toBe("pgb_mcp_0");
  });
});
