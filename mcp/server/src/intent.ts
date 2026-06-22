/**
 * Tiered intent capture, T0–T2 (SPEC §11.2, §11.5, §15.3 one-way door).
 *
 * Mirrors the canonical Rust shape in `crates/policy/src/intent.rs`. The MCP
 * server sits cooperatively in front of the wire, so it INFERS intent rather
 * than demanding it. In the MVP these tiers are **captured and logged only** —
 * serialized into the audit/blast-radius record but NOT acted on. T3 (explicit
 * MCP asserts) and T4 (attested provenance) are out of MVP scope.
 *
 * Critical posture: this parser is best-effort and NEVER fails the action on a
 * malformed annotation — it just leaves fields empty. Absence of an intent
 * signal must never loosen *or* (DoS) tighten anything in MVP; the annotation is
 * attacker-controllable, so it is logged, never trusted.
 */

/** T0 — coarse role / identity. Always available at the wire. */
export interface TierT0 {
  /** The database role / principal the session authenticated as. */
  role: string;
  /** Optional coarse purpose/scope label (informational in MVP). */
  purpose?: string;
}

/** A parsed `/* intent: … ticket: … actor: … *​/` annotation (T1). */
export interface IntentAnnotation {
  intent?: string;
  ticket?: string;
  actor?: string;
}

/** T1 — the SQL itself + comments + application_name / GUCs. */
export interface TierT1 {
  /** The raw statement text as seen at the wire. */
  statement_text: string;
  /** Coarse statement class derived from the leading keyword. */
  statement_class?: string;
  /** The libpq application_name, if set. */
  application_name?: string;
  /** Selected session GUCs (e.g. a pg_bumpers.trace_id). */
  gucs: Record<string, string>;
  /** The parsed /* intent: … *​/ annotation. */
  annotation: IntentAnnotation;
}

/** T2 — observed session context / behavioral inference (subset for MVP). */
export interface TierT2 {
  /** Whether at least one read preceded this write in the session. */
  reads_before_write: boolean;
  /** Distinct relations touched in the session window (best-effort). */
  tables: string[];
}

/** The full T0–T2 intent-capture record logged with each action. */
export interface IntentTiers {
  t0: TierT0;
  t1: TierT1;
  t2: TierT2;
}

/**
 * Derive the coarse statement class from the leading SQL keyword. Best-effort
 * and case-insensitive; returns undefined when no keyword is recognizable. This
 * is an INFERENCE for logging — it is NOT the read/write classifier the floor
 * relies on (see classifier.ts).
 */
export function statementClass(sql: string): string | undefined {
  const m = stripLeadingComments(sql).match(/^\s*([A-Za-z]+)/);
  if (!m) return undefined;
  return m[1].toUpperCase();
}

/**
 * Parse a `/* intent: … ticket: … actor: … *​/` annotation from the SQL's
 * comments. Best-effort: unrecognized or empty fields are simply omitted. Never
 * throws.
 */
export function parseAnnotation(sql: string): IntentAnnotation {
  const ann: IntentAnnotation = {};
  // Scan every block comment; the first key occurrence wins.
  const comments = sql.match(/\/\*[\s\S]*?\*\//g) ?? [];
  for (const c of comments) {
    for (const key of ["intent", "ticket", "actor"] as const) {
      if (ann[key] !== undefined) continue;
      // key: value  — value runs until the next recognized key or comment end.
      const re = new RegExp(`${key}\\s*:\\s*([^*]*?)(?=\\b(?:intent|ticket|actor)\\s*:|\\*/|$)`, "i");
      const m = c.match(re);
      if (m) {
        const val = m[1].trim();
        if (val.length > 0) ann[key] = val;
      }
    }
  }
  return ann;
}

/** Strip leading line/block comments so the leading keyword is reachable. */
function stripLeadingComments(sql: string): string {
  let s = sql;
  // Loop because comments can stack.
  for (;;) {
    const before = s;
    s = s.replace(/^\s+/, "");
    s = s.replace(/^--[^\n]*\n?/, "");
    s = s.replace(/^\/\*[\s\S]*?\*\//, "");
    if (s === before) break;
  }
  return s;
}

/**
 * Capture T0–T2 intent for one statement. Pure and total: any input yields a
 * fully-populated record (empty fields where signal is absent). The result is
 * meant to be *logged*, never to gate.
 */
export function captureIntent(args: {
  role: string;
  sql: string;
  applicationName?: string;
  gucs?: Record<string, string>;
  readsBeforeWrite?: boolean;
  tables?: string[];
  purpose?: string;
}): IntentTiers {
  return {
    t0: { role: args.role, ...(args.purpose ? { purpose: args.purpose } : {}) },
    t1: {
      statement_text: args.sql,
      statement_class: statementClass(args.sql),
      ...(args.applicationName ? { application_name: args.applicationName } : {}),
      gucs: args.gucs ?? {},
      annotation: parseAnnotation(args.sql),
    },
    t2: {
      reads_before_write: args.readsBeforeWrite ?? false,
      tables: args.tables ?? [],
    },
  };
}
