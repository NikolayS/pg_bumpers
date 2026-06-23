//! The **frontend-frame gate**: the pure enforcement decision the proxy applies
//! to every client message before it is allowed near the backend (SPEC §3
//! layer 2, §4, §7 S1).
//!
//! This module is deliberately **pure and synchronous** so the whole gate is
//! unit-testable without a socket or a database — the marquee `COMMIT; DROP
//! SCHEMA public CASCADE` statement-stacking block is proven here as a plain
//! function call, then exercised end-to-end through the FE/BE loop.
//!
//! Two layers, both fail-closed:
//!
//! 1. **Tag gate** (extended-protocol-only): a simple `Query` ('Q') or any
//!    `Copy*` frame is **rejected** outright — this is what kills statement
//!    stacking, because the agent can never use the only protocol path that
//!    permits multiple statements in one message.
//! 2. **SQL gate** (read-only): the SQL text carried by an extended-protocol
//!    `Parse` is classified by [`pgb_pgwire::classify`]; anything not provably a
//!    single read is **blocked**. The classifier is advisory — the WALL role is
//!    the un-foolable backstop — but the proxy still gates on it and audits.

use pgb_pgwire::{
    Classification, FrontendMessage, NotReadReason, RejectReason, classify_frontend_tag,
    classify_with_reason,
};

/// The gate's verdict for one frontend frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Forward the frame to the backend. Carries the SQL text when the frame is
    /// a `Parse` (so the caller can audit the allowed statement) — `None` for
    /// the structural extended-protocol frames (Bind/Execute/Sync/…).
    Allow {
        /// The prepared statement's SQL, when this frame is a `Parse`.
        sql: Option<String>,
    },
    /// Reject the frame before it reaches the backend: respond with a structured
    /// `ErrorResponse` and (for the simple-query/COPY case) refuse the protocol.
    /// `REJECT` in the audit taxonomy — refused at/ before parse.
    Reject {
        /// The structural reason this frame is refused.
        kind: RejectKind,
        /// A short machine-readable reason code (audit + error `C`ode field).
        code: &'static str,
        /// A human-readable message for the `ErrorResponse` `M` field.
        message: String,
    },
    /// Block the statement on a content rule (read-only) — a recoverable error;
    /// the session continues. `BLOCK` in the audit taxonomy.
    Block {
        /// The SQL that was blocked (for audit).
        sql: String,
        /// A short machine-readable reason code.
        code: &'static str,
        /// A human-readable message for the `ErrorResponse` `M` field.
        message: String,
    },
}

/// Why a frame was structurally rejected (the extended-protocol-only gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// A simple `Query` ('Q') — the statement-stacking vector.
    SimpleQuery,
    /// A `Copy*` frontend frame — the bulk path (no per-statement gate;
    /// `COPY … PROGRAM` is an RCE vector).
    Copy,
}

/// The stateless enforcement gate. Holds no mutable state — all per-statement
/// state (budgets, audit chain) lives in the session — so a single instance can
/// gate every connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct Enforcement;

impl Enforcement {
    /// Construct the gate.
    pub fn new() -> Self {
        Enforcement
    }

    /// Decide what to do with one decoded frontend frame.
    ///
    /// `Parse` is the only frame that carries SQL to classify; the other
    /// extended-protocol frames (`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/
    /// `Close`/`Terminate`) are structural and forwarded. `Query` and `Copy*`
    /// are rejected (extended-only). Auth-phase frames must never reach here
    /// (the session handles auth before the query loop).
    pub fn gate(&self, msg: &FrontendMessage) -> GateDecision {
        // (1) Tag gate first — cheap, structural, fail-closed.
        if let Err(reason) = classify_frontend_tag(msg.tag()) {
            return match reason {
                RejectReason::SimpleQuery => GateDecision::Reject {
                    kind: RejectKind::SimpleQuery,
                    code: "simple_query_rejected",
                    message: "simple query protocol is not permitted for agent \
                              connections; use the extended protocol (Parse/Bind/\
                              Execute) — this blocks statement-stacking such as \
                              `COMMIT; DROP SCHEMA …`"
                        .to_string(),
                },
                RejectReason::Copy => GateDecision::Reject {
                    kind: RejectKind::Copy,
                    code: "copy_rejected",
                    message: "COPY is not permitted for agent connections \
                              (no per-statement gate; COPY … PROGRAM is an RCE \
                              vector)"
                        .to_string(),
                },
            };
        }

        // (2) SQL gate — only `Parse` carries statement text to classify.
        match msg {
            FrontendMessage::Parse { sql, .. } => self.gate_sql(sql),
            // Structural extended-protocol frames: forwarded verbatim.
            _ => GateDecision::Allow { sql: None },
        }
    }

    /// The read-only content gate for an extended-protocol statement's SQL.
    ///
    /// Fail-closed: a parse error, statement-stacking, an empty body, or any
    /// non-read statement is **blocked**. A single provable read is allowed —
    /// still subject to the WALL role + cutoff + timeout downstream.
    pub fn gate_sql(&self, sql: &str) -> GateDecision {
        match classify_with_reason(sql) {
            (Classification::Read, _) => GateDecision::Allow {
                sql: Some(sql.to_string()),
            },
            (Classification::NotRead, reason) => {
                let (code, message) = not_read_message(reason);
                GateDecision::Block {
                    sql: sql.to_string(),
                    code,
                    message,
                }
            }
        }
    }
}

/// Map a not-read reason to an audit code + a user-facing message.
fn not_read_message(reason: Option<NotReadReason>) -> (&'static str, String) {
    match reason {
        Some(NotReadReason::MultipleStatements) => (
            "stacked_statement",
            "multiple statements in one Parse are not permitted (statement-\
             stacking); send exactly one read statement"
                .to_string(),
        ),
        Some(NotReadReason::ParseError) => (
            "parse_failed",
            "statement could not be parsed; the read-only gate fails closed and \
             refuses anything it cannot prove is a single read"
                .to_string(),
        ),
        Some(NotReadReason::Empty) => (
            "empty_statement",
            "empty statement is not a read".to_string(),
        ),
        Some(NotReadReason::NotAReadStatement) | None => (
            "write_on_readonly",
            "only read-only statements are permitted on the agent read path \
             (writes/DDL/utility/COPY are blocked)"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn parse(sql: &str) -> FrontendMessage {
        FrontendMessage::Parse {
            statement: String::new(),
            sql: sql.to_string(),
            param_types: vec![],
        }
    }

    #[test]
    fn allows_a_single_select() {
        let g = Enforcement::new();
        match g.gate(&parse("SELECT id FROM public.allowed_read")) {
            GateDecision::Allow { sql: Some(s) } => {
                assert!(s.contains("SELECT"));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn marquee_commit_drop_schema_is_rejected_as_simple_query() {
        // The headline statement-stacking attack arriving over the SIMPLE query
        // protocol ('Q'): rejected structurally, before the body is even parsed.
        let g = Enforcement::new();
        let attack = FrontendMessage::Query {
            sql: "COMMIT; DROP SCHEMA public CASCADE".to_string(),
        };
        match g.gate(&attack) {
            GateDecision::Reject {
                kind: RejectKind::SimpleQuery,
                code,
                ..
            } => assert_eq!(code, "simple_query_rejected"),
            other => panic!("expected SimpleQuery Reject, got {other:?}"),
        }
    }

    #[test]
    fn marquee_commit_drop_schema_is_blocked_even_via_extended_parse() {
        // Defense-in-depth: even if the attacker smuggles the stacked statement
        // into a single Parse body, the read-only classifier blocks it
        // (MultipleStatements). The simple-query path is rejected above; this is
        // the belt to that suspenders.
        let g = Enforcement::new();
        match g.gate(&parse("COMMIT; DROP SCHEMA public CASCADE")) {
            GateDecision::Block { code, .. } => assert_eq!(code, "stacked_statement"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn blocks_update_delete_ddl() {
        let g = Enforcement::new();
        for sql in [
            "UPDATE public.allowed_read SET label = 'x'",
            "DELETE FROM public.allowed_read",
            "DROP TABLE public.allowed_read",
            "CREATE TABLE t (id int)",
            "TRUNCATE public.allowed_read",
        ] {
            match g.gate(&parse(sql)) {
                GateDecision::Block { code, .. } => assert_eq!(code, "write_on_readonly", "{sql}"),
                other => panic!("expected Block for {sql}, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_copy_frontend_frames() {
        let g = Enforcement::new();
        for f in [
            FrontendMessage::CopyData {
                data: Bytes::from_static(b"x"),
            },
            FrontendMessage::CopyDone,
            FrontendMessage::CopyFail {
                message: "x".to_string(),
            },
        ] {
            match g.gate(&f) {
                GateDecision::Reject {
                    kind: RejectKind::Copy,
                    ..
                } => {}
                other => panic!("expected Copy reject, got {other:?}"),
            }
        }
    }

    #[test]
    fn fail_closed_on_unparseable_sql() {
        let g = Enforcement::new();
        match g.gate(&parse("SELEKT * FRM nonsense !!!")) {
            GateDecision::Block { code, .. } => assert_eq!(code, "parse_failed"),
            other => panic!("expected Block(parse_failed), got {other:?}"),
        }
    }

    #[test]
    fn classifier_blind_spot_pg_sleep_classifies_as_read() {
        // Honesty: the advisory classifier does NOT catch pg_sleep — it is a
        // SELECT and classifies as Read. The proxy lets it through the gate and
        // relies on statement_timeout (an un-foolable backstop) to stop it. This
        // test documents the blind spot so the timeout backstop is justified.
        let g = Enforcement::new();
        assert!(matches!(
            g.gate(&parse("SELECT pg_sleep(30)")),
            GateDecision::Allow { .. }
        ));
    }

    #[test]
    fn structural_extended_frames_pass_through() {
        let g = Enforcement::new();
        for f in [
            FrontendMessage::Sync,
            FrontendMessage::Flush,
            FrontendMessage::Execute {
                portal: String::new(),
                max_rows: 0,
            },
            FrontendMessage::Terminate,
        ] {
            assert!(matches!(g.gate(&f), GateDecision::Allow { sql: None }));
        }
    }
}
