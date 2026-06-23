//! Audit recording for the proxy (SPEC §3/§4 "Records every statement incl.
//! rejects").
//!
//! Every gate verdict — allow, block, reject — and every mid-stream cutoff is
//! appended to a hash-chained [`pgb_audit`] sink, stamped from a `core::Clock`
//! so the chain order is deterministic and wall-clock-free. The recorder owns
//! the principal (the audited agent role + session id) and the
//! [`pgb_audit::Sink`], and exposes a thin verb for each outcome the session
//! loop produces.
//!
//! The sink is a trait object so the proxy can write to an [`pgb_audit::InMemorySink`]
//! in tests and the Postgres `_meta` sink in production without changing the
//! session loop.

use std::sync::{Arc, Mutex};

use pgb_audit::{Decision, NewEntry, Principal, Sink};
use pgb_core::Clock;
use pgb_policy::IntentTiers;

/// Records gate outcomes onto a hash-chained audit sink.
///
/// Cloneable + `Send`/`Sync`: the sink and clock are shared behind an `Arc`, so
/// every connection task records onto the same chain. The `Mutex` serializes
/// appends, which is required anyway — a hash chain is inherently sequential.
#[derive(Clone)]
pub struct Recorder {
    sink: Arc<Mutex<dyn Sink + Send>>,
    clock: Arc<dyn Clock>,
    role: String,
}

impl Recorder {
    /// Build a recorder over a shared sink + clock, auditing `role`.
    pub fn new(
        sink: Arc<Mutex<dyn Sink + Send>>,
        clock: Arc<dyn Clock>,
        role: impl Into<String>,
    ) -> Self {
        Recorder {
            sink,
            clock,
            role: role.into(),
        }
    }

    /// Record one decision about one statement. Errors from the sink are
    /// surfaced as a string (the session decides whether a failed audit append
    /// is fatal — for the audit-is-evidence guarantee, it should be).
    pub fn record(
        &self,
        session_id: &str,
        statement_text: &str,
        decision: Decision,
        reason_code: &str,
        reason: Option<String>,
    ) -> Result<(), String> {
        let entry = NewEntry {
            statement_text: statement_text.to_string(),
            decision,
            reason_code: reason_code.to_string(),
            reason,
            principal: Principal {
                role: self.role.clone(),
                session_id: Some(session_id.to_string()),
                principal: None,
            },
            intent: IntentTiers::from_statement(&self.role, statement_text, Some("proxy".into())),
            write_safety: Default::default(),
        };
        let ts = self.clock.now_unix_millis();
        let mut sink = self
            .sink
            .lock()
            .map_err(|_| "audit sink mutex poisoned".to_string())?;
        sink.append(entry, ts).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The injected clock backing this recorder.
    ///
    /// Exposed so the session loop can drive the deterministic per-window volume
    /// meter ([`crate::window::WindowMeter`]) off the **same** injected clock the
    /// audit chain is stamped from — one time source per session, swappable for a
    /// [`pgb_core::MockClock`] in tests.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    /// Convenience: record an allowed statement.
    pub fn allow(&self, session_id: &str, sql: &str) -> Result<(), String> {
        self.record(session_id, sql, Decision::Allow, "ok", None)
    }

    /// Convenience: record a blocked statement (read-only / cutoff).
    pub fn block(
        &self,
        session_id: &str,
        sql: &str,
        code: &str,
        reason: Option<String>,
    ) -> Result<(), String> {
        self.record(session_id, sql, Decision::Block, code, reason)
    }

    /// Convenience: record a rejected frame (extended-only).
    pub fn reject(
        &self,
        session_id: &str,
        sql: &str,
        code: &str,
        reason: Option<String>,
    ) -> Result<(), String> {
        self.record(session_id, sql, Decision::Reject, code, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_audit::{InMemorySink, verify_chain};
    use pgb_core::MockClock;

    fn shared_inmem() -> (Recorder, Arc<Mutex<InMemorySink>>) {
        let inner = Arc::new(Mutex::new(InMemorySink::new()));
        // Two Arc handles to the same sink: one as the trait object the recorder
        // uses, one concrete for the test to read the chain back.
        let as_trait: Arc<Mutex<dyn Sink + Send>> = inner.clone();
        let clock: Arc<dyn Clock> = Arc::new(MockClock::starting_at(1_700_000_000_000));
        (Recorder::new(as_trait, clock, "pgb_agent"), inner)
    }

    #[test]
    fn records_allow_block_reject_and_chain_verifies() {
        let (rec, sink) = shared_inmem();
        rec.allow("s1", "SELECT 1").unwrap();
        rec.reject(
            "s1",
            "COMMIT; DROP SCHEMA public CASCADE",
            "simple_query_rejected",
            None,
        )
        .unwrap();
        rec.block("s1", "UPDATE t SET x=1", "write_on_readonly", None)
            .unwrap();

        let chain = sink.lock().unwrap().chain().records().to_vec();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].payload.decision, Decision::Allow);
        assert_eq!(chain[1].payload.decision, Decision::Reject);
        assert_eq!(chain[2].payload.decision, Decision::Block);
        // The marquee statement-stacking attempt is captured verbatim.
        assert!(chain[1].payload.statement_text.contains("DROP SCHEMA"));
        verify_chain(&chain).expect("chain must verify");
    }
}
