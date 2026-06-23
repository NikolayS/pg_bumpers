//! `ThreadedSink` — run the SYNCHRONOUS `_meta` `PgSink` on a dedicated OS thread
//! so the proxy's `#[tokio::main]` async runtime never collides with the sync
//! `postgres` client.
//!
//! ## Why this exists (the real blocker it fixes)
//! The audit `_meta` sink ([`pgb_audit::PgSink`]) is backed by the **synchronous**
//! `postgres` crate, whose client drives its OWN internal tokio runtime via
//! `block_on`. The proxy serves connections on a multi-threaded tokio runtime and
//! the `Recorder` appends a gate verdict **synchronously from inside an async
//! task** on every statement. Calling the sync client there panics with
//! "Cannot start a runtime from within a runtime" (a `block_on` is forbidden while
//! a runtime is entered). The proxy binary was only ever exercised with the
//! in-memory sink before, so this never surfaced until it was launched as a real
//! process against a live `_meta` chain (deploy/up.sh).
//!
//! ## What it does
//! `ThreadedSink` owns the real `PgSink` on a dedicated `std::thread` that is NOT
//! inside the tokio runtime (so the sync client's `block_on` is legal there). It
//! implements the synchronous [`Sink`] trait by forwarding each `append` /
//! `load_chain` over a channel and blocking on the reply. The recorder keeps its
//! existing synchronous API; only the place the bytes ultimately hit the DB moves
//! off the runtime threads.
//!
//! Cross-process chain integrity is unchanged: [`PgSink::append`] already
//! serializes the head-read + insert under a `pg_advisory_xact_lock`, so the proxy
//! recorder's own client appends safely alongside applyd/warden (each their own
//! client) onto the one shared `_meta.audit_log`.

use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;

use pgb_audit::{AuditRecord, NewEntry, PgSink, Sink, SinkError};

/// One request to the audit thread + its reply channel.
enum Cmd {
    Append {
        entry: Box<NewEntry>,
        timestamp_ms: u64,
        reply: Sender<Result<AuditRecord, SinkError>>,
    },
    LoadChain {
        reply: Sender<Result<Vec<AuditRecord>, SinkError>>,
    },
}

/// A [`Sink`] that forwards to a `PgSink` owned by a dedicated OS thread.
pub struct ThreadedSink {
    // `Option` so `Drop` can drop the sender FIRST (closing the channel and
    // ending the thread's loop) and only THEN join — otherwise the join would
    // hang on a thread still blocked reading the (not-yet-closed) channel.
    tx: Option<Sender<Cmd>>,
    handle: Option<JoinHandle<()>>,
}

impl ThreadedSink {
    /// Connect a fresh writer `Client` to `writer_dsn` (the `pgb_audit_writer`
    /// role) ON the dedicated thread and serve `Sink` calls from it. Returns an
    /// error if the initial connect fails (fail-closed: no audit sink ⇒ refuse to
    /// start, same posture as the boot path).
    pub fn connect(writer_dsn: &str) -> Result<Self, SinkError> {
        let (tx, rx) = std::sync::mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let dsn = writer_dsn.to_string();
        let handle = std::thread::Builder::new()
            .name("pgb-proxy-audit".to_string())
            .spawn(move || run(dsn, rx, ready_tx))
            .map_err(|e| SinkError::Backend(format!("spawn audit thread: {e}")))?;
        // Block until the thread has connected (or failed to).
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(ThreadedSink {
                tx: Some(tx),
                handle: Some(handle),
            }),
            Ok(Err(e)) => Err(SinkError::Backend(e)),
            Err(e) => Err(SinkError::Backend(format!(
                "audit thread died on start: {e}"
            ))),
        }
    }
}

/// The dedicated thread body: connect the sync client, signal readiness, then
/// serve commands until the channel closes.
fn run(dsn: String, rx: Receiver<Cmd>, ready: Sender<Result<(), String>>) {
    let mut sink = match PgSink::connect(&dsn) {
        Ok(s) => s,
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    for cmd in rx {
        match cmd {
            Cmd::Append {
                entry,
                timestamp_ms,
                reply,
            } => {
                let _ = reply.send(sink.append(*entry, timestamp_ms));
            }
            Cmd::LoadChain { reply } => {
                let _ = reply.send(sink.load_chain_mut());
            }
        }
    }
}

impl Sink for ThreadedSink {
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| SinkError::Backend("audit thread is gone".to_string()))?;
        let (reply, reply_rx) = std::sync::mpsc::channel();
        tx.send(Cmd::Append {
            entry: Box::new(entry),
            timestamp_ms,
            reply,
        })
        .map_err(|_| SinkError::Backend("audit thread is gone".to_string()))?;
        reply_rx
            .recv()
            .map_err(|_| SinkError::Backend("audit thread dropped the reply".to_string()))?
    }

    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| SinkError::Backend("audit thread is gone".to_string()))?;
        let (reply, reply_rx) = std::sync::mpsc::channel();
        tx.send(Cmd::LoadChain { reply })
            .map_err(|_| SinkError::Backend("audit thread is gone".to_string()))?;
        reply_rx
            .recv()
            .map_err(|_| SinkError::Backend("audit thread dropped the reply".to_string()))?
    }
}

impl Drop for ThreadedSink {
    fn drop(&mut self) {
        // Drop the sender FIRST: that closes the channel, so the thread's
        // `for cmd in rx` loop ends and the thread exits. THEN join for a clean
        // teardown (a stale audit thread must never outlive the proxy).
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
