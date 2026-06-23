//! The Postgres `_meta` audit sink (SPEC §4, §10.9), behind the `pg` feature.
//!
//! Appends sealed records to the append-only `pgb_audit.audit_log` table (see
//! `crates/audit/sql/10_audit_meta.sql`) and reads them back for
//! [`verify_chain`](crate::chain::verify_chain). The sink stores the **exact
//! canonical JSON bytes** the Rust side hashed (verbatim `text`, not `jsonb`,
//! since `jsonb` reorders keys and would change the digest), so a record read
//! back from Postgres recomputes to the identical `record_hash` and the chain
//! verifies byte-for-byte.
//!
//! The sink connects as the **audit-writer** role; it never connects as the
//! audited principal. The "audited cannot write audit" guarantee is enforced by
//! the table grants (the SQL `REVOKE`s the agent from INSERT/UPDATE/DELETE), and
//! the env-gated integration test proves it by *attempting* a write as the agent
//! and asserting it fails.

use postgres::Client;

use crate::chain::NewEntry;
use crate::record::{AuditPayload, AuditRecord, GENESIS_PREV_HASH, Hash};
use crate::sink::{Sink, SinkError};

/// The fully-qualified audit table name.
pub const AUDIT_TABLE: &str = "pgb_audit.audit_log";

/// The fixed `pg_advisory_xact_lock` key the audit chain serializes appends on
/// (S5 #76, item 2). EVERY appender (warden + applyd + proxy) takes this same
/// transaction-scoped advisory lock around its head-read + insert, so the
/// otherwise-racy "read head seq → INSERT seq+1" is serialized **across
/// processes** (the in-process [`crate::SharedSink`] mutex only orders one
/// process' appenders). Without it, two processes can both read head `N` and both
/// try to INSERT seq `N+1` → a `UNIQUE(seq)` collision that crashes the live
/// warden (`run.rs` treats an append failure as fatal) or drops a record.
///
/// The value is an arbitrary fixed 64-bit constant unique to this chain;
/// `pg_advisory_xact_lock(bigint)` auto-releases at txn end (commit or abort), so
/// a crashed appender cannot wedge the lock. The bytes spell `"pgb_audi"`, so it
/// will not collide with an application advisory lock by accident.
pub const AUDIT_CHAIN_LOCK_KEY: i64 = 0x7067_625f_6175_6469u64 as i64; // b"pgb_audi"

impl From<postgres::Error> for SinkError {
    fn from(e: postgres::Error) -> Self {
        SinkError::Backend(e.to_string())
    }
}

/// A Postgres-backed append-only audit sink writing to `pgb_audit.audit_log`.
///
/// Holds a [`Client`] already connected as the **writer** role. Chaining state
/// (the head `seq` + `prev_hash`) is read from the table on each append.
///
/// # Cross-process serialization (S5 #76, item 2)
/// warden, applyd, and proxy are **separate processes**, each with its own
/// `PgSink`/`Client`. The in-process [`crate::SharedSink`] mutex orders appends
/// *within* a process, but not *across* them: two processes could both read head
/// `N` and both try to INSERT seq `N+1`, colliding on `UNIQUE(seq)`. That
/// collision is fatal to the live warden (`run.rs`) and, worse, would silently
/// drop the loser's record. To prevent it, [`append`](Sink::append) wraps the
/// head-read + insert in **one transaction** holding a fixed
/// `pg_advisory_xact_lock(`[`AUDIT_CHAIN_LOCK_KEY`]`)`, so the whole
/// read-then-insert is serialized across every appender. The advisory lock
/// auto-releases at commit/abort, so a crashing appender never wedges the chain.
/// The `UNIQUE(seq)` + `UNIQUE(record_hash)` constraints remain as a loud
/// last-resort backstop.
pub struct PgSink {
    client: Client,
}

impl PgSink {
    /// Wrap an already-connected writer client. The caller is responsible for
    /// connecting as `pgb_audit_writer` (never as the audited agent role).
    pub fn new(client: Client) -> Self {
        PgSink { client }
    }

    /// Borrow the underlying client (e.g. for the integration test to run
    /// assertions on the same connection).
    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    /// The current chain head: `(next_seq, prev_hash)`, read **inside the caller's
    /// transaction** (so it is covered by the same advisory lock as the insert).
    /// Reads the row with the greatest `seq`; an empty table yields
    /// `(0, GENESIS_PREV_HASH)`.
    fn head_in_txn(txn: &mut postgres::Transaction<'_>) -> Result<(u64, Hash), SinkError> {
        let row = txn.query_opt(
            "SELECT seq, record_hash FROM pgb_audit.audit_log ORDER BY seq DESC LIMIT 1",
            &[],
        )?;
        match row {
            None => Ok((0, GENESIS_PREV_HASH.to_string())),
            Some(r) => {
                let seq: i64 = r.get(0);
                let record_hash: String = r.get(1);
                Ok(((seq as u64) + 1, record_hash))
            }
        }
    }

    /// Reconstruct an [`AuditRecord`] from a stored row: parse the verbatim
    /// canonical payload bytes back into an [`AuditPayload`] and pair it with the
    /// stored `record_hash`. Verification then recomputes the hash from the
    /// payload and compares — so a tampered `payload` or `record_hash` column is
    /// caught exactly as for the in-memory chain.
    fn row_to_record(payload_json: &str, record_hash: Hash) -> Result<AuditRecord, SinkError> {
        let payload: AuditPayload = serde_json::from_str(payload_json)
            .map_err(|e| SinkError::Backend(format!("corrupt audit payload json: {e}")))?;
        Ok(AuditRecord {
            payload,
            record_hash,
        })
    }
}

impl Sink for PgSink {
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError> {
        // Cross-process serialization (S5 #76, item 2): take a transaction-scoped
        // advisory lock, then read the head + insert INSIDE the same txn. Holding
        // the lock across the read-then-insert means a concurrent appender (in any
        // process) blocks until we commit, so two appenders can never both compute
        // the same next seq and collide on UNIQUE(seq). The lock auto-releases at
        // commit/abort.
        let mut txn = self.client.transaction()?;
        txn.execute("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])?;

        let (seq, prev_hash) = Self::head_in_txn(&mut txn)?;
        let payload = AuditPayload {
            seq,
            statement_text: entry.statement_text,
            decision: entry.decision,
            reason_code: entry.reason_code,
            reason: entry.reason,
            principal: entry.principal,
            intent: entry.intent,
            write_safety: entry.write_safety,
            timestamp_unix_millis: timestamp_ms,
            prev_hash,
        };
        let record = AuditRecord::seal(payload);

        // Store the EXACT canonical bytes that were hashed (verbatim text), so a
        // read-back recomputes the identical record_hash.
        let payload_bytes = record.payload.canonical_bytes();
        let payload_text = String::from_utf8(payload_bytes)
            .map_err(|e| SinkError::Backend(format!("non-utf8 canonical payload: {e}")))?;

        txn.execute(
            "INSERT INTO pgb_audit.audit_log (seq, prev_hash, record_hash, payload) \
             VALUES ($1, $2, $3, $4)",
            &[
                &(record.payload.seq as i64),
                &record.payload.prev_hash,
                &record.record_hash,
                &payload_text,
            ],
        )?;
        // Commit releases the advisory lock and makes the row visible to the next
        // appender (which then reads it as the new head).
        txn.commit()?;
        Ok(record)
    }

    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError> {
        // `Sink::load_chain` takes `&self`, but `postgres::Client::query` needs
        // `&mut`. We open a short-lived read by re-querying through an immutable
        // borrow is impossible with the sync client, so callers that need to
        // verify should use `load_chain_mut`. To keep the trait usable, this
        // path is unsupported on the sync client and documented as such.
        Err(SinkError::Backend(
            "PgSink::load_chain needs &mut; call load_chain_mut() / verify_mut()".to_string(),
        ))
    }

    /// Read the full chain back, oldest first (the `&mut` variant the sync
    /// Postgres client requires). Reconstructs each record from its verbatim
    /// canonical payload + stored `record_hash`. This **overrides** the trait
    /// default (which would delegate to the unsupported `&self` `load_chain`), so
    /// reads through a `dyn Sink` (e.g. [`crate::sink::SharedSink`]) work against
    /// the `_meta` table.
    fn load_chain_mut(&mut self) -> Result<Vec<AuditRecord>, SinkError> {
        let rows = self.client.query(
            "SELECT payload, record_hash FROM pgb_audit.audit_log ORDER BY seq ASC",
            &[],
        )?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let payload_json: String = r.get(0);
            let record_hash: String = r.get(1);
            out.push(Self::row_to_record(&payload_json, record_hash)?);
        }
        Ok(out)
    }
}
