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
use crate::record::{AuditPayload, AuditRecord, Hash, GENESIS_PREV_HASH};
use crate::sink::{Sink, SinkError};

/// The fully-qualified audit table name.
pub const AUDIT_TABLE: &str = "pgb_audit.audit_log";

impl From<postgres::Error> for SinkError {
    fn from(e: postgres::Error) -> Self {
        SinkError::Backend(e.to_string())
    }
}

/// A Postgres-backed append-only audit sink writing to `pgb_audit.audit_log`.
///
/// Holds a [`Client`] already connected as the **writer** role. Chaining state
/// (the head `seq` + `prev_hash`) is read from the table on each append, so the
/// sink is correct even if multiple writers append (the `UNIQUE(seq)` +
/// `UNIQUE(record_hash)` constraints make a racing duplicate fail loudly rather
/// than silently fork the chain).
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

    /// The current chain head: `(next_seq, prev_hash)`. Reads the row with the
    /// greatest `seq`; an empty table yields `(0, GENESIS_PREV_HASH)`.
    fn head(&mut self) -> Result<(u64, Hash), SinkError> {
        let row = self.client.query_opt(
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
        let (seq, prev_hash) = self.head()?;
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

        self.client.execute(
            "INSERT INTO pgb_audit.audit_log (seq, prev_hash, record_hash, payload) \
             VALUES ($1, $2, $3, $4)",
            &[
                &(record.payload.seq as i64),
                &record.payload.prev_hash,
                &record.record_hash,
                &payload_text,
            ],
        )?;
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
}

impl PgSink {
    /// Read the full chain back, oldest first (the `&mut` variant the sync
    /// Postgres client requires). Reconstructs each record from its verbatim
    /// canonical payload + stored `record_hash`.
    pub fn load_chain_mut(&mut self) -> Result<Vec<AuditRecord>, SinkError> {
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

    /// Verify the persisted chain (the `&mut` variant). Returns the first broken
    /// link if any, exactly like the in-memory path.
    pub fn verify_mut(&mut self) -> Result<(), SinkError> {
        let chain = self.load_chain_mut()?;
        crate::chain::verify_chain(&chain).map_err(SinkError::Integrity)
    }
}
