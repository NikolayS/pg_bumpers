//! The **independent** golden-state differ (THROWAWAY; SPEC §10.6).
//!
//! The restore check must not be circular: if we compared the restored DB using
//! the *same* code that captured/applied the inverse, a bug shared by both could
//! mask itself. So this module is deliberately **independent of the inverse
//! under test** — it shares no code with [`crate::harness`]'s pre-image capture,
//! the `pgb_core` checksum, or the `InversePlan` apply. It fingerprints table
//! state by asking **Postgres itself** to hash the full ordered contents of each
//! table (`md5(string_agg(row::text, … ORDER BY …))`), plus the sequence
//! `last_value` and the trigger-side-effect (audit) row count.
//!
//! A golden state is therefore a small, opaque record of MD5 digests + scalars.
//! Equality of two [`GoldenState`]s ⇒ the certified table rows match
//! byte-for-byte. The sequence/audit scalars are recorded **separately** so the
//! gate can assert they are *not* claimed restored (the documented gaps).

use postgres::{Client, NoTls};

/// Independent differ errors.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    /// A libpq / protocol error.
    #[error("postgres error: {0}")]
    Pg(#[from] postgres::Error),
}

/// A captured fingerprint of the database's certified-restorable state plus the
/// known unrestored-gap scalars. Computed entirely via SQL — no shared code with
/// the inverse-under-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenState {
    /// MD5 over the full ordered contents of `public.orders`.
    pub orders_md5: String,
    /// MD5 over the full ordered contents of `public.order_items` (cascade
    /// child relation).
    pub order_items_md5: String,
    /// `last_value` of `public.ticket_seq` — a documented **unrestored gap**;
    /// recorded so the gate can assert it is NOT restored.
    pub ticket_seq_last_value: i64,
    /// Row count of the trigger-written `public.order_audit` table — a
    /// documented **unrestored gap**; recorded so the gate can assert it is NOT
    /// restored.
    pub audit_row_count: i64,
}

impl GoldenState {
    /// The part of the state the typed-inverse is *contracted* to restore: the
    /// certified table rows only. Two states with equal [`certified_fingerprint`]
    /// have byte-identical `orders` + `order_items` contents.
    ///
    /// [`certified_fingerprint`]: GoldenState::certified_fingerprint
    pub fn certified_fingerprint(&self) -> (&str, &str) {
        (&self.orders_md5, &self.order_items_md5)
    }
}

/// An independent connection helper (the differ owns its own client so it cannot
/// accidentally reuse harness transaction state).
pub fn connect(url: &str) -> Result<Client, DiffError> {
    Ok(Client::connect(url, NoTls)?)
}

/// Capture the golden/current state via Postgres-side hashing.
///
/// `orders` and `order_items` are hashed by casting each row to `text` and
/// aggregating in a deterministic order, then MD5-ing the concatenation. This is
/// computed by the database, not by any Rust code shared with the inverse path.
pub fn capture(client: &mut Client) -> Result<GoldenState, DiffError> {
    let orders_md5: Option<String> = client
        .query_one(
            "SELECT md5(coalesce(string_agg(t.r, '|' ORDER BY t.id), ''))
             FROM (SELECT id, orders::text AS r FROM public.orders) t",
            &[],
        )?
        .get(0);
    let order_items_md5: Option<String> = client
        .query_one(
            "SELECT md5(coalesce(string_agg(t.r, '|' ORDER BY t.order_id, t.line_no), ''))
             FROM (SELECT order_id, line_no, order_items::text AS r FROM public.order_items) t",
            &[],
        )?
        .get(0);
    let ticket_seq_last_value: i64 = client
        .query_one("SELECT last_value FROM public.ticket_seq", &[])?
        .get(0);
    let audit_row_count: i64 = client
        .query_one("SELECT count(*) FROM public.order_audit", &[])?
        .get(0);

    Ok(GoldenState {
        orders_md5: orders_md5.unwrap_or_default(),
        order_items_md5: order_items_md5.unwrap_or_default(),
        ticket_seq_last_value,
        audit_row_count,
    })
}

/// The result of comparing two golden states across a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreVerdict {
    /// Whether the certified table rows (`orders` + `order_items`) match
    /// byte-for-byte — this is what §10.5(b) requires to PASS.
    pub certified_rows_restored: bool,
    /// Whether the sequence `last_value` matches (it should **not** after a
    /// `nextval` — a documented gap).
    pub sequence_restored: bool,
    /// Whether the audit-table row count matches (it should **not** after a
    /// trigger fired — a documented gap).
    pub trigger_side_effects_restored: bool,
}

/// Compare a `golden` state with the `restored` state and produce a verdict.
///
/// The differ is intentionally honest about the gaps: it reports
/// `sequence_restored`/`trigger_side_effects_restored` so the caller can
/// **assert they are FALSE** (the documented non-restored effects).
pub fn diff(golden: &GoldenState, restored: &GoldenState) -> RestoreVerdict {
    RestoreVerdict {
        certified_rows_restored: golden.certified_fingerprint() == restored.certified_fingerprint(),
        sequence_restored: golden.ticket_seq_last_value == restored.ticket_seq_last_value,
        trigger_side_effects_restored: golden.audit_row_count == restored.audit_row_count,
    }
}
