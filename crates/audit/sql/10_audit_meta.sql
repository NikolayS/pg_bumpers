-- pg_bumpers — the append-only, hash-chained AUDIT table in the `_meta` DB.
-- =====================================================================================
-- Source of truth: docs/spec/SPEC.md (v0.8) §3 (architecture: "hash-chained AUDIT …
-- audited cannot write audit"), §4 ("Audit (Rust): append-only hash-chained rows in
-- `_meta` DB … REVOKE so the audited principal cannot write/rewrite audit. Records every
-- statement incl. rejects."), §5 (hash-chain integrity + tamper-injection), §10.9
-- (root-of-trust: audited principal REVOKEd from writing audit). Issue #21.
--
-- This schema delivers the S1 slice of the audit root-of-trust:
--   * an append-only table holding one row per recorded statement (incl. rejects);
--   * each row carries the chain links (prev_hash, record_hash) + the canonical payload
--     bytes that the Rust `verify_chain()` recomputes the hash from;
--   * GRANTS so ONLY the dedicated audit-WRITER role inserts, and the audited principal
--     (the agent role) is REVOKEd from INSERT/UPDATE/DELETE — it "cannot write audit".
--
-- The external WORM anchor + KMS key-separation land in S4 (§10.9); this file is the
-- chain + the write-side REVOKE only. It is IDEMPOTENT (safe to re-run; re-asserts grants
-- to drift-correct), and is meant to run against the `_meta` database.
--
-- Identifiers are plain literals on purpose (no psql :vars inside DO bodies) — matches
-- deploy/sql/10_hardened_role.sql. To re-target roles, change the names here.
-- =====================================================================================

\set ON_ERROR_STOP on

BEGIN;

-- -------------------------------------------------------------------------------------
-- 0. Roles. Two principals with SEPARATED duties (SPEC §3/§10.9 "audited cannot write
--    audit"):
--      * pgb_audit_writer — the ONLY role allowed to INSERT audit rows. The proxy/warden
--        write the chain as THIS role, never as the agent. (Dev password; production
--        credentials come from the secret store, not this file.)
--      * pgb_agent — the audited principal (created by the WALL migration). It is the
--        SUBJECT of audit rows but must NOT be able to write/rewrite them.
--    Both are created here if absent so this file stands alone against a bare `_meta` DB.
-- -------------------------------------------------------------------------------------
-- The `IF NOT EXISTS` check + CREATE is non-atomic, so two concurrent applies can
-- both pass the check and race on the CREATE; we catch `duplicate_object` /
-- `unique_violation` and treat them as "already created" so the migration stays
-- idempotent even under concurrency (the integration suite applies it in parallel).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgb_audit_writer') THEN
    BEGIN
      CREATE ROLE pgb_audit_writer LOGIN PASSWORD 'pgb_audit_writer_dev_pw';
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
      NULL;  -- created concurrently; fine.
    END;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgb_agent') THEN
    -- The audited principal. The authoritative hardening lives in the WALL migration
    -- (deploy/sql/10_hardened_role.sql); we only need it to EXIST here so the REVOKE
    -- below has a subject even when `_meta` is a standalone database.
    BEGIN
      CREATE ROLE pgb_agent LOGIN PASSWORD 'pgb_agent_dev_pw' NOSUPERUSER NOINHERIT;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
      NULL;  -- created concurrently; fine.
    END;
  END IF;
END
$$;

-- -------------------------------------------------------------------------------------
-- 1. A dedicated schema for the audit log so grants are scoped tightly.
-- -------------------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS pgb_audit;

-- -------------------------------------------------------------------------------------
-- 2. The append-only chain table. One row per recorded statement (incl. rejects).
--    Columns mirror the Rust `AuditRecord`:
--      * seq            — monotonic chain position (0 = genesis); UNIQUE so a duplicate
--                         seq (a replay/forge attempt) is rejected by the DB itself.
--      * prev_hash      — predecessor's record_hash (genesis = 64 hex zeros).
--      * record_hash    — sha256(prev_hash || canonical(payload)); UNIQUE.
--      * payload        — the EXACT canonical JSON bytes the Rust side hashed, stored as
--                         jsonb? NO: jsonb re-orders keys and would change the bytes, so
--                         we store the canonical bytes verbatim as `text` to keep the
--                         hash reproducible on read-back. (A jsonb mirror could be added
--                         for querying without affecting verification.)
--    No UPDATE/DELETE is ever issued by the app; the REVOKE below removes the privilege
--    from the agent, and the writer role only ever INSERTs.
-- -------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pgb_audit.audit_log (
    seq          bigint       NOT NULL,
    prev_hash    text         NOT NULL,
    record_hash  text         NOT NULL,
    payload      text         NOT NULL,            -- canonical JSON bytes, verbatim
    inserted_at  timestamptz  NOT NULL DEFAULT now(),  -- DB-side receipt time (not the
                                                       -- chain timestamp, which is in
                                                       -- payload via core::Clock)
    CONSTRAINT audit_log_seq_key         UNIQUE (seq),
    CONSTRAINT audit_log_record_hash_key UNIQUE (record_hash),
    CONSTRAINT audit_log_seq_nonneg      CHECK (seq >= 0)
);

-- -------------------------------------------------------------------------------------
-- 3. Append-only enforcement at the table level (defense-in-depth beyond grants).
--    A BEFORE UPDATE/DELETE trigger raises, so even a role that somehow held UPDATE/
--    DELETE cannot mutate history. (Grants below are the primary control; this is the
--    belt-and-suspenders the matrix test also asserts.)
-- -------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pgb_audit.deny_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'pgb_audit.audit_log is append-only: % is not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;

DROP TRIGGER IF EXISTS audit_log_no_mutation ON pgb_audit.audit_log;
CREATE TRIGGER audit_log_no_mutation
  BEFORE UPDATE OR DELETE ON pgb_audit.audit_log
  FOR EACH ROW EXECUTE FUNCTION pgb_audit.deny_mutation();

-- -------------------------------------------------------------------------------------
-- 4. GRANTS — the "audited cannot write audit" guarantee (SPEC §3/§4/§10.9).
--    Re-assert UNCONDITIONALLY every run (idempotent drift defense).
--
--    (a) Only the writer role may INSERT. It gets no UPDATE/DELETE — append-only.
--    (b) The audited principal (pgb_agent) is explicitly REVOKEd from INSERT/UPDATE/
--        DELETE on the audit table. It is the SUBJECT of the log, never its author.
--    (c) PUBLIC gets nothing on this schema (default-deny); future tables inherit the
--        default-privilege revoke.
-- -------------------------------------------------------------------------------------

-- (c) Default-deny: strip any PUBLIC defaults on the schema/table first.
REVOKE ALL ON SCHEMA pgb_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pgb_audit FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgb_audit REVOKE ALL ON TABLES FROM PUBLIC;

-- (a) The writer role: USAGE on the schema + INSERT + SELECT on the table. NO UPDATE,
--     NO DELETE, NO TRUNCATE — append-only even for the writer.
GRANT USAGE ON SCHEMA pgb_audit TO pgb_audit_writer;
GRANT INSERT, SELECT ON pgb_audit.audit_log TO pgb_audit_writer;
-- The writer reads the head (last seq + record_hash) to chain the next row, hence SELECT.
-- It needs the sequence-less table's identity, so nothing else is required.

-- (b) THE KEY REVOKE: the audited principal cannot write/rewrite the audit table.
--     REVOKE of a never-granted privilege is a harmless no-op; we issue it explicitly so
--     the guarantee is auditable line-by-line and drift-corrected on every re-apply.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON pgb_audit.audit_log FROM pgb_agent;
REVOKE ALL ON SCHEMA pgb_audit FROM pgb_agent;
-- The agent gets NO grant back on this schema. It cannot even read other principals'
-- audit rows from here (default-deny); read access for forensics is a separate,
-- audited path (the MCP `get_audit` tool), not direct table access by the agent.

COMMIT;

-- =====================================================================================
-- Done. pgb_audit.audit_log is append-only (grants + trigger), written ONLY by
-- pgb_audit_writer, and the audited principal pgb_agent is REVOKEd from INSERT/UPDATE/
-- DELETE — it "cannot write audit" (SPEC §3/§4/§10.9). The external WORM anchor + KMS
-- key-separation are S4. The Rust `_meta` sink (crates/audit/src/pg.rs) INSERTs as the
-- writer role and reads rows back for `verify_chain()`.
-- =====================================================================================
