-- pg_brakes — STRICT PUBLIC LOCKDOWN (OPT-IN; greenfield/dedicated-DB ONLY). Issue #108.
-- =====================================================================================
-- ⚠️  DANGER — DO NOT run this on a SHARED / EXISTING application database.
-- This file REVOKEs privileges FROM PUBLIC (function EXECUTE blanket + ALTER DEFAULT
-- PRIVILEGES, CREATE on schema public, TEMPORARY on the database, the in-DB large-object
-- write built-ins). Those mutate the privilege model for **EVERY role in the database, not
-- just pgb_agent**. On a live application DB this strips the implicit PUBLIC grants that
-- running applications and monitoring rely on — applied to a production primary this caused
-- permission-denied errors and broke the app (see KNOWN_DANGERS.md D1, the original
-- incident this whole split fixes).
--
-- APPLY THIS FILE **ONLY** WHEN:
--   * the database is DEDICATED to pg_brakes / greenfield / throwaway (nothing else depends
--     on PUBLIC's defaults), OR
--   * you have REHEARSED it on a thin clone of your DB and smoke-tested your application
--     against the result (the M3 clone-rehearsal path — coming) and confirmed zero breakage.
--
-- It is the DB-LEVEL belt-and-suspenders ON TOP OF the agent-only default
-- (deploy/sql/10_hardened_role.sql). The DEFAULT BYO posture is agent-only and does NOT
-- apply this file. The dev/test/CI fixture DOES apply it (so the strict posture stays
-- tested by deploy/test/wall_matrix.sh's strict-lockdown context).
--
-- HONEST NOTE (what this restores): with ONLY the agent-only default, the agent — as a
-- PUBLIC member — retains PUBLIC's default function-EXECUTE and the in-DB large-object
-- write built-ins at the DB level. Containment then rests, not on a global revoke but,
-- split by path: THROUGH THE PROXY (the realistic agent path) on the M2a fail-closed read
-- classifier (#114/#115 — SELECT lo_create()/write-fn/non-allowlisted-or-qualified call →
-- NotRead → Blocked at the proxy floor), and DIRECT-TO-DB on the §3 network boundary — see
-- SPEC.amendments.md A-M2, KNOWN_BYPASSES B-lo. This file revokes those FROM PUBLIC,
-- restoring the DB-level deny for a dedicated DB.
--
-- IDEMPOTENT: safe to run repeatedly. Run it against the SAME database `10_hardened_role.sql`
-- was applied to. Identifiers are plain literals on purpose (psql does NOT interpolate
-- :'var' inside DO $$…$$ bodies). The TEMP/db-level revoke targets current_database().
-- =====================================================================================

\set ON_ERROR_STOP on

BEGIN;

-- -------------------------------------------------------------------------------------
-- 1. [REVOKE … FROM PUBLIC] CREATE on schema public — strip PUBLIC's default CREATE.
--    Note: PG15+ already removed CREATE-on-public from PUBLIC by default (this is a no-op
--    there); on PG14 it is a real, global change. The agent-only default already revoked
--    CREATE from pgb_agent/pgb_applier directly; this widens it to PUBLIC.
-- -------------------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- -------------------------------------------------------------------------------------
-- 2. [REVOKE … FROM PUBLIC] Function EXECUTE — the language default for EXISTING functions,
--    plus a best-effort future-function default. PostgreSQL grants EXECUTE to PUBLIC on
--    every newly-created function unless revoked. The blanket `REVOKE EXECUTE ON ALL
--    FUNCTIONS … FROM PUBLIC` reliably strips it from EVERY function that EXISTS now. This
--    is the function-execute blast radius (it strips the implicit EXECUTE EVERY app role
--    relies on) — the worst of the FROM-PUBLIC revokes. Dedicated DB only.
--
--    HONEST PG CAVEAT (verified on PG 14-18): the `ALTER DEFAULT PRIVILEGES … REVOKE
--    EXECUTE … FROM PUBLIC` line below is the canonical idiom for FUTURE functions, but
--    PostgreSQL does NOT persist a default-ACL entry when the result would be the empty
--    set (no other default grants exist to anchor it) — so a function created LATER by a
--    role with no other default-ACL customization falls back to the built-in PUBLIC default
--    and IS PUBLIC-executable again. The reliable deny is therefore: re-run this lockdown
--    (the blanket revoke re-strips existing functions) OR grant EXECUTE explicitly only to
--    the roles that need it. We keep the ADP line because it DOES take effect once any
--    default-ACL customization exists for the owner, and it documents intent. On a shared
--    BYO DB this residual is one more reason the default is agent-only + proxy-gated.
-- -------------------------------------------------------------------------------------
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- -------------------------------------------------------------------------------------
-- 3. [REVOKE … FROM PUBLIC] TEMPORARY on the connected database — close the session-local
--    write + disk-DoS path for EVERY role (the agent-only default already revoked TEMP from
--    pgb_agent directly; this widens it to PUBLIC). CONNECT is left intact.
-- -------------------------------------------------------------------------------------
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

-- -------------------------------------------------------------------------------------
-- 4. [REVOKE … FROM PUBLIC] In-DB large-object WRITE built-ins — the one DB-level write
--    surface that has NO agent-scoped revoke (it is reachable only via the PUBLIC-default
--    EXECUTE). REVOKE EXECUTE FROM PUBLIC on every lo_* write/mutate built-in so no in-DB
--    large-object write path remains for any non-superuser. (loread/lo_open are reads and
--    are left intact.) This is the residual the agent-only default leaves open on a shared
--    DB (KNOWN_BYPASSES B-lo); applying it closes that residual on a dedicated DB.
-- -------------------------------------------------------------------------------------
SET LOCAL client_min_messages = error;   -- silence any "no privileges could be revoked" notices
REVOKE EXECUTE ON FUNCTION lo_create(oid)            FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_creat(integer)         FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lowrite(integer, bytea)   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_from_bytea(oid, bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_put(oid, bigint, bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_truncate(integer, integer)   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_truncate64(integer, bigint)  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_unlink(oid)            FROM PUBLIC;
RESET client_min_messages;

COMMIT;

-- =====================================================================================
-- Done. PUBLIC's dangerous defaults (CREATE on schema public, function EXECUTE + the
-- future-function default, TEMPORARY on the database, the in-DB large-object write
-- built-ins) are revoked DB-wide. This is the strict, dedicated-DB posture; the agent-only
-- default (10_hardened_role.sql) is the safe BYO default that NEVER touches PUBLIC.
-- =====================================================================================
