-- pg_bumpers — Layer 1 WALL: the hardened native agent role (idempotent).
-- =====================================================================================
-- Source of truth: docs/spec/SPEC.md (v0.8) §3 (layer 1 WALL), §4 ("Network/roles — do
-- FIRST"), §5 (role-hardening matrix). decisions.md: "Native roles = the security wall,
-- hardened … 'not superuser' is insufficient." Issue #5.
--
-- This migration is the DETERMINISTIC FLOOR's first layer: it makes a hostile *raw*
-- libpq client (no proxy, no MCP) physically unable to read non-whitelisted data or to
-- write/escalate, EVEN BEFORE the proxy. Every line below maps to a row in the
-- role-hardening matrix that deploy/test/wall_matrix.sh asserts by ATTEMPTING the denied
-- action as the agent role and proving it fails.
--
-- It is fully IDEMPOTENT: safe to run repeatedly (the dev substrate sources it on every
-- `up`). Re-running re-asserts the hardened state (defends against config drift).
--
-- The role is the fixed name `pgb_agent` and is scoped to the connected database (the
-- dev substrate applies it against `postgres`). To re-target, change the name here OR run
-- this file against the intended database; identifiers are kept as plain literals (not
-- psql :'vars') on purpose — psql does NOT interpolate :'var' inside the DO $$…$$ bodies
-- this migration uses, so plain literals are the robust, no-surprise choice.
--
-- Enforcement taxonomy (honest):
--   [REVOKE]    an explicit REVOKE strips a default/inherited privilege.
--   [NO-GRANT]  the capability is denied by NEVER granting it + member-of-nothing +
--               NOT superuser; PostgreSQL gates it on a predefined-role membership or the
--               superuser bit this role does not hold. (You cannot REVOKE what was never
--               granted; the harness proves the deny by ATTEMPTING the action.)
--   [ATTR]      a role attribute (NOSUPERUSER, NOINHERIT, …) set at the role level.
-- =====================================================================================

\set ON_ERROR_STOP on

-- Run inside a single txn so a partial apply never leaves a half-hardened role.
BEGIN;

-- -------------------------------------------------------------------------------------
-- 0. Role existence + [ATTR] attribute matrix (idempotent).
--    Create if absent, then UNCONDITIONALLY re-assert every attribute (drift defense).
--    MUST be: LOGIN, NOSUPERUSER, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION,
--    NOBYPASSRLS. (BYPASSRLS off => RLS policies actually bind for this role.)
-- -------------------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgb_agent') THEN
    -- Dev placeholder password; production credentials come from the secret store, not
    -- this file. LOGIN so a raw client can attempt to connect (that the WALL blocks the
    -- *actions*, and the pg_hba boundary blocks the *origin*, is the whole point).
    CREATE ROLE pgb_agent LOGIN PASSWORD 'pgb_agent_dev_pw';
  END IF;
END
$$;

-- [ATTR] Re-assert the full attribute matrix every run (idempotent hardening).
ALTER ROLE pgb_agent
  NOSUPERUSER       -- [ATTR] not superuser (the bypass-everything bit)
  NOCREATEDB        -- [ATTR] cannot CREATE DATABASE
  NOCREATEROLE      -- [ATTR] cannot create/alter other roles (no lateral escalation)
  NOREPLICATION     -- [ATTR] cannot start replication / create slots (no WAL exfil)
  NOBYPASSRLS       -- [ATTR] RLS policies bind (cannot read around row security)
  NOINHERIT         -- [ATTR] does NOT auto-inherit privileges of granted roles;
                    --        even if a role were granted it must SET ROLE explicitly.
  LOGIN;

-- [BEST-EFFORT / DEFENSE-IN-DEPTH] Pin search_path at the role level. HONEST CAVEAT:
-- this role-level pin is NOT immutable. PostgreSQL lets ANY non-superuser role change its
-- OWN role-level GUCs, so `ALTER ROLE pgb_agent SET search_path=…` / `RESET ALL` (run as
-- the agent itself) defeats this pin. The AUTHORITATIVE search_path pin is the PROXY (S1),
-- which sets search_path per session on every connection it brokers; this line is
-- defense-in-depth for the raw-client lens and to drift-correct on every re-apply.
--   The WALL's REAL guarantee does NOT depend on search_path: access is via fully-qualified
-- EXPLICIT SELECT grants only (§6 whitelist), and the agent can neither CREATE schemas/
-- objects (NOCREATE on schema public, NOSUPERUSER, member-of-nothing) nor write anywhere.
-- Therefore ANY search_path the agent picks (even pg_temp-first, even RESET ALL) CANNOT
-- widen its read surface or plant a trojan. The wall_matrix asserts exactly this invariant
-- (see the "search_path invariant" rows): the agent CAN mutate its path (documented PG
-- behavior), yet STILL cannot read non-whitelisted data or write after maximal mutation.
ALTER ROLE pgb_agent SET search_path = pg_catalog, "public";

-- -------------------------------------------------------------------------------------
-- 1. [REVOKE] Member-of-nothing — strip EVERY predefined pg_* role + any other.
--    Enumerate ALL roles the agent is a member of and REVOKE them, so the matrix test's
--    "pg_auth_members empty for the agent" assertion holds. This explicitly covers
--    pg_read_all_data, pg_write_all_data, pg_execute_server_program, pg_read_server_files,
--    pg_write_server_files, pg_monitor, and every other pg_* predefined role.
-- -------------------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT g.rolname AS granted_role
    FROM pg_auth_members m
    JOIN pg_roles a ON a.oid = m.member
    JOIN pg_roles g ON g.oid = m.roleid
    WHERE a.rolname = 'pgb_agent'
  LOOP
    EXECUTE format('REVOKE %I FROM pgb_agent', r.granted_role);
  END LOOP;
END
$$;

-- [REVOKE] Belt-and-suspenders: explicitly REVOKE the headline predefined roles even if
-- the loop above already covered them (REVOKE of a non-member is a harmless no-op). This
-- makes the intent auditable line-by-line and documents the matrix.
-- REVOKE of a non-member emits a NOTICE/WARNING per role; silence just these so a clean
-- re-apply isn't drowned in noise. ON_ERROR_STOP still aborts on any real ERROR.
SET LOCAL client_min_messages = error;
REVOKE pg_read_all_data            FROM pgb_agent;
REVOKE pg_write_all_data           FROM pgb_agent;
REVOKE pg_read_all_settings        FROM pgb_agent;
REVOKE pg_read_all_stats           FROM pgb_agent;
REVOKE pg_stat_scan_tables         FROM pgb_agent;
REVOKE pg_monitor                  FROM pgb_agent;
REVOKE pg_execute_server_program   FROM pgb_agent;   -- the COPY … PROGRAM gate
REVOKE pg_read_server_files        FROM pgb_agent;   -- pg_read_file / server-file read
REVOKE pg_write_server_files       FROM pgb_agent;
REVOKE pg_maintain                 FROM pgb_agent;
REVOKE pg_checkpoint               FROM pgb_agent;
REVOKE pg_signal_backend           FROM pgb_agent;
REVOKE pg_create_subscription      FROM pgb_agent;
REVOKE pg_use_reserved_connections FROM pgb_agent;
RESET client_min_messages;

-- [NO-GRANT] REPLICATION is a role ATTRIBUTE, cleared via NOREPLICATION above (§0).
-- There is no GRANT REPLICATION; the attribute is the control. Asserted in the matrix.

-- -------------------------------------------------------------------------------------
-- 2. [REVOKE] Default-deny on data: revoke PUBLIC's implicit privileges, then strip any
--    privilege the agent may have picked up. The SELECT-whitelist (§4) is the ONLY way
--    back in. This guarantees "default-deny elsewhere".
-- -------------------------------------------------------------------------------------
-- Block the agent from creating objects in (or even using) public except read-whitelist.
-- Note: in PG15+ PUBLIC already lacks CREATE on public; we re-assert for older drift and
-- additionally revoke from the agent role directly.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM pgb_agent;   -- agent cannot create tables/etc.
-- Re-grant only CONNECT to this DB + USAGE on the whitelisted schema (read surface).
-- (CONNECT is granted via the database default to PUBLIC; USAGE on public is the path to
-- the whitelisted relation. We do not touch DATABASE-level grants to avoid lock-out.)
GRANT USAGE ON SCHEMA public TO pgb_agent;

-- -------------------------------------------------------------------------------------
-- 3. [REVOKE] PUBLIC EXECUTE on functions — revoke the language default, then grant back
--    NOTHING by default. (PostgreSQL grants EXECUTE to PUBLIC on every newly-created
--    function unless revoked.) Combined with member-of-nothing this denies reachable
--    SECURITY DEFINER / volatile server-side write functions to the agent.
--    We scope the blanket revoke to the application schema(s); pg_catalog built-ins are
--    governed by predefined-role membership (already stripped) and the superuser bit
--    (NOSUPERUSER), which is why pg_read_file/lo_*/etc. are denied even without an
--    explicit REVOKE (the harness proves each by attempting it).
-- -------------------------------------------------------------------------------------
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM pgb_agent;
-- Future functions created in public: default-deny EXECUTE to PUBLIC as well.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- -------------------------------------------------------------------------------------
-- 4. [REVOKE] No write grant ANYWHERE — close the two PUBLIC-default write paths.
--    (a) TEMP on the database: PostgreSQL grants TEMPORARY to PUBLIC by default, which
--        lets the agent CREATE TEMP TABLE … INSERT (session-local, but still a write +
--        disk-consumption DoS vector). REVOKE it from PUBLIC and from the agent so the
--        "no write grant anywhere" claim is TRUE. (CONNECT is left intact so the agent
--        can still log in.)
--    (b) Large-object WRITE built-ins: PostgreSQL grants EXECUTE to PUBLIC by default on
--        the lo_* server-side functions. The READ/file paths (lo_import/lo_export) are
--        already gated on pg_read/write_server_files (denied above), but the IN-DB write
--        path (lo_create/lowrite/lo_from_bytea/lo_put/lo_creat/lo_truncate*/lo_unlink) is
--        reachable via the PUBLIC default and lets the agent write large objects it owns.
--        REVOKE EXECUTE on every lo_* WRITE/mutate built-in from PUBLIC so no in-DB write
--        path remains. (loread/lo_open are reads and are left for completeness of the
--        no-write claim; they cannot widen the read surface beyond LOs the agent created,
--        which it now cannot.)
--    Both are real REVOKEs (the privilege exists by PUBLIC default); the harness proves
--    each by ATTEMPTING the write as the agent and asserting a permission error.
-- -------------------------------------------------------------------------------------
-- REVOKE TEMP on the CONNECTED database (current_database()); identifiers stay literal-free
-- via format()/EXECUTE so this file needs no psql :vars and re-targets by being run against
-- the intended database (matches the role's "scoped to the connected database" model above).
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM pgb_agent', current_database());
END
$$;

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

-- -------------------------------------------------------------------------------------
-- 5. [NO-GRANT] Server-file large objects (lo_import/lo_export) and pg_read_file are
--    gated by superuser + predefined-role membership (pg_read/write_server_files), both
--    denied above. There is no per-object GRANT to revoke for those file paths; the deny
--    is structural and proven by the harness attempting them and asserting a permission
--    error. Documented, not silently skipped.
--
-- 6. [NO-GRANT] dblink / postgres_fdw / file_fdw egress: the agent is NOT superuser and
--    has no CREATE on the database, so it cannot CREATE EXTENSION. The harness asserts
--    these extensions are NOT installed AND that the agent cannot create them.
-- -------------------------------------------------------------------------------------

COMMIT;

-- =====================================================================================
-- 6. The SELECT-WHITELIST (explicit grants only; default-deny everywhere else).
--    This is the ONLY positive grant surface. A demo schema + two tables model the
--    whitelist: public.allowed_read is granted SELECT; public.secret_data is NOT (so a
--    raw agent SELECT on it must fail — the matrix's positive+negative read pair).
--    Real deployments replace these with their own allow-listed relations/columns.
-- =====================================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS public.allowed_read (
    id    integer PRIMARY KEY,
    label text NOT NULL
);
INSERT INTO public.allowed_read (id, label) VALUES
    (1, 'whitelisted row one'),
    (2, 'whitelisted row two')
ON CONFLICT (id) DO NOTHING;

-- A NON-whitelisted table: the agent must NOT be able to SELECT this (default-deny).
CREATE TABLE IF NOT EXISTS public.secret_data (
    id     integer PRIMARY KEY,
    secret text NOT NULL
);
INSERT INTO public.secret_data (id, secret) VALUES
    (1, 'TOP SECRET — must never reach the agent role')
ON CONFLICT (id) DO NOTHING;

-- THE WHITELIST: explicit SELECT on the one allowed relation. No INSERT/UPDATE/DELETE
-- anywhere (no write grant). secret_data is intentionally NOT granted.
GRANT SELECT ON public.allowed_read TO pgb_agent;

-- Re-assert default-deny on the secret table for the agent (no-op if never granted;
-- defends against drift where a prior run / operator granted it).
REVOKE ALL ON public.secret_data FROM pgb_agent;

COMMIT;

-- =====================================================================================
-- Done. The agent role is now: LOGIN, NOSUPERUSER, NOINHERIT, member-of-nothing,
-- NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS, PUBLIC EXECUTE revoked, NO write grant
-- ANYWHERE (incl. TEMP on the database + the in-DB large-object write built-ins, both
-- revoked from PUBLIC above), SELECT only on the explicit whitelist, default-deny
-- everywhere else. dblink/fdw/COPY-PROGRAM/lo_import/lo_export/pg_read_file denied
-- structurally (superuser/predefined-role gated).
--
-- search_path: the role-level pin above is BEST-EFFORT defense-in-depth ONLY — a
-- non-superuser CAN change its own role GUCs, so the agent can mutate/RESET its path.
-- The AUTHORITATIVE pin is the PROXY (S1). The WALL's guarantee does NOT rely on
-- search_path: with explicit fully-qualified SELECT grants as the only read surface and
-- no CREATE/no write anywhere, no search_path the agent chooses can widen access or plant
-- a trojan. deploy/test/wall_matrix.sh asserts every deny by attempting it as the agent,
-- AND asserts the search_path invariant (agent mutates path + RESET ALL → STILL cannot
-- read non-whitelisted data or write anywhere).
-- =====================================================================================
