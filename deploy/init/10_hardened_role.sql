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
-- BRING-YOUR-OWN POSTGRES (SPEC §0.5): this file is the CANONICAL, version-agnostic role
-- HARDENING ONLY — it creates + hardens `pgb_agent` (read WALL) and `pgb_applier` (DML-
-- only apply role) and revokes every default/inherited privilege, but it NO LONGER seeds
-- any demo schema or grants any application tables. A BYO user applies THIS file against
-- their existing database (PG 14-18), then grants the agent/applier ONLY their own
-- allow-listed relations (the §6 GRANT pattern, see below). The dev/test/CI fixtures (the
-- one-command `up.sh`, the docker-compose stack, `wall_matrix.sh`) additionally apply the
-- companion FIXTURE-ONLY seed `deploy/sql/20_demo_seed.sql` (the `allowed_read` /
-- `secret_data` demo tables + their grants) so the matrix has a positive+negative read
-- pair to assert against. A real deployment does NOT apply `20_demo_seed.sql`.
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
-- which IS WIRED to `SET search_path` per session on EVERY brokered backend connection
-- (crates/proxy/src/session.rs `inject_search_path`, run on `connect_backend` right beside
-- the statement_timeout injection; ProxyConfig::DEFAULT_SEARCH_PATH = `pg_catalog, "public"`
-- matches THIS line). A fresh brokered session is always re-pinned, so no agent-chosen path
-- survives into a new session (proven by crates/proxy/tests/proxy_it.rs
-- `proxy_pins_search_path_on_every_brokered_session`). This role-level line is
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
-- 0b. The CONSTRAINED APPLY role `pgb_applier` (S5 #77 — least-privilege write path).
--     The write-path daemon (`pgb-applyd`) connects as THIS role to run the grant-gated
--     bounded-reversible apply (`guarded_apply_with_grant`). The deterministic floor
--     (the application-layer §4 guards: WALL classify, cap/predicate gate, pre-image
--     capture, reconciliation) is the PRIMARY control on what may be written. THIS role
--     is DEFENSE-IN-DEPTH: it bounds what a bug in the apply path could even ATTEMPT at
--     the DB level. It is DML-ONLY (SELECT/INSERT/UPDATE/DELETE on the application tables,
--     granted in §6 below) and CANNOT DDL — no CREATE/ALTER/DROP, NOT superuser, owns no
--     objects, member of nothing. Before #77 the only WORKING deployment ran applyd as the
--     Postgres SUPERUSER (because `pgb_agent` is read-only and cannot write), so a bug in
--     `guarded_apply_with_grant` could have issued arbitrary DDL. `pgb_applier` closes that.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgb_applier') THEN
    -- Dev placeholder password; production credentials come from the secret store, not
    -- this file. LOGIN so the daemon can connect.
    CREATE ROLE pgb_applier LOGIN PASSWORD 'pgb_applier_dev_pw';
  END IF;
END
$$;

-- [ATTR] Re-assert the applier's attribute matrix every run (idempotent drift defense).
-- Like pgb_agent it is NOT superuser, cannot create DBs/roles, cannot replicate, and
-- RLS binds. NOCREATEDB/NOCREATEROLE + NOSUPERUSER are the structural DDL/escalation
-- denials; INHERIT is fine (it is granted no roles to inherit from — member of nothing).
ALTER ROLE pgb_applier
  NOSUPERUSER       -- [ATTR] not superuser (no bypass-everything bit → no arbitrary DDL)
  NOCREATEDB        -- [ATTR] cannot CREATE DATABASE
  NOCREATEROLE      -- [ATTR] cannot create/alter roles (no lateral escalation)
  NOREPLICATION     -- [ATTR] cannot start replication / create slots
  NOBYPASSRLS       -- [ATTR] RLS policies bind
  LOGIN;
-- Pin the applier's search_path too (defense-in-depth; same honest caveat as pgb_agent's:
-- a non-superuser can change its own role GUC, the authoritative path is set per-session).
ALTER ROLE pgb_applier SET search_path = pg_catalog, "public";
-- [REVOKE] The applier owns no schema and may NOT create objects in public — this is the
-- key DDL denial at the schema level (a bug cannot `CREATE TABLE` even if it tried). It
-- gets USAGE on public so it can reach the application tables its DML grants name (§6).
REVOKE CREATE ON SCHEMA public FROM pgb_applier;
GRANT  USAGE  ON SCHEMA public TO   pgb_applier;

-- [REVOKE] Member-of-nothing for the APPLIER too — strip EVERY predefined pg_* role +
-- any other (drift defense). pgb_applier is write-capable, so the destructive predefined
-- roles (pg_execute_server_program → COPY … PROGRAM; pg_read/write_server_files → server-
-- file read/write; pg_write_all_data) matter MORE here, not less. These are belt-and-
-- suspenders (the role is NOSUPERUSER + member-of-nothing by construction), but re-asserting
-- them every run is the whole point: a drifted GRANT can never silently arm the applier.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT g.rolname AS granted_role
    FROM pg_auth_members m
    JOIN pg_roles a ON a.oid = m.member
    JOIN pg_roles g ON g.oid = m.roleid
    WHERE a.rolname = 'pgb_applier'
  LOOP
    EXECUTE format('REVOKE %I FROM pgb_applier', r.granted_role);
  END LOOP;
END
$$;

-- [REVOKE] Belt-and-suspenders: explicitly REVOKE the headline predefined roles from the
-- applier (same list as pgb_agent below). The destructive-vector ones for a WRITE-capable
-- role are pg_execute_server_program (COPY … PROGRAM), pg_read_server_files /
-- pg_write_server_files (server-file I/O), and pg_write_all_data; the applier's IT asserts
-- a TRUNCATE and a COPY … PROGRAM as pgb_applier are denied.
--
-- VERSION-AGNOSTIC (C1 #102, spec v0.8.1 §0.5 — supported PG 14-18): several of these
-- predefined roles were INTRODUCED in a specific major and DO NOT EXIST on older ones —
-- pg_checkpoint (15+), pg_create_subscription (16+), pg_use_reserved_connections (16+),
-- pg_maintain (17+). A raw `REVOKE pg_maintain …` against PG 14-16 raises a real ERROR
-- (`role "pg_maintain" does not exist`) which aborts the whole migration under
-- ON_ERROR_STOP. So we LOOP over the role-name list and GUARD each REVOKE with
-- `to_regrole(name) IS NOT NULL` — it no-ops (auditably) where the role is absent and
-- runs where it exists. pg_read_all_data / pg_write_all_data are 14+ (present on every
-- supported major) but go through the same guard for uniformity. This is the
-- deterministic floor staying version-agnostic: a write-capable role can never silently
-- retain a destructive predefined role just because the migration aborted mid-apply.
-- (`client_min_messages = error` is set inside the block to silence the harmless
-- "is not a member" WARNING a REVOKE of a non-member emits — the existence guard prevents
-- the hard ERROR on absent roles, this just keeps a clean re-apply quiet; the txn-local
-- set_config(…, is_local => true) is reverted at COMMIT.)
DO $$
DECLARE
  role_name text;
BEGIN
  PERFORM set_config('client_min_messages', 'error', true);
  FOREACH role_name IN ARRAY ARRAY[
    'pg_read_all_data',            -- 14+
    'pg_write_all_data',           -- 14+  (no write outside the DML grants)
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_stat_scan_tables',
    'pg_monitor',
    'pg_execute_server_program',   -- the COPY … PROGRAM gate
    'pg_read_server_files',        -- pg_read_file / server-file read
    'pg_write_server_files',       -- server-file write
    'pg_signal_backend',
    'pg_checkpoint',               -- 15+
    'pg_create_subscription',      -- 16+
    'pg_use_reserved_connections', -- 16+
    'pg_maintain'                  -- 17+
  ]
  LOOP
    IF to_regrole(role_name) IS NOT NULL THEN
      EXECUTE format('REVOKE %I FROM pgb_applier', role_name);
    END IF;
  END LOOP;
END
$$;

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
--
-- VERSION-AGNOSTIC (C1 #102, spec v0.8.1 §0.5 — supported PG 14-18): same per-role
-- `to_regrole(name) IS NOT NULL` guard as the applier block above. pg_checkpoint (15+),
-- pg_create_subscription (16+), pg_use_reserved_connections (16+) and pg_maintain (17+)
-- DO NOT EXIST on older majors, so a raw REVOKE would raise `role "…" does not exist`
-- and abort the migration under ON_ERROR_STOP. The existence guard skips an absent role,
-- and `client_min_messages = error` (txn-local) silences the harmless "is not a member"
-- WARNING a REVOKE of a non-member emits. ON_ERROR_STOP still aborts on any REAL error.
DO $$
DECLARE
  role_name text;
BEGIN
  PERFORM set_config('client_min_messages', 'error', true);
  FOREACH role_name IN ARRAY ARRAY[
    'pg_read_all_data',            -- 14+
    'pg_write_all_data',           -- 14+
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_stat_scan_tables',
    'pg_monitor',
    'pg_execute_server_program',   -- the COPY … PROGRAM gate
    'pg_read_server_files',        -- pg_read_file / server-file read
    'pg_write_server_files',
    'pg_signal_backend',
    'pg_checkpoint',               -- 15+
    'pg_create_subscription',      -- 16+
    'pg_use_reserved_connections', -- 16+
    'pg_maintain'                  -- 17+
  ]
  LOOP
    IF to_regrole(role_name) IS NOT NULL THEN
      EXECUTE format('REVOKE %I FROM pgb_agent', role_name);
    END IF;
  END LOOP;
END
$$;

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
-- 6. The SELECT-WHITELIST — APPLIED BY THE USER, NOT BY THIS CANONICAL FILE (SPEC §0.5).
--    This file no longer seeds any demo schema or grants any application table: the WALL
--    above is default-deny on ALL data, so the ONLY way back in is an EXPLICIT grant the
--    user makes for THEIR OWN allow-listed relations. A BYO user runs, against their DB,
--    something like the pattern below (substituting their real schema-qualified tables):
--
--        -- the agent's READ whitelist (SELECT only; never INSERT/UPDATE/DELETE):
--        GRANT SELECT ON <schema>.<your_read_table> TO pgb_agent;
--        -- the applier's WRITE surface (DML only; never DDL; owner stays unchanged):
--        GRANT SELECT, INSERT, UPDATE, DELETE ON <schema>.<your_write_table> TO pgb_applier;
--
--    Keep it minimal: grant the agent SELECT on exactly the relations it must read, and
--    the applier DML on exactly the relations a bounded-reversible apply may touch. Do NOT
--    transfer ownership (so neither role can ALTER/DROP). Everything else stays default-
--    deny. Run `pgb-cli doctor` afterwards to verify the WALL + grants fail-closed.
--
--    The dev/test/CI FIXTURES apply the companion `deploy/sql/20_demo_seed.sql` (the
--    `allowed_read` / `secret_data` demo tables + the matching grants) so the role-
--    hardening matrix (`deploy/test/wall_matrix.sh`) has a positive (granted) + negative
--    (denied) read pair to assert against. A real deployment does NOT apply that seed.
-- =====================================================================================

-- =====================================================================================
-- Done. The agent role is now: LOGIN, NOSUPERUSER, NOINHERIT, member-of-nothing,
-- NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS, PUBLIC EXECUTE revoked, NO write grant
-- ANYWHERE (incl. TEMP on the database + the in-DB large-object write built-ins, both
-- revoked from PUBLIC above), default-deny on ALL data until the user grants their own
-- allow-listed relations (§6 above). dblink/fdw/COPY-PROGRAM/lo_import/lo_export/
-- pg_read_file denied structurally (superuser/predefined-role gated).
--
-- search_path: the role-level pin above is BEST-EFFORT defense-in-depth ONLY — a
-- non-superuser CAN change its own role GUCs, so the agent can mutate/RESET its path.
-- The AUTHORITATIVE pin is the PROXY (S1). The WALL's guarantee does NOT rely on
-- search_path: with explicit fully-qualified SELECT grants as the only read surface and
-- no CREATE/no write anywhere, no search_path the agent chooses can widen access or plant
-- a trojan. deploy/test/wall_matrix.sh (which applies 20_demo_seed.sql for its fixtures)
-- asserts every deny by attempting it as the agent, AND asserts the search_path invariant
-- (agent mutates path + RESET ALL → STILL cannot read non-whitelisted data or write).
--
-- pgb_applier (S5 #77): the constrained write-path role applyd connects as. LOGIN,
-- NOSUPERUSER, NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS, no CREATE on public, owns
-- no objects -> it CANNOT DDL (no CREATE/ALTER/DROP). It is granted DML ONLY (SELECT/
-- INSERT/UPDATE/DELETE) on the application table(s) the USER grants it -- the defense-in-
-- depth floor under the §4 application-layer apply guards (which remain the primary
-- control). The applyd IT proves both halves: a guarded write COMMITS as pgb_applier AND
-- a DDL attempt as pgb_applier is rejected with `permission denied`.
-- =====================================================================================
