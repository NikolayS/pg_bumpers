-- pg_bumpers — FIXTURE-ONLY demo seed (NOT applied by a real BYO deployment).
-- =====================================================================================
-- Source of truth: docs/spec/SPEC.md (v0.8) §0.5 ("the docker-compose demo cluster is
-- CI/dev/test ONLY"), §5 (role-hardening matrix). Split out of the canonical role
-- hardening (deploy/sql/10_hardened_role.sql) by issue #103 so the canonical file is a
-- version-agnostic, BYO-applicable HARDENING ONLY: a BYO user applies 10_hardened_role.sql
-- + grants their OWN allow-listed relations, and NEVER applies this demo seed.
--
-- WHO APPLIES THIS: the dev/test/CI FIXTURES ONLY — the one-command `up.sh`, the docker-
-- compose stack (deploy/init runs this after 10_hardened_role.sql), and the role-hardening
-- matrix `deploy/test/wall_matrix.sh`. It seeds a tiny demo schema + the matching grants so
-- the matrix has a POSITIVE (granted) + NEGATIVE (denied) read pair to assert against:
--   * public.allowed_read   — granted SELECT to pgb_agent (the whitelist positive case);
--   * public.secret_data    — NEVER granted (the default-deny negative case).
--
-- PREREQUISITE: deploy/sql/10_hardened_role.sql must already have run in this database
-- (it creates + hardens pgb_agent + pgb_applier). This seed only adds the demo tables +
-- their grants on top. Idempotent (safe to re-run); applied against the connected database
-- (identifiers are plain literals — re-target by running against the intended database).
-- =====================================================================================

\set ON_ERROR_STOP on

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

-- THE APPLIER'S DML SURFACE (S5 #77): the constrained write role gets SELECT/INSERT/
-- UPDATE/DELETE on the application table(s) the bounded-reversible apply may touch — and
-- NOTHING that lets it DDL. (The apply needs SELECT for the FOR-UPDATE pre-image capture,
-- INSERT/UPDATE/DELETE for the forward op + the typed-inverse revert.) A real deployment
-- replaces `public.allowed_read` with its OWN writable application relations and grants the
-- applier DML on exactly those (see the §6 GRANT pattern in 10_hardened_role.sql). NO
-- ownership is transferred (owner = postgres), so the applier still cannot ALTER/DROP these
-- tables — only mutate their ROWS.
GRANT SELECT, INSERT, UPDATE, DELETE ON public.allowed_read TO pgb_applier;
-- The applier must NOT read/write the secret (default-deny; drift defense).
REVOKE ALL ON public.secret_data FROM pgb_applier;

COMMIT;

-- =====================================================================================
-- Done. The demo schema is seeded and granted: pgb_agent has SELECT on allowed_read (the
-- positive whitelist case) and NOTHING on secret_data (the negative default-deny case);
-- pgb_applier has DML on allowed_read (the demo write surface) and NOTHING on secret_data.
-- wall_matrix.sh asserts the positive+negative read pair + the applier's DML-only surface.
-- =====================================================================================
