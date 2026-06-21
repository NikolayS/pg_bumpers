-- pg_bumpers — primary init hooks (docker-compose entrypoint)
--
-- Files in this directory are executed once, in alphabetical order, by the
-- official postgres image on FIRST boot of the `primary` service
-- (/docker-entrypoint-initdb.d). They run as the bootstrap superuser.
--
-- Source of truth: docs/spec/SPEC.md (v0.8) §3 (WALL layers 0-1), §4 (_meta audit).
--
-- ===========================================================================
-- >>> HARDENED-ROLE INCLUDE POINT — issue #5 (the native-role WALL) <<<
-- ===========================================================================
-- The native-role WALL (hardened agent role, least-privilege GRANTs, and the
-- role-hardening matrix; SPEC §3 layer 1) is in this directory as
-- deploy/init/10_hardened_role.sql and is picked up automatically by this
-- entrypoint mount (files run alphabetically — this 00_ file runs first, then
-- 10_hardened_role.sql). That file is a byte-for-byte SYNCED COPY of the
-- canonical deploy/sql/10_hardened_role.sql (the docker entrypoint mounts only
-- deploy/init/, so the WALL SQL is duplicated here; a symlink would dangle
-- inside the container). deploy/sql/check-init-sync.sh guards against drift.
--
-- The Layer 0 pg_hba NETWORK BOUNDARY (agent role permitted only from the proxy
-- host) is a deploy-time pg_hba concern, not an initdb-SQL concern. Its template
-- + generator + network-policy companion live in deploy/hba/; the dedicated
-- matrix harness deploy/test/wall_matrix.sh proves the boundary (agent from a
-- non-proxy origin REJECTED, from the proxy host allowed) on its own throwaway
-- cluster. The dev primary itself keeps trust-local auth so the stack stays
-- queryable end-to-end.
-- ===========================================================================

-- Minimal, non-WALL baseline so a fresh `up` is queryable end-to-end.
-- (A trivial marker table; replaced/augmented by real fixtures later.)
CREATE TABLE IF NOT EXISTS public.pgb_devstack_marker (
    id        integer PRIMARY KEY,
    note      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.pgb_devstack_marker (id, note)
VALUES (1, 'pg_bumpers devstack primary initialized')
ON CONFLICT (id) DO NOTHING;

-- Replication role for the streaming standby (docker path). The local-stack.sh
-- path creates an equivalent role for the local PG18 substrate. Password is a
-- dev placeholder; production credentials come from secrets, not this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'replicator') THEN
        CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator';
    END IF;
END
$$;
