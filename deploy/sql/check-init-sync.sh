#!/usr/bin/env bash
# pg_brakes — guard: the docker-init copies of the WALL SQL must stay byte-for-byte in
# sync with the canonical sources. The docker entrypoint mounts only deploy/init/, so the
# SQL is duplicated there (a symlink would dangle inside the container). This guard fails
# loudly on drift so the two never diverge silently. Run it in review/CI and the matrix
# harness runs it on startup.
#
# THREE synced files (issue #103 split the role hardening from the demo seed; issue #108
# split the strict PUBLIC lockdown out of the role hardening):
#   * 10_hardened_role.sql    — the canonical, version-agnostic, BYO-applicable, AGENT-ROLE-
#     ONLY role hardening (a real deployment applies this + grants its own relations; it
#     NEVER mutates PUBLIC — issue #108);
#   * 21_public_lockdown.sql  — the OPT-IN strict PUBLIC lockdown (the `… FROM PUBLIC`
#     revokes; greenfield/dedicated-DB ONLY). The dev/test/CI fixture applies it; a BYO
#     user does NOT (it is in init/ because the docker primary is itself a throwaway fixture);
#   * 20_demo_seed.sql        — the FIXTURE-ONLY demo schema + grants (dev/test/CI only;
#     a real deployment does NOT apply this).
# All must stay byte-synced sql/ <-> init/.
#
#   deploy/sql/check-init-sync.sh   # exit 0 if in sync, non-zero + diff if not
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Every canonical SQL file that is duplicated into deploy/init/ (byte-synced).
SYNCED_FILES=(10_hardened_role.sql 20_demo_seed.sql 21_public_lockdown.sql)

drift=0
for name in "${SYNCED_FILES[@]}"; do
  CANON="$DEPLOY_DIR/sql/$name"
  INIT="$DEPLOY_DIR/init/$name"
  for f in "$CANON" "$INIT"; do
    [ -f "$f" ] || { echo "check-init-sync: missing $f" >&2; exit 1; }
  done
  if diff -u "$CANON" "$INIT" >/tmp/pgb_init_sync_diff.$$ 2>&1; then
    echo "check-init-sync: deploy/init/$name is IN SYNC with deploy/sql/."
  else
    echo "check-init-sync: DRIFT — deploy/init/$name differs from the canonical" >&2
    echo "  deploy/sql/$name. Re-sync with:" >&2
    echo "    cp deploy/sql/$name deploy/init/$name" >&2
    echo "--- diff (canonical -> init) ---" >&2
    cat /tmp/pgb_init_sync_diff.$$ >&2
    drift=1
  fi
  rm -f /tmp/pgb_init_sync_diff.$$
done

# -------------------------------------------------------------------------------------
# SPLIT GUARD (issue #103, FIX 6): the role hardening and the demo seed must stay
# SEPARATE. 10_hardened_role.sql is the canonical, BYO-applicable HARDENING ONLY — it
# must NOT (re)create the demo seed (the allowed_read / secret_data demo tables), so a
# future edit can't silently re-merge the fixture back into the file a real BYO user
# applies. Conversely 20_demo_seed.sql MUST carry that seed. We grep for the load-bearing
# marker `CREATE TABLE … (allowed_read|secret_data)` (the canonical file still NAMES those
# tables in its prose, so we key on the CREATE TABLE statement, not the bare name).
HARDEN="$DEPLOY_DIR/sql/10_hardened_role.sql"
SEED="$DEPLOY_DIR/sql/20_demo_seed.sql"
seed_re='CREATE TABLE.*(allowed_read|secret_data)'

if grep -Eq "$seed_re" "$HARDEN"; then
  echo "check-init-sync: SPLIT VIOLATION — deploy/sql/10_hardened_role.sql CREATEs a demo" >&2
  echo "  seed table (allowed_read/secret_data). The canonical role hardening must be" >&2
  echo "  hardening-ONLY (BYO-applicable); the demo seed belongs in 20_demo_seed.sql." >&2
  grep -nE "$seed_re" "$HARDEN" >&2
  drift=1
else
  echo "check-init-sync: SPLIT OK — 10_hardened_role.sql creates NO demo seed table (hardening-only)."
fi

if grep -Eq "$seed_re" "$SEED"; then
  echo "check-init-sync: SPLIT OK — 20_demo_seed.sql DOES create the demo seed tables (fixture)."
else
  echo "check-init-sync: SPLIT VIOLATION — deploy/sql/20_demo_seed.sql is missing the demo" >&2
  echo "  seed tables (allowed_read/secret_data) — the fixture must carry them." >&2
  drift=1
fi

# -------------------------------------------------------------------------------------
# FROM-PUBLIC SPLIT GUARD (issue #108, M2 — the incident fix): the DEFAULT BYO hardening
# (10_hardened_role.sql) must constrain the AGENT ROLE ONLY and NEVER mutate PUBLIC — i.e.
# it must contain NO executable `… FROM PUBLIC` statement (that is the global blast radius
# that took down a production DB — KNOWN_DANGERS.md D1). The strict `… FROM PUBLIC` revokes
# move to the OPT-IN 21_public_lockdown.sql, which MUST carry them. This is the load-bearing
# red/green check: if a future edit re-introduces a FROM-PUBLIC revoke into the default, this
# guard FAILS. We match an EXECUTABLE statement (REVOKE/GRANT/ALTER DEFAULT PRIVILEGES …
# FROM PUBLIC) anchored at line start (optional leading whitespace), so the explanatory PROSE
# (comment lines beginning with `--`, which mention "… FROM PUBLIC") never trips it.
LOCKDOWN="$DEPLOY_DIR/sql/21_public_lockdown.sql"
# An executable revoke-from-PUBLIC: a non-comment line whose statement ends in FROM PUBLIC.
# (Covers `REVOKE … FROM PUBLIC`, `ALTER DEFAULT PRIVILEGES … REVOKE … FROM PUBLIC`, and the
# `EXECUTE format('REVOKE … FROM PUBLIC', …)` dynamic form.) Comment lines start with `--`.
# CASE-INSENSITIVE (`grep -Ei`): SQL keywords are case-insensitive, so a `revoke … from public`
# or `From Public` re-introduced into the default must trip this guard just as `FROM PUBLIC` does.
frompublic_re='^[[:space:]]*[^-].*FROM[[:space:]]+PUBLIC'

if grep -Eiq "$frompublic_re" "$HARDEN"; then
  echo "check-init-sync: FROM-PUBLIC VIOLATION — deploy/sql/10_hardened_role.sql contains an" >&2
  echo "  executable '… FROM PUBLIC' statement. The DEFAULT BYO hardening must be AGENT-ROLE-" >&2
  echo "  ONLY and NEVER mutate PUBLIC (issue #108, KNOWN_DANGERS.md D1). Move the strict" >&2
  echo "  PUBLIC revokes to the opt-in 21_public_lockdown.sql." >&2
  grep -niE "$frompublic_re" "$HARDEN" >&2
  drift=1
else
  echo "check-init-sync: FROM-PUBLIC OK — 10_hardened_role.sql has NO '… FROM PUBLIC' statement (agent-only default)."
fi

if [ -f "$LOCKDOWN" ] && grep -Eiq "$frompublic_re" "$LOCKDOWN"; then
  echo "check-init-sync: FROM-PUBLIC OK — 21_public_lockdown.sql DOES carry the '… FROM PUBLIC' revokes (opt-in strict lockdown)."
else
  echo "check-init-sync: FROM-PUBLIC VIOLATION — deploy/sql/21_public_lockdown.sql is missing" >&2
  echo "  the strict '… FROM PUBLIC' revokes — the opt-in lockdown must carry them." >&2
  drift=1
fi

exit "$drift"
