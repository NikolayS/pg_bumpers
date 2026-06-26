#!/usr/bin/env bash
# pg_bumpers — guard: the docker-init copies of the WALL SQL must stay byte-for-byte in
# sync with the canonical sources. The docker entrypoint mounts only deploy/init/, so the
# SQL is duplicated there (a symlink would dangle inside the container). This guard fails
# loudly on drift so the two never diverge silently. Run it in review/CI and the matrix
# harness runs it on startup.
#
# TWO synced files (issue #103 split the role hardening from the demo seed):
#   * 10_hardened_role.sql — the canonical, version-agnostic, BYO-applicable role hardening
#     (a real deployment applies this + grants its own relations);
#   * 20_demo_seed.sql     — the FIXTURE-ONLY demo schema + grants (dev/test/CI only;
#     a real deployment does NOT apply this).
# Both must stay byte-synced sql/ <-> init/.
#
#   deploy/sql/check-init-sync.sh   # exit 0 if in sync, non-zero + diff if not
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Every canonical SQL file that is duplicated into deploy/init/ (byte-synced).
SYNCED_FILES=(10_hardened_role.sql 20_demo_seed.sql)

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

exit "$drift"
