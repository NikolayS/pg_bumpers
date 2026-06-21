#!/usr/bin/env bash
# pg_bumpers — guard: the docker-init copy of the hardened-role SQL must stay byte-for-byte
# in sync with the canonical source. The docker entrypoint mounts only deploy/init/, so the
# WALL SQL is duplicated there (a symlink would dangle inside the container). This guard
# fails loudly on drift so the two never diverge silently. Run it in review/CI and the
# matrix harness runs it on startup.
#
#   deploy/sql/check-init-sync.sh   # exit 0 if in sync, non-zero + diff if not
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CANON="$DEPLOY_DIR/sql/10_hardened_role.sql"
INIT="$DEPLOY_DIR/init/10_hardened_role.sql"

for f in "$CANON" "$INIT"; do
  [ -f "$f" ] || { echo "check-init-sync: missing $f" >&2; exit 1; }
done

if diff -u "$CANON" "$INIT" >/tmp/pgb_init_sync_diff.$$ 2>&1; then
  rm -f /tmp/pgb_init_sync_diff.$$
  echo "check-init-sync: deploy/init/10_hardened_role.sql is IN SYNC with deploy/sql/."
  exit 0
fi
echo "check-init-sync: DRIFT — deploy/init/10_hardened_role.sql differs from the canonical" >&2
echo "  deploy/sql/10_hardened_role.sql. Re-sync with:" >&2
echo "    cp deploy/sql/10_hardened_role.sql deploy/init/10_hardened_role.sql" >&2
echo "--- diff (canonical -> init) ---" >&2
cat /tmp/pgb_init_sync_diff.$$ >&2
rm -f /tmp/pgb_init_sync_diff.$$
exit 1
