#!/usr/bin/env bash
# pg_bumpers — deploy/down.sh: clean teardown of the deploy/up.sh stack.
#
# Stops the three daemons by tracked PID (pgb-warden, pgb-applyd, pgb-proxy),
# tears down the throwaway PG18 via deploy/local-stack.sh down, removes the temp
# state dir, and verifies the dedicated ports are freed and :5432 is untouched.
#
# Usage: deploy/down.sh

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"

PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
META_PORT="${PG_BUMPERS_META_PORT:-54323}"
REPLICA_PORT="${PG_BUMPERS_REPLICA_PORT:-54322}"
PROXY_PORT="${PGB_UP_PROXY_PORT:-6432}"
STATE_DIR="${PGB_UP_STATE_DIR:-${TMPDIR:-/tmp}/pg_bumpers-up}"

log()  { printf '[down.sh] %s\n' "$*" >&2; }
die()  { printf '[down.sh] ERROR: %s\n' "$*" >&2; exit 1; }

port_listeners() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
PRE_5432="$(port_listeners 5432)"
log "pre-flight :5432 listener(s): ${PRE_5432:-<none>} (we NEVER touch these)"

# ----------------------------------------------------------------------------
# Stop each daemon by its tracked PID (most-dependent first).
# ----------------------------------------------------------------------------
stop_tracked() {
  local name="$1" pidfile="$STATE_DIR/$1.pid"
  [ -f "$pidfile" ] || { log "$name: no tracked pid (already gone)"; return 0; }
  local pid; pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    log "stopping $name (pid $pid)"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$pid" 2>/dev/null || true
  else
    log "$name: tracked pid ${pid:-<empty>} not alive"
  fi
  rm -f "$pidfile"
}

stop_tracked warden
stop_tracked applyd
stop_tracked proxy

# ----------------------------------------------------------------------------
# Tear down the throwaway PG18 clusters (primary/meta/replica) + remove state.
# ----------------------------------------------------------------------------
log "tearing down the throwaway PG18 (deploy/local-stack.sh down)…"
PGBIN="$PGBIN" "$SCRIPT_DIR/local-stack.sh" down || log "local-stack down reported an issue (continuing)"

if [ -d "$STATE_DIR" ]; then
  log "removing state dir $STATE_DIR"
  rm -rf "$STATE_DIR"
fi

# ----------------------------------------------------------------------------
# Verify the dedicated ports are freed; :5432 must be untouched.
# ----------------------------------------------------------------------------
stuck=()
for spec in "proxy:$PROXY_PORT" "primary:$PRIMARY_PORT" "meta:$META_PORT" "replica:$REPLICA_PORT"; do
  label="${spec%%:*}"; port="${spec##*:}"
  if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    stuck+=("$label:$port")
  fi
done
if [ "${#stuck[@]}" -ne 0 ]; then
  die "teardown INCOMPLETE — still LISTENing: ${stuck[*]}"
fi

POST_5432="$(port_listeners 5432)"
[ "$PRE_5432" = "$POST_5432" ] || die ":5432 listener set changed (pre='$PRE_5432' post='$POST_5432') — investigate!"

log "stack down: daemons stopped, ports $PROXY_PORT/$PRIMARY_PORT/$META_PORT/$REPLICA_PORT free, :5432 untouched (${POST_5432:-<none>})."
