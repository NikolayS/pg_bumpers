#!/usr/bin/env bash
# pg_bumpers — local dev/test substrate (live S0 substrate for THIS environment)
#
# Brings up isolated, throwaway Postgres 18 clusters under ./.localstack/ using the
# Homebrew keg-only postgresql@18 binaries (initdb / pg_basebackup / pg_ctl). No Docker.
#
# Why local PG instead of docker-compose here: `docker pull` is non-functional in the
# pg_bumpers build environment (host-level daemon networking fault). docker-compose.yml
# remains the shipped artifact; this script is the live substrate every integration test
# and the fidelity gate (#8) run against. See docs/spec/SPEC.amendments.md "S0 integration
# substrate". SPEC refs: §7 (S0 compose), §12 (graceful degradation), §10.8 (degraded
# mode, no replica), §4 (append-only _meta audit DB).
#
# Topology (dedicated high ports; never touches the cluster on 5432):
#   primary  port 54321  — wal_level=replica, replication-ready, PITR-ready.
#   replica  port 54322  — streaming standby of primary via pg_basebackup -R.
#   meta     port 54323  — separate cluster hosting the append-only _meta audit DB (§4).
#
# Usage:
#   deploy/local-stack.sh up      # initdb + start primary + meta, base-backup + stream replica
#   deploy/local-stack.sh down    # stop all clusters and remove ./.localstack/ (clean teardown)
#   deploy/local-stack.sh status  # pg_isready + recovery/replication snapshot
#
# Idempotent: `up` on an already-up stack is a no-op-ish refresh; `down` is always safe.

set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"

# Repo root = parent of this script's dir, so paths work from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ROOT="${PG_BUMPERS_LOCALSTACK_DIR:-$REPO_ROOT/.localstack}"
PRIMARY_DIR="$ROOT/primary"
REPLICA_DIR="$ROOT/replica"
META_DIR="$ROOT/meta"
LOG_DIR="$ROOT/logs"

# Out-of-tree PID ledger: survives `rm -rf ./.localstack/`. This is how `down`
# can still stop OUR postmasters after the data dir is deleted out-of-band.
# Keyed by a stable digest of $ROOT so distinct stacks (different
# PG_BUMPERS_LOCALSTACK_DIR) never share a ledger.
PID_BASE="${PG_BUMPERS_PID_DIR:-${TMPDIR:-/tmp}/pg_bumpers-localstack}"
ROOT_KEY="$(printf '%s' "$ROOT" | cksum | tr -d ' ' | cut -c1-12)"
PID_DIR="$PID_BASE/$ROOT_KEY"

PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
REPLICA_PORT="${PG_BUMPERS_REPLICA_PORT:-54322}"
META_PORT="${PG_BUMPERS_META_PORT:-54323}"

REPL_USER="replicator"
REPL_PASS="replicator"
REPL_SLOT="local_replica_slot"

# Bind to loopback only — these are throwaway dev clusters.
LISTEN="localhost"

# Unique identity stamped into every cluster at init. wait_ready and the smoke
# harness check for this so a stale orphan squatting our port can never read as
# "our freshly-started cluster". A single run-id ties primary/replica/meta to
# the same `up` invocation.
SENTINEL_DB="pgb_localstack_sentinel"
SENTINEL_FILE="$ROOT/run_id"

# Tracks which clusters this process actually started, so the EXIT/ERR trap
# tears down ONLY what a partial `up` brought up.
STARTED_DIRS=()
UP_IN_PROGRESS=0

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
log()  { printf '[local-stack] %s\n' "$*" >&2; }
die()  { printf '[local-stack] ERROR: %s\n' "$*" >&2; exit 1; }

require_bins() {
  for b in initdb pg_ctl pg_basebackup psql pg_isready; do
    [ -x "$PGBIN/$b" ] || die "missing $PGBIN/$b — set PGBIN to your postgresql@18 bin dir"
  done
}

# Refuse to operate on a dangerous $ROOT before any rm -rf. Defaults are safe
# ($REPO_ROOT/.localstack); this guards a caller exporting a broad path.
validate_root() {
  [ -n "$ROOT" ]            || die "PG_BUMPERS_LOCALSTACK_DIR resolved to empty — refusing"
  [ "$ROOT" != "/" ]       || die "PG_BUMPERS_LOCALSTACK_DIR='/' — refusing"
  case "$ROOT" in
    /*) : ;;  # absolute, good
    *)  die "PG_BUMPERS_LOCALSTACK_DIR='$ROOT' is not an absolute path — refusing" ;;
  esac
  # Disallow $HOME itself and other obviously-too-broad roots.
  [ "$ROOT" != "${HOME:-/nonexistent}" ] || die "PG_BUMPERS_LOCALSTACK_DIR='$ROOT' is \$HOME — refusing"
  # The basename must be a recognizable localstack dir, OR the path must be
  # confined under the repo. This keeps teardown defensible against typos.
  local base; base="$(basename "$ROOT")"
  case "$ROOT" in
    "$REPO_ROOT"/*) return 0 ;;  # under the repo — always fine
  esac
  case "$base" in
    .localstack|*localstack*) return 0 ;;
  esac
  die "PG_BUMPERS_LOCALSTACK_DIR='$ROOT' is neither under the repo ($REPO_ROOT) nor a *localstack* dir — refusing rm -rf"
}

# Record a started postmaster's PID, keyed by port, in the out-of-tree ledger so
# `down` can stop it even after ./.localstack/ is deleted. Also remember the
# data dir for the cleanup trap.
record_started() {
  local dir="$1" port="$2"
  STARTED_DIRS+=("$dir")
  mkdir -p "$PID_DIR"
  local pid=""
  [ -f "$dir/postmaster.pid" ] && pid="$(head -n1 "$dir/postmaster.pid" 2>/dev/null || true)"
  # Persist both the PID and the data dir so `down` can match on EITHER the
  # recorded PID or the pgdata path — never on "whatever is on the port".
  printf '%s\t%s\n' "${pid:-?}" "$dir" > "$PID_DIR/$port.pid"
}

# Is $pid a postmaster WE own? True only if its `postgres -D <dir>` data dir is
# one of ours (under $ROOT or a recorded data dir). Never matches the founder's
# 5432 cluster or any unrelated process.
pid_is_ours() {
  local pid="$1"
  [ -n "$pid" ] && [ "$pid" != "?" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  # Resolve the data dir from the live process args.
  local args
  args="$(ps -o command= -p "$pid" 2>/dev/null || true)"
  case "$args" in
    *postgres*) : ;;
    *)          return 1 ;;
  esac
  # Match the -D data dir against our roots.
  case "$args" in
    *"-D $PRIMARY_DIR"*|*"-D $REPLICA_DIR"*|*"-D $META_DIR"*) return 0 ;;
    *"-D $ROOT/"*)                                            return 0 ;;
  esac
  return 1
}

# Wait until OUR freshly-started cluster accepts connections (bounded). Beyond a
# port probe, it verifies the sentinel DB exists AND carries this run's id, so a
# stale orphan on the port cannot masquerade as ready.
wait_ready() {
  local port="$1" label="$2" tries="${3:-60}" run_id="${4:-}"
  for _ in $(seq 1 "$tries"); do
    if "$PGBIN/pg_isready" -h "$LISTEN" -p "$port" -q; then
      if [ -z "$run_id" ]; then
        log "$label ready on port $port"
        return 0
      fi
      local got
      got="$("$PGBIN/psql" -X -h "$LISTEN" -p "$port" -U postgres -d "$SENTINEL_DB" \
               -tAqc 'SELECT run_id FROM public.pgb_sentinel LIMIT 1' 2>/dev/null || true)"
      if [ "$got" = "$run_id" ]; then
        log "$label ready on port $port (sentinel ok)"
        return 0
      fi
      # Port is up but it isn't us (orphan/foreign) — keep waiting; up's
      # pre-flight already refuses to start onto a squatted port.
    fi
    sleep 0.5
  done
  die "$label did not become our ready cluster on port $port"
}

# Stamp the per-run sentinel into a cluster (primary or meta — anything we can
# write to). The replica inherits it via streaming, so we don't stamp it there.
stamp_sentinel() {
  local port="$1" run_id="$2"
  if ! "$PGBIN/psql" -X -h "$LISTEN" -p "$port" -U postgres -d postgres -tAqc \
        "SELECT 1 FROM pg_database WHERE datname = '$SENTINEL_DB'" | grep -q 1; then
    "$PGBIN/psql" -X -h "$LISTEN" -p "$port" -U postgres -d postgres -v ON_ERROR_STOP=1 -qc \
      "CREATE DATABASE \"$SENTINEL_DB\";"
  fi
  "$PGBIN/psql" -X -h "$LISTEN" -p "$port" -U postgres -d "$SENTINEL_DB" -v ON_ERROR_STOP=1 -q <<EOF
CREATE TABLE IF NOT EXISTS public.pgb_sentinel (run_id text PRIMARY KEY);
TRUNCATE public.pgb_sentinel;
INSERT INTO public.pgb_sentinel (run_id) VALUES ('$run_id');
EOF
}

# --------------------------------------------------------------------------------------
# init + configure each cluster
# --------------------------------------------------------------------------------------
init_primary() {
  log "initdb primary -> $PRIMARY_DIR"
  "$PGBIN/initdb" -D "$PRIMARY_DIR" -U postgres -A trust --no-sync >/dev/null

  # postgresql.conf: replication-ready + PITR-ready knobs.
  cat >> "$PRIMARY_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: primary (SPEC §7/§12) ---
listen_addresses = '$LISTEN'
port = $PRIMARY_PORT
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
wal_keep_size = '128MB'
hot_standby = on
# archive_mode is OFF by default (PITR is OPTIONAL per §12). To make this
# PITR-ready: archive_mode = on; archive_command = 'test ! -f .../%f && cp %p .../%f'
EOF

  # pg_hba.conf: local access + a replication entry for the standby over TCP.
  cat >> "$PRIMARY_DIR/pg_hba.conf" <<EOF

# --- pg_bumpers local-stack: local access + streaming replication ---
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
host    replication     $REPL_USER      127.0.0.1/32            trust
host    replication     $REPL_USER      ::1/128                 trust
EOF
}

start_primary() {
  log "starting primary on port $PRIMARY_PORT"
  "$PGBIN/pg_ctl" -D "$PRIMARY_DIR" -l "$LOG_DIR/primary.log" \
    -o "-p $PRIMARY_PORT" -w -t 60 start >/dev/null
  record_started "$PRIMARY_DIR" "$PRIMARY_PORT"
  wait_ready "$PRIMARY_PORT" "primary"

  # Stamp the per-run sentinel so wait_ready / smoke can prove identity, and so
  # the standby inherits it via streaming replication.
  stamp_sentinel "$PRIMARY_PORT" "$RUN_ID"

  # Replication role for the standby.
  "$PGBIN/psql" -X -h "$LISTEN" -p "$PRIMARY_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$REPL_USER') THEN
    CREATE ROLE $REPL_USER WITH REPLICATION LOGIN PASSWORD '$REPL_PASS';
  END IF;
END
\$\$;
EOF

  # =====================================================================
  # >>> HARDENED-ROLE INCLUDE POINT — issue #5 (the native-role WALL) <<<
  # The native-role WALL (hardened agent role, least-privilege GRANTs,
  # role-hardening matrix; SPEC §3 layer 0-1) is applied here against the
  # primary. The SQL is idempotent, so re-running `up` re-asserts the
  # hardened state. The pg_hba network boundary (Layer 0) is a deploy-time
  # concern (deploy/hba/) exercised by the dedicated matrix harness
  # (deploy/test/wall_matrix.sh) — the dev primary keeps trust-local auth so
  # the stack stays queryable; the boundary template/generator ship in
  # deploy/hba/ and the harness proves the boundary on its own cluster.
  # =====================================================================
  log "applying hardened-role WALL SQL (deploy/sql/10_hardened_role.sql)"
  "$PGBIN/psql" -X -h "$LISTEN" -p "$PRIMARY_PORT" -U postgres -d postgres \
    -v ON_ERROR_STOP=1 -q -f "$SCRIPT_DIR/sql/10_hardened_role.sql" >/dev/null

  # Minimal baseline marker table so the stack is queryable end-to-end and the
  # smoke harness has a deterministic row to replicate.
  "$PGBIN/psql" -X -h "$LISTEN" -p "$PRIMARY_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q <<'EOF'
CREATE TABLE IF NOT EXISTS public.pgb_devstack_marker (
    id         integer PRIMARY KEY,
    note       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.pgb_devstack_marker (id, note)
VALUES (1, 'pg_bumpers local-stack primary initialized')
ON CONFLICT (id) DO NOTHING;
EOF
}

init_and_start_replica() {
  log "pg_basebackup replica <- primary($PRIMARY_PORT) -> $REPLICA_DIR"
  # -R writes standby.signal + primary_conninfo; -C -S creates a physical slot.
  PGPASSWORD="$REPL_PASS" "$PGBIN/pg_basebackup" \
    -h "$LISTEN" -p "$PRIMARY_PORT" -U "$REPL_USER" \
    -D "$REPLICA_DIR" -Fp -Xs -P -R -C -S "$REPL_SLOT" --no-sync

  # Standby-specific knobs (appended so they win).
  cat >> "$REPLICA_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: replica (standby) ---
listen_addresses = '$LISTEN'
port = $REPLICA_PORT
hot_standby = on
EOF

  log "starting replica on port $REPLICA_PORT"
  "$PGBIN/pg_ctl" -D "$REPLICA_DIR" -l "$LOG_DIR/replica.log" \
    -o "-p $REPLICA_PORT" -w -t 60 start >/dev/null
  record_started "$REPLICA_DIR" "$REPLICA_PORT"
  # The replica inherits the primary's sentinel DB via streaming, so the same
  # run_id check proves it is OUR standby (not an orphan).
  wait_ready "$REPLICA_PORT" "replica" 60 "$RUN_ID"
}

init_and_start_meta() {
  log "initdb meta -> $META_DIR"
  "$PGBIN/initdb" -D "$META_DIR" -U postgres -A trust --no-sync >/dev/null
  cat >> "$META_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: meta (append-only _meta audit DB, SPEC §4) ---
listen_addresses = '$LISTEN'
port = $META_PORT
EOF
  cat >> "$META_DIR/pg_hba.conf" <<EOF

# --- pg_bumpers local-stack: local access ---
local   all   all                  trust
host    all   all   127.0.0.1/32   trust
host    all   all   ::1/128        trust
EOF

  log "starting meta on port $META_PORT"
  "$PGBIN/pg_ctl" -D "$META_DIR" -l "$LOG_DIR/meta.log" \
    -o "-p $META_PORT" -w -t 60 start >/dev/null
  record_started "$META_DIR" "$META_PORT"
  wait_ready "$META_PORT" "meta"

  # meta is a separate cluster (no streaming), so stamp its own sentinel.
  stamp_sentinel "$META_PORT" "$RUN_ID"
  wait_ready "$META_PORT" "meta" 60 "$RUN_ID"

  # Create the append-only _meta audit DB (the audit schema itself lands later).
  if ! "$PGBIN/psql" -X -h "$LISTEN" -p "$META_PORT" -U postgres -d postgres -tAqc \
       "SELECT 1 FROM pg_database WHERE datname = '_meta'" | grep -q 1; then
    "$PGBIN/psql" -X -h "$LISTEN" -p "$META_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -qc \
      'CREATE DATABASE "_meta";'
    log "created _meta audit database"
  fi
}

# --------------------------------------------------------------------------------------
# Teardown — truthful, even when ./.localstack/ is gone out-of-band.
# --------------------------------------------------------------------------------------

# Stop a postmaster by PID without pg_ctl (used when the data dir is gone).
stop_pid() {
  local pid="$1"
  pid_is_ours "$pid" || return 0
  log "stopping our orphaned postmaster pid=$pid (data dir gone)"
  # SIGINT = fast shutdown for postgres; fall back to SIGQUIT (immediate).
  kill -INT "$pid" 2>/dev/null || true
  for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
  kill -QUIT "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
  kill -KILL "$pid" 2>/dev/null || true
}

# Stop a single cluster. Prefers pg_ctl (clean) when the data dir + pidfile are
# present; otherwise falls back to the recorded PID, then to whatever OF OURS is
# listening on the port. Never touches a process that isn't ours.
stop_cluster() {
  local dir="$1" label="$2" port="$3"

  if [ -d "$dir" ] && [ -f "$dir/postmaster.pid" ]; then
    log "stopping $label (pg_ctl)"
    "$PGBIN/pg_ctl" -D "$dir" -m fast -w -t 30 stop >/dev/null 2>&1 || \
      "$PGBIN/pg_ctl" -D "$dir" -m immediate -w -t 30 stop >/dev/null 2>&1 || true
  fi

  # Data dir / pidfile may be gone (rm -rf .localstack out-of-band). Use the
  # recorded PID ledger to stop OUR postmaster anyway.
  local ledger="$PID_DIR/$port.pid"
  if [ -f "$ledger" ]; then
    local rec_pid rec_dir
    # rec_dir is recorded for forensics; identity is reconfirmed live via ps.
    # shellcheck disable=SC2034
    IFS=$'\t' read -r rec_pid rec_dir < "$ledger" || true
    stop_pid "$rec_pid"
  fi

  # Last resort: a postmaster of OURS still LISTENing on our port (e.g. PID
  # recycled / ledger lost). Match identity via its -D data dir before killing.
  local lpid
  for lpid in $(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true); do
    stop_pid "$lpid"
  done

  rm -f "$ledger" 2>/dev/null || true
}

# True if any of our dedicated ports is still bound (by anyone).
port_listening() { lsof -tiTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

# --------------------------------------------------------------------------------------
# Cleanup trap — a partial/failed `up` tears down only what IT started.
# --------------------------------------------------------------------------------------
cleanup_on_err() {
  local rc="$?"
  [ "$UP_IN_PROGRESS" = "1" ] || return 0
  UP_IN_PROGRESS=0
  log "up failed (rc=$rc) — tearing down what was started"
  local dir
  for dir in "${STARTED_DIRS[@]:-}"; do
    [ -n "$dir" ] || continue
    case "$dir" in
      "$PRIMARY_DIR") stop_cluster "$PRIMARY_DIR" "primary" "$PRIMARY_PORT" ;;
      "$REPLICA_DIR") stop_cluster "$REPLICA_DIR" "replica" "$REPLICA_PORT" ;;
      "$META_DIR")    stop_cluster "$META_DIR"    "meta"    "$META_PORT" ;;
    esac
  done
  cmd_down_quiet
}

# --------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------
cmd_up() {
  require_bins
  validate_root

  # Fresh clusters each up: tear down anything stale (incl. orphans) first so
  # `up` is deterministic and never wedges on a squatted port.
  cmd_down_quiet

  # Pre-flight: if a dedicated port is STILL bound after teardown, it's a
  # foreign process (not ours) — refuse rather than silently colliding.
  local spec label port
  for spec in "primary:$PRIMARY_PORT" "replica:$REPLICA_PORT" "meta:$META_PORT"; do
    label="${spec%%:*}"; port="${spec##*:}"
    if port_listening "$port"; then
      die "port $port ($label) is occupied by a process we do not own — refusing to start (free it or override PG_BUMPERS_${label}_PORT)"
    fi
  done

  RUN_ID="$(date +%s)-$$-${RANDOM}"
  STARTED_DIRS=()
  UP_IN_PROGRESS=1
  trap cleanup_on_err ERR EXIT

  mkdir -p "$ROOT" "$LOG_DIR"
  printf '%s\n' "$RUN_ID" > "$SENTINEL_FILE"

  init_primary
  start_primary
  init_and_start_meta
  init_and_start_replica

  # Success — disarm the cleanup trap so we keep the stack up.
  UP_IN_PROGRESS=0
  trap - ERR EXIT
  log "stack up: primary=$PRIMARY_PORT meta=$META_PORT replica=$REPLICA_PORT (run_id=$RUN_ID)"
}

cmd_down_quiet() {
  stop_cluster "$REPLICA_DIR" "replica" "$REPLICA_PORT"
  stop_cluster "$META_DIR"    "meta"    "$META_PORT"
  stop_cluster "$PRIMARY_DIR" "primary" "$PRIMARY_PORT"
  validate_root
  if [ -d "$ROOT" ]; then
    rm -rf "$ROOT"
  fi
  # Drop the per-stack ledger dir if now empty.
  rmdir "$PID_DIR" 2>/dev/null || true
}

cmd_down() {
  require_bins
  cmd_down_quiet

  # Truthful report: fail loudly if any dedicated port is STILL bound. We never
  # claim success while a postmaster keeps LISTENing on our ports.
  local spec label port stuck=()
  for spec in "primary:$PRIMARY_PORT" "replica:$REPLICA_PORT" "meta:$META_PORT"; do
    label="${spec%%:*}"; port="${spec##*:}"
    port_listening "$port" && stuck+=("$label:$port")
  done
  if [ "${#stuck[@]}" -ne 0 ]; then
    die "teardown INCOMPLETE — still LISTENing: ${stuck[*]} (a process we could not match as ours is squatting the port)"
  fi
  log "stack down: clusters stopped, ports ${PRIMARY_PORT}/${REPLICA_PORT}/${META_PORT} free, $ROOT removed"
}

cmd_status() {
  require_bins
  for spec in "primary:$PRIMARY_PORT" "meta:$META_PORT" "replica:$REPLICA_PORT"; do
    local label="${spec%%:*}" port="${spec##*:}"
    if "$PGBIN/pg_isready" -h "$LISTEN" -p "$port" -q; then
      printf '[local-stack] %-8s port %-6s UP\n' "$label" "$port" >&2
    else
      printf '[local-stack] %-8s port %-6s DOWN\n' "$label" "$port" >&2
    fi
  done
}

main() {
  local sub="${1:-}"
  case "$sub" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *) die "usage: $(basename "$0") {up|down|status}" ;;
  esac
}

main "$@"
