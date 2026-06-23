#!/usr/bin/env bash
# pg_bumpers — THE S5 MARQUEE runner (issue #68).
#
# "delete a DB through the official MCP", end-to-end, per DAMAGE CLASS, against the
# REAL ASSEMBLED STACK (live proxy read path + live pgb-applyd + anchored _meta
# audit), driven by a REAL MCP client over the shipped Rust `pgb-mcp` handler —
# NOT a fake, NOT raw PG.
#
# It builds the binaries and runs the env-gated Rust end-to-end tests in
# `crates/mcp/tests` (PG_BUMPERS_IT=1):
#   • write_path_e2e — stands up its OWN throwaway PG18 (dedicated high port,
#     default 54360; ⚠️ NEVER 5432) + a REAL pgb-applyd child, drives the SHIPPED
#     PgBumpersMcp handler over the SAME duplex transport the stdio binary uses,
#     and tears the cluster down cleanly.
#   • read_path_e2e  — runs the read path THROUGH a live pgb-proxy (TLS+SCRAM) in
#     front of a throwaway PG18 the marquee brings up via deploy/local-stack.sh
#     (primary 54321/meta 54323/replica 54322; ⚠️ NEVER 5432).
# The captured transcript is written to deploy/marquee.transcript.txt.
#
# What the system ACTUALLY does (honest, split by damage class — see the tests):
#   1. IRREVERSIBLE / STRUCTURAL (DROP TABLE/TRUNCATE) and STEERABLE-PREDICATE
#      writes → REFUSED, default-deny (NOT_REHEARSABLE / predicate gate). The
#      "delete a DB" headline is NEUTRALIZED BY REFUSAL, NOT run.
#   2. BOUNDED REVERSIBLE WRITE (wide UPDATE, single-int-PK) → bounded; no grant →
#      APPROVAL_REQUIRED; operator-approved grant → applied reversibly (rows read
#      back from PG18); an over-cap apply → BLAST_DRIFT abort, no mutation.
#   3. READ PATH THROUGH THE PROXY → a GRANTED table returns rows; a NON-granted
#      table is WALL_DENIED (a raw superuser would have returned it — the proof the
#      read path is behind the proxy/WALL); explain_plan never executes a stacked
#      write.
#   4. EVERY decision lands on the anchored _meta chain — get_audit reads the tail.
#
# Usage:
#   deploy/marquee.sh            # build + run the marquee, record the transcript
#   PG_BUMPERS_MARQUEE_PORT=54350 deploy/marquee.sh   # override the write-path high port
#
# Requirements: the Homebrew keg-only postgresql@18 binaries (PGBIN) and a Rust
# toolchain. Clean-room; Apache/MIT/BSD/ISC deps only.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"
# The write-path e2e stands up its OWN throwaway PG18 on this dedicated high port.
PORT="${PG_BUMPERS_MARQUEE_PORT:-54341}"
# The read-path e2e connects to the local-stack primary (a separate high port).
PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
TRANSCRIPT="$SCRIPT_DIR/marquee.transcript.txt"

log() { printf '[marquee.sh] %s\n' "$*" >&2; }
die() { printf '[marquee.sh] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$PORT" != "5432" ] && [ "$PRIMARY_PORT" != "5432" ] || die "refusing to run the marquee on :5432 (the founder's cluster)"

# ----------------------------------------------------------------------------
# Pre-flight: the founder's :5432 must be left exactly as we found it.
# ----------------------------------------------------------------------------
port_listeners() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
PRE_5432="$(port_listeners 5432)"
log "pre-flight :5432 listener(s): ${PRE_5432:-<none>} (we NEVER touch these)"

[ -x "$PGBIN/initdb" ] || die "PG18 initdb not found at $PGBIN; set PGBIN to your postgresql@18 bin dir"
command -v cargo >/dev/null || die "cargo not found"

# ----------------------------------------------------------------------------
# Build the live binaries the e2e tests exercise (applyd child + cli + the
# pgb-mcp handler the tests link in-process).
# ----------------------------------------------------------------------------
log "building pgb-applyd, pgb-warden, pgb-cli, pgb-mcp (the assembled write/read/verify path)…"
( cd "$REPO_ROOT" && cargo build --locked -p pgb-applyd -p pgb-warden -p pgb-cli -p pgb-mcp )

# ----------------------------------------------------------------------------
# Bring up a throwaway PG18 (primary/meta/replica on high ports) for the
# read-path e2e (it connects THROUGH a live proxy in front of this primary).
# The write-path e2e owns its OWN throwaway cluster + teardown.
# ----------------------------------------------------------------------------
RAW="$(mktemp -t pgb-marquee-XXXXXX.log)"
cleanup_localstack() { PGBIN="$PGBIN" "$SCRIPT_DIR/local-stack.sh" down >/dev/null 2>&1 || true; }
trap 'cleanup_localstack; rm -f "$RAW"' EXIT

log "bringing up the throwaway PG18 (deploy/local-stack.sh up; primary $PRIMARY_PORT) for the read path…"
PGBIN="$PGBIN" "$SCRIPT_DIR/local-stack.sh" up

# ----------------------------------------------------------------------------
# Run the marquee e2e tests. Capture stdout+stderr (--nocapture surfaces the
# per-damage-class assertions). The write path needs --test-threads=1.
# ----------------------------------------------------------------------------
log "running the WRITE-path marquee e2e (PG_BUMPERS_IT=1; throwaway PG18 on :$PORT)…"
set +e
( cd "$REPO_ROOT" \
    && PG_BUMPERS_IT=1 \
       PG_BUMPERS_PRIMARY_PORT="$PORT" \
       PG_BUMPERS_PG_BINDIR="${PG_BUMPERS_PG_BINDIR:-$PGBIN}" \
       cargo test --locked -p pgb-mcp --test write_path_e2e -- --nocapture --test-threads=1 ) >"$RAW" 2>&1
RC_WRITE=$?

log "running the READ-path marquee e2e (PG_BUMPERS_IT=1; read THROUGH the proxy → primary :$PRIMARY_PORT)…"
( cd "$REPO_ROOT" \
    && PG_BUMPERS_IT=1 \
       PG_BUMPERS_PROXY_PGURL="host=127.0.0.1 port=$PRIMARY_PORT user=postgres dbname=postgres" \
       cargo test --locked -p pgb-mcp --test read_path_e2e -- --nocapture --test-threads=1 ) >>"$RAW" 2>&1
RC_READ=$?
set -e

# ----------------------------------------------------------------------------
# Record the transcript: the e2e [ok] assertions + the cargo test result lines.
# ----------------------------------------------------------------------------
{
  echo "================================================================================"
  echo " pg_bumpers — S5 MARQUEE TRANSCRIPT (issue #68)  [recorded by deploy/marquee.sh]"
  echo " server: Rust pgb-mcp (crates/mcp) — the single deployable MCP server (EPIC #83)"
  echo " generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)  write-port: $PORT  read-primary: $PRIMARY_PORT"
  echo " pg: $("$PGBIN/initdb" --version)"
  echo "================================================================================"
  echo
  echo "--- per-damage-class assertions (the [ok] lines the e2e tests emit) ---"
  grep -E '^\[ok\]' "$RAW" | sed -n '1,200p' || true
  echo
  echo "cargo test result lines (write-path + read-path):"
  grep -E 'test result:' "$RAW" || true
} >"$TRANSCRIPT"
log "transcript written to $TRANSCRIPT"

# ----------------------------------------------------------------------------
# Post-flight: :5432 must be untouched; no high-port cluster left behind.
# ----------------------------------------------------------------------------
cleanup_localstack
POST_5432="$(port_listeners 5432)"
if [ "$PRE_5432" != "$POST_5432" ]; then
  die ":5432 listener set changed (pre='${PRE_5432}' post='${POST_5432}') — investigate!"
fi
log "post-flight :5432 unchanged (${POST_5432:-<none>}) ✓"

for p in "$PORT" "$PRIMARY_PORT"; do
  if lsof -tiTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    die "the throwaway cluster on :$p is STILL listening (teardown leak)"
  fi
done
log "throwaway clusters on :$PORT and :$PRIMARY_PORT torn down ✓"

if [ "$RC_WRITE" -ne 0 ] || [ "$RC_READ" -ne 0 ]; then
  log "MARQUEE FAILED (write rc=$RC_WRITE, read rc=$RC_READ). Tail of the run:"
  tail -60 "$RAW" >&2
  exit 1
fi

log "MARQUEE PASSED — all damage classes demonstrated through Rust pgb-mcp; :5432 untouched; clean teardown."
log "see the transcript: $TRANSCRIPT"
