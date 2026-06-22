#!/usr/bin/env bash
# pg_bumpers — THE S5 MARQUEE runner (issue #68).
#
# "delete a DB through the official MCP", end-to-end, per DAMAGE CLASS, against the
# ASSEMBLED STACK (live proxy read path + pgb-applyd + live pgb-warden + anchored
# _meta audit), driven by a REAL MCP client over the deployable stdio shell.
#
# It builds the binaries, builds the MCP shell, runs the env-gated marquee
# integration test (PG_BUMPERS_IT=1) which stands up its OWN throwaway PG18 on a
# dedicated high port (default 54341; ⚠️ NEVER 5432) and tears it down, and writes
# the captured transcript to deploy/marquee.transcript.txt.
#
# What the system ACTUALLY does (honest, split by damage class — see the test):
#   1. IRREVERSIBLE / STRUCTURAL (DROP DATABASE/TABLE, TRUNCATE, ALTER) → REFUSED,
#      default-deny. The "delete a DB" headline is NEUTRALIZED BY REFUSAL, NOT run.
#   2. BOUNDED REVERSIBLE WRITE (no-WHERE/wide UPDATE, single-int-PK) → bounded;
#      no grant → APPROVAL_REQUIRED; operator-approved grant → applied reversibly;
#      a drifted apply → ABORT, no mutation.
#   3. RUNAWAY READ (agent-tagged long pg_sleep) → KILLED by the live warden; a
#      non-agent session is SPARED; the kill is AUDITED.
#   4. EVERY decision lands on ONE anchored _meta chain — pgb-cli verify proves
#      verify_chain + the anchored head match at the end.
#
# Usage:
#   deploy/marquee.sh            # build + run the marquee, record the transcript
#   PG_BUMPERS_MARQUEE_PORT=54350 deploy/marquee.sh   # override the high port
#
# Requirements: the Homebrew keg-only postgresql@18 binaries (PGBIN), a Rust
# toolchain, Node + pnpm. Clean-room; Apache/MIT/BSD/ISC deps only.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"
PORT="${PG_BUMPERS_MARQUEE_PORT:-54341}"
TRANSCRIPT="$SCRIPT_DIR/marquee.transcript.txt"

log() { printf '[marquee.sh] %s\n' "$*" >&2; }
die() { printf '[marquee.sh] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$PORT" != "5432" ] || die "refusing to run the marquee on :5432 (the founder's cluster)"

# ----------------------------------------------------------------------------
# Pre-flight: the founder's :5432 must be left exactly as we found it.
# ----------------------------------------------------------------------------
port_listeners() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
PRE_5432="$(port_listeners 5432)"
log "pre-flight :5432 listener(s): ${PRE_5432:-<none>} (we NEVER touch these)"

[ -x "$PGBIN/initdb" ] || die "PG18 initdb not found at $PGBIN; set PGBIN to your postgresql@18 bin dir"
command -v cargo >/dev/null || die "cargo not found"
command -v pnpm  >/dev/null || die "pnpm not found"

# ----------------------------------------------------------------------------
# Build the live binaries + the MCP shell the marquee drives.
# ----------------------------------------------------------------------------
log "building pgb-applyd, pgb-warden, pgb-cli (the assembled write/watchdog/verify path)…"
( cd "$REPO_ROOT" && cargo build --locked -p pgb-applyd -p pgb-warden -p pgb-cli )

log "building the deployable MCP stdio shell (pgb-mcp)…"
( cd "$REPO_ROOT/mcp/server" && pnpm install --frozen-lockfile && pnpm run build )

# ----------------------------------------------------------------------------
# Run the marquee. The test owns the throwaway PG18 lifecycle + teardown.
# Capture stderr (where the [marquee] transcript lines are emitted).
# ----------------------------------------------------------------------------
RAW="$(mktemp -t pgb-marquee-XXXXXX.log)"
trap 'rm -f "$RAW"' EXIT

log "running the marquee e2e (PG_BUMPERS_IT=1; throwaway PG18 on :$PORT)…"
set +e
( cd "$REPO_ROOT/mcp/server" \
    && PG_BUMPERS_IT=1 PG_BUMPERS_MARQUEE_PORT="$PORT" PGBIN="$PGBIN" \
       pnpm exec vitest run test/marquee.integration.test.ts ) >"$RAW" 2>&1
RC=$?
set -e

# Extract the committed transcript from the test's stderr block.
if grep -q "MARQUEE TRANSCRIPT" "$RAW"; then
  {
    echo "================================================================================"
    echo " pg_bumpers — S5 MARQUEE TRANSCRIPT (issue #68)  [recorded by deploy/marquee.sh]"
    echo " generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)  port: $PORT  pg: $("$PGBIN/initdb" --version)"
    echo "================================================================================"
    echo
    sed -n '/MARQUEE TRANSCRIPT/,/=============================/p' "$RAW" \
      | sed 's/^===== MARQUEE TRANSCRIPT =====/--- per-damage-class transcript ---/'
    echo
    echo "vitest result line:"
    grep -E "Tests +[0-9]+ passed" "$RAW" | tail -1 || true
  } >"$TRANSCRIPT"
  log "transcript written to $TRANSCRIPT"
fi

# ----------------------------------------------------------------------------
# Post-flight: :5432 must be untouched; no high-port cluster left behind.
# ----------------------------------------------------------------------------
POST_5432="$(port_listeners 5432)"
if [ "$PRE_5432" != "$POST_5432" ]; then
  die ":5432 listener set changed (pre='${PRE_5432}' post='${POST_5432}') — investigate!"
fi
log "post-flight :5432 unchanged (${POST_5432:-<none>}) ✓"

if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  die "the throwaway cluster on :$PORT is STILL listening (teardown leak)"
fi
log "throwaway cluster on :$PORT torn down ✓"

if [ "$RC" -ne 0 ]; then
  log "MARQUEE FAILED (vitest rc=$RC). Tail of the run:"
  tail -40 "$RAW" >&2
  exit "$RC"
fi

log "MARQUEE PASSED — all damage classes demonstrated; :5432 untouched; clean teardown."
log "see the transcript: $TRANSCRIPT"
