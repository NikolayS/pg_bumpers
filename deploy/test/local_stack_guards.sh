#!/usr/bin/env bash
# pg_bumpers — local-stack.sh PATH/PID guard tests (issue #16).
# =====================================================================================
# Pure path/PID-logic unit tests for the two defense-in-depth hardenings flagged in the
# PR #14 review. NO real PostgreSQL is required (and none is started); NOTHING real is
# ever killed. The test sources local-stack.sh with PG_BUMPERS_LOCALSTACK_TEST=1 so the
# script defines its functions but does NOT run `main`, then drives the real
# `validate_root`, `canonicalize_path`, and `pid_is_ours` functions with controlled
# inputs.
#
# It asserts BOTH hardenings, with teeth (a RED self-check proves the assertions would
# have failed against the pre-fix logic — see the inline RED notes):
#
#   GUARD 1 — validate_root rejects a hostile PG_BUMPERS_LOCALSTACK_DIR whose `..`
#     escapes the repo (the script die()s / exits non-zero, and NO rm -rf runs outside
#     confinement), and ACCEPTS the safe default + a legitimate *localstack* dir.
#
#   GUARD 2 — pid_is_ours returns FALSE for a process whose args merely CONTAIN our
#     datadir as a substring / a prefix-collision, and TRUE only for an exact canonical
#     data-dir match. Driven against a real `sleep` process with a crafted argv — never
#     against a real cluster, never a kill.
#
# Always-runnable (no env gate): it is pure logic, so it runs in the FAST path and in
# CI without a live PG. SPEC §12 (graceful degradation). Issue #16.
#
# Usage:
#   deploy/test/local_stack_guards.sh        # run all guard assertions, exit 0 on PASS
# =====================================================================================
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
STACK="$DEPLOY_DIR/local-stack.sh"

PASS=0
FAIL=0
log()   { printf '[guards] %s\n' "$*"; }
okrow() { printf '  PASS — %s\n' "$*"; PASS=$((PASS + 1)); }
badrow(){ printf '  FAIL — %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }

[ -f "$STACK" ] || { echo "[guards] FAIL: missing $STACK" >&2; exit 1; }

# A dedicated scratch repo-root + localstack tree so we exercise the confinement logic
# against real directories without touching the actual repo or its .localstack.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/pgb_guards.XXXXXX")"
# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT INT TERM` below.
cleanup() {
  # Kill any test-only sleep we spawned (NEVER a real cluster).
  [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null || true
  rm -rf "$SCRATCH" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

FAKE_REPO="$SCRATCH/repo"
mkdir -p "$FAKE_REPO/.localstack"

# -------------------------------------------------------------------------------------
# Source local-stack.sh in TEST mode: it must define functions but NOT run main. We feed
# it controlled env so REPO_ROOT/ROOT/PRIMARY_DIR/etc. resolve into our scratch tree.
# A subshell isolates each scenario so per-scenario env (and a die() that exits) never
# pollutes the next assertion.
# -------------------------------------------------------------------------------------

# run_validate_root <ROOT> <REPO_ROOT> -> prints OK / REJECT. validate_root uses die()
# (which `exit 1`s), so we run it in a child process and key off that child's exit
# status: exit 0 == accepted (OK), non-zero == rejected (REJECT). The `|| true` keeps our
# own `set -e` from aborting on the (expected) reject. NEVER runs any rm.
run_validate_root() {
  local root="$1" repo="$2" rc=0
  (
    export PG_BUMPERS_LOCALSTACK_TEST=1
    export PG_BUMPERS_LOCALSTACK_DIR="$root"
    # We can't change BASH_SOURCE, so override REPO_ROOT/ROOT after sourcing. These are
    # consumed by the sourced validate_root (cross-source data flow shellcheck can't see).
    # shellcheck source=/dev/null
    source "$STACK"
    # shellcheck disable=SC2034
    REPO_ROOT="$repo"
    # shellcheck disable=SC2034
    ROOT="$root"
    validate_root
  ) >/dev/null 2>&1 && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then echo OK; else echo REJECT; fi
}

# run_pid_is_ours <pid> <PRIMARY_DIR> <REPLICA_DIR> <META_DIR> <ROOT> -> OURS / NOT
run_pid_is_ours() {
  local pid="$1" primary="$2" replica="$3" meta="$4" root="$5"
  (
    export PG_BUMPERS_LOCALSTACK_TEST=1
    # shellcheck source=/dev/null
    source "$STACK"
    # These override the script's globals and are read by the sourced pid_is_ours
    # (cross-source data flow shellcheck can't see).
    # shellcheck disable=SC2034
    PRIMARY_DIR="$primary"
    # shellcheck disable=SC2034
    REPLICA_DIR="$replica"
    # shellcheck disable=SC2034
    META_DIR="$meta"
    # shellcheck disable=SC2034
    ROOT="$root"
    if pid_is_ours "$pid" 2>/dev/null; then echo OURS; else echo NOT; fi
  )
}

# =====================================================================================
# GUARD 1 — validate_root: `..` escape rejection + safe-default/localstack acceptance.
# =====================================================================================
log "GUARD 1 — validate_root path confinement"

# (1a) Safe DEFAULT must still pass: $REPO_ROOT/.localstack under the repo.
got="$(run_validate_root "$FAKE_REPO/.localstack" "$FAKE_REPO")"
if [ "$got" = "OK" ]; then
  okrow "safe default \$REPO_ROOT/.localstack ACCEPTED"
else
  badrow "safe default \$REPO_ROOT/.localstack was REJECTED ($got) — guard too strict"
fi

# (1b) A legitimate *localstack* dir OUTSIDE the repo must still pass (basename allowance).
mkdir -p "$SCRATCH/elsewhere/my-localstack-scratch"
got="$(run_validate_root "$SCRATCH/elsewhere/my-localstack-scratch" "$FAKE_REPO")"
if [ "$got" = "OK" ]; then
  okrow "legitimate *localstack* dir outside repo ACCEPTED"
else
  badrow "legitimate *localstack* dir was REJECTED ($got)"
fi

# (1c) HOSTILE: a `..` that string-prefixes the repo but RESOLVES outside it. This is the
# core attack. Pre-fix (unanchored string-prefix "$REPO_ROOT/*") this PASSED because the
# literal string starts with "$REPO_ROOT/" — yet it canonicalizes to $SCRATCH/escaped,
# OUTSIDE the repo and outside any *localstack* dir, where the later `rm -rf "$ROOT"`
# would run. The fix must REJECT it.
mkdir -p "$SCRATCH/escaped"
HOSTILE="$FAKE_REPO/.localstack/../../escaped"
got="$(run_validate_root "$HOSTILE" "$FAKE_REPO")"
if [ "$got" = "REJECT" ]; then
  okrow "hostile '..' escape ('$HOSTILE' -> $SCRATCH/escaped) REJECTED"
else
  badrow "hostile '..' escape was ACCEPTED ($got) — confinement bypassed! (RED: pre-fix string-prefix lets this through)"
fi

# (1d) HOSTILE variant: `..` that escapes even the *localstack* basename allowance. The
# literal basename here is 'tmp' after normalization, well outside the repo. (Belt: a `..`
# chain that lands in a non-localstack dir.)
mkdir -p "$SCRATCH/outside"
HOSTILE2="$SCRATCH/elsewhere/my-localstack-scratch/../../outside"
got="$(run_validate_root "$HOSTILE2" "$FAKE_REPO")"
if [ "$got" = "REJECT" ]; then
  okrow "hostile '..' escape past the *localstack* allowance ('$HOSTILE2' -> $SCRATCH/outside) REJECTED"
else
  badrow "hostile '..' escape past the *localstack* allowance was ACCEPTED ($got)"
fi

# (1e) NO rm -rf ever happens in validate_root itself — assert the scratch tree the
# hostile ROOTs pointed at is still intact (validate_root must never delete; it only
# gate-keeps). This proves the reject path didn't take a destructive branch.
if [ -d "$SCRATCH/escaped" ] && [ -d "$SCRATCH/outside" ]; then
  okrow "no destructive side effect: validate_root left target dirs intact (gate-only)"
else
  badrow "a target dir vanished — validate_root must NEVER rm anything"
fi

# =====================================================================================
# GUARD 2 — pid_is_ours: exact canonical data-dir equality, not substring.
# =====================================================================================
log "GUARD 2 — pid_is_ours exact canonical data-dir match"

# Our canonical cluster dirs live under the fake stack root.
G_ROOT="$FAKE_REPO/.localstack"
G_PRIMARY="$G_ROOT/primary"
G_REPLICA="$G_ROOT/replica"
G_META="$G_ROOT/meta"
mkdir -p "$G_PRIMARY" "$G_REPLICA" "$G_META"

# A prefix-collision dir: its path string CONTAINS our primary dir as a prefix, but it is
# a DIFFERENT directory. Pre-fix the unanchored `*"-D $PRIMARY_DIR"*` substring matched
# any args containing the prefix -> false OURS. The fix's exact-equality must say NOT.
COLLIDE="${G_PRIMARY}-evil"   # ".../primary-evil" — has ".../primary" as a string prefix
mkdir -p "$COLLIDE"

# Spawn a `sleep` whose argv mimics `<comm> -D <dir>` IN THIS shell (NOT a command
# substitution — that would put the job in a short-lived subshell that reaps it before we
# can inspect it). Sets SLEEP_PID. This harmless sleep is the ONLY process we ever touch;
# never a real cluster, never a kill of anything but our own sleep.
#   $1 = leading comm token (e.g. "postgres" or "not_a_db")
#   $2 = the -D data-dir value
spawn_fake_pg() {
  local comm="$1" datadir="$2"
  # exec -a sets argv[0] to the whole "comm -D datadir" string; `ps -o command=` then
  # renders it as our crafted command line.
  bash -c 'exec -a "'"$comm"' -D '"$datadir"'" sleep 30' &
  SLEEP_PID="$!"
  # Give the exec a moment so `ps` sees the renamed argv rather than the bootstrap bash.
  sleep 0.2
}
reap_sleep() { [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null; wait "$SLEEP_PID" 2>/dev/null || true; SLEEP_PID=""; }

# (2a) EXACT match on our primary dir -> OURS.
spawn_fake_pg "postgres" "$G_PRIMARY"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "OURS" ]; then
  okrow "exact match: 'postgres -D $G_PRIMARY' recognized as OURS"
else
  badrow "exact match on our primary dir was NOT recognized ($got) — fail-closed too aggressive"
fi
reap_sleep

# (2b) PREFIX-COLLISION: a DIFFERENT dir whose string has our primary dir as a prefix
# must be NOT ours. RED: pre-fix `*"-D $PRIMARY_DIR"*` substring match returns OURS here
# (the killer could then target a non-ours postmaster). The fix must return NOT.
spawn_fake_pg "postgres" "$COLLIDE"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "prefix-collision: 'postgres -D ${COLLIDE}' correctly NOT ours (exact-equality, not substring)"
else
  badrow "prefix-collision dir matched as OURS ($got) — UNANCHORED SUBSTRING BUG (RED: pre-fix substring matches)"
fi
reap_sleep

# (2c) A process whose args CONTAIN our datadir merely as an embedded substring (not the
# real -D value) must be NOT ours. RED: pre-fix `*"-D $ROOT/"*` substring matches this.
spawn_fake_pg "postgres" "$G_ROOT/primary/pgdata --opt"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "embedded-substring arg under \$ROOT but not an exact datadir correctly NOT ours"
else
  badrow "embedded-substring arg matched as OURS ($got) — \$ROOT/ substring bug (RED)"
fi
reap_sleep

# (2d) FAIL-CLOSED: a non-postgres process (no `postgres` token) is never ours, even if
# its args contain the exact datadir.
spawn_fake_pg "not_a_db" "$G_PRIMARY"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "non-postgres process with exact datadir arg correctly NOT ours (fail-closed)"
else
  badrow "non-postgres process matched as OURS ($got)"
fi
reap_sleep

# (2e) FAIL-CLOSED: a dead/never-existed PID is never ours.
got="$(run_pid_is_ours "999999" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "non-existent PID correctly NOT ours (fail-closed)"
else
  badrow "non-existent PID matched as OURS ($got)"
fi

# =====================================================================================
# Verdict
# =====================================================================================
echo
log "===== RESULT: PASS=$PASS FAIL=$FAIL ====="
[ "$FAIL" -eq 0 ] || { log "GUARD TESTS FAILED: $FAIL assertion(s) did not pass."; exit 1; }
log "GREEN: all $PASS guard assertions passed."
exit 0
