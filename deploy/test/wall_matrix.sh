#!/usr/bin/env bash
# pg_brakes — Layer 1 WALL + Layer 0 boundary: the role-hardening TEST MATRIX.
# =====================================================================================
# Env-gated on PG_BRAKES_IT=1 (the project integration-test gate). Spins a DEDICATED,
# throwaway Postgres 18 cluster on port 54331 under a temp dir (never collides with
# local-stack's 54321-3, and NEVER touches the founder's 5432), applies the hardened-role
# SQL + the Layer 0 boundary pg_hba, then asserts ONE matrix row per check by ATTEMPTING
# the denied action as the agent role and proving it fails with a PERMISSION error — plus
# the whitelisted SELECT succeeds, member-of-nothing, and the direct-from-non-proxy
# connection is refused.
#
# TWO-PHASE STRUCTURE (issue #108, M2 — agent-only default vs. opt-in strict lockdown):
#   * PHASE 1 (the AGENT-ONLY DEFAULT): apply ONLY deploy/sql/10_hardened_role.sql (which
#     NEVER mutates PUBLIC) + the demo seed. Section C-agent proves the agent stays contained
#     WITHOUT any `… FROM PUBLIC` revoke (no DML grant, no CREATE on public, TEMP revoked from
#     the AGENT). Section C-PUBLIC-UNTOUCHED proves the default did NOT globally revoke —
#     PUBLIC STILL HAS its EXECUTE / TEMP / lo_* defaults after the agent-only file. This is
#     the load-bearing M2 distinction: "agent denied" (must hold) vs. "PUBLIC globally
#     revoked" (the default must NOT do).
#   * PHASE 2 (the OPT-IN STRICT LOCKDOWN): apply deploy/sql/21_public_lockdown.sql (the
#     `… FROM PUBLIC` revokes) and re-assert the PUBLIC-globally-revoked rows in their own
#     context — the in-DB large-object write built-ins (lo_create/lowrite/lo_from_bytea/
#     lo_put) and PUBLIC EXECUTE on public functions are now DENIED to the agent at the DB
#     level. A real BYO deployment applies ONLY phase 1; the fixture applies both.
# Two security claims the reviewer flagged are covered honestly:
#   * search_path INVARIANT (section I): the role-level search_path pin is BEST-EFFORT (a
#     non-superuser CAN change its own role GUCs — the proxy is the authoritative pin). We
#     assert the agent CAN mutate/RESET its path (documented PG behavior) AND that after
#     maximal mutation + RESET ALL it STILL cannot read non-whitelisted DATA (no DML grant)
#     — the WALL's guarantee is the explicit-grant model, not search_path. (It does NOT claim
#     "cannot write/CREATE anywhere": on the agent-only default the agent retains PUBLIC's
#     TEMP/CREATE-on-PG14 defaults at the DB level — see the RESIDUAL rows below.)
#   * NO DML write GRANT to the AGENT (section C): the agent has no grant on any application
#     relation, so DML on the seeded tables is denied. But CREATE TEMP TABLE is NOT denied on
#     the agent-only default — TEMP flows through PUBLIC and a per-role REVOKE cannot subtract
#     it (section C asserts the agent CAN create a TEMP table as a documented RESIDUAL). The
#     TEMP + in-DB large-object write built-ins are denied at the DB level only under the
#     PHASE-2 lockdown (no agent-scoped revoke exists for them). THROUGH THE PROXY that same
#     write class (SELECT lo_create()/lowrite()/CREATE TEMP) is Blocked by the M2a fail-closed
#     classifier (#114/#115); DIRECT-TO-DB it is gated by the §3 network boundary.
# assert_denied now requires a permission/insufficient-privilege error class (a typo or
# connection error can no longer masquerade as a deny), and an independent BOUNDARY-RED
# self-test proves the boundary assertion fails when the pg_hba is misconfigured.
#
# Two modes (TDD red/green):
#   GREEN (default):  PHASE 1 apply deploy/sql/10_hardened_role.sql (agent-only) → the
#                     agent-containment + PUBLIC-untouched rows must PASS; PHASE 2 then apply
#                     deploy/sql/21_public_lockdown.sql → the PUBLIC-globally-revoked rows
#                     must PASS. EVERY row must PASS.
#   RED  (--red):     create a bare, UN-hardened agent role (LOGIN + a couple of broad
#                     grants a careless operator might give) → the deny assertions FAIL,
#                     proving the tests have teeth (a freshly-created role CAN do denied
#                     things). RED applies NEITHER file's lockdown; it exits NON-ZERO
#                     (failures are expected and demonstrate the RED state).
#
# SPEC §3 (layers 0-1), §4 ("Network/roles — do FIRST"), §5 (role-hardening matrix +
# network-boundary negative test). Issue #5. decisions.md "native roles = the security
# wall, hardened".
#
# Usage:
#   PG_BRAKES_IT=1 deploy/test/wall_matrix.sh           # GREEN: all rows pass, exit 0
#   PG_BRAKES_IT=1 deploy/test/wall_matrix.sh --red     # RED:  denies fail, exit non-0
#   deploy/test/wall_matrix.sh                           # gate unset → SKIP (exit 0)
# =====================================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------
# PG bin dir. Precedence (unified — issues #44, #102): PG_BRAKES_PG_BIN → PGBIN
# (legacy) → the version-neutral Homebrew keg path (macOS dev fallback).
# Version-agnostic across the supported PG 14-18 range (the WALL matrix is the
# very assertion that the hardened-role SQL applies on every supported major).
PGBIN="${PG_BRAKES_PG_BIN:-${PGBIN:-/opt/homebrew/opt/postgresql/bin}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SQL_FILE="$DEPLOY_DIR/sql/10_hardened_role.sql"
# The OPT-IN strict PUBLIC lockdown (issue #108 split it out of the agent-only hardening):
# the `… FROM PUBLIC` revokes (function EXECUTE blanket + ALTER DEFAULT PRIVILEGES, CREATE/
# TEMP, the lo_* in-DB write built-ins). The DEFAULT BYO posture (10_hardened_role.sql) is
# AGENT-ROLE-ONLY and does NOT apply this; the FIXTURE (this matrix, the dev stack) DOES, so
# the strict DB-level posture stays tested — but only AFTER section C-agent has proven the
# agent stays contained WITHOUT it (see the two-phase structure below).
LOCKDOWN_FILE="$DEPLOY_DIR/sql/21_public_lockdown.sql"
# The FIXTURE-ONLY demo seed (issue #103 split it out of the canonical hardening): the
# allowed_read / secret_data demo tables + grants the matrix's positive+negative read pair
# asserts against. A real BYO deployment does NOT apply this; the matrix (a fixture) does.
DEMO_SEED_FILE="$DEPLOY_DIR/sql/20_demo_seed.sql"
HBA_RENDER="$DEPLOY_DIR/hba/render-hba.sh"

# Dedicated test port + temp data dir. 54331 ∉ {54321,54322,54323,5432}.
TEST_PORT="${PG_BRAKES_WALL_PORT:-54331}"
AGENT_ROLE="pgb_agent"
AGENT_PW="pgb_agent_dev_pw"           # must match deploy/sql/10_hardened_role.sql default
AGENT_DB="postgres"
# ::1 = proxy-host stand-in (agent ALLOWED). 127.0.0.1 = non-proxy origin (agent REJECT).
PROXY_HOST="::1"
NONPROXY_HOST="127.0.0.1"

MODE="green"
[ "${1:-}" = "--red" ] && MODE="red"

# --------------------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------------------
if [ "${PG_BRAKES_IT:-0}" != "1" ]; then
  echo "[wall] PG_BRAKES_IT != 1 — skipping role-hardening matrix (set PG_BRAKES_IT=1 to run)."
  exit 0
fi
for b in initdb pg_ctl psql pg_isready; do
  [ -x "$PGBIN/$b" ] || { echo "[wall] FAIL: missing $PGBIN/$b — set PGBIN to a PostgreSQL 14-18 bin dir" >&2; exit 1; }
done
[ -f "$SQL_FILE" ]      || { echo "[wall] FAIL: missing $SQL_FILE" >&2; exit 1; }
[ -f "$LOCKDOWN_FILE" ] || { echo "[wall] FAIL: missing $LOCKDOWN_FILE" >&2; exit 1; }
[ -f "$HBA_RENDER" ]    || { echo "[wall] FAIL: missing $HBA_RENDER" >&2; exit 1; }

# Guard: the docker-init copy of the WALL SQL must match the canonical source we apply.
bash "$DEPLOY_DIR/sql/check-init-sync.sh" || {
  echo "[wall] FAIL: deploy/init copy of the WALL SQL is out of sync (see above)." >&2; exit 1; }

DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/pgb_wall.XXXXXX")"
PASS=0; FAIL=0

log()  { printf '[wall] %s\n' "$*"; }
okrow(){ printf '  PASS — %s\n' "$*"; PASS=$((PASS+1)); }
badrow(){ printf '  FAIL — %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

# Superuser psql (local, trust) — for setup/inspection.
SU() { "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" -v ON_ERROR_STOP=1 -tAqc "$1"; }

# Run SQL AS THE AGENT ROLE from the proxy host (::1, allowed). Captures combined
# stdout+stderr and the exit code. This is how every deny is *attempted*.
AGENT() { # sql -> sets AGENT_OUT, returns psql exit code
  AGENT_OUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
    "host=$PROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
    -v ON_ERROR_STOP=1 -tAqc "$1" 2>&1)"; }

cleanup() {
  if [ -d "$DATADIR/data" ]; then
    "$PGBIN/pg_ctl" -D "$DATADIR/data" -m immediate -w -t 20 stop >/dev/null 2>&1 || true
  fi
  rm -rf "$DATADIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------------------
# Safety: refuse to ever touch 5432, and refuse if 54331 is already bound by someone else.
# --------------------------------------------------------------------------------------
[ "$TEST_PORT" != "5432" ] || { echo "[wall] FAIL: refusing TEST_PORT=5432 (the founder's cluster)" >&2; exit 1; }
if lsof -tiTCP:"$TEST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[wall] FAIL: port $TEST_PORT already bound — refusing to collide (set PG_BRAKES_WALL_PORT)" >&2
  exit 1
fi

# --------------------------------------------------------------------------------------
# 1. initdb + configure the dedicated cluster (listen on ::1 AND 127.0.0.1).
# --------------------------------------------------------------------------------------
log "mode=$MODE — initdb dedicated cluster on :$TEST_PORT under $DATADIR"
# initdb with trust for the bootstrap superuser (local setup); the rendered pg_hba below
# overwrites the rules so the AGENT role authenticates with scram from the proxy host and
# is rejected from non-proxy origins. password_encryption=scram so the agent's password
# verifier is scram (set explicitly; the PostgreSQL 14-18 default is scram already).
"$PGBIN/initdb" -D "$DATADIR/data" -U postgres -A trust --no-sync >/dev/null

cat >> "$DATADIR/data/postgresql.conf" <<EOF

# pg_brakes wall-matrix test cluster
listen_addresses = '$NONPROXY_HOST,$PROXY_HOST'
port = $TEST_PORT
# Pin the socket dir to our (short, writable) scratch dir. PGDG PostgreSQL on
# Debian/Ubuntu defaults unix_socket_directories to /var/run/postgresql, which a
# CI runner user cannot write to — so pg_ctl start would fail. All queries here
# go over TCP anyway; the socket is only for the postmaster's own bind.
unix_socket_directories = '$DATADIR'
password_encryption = 'scram-sha-256'
EOF

# Base pg_hba: superuser 'postgres' trusted locally for setup. Then APPEND the rendered
# Layer 0 boundary for the AGENT role (proxy=::1 allowed, everything else rejected).
cat > "$DATADIR/data/pg_hba.conf" <<EOF
# superuser setup access (test only)
local   all   postgres                    trust
host    all   postgres   127.0.0.1/32     trust
host    all   postgres   ::1/128          trust
EOF
# The boundary rules for the agent role (rendered from the shipped template). proxy=::1.
PGB_AGENT_ROLE="$AGENT_ROLE" PGB_AGENT_DB="$AGENT_DB" \
  bash "$HBA_RENDER" --proxy-cidr "$PROXY_HOST/128" --auth scram-sha-256 \
  >> "$DATADIR/data/pg_hba.conf"

"$PGBIN/pg_ctl" -D "$DATADIR/data" -l "$DATADIR/log" -o "-p $TEST_PORT" -w -t 30 start >/dev/null
log "cluster up; PG $(SU 'SHOW server_version' | tr -d '\n')"
# Server MAJOR version (e.g. 14, 15, 18) — drives the version-aware rows below. PG14 still
# grants CREATE on schema public to PUBLIC by default; PG15+ removed it (issue #108: that
# difference means "agent can create in public" is a PG14-only residual on the agent-only
# default — denied agent-only on PG15+, denied only under the lockdown on PG14).
PG_MAJOR_SRV="$(SU "SELECT current_setting('server_version_num')::int / 10000")"

# --------------------------------------------------------------------------------------
# 2. Provision the role under test.
#    GREEN: run the real hardened-role migration (creates + hardens pgb_agent + whitelist).
#    RED:   create a bare role with the kind of broad grants a careless operator gives,
#           so the deny assertions below FAIL (proving the matrix has teeth).
# --------------------------------------------------------------------------------------
if [ "$MODE" = "green" ]; then
  # =====================================================================================
  # PHASE 1 — AGENT-ONLY DEFAULT (issue #108). Apply ONLY the agent-role-only hardening
  # (10_hardened_role.sql) + the fixture demo seed. NOT the strict 21_public_lockdown.sql
  # yet: section C-agent + the PUBLIC-untouched checks below must PASS against this default
  # to prove (a) the agent is STILL contained without the global revoke, and (b) the default
  # did NOT mutate PUBLIC. The strict lockdown is applied later (PHASE 2) and its own context
  # re-asserts the PUBLIC-globally-revoked rows. This is the load-bearing M2 distinction.
  # =====================================================================================
  log "GREEN PHASE 1: applying AGENT-ONLY deploy/sql/10_hardened_role.sql + fixture demo seed (20_demo_seed.sql) — NOT the lockdown yet"
  # 1) the canonical AGENT-ONLY role HARDENING (creates + hardens pgb_agent + pgb_applier;
  #    NEVER mutates PUBLIC).
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$SQL_FILE" >/dev/null
  # 2) the FIXTURE-ONLY demo seed (the allowed_read / secret_data positive+negative read
  #    pair + grants). Issue #103 split this OUT of the canonical hardening, so the matrix
  #    (a fixture) applies it explicitly; a real BYO deployment never does.
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$DEMO_SEED_FILE" >/dev/null
  # Idempotency check: apply BOTH a SECOND time — must still succeed without error.
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$SQL_FILE" >/dev/null
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$DEMO_SEED_FILE" >/dev/null
  # Create a SECURITY DEFINER write function NOW (before any lockdown), NOT granted to the
  # agent. On the agent-only default it is PUBLIC-executable (residual — see section G); the
  # PHASE-2 lockdown's blanket `REVOKE EXECUTE ON ALL FUNCTIONS … FROM PUBLIC` reliably
  # strips it (it EXISTS at lockdown time), which G-LOCKDOWN asserts.
  SU "CREATE OR REPLACE FUNCTION public.pgb_secdef_write() RETURNS void LANGUAGE sql SECURITY DEFINER AS \$\$ INSERT INTO public.secret_data(id,secret) VALUES (1000,'via secdef') ON CONFLICT DO NOTHING \$\$;" >/dev/null
  log "GREEN PHASE 1: agent-only migration + demo seed applied twice (idempotent); secdef probe fn created"
else
  log "RED: creating a BARE, UN-hardened agent role with broad grants"
  SU "DROP ROLE IF EXISTS $AGENT_ROLE;" >/dev/null || true
  SU "CREATE ROLE $AGENT_ROLE LOGIN PASSWORD '$AGENT_PW';"
  # The tables exist either way (so SELECT targets are present).
  SU "CREATE TABLE IF NOT EXISTS public.allowed_read (id int PRIMARY KEY, label text NOT NULL);"
  SU "INSERT INTO public.allowed_read VALUES (1,'a'),(2,'b') ON CONFLICT DO NOTHING;"
  SU "CREATE TABLE IF NOT EXISTS public.secret_data (id int PRIMARY KEY, secret text NOT NULL);"
  SU "INSERT INTO public.secret_data VALUES (1,'TOP SECRET') ON CONFLICT DO NOTHING;"
  # The careless grants that the WALL is supposed to PREVENT:
  SU "GRANT pg_read_all_data TO $AGENT_ROLE;"     # makes the agent able to read EVERYTHING
  SU "GRANT pg_execute_server_program TO $AGENT_ROLE;"  # enables COPY … PROGRAM
  SU "GRANT ALL ON public.allowed_read TO $AGENT_ROLE;" # includes write
  SU "GRANT ALL ON public.secret_data TO $AGENT_ROLE;"  # non-whitelisted, should be denied
  # In RED, the boundary pg_hba is still in place; allow the agent from ::1 to run checks.
fi

# The permission/insufficient-privilege error class we require for a genuine deny. A plain
# non-zero psql exit is NOT enough — a typo, a missing relation, or a connection failure
# would also exit non-zero and could masquerade as "denied". We pin the pass to PostgreSQL's
# privilege-error wording (SQLSTATE class 42501 "insufficient_privilege" and friends), so a
# deny row only passes when the action was refused for a SECURITY reason.
PERM_DENIED_RE='permission denied|must be superuser|must be a member of|insufficient privilege|insufficient_privilege|pg_hba\.conf rejects connection|no privileges were granted|is not allowed'

# Helper: assert an action ATTEMPTED AS THE AGENT FAILS with a PERMISSION error (deny row).
# $1 = human label, $2 = SQL to attempt. PASS iff psql returns non-zero AND the captured
# output matches the permission-denied/insufficient-privilege error class (non-fakeable).
assert_denied() {
  local label="$1" sql="$2"
  if AGENT "$sql"; then
    badrow "$label — action SUCCEEDED but should have been DENIED. Output: ${AGENT_OUT:-<empty>}"
  elif printf '%s' "$AGENT_OUT" | grep -Eqi "$PERM_DENIED_RE"; then
    # Show the actual permission-error line (not the trailing caret/hint line) as evidence.
    okrow "$label — denied ($(printf '%s' "$AGENT_OUT" | grep -Ei "$PERM_DENIED_RE" | head -1))"
  else
    badrow "$label — failed but NOT with a permission/insufficient-privilege error (could be a typo/connection error, not a real deny): ${AGENT_OUT:-<empty>}"
  fi
}
# Helper: assert an action ATTEMPTED AS THE AGENT SUCCEEDS (whitelist row).
assert_allowed() {
  local label="$1" sql="$2" want="${3:-}"
  if AGENT "$sql"; then
    if [ -z "$want" ] || printf '%s' "$AGENT_OUT" | grep -q "$want"; then
      okrow "$label — allowed (${AGENT_OUT//$'\n'/ })"
    else
      badrow "$label — allowed but output unexpected: ${AGENT_OUT:-<empty>} (wanted '$want')"
    fi
  else
    badrow "$label — should have SUCCEEDED but was denied: ${AGENT_OUT:-<empty>}"
  fi
}

echo
log "===== ROLE-HARDENING MATRIX (mode=$MODE) ====="

# --------------------------------------------------------------------------------------
# A. Role-attribute matrix (queried from the catalog; the attributes ARE the control).
# --------------------------------------------------------------------------------------
ATTRS="$(SU "SELECT rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='$AGENT_ROLE'")"
IFS='|' read -r r_super r_inherit r_createrole r_createdb r_repl r_bypassrls <<<"$ATTRS"
[ "$r_super"      = "f" ] && okrow "NOT superuser (rolsuper=f)"            || badrow "rolsuper=$r_super (expected f)"
[ "$r_inherit"    = "f" ] && okrow "NOINHERIT (rolinherit=f)"             || badrow "rolinherit=$r_inherit (expected f)"
[ "$r_createrole" = "f" ] && okrow "NOT CREATEROLE (rolcreaterole=f)"     || badrow "rolcreaterole=$r_createrole (expected f)"
[ "$r_createdb"   = "f" ] && okrow "NOT CREATEDB (rolcreatedb=f)"         || badrow "rolcreatedb=$r_createdb (expected f)"
[ "$r_repl"       = "f" ] && okrow "NOT REPLICATION (rolreplication=f)"   || badrow "rolreplication=$r_repl (expected f)"
[ "$r_bypassrls"  = "f" ] && okrow "NOT BYPASSRLS (rolbypassrls=f)"       || badrow "rolbypassrls=$r_bypassrls (expected f)"

# Member-of-nothing: pg_auth_members must be EMPTY for the agent (no pg_* role memberships).
NMEMB="$(SU "SELECT count(*) FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member WHERE a.rolname='$AGENT_ROLE'")"
if [ "$NMEMB" = "0" ]; then
  okrow "member-of-nothing (pg_auth_members empty for agent)"
else
  MEMBS="$(SU "SELECT string_agg(g.rolname,',') FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member JOIN pg_roles g ON g.oid=m.roleid WHERE a.rolname='$AGENT_ROLE'")"
  badrow "member-of-nothing — agent is a member of: $MEMBS (expected none)"
fi

# search_path role-level pin present (BEST-EFFORT defense-in-depth, NOT immutable). The
# role-level pin must exist and not contain "$user" — but it is only the drift-correcting
# default, NOT the security guarantee. The proxy (S1) is the authoritative per-session pin;
# the WALL's real guarantee is the explicit-grant model, asserted by the "search_path
# invariant" rows in section I below (agent mutates path + RESET ALL → still denied).
SP="$(SU "SELECT coalesce((SELECT c FROM unnest(rolconfig) c WHERE c LIKE 'search_path=%'),'<unset>') FROM pg_roles WHERE rolname='$AGENT_ROLE'")"
if printf '%s' "$SP" | grep -q 'search_path=' && ! printf '%s' "$SP" | grep -q '\$user'; then
  okrow "search_path role-level pin present, no \$user (best-effort; proxy is authoritative) ($SP)"
else
  badrow "search_path role-level pin missing / contains \$user ($SP)"
fi

# --------------------------------------------------------------------------------------
# B. Predefined-role REVOKEs — proven by ATTEMPTING the capability each grants.
# --------------------------------------------------------------------------------------
# pg_read_all_data → can read ANY table. Prove revoked: SELECT a non-whitelisted table fails.
assert_denied "REVOKE pg_read_all_data (SELECT non-whitelisted public.secret_data)" \
  "SELECT secret FROM public.secret_data LIMIT 1"
# pg_read_all_settings → can read restricted GUCs. (Functional proof is covered by member-
# of-nothing + the catalog check above; here we assert the membership is gone.)
#
# VERSION-AGNOSTIC (C1 #102, spec v0.8.1 §0.5 — supported PG 14-18): some of these
# predefined roles were introduced in a specific major and DO NOT EXIST on older ones —
# pg_checkpoint (15+), pg_create_subscription (16+), pg_use_reserved_connections (16+),
# pg_maintain (17+). `pg_has_role(role, 'pg_maintain', 'MEMBER')` raises a hard ERROR on a
# major where the role is absent. So the assertion is guarded by `to_regrole(PR) IS NULL`:
# when the role does not exist on this major, the agent VACUOUSLY cannot be a member of it
# (the capability simply isn't present), so the row PASSES as N/A — never a false RED.
for PR in pg_read_all_data pg_write_all_data pg_read_all_settings pg_read_all_stats \
          pg_monitor pg_execute_server_program pg_read_server_files pg_write_server_files \
          pg_maintain pg_checkpoint pg_signal_backend pg_create_subscription \
          pg_stat_scan_tables pg_use_reserved_connections; do
  # Returns 'absent' when the role does not exist on this major (vacuously not a
  # member), else 't'/'f' from pg_has_role. NB: avoid `boolean::text` (it renders
  # 'true'/'false'); map to the single-char token psql shows for a bare boolean so
  # the existing 'f' == not-a-member check holds.
  IS_MEMBER="$(SU "SELECT CASE
                     WHEN to_regrole('$PR') IS NULL THEN 'absent'
                     WHEN pg_has_role('$AGENT_ROLE','$PR','MEMBER') THEN 't'
                     ELSE 'f'
                   END")"
  case "$IS_MEMBER" in
    f)      okrow "not a member of $PR" ;;
    absent) okrow "not a member of $PR (N/A — role absent on this PG major)" ;;
    *)      badrow "agent IS a member of $PR (expected revoked)" ;;
  esac
done

# --------------------------------------------------------------------------------------
# C. Write denies that hold on the AGENT-ONLY DEFAULT (issue #108) — NO write GRANT to the
#    agent. These pass WITHOUT any `… FROM PUBLIC` revoke: they rest on default-deny on data
#    (no DML grant), no CREATE on schema public (agent-scoped revoke), and TEMPORARY revoked
#    from the AGENT directly. This is the load-bearing proof the agent stays contained even
#    though the default no longer mutates PUBLIC. (The in-DB large-object write built-ins are
#    a PUBLIC-default surface with NO agent-scoped revoke — those denies move to section
#    C-LOCKDOWN below, which runs only AFTER the opt-in 21_public_lockdown.sql is applied.)
# --------------------------------------------------------------------------------------
assert_denied "no INSERT on whitelisted public.allowed_read" \
  "INSERT INTO public.allowed_read (id,label) VALUES (999,'pwn')"
assert_denied "no UPDATE on whitelisted public.allowed_read" \
  "UPDATE public.allowed_read SET label='pwn' WHERE id=1"
assert_denied "no DELETE on whitelisted public.allowed_read" \
  "DELETE FROM public.allowed_read WHERE id=1"
assert_denied "no INSERT on non-whitelisted public.secret_data" \
  "INSERT INTO public.secret_data (id,secret) VALUES (999,'pwn')"
# CREATE TABLE in schema public — VERSION-AWARE (issue #108). On PG15+ PUBLIC lacks CREATE
# on schema public by default, so the agent (with the agent-only revoke on top) is DENIED —
# assert the deny. On PG14 PUBLIC STILL has CREATE on public by default and the agent
# inherits it via PUBLIC (the agent-scoped `REVOKE CREATE … FROM pgb_agent` is a no-op while
# PUBLIC has it — verified on real PG14), so "agent can create in public" is a DOCUMENTED
# PG14 RESIDUAL on the agent-only default; its DB-level deny comes only from the lockdown
# (PHASE 2 asserts it). CREATE TABLE is DDL, so THROUGH THE PROXY it is Blocked structurally
# by the read-only classifier (M2a #114/#115); DIRECT-TO-DB the PG14 create is gated by the
# §3 network boundary. (We drop any table the agent manages to create so it does not linger.)
if [ "$PG_MAJOR_SRV" -ge 15 ]; then
  assert_denied "no CREATE TABLE in public (PG15+: PUBLIC lacks CREATE on public; agent denied)" \
    "CREATE TABLE public.pgb_pwn (id int)"
else
  assert_allowed "RESIDUAL (agent-only, PG14): agent CAN CREATE TABLE in public — PG14 PUBLIC still has CREATE on schema public; not deniable agent-only (through-proxy: DDL Blocked by the M2a classifier; direct-to-DB: gated by the network boundary; DB-level deny only under the lockdown)" \
    "CREATE TABLE public.pgb_pwn14 (id int); SELECT 'created-pg14'" "created-pg14"
  SU "DROP TABLE IF EXISTS public.pgb_pwn14" >/dev/null
fi
# CREATE TEMP TABLE: on the AGENT-ONLY default this is a DOCUMENTED RESIDUAL on EVERY major —
# TEMP flows through the PUBLIC grant and CANNOT be denied by an agent-scoped revoke (verified
# on real PG 14-18: has_database_privilege(agent,…,'TEMP') stays TRUE after `REVOKE TEMPORARY …
# FROM pgb_agent`). So the agent CAN create a temp table at the DB level; that write is gated
# NOT by a DB revoke but, split by path: THROUGH THE PROXY `CREATE TEMP TABLE` is DDL, Blocked
# structurally by the M2a read-only classifier (#114/#115); DIRECT-TO-DB by the §3 network
# boundary. We assert it SUCCEEDS here (honest DB-level residual) and assert the DB-level DENY
# in PHASE 2 after the lockdown revokes TEMP FROM PUBLIC.
# (See KNOWN_BYPASSES B-lo / SPEC.amendments A-M2.) A single `CREATE TEMP TABLE` statement
# returns no rows under -tAq (the command tag is suppressed) so we assert SUCCESS by exit code
# only (empty `want`); the table is session-local and vanishes when this psql session ends.
assert_allowed "RESIDUAL (agent-only): agent CAN CREATE TEMP TABLE — TEMP is a PUBLIC default, not deniable agent-only (through-proxy: DDL Blocked by the M2a classifier; direct-to-DB: gated by the network boundary; DB-level deny only under the lockdown)" \
  "CREATE TEMP TABLE pgb_residual_tmp (id int)"

# --------------------------------------------------------------------------------------
# C-PUBLIC-UNTOUCHED. The AGENT-ONLY default must NOT have globally revoked PUBLIC's
# defaults (issue #108 — that global mutation is the production-outage blast radius). We
# assert the OPPOSITE of a deny here: PUBLIC STILL HAS its default privileges after the
# agent-only file. This distinguishes "agent denied" (must hold, above) from "PUBLIC
# globally revoked" (the DEFAULT must NOT do — proven here; the strict lockdown does it
# later, in its own PHASE-2 context). If a future edit re-introduces a FROM-PUBLIC revoke
# into the default, these rows FLIP to FAIL.
# --------------------------------------------------------------------------------------
# PUBLIC still has EXECUTE on a public function created after apply (the language default).
SU "CREATE OR REPLACE FUNCTION public.pgb_pub_probe() RETURNS int LANGUAGE sql AS \$\$ SELECT 42 \$\$;" >/dev/null
HAS_PUB_EXEC="$(SU "SELECT has_function_privilege('public','public.pgb_pub_probe()','EXECUTE')")"
if [ "$HAS_PUB_EXEC" = "t" ]; then
  okrow "PUBLIC-UNTOUCHED: PUBLIC still has EXECUTE on a public function (agent-only default did NOT globally revoke function EXECUTE)"
else
  badrow "PUBLIC-UNTOUCHED: PUBLIC lost EXECUTE on a public function after the agent-only default (it should NOT mutate PUBLIC — issue #108)"
fi
# PUBLIC still has TEMPORARY on the database (the agent-only default revoked TEMP from the
# AGENT only, not from PUBLIC).
HAS_PUB_TEMP="$(SU "SELECT has_database_privilege('public', current_database(), 'TEMP')")"
if [ "$HAS_PUB_TEMP" = "t" ]; then
  okrow "PUBLIC-UNTOUCHED: PUBLIC still has TEMP on the database (agent-only default did NOT revoke TEMP from PUBLIC)"
else
  badrow "PUBLIC-UNTOUCHED: PUBLIC lost TEMP on the database after the agent-only default (it should NOT mutate PUBLIC — issue #108)"
fi
# PUBLIC still has EXECUTE on an in-DB large-object write built-in (lo_create) — the residual
# the agent-only default deliberately leaves open on a shared DB (KNOWN_BYPASSES B-lo).
HAS_PUB_LO="$(SU "SELECT has_function_privilege('public','lo_create(oid)','EXECUTE')")"
if [ "$HAS_PUB_LO" = "t" ]; then
  okrow "PUBLIC-UNTOUCHED: PUBLIC still has EXECUTE on lo_create (agent-only default leaves the lo_* PUBLIC default — documented residual; through-proxy SELECT lo_create() is Blocked by the M2a classifier, direct-to-DB gated by the network boundary)"
else
  badrow "PUBLIC-UNTOUCHED: PUBLIC lost EXECUTE on lo_create after the agent-only default (it should NOT mutate PUBLIC — issue #108)"
fi
SU "DROP FUNCTION IF EXISTS public.pgb_pub_probe();" >/dev/null

# --------------------------------------------------------------------------------------
# D. SELECT-whitelist — positive + negative read pair.
# --------------------------------------------------------------------------------------
assert_allowed "whitelisted SELECT public.allowed_read succeeds" \
  "SELECT count(*) FROM public.allowed_read" "2"
assert_denied  "non-whitelisted SELECT public.secret_data denied" \
  "SELECT secret FROM public.secret_data LIMIT 1"

# --------------------------------------------------------------------------------------
# E. Egress / file / program / large-object denies — ATTEMPT each as the agent.
# --------------------------------------------------------------------------------------
assert_denied "COPY … PROGRAM denied (no pg_execute_server_program / superuser)" \
  "COPY (SELECT 1) TO PROGRAM 'cat > /tmp/pgb_pwn_copy'"
assert_denied "COPY FROM PROGRAM denied" \
  "COPY public.allowed_read FROM PROGRAM 'echo 1,x'"
assert_denied "pg_read_file denied (no pg_read_server_files / superuser)" \
  "SELECT pg_read_file('pg_hba.conf')"
assert_denied "pg_read_server_files via pg_read_binary_file denied" \
  "SELECT length(pg_read_binary_file('PG_VERSION'))"
assert_denied "pg_ls_dir (server-file enumeration) denied" \
  "SELECT pg_ls_dir('.')"
assert_denied "lo_import (large-object file read) denied" \
  "SELECT lo_import('/etc/hosts')"
assert_denied "lo_export (large-object file write) denied" \
  "SELECT lo_export(2, '/tmp/pgb_pwn_lo')"
assert_denied "adminpack-style pg_logfile (catalog admin fn) denied or absent" \
  "SELECT pg_read_file('postgresql.conf', 0, 16)"

# --------------------------------------------------------------------------------------
# F. dblink / postgres_fdw deny — enumerate installed extensions; assert absent + the
#    agent cannot CREATE them (no superuser, no CREATE on db).
# --------------------------------------------------------------------------------------
EXTS="$(SU "SELECT coalesce(string_agg(extname,','),'<none>') FROM pg_extension WHERE extname IN ('dblink','postgres_fdw','file_fdw')")"
if [ "$EXTS" = "<none>" ]; then
  okrow "dblink/postgres_fdw/file_fdw NOT installed (enumerated pg_extension)"
else
  badrow "dangerous extensions installed: $EXTS"
fi
assert_denied "agent cannot CREATE EXTENSION dblink (egress)" \
  "CREATE EXTENSION IF NOT EXISTS dblink"
assert_denied "agent cannot CREATE EXTENSION postgres_fdw (egress)" \
  "CREATE EXTENSION IF NOT EXISTS postgres_fdw"

# --------------------------------------------------------------------------------------
# G. PUBLIC EXECUTE residual on the AGENT-ONLY default (issue #108). A SECURITY DEFINER
#    function created in public (here pgb_secdef_write, created in PHASE 1 above and NOT
#    granted to the agent) IS reachable by the agent via the PUBLIC default — the agent-only
#    default does NOT revoke function EXECUTE from PUBLIC. We assert it SUCCEEDS here (honest
#    residual), then prove the DB-level DENY in section G-LOCKDOWN below (after the lockdown's
#    blanket `REVOKE EXECUTE ON ALL FUNCTIONS … FROM PUBLIC` strips it). On a shared BYO DB
#    the agent's containment against such a function rests, split by path, NOT on a DB revoke:
#    THROUGH THE PROXY (the realistic agent path) the M2a fail-closed read classifier
#    (#114/#115) Blocks the very call — `SELECT public.pgb_secdef_write()` references a
#    NON-allowlisted (and schema-qualified) function, so the SELECT classifies NotRead and the
#    proxy floor rejects it BEFORE it reaches the DB (the classifier gates the CALL by name; it
#    does not need to see the INSERT inside the SECURITY DEFINER body). DIRECT-TO-DB it is gated
#    by the §3 network boundary. See SPEC.amendments.md A-M2 / KNOWN_BYPASSES.md B-lo. (The
#    write the function performs is a no-op ON CONFLICT, so asserting it succeeds here — at the
#    DB level, bypassing the proxy — does not corrupt the secret_data fixture.)
# --------------------------------------------------------------------------------------
assert_allowed "RESIDUAL (agent-only, DIRECT-TO-DB): agent CAN call a PUBLIC-executable SECURITY DEFINER fn — function EXECUTE is a PUBLIC default, not deniable agent-only (through-proxy the M2a classifier Blocks this SELECT: non-allowlisted/qualified fn → NotRead; direct-to-DB gated by the network boundary; DB-level deny only under the lockdown)" \
  "SELECT public.pgb_secdef_write(); SELECT 'secdef-called'" "secdef-called"

# --------------------------------------------------------------------------------------
# I. search_path INVARIANT — the security guarantee does NOT depend on the role-level pin.
#    PostgreSQL lets a non-superuser change its OWN role GUCs, so the agent CAN mutate /
#    RESET its search_path (documented PG behavior — we assert it SUCCEEDS, not pretend it
#    fails). The WALL's real guarantee is the explicit-grant model: after MAXIMAL mutation
#    (hostile pg_temp-first path) AND a full `RESET ALL` that wipes the pin entirely, the
#    agent STILL cannot read non-whitelisted DATA or perform grant-gated DML (no grant). This
#    is scoped to the GRANT-based read/DML surface — it does NOT claim "no write/CREATE
#    anywhere": on the agent-only default the agent retains PUBLIC's TEMP / lo_* / (PG14)
#    CREATE-on-public defaults at the DB level (the RESIDUAL rows in section C assert those;
#    their DB-level deny is asserted only after the PHASE-2 lockdown, and through the proxy
#    they are Blocked by the M2a classifier). We prove the invariant two ways: (1) within a
#    single session that sets a hostile path then attempts the deny; (2) by persisting
#    `ALTER ROLE self … / RESET ALL` and re-connecting a FRESH session.
# --------------------------------------------------------------------------------------
echo
log "===== SEARCH_PATH INVARIANT (role-level pin is best-effort; guarantee is grant-model) ====="

# I.1 — The agent CAN mutate its own role-level search_path (KNOWN PG behavior, documented).
#       A bare non-zero exit here would be a real problem (it should SUCCEED), so assert_allowed.
assert_allowed "agent CAN ALTER ROLE self SET search_path (documented PG behavior — pin is not immutable)" \
  "ALTER ROLE $AGENT_ROLE SET search_path = pg_temp, public, pg_catalog; SELECT 'altered'" "altered"

# I.2 — INVARIANT after self-mutation, FRESH session: a brand-new connection inherits the
#       mutated (pg_temp-first) path, yet the agent STILL cannot read the non-whitelisted table.
assert_denied "INVARIANT: after self-ALTER search_path (pg_temp-first), STILL cannot read non-whitelisted secret_data" \
  "SELECT secret FROM public.secret_data LIMIT 1"
# …and STILL cannot read non-whitelisted data regardless of the hostile path (the load-
# bearing search_path invariant: access is grant-based, not path-based). (CREATE TEMP TABLE
# and lo_create are PUBLIC-default residuals on the agent-only default — they are not denied
# here; their DB-level deny is asserted in section C-LOCKDOWN after the PUBLIC lockdown.)

# I.3 — RESET ALL wipes the pin entirely; the next session falls back to the cluster default
#       ("$user", public) — re-introducing the very $user element the pin removed. Assert the
#       agent CAN do this (documented), then prove the INVARIANT survives even that.
assert_allowed "agent CAN ALTER ROLE self RESET ALL (wipes the search_path pin — documented PG behavior)" \
  "ALTER ROLE $AGENT_ROLE RESET ALL; SELECT 'reset'" "reset"
# Confirm the pin really is gone now (defense-in-depth pin defeated — this is EXPECTED/known).
SP_AFTER="$(SU "SELECT coalesce((SELECT c FROM unnest(rolconfig) c WHERE c LIKE 'search_path=%'),'<unset>') FROM pg_roles WHERE rolname='$AGENT_ROLE'")"
if [ "$SP_AFTER" = "<unset>" ]; then
  okrow "DOCUMENTED: after RESET ALL the role-level search_path pin is GONE (<unset>) — pin is best-effort, not immutable; proxy is authoritative"
else
  badrow "expected pin wiped after RESET ALL but rolconfig still has: $SP_AFTER"
fi
# THE INVARIANT, with the pin fully wiped and a fresh session on the cluster default path:
assert_denied "INVARIANT: after RESET ALL (pin wiped, cluster-default path), STILL cannot read non-whitelisted secret_data" \
  "SELECT secret FROM public.secret_data LIMIT 1"
assert_denied "INVARIANT: after RESET ALL, STILL cannot write (INSERT into whitelisted allowed_read)" \
  "INSERT INTO public.allowed_read (id,label) VALUES (998,'pwn')"
# (CREATE TEMP TABLE / lo_create remain PUBLIC-default residuals on the agent-only default —
# their DB-level deny is asserted in section C-LOCKDOWN, not here. The search_path invariant
# is about the GRANT-based read/DML surface, which the asserts above cover.)
# The whitelisted read STILL works (access is grant-based, search_path-independent).
assert_allowed "INVARIANT: whitelisted SELECT still works regardless of search_path mutation" \
  "SELECT count(*) FROM public.allowed_read" "2"

# Restore the role-level pin for the rest of the run + clean state (the migration would do
# this on its next apply; we re-pin here so the cluster ends in the hardened shape).
SU "ALTER ROLE $AGENT_ROLE SET search_path = pg_catalog, \"public\";" >/dev/null

# --------------------------------------------------------------------------------------
# H. Layer 0 NETWORK BOUNDARY — agent from non-proxy origin REFUSED; from proxy ALLOWED.
# --------------------------------------------------------------------------------------
echo
log "===== LAYER 0 NETWORK BOUNDARY ====="
# Negative: agent from 127.0.0.1 (a NON-proxy origin) must be REJECTED at pg_hba.
if BOUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$NONPROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' 2>&1)"; then
  badrow "BOUNDARY — agent CONNECTED from non-proxy $NONPROXY_HOST (should be REJECTED): $BOUT"
else
  if printf '%s' "$BOUT" | grep -qi 'pg_hba.conf rejects connection'; then
    okrow "BOUNDARY — agent from non-proxy $NONPROXY_HOST refused at pg_hba ($(printf '%s' "$BOUT" | tr '\n' ' '))"
  else
    badrow "BOUNDARY — agent from $NONPROXY_HOST failed but not via pg_hba reject: $BOUT"
  fi
fi
# Positive: agent from ::1 (the proxy-host stand-in) must be ALLOWED.
if POUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$PROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' 2>&1)" && [ "$POUT" = "1" ]; then
  okrow "BOUNDARY — agent from proxy host $PROXY_HOST allowed (models the proxy's IP/CIDR)"
else
  badrow "BOUNDARY — agent from proxy host $PROXY_HOST should be ALLOWED: $POUT"
fi

# --------------------------------------------------------------------------------------
# H-RED. Independent BOUNDARY-RED self-test — prove the boundary assertion has TEETH.
#   The reviewer flagged that the boundary rows pass even in --red (RED only un-hardens the
#   ROLE, not the pg_hba), so the boundary had no independent failing path. Here we make one:
#   we swap in a DELIBERATELY-PERMISSIVE pg_hba that lets the agent in from the non-proxy
#   origin (127.0.0.1), reload, and assert the agent NOW CONNECTS from 127.0.0.1 — i.e. the
#   boundary's negative assertion WOULD have failed had the boundary been misconfigured. We
#   then RESTORE the strict boundary and re-confirm the reject, proving the test distinguishes
#   an enforced boundary from a broken one (it is not passing vacuously). Always runs.
# --------------------------------------------------------------------------------------
echo
log "===== BOUNDARY-RED (independent: prove the boundary test can FAIL when misconfigured) ====="
HBA_FILE="$DATADIR/data/pg_hba.conf"
cp "$HBA_FILE" "$DATADIR/pg_hba.conf.strict.bak"
# Permissive misconfig: allow the agent from the NON-proxy origin (what a careless op might do).
{
  echo "# BOUNDARY-RED self-test: deliberately-permissive rule (allows the agent from non-proxy)"
  echo "host    all   $AGENT_ROLE   $NONPROXY_HOST/32   scram-sha-256"
  cat "$DATADIR/pg_hba.conf.strict.bak"
} > "$HBA_FILE"
SU "SELECT pg_reload_conf()" >/dev/null
sleep 0.5
if RBOUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$NONPROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' 2>&1)" && [ "$RBOUT" = "1" ]; then
  okrow "BOUNDARY-RED — with a permissive pg_hba the agent CONNECTS from non-proxy $NONPROXY_HOST (the strict-boundary assertion would correctly FAIL here → it has teeth)"
else
  badrow "BOUNDARY-RED — permissive pg_hba did NOT let the agent in from $NONPROXY_HOST (self-test inconclusive): $RBOUT"
fi
# Restore the strict boundary and re-confirm the reject (the boundary is enforced again).
cp "$DATADIR/pg_hba.conf.strict.bak" "$HBA_FILE"
SU "SELECT pg_reload_conf()" >/dev/null
sleep 0.5
if PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$NONPROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' >/dev/null 2>&1; then
  badrow "BOUNDARY-RED — after restoring strict pg_hba the agent STILL connected from $NONPROXY_HOST (boundary not re-enforced!)"
else
  okrow "BOUNDARY-RED — strict boundary RESTORED: agent again REJECTED from non-proxy $NONPROXY_HOST (boundary enforcement confirmed reversible)"
fi

# ======================================================================================
# PHASE 2 — STRICT PUBLIC LOCKDOWN (opt-in; issue #108). GREEN only. Everything above
# proved the AGENT-ONLY default contains the agent AND leaves PUBLIC untouched. NOW apply
# the opt-in deploy/sql/21_public_lockdown.sql (the `… FROM PUBLIC` revokes) and re-assert
# the PUBLIC-globally-revoked rows in THEIR OWN context: with the lockdown applied the
# in-DB large-object write built-ins and PUBLIC EXECUTE on public functions are denied to
# the agent at the DB level (the belt-and-suspenders a dedicated DB gets). RED skips this
# (it un-hardens the role; there is no lockdown to layer on).
# ======================================================================================
if [ "$MODE" = "green" ]; then
  echo
  log "===== PHASE 2: STRICT PUBLIC LOCKDOWN (opt-in 21_public_lockdown.sql — fixture only) ====="
  # Apply the opt-in strict lockdown (idempotent — apply twice to prove it).
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$LOCKDOWN_FILE" >/dev/null
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$LOCKDOWN_FILE" >/dev/null
  log "PHASE 2: strict lockdown applied twice (idempotent)"

  # --- PUBLIC-NOW-REVOKED: the lockdown DID globally revoke PUBLIC's defaults. -----------
  # PUBLIC no longer has TEMP on the database.
  HAS_PUB_TEMP2="$(SU "SELECT has_database_privilege('public', current_database(), 'TEMP')")"
  if [ "$HAS_PUB_TEMP2" = "f" ]; then
    okrow "LOCKDOWN: PUBLIC no longer has TEMP on the database (REVOKE TEMPORARY … FROM PUBLIC applied)"
  else
    badrow "LOCKDOWN: PUBLIC still has TEMP on the database after the strict lockdown (expected revoked)"
  fi
  # PUBLIC no longer has EXECUTE on the in-DB large-object write built-in lo_create.
  HAS_PUB_LO2="$(SU "SELECT has_function_privilege('public','lo_create(oid)','EXECUTE')")"
  if [ "$HAS_PUB_LO2" = "f" ]; then
    okrow "LOCKDOWN: PUBLIC no longer has EXECUTE on lo_create (REVOKE EXECUTE … FROM PUBLIC applied)"
  else
    badrow "LOCKDOWN: PUBLIC still has EXECUTE on lo_create after the strict lockdown (expected revoked)"
  fi
  # HONEST PG WART (documented residual, verified on PG 14-18): a function created AFTER the
  # lockdown by a role with NO other default-ACL customization is STILL PUBLIC-executable —
  # `ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE … FROM PUBLIC` does not persist an entry when
  # the result would be the empty set, so new functions fall back to the built-in PUBLIC
  # default (proacl NULL). We assert that documented behavior here (NOT a false "deny"), so a
  # future PG that changes this is caught. The RELIABLE deny is the blanket revoke of
  # functions that EXIST at lockdown time (asserted by G-LOCKDOWN below) + re-running the
  # lockdown / explicit per-function grants. See 21_public_lockdown.sql §2 caveat.
  SU "CREATE OR REPLACE FUNCTION public.pgb_pub_probe2() RETURNS int LANGUAGE sql AS \$\$ SELECT 7 \$\$;" >/dev/null
  HAS_PUB_FUT="$(SU "SELECT has_function_privilege('public','public.pgb_pub_probe2()','EXECUTE')")"
  if [ "$HAS_PUB_FUT" = "t" ]; then
    okrow "LOCKDOWN WART (documented): a function created AFTER the lockdown is STILL PUBLIC-executable (ALTER DEFAULT PRIVILEGES does not persist an empty-result entry — reliable deny is the blanket revoke of existing functions; see 21_public_lockdown.sql §2)"
  else
    okrow "LOCKDOWN: a function created AFTER the lockdown is NOT PUBLIC-executable (ALTER DEFAULT PRIVILEGES took effect on this PG — stricter than documented; acceptable)"
  fi
  SU "DROP FUNCTION IF EXISTS public.pgb_pub_probe2();" >/dev/null

  # --- C-LOCKDOWN: the in-DB large-object WRITE built-ins are now DENIED to the agent. ----
  # (EXECUTE revoked from PUBLIC by the lockdown; the agent, a PUBLIC member, loses them.)
  assert_denied "LOCKDOWN: no lo_create (large-object create EXECUTE revoked from PUBLIC)" \
    "SELECT lo_create(0)"
  assert_denied "LOCKDOWN: no lo_from_bytea (large-object create-from-bytea revoked from PUBLIC)" \
    "SELECT lo_from_bytea(0, '\\x00'::bytea)"
  assert_denied "LOCKDOWN: no lowrite (large-object write revoked from PUBLIC)" \
    "SELECT lowrite(lo_open(lo_create(0), 131072), repeat('x',1024)::bytea)"
  assert_denied "LOCKDOWN: no lo_put (large-object write-at-offset revoked from PUBLIC)" \
    "SELECT lo_put(lo_create(0), 0, '\\x00'::bytea)"

  # --- G-LOCKDOWN: PUBLIC EXECUTE revoked — the SECURITY DEFINER write function created in
  #     PHASE 1 (public.pgb_secdef_write, which EXISTED at lockdown time) is now stripped by
  #     the blanket `REVOKE EXECUTE ON ALL FUNCTIONS … FROM PUBLIC`, so the agent can no
  #     longer call it via the PUBLIC default (was the PHASE-1 residual in section G). We do
  #     NOT re-create it (re-creating would reset its ACL to the PUBLIC default). ---
  assert_denied "LOCKDOWN: PUBLIC EXECUTE revoked (cannot call the SECURITY DEFINER write fn that existed at lockdown time)" \
    "SELECT public.pgb_secdef_write()"

  # --- C-LOCKDOWN (PG14 residual closed): CREATE in schema public is now DENIED to the agent
  #     on PG14 too — the lockdown's `REVOKE CREATE ON SCHEMA public FROM PUBLIC` strips the
  #     PG14 PUBLIC default the agent-only file could not. On PG15+ this was already denied in
  #     PHASE 1 (PUBLIC lacks CREATE there); re-asserting under the lockdown is harmless and
  #     shows the lockdown is the deny on the one major where the default left a residual. ---
  assert_denied "LOCKDOWN: agent cannot CREATE TABLE in public (CREATE revoked from PUBLIC — closes the PG14 residual)" \
    "CREATE TABLE public.pgb_pwn_lockdown_tbl (id int)"

  # --- AGENT STILL CONTAINED under the lockdown too: re-assert the core agent denies hold ---
  # (the lockdown is additive belt-and-suspenders; it must not have loosened anything).
  assert_denied "LOCKDOWN: agent STILL cannot read non-whitelisted secret_data" \
    "SELECT secret FROM public.secret_data LIMIT 1"
  assert_allowed "LOCKDOWN: whitelisted SELECT public.allowed_read STILL works" \
    "SELECT count(*) FROM public.allowed_read" "2"
  assert_denied "LOCKDOWN: agent STILL cannot CREATE TEMP TABLE" \
    "CREATE TEMP TABLE pgb_pwn_lockdown (id int)"
fi

# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------
echo
log "===== RESULT (mode=$MODE): PASS=$PASS FAIL=$FAIL ====="
if [ "$MODE" = "red" ]; then
  # RED is a DEMONSTRATION that deny assertions fail on an un-hardened role. We EXPECT
  # failures; exit non-zero so the red state is unmistakable (and captured in the PR).
  if [ "$FAIL" -gt 0 ]; then
    log "RED as expected: $FAIL deny/whitelist assertion(s) FAILED on the un-hardened role."
    exit 1
  else
    log "RED UNEXPECTED: no assertions failed on the un-hardened role — the matrix lacks teeth!"
    exit 2
  fi
fi
# GREEN: every row must pass.
[ "$FAIL" -eq 0 ] || { log "GREEN FAILED: $FAIL matrix row(s) did not pass."; exit 1; }
log "GREEN: all $PASS matrix rows passed."
exit 0
