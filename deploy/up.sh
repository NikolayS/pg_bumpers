#!/usr/bin/env bash
# pg_bumpers — deploy/up.sh: THE one-command runnable stack (S5 demo).
#
# Brings up the FULL assembled stack and prints a ready-to-paste `claude mcp add`
# line so a REAL Claude Code can connect and exercise the deterministic floor:
#   clone → build → `deploy/up.sh` → paste the printed line → ask Claude Code to
#   read/write → watch a DROP TABLE get REFUSED and a no-WHERE UPDATE get bounded.
#
# What it ACTUALLY launches (live, honest — see the per-line health checks):
#   1. a hardened throwaway PG18 via deploy/local-stack.sh up (primary 54321 +
#      meta 54323 + replica 54322; NEVER 5432). The native-role WALL `pgb_agent`
#      is applied to the primary by local-stack (deploy/sql/10_hardened_role.sql).
#   2. a demo DB on the primary carrying the canonical `_meta` audit chain
#      (crates/audit/sql/10_audit_meta.sql → pgb_audit schema + pgb_audit_writer)
#      and a single-int-PK `accounts` table (the bounded-reversible-write shape),
#      with SELECT on the read surface GRANTed to the WALL role `pgb_agent`.
#   3. pgb-proxy — the inline agent endpoint IN FRONT of the primary. The MCP read
#      path connects HERE (agent SCRAM endpoint), NOT raw PG18. Dev-mode TLS is OFF
#      (PGB_PROXY_REQUIRE_TLS=false) — stated explicitly; the proxy still does
#      SCRAM-SHA-256 of the agent and originates the backend session as the WALL
#      role. The proxy is the audit-chain anchor OWNER.
#   4. pgb-applyd — the write-path daemon on a Unix socket (the grant-gated
#      guarded_apply floor). Audit-chain VERIFY-only (the proxy owns the anchor).
#   5. pgb-warden — the live out-of-band watchdog (terminates agent-tagged runaway
#      reads; audits to the SAME `_meta` chain).
#
# PIDs are tracked under $STATE_DIR; each daemon is health-checked before success.
# Tear down with deploy/down.sh (stops the three daemons + local-stack, frees
# ports, verifies :5432 untouched).
#
# Usage:
#   deploy/up.sh                 # build (unless --no-build) + launch + print connect line
#   deploy/up.sh --no-build      # skip the cargo/pnpm build (use prebuilt artifacts)
#
# Requirements: the Homebrew keg-only postgresql@18 binaries (PGBIN), a Rust
# toolchain, Node + pnpm. Clean-room; Apache/MIT/BSD/ISC deps only.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"

# Dedicated high ports (NEVER 5432). The primary/meta/replica come from
# local-stack; the proxy's agent endpoint is its own high port.
PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
META_PORT="${PG_BUMPERS_META_PORT:-54323}"
PROXY_PORT="${PGB_UP_PROXY_PORT:-6432}"
HOST="127.0.0.1"

# The demo DB on the PRIMARY that carries BOTH the `_meta` audit chain and the
# demo `accounts`/read tables (one DB ⇒ one unified hash-chained audit chain that
# pgb-cli verify proves end-to-end).
DEMO_DB="${PGB_UP_DEMO_DB:-pgb_demo}"

# Out-of-tree state dir (PIDs, anchor file, socket, keys) so down.sh can stop the
# daemons even if the repo tree is touched. Stable across runs.
STATE_DIR="${PGB_UP_STATE_DIR:-${TMPDIR:-/tmp}/pg_bumpers-up}"
SOCKET_PATH="$STATE_DIR/applyd.sock"
ANCHOR_PATH="$STATE_DIR/audit.anchor.worm"

# Dev secrets (placeholders matching the local-stack WALL role; production sources
# them from a secret store — see deploy/proxy.env.example).
AGENT_PASSWORD="pgb_agent_dev_pw"
AUDIT_WRITER_PASSWORD="pgb_audit_writer_dev_pw"
AUDIT_SIGNING_KEY="pgb-audit-signing-key-dev-000001"
SESSION_ID="pgb-demo-session"

DO_BUILD=1
[ "${1:-}" = "--no-build" ] && DO_BUILD=0

log()  { printf '[up.sh] %s\n' "$*" >&2; }
die()  { printf '[up.sh] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$PROXY_PORT" != "5432" ] && [ "$PRIMARY_PORT" != "5432" ] || die "refusing to use :5432 (the founder's cluster)"

# ----------------------------------------------------------------------------
# Pre-flight: the founder's :5432 must be left exactly as we found it.
# ----------------------------------------------------------------------------
port_listeners() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
PRE_5432="$(port_listeners 5432)"
log "pre-flight :5432 listener(s): ${PRE_5432:-<none>} (we NEVER touch these)"

[ -x "$PGBIN/initdb" ] || die "PG18 initdb not found at $PGBIN; set PGBIN to your postgresql@18 bin dir"
command -v cargo >/dev/null || die "cargo not found"
command -v node  >/dev/null || die "node not found"

psql_primary() {
  "$PGBIN/psql" -X -h "$HOST" -p "$PRIMARY_PORT" -U postgres -d "${1:-postgres}" -v ON_ERROR_STOP=1 -tAc "$2"
}

# ----------------------------------------------------------------------------
# 1. Build the binaries + the MCP shell (unless --no-build).
# ----------------------------------------------------------------------------
if [ "$DO_BUILD" = "1" ]; then
  command -v pnpm >/dev/null || die "pnpm not found"
  log "building pgb-proxy, pgb-applyd, pgb-warden, pgb-cli…"
  ( cd "$REPO_ROOT" && cargo build --locked -p pgb-proxy -p pgb-applyd -p pgb-warden -p pgb-cli )
  log "building the deployable MCP stdio shell (pgb-mcp)…"
  ( cd "$REPO_ROOT/mcp/server" && pnpm install --frozen-lockfile && pnpm run build )
fi

PROXY_BIN="$REPO_ROOT/target/debug/pgb-proxy"
APPLYD_BIN="$REPO_ROOT/target/debug/pgb-applyd"
WARDEN_BIN="$REPO_ROOT/target/debug/pgb-warden"
MCP_BIN="$REPO_ROOT/mcp/server/dist/bin/mcpStdio.js"
for b in "$PROXY_BIN" "$APPLYD_BIN" "$WARDEN_BIN" "$MCP_BIN"; do
  [ -e "$b" ] || die "missing build artifact: $b (run without --no-build, or build first)"
done

# ----------------------------------------------------------------------------
# 2. Bring up the hardened throwaway PG18 (primary + meta + replica) via local-stack.
# ----------------------------------------------------------------------------
log "bringing up the throwaway PG18 (deploy/local-stack.sh up; primary $PRIMARY_PORT, meta $META_PORT)…"
PGBIN="$PGBIN" "$SCRIPT_DIR/local-stack.sh" up

# Fresh state dir (keys, socket dir, anchor) for this run.
rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# ----------------------------------------------------------------------------
# 3. Seed the demo DB on the primary: the `_meta` audit chain + the demo tables.
# ----------------------------------------------------------------------------
log "seeding demo DB '$DEMO_DB' on the primary (audit _meta chain + accounts read surface)…"
psql_primary postgres "SELECT 1 FROM pg_database WHERE datname='$DEMO_DB'" | grep -q 1 \
  || psql_primary postgres "CREATE DATABASE \"$DEMO_DB\""

# The canonical _meta schema (creates pgb_audit schema + pgb_audit_writer role +
# the append-only audit_log). Strip psql meta-commands the -f path tolerates but
# we keep it simple by running the file directly.
"$PGBIN/psql" -X -h "$HOST" -p "$PRIMARY_PORT" -U postgres -d "$DEMO_DB" -v ON_ERROR_STOP=1 -q \
  -f "$REPO_ROOT/crates/audit/sql/10_audit_meta.sql" >/dev/null

# The hardened WALL role `pgb_agent` already exists on the primary (applied by
# local-stack to the `postgres` DB), but role-level grants on THIS demo DB's
# objects must be granted here. Seed the demo tables + GRANT the read surface to
# the WALL role so reads THROUGH THE PROXY (which connects as pgb_agent) succeed,
# while a write table is owned by postgres (applyd writes as postgres).
"$PGBIN/psql" -X -h "$HOST" -p "$PRIMARY_PORT" -U postgres -d "$DEMO_DB" -v ON_ERROR_STOP=1 -q <<SQL >/dev/null
-- single-int-PK accounts: the MVP bounded-reversible-write shape.
CREATE TABLE IF NOT EXISTS public.accounts (
    id      int PRIMARY KEY,
    owner   text NOT NULL,
    balance bigint NOT NULL,
    notes   text NOT NULL DEFAULT ''
);
TRUNCATE public.accounts;
INSERT INTO public.accounts(id, owner, balance, notes)
  SELECT g, 'owner-' || g, (g * 1000)::bigint, 'note-' || g FROM generate_series(1, 8) AS g;

-- A whitelisted read surface for the agent (read THROUGH the proxy as pgb_agent).
GRANT USAGE ON SCHEMA public TO pgb_agent;
GRANT SELECT ON public.accounts TO pgb_agent;

-- A NON-whitelisted secret the WALL must keep from the agent (default-deny proof).
CREATE TABLE IF NOT EXISTS public.secret_data (id int PRIMARY KEY, secret text NOT NULL);
INSERT INTO public.secret_data(id, secret) VALUES (1, 'TOP SECRET — never to the agent')
  ON CONFLICT (id) DO NOTHING;
REVOKE ALL ON public.secret_data FROM pgb_agent;
SQL

META_DSN="host=$HOST port=$PRIMARY_PORT dbname=$DEMO_DB user=pgb_audit_writer password=$AUDIT_WRITER_PASSWORD"

# ----------------------------------------------------------------------------
# Helpers to launch + health-check a daemon.
# ----------------------------------------------------------------------------
track_pid() { printf '%s' "$2" > "$STATE_DIR/$1.pid"; }

wait_tcp() { # host port label tries
  local h="$1" p="$2" label="$3" tries="${4:-100}"
  for _ in $(seq 1 "$tries"); do
    if "$PGBIN/pg_isready" -h "$h" -p "$p" -q 2>/dev/null || nc -z "$h" "$p" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# ----------------------------------------------------------------------------
# 4. Launch pgb-proxy — IN FRONT of the primary; the MCP read path connects HERE.
#    The proxy is the audit anchor OWNER (anchors genesis before any traffic).
# ----------------------------------------------------------------------------
log "launching pgb-proxy (agent endpoint $HOST:$PROXY_PORT → primary $PRIMARY_PORT as WALL role pgb_agent; TLS OFF dev-mode)…"
PROXY_LOG="$STATE_DIR/proxy.log"
env \
  PGB_PROXY_LISTEN="$HOST:$PROXY_PORT" \
  PGB_PROXY_REQUIRE_TLS=false \
  PGB_AGENT_USER=pgb_agent \
  PGB_AGENT_PASSWORD="$AGENT_PASSWORD" \
  PGB_BACKEND_HOST="$HOST" \
  PGB_BACKEND_PORT="$PRIMARY_PORT" \
  PGB_BACKEND_DB="$DEMO_DB" \
  PGB_BACKEND_ROLE=pgb_agent \
  PGB_BACKEND_PASSWORD="$AGENT_PASSWORD" \
  PGB_POLICY_PATH="$REPO_ROOT/crates/policy/policy.example.yaml" \
  PGB_POLICY_ROLE=analytics \
  PGB_STATEMENT_TIMEOUT_MS=30000 \
  PGB_META_DSN="$META_DSN" \
  PGB_AUDIT_SIGNING_KEY="$AUDIT_SIGNING_KEY" \
  PGB_ANCHOR_PATH="$ANCHOR_PATH" \
  PGB_ANCHOR_INTERVAL_MS=60000 \
  PGB_ANCHOR_ROLE=owner \
  "$PROXY_BIN" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
track_pid proxy "$PROXY_PID"

if ! wait_tcp "$HOST" "$PROXY_PORT" proxy 100; then
  log "pgb-proxy did not open $HOST:$PROXY_PORT. Tail of its log:"; tail -30 "$PROXY_LOG" >&2
  die "pgb-proxy failed to start"
fi
kill -0 "$PROXY_PID" 2>/dev/null || { tail -30 "$PROXY_LOG" >&2; die "pgb-proxy exited early"; }
log "pgb-proxy up (pid $PROXY_PID; reads route through here, NOT raw PG18)."

# ----------------------------------------------------------------------------
# 5. Generate the throwaway Ed25519 approver keypair (the apply-time trust root).
#    Same shape crates/policy/crates/cli expect: a 32-byte seed (hex) signs grants
#    at `approve`; the 32-byte public key (hex) is applyd's configured trust root.
#    Produced with Node's crypto (Ed25519), matching the integration tests'
#    ed25519Hex() derivation (last 32 bytes of the DER spki/pkcs8).
# ----------------------------------------------------------------------------
KEYS_JSON="$(node -e '
  const { generateKeyPairSync } = require("crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" });
  const priv = privateKey.export({ type: "pkcs8", format: "der" });
  process.stdout.write(JSON.stringify({
    pub: pub.subarray(pub.length - 32).toString("hex"),
    seed: priv.subarray(priv.length - 32).toString("hex"),
  }));
')"
APPROVER_PUBKEY="$(printf '%s' "$KEYS_JSON" | node -e 'process.stdin.on("data",d=>process.stdout.write(JSON.parse(d).pub))')"
APPROVER_SEED="$(printf '%s' "$KEYS_JSON" | node -e 'process.stdin.on("data",d=>process.stdout.write(JSON.parse(d).seed))')"
printf '%s' "$APPROVER_PUBKEY" > "$STATE_DIR/approver.pub.hex"
printf '%s' "$APPROVER_SEED"  > "$STATE_DIR/approver.seed.hex"
chmod 0600 "$STATE_DIR/approver.seed.hex"
log "generated throwaway Ed25519 approver keypair (pubkey ${APPROVER_PUBKEY:0:16}…; seed in $STATE_DIR/approver.seed.hex)."

# ----------------------------------------------------------------------------
# 6. Launch pgb-applyd — the write-path socket daemon. VERIFY-only on the chain.
# ----------------------------------------------------------------------------
log "launching pgb-applyd (Unix socket $SOCKET_PATH; write role on the primary; audit verify-only)…"
APPLYD_LOG="$STATE_DIR/applyd.log"
env \
  PGB_APPLYD_SOCKET="$SOCKET_PATH" \
  PGB_APPROVER_PUBKEY="$APPROVER_PUBKEY" \
  PGB_POLICY_PATH="$REPO_ROOT/crates/policy/policy.example.yaml" \
  PGB_POLICY_ROLE=analytics \
  PGB_BACKEND_HOST="$HOST" \
  PGB_BACKEND_PORT="$PRIMARY_PORT" \
  PGB_BACKEND_DB="$DEMO_DB" \
  PGB_BACKEND_ROLE=postgres \
  PGB_BACKEND_PASSWORD=unused-trust \
  PGB_META_DSN="$META_DSN" \
  PGB_AUDIT_SIGNING_KEY="$AUDIT_SIGNING_KEY" \
  PGB_ANCHOR_PATH="$ANCHOR_PATH" \
  PGB_ANCHOR_INTERVAL_MS=60000 \
  PGB_ANCHOR_ROLE=verify \
  "$APPLYD_BIN" >"$APPLYD_LOG" 2>&1 &
APPLYD_PID=$!
track_pid applyd "$APPLYD_PID"

for _ in $(seq 1 100); do [ -S "$SOCKET_PATH" ] && break; sleep 0.1; done
[ -S "$SOCKET_PATH" ] || { tail -30 "$APPLYD_LOG" >&2; die "pgb-applyd socket never appeared at $SOCKET_PATH"; }
kill -0 "$APPLYD_PID" 2>/dev/null || { tail -30 "$APPLYD_LOG" >&2; die "pgb-applyd exited early"; }
log "pgb-applyd up (pid $APPLYD_PID; socket → guarded_apply_with_grant → primary)."

# ----------------------------------------------------------------------------
# 7. Launch pgb-warden — the live out-of-band watchdog over the primary.
# ----------------------------------------------------------------------------
log "launching pgb-warden (live watchdog over the primary; audits to the same _meta chain)…"
WARDEN_LOG="$STATE_DIR/warden.log"
env \
  PGB_POLICY_PATH="$REPO_ROOT/crates/policy/policy.example.yaml" \
  PGB_BACKEND_HOST="$HOST" \
  PGB_BACKEND_PORT="$PRIMARY_PORT" \
  PGB_BACKEND_DB="$DEMO_DB" \
  PGB_AUDIT_DB="$DEMO_DB" \
  PGB_WARDEN_ADMIN_ROLE=postgres \
  PGB_WARDEN_ADMIN_PASSWORD=unused-trust \
  PGB_AUDIT_WRITER_ROLE=pgb_audit_writer \
  PGB_AUDIT_WRITER_PASSWORD="$AUDIT_WRITER_PASSWORD" \
  "$WARDEN_BIN" >"$WARDEN_LOG" 2>&1 &
WARDEN_PID=$!
track_pid warden "$WARDEN_PID"

sleep 1.5
kill -0 "$WARDEN_PID" 2>/dev/null || { tail -30 "$WARDEN_LOG" >&2; die "pgb-warden exited early"; }
log "pgb-warden up (pid $WARDEN_PID)."

# ----------------------------------------------------------------------------
# 8. Record the connect env for down.sh / the operator approve hop, and PRINT the
#    ready-to-paste `claude mcp add` line.
# ----------------------------------------------------------------------------
cat > "$STATE_DIR/connect.env" <<ENV
PGB_APPLYD_SOCKET=$SOCKET_PATH
PGB_PROXY_HOST=$HOST
PGB_PROXY_PORT=$PROXY_PORT
PGB_PROXY_DB=$DEMO_DB
PGB_PROXY_USER=pgb_agent
PGB_PROXY_PASSWORD=$AGENT_PASSWORD
PGB_PROXY_APP_NAME=pgb_proxy
PGB_ROLE=pgb_agent
PGB_SESSION_ID=$SESSION_ID
PGB_META_DSN=$META_DSN
PGB_AUDIT_SIGNING_KEY=$AUDIT_SIGNING_KEY
PGB_ANCHOR_PATH=$ANCHOR_PATH
PGB_APPROVER_SEED_HEX=$APPROVER_SEED
DEMO_DB=$DEMO_DB
PRIMARY_PORT=$PRIMARY_PORT
ENV

# Post-flight: :5432 must be untouched.
POST_5432="$(port_listeners 5432)"
[ "$PRE_5432" = "$POST_5432" ] || die ":5432 listener set changed (pre='$PRE_5432' post='$POST_5432') — investigate!"

cat >&2 <<BANNER

================================================================================
 pg_bumpers stack is UP. Reads route through pgb-proxy (NOT raw PG18). :5432 untouched.
================================================================================

  pgb-proxy  : $HOST:$PROXY_PORT   (agent SCRAM endpoint, TLS OFF dev-mode, WALL role pgb_agent)
  pgb-applyd : $SOCKET_PATH        (write-path Unix socket)
  pgb-warden : live (pid $WARDEN_PID)
  PG18       : primary $PRIMARY_PORT, meta $META_PORT  (throwaway; NEVER 5432)
  demo DB    : $DEMO_DB  (accounts read surface + the _meta audit chain)

  Connect a REAL Claude Code to this stack — paste this single line:

  claude mcp add pg-bumpers \\
    --env PGB_APPLYD_SOCKET=$SOCKET_PATH \\
    --env PGB_PROXY_HOST=$HOST \\
    --env PGB_PROXY_PORT=$PROXY_PORT \\
    --env PGB_PROXY_DB=$DEMO_DB \\
    --env PGB_PROXY_USER=pgb_agent \\
    --env PGB_PROXY_PASSWORD=$AGENT_PASSWORD \\
    --env PGB_PROXY_APP_NAME=pgb_proxy \\
    --env PGB_ROLE=pgb_agent \\
    --env PGB_SESSION_ID=$SESSION_ID \\
    -- node $MCP_BIN

  Then ask Claude Code to:
    • read:    "query SELECT * FROM public.accounts"        → rows (bounded; through pgb-proxy)
    • refused: "propose_write DROP TABLE public.accounts"   → REFUSED (NOT_REHEARSABLE)
    • bounded: "propose_write UPDATE public.accounts SET balance=0 WHERE id%2=0"
               then dry_run → blast radius; apply_write → APPROVAL_REQUIRED
    • approve (operator, out-of-band — the signing key NEVER enters the agent path):
        the approver seed is in $STATE_DIR/approver.seed.hex; the operator calls
        the applyd socket 'approve' RPC (see deploy/README.md / the e2e test), then
        apply_write → COMMITTED, bounded + reversible.
    • verify:  PGB_META_DSN='$META_DSN' \\
               PGB_AUDIT_SIGNING_KEY=$AUDIT_SIGNING_KEY \\
               PGB_ANCHOR_PATH=$STATE_DIR/verify.anchor.worm \\
               $REPO_ROOT/target/debug/pgb-cli verify   → the chain verifies.

  Tear it all down:   deploy/down.sh
================================================================================
BANNER

log "stack ready."
