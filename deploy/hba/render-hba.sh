#!/usr/bin/env bash
# pg_bumpers — render the Layer 0 network-boundary pg_hba rules from the template.
# =====================================================================================
# Substitutes the @PLACEHOLDERS@ in pg_hba.agent-boundary.conf.template and prints the
# rendered rules to stdout. The caller appends them to a cluster's pg_hba.conf (ABOVE any
# broad catch-all for the agent role, since pg_hba is first-match).
#
# SPEC §3 (layer 0), §4, §5. Issue #5. See the template header for the rule semantics.
#
# Usage:
#   deploy/hba/render-hba.sh [--agent-role R] [--agent-db D] [--proxy-cidr C] [--auth M]
# Env fallbacks: PGB_AGENT_ROLE PGB_AGENT_DB PGB_PROXY_CIDR PGB_AGENT_AUTH
#
# Example (production):
#   deploy/hba/render-hba.sh --proxy-cidr 10.0.0.5/32 >> "$PGDATA/pg_hba.conf"
# Example (local boundary test — proxy-host stand-in = ::1):
#   deploy/hba/render-hba.sh --proxy-cidr ::1/128 --auth scram-sha-256
# =====================================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/pg_hba.agent-boundary.conf.template"

AGENT_ROLE="${PGB_AGENT_ROLE:-pgb_agent}"
AGENT_DB="${PGB_AGENT_DB:-all}"
PROXY_CIDR="${PGB_PROXY_CIDR:-}"
AUTH="${PGB_AGENT_AUTH:-scram-sha-256}"

while [ $# -gt 0 ]; do
  case "$1" in
    --agent-role) AGENT_ROLE="$2"; shift 2 ;;
    --agent-db)   AGENT_DB="$2";   shift 2 ;;
    --proxy-cidr) PROXY_CIDR="$2"; shift 2 ;;
    --auth)       AUTH="$2";       shift 2 ;;
    *) echo "render-hba.sh: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

[ -f "$TEMPLATE" ] || { echo "render-hba.sh: missing template $TEMPLATE" >&2; exit 1; }
[ -n "$PROXY_CIDR" ] || { echo "render-hba.sh: --proxy-cidr (or PGB_PROXY_CIDR) is required" >&2; exit 2; }

# Plain literal substitution (no eval; values are config, not code).
sed \
  -e "s|@AGENT_ROLE@|${AGENT_ROLE}|g" \
  -e "s|@AGENT_DB@|${AGENT_DB}|g" \
  -e "s|@PROXY_CIDR@|${PROXY_CIDR}|g" \
  -e "s|@AUTH@|${AUTH}|g" \
  "$TEMPLATE"
