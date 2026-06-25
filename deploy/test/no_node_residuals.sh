#!/usr/bin/env bash
# pg_bumpers — Rust-only grep-acceptance gate (issue #101, spec v0.8.1 §0.5).
# =====================================================================================
# The implementation is **Rust-only**: NO Node.js / TypeScript / pnpm technology in
# tracked source, docs, CI, or the toolchain. The deployable MCP server is the native
# Rust `pgb-mcp` (crates/mcp, rmcp); the original non-Rust MCP server is gone.
#
# This gate FAILS (exit 1) if a Node.js / TypeScript / pnpm *technology* residual is
# reintroduced. It is intentionally aggressive: it catches not just the toolchain
# manifest tokens (`pnpm`, `tsconfig`, `node_modules`, …) but the realistic
# REINTRODUCTIONS this PR removes — a `node -e '…'`/`node build.js` invocation, a
# `Node 22` prereq line, a `.ts`/`.tsx` source ref, `ts-node`/`tsc`, the Node manifests
# /lockfiles (`package.json`, `package-lock.json`, `yarn.lock`), `@types/node`, and a
# boundary-anchored `npm`. A two-stage design keeps the gate honest:
#   1. a broad DETECTION regex ($TECH_TOKENS) flags every candidate line;
#   2. a benign-context ALLOWLIST ($ALLOWLIST_RE) + path excludes drop the small set of
#      legitimate non-Node.js uses (AST/query-plan "node(s)", `set_nodelay`, the
#      Tailscale "exit node", the EPIC #83 *historical* `.ts` filenames recorded in the
#      amendments/test docs, and this PR's OWN removal-documenting comments).
# A residual survives the allowlist ⇒ RED. The allowlist is context-scoped (not a blanket
# whole-file skip), so a REAL `node -e` newly dropped into an allowlisted file is still
# caught — see `--self-test` for the regression matrix that proves the teeth.
#
# SCOPE (tracked tree, by design): the gate scans the COMMITTED tree via `git grep`
# (untracked/build cruft is out of scope — `node_modules/`, `dist/` are never tracked).
# This is the right scope for CI: CI checks out the committed files, and any untracked
# residual is caught the moment it is committed. (`--worktree` is offered for local use
# to additionally scan unstaged working-tree changes before commit.)
#
# Exclusions (by design, see the issue Decisions):
#   - build artifacts (not tracked anyway) + the resolved `Cargo.lock` (a lockfile of
#     crate names, not a technology choice).
#   - this script itself (it must NAME the banned technology tokens to scan for them).
#   - the FROZEN docs/spec/SPEC.md, which STATES the Rust-only prohibition itself
#     ("NO Node/TypeScript … no pnpm/node in the toolchain or CI") — it must name the
#     banned technologies to forbid them, and is build-frozen (never edited in features).
#
# Usage:
#   no_node_residuals.sh            scan the committed tree (CI default)
#   no_node_residuals.sh --worktree scan committed + unstaged working-tree changes
#   no_node_residuals.sh --self-test  run the regression matrix (RED/GREEN teeth proof)
#
# Exit 0 (GREEN) when no residual survives the allowlist; exit 1 (RED) otherwise.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------------------
# (1) DETECTION — broad ERE matching every realistic Node.js/TS/pnpm residual class.
#     POSIX ERE (git grep -E): no `\b`; word boundaries are spelled `(^|[^[:alnum:]_])`.
# ---------------------------------------------------------------------------------------
# A `node` INVOCATION: `node` as a shell word (not a substring like `set_nodelay`, and
#   not `./node`-path-fragments), e.g. `node -e`, `node build.js`, `node  server.ts`.
NODE_INVOCATION='(^|[^[:alnum:]_./-])node[[:space:]]'
# A `Node <version>` prereq line, or the `Node.js` product name.
NODE_PRODUCT='Node[[:space:]][0-9]|Node\.js'
# TypeScript SOURCE refs: a `.ts`/`.tsx` file extension (followed by a delimiter or EOL),
#   plus the `ts-node` runner and the `tsc` compiler as a word.
TS_TOKENS='\.tsx?([[:space:]"'"'"'`),;:]|$)|ts-node|(^|[^[:alnum:]])tsc([^[:alnum:]]|$)'
# Node toolchain/package manifests + lockfiles + the Node typings package.
NODE_MANIFESTS='package\.json|package-lock\.json|yarn\.lock|@types/node'
# pnpm / TypeScript toolchain markers + the original token set.
TOOLCHAIN='pnpm|typescript|vitest|tsconfig|node_modules|nodejs'
# A boundary-anchored bare `npm` (no mandatory trailing space — catches EOL `npm`).
NPM_TOKEN='(^|[^[:alnum:]])npm([^[:alnum:]]|$)'

TECH_TOKENS="${NODE_INVOCATION}|${NODE_PRODUCT}|${TS_TOKENS}|${NODE_MANIFESTS}|${TOOLCHAIN}|${NPM_TOKEN}"

# ---------------------------------------------------------------------------------------
# (2) ALLOWLIST — benign-context filter dropping the legitimate non-Node.js matches so
#     the gate stays GREEN on the current tree, WITHOUT a blanket whole-file skip (a real
#     `node -e`/`node x.js` in any file still reds — see `--self-test`).
# ---------------------------------------------------------------------------------------
# Lines are presented to the filter as `path:lineno:content`. A line is BENIGN iff it
# matches a TRUSTED documentation clause (b/c/d, never overridden), OR it matches the
# PROSE heuristic (a) AND is not a HARD residual. What survives is a real residual ⇒ RED.
# The allowlist is split in two so the HARD-residual override (below) overrides ONLY the
# fuzzy prose heuristic, never the path-scoped trusted-documentation clauses:
#
# DOC_ALLOWLIST_RE — TRUSTED documentation contexts, path+wording scoped, never overridden:
#   (b) EPIC #83 *historical* `.ts` filenames in the amendments doc + Rust test comments;
#   (c) the Tailscale "exit node" (a network node);
#   (d) this PR's OWN removal-documenting comments naming the removed `node -e`
#       (crates/cli/{Cargo.toml,tests/keygen.rs}; keyed on removed/replacement/deleted).
DOC_ALLOWLIST_RE='(SPEC\.amendments\.md:[0-9]+:.*\.tsx?)|(crates/[^:]*/tests/[^:]*\.rs:[0-9]+:.*(deleted|//[/!]).*\.tsx?)|(:[0-9]+:.*exit[[:space:]]node)|(crates/cli/(Cargo\.toml|tests/keygen\.rs):[0-9]+:.*(removed|replacement|deleted).*node[[:space:]]-e)'
#
# PROSE_ALLOWLIST_RE — clause (a): AST / query-plan "node"/"nodes" used as prose — `node`
#   followed by whitespace and ANY non-dash char (a letter, markdown `*`/backtick, or a
#   non-ASCII `→` arrow; locale-independent). The only thing excluded here is a leading
#   `-` (a flag, e.g. `node -e`). This is a HEURISTIC, so it is OVERRIDDEN by
#   HARD_RESIDUAL_RE — a real `node x.js`/`node build.mjs` newly dropped into e.g.
#   predicate.rs is restored by the script-extension clause there.
PROSE_ALLOWLIST_RE=':[0-9]+:.*nodes?[[:space:]]+[^-[:space:]]'

# HARD RESIDUAL — a definite Node.js/TS residual that the PROSE heuristic may NEVER excuse.
# A line bearing a real flag/script/manifest/toolchain marker is a residual regardless of
# the prose clause. This stops a LIVE `node -e`/`node x.js`/`Node 22` slipping into an
# otherwise prose-allowlisted file. (Note: the trusted DOC clauses still apply first, so
# the documenting `node -e` comments in crates/cli stay benign.)
HARD_RESIDUAL_RE='node[[:space:]]+-|node[[:space:]]+[^[:space:]]*\.(js|mjs|cjs|tsx?)|\.tsx?([^[:alnum:]]|$)|Node[[:space:]][0-9]|Node\.js|nodejs|node_modules|pnpm|typescript|vitest|tsconfig|ts-node|package(-lock)?\.json|yarn\.lock|@types/node|(^|[^[:alnum:]])tsc([^[:alnum:]]|$)|(^|[^[:alnum:]])npm([^[:alnum:]]|$)'

# Files excluded wholesale from the scan (documented above).
EXCLUDES=(
  ':(exclude)Cargo.lock'
  ':(exclude)deploy/test/no_node_residuals.sh'
  ':(exclude)docs/spec/SPEC.md'
)

# scan_tree: emit (to stdout) every `path:lineno:content` residual that SURVIVES the
# allowlist. `$1` = "worktree" to also include unstaged working-tree changes.
scan_tree() {
  local mode="${1:-tracked}"
  local raw
  # `git grep -nIiE` over tracked files (default). `|| true`: grep exits 1 on no-match.
  raw="$(git grep -nIiE "$TECH_TOKENS" -- . "${EXCLUDES[@]}" || true)"
  if [ "$mode" = "worktree" ]; then
    # Additionally scan the unstaged working tree (catches not-yet-committed residuals).
    local wt
    wt="$(git grep --no-index -nIiE "$TECH_TOKENS" -- . \
            ':(exclude)Cargo.lock' \
            ':(exclude)deploy/test/no_node_residuals.sh' \
            ':(exclude)docs/spec/SPEC.md' \
            ':(exclude).git' 2>/dev/null || true)"
    raw="$(printf '%s\n%s\n' "$raw" "$wt" | sort -u | sed '/^$/d')"
  fi
  raw="$(printf '%s\n' "$raw" | sed '/^$/d')"
  # Stage 1: drop TRUSTED documentation lines (DOC clauses b/c/d) — unconditional.
  local after_doc not_prose prose_hard
  after_doc="$(printf '%s\n' "$raw" | grep -ivE "$DOC_ALLOWLIST_RE" || true)"
  # Stage 2a: of the rest, keep lines that do NOT match the PROSE heuristic (clause a).
  not_prose="$(printf '%s\n' "$after_doc" | grep -ivE "$PROSE_ALLOWLIST_RE" || true)"
  # Stage 2b: PROSE-allowlisted lines are excused ONLY if they are not HARD residuals;
  #   a HARD residual hiding behind the prose heuristic is restored.
  prose_hard="$(printf '%s\n' "$after_doc" | grep -iE "$PROSE_ALLOWLIST_RE" \
                  | grep -iE "$HARD_RESIDUAL_RE" || true)"
  printf '%s\n%s\n' "$not_prose" "$prose_hard" | sed '/^$/d' | sort -u
}

# -------------------------------------- self-test --------------------------------------
# `--self-test`: prove the gate has TEETH. For each realistic residual we append it to a
# tracked file, assert the gate goes RED (CAUGHT), then restore — and assert the clean
# tree is GREEN. Runs against a throwaway temp checkout so it never dirties the worktree.
SELFTEST_TMP=""
cleanup_self_test() { [ -n "${SELFTEST_TMP:-}" ] && rm -rf "$SELFTEST_TMP"; }

run_self_test() {
  echo "== no_node_residuals --self-test: regression matrix =="
  local tmp fail=0
  tmp="$(mktemp -d)"
  SELFTEST_TMP="$tmp"
  trap cleanup_self_test EXIT
  # Snapshot the committed tree into a temp git repo (so the gate's `git grep` works).
  git archive --format=tar HEAD | (cd "$tmp" && tar -xf -)
  ( cd "$tmp" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm base )
  cp "$0" "$tmp/deploy/test/no_node_residuals.sh"
  # `--allow-empty`: the cp above is byte-identical to the archived gate copy, so there is
  # nothing to commit; without this the empty `git commit` exits 1 and `set -Eeuo pipefail`
  # aborts the whole self-test before the case loop runs.
  ( cd "$tmp" && git add -A && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m gate )

  # The realistic residuals. Each is appended to a tracked file (default deploy/up.sh).
  # format: "label::residual-line::target-file"
  local cases=(
    "node -e in up.sh::node -e 'console.log(1)'::deploy/up.sh"
    "node build.js::node build.js::deploy/up.sh"
    "Node 22 prereq::Prereq: Node 22::README.md"
    "server.ts ref::see server.ts::README.md"
    ".ts source ref::import x from './x.ts'::README.md"
    "package.json::add a package.json::README.md"
    "package-lock.json::commit package-lock.json::README.md"
    "yarn.lock::commit yarn.lock::README.md"
    "ts-node::run ts-node main::README.md"
    "@types/node::dep @types/node::README.md"
    "tsc compiler::run tsc --noEmit::README.md"
    "npm at EOL::then run npm::README.md"
  )

  for c in "${cases[@]}"; do
    local label="${c%%::*}" rest="${c#*::}"
    local line="${rest%%::*}" file="${rest##*::}"
    ( cd "$tmp" && cp "$file" "$file.bak" && printf '\n%s\n' "$line" >> "$file" \
        && git add -A && git -c user.email=t@t -c user.name=t commit -qm "res: $label" )
    if ( cd "$tmp" && bash deploy/test/no_node_residuals.sh >/dev/null 2>&1 ); then
      printf '  [%-22s] FAIL — residual NOT caught (gate stayed GREEN)\n' "$label"; fail=1
    else
      printf '  [%-22s] CAUGHT (gate → exit 1)\n' "$label"
    fi
    ( cd "$tmp" && mv "$file.bak" "$file" \
        && git add -A && git -c user.email=t@t -c user.name=t commit -qm "restore: $label" )
  done

  # Clean tree must be GREEN.
  if ( cd "$tmp" && bash deploy/test/no_node_residuals.sh >/dev/null 2>&1 ); then
    printf '  [%-22s] GREEN (gate → exit 0)\n' "clean tree"
  else
    printf '  [%-22s] FAIL — clean tree is RED!\n' "clean tree"; fail=1
  fi

  echo
  if [ "$fail" -eq 0 ]; then
    echo "SELF-TEST PASSED: every residual CAUGHT, clean tree GREEN."
    return 0
  fi
  echo "SELF-TEST FAILED: see FAIL rows above." >&2
  return 1
}

# ------------------------------------------ main ---------------------------------------
MODE="tracked"
case "${1:-}" in
  --self-test) run_self_test; exit $? ;;
  --worktree)  MODE="worktree" ;;
  "" ) ;;
  * ) echo "usage: $0 [--worktree|--self-test]" >&2; exit 2 ;;
esac

echo "== no_node_residuals: scanning tracked files for Node.js/pnpm/TypeScript technology =="

residuals="$(scan_tree "$MODE")"

if [ -n "$residuals" ]; then
  echo "RED: Node.js/pnpm/TypeScript technology residual(s) found in tracked files:" >&2
  echo "$residuals" | sed 's/^/  /' >&2
  exit 1
fi

echo "GREEN: no Node.js/pnpm/TypeScript technology residual in tracked files."

# --- Reviewer aid: surface every remaining literal `node` word for confirmation -------
# These are the legitimate non-Node.js uses (plan/AST "node", `set_nodelay`, "exit node").
# Listed, never failed on — the reviewer confirms each is benign.
echo
echo "== remaining literal 'node' substrings (expected: legitimate non-Node.js uses only) =="
git grep -nIi 'node' -- . ':(exclude)Cargo.lock' || echo "  (none)"

exit 0
