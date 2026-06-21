#!/usr/bin/env bash
# scripts/build-site.sh
# Assemble the GitHub Pages site into site/.
# Output: site/index.html is byte-identical to docs/spec/brief.html.
# Run locally: bash scripts/build-site.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Building site from ${REPO_ROOT} ..."

rm -rf "${REPO_ROOT}/site"
mkdir -p "${REPO_ROOT}/site"

cp "${REPO_ROOT}/docs/spec/brief.html"    "${REPO_ROOT}/site/index.html"
cp "${REPO_ROOT}/docs/spec/SPEC.md"       "${REPO_ROOT}/site/SPEC.md"
cp "${REPO_ROOT}/docs/spec/decisions.md"  "${REPO_ROOT}/site/decisions.md"

touch "${REPO_ROOT}/site/.nojekyll"

echo "Site built:"
ls -lh "${REPO_ROOT}/site"
