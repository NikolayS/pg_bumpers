#!/usr/bin/env node
/**
 * License gate for the MCP server (mirror of the Rust `cargo deny` AGPL guard,
 * SPEC.md §4: Apache/MIT/BSD/ISC only — ban GPL/AGPL).
 *
 * Uses `pnpm licenses list --json`, which (unlike `license-checker` under
 * pnpm's symlinked store) walks the FULL transitive tree. Any package whose
 * SPDX license is not on the permissive allow-list fails the build. GPL / AGPL
 * / LGPL are never allowed — that is the whole point of this gate.
 */
import { execFileSync } from "node:child_process";

// Permissive licenses we accept. Apache/MIT/BSD/ISC are the policy set; the
// CC0-1.0 / CC-BY-3.0 entries cover SPDX *data* packages used by build tooling
// (spdx-exceptions, spdx-ranges) and are not copyleft code licenses.
const ALLOW = new Set([
  "Apache-2.0",
  "MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "0BSD",
  "CC0-1.0",
  "CC-BY-3.0",
  "(MIT AND CC-BY-3.0)",
  "Unlicense",
  "Python-2.0",
  "BlueOak-1.0.0",
]);

// Substrings that must NEVER appear in any dependency license (the AGPL guard).
const FORBIDDEN = ["GPL", "AGPL", "LGPL"];

function getLicenseTree() {
  const raw = execFileSync("pnpm", ["licenses", "list", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(raw);
}

const tree = getLicenseTree();
const violations = [];

for (const [license, packages] of Object.entries(tree)) {
  const upper = license.toUpperCase();
  const isForbidden = FORBIDDEN.some((f) => upper.includes(f));
  const isAllowed = ALLOW.has(license) && !isForbidden;
  if (!isAllowed) {
    const names = packages.map((p) => p.name ?? p).join(", ");
    violations.push(`  ${license}: ${names}`);
  }
}

if (violations.length > 0) {
  console.error("License check FAILED — disallowed licenses found:");
  console.error(violations.join("\n"));
  console.error(
    "\nOnly permissive licenses (Apache/MIT/BSD/ISC) are allowed; GPL/AGPL/LGPL are banned.",
  );
  process.exit(1);
}

console.log("License check OK — all dependency licenses are permissive (no GPL/AGPL).");
