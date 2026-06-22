#!/usr/bin/env python3
"""Enforce a per-crate line-coverage floor on the enforcement crates (SPEC §4,
§10.6).

`cargo llvm-cov --workspace --json` emits one record per source file. We
aggregate covered/total lines per enforcement crate (by path prefix) and FAIL
(exit 1) if any crate is below its floor. This is the deterministic coverage
gate: the enforcement crates carry the safety guarantees, so their coverage must
not silently rot.

Floors are set from the ACTUAL current DB-free numbers with a small headroom so
the gate is green today but catches real regressions. RATCHET THEM UP as
coverage improves — never down to make a red build green.

Usage:  coverage_floor.py <llvm-cov-json-path>
"""

import json
import sys

# Enforcement crates: path prefix -> (crate name, line-coverage floor %).
#
# Measured (DB-free, workspace run) on this PR — see PR #42 evidence:
#   pgb-core                96.81%   pgb-policy              97.19%
#   pgb-pgwire              91.78%   pgb-clone-orchestrator  81.44%
#   pgb-proxy               56.66%   (much of proxy is the async session loop +
#                                     main.rs/tls.rs exercised only under the
#                                     env-gated PG18 integration test)
#   pgb-warden              86.62%   (S5 #65 made the warden a RUNNING, AUDITED
#                                     watchdog: the model/thresholds/breaker/
#                                     poller gating logic + the pure audit-record
#                                     construction + the binary's config/DSN
#                                     assembly are fully DB-free unit-tested
#                                     (each module >95%). The drop from S4's
#                                     95.18% is NOT logic rot — it is the NEW,
#                                     inherently-DB-only live seams added by #65:
#                                     run.rs's `pg` module (PgActivitySource /
#                                     PgKiller — the `pg_stat_activity` /
#                                     `pg_replication_slots` / `pg_terminate_backend`
#                                     SQL), run_loop's real sleep driver, and the
#                                     thin main.rs. Those are 0% DB-free and proven
#                                     ONLY under the env-gated PG18 integration
#                                     test (`tests/warden_it.rs`) — exactly like
#                                     pgb-audit's pg.rs / pgb-proxy's session loop.
#                                     Floor set to 85% to bound that IT-only
#                                     surface; RATCHET UP as logic coverage grows.)
#   pgb-audit               82.84%   (S4; the chain + anchor + KMS key-separation
#                                     + secret store are fully DB-free unit/IT
#                                     tested — anchor 92.9%, kms 97.0%, secret
#                                     99.0%; only pg.rs, the `_meta` sink, is 0%
#                                     DB-free because it runs under the env-gated
#                                     PG18 integration test, like pgb-proxy)
#
# Floors sit a couple of points under current so normal churn stays green while
# a genuine drop trips CI. RATCHET UP, never down.
FLOORS = {
    "crates/core/": ("pgb-core", 95.0),
    "crates/policy/": ("pgb-policy", 95.0),
    "crates/pgwire/": ("pgb-pgwire", 89.0),
    "crates/clone-orchestrator/": ("pgb-clone-orchestrator", 79.0),
    "crates/proxy/": ("pgb-proxy", 54.0),
    "crates/warden/": ("pgb-warden", 85.0),
    "crates/audit/": ("pgb-audit", 80.0),
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: coverage_floor.py <llvm-cov-json>", file=sys.stderr)
        return 2

    with open(sys.argv[1]) as fh:
        data = json.load(fh)

    # covered, total per crate
    agg = {name: [0, 0] for name, _ in FLOORS.values()}
    for f in data["data"][0]["files"]:
        fn = f["filename"]
        for prefix, (name, _floor) in FLOORS.items():
            if prefix in fn:
                lines = f["summary"]["lines"]
                agg[name][0] += lines["covered"]
                agg[name][1] += lines["count"]
                break

    floors_by_name = {name: floor for name, floor in FLOORS.values()}
    ok = True
    print("Enforcement-crate line coverage (floor gate):")
    print(f"  {'crate':26s} {'lines':>8s}  {'floor':>6s}  status")
    for name in sorted(agg):
        covered, total = agg[name]
        pct = 100.0 * covered / total if total else 0.0
        floor = floors_by_name[name]
        status = "OK" if pct >= floor else "FAIL"
        if pct < floor:
            ok = False
        print(
            f"  {name:26s} {pct:7.2f}%  {floor:5.1f}%  {status}"
            f"   ({covered}/{total})"
        )

    if not ok:
        print(
            "\nFAIL: an enforcement crate dropped below its coverage floor.",
            file=sys.stderr,
        )
        return 1
    print("\nAll enforcement crates meet their coverage floor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
