# pg_bumpers — docs

Project documentation for **pg_bumpers** — a self-hostable control plane that lets
AI agents read and write **production Postgres** safely. These docs describe the
system **as it exists in the tree today** and flag clearly what is stubbed, in
progress, or fast-follow.

> **Source of truth.** The product spec is [`spec/SPEC.md`](spec/SPEC.md) (v0.8,
> build-frozen). Intentional deviations live in
> [`spec/SPEC.amendments.md`](spec/SPEC.amendments.md). These docs **link** to the
> spec — they never replace it.

## Status (single framing)

- **Merged & green on PG 18:** S0 (skeleton · WALL · `core`/contracts · fidelity
  gate), S1 (pgwire · audit · proxy), S2 (clone dry-run · governance).
- **In progress:** S3 (guarded apply + typed-inverse).
- **Upcoming / fast-follow:** S4 (warden · MCP · policy wiring · audit anchor ·
  read-gates · CLI approval), S5 (benchmark · marquee MCP-bypass repro), and the
  LLM gating engine. The MVP `RiskEngine` is a **stub returning `Allow`** — the
  **deterministic floor** is the safety guarantee, not any model.

## The guides

| Doc | What's in it |
|---|---|
| [`architecture.md`](architecture.md) | The four layers + the mandatory network boundary, the crate map (as built), read/write data flow, the local-PG18 substrate, graceful degradation, and the floor-vs-RiskEngine-stub posture. |
| [`quickstart.md`](quickstart.md) | Prerequisites (Rust 1.90, PG 18), build/test loop, the `deploy/local-stack.sh` dev substrate, and running the env-gated (`PG_BUMPERS_IT=1`) integration suites against real PG 18. |
| [`development.md`](development.md) | The engineering process: red/green TDD, the CI gates, the `PG_BUMPERS_IT` integration convention, test-port discipline, license hygiene, the pgDog clean-room rule, and the PR lifecycle. |
| [`components.md`](components.md) | A per-crate map of what exists today (`core`, `policy`, `pgwire`, `proxy`, `audit`, `clone-orchestrator`, the WALL SQL/hba, the MCP server, and the warden/cli stubs). |
| [`demo.md`](demo.md) | The marquee walkthrough, grounded in real tests: the no-`WHERE` `UPDATE` blast-radius preview (write-safety) and the `COMMIT; DROP SCHEMA` statement-stacking block + bounded-disclosure cutoff (read-safety). |

## The spec & decisions (source of truth — do not edit in feature PRs)

- [`spec/SPEC.md`](spec/SPEC.md) — the product spec (v0.8, build-frozen).
- [`spec/SPEC.amendments.md`](spec/SPEC.amendments.md) — recorded deviations (the docker→local-PG18 substrate pivot; the S1 proxy SCRAM/TLS/audit-sink decisions).
- [`spec/decisions.md`](spec/decisions.md) — decisions / rationale.
- [`spec/fidelity-spike-report.md`](spec/fidelity-spike-report.md) — the S0 fidelity-spike findings.
- [`spec/brief.md`](spec/brief.md) — the public brief.

## Elsewhere in the repo

- [`../README.md`](../README.md) — the project overview.
- [`../CLAUDE.md`](../CLAUDE.md) — engineering principles (red/green TDD · fail-closed · clean-room).
- [`../deploy/README.md`](../deploy/README.md) — the dev/test stack runbook.
