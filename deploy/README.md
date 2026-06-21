# `deploy/` — local dev stack & deployment assets (placeholder)

This directory will hold the local development and deployment assets for
pg_bumpers, per `docs/spec/SPEC.md` §3.

## What lands here next (issue #4)

- **`docker-compose.yml`** — the dev stack: Postgres **primary** + **replica** +
  a `_meta` **audit DB**, with the **replica** and **DBLab** behind compose
  **profiles** so the bare-primary baseline runs without them (SPEC §3, §12;
  process spec #1: "prove the bare-primary baseline").
- Role-hardening / `pg_hba` bootstrap for the **WALL** (issue #5, SPEC §3 layer 0–1).
- Seed/fixtures and teardown helpers for clone governance (SPEC §4: clones are
  prod-classified — encryption-at-rest, RLS/column-grant parity, mandatory
  teardown after dry-run).

## What is intentionally NOT here yet

S0's foundation issue (#3) does **not** build the compose — that is issue #4.
Integration/docker tests are gated behind an env var so the cargo CI stays fast,
but are run for real with evidence on the relevant PRs (process spec #1).

> Source of truth: `docs/spec/SPEC.md` (v0.8). License: Apache-2.0.
