# `proto/` — wire/IPC protocol definitions (placeholder)

This directory will hold the protocol/IDL definitions for pg_bumpers once the
internal protocols solidify, per `docs/spec/SPEC.md` §3.

## What lands here later

- The **warden ↔ proxy** authenticated circuit-breaker protocol (SPEC §3 layer 2,
  §4: "breaker state authenticated").
- The **MCP ↔ core** proposal/ticket contract surfaces that are not better
  expressed in the TS MCP server (SPEC §4).
- Any cross-process message schemas (e.g. audit anchoring hand-off) that need a
  language-neutral definition.

## What is intentionally NOT here yet

Nothing is generated or built from `proto/` in S0. IDL is added incrementally as
each protocol is designed and red/green-tested — we do not speculatively define
schemas before the consuming code exists.

> Source of truth: `docs/spec/SPEC.md` (v0.8). License: Apache-2.0.
