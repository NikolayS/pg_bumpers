# S0 fidelity-spike report — 🚦 THE GATE (issue #8)

> **Throwaway spike** (`spikes/fidelity`, `publish = false`). It red-tests the
> two riskiest assumptions of the whole product *in week 2, not week 10*
> (SPEC §5, §10.5): clone↔prod PK-set prediction fidelity, and typed-inverse
> restore of a golden prod state. **If this fails its binary pass criteria, the
> moat is invalid — STOP, do not start S1, escalate.** This report records the
> real-run verdict against live PostgreSQL.

## Verdict: **GATE PASS** against §10.5 (a), (b), (c)

All three binary pass criteria PASS, and all five drift tests behave exactly as
required (ABORT / REFUSED), running **for real** against PostgreSQL.

## Environment

- **PostgreSQL:** `PostgreSQL 18.4 (Homebrew)` — binaries at
  `/opt/homebrew/opt/postgresql@18/bin`.
- **Cluster:** throwaway, on **port 55431**, data dir `target/fidelity-pgdata/`
  (git-ignored via `/target/`). The founder's cluster on 5432 is untouched.
- **Driver:** `postgres = "0.19"` (sync client, MIT/Apache — `cargo deny` green).
- **Seams consumed (real merged `crates/core`):** `ApplyBarrier`
  (`NoopBarrier` for prod path, `ClosureBarrier` to inject drift at the
  `pause_point()` between dry-run and apply), `Clock`/`MockClock` (deterministic
  staleness/timing — no wall-clock in assertions), `PkSetBuilder`/`PkChecksum`
  (affected-PK-set checksum, single + composite tuples, PK-less refused),
  `InverseKind`/`InversePlan` (typed-inverse capture), `certify`/`RefusedOp`
  (default-deny certified action set).
- **Run command:**
  `PG_BUMPERS_IT=1 cargo test -p fidelity-spike -- --nocapture` (env-gated so the
  fast CI `cargo test` job skips the DB tests; the crate still compiles there).

## Seed (deterministic OLTP-ish schema → well-defined golden prod state)

- `public.orders(id PK int, customer, status, total_cents)` — 10 rows; `status`
  alternates `open`/`closed`, so the stable predicate `status = 'open'` matches a
  known PK set (ids `{2,4,6,8,10}`, 5 rows).
- `public.order_items(order_id, line_no, sku, qty, PRIMARY KEY(order_id,line_no))`
  — **composite PK**, FK to `orders(id)` **ON DELETE CASCADE** (the cascade
  path); 20 rows (2 per order).
- `public.order_audit` — written by an **AFTER UPDATE/DELETE trigger** on
  `orders` (the side-effect table; a documented unrestored gap).
- `public.ticket_seq` — a **sequence** (its advance is a documented unrestored
  gap).

Golden prod state = per-table content hashes (computed by Postgres itself, see
the independent differ below) + sequence `last_value` + trigger-side-effect row
count.

## §10.5 binary pass criteria — real numbers

### (a) Prediction exactness on a no-drift apply — **PASS**

| Quantity | Value |
| --- | --- |
| relation | `public.orders` |
| predicted `total_rows` | **5** |
| dry-run `pk_set_checksum` | `sha256:bec9ed2dc45f65ebdbd0e20cd5334c27b7dc0f4704c8498ee9b789b2bdf7ebe6` |
| apply-time checksum (recomputed in the apply txn) | `sha256:bec9ed2dc45f65ebdbd0e20cd5334c27b7dc0f4704c8498ee9b789b2bdf7ebe6` |
| actual rows (from `RETURNING`) | **5** |
| cascade composite-PK set (`order_items`) | 10 rows, `sha256:0358241f90c7ef0e87e9c76caa4d2f7e0f23c49231dd4304026333c0055f9d5e` |

Dry-run checksum **==** apply-time checksum (exact); predicted `total_rows` **==**
actual (delta **0**).

### (b) Typed-inverse restores the golden prod state — **PASS** (with documented gaps)

UPDATE inverse (`PREIMAGE_UPSERT`), 5 pre-image rows captured; the apply also
fires the audit trigger and we advanced the sequence to prove the gaps:

| State | `orders` md5 | `order_items` md5 | `ticket_seq.last_value` | audit rows |
| --- | --- | --- | --- | --- |
| golden | `ad7baca15fc42325a44cd1b32358c5d9` | `2301ad80c36aefde70bf33da3ec22e19` | 1000 | 0 |
| post-apply | `d965a3e6a39bb325f965bce9a8332511` | (unchanged) | 1002 | 5 |
| restored | `ad7baca15fc42325a44cd1b32358c5d9` | `2301ad80c36aefde70bf33da3ec22e19` | 1002 | 10 |

- Certified table rows (`orders` + `order_items`) restored **byte-for-byte**
  (golden md5 == restored md5).
- **Documented gaps asserted NOT restored:** sequence `last_value`
  (1000 → 1002, stays advanced) and trigger-audit side-effects (0 → 10, stay).
  `NOTIFY` is in the same documented-gap set (`NotRestored::NotifyDelivered`);
  a delivered NOTIFY cannot be recalled (asserted at the type level in core).

DELETE inverse (`INSERT`, FK-ordered) also PASSES: deleting the 5 open orders
cascades to 10 `order_items`; the inverse re-inserts 5 parents then 10 children
in FK order, restoring both tables byte-for-byte.

### (c) Staleness bound — **PASS**

Modeled via `pg_wal_lsn_diff` (WAL bytes between a captured snapshot LSN and the
current LSN); time advanced deterministically with `MockClock` (no wall-clock).

| Clone | `staleness_lsn_bytes` | ceiling (16 MiB) | verdict |
| --- | --- | --- | --- |
| fresh | 0 | 16,777,216 | accepted |
| after WAL burn | 25,687,440 | 16,777,216 | **REJECTED** |

A clone whose staleness exceeds the ceiling is rejected.

## Five drift tests (drift injected inside `ApplyBarrier::pause_point()`)

| Test | Mechanism | Required | Result |
| --- | --- | --- | --- |
| **T-drift-insert** | new matching row inserted post-snapshot (over-count) | ABORT | **ABORT** ✓ |
| **T-drift-delete-shrink** | matching row deleted post-snapshot (under-count) | ABORT | **ABORT** ✓ |
| **T-drift-predicate-flip** (headline) | one row flipped out, one flipped in — **same count (5), different PK set** | ABORT | **ABORT** ✓ |
| **T-drift-trigger-amplification** | trigger added post-snapshot; its migration shifts a row into the predicate, amplifying the footprint | ABORT | **ABORT** ✓ |
| **T-nondeterministic-predicate** | volatile (`now()`/`random()`) op | REFUSED, never applied | **REFUSED**, DB untouched ✓ |

The **predicate-flip** test explicitly proves the count-only blind spot: after
the flip the matching-row count is still **5**, so a row-count guard would have
passed it; the PK-set checksum guard ABORTs because the *set of PKs* changed.

## Independent differ (avoids circularity — SPEC §10.6)

The restore-equality check uses `differ::` (in `spikes/fidelity/src/differ.rs`),
which **shares no code with the inverse under test**: it fingerprints table state
by asking **Postgres itself** to hash each table's full ordered contents
(`md5(string_agg(row::text, … ORDER BY …))`) and reads the sequence/audit scalars
directly via SQL. It does not touch `PkSetBuilder`, `InversePlan`, or the harness
apply path, so a bug shared between capture and restore cannot mask itself. The
differ confirms certified-row equality **and** reports the sequence/trigger
scalars separately so the gate asserts they are NOT restored.

## Honest limitations of this guard (not a gate failure — documented)

- The apply-time checksum is recomputed on the predicate **before** the forward
  op, inside the apply txn. A post-snapshot trigger that fires *during* the
  forward op and touches rows **outside** the predicate is not visible to a
  pre-op-only guard; the trigger-amplification test models the catchable case
  (the migration that adds the trigger also shifts a row into the predicate).
  A production guard should additionally verify the actual written set
  (e.g. via `RETURNING`) against the prediction — noted for S3.
- Sequences, trigger side-effects, and delivered `NOTIFY` are **out of scope by
  design** for the typed inverse (SPEC §10.3) and are asserted as gaps, not
  restored.
- This is a spike: a single integer-PK table + one composite-PK cascade child,
  certified `UPDATE`/`DELETE` only. It is enough to exercise the §10.5 gate
  honestly; broader op/type coverage is S3 work.

## Conclusion

**GATE PASS.** Clone↔prod PK-set prediction is exact under no-drift and ABORTs on
every modeled drift (including the count-blind predicate flip); the typed inverse
restores the golden prod state byte-for-byte for the certified op set, with the
sequence/trigger/NOTIFY gaps documented and asserted. The moat assumptions hold
against real PostgreSQL 18.4. S1 may proceed (pending manager confirmation).
