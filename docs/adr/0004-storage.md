# 0004. Storage: Postgres, plain SQL, append-only evidence

Status: Accepted (2026-11-01)

## Context

The owner chose Python, FastAPI and Postgres with plain SQL (no ORM) and Alembic migrations.
The expected deployment gives Tuisku a dedicated Postgres database. Evidence must be immutable,
and that has to hold even against a compromised application process. Incidents, by contrast,
are mutable working objects that keep a history.

## Decision

1. **Postgres 16, accessed with psycopg 3** (async pool) and hand-written SQL. No ORM. Alembic
   manages migrations with raw `op.execute()` SQL, and SQLAlchemy is present only as Alembic's
   connection layer.
2. **Every migration declares `expand_only = True|False`.** An expand-only migration adds
   tables, nullable columns or indexes and nothing else, so an older image can still run against
   the newer schema. Migrations never run on API start. A separate `tuisku migrate` step runs
   them under an advisory lock.
3. **Roles enforce append-only, not just triggers.** Three roles have distinct jobs:
   - `tuisku_owner` owns the schema and is used only by `tuisku migrate`.
   - `tuisku_app` is used by the API and the worker. On evidence tables it has `SELECT` and
     `INSERT` only: no `UPDATE`, `DELETE` or `TRUNCATE`, and it does not own the tables, so it
     cannot disable triggers. On working tables (findings, incidents, the work queue) it has
     the privileges it needs.
   - Retention runs only through a `SECURITY DEFINER` function owned by `tuisku_owner`. That
     function enforces the holds (anything an open incident references is kept), clears raw
     bodies rather than deleting rows, and writes an append-only tombstone (row id, sha256,
     actor, time).

   Row and statement triggers that reject `UPDATE`, `DELETE` and `TRUNCATE` on evidence tables
   stay as a second line of defence. `tuisku_app` is never a member of `tuisku_owner`.
4. **Evidence tables** are the append-only ones: `raw_records`, `parse_attempts`,
   `raw_duplicates`, `observations`, `detections`, the link tables between them, and
   `incident_events`. Findings and incidents are mutable projections. Every incident change
   writes an `incident_events` row.
5. **Idempotent ingestion.** `raw_records` has `UNIQUE (source_id, sha256)`, where `sha256` is
   the digest of the UTF-8 bytes of the envelope's `raw` string. It does not cover the envelope
   itself, because `collector` metadata such as path or offset changes when a shipper re-reads a
   rotated file. A re-delivery inserts nothing and is reported as a duplicate. Each duplicate
   receipt is recorded in `raw_duplicates (raw_record_id, received_at)`, so a burst of
   byte-identical lines is visible as a count rather than lost. Sensors we target include a
   timestamp in every line (Harava logs carry millisecond time), so real events rarely collide.
6. **Two clocks on every derived row.** `event_time` comes from the sensor and may be wrong or
   hostile. `received_at` is Tuisku's own clock. A row whose `event_time` is more than a
   configured skew away from `received_at` is flagged `clock_skew`. Rules then evaluate it at
   `received_at` rather than skipping it, so a forged timestamp cannot hide an event. For
   fixture replay and backfill, the ingest path accepts an injected clock (tests and the
   `tuisku replay` command), so old fixtures keep their meaning.
7. **Columns for what queries need, JSONB for the rest.** Columns hold ids, `source_id`, `kind`,
   times, `severity_id`, `entity_keys text[]` (GIN-indexed) and `community_id`. The OCSF-shaped
   payload is `attributes jsonb`.
8. **Ids.**
   - internal `bigint` identity keys for joins
   - a `uid uuid` (v4) on every row for external reference
   - deterministic UUIDv5 ids only for exported STIX objects ([0008](0008-identifiers-and-interchange.md))
9. **Retention** is a configured policy per layer, for example raw bodies kept for N days.
   Anything an open incident references is held until the incident closes, plus N days.
   Retention is a prerequisite for ingesting user-traffic sources such as HTTP and DNS logs,
   which carry personal data. It must be configured before such a source is enabled in
   production; the first milestone's Harava source carries no URLs or values. Nothing above L0
   needs the L0 body to stay readable.
10. **Scale path, not built now:** monthly range partitioning of `raw_records` and `observations`
    by `received_at`, and moving cold L0 bodies to object storage by content hash. Both fit
    without changing ids.

## Consequences

- At-least-once shippers are safe to use.
- A compromised API process can add evidence but cannot rewrite or remove it.
- Tables grow fast, so partitioning and retention are known follow-ups.
- Without an ORM, the SQL in `tuisku.store` is the single place in code that holds schema
  knowledge, and tests run it against a real Postgres.
