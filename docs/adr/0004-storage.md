# 0004. Storage: Postgres, plain SQL, append-only evidence

Status: Accepted (2026-11-01)

## Context

The owner chose Python, FastAPI and Postgres with plain SQL (no ORM) and Alembic migrations. The
expected deployment gives Tuisku a dedicated Postgres database. Evidence must be immutable;
incidents are mutable working objects with a history.

## Decision

1. **Postgres 16, accessed with psycopg 3** (async pool) and hand-written SQL. No ORM. Alembic
   manages migrations with raw `op.execute()` SQL; SQLAlchemy is present only as Alembic's
   connection layer.
2. **Every migration declares `expand_only = True|False`.** Expand-only migrations add tables,
   nullable columns or indexes and nothing else, so an older image can still run against the
   newer schema. Migrations never run on API start; a separate `tuisku migrate` step does, under
   an advisory lock.
3. **Evidence tables are append-only**: `raw_records`, `observations`, `detections`, and the link
   tables that connect them. A database trigger rejects `UPDATE` and `DELETE` on them, except
   for the retention job, which runs under a dedicated role. Findings and incidents are mutable,
   and every change to an incident writes an append-only `incident_events` row (the timeline).
4. **Idempotent ingestion.** `raw_records` has `UNIQUE (source_id, sha256)`, where `sha256` is
   the digest of the exact bytes received. Re-delivery (at-least-once shippers, replays after a
   crash, file rotation) inserts nothing and is reported as a duplicate. Deliberately repeated
   identical lines from one source are therefore collapsed; sources whose lines can legitimately
   repeat must include a distinguishing field (a timestamp, offset or sequence), which every
   sensor we target does.
5. **Two clocks on every derived row:** `event_time` (from the sensor, may be wrong or hostile)
   and `received_at` (Tuisku's clock). Rules use `event_time` within a bounded skew of
   `received_at`; records whose `event_time` is implausibly far from `received_at` are flagged.
6. **Shapes that queries need get columns; the rest stays JSONB.** Columns: ids, `source_id`,
   `kind`, times, `severity_id`, `entity_keys text[]` (GIN-indexed), `community_id`. The
   OCSF-shaped payload is `attributes jsonb`.
7. **Ids:** internal `bigint` identity keys for joins; a `uid uuid` on every row for external
   reference; deterministic UUIDv5 ids for entities and indicators
   ([0008](0008-identifiers-and-interchange.md)).
8. **Retention** is a configured policy per layer (raw records kept N days; anything referenced
   by an open incident is kept until the incident closes plus N days). It is not built in the
   first milestone, but the schema keeps it possible: nothing above L0 needs L0's body to stay
   readable.
9. **Scale path, not built now:** monthly range partitioning of `raw_records` and `observations`
   by `received_at`; moving cold L0 bodies to object storage by content hash. Both fit the
   schema without changing ids.

## Consequences

- At-least-once shippers are safe to use.
- Tables grow fast; partitioning and retention are known follow-ups.
- Without an ORM, the SQL in `tuisku.store` is the single place schema knowledge lives in code;
  tests run it against a real Postgres.
