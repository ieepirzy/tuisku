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
   - Retention runs only through one `SECURITY DEFINER` function, `tuisku_apply_retention()`,
     owned by `tuisku_owner`.
     - **Inputs:** it takes no parameters. The policy, meaning the retention period per layer,
       comes from a table that only `tuisku_owner` can write.
     - **Access:** `EXECUTE` is revoked from `PUBLIC` and granted only to a `tuisku_retention`
       role. The app role is not a member of that role. The function pins `search_path`.
     - **What it does:** it records `session_user` as the actor. Past their retention periods,
       it clears raw bodies and redacts L1/L2 payloads (`attributes`, `unmapped`,
       `explanation`) instead of deleting rows. Each time, it writes an append-only tombstone:
       row id, sha256, actor and time.
     - **Holds:** it touches nothing in the transitive evidence closure of an incident whose
       status is not `closed`. The same applies to a finding that is not `resolved` or
       `expired`.
     - **Trigger exception:** the evidence-table triggers allow exactly one change, setting
       those payload columns to NULL, and only when `current_user = 'tuisku_owner'`.

   Row and statement triggers that reject `UPDATE`, `DELETE` and `TRUNCATE` on evidence tables
   stay as a second line of defence. `tuisku_app` is never a member of `tuisku_owner`.
4. **Evidence tables** are the append-only ones:
   - `raw_records`, `parse_attempts` and `raw_duplicates`
   - `observations`, `detections`, and the link tables between them (including
     `detection_evidence`)
   - the histories: `finding_events` and `incident_events`
   - later, the L4 tables (`hypotheses`, `investigator_sessions`, `tool_calls`,
     `proposed_actions`)

   Findings and incidents are mutable projections. Every change to one writes a
   `finding_events` or `incident_events` row.
5. **Idempotent ingestion.** `raw_records` has `UNIQUE (source_id, sha256)`. For NDJSON records,
   `sha256` is the digest of the UTF-8 bytes of the envelope's `raw` string. For OTLP, it is the
   digest of the request body bytes. It does not cover the envelope
   itself, because `collector` metadata such as path or offset changes when a shipper re-reads a
   rotated file. A re-delivery inserts nothing and is reported as a duplicate. Each duplicate
   receipt is recorded in `raw_duplicates (raw_record_id, received_at)`, so a burst of
   byte-identical lines is visible as a count rather than lost. Sensors we target include a
   timestamp in every line (Harava logs carry millisecond time), so real events rarely collide.
6. **Two clocks on every derived row.**
   - `event_time` comes from the sensor and may be wrong or hostile. `received_at` is Tuisku's
     own clock.
   - A row whose `event_time` lies in the *future* by more than a configured tolerance is
     flagged `clock_skew`. Rules evaluate that row at `received_at` instead of skipping it, so a
     forged timestamp cannot hide an event.
   - Rows that arrive *late* are handled by the lateness rules in
     [0006](0006-detection-rules-and-correlation.md).
   - For fixture replay and backfill, the ingest path accepts an injected clock (used by tests
     and the `tuisku replay` command), so old fixtures keep their meaning.
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
