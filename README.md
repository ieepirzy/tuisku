# Tuisku

Tuisku is an open-source intrusion-detection and agentic blue-team framework.
Deterministic sensors detect suspicious activity and preserve the evidence;
agents then investigate that evidence through controlled, audited tools, without
ever rewriting what the sensors observed. Released under the MIT license.

## Development quickstart

Requires [uv](https://docs.astral.sh/uv/) and Docker (or any Postgres 16).

```sh
docker compose up -d                       # dev-only Postgres on 127.0.0.1:55432
uv sync
export TUISKU_DATABASE_URL=postgresql://tuisku:tuisku-dev@127.0.0.1:55432/tuisku
uv run tuisku migrate                      # apply migrations (never done on API boot)
uv run tuisku api --port 8080              # GET /v1/health, GET /v1/ready

# tests create and drop their own database using this URL
TUISKU_TEST_DATABASE_URL=$TUISKU_DATABASE_URL uv run pytest -q -ra
```

See [AGENTS.md](AGENTS.md) for repository rules and `docs/adr/` for architecture
decisions.

## Sources, tokens and ingest

```sh
uv run tuisku source add edge-suricata --adapter suricata   # prints a tsk_src_ token once
uv run tuisku source token add edge-suricata --label rotation-2027
uv run tuisku source token list edge-suricata              # uids and dates, never secrets
uv run tuisku source token revoke edge-suricata <token-uid>
uv run tuisku source disable edge-suricata
uv run tuisku operator-token add --name oncall --role read  # prints a tsk_op_ token once
uv run tuisku operator-token list                          # uids, names, roles, never secrets
uv run tuisku operator-token revoke <token-uid>
# Out of band, connected as the database owner only (ADR 0005):
uv run tuisku approver add --person "A. Person"
uv run tuisku approver revoke <token-uid>
uv run tuisku operator-token add --name lead --role triage --person "A. Person"
```

Tokens are revoked, never deleted, so past actors stay resolvable; the API role has no `DELETE`
or `UPDATE` on `operator_tokens`. It revokes by inserting into the append-only
`operator_token_revocations`, which an owner trigger applies, so a revocation cannot be undone.
Revoking an approve token or a person-bound token, like issuing one, needs
the database owner.

Approve tokens and person-bound operator tokens can be issued only by the database owner; a
trigger refuses them for any other role, so the app role the API uses can never create them.

Only the SHA-256 of a token is stored; copy it when it is printed. Adapter options are
`--option key=value` (string) or `--option-json key=<json>`.

Shippers post NDJSON envelopes (`{"raw": "<line>", "collector": {...}}`) to
`POST /v1/sources/{source}/records`, or OTLP/HTTP JSON metrics to
`POST /v1/sources/{source}/otlp/v1/metrics`, with `Authorization: Bearer tsk_src_...`, plain or
`Content-Encoding: gzip`. Limits (ADR 0005) are settings: `TUISKU_INGEST_MAX_BODY_BYTES`
(5 MiB, on the wire and after decompression), `TUISKU_INGEST_MAX_LINES` (5000),
`TUISKU_INGEST_MAX_LINE_BYTES` (256 KiB), `TUISKU_INGEST_MAX_COLLECTOR_BYTES` (4 KiB). Only a
malformed envelope is `rejected`: an over-long record is stored truncated, flagged, unparsed
(`parse: skipped`), and an oversized `collector` is replaced by a marker. Every breach raises
one `tuisku.meta.*` detection per source, kind, subject (the limit) and 5-minute bucket;
repeats are counted in `meta_counters`. Buckets are slices of the database clock, and the
database accepts the API's meta-detections only for its own ingest kinds and the current bucket,
so a bucket cannot be claimed in advance.

Adapters run in a bounded pool of worker threads (`TUISKU_INGEST_PARSE_THREADS`). A request that
runs past `TUISKU_INGEST_REQUEST_BUDGET_SECONDS` (10 s) stops before its next line, commits
what it processed and answers 503 with `Retry-After`, marking the rest `not_processed`; the
shipper retries the batch, and the processed lines come back as duplicates. Each record's parse
also has its own deadline (`TUISKU_INGEST_PARSE_TIMEOUT_SECONDS`, 2 s). A parse that overruns
it is abandoned, because a Python thread cannot be killed: its thread runs on, but its slot is
released. The record stays accepted with a failed `time_budget` parse attempt and a
`parse_time` limit breach.

The per-source rate limit (`TUISKU_INGEST_RATE_PER_SECOND`, `TUISKU_INGEST_RATE_BURST`) is a
token bucket held **in each API replica's memory**: with N replicas a source can send up to
N times the configured rate. An exhausted bucket answers 429 with `Retry-After`. Refusals are
counted in process. The first refusal per source is recorded at once; the rest are written at
most every `TUISKU_INGEST_RATE_BREACH_FLUSH_SECONDS` (10 s) and at shutdown, never once per
refused request.

Operator tokens with the `read` role (or `triage`/`admin`) can read evidence:
`GET /v1/observations`, `GET /v1/detections` (filters `kind`, `source`, `entity_key`, `since`,
`until`; newest first, `limit` up to 500, next page with `before=<next_before>`; only rows of
each raw record's newest successful parse attempt unless `all_attempts=true`) and
`GET /v1/raw/{uid}` (metadata and the body as base64).

## Database roles

Evidence tables are append-only (ADR 0004). Run `tuisku migrate` as the owning role, the API as
a non-owning app role (`TUISKU_APP_ROLE`), and the rule worker as a separate worker role
(`TUISKU_WORKER_ROLE`, default `tuisku_worker`), both named when migrating:

```sh
# as a superuser, once:
#   CREATE ROLE tuisku_app LOGIN PASSWORD '...';
#   CREATE ROLE tuisku_worker LOGIN PASSWORD '...';
TUISKU_APP_ROLE=tuisku_app TUISKU_WORKER_ROLE=tuisku_worker \
  TUISKU_DATABASE_URL=<owner url> uv run tuisku migrate
TUISKU_DATABASE_URL=<tuisku_app url> uv run tuisku api
```

With `TUISKU_APP_ROLE` set, migrations grant the app role `SELECT` on evidence tables and
`INSERT` on those that ingest writes (`raw_records`, `raw_duplicates`, `parse_attempts`,
`observations`, `detections`, `detection_observations`). Triggers accept the API role's parse
attempts only for a raw record inserted in the same transaction, and its observations, sensor
detections and their links only for an attempt from that transaction. The API role therefore
cannot make a stored record's rows stale or attach rows to it. The migrations also grant it
`SELECT, INSERT` on `sources` and `source_tokens`, with no `UPDATE`: the API role can take no
row lock (which needs `UPDATE`) on anything the worker references. It disables a source or
revokes a token by inserting into the append-only `source_admin_requests` or
`token_revocations`, which an owner trigger applies at once. It records token use in its own
`source_token_usage` table. Renames go through the owner CLI, and each raw record keeps the
source name it arrived with in `source_name`. For `operator_tokens`, `sources` and
`source_tokens` the API role creates, a trigger sets `created_at` (and any `revoked_at` or
`disabled_at` given) to the database's `now()`. They grant `SELECT, INSERT` on
`operator_tokens`, `SELECT, INSERT` and column-level `UPDATE` on `meta_counters (count)`, the
API's own counters, and `INSERT (observation_id, detection_id, enqueued_at)` on `evaluation_queue` (a trigger accepts
only observations and detections inserted in the same transaction), plus `USAGE` on
sequences. A trigger sets each raw record's `source_name` from `sources`, whatever the writer
supplied. Only the worker role claims, updates or deletes queue rows, or touches
`evaluation_dead_letter`. No `tuisku_*` database function is executable by PUBLIC. Only the
read-only helpers `tuisku_is_worker()`, `tuisku_xmin_is_current()` and
`tuisku_current_bucket()` are granted to the runtime roles. Every trigger function refuses to
run on any table but its own, and PUBLIC has no `TEMP` on the database, so no role can attach
Tuisku's trigger functions to a table of its own. The migrating role must therefore own the
database, or the migration stops and asks for the `REVOKE TEMP` to be run by its owner. Operator
tokens can be created without a person (read, triage, admin) and only revoked afterwards.

Tuisku expects a database of its own. `REVOKE TEMP ON DATABASE ... FROM PUBLIC` applies to the
whole database, so any other application sharing it would lose temporary tables too. Two things
no grant can stop remain open to any role that can log in:

- **Large objects:** any role can call `lo_create()` and write large objects.
- **Unbounded writes:** a compromised API process can still insert evidence, and with it
  queue rows, as fast as Postgres accepts them.

Migrations also cap the app role (`TUISKU_APP_ROLE_CONNECTION_LIMIT`, 20) and set defaults
for its `statement_timeout` (30 s) and `idle_in_transaction_session_timeout` (60 s). A session
can override those timeouts, so they bound mistakes, not attacks. On Postgres 16 and later,
reserve slots for the worker so an exhausted pool cannot lock it out: set
`reserved_connections` (for example 3) and `GRANT pg_use_reserved_connections TO
tuisku_worker`. Give the database a disk quota, or at least disk alerts, sized to the retention
policy. The
worker's backlog check (`tuisku.meta.backlog`) pages when the queue or the notification outbox
falls behind.

The worker role alone writes rule output, so a compromised API process cannot forge it. Only the
worker role gets `INSERT` on `detection_evidence`. A trigger lets only the worker role insert
`tuisku`-evaluated detections and links to them. The one exception is the API's own bucketed
ingest meta-detections, whose identity is their kind.

Grants are made by the revision that creates each table, so set both variables before the first
`tuisku migrate`. For an existing database, run the same `GRANT` statements by hand. With
`TUISKU_APP_ROLE` unset no grants are made, and the owning role does everything; that suits
local development only. Independently of roles, triggers reject `UPDATE`, `DELETE` and
`TRUNCATE` on evidence tables for every role, owner included.
