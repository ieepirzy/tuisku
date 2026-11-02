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
on `operator_tokens`. Revoking an approve token or a person-bound token, like issuing one, needs
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
`observations`, `detections`, `detection_observations`). They also grant it
`SELECT, INSERT, UPDATE, DELETE` on `sources` and `source_tokens`, `SELECT, INSERT, UPDATE` on
`operator_tokens` and `meta_counters`, `INSERT` only on `evaluation_queue`, and `USAGE` on
sequences. Only the worker role claims, updates or deletes queue rows, or touches
`evaluation_dead_letter`.

The worker role alone writes rule output, so a compromised API process cannot forge it. Only the
worker role gets `INSERT` on `detection_evidence`. A trigger lets only the worker role insert
`tuisku`-evaluated detections and links to them. The one exception is the API's own bucketed
ingest meta-detections, whose identity is their kind.

Grants are made by the revision that creates each table, so set both variables before the first
`tuisku migrate`. For an existing database, run the same `GRANT` statements by hand. With
`TUISKU_APP_ROLE` unset no grants are made, and the owning role does everything; that suits
local development only. Independently of roles, triggers reject `UPDATE`, `DELETE` and
`TRUNCATE` on evidence tables for every role, owner included.
