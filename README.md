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
# Declarative, for deploy Jobs: create if absent, register the token held in $EDGE_TOKEN
uv run tuisku source ensure edge-suricata --adapter suricata --token-env EDGE_TOKEN
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

`tuisku source ensure NAME --adapter ADAPTER [--option ...] [--option-json ...] --token-env VAR
[--token-label LABEL]` lets a deployment generate a source's token itself (`tsk_src_` followed
by 43 URL-safe base64 characters, e.g. `"tsk_src_" + secrets.token_urlsafe(32)`) and keep it in
its own secret store. It is idempotent and safe to run on every deploy: it creates the source if
it is absent and registers the token in `VAR` if its SHA-256 is not registered yet, never prints
the token, and exits 0 when there is nothing to do. It never changes what exists: a source with
another adapter or other options (compared as JSON), a disabled source, and a token that is
revoked, expired or registered to another source are errors (exit 1), and a missing or malformed
token is a usage error (exit 2). Like `source add`, it needs `SELECT, INSERT` on `sources` and
`source_tokens`, which the app role has; it does not need the database owner.

Shippers post NDJSON envelopes (`{"raw": "<line>", "collector": {...}}`) to
`POST /v1/sources/{source}/records`, OTLP/HTTP JSON logs to
`POST /v1/sources/{source}/otlp/v1/logs`, or OTLP/HTTP JSON metrics to
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

On the OTLP logs endpoint each `logRecord` is one record, handled as one NDJSON line: its raw
record is `body.stringValue`, byte for byte, parsed by the source's adapter, and the line limits
apply per record (`TUISKU_INGEST_MAX_LINES` counts log records). A body of any other kind (say,
a `kvlistValue` made by a collector-side JSON parser) is `rejected` as `body_not_string`: ship
raw lines and let Tuisku parse them. The record's `collector` is the resource attributes merged
with its own attributes (the record's win), under their OpenTelemetry names (`k8s.node.name`,
`k8s.pod.name`, `log.file.path`, ...), plus `otlp.observed_time_unix_nano` and
`otlp.time_unix_nano` when set; like any `collector` it is receipt metadata that no adapter
reads, and the 4 KiB cap applies. A body that is not an OTLP/JSON logs request is 400. The answer
is an `ExportLogsServiceResponse`: `partialSuccess.rejectedLogRecords` counts rejected records,
and `results` lists every record's outcome. For the OpenTelemetry Collector, a `filelog`
receiver and an `otlphttp` exporter with `encoding: json`, `logs_endpoint` set to the URL above
and `headers: {Authorization: "Bearer ${env:TOKEN}"}` is enough. Keep its batches under the
body and record limits, because the Collector does not retry a 413, and keep its sending queue
and retries on: 429 and 503 are retried after `Retry-After`.

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

## Rules, findings and incidents

`tuisku worker` evaluates every new observation and detection against the rule packs (ADR 0006)
and folds firings into findings and incidents (ADR 0007). Run it as its own process, connected
as the worker role (ADR 0011); `--once` drains the queue and exits, `--check-packs` only
validates the packs.

```sh
uv run tuisku worker --check-packs          # load and validate packs/ plus configured paths
uv run tuisku worker                        # poll the evaluation queue
```

Packs are directories with a `pack.yaml` and `rules/*.yaml` (see `packs/` and ADR 0006). The
built-in packs (`harava`, `sensors-default`, `tuisku-meta`) ship generic defaults only, and only
they may declare `authorship: tuisku`. A deployment mounts
its own packs and params from its configuration repository:
`TUISKU_RULE_PACK_PATHS=/etc/tuisku/packs` (separated by `:`) and
`TUISKU_RULE_PARAMS_FILE=/etc/tuisku/params.yaml`, which maps pack ids to param overrides, e.g.
`harava: {restricted_callers: [agents, crawler]}`. Every pack's SHA-256 is recorded in
`pack_loads` and in each detection's explanation. Each rule ships positive and negative fixtures
in its pack's `fixtures/`, run through the real adapters by `tests/test_packs.py`.

Notifications go to an append-only outbox and are delivered after each evaluation commits;
each delivery or notifier failure appends to the append-only `notification_deliveries` log, so
one failing notification never blocks the others and none can be deleted unnoticed. A failed
delivery is retried after an exponential backoff from its last failure (5 s doubling, capped
at 5 minutes) and never dropped; after 10 failures a `tuisku.meta.notification_undeliverable`
meta-detection pages through `tuisku-meta` (route it to another channel). The only
notifier today writes one JSON line per notification to the `tuisku.notify` logger; routing
them to people is a deployment decision. A rule that fails 5 times on a row is dead-lettered and
pages (`evaluation_dead_lettered`), and `tuisku-meta` turns the resulting
`tuisku.meta.evaluation_failed` meta-detections into a finding that pages on every occurrence.

Operator tokens with `read` list `GET /v1/findings` and `GET /v1/incidents` (filters `status`,
`entity_key`, `rule_id` for findings; `before`/`limit` paging) and read
`GET /v1/incidents/{uid}` (timeline, findings, evidence summary). Tokens with `triage` post
`POST /v1/incidents/{uid}/status` (`{"status": "closed", "disposition": "false_positive"}`;
closing or resolving resolves the incident's open findings, so detection re-arms) and
`POST /v1/findings/{uid}/status` (`acknowledged`, `resolved`, `open`, or `suppressed` with
`suppressed_until` within 30 days and a `reason`). Every change is an event attributed to
`operator:<token uid>`.

Worker settings: `TUISKU_WORKER_BATCH_SIZE`, `TUISKU_WORKER_LEASE_SECONDS` (120),
`TUISKU_WORKER_POLL_SECONDS`, `TUISKU_WORKER_STATEMENT_TIMEOUT_SECONDS` (10),
`TUISKU_WORKER_MAX_OPEN_FINDINGS` (1000) and `TUISKU_WORKER_MAX_LIVE_INCIDENTS` (100), which
can only be lowered, `TUISKU_WORKER_EXPORT_INTERVAL_SECONDS` (60) and
`TUISKU_WORKER_ALLOWED_LATENESS_SECONDS` (86400). A queued row or undelivered notification older
than `TUISKU_WORKER_BACKLOG_SECONDS` (300) raises a `tuisku.meta.backlog` that pages at once.

## Export to an append-only sink

`tuisku worker` can export every finding and incident event (ADR 0012) at least once to an
append-only store, over OTLP/HTTP JSON logs, typically through an OpenTelemetry Collector:

- `TUISKU_EXPORT_OTLP_LOGS_URL`: the full URL, e.g. `http://collector:4318/v1/logs`. Unset (the
  default), export is disabled: the worker discards queued events older than
  `TUISKU_WORKER_BACKLOG_SECONDS` and nothing pages. Give every worker replica the same setting.
- `TUISKU_EXPORT_BATCH_SIZE` (100): records per POST; one POST per worker pass.
- `TUISKU_EXPORT_TIMEOUT_SECONDS` (10): the bound on one POST.
- `TUISKU_EXPORT_REDACT_ENTITY_KINDS` (`user,email`): entity keys of these kinds are exported as
  `<kind>:sha256:<hex of the value>`.

Each event is one log record (`service.name=tuisku`, `service.version` the build revision,
attributes `tuisku.stream` and `tuisku.record_uid`) whose body is a compact JSON
`tuisku.export.v1` record: the event and the finding or incident as the event's transaction
committed it. Free text a person typed, such as a triage reason, is exported only as its
SHA-256 and length. A non-2xx or a timeout leaves the events queued and retries with backoff (5 s
doubling to 5 minutes); an event still queued after `TUISKU_WORKER_BACKLOG_SECONDS` raises a
`tuisku.meta.backlog` (subject `export`) that pages. Consumers deduplicate on `record_uid`.
Events committed before the export migration are not exported.

## Database roles

Evidence tables are append-only (ADR 0004). Run `tuisku migrate` as the owning role, the API as
a non-owning app role (`TUISKU_APP_ROLE`), and `tuisku worker` as a separate worker role
(`TUISKU_WORKER_ROLE`, default `tuisku_worker`, ADR 0011), named when migrating:

```sh
# as a superuser, once:
#   CREATE ROLE tuisku_app LOGIN PASSWORD '...';
#   CREATE ROLE tuisku_worker LOGIN PASSWORD '...';
TUISKU_APP_ROLE=tuisku_app TUISKU_WORKER_ROLE=tuisku_worker \
  TUISKU_DATABASE_URL=<owner url> uv run tuisku migrate
TUISKU_DATABASE_URL=<tuisku_app url> uv run tuisku api
TUISKU_DATABASE_URL=<tuisku_worker url> uv run tuisku worker
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
`evaluation_dead_letter`. The export queue (`export_queue`, ADR 0012) is filled only by an owner
trigger (`SECURITY DEFINER`) at the commit of each finding or incident event; the worker role
has `SELECT` and `DELETE` on it and nothing else, and the API role has no privilege on it. No `tuisku_*` database function is executable by PUBLIC. Only the
read-only helpers `tuisku_is_worker()`, `tuisku_xmin_is_current()` and
`tuisku_current_bucket()` are granted to the runtime roles. Every trigger function refuses to
run on any table but its own, and PUBLIC has no `TEMP` on the database, so no role can attach
Tuisku's trigger functions to a table of its own. The migrating role must therefore own the
database, or the migration stops and asks for the `REVOKE TEMP` to be run by its owner. Operator
tokens can be created without a person (read, triage, admin) and only revoked afterwards. For
triage the API role gets `SELECT` on findings, incidents and their tables, and `INSERT` on the
append-only `triage_requests`, nothing more: no `UPDATE` on findings or incidents and no
events. An owner trigger applies each request with the triage rules (a live, unexpired operator
token with the triage role; a suppression at most 30 days from the finding's first suppression;
the incident transition table) and writes its event, or refuses it, and the API answers 404 or
409 as before. The request must come with the operator's bearer secret, which the API sets
for the transaction only and the trigger checks against the token's hash, so the API role
cannot triage as an operator whose token it has not seen. Statement logging can capture that secret:
`log_statement`, `log_min_duration_statement` and `auto_explain` with parameter logging may
write the `set_config` call with its value. Keep them off for the app role (as a superuser:
`ALTER ROLE tuisku_app SET log_statement = 'none'`, and no duration or auto_explain parameter
logging for it), or treat the server logs as secret. It cannot write notifications at all: the pages triage causes are written by
owner-defined triggers. ADR 0011 lists exactly what each role can
write.

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
policy. The worker's backlog check (`tuisku.meta.backlog`) pages when the queue or the
notification outbox falls behind. A stalled worker cannot page about itself, and a compromised API could fake any health
view it serves, so monitor the worker process directly: `tuisku worker --health-port 8081`
(or `TUISKU_WORKER_HEALTH_PORT`, bound to `TUISKU_WORKER_HEALTH_HOST`) answers any `GET` with
200 `{"status": "ok"}` while its last healthy pass is newer than
`TUISKU_WORKER_HEARTBEAT_STALE_SECONDS` (120), and 503 otherwise, without authentication and
with status only. Set `TUISKU_WORKER_DEADMAN_URL` to have the worker fetch a dead-man's-switch
URL after each healthy round. `GET /v1/worker/health` on the API is advisory and needs the
`read` role: it shows the heartbeat and the age of the oldest queued row and undelivered
notification (ADR 0011, "Availability limits").

Only the worker role writes rule output: `tuisku`-evaluated detections and their links,
`detection_evidence`, `rule_firings`, `findings`, `incidents`, `finding_detections`,
`incident_findings`, `finding_overflow_groups`, `pack_loads`, `notification_deliveries`,
`evaluation_attempts` and `evaluation_dead_letter_rules`, and events with `system` or `rule:`
actors. Triggers enforce the parts that share a table with ingest. A compromised API process
therefore cannot forge rule output or firing keys (ADR 0011). A firing key is also accepted
only for a row linked to its detection in the same transaction. The worker serializes itself
with row locks on the worker-only tables `worker_locks` and `group_locks`, never with advisory
locks, which any role could take. Its connection runs with `lock_timeout` and
`statement_timeout`, so a lock held elsewhere delays one step and never stalls a pass.

Triggers set the timestamps of the histories, link tables, firing keys, pack loads and
deliveries to the database clock. Grants for both roles are made by the revision that creates
each table, so set both variables before the first `tuisku migrate`. For an existing database, run the same `GRANT` statements by hand. With
`TUISKU_APP_ROLE` unset no grants are made, and the owning role does everything; that suits
local development only. Independently of roles, triggers reject `UPDATE`, `DELETE` and
`TRUNCATE` on evidence tables for every role, owner included.
