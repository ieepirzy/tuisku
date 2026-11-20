# 0012. Export of finding and incident events to an append-only sink

Status: Accepted (2026-11-13; revised 2026-11-20 after review)

## Context

The incident timeline is the audit log ([0007](0007-findings-and-incidents.md)), and the
histories `finding_events` and `incident_events` are append-only in Tuisku's database
([0004](0004-storage.md)). That still leaves them inside one database: whoever controls it (a
superuser, a compromised owner, a lost volume) controls the only copy of what Tuisku concluded
and what operators did about it. Deployments that keep an audit trail want a copy of every
event in a store Tuisku cannot change or delete afterwards, such as object storage with a
retention lock, written through a log pipeline they already run.

Such a store is immutable, so whatever personal data reaches it stays for its whole retention.
Finding and incident events carry some: entity keys built from telemetry (IP addresses, caller
and identity names) and free text an operator typed (a triage reason).
[0008](0008-identifiers-and-interchange.md) already decides how exports treat that: "IP,
identity and caller entity keys are pseudonymised by default", as HMAC-SHA-256 under a
deployment-held key with the type prefix kept (`ip:hmac:…`).

The usual transport for such a pipeline is OpenTelemetry: an OpenTelemetry Collector with an
OTLP/HTTP logs receiver, processors, and an exporter to the store.

## Decision

### What is exported

While export is on, every row of `finding_events` and `incident_events` is exported at least
once, as one OTLP log record over OTLP/HTTP JSON to `TUISKU_EXPORT_OTLP_LOGS_URL` (a full URL,
such as `http://collector:4318/v1/logs`). Events committed while export is off, or before
revision 0004, are not exported: a backfill is a data migration, and a deployment that needs
older events reads them from the database.

### On and off: a flag the owner sets

Whether events are enqueued is decided in the database, by the one-row table `export_state`,
which only the owner writes. `tuisku migrate` sets it on every run: on when its environment has
`TUISKU_EXPORT_OTLP_LOGS_URL`, off otherwise. Off is the default, and then the trigger writes
nothing, so a deployment without export pays no queue writes and no vacuum churn.

The flag lives in the database, not in the worker's settings, because only the database can
make the decision in the same transaction as the event, and the worker role should not hold a
grant to change it. The two can disagree, and both directions are caught:

- **The worker exports, the database does not enqueue** (migrate ran without the URL): the
  worker raises `tuisku.meta.export_failed` (subject `not_enqueued`), which pages, and logs the
  remedy.
- **The database enqueues, a worker does not export** (no URL on that replica, or a rollback):
  that worker leaves the queue alone, because another replica may be exporting, and once a row is
  older than `TUISKU_WORKER_BACKLOG_SECONDS` the backlog check pages (`tuisku.meta.backlog`,
  subject `export`). It never discards what is meant to be exported.

With export off in both places, a worker deletes rows left from when it was on (at most 1000 per
round) and nothing pages.

### A queue filled by trigger, not an id cursor

An owner-defined `SECURITY DEFINER` trigger on both event tables inserts one `export_queue` row
per event, in the event's own transaction. The worker drains the queue: it reads a batch in id
order, sends it, and deletes exactly the rows it sent after a 2xx.

A cursor ("export every event with an id above the last one exported") would be simpler and
wrong. Identity values are handed out when a row is inserted, not when its transaction commits.
A transaction that takes id 41 and commits after one that took id 42 has been exported is
skipped for good. Long triage requests, lock waits and retried evaluations make that ordinary,
not rare. With the queue, an event exists for the exporter exactly when it is committed, and
it stays until it has been acknowledged; the order in which transactions commit does not
matter (`tests/test_export.py` commits a lower id late and checks it is still sent).

The trigger is a deferred constraint trigger (`DEFERRABLE INITIALLY DEFERRED`), so it runs at
commit. Each queue row holds the event (`event`) and a snapshot (`state`) of the finding or
incident as the event's transaction committed them. Tuisku often writes the event just before
the update it records, so an immediate trigger would snapshot the state before the change. A
transaction that writes several events for the same finding gives each of them the same, final
snapshot. A session may `SET CONSTRAINTS ... IMMEDIATE`; that only moves the snapshot earlier,
the event is still enqueued. The snapshot also makes a resend byte-for-byte the same record.

The database renders every time in the snapshot as RFC 3339 UTC text
(`tuisku_export_time()`), whatever the session's `TimeZone`; a value outside what RFC 3339 or
Python can hold (`-infinity`, a BC date) is carried as text (`-infinity`, `... BC`). The
exporter never parses a time, so no stored value can make a record unencodable. The trigger only
reads and inserts, and falls back to an empty snapshot rather than raising, so export can never
block evaluation or triage.

### Roles

The queue is a working table, not evidence: the evidence stays in the event tables, which are
append-only. Within the role model of [0011](0011-separate-worker-database-role.md):

- The API role gets nothing on the queue or on `export_state`: no `SELECT`, `INSERT`, `DELETE`
  or lock. Its triage events are enqueued by the owner trigger.
- The worker role gets `SELECT` and `DELETE` on the queue and `SELECT` on `export_state`, and
  nothing else: no `INSERT`, `UPDATE`, `TRUNCATE` or sequence. Delivery backoff therefore lives
  in the worker's memory. Exporters take turns through a lease on the existing worker-only
  `worker_locks` row `export` (two new nullable columns, `holder` and `lease_until`; the row is
  seeded by the migration), which the worker could already update.
- The functions `tuisku_enqueue_export()`, `tuisku_export_time()` and
  `tuisku_check_triage_expiry()` are owned by the migrating role; PUBLIC and the runtime roles
  have no `EXECUTE` on them. The two trigger functions refuse to run on any table but their own.

A compromised worker can delete queue rows unsent. It can already forge rule output (0011);
the events themselves stay in the database, and the sink's consumers can compare the event
uids they hold with the database's.

### The record, `tuisku.export.v1`

The OTLP log record's `body.stringValue` is one compact JSON object (keys sorted):

```json
{"schema": "tuisku.export.v1", "record_uid": "<event uid>", "stream": "finding",
 "event": {"uid": "...", "at": "2026-11-01T09:30:00.123456Z", "actor": "rule:<id>@<rev>",
           "kind": "opened", "old_value": null, "new_value": {"status": "open", "severity_id": 4},
           "payload": {"detection_uid": "..."}, "reason_hmac": null, "reason_length": null},
 "finding": {"uid": "...", "rule_id": "...", "rule_rev": 1, "rule_name": "...", "pack_id": "...",
             "pack_version": "...", "pack_sha256": "...", "overflow": false, "title": "...",
             "severity_id": 4, "status": "open", "count": 1,
             "entity_keys": ["caller:hmac:<hex>", "host:node-a"],
             "first_seen_at": "...", "last_seen_at": "...", "suppressed_until": null,
             "incident_uid": "...", "updated_at": "..."},
 "exporter": {"service": "tuisku", "build_revision": "<TUISKU_BUILD_REVISION>"}}
```

An incident event has `"stream": "incident"` and an `incident` object instead: `uid`, `title`,
`severity_id`, `status`, `disposition`, `rule_id`, `rule_rev`, `overflow`, `entity_keys`,
`finding_count`, `opened_at`, `updated_at`, `previous_incident_uid`. Incident events have no
old or new values (`null`). `record_uid` is the event's uid: consumers deduplicate on it.

A row that still cannot be encoded, or that the sink refuses on its own, is sent as a **stub**
in its place: `schema`, `record_uid`, `stream`, `error` (`unencodable: <type>` or
`refused: HTTP <status>`), `event` (`uid`, `at`, `kind`) and `exporter`. The gap is then visible
in the sink as well as paged.

### Personal data: pseudonymised, not removed

Export needs `TUISKU_EXPORT_PSEUDONYM_KEY`, a secret of at least 32 characters (and at least 8
distinct ones) that the deployment holds; the worker refuses to start with an export URL and no
key. Under that key, as ADR 0008 decides:

- **Entity keys** whose kind (the part before the first `:`) is in
  `TUISKU_EXPORT_PSEUDONYMIZE_ENTITY_KINDS` (default `ip,caller,identity`) become
  `<kind>:hmac:<hex HMAC-SHA-256 of the value after the first ':'>`. Without the key, an address
  cannot be recovered by enumerating the IPv4 space, as an unsalted SHA-256 could be. With it,
  the same value gives the same pseudonym, so correlation inside the estate still works.
- **Kinds left raw by default:**
  - `host`, `k8s`, `k8s-ns` and `image` name the estate's own machines, workloads and images,
    which an audit trail needs readable to be useful;
  - `process` (`<host>/<pid>/<start>`) names nothing beyond its host;
  - `domain`, `sha256` and the like are indicators, not people.

  A deployment whose naming carries people (a pod or host per user, for example) adds those
  kinds to the setting.
- **Free text a person typed is never exported raw.** An event's reason (the `reason` column of
  a finding event, `payload.reason` of an incident event) becomes `reason_hmac` (the same HMAC)
  and `reason_length` (in characters). In payloads and old or new values, only keys known to
  hold structured values (ids, enums, numbers, times; the list is `STRUCTURED_KEYS` in
  `tuisku.worker.export`) pass as they are. Any other key's text or nested value becomes
  `{"hmac": ..., "length": ...}`, so a field added later (an operator note, L4 text) cannot
  leak until it is reviewed and listed.
- **Titles** come from rule packs (the rule's title, or `Overflow: <title>`), never from
  telemetry: rules have no templating (0006).
- Left out entirely: `group_values` and `explanation` (telemetry-derived values), a finding's
  `suppression_reason` (typed text; its event carries the HMAC), L0 bodies and any observation
  or detection content.

So the sink holds pseudonymous personal data, not none: whoever holds the key can test a guess
(is this pseudonym `ip:192.0.2.1`?), and the kinds left raw are only as impersonal as the
estate's naming. The key must be kept apart from the sink, and rotating it breaks correlation
across the rotation.

### The OTLP envelope

One `ExportLogsServiceRequest` per batch: one `resourceLogs` whose resource attributes are
`service.name = tuisku` and `service.version = <build revision>`, one `scopeLogs` (scope
`tuisku.export`), and one `logRecord` per event:

- `timeUnixNano`: the event's `at` (computed by the database; `0` if out of range);
- `severityNumber` and `severityText`, from the finding's or incident's `severity_id`:

  | severity_id | severityText | severityNumber |
  |---|---|---|
  | 0 | Unknown | 0 (UNSPECIFIED) |
  | 1 | Informational | 9 (INFO) |
  | 2 | Low | 13 (WARN) |
  | 3 | Medium | 14 (WARN2) |
  | 4 | High | 17 (ERROR) |
  | 5 | Critical | 21 (FATAL) |
  | 6 | Fatal | 22 (FATAL2) |

- attributes `tuisku.stream` (`finding` or `incident`), `tuisku.record_uid` and
  `tuisku.schema` (`tuisku.export.v1`);
- `body.stringValue`: the record.

### Delivery

The exporter is an asyncio task of `tuisku worker` with a database connection of its own, beside
the evaluation loop, so a slow sink never delays evaluation, the notification drain or the
worker's health.

- **Rounds and the lease:** a round takes the `export` lease (`timeout + 30 s`, renewed after
  every batch, released at the end), then sends batches of `TUISKU_EXPORT_BATCH_SIZE` (100)
  until the queue is empty or 30 s have passed, and starts the next round at once while rows
  remain. Each request is bounded by `TUISKU_EXPORT_TIMEOUT_SECONDS` (10) and runs in a thread,
  off the event loop. No transaction is open during a request: the batch is read, posted, and
  then deleted in a statement of its own. A holder that dies loses the lease when it expires.
- **At least once:** rows are deleted only after a 2xx. A crash between the POST and the delete,
  or a lease that expires mid-request, sends the batch again; the records are identical.
- **Failures:** a 5xx, 429, 401, 403, 404 or other non-2xx, a timeout, a connection error or a
  redirect leaves the rows queued. The next try waits 5 s, doubling to at most 5 minutes. The
  backoff is in the process's memory: it starts from zero after a restart, and resets once the
  queue is empty. Persistent failure pages through the backlog check.
- **A 400 or 413** means the sink refuses the content, so resending it cannot help: the batch is
  halved, down to one record. A record still refused on its own is replaced by a stub; if the
  stub is refused too, the row is dropped. Either way `tuisku.meta.export_failed` (subject
  `refused`) pages, and the rows behind it go on.
- **OTLP partial success** (`partialSuccess.rejectedLogRecords` in a 2xx answer) is not retried,
  as OTLP requires: the sink refused those records for good, and the response does not say
  which. The batch's rows are deleted, and `tuisku.meta.export_failed` (subject
  `partial_success`, with the count) pages.
- **Backlog:** an export row older than `TUISKU_WORKER_BACKLOG_SECONDS` (by the database clock,
  which set `enqueued_at`) raises the existing `tuisku.meta.backlog` meta-detection with subject
  `export`. It pages at once through the owner trigger `tuisku_page_backlog`, and the
  `tuisku-meta` backlog rule groups it by subject.
- **`tuisku.meta.export_failed`** is a worker meta kind like `backlog`: one per subject and
  5-minute bucket, written by the worker. Its details carry the first occurrence in the bucket
  (the count, the queue id), and later ones in the same bucket are only logged. The
  `tuisku-meta` pack's `export_failed` rule pages on every one. The database's meta allowlists
  need no change: they restrict the API role's own ingest kinds, and the worker may write any
  `tuisku.meta.*` kind.

So the guarantee is at least once for every event the database enqueued, **except** records
that the sink itself refuses for good (a partial success, or a record and its stub both
refused). Those are lost to the sink, never silently: each loss pages, and the events stay in
the database.

### Transport

- The URL must not carry credentials (urllib cannot use them, and they would reach name
  resolution): a sink that needs one gets it as a header from
  `TUISKU_EXPORT_OTLP_HEADERS_JSON` (a JSON object of strings, held as a secret). Headers are
  refused with an `http://` URL, so a secret never travels in clear text; an in-cluster sink
  reached over plain HTTP relies on network policy instead.
- Environment proxies (`HTTP_PROXY` and the like) are ignored: records go straight to the sink.
- Redirects are failures, so records never go anywhere but the configured URL.

### Triage cannot store a suppression that never ends

Review found that triage checked only the upper bound of a suppression's expiry, so the API
role, with an operator secret it had seen, could suppress until `-infinity`. Revision 0004 adds a
`BEFORE INSERT` check on `triage_requests` (`tuisku_check_triage_expiry()`): the expiry must be
a finite time after the database's `now()`. `tuisku_apply_triage` from revision 0002 is left as
it is, with every check it has; the API already checks the same bounds with its own clock.

### Rollback

Revision 0004 is not expand-only by the convention, so an automatic rollback across it is refused
and a person decides. An image from before export does not drain the queue and does not know to
page about it. Before rolling back to such an image with export on, turn export off: run
`tuisku migrate` from the current image without `TUISKU_EXPORT_OTLP_LOGS_URL`, which clears the
flag, so the triggers stop writing. Rows already queued then wait, bounded, until a newer worker
discards or exports them.

## Consequences

- A deployment gets a copy of every finding and incident event outside Tuisku's database,
  through a pipeline it already operates, with IPs, callers, identities and typed text
  pseudonymised under its own key.
- With export on, each event write costs one queue insert at commit; with it off, nothing. The
  queue is a working table that the worker empties.
- Records arrive at least once and roughly in commit order, not in event order: consumers
  deduplicate on `record_uid` and order by `event.at`.
- The sink's own durability (retention lock, replication) is the deployment's to configure;
  Tuisku's guarantee ends at the 2xx.
- `tuisku migrate` needs the export URL in its environment whenever the worker has it.
