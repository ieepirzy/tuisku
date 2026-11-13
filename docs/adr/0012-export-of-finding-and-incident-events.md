# 0012. Export of finding and incident events to an append-only sink

Status: Accepted (2026-11-13)

## Context

The incident timeline is the audit log ([0007](0007-findings-and-incidents.md)), and the
histories `finding_events` and `incident_events` are append-only in Tuisku's database
([0004](0004-storage.md)). That still leaves them inside one database: whoever controls it (a
superuser, a compromised owner, a lost volume) controls the only copy of what Tuisku concluded
and what operators did about it. Deployments that keep an audit trail want a copy of every
event in a store Tuisku cannot change or delete afterwards, such as object storage with a
retention lock, written through a log pipeline they already run.

That destination may have to hold no personal data at all. Finding and incident events carry
some: entity keys such as user names, and free text an operator typed (a triage reason).

The usual transport for such a pipeline is OpenTelemetry: an OpenTelemetry Collector with an
OTLP/HTTP logs receiver, processors, and an exporter to the store.

## Decision

### What is exported

Every row of `finding_events` and `incident_events` committed after revision 0003, once each
and at least once, as one OTLP log record over OTLP/HTTP JSON to
`TUISKU_EXPORT_OTLP_LOGS_URL` (a full URL, such as `http://collector:4318/v1/logs`). Events
committed before the migration are not backfilled: a backfill is a data migration, and with
export disabled by default it would only be discarded. A deployment that needs them reads them
from the database.

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
commit. Each queue row holds a snapshot (`state`) of the finding or incident as the event's
transaction committed it. Tuisku often writes the event just before the update it records, so
an immediate trigger would snapshot the state before the change. A transaction that writes
several events for the same finding gives each of them the same, final snapshot. A session may
`SET CONSTRAINTS ... IMMEDIATE`; that only moves the snapshot earlier, the event is still
enqueued. The snapshot also makes a resend byte-for-byte the same record.

The trigger only reads and inserts, and falls back to an empty snapshot rather than raising, so
export can never block evaluation or triage.

### Roles

The queue is a working table, not evidence: the evidence stays in the event tables, which are
append-only. Within the role model of [0011](0011-separate-worker-database-role.md):

- The API role gets nothing on the queue: no `SELECT`, `INSERT`, `DELETE` or lock. Its triage
  events are enqueued by the owner trigger.
- The worker role gets `SELECT` and `DELETE` on the queue and nothing else: no `INSERT`,
  `UPDATE`, `TRUNCATE` or sequence. Delivery backoff therefore lives in the worker's memory.
  Exporters serialize on a row of the existing worker-only `worker_locks` table (`export`), as
  the notification drain does.
- The trigger function `tuisku_enqueue_export()` is owned by the migrating role, refuses to
  run on any table but `finding_events` and `incident_events`, and PUBLIC has no `EXECUTE` on
  it.

A compromised worker can delete queue rows unsent. It can already forge rule output (0011);
the events themselves stay in the database, and the sink's consumers can compare the event
uids they hold with the database's.

### The record, `tuisku.export.v1`

The OTLP log record's `body.stringValue` is one compact JSON object (keys sorted):

```json
{"schema": "tuisku.export.v1", "record_uid": "<event uid>", "stream": "finding",
 "event": {"uid": "...", "at": "2026-11-01T09:30:00.123456Z", "actor": "rule:<id>@<rev>",
           "kind": "opened", "old_value": null, "new_value": {"status": "open", "severity_id": 4},
           "payload": {"detection_uid": "..."}, "reason_sha256": null, "reason_length": null},
 "finding": {"uid": "...", "rule_id": "...", "rule_rev": 1, "rule_name": "...", "pack_id": "...",
             "pack_version": "...", "pack_sha256": "...", "overflow": false, "title": "...",
             "severity_id": 4, "status": "open", "count": 1, "entity_keys": ["..."],
             "first_seen_at": "...", "last_seen_at": "...", "suppressed_until": null,
             "incident_uid": "...", "updated_at": "..."},
 "exporter": {"service": "tuisku", "build_revision": "<TUISKU_BUILD_REVISION>"}}
```

An incident event has `"stream": "incident"` and an `incident` object instead: `uid`, `title`,
`severity_id`, `status`, `disposition`, `rule_id`, `rule_rev`, `overflow`, `entity_keys`,
`finding_count`, `opened_at`, `updated_at`, `previous_incident_uid`. Incident events have no
old or new values (`null`). `record_uid` is the event's uid: consumers deduplicate on it.

**No personal data by construction:**

- **Free text a person typed is never exported raw.** An event's reason (the `reason` column of
  a finding event, `payload.reason` of an incident event) becomes `reason_sha256` (hex SHA-256 of
  its UTF-8) and `reason_length` (in characters). In payloads and old or new values, only keys
  known to hold structured values (ids, enums, numbers, times; the list is `STRUCTURED_KEYS` in
  `tuisku.worker.export`) pass as they are. Any other key's text or nested value becomes
  `{"sha256": ..., "length": ...}`, so a field added later (an operator note, L4 text) cannot
  leak until it is reviewed and listed.
- **Entity keys** are telemetry-derived. Keys whose kind (the part before the first `:`) is in
  `TUISKU_EXPORT_REDACT_ENTITY_KINDS` (default `user,email`) become
  `<kind>:sha256:<hex of the value>`. This is pseudonymization, not anonymization: an unsalted
  hash of a guessable value can be reversed by guessing. A deployment whose store must hold no
  identifiers at all lists more kinds (`ip`, `host`, `caller`, ...).
- **Titles** come from rule packs (the rule's title, or `Overflow: <title>`), never from
  telemetry: rules have no templating (0006).
- Left out entirely: `group_values` and `explanation` (telemetry-derived values), a finding's
  `suppression_reason` (typed text; its event carries the digest), L0 bodies and any
  observation or detection content.

### The OTLP envelope

One `ExportLogsServiceRequest` per batch: one `resourceLogs` whose resource attributes are
`service.name = tuisku` and `service.version = <build revision>`, one `scopeLogs` (scope
`tuisku.export`), and one `logRecord` per event:

- `timeUnixNano`: the event's `at`;
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

The export runs in the worker loop as one step after the notification drain:

- **Bounded:** at most one batch (`TUISKU_EXPORT_BATCH_SIZE`, 100) per pass, one POST, bounded in
  total by `TUISKU_EXPORT_TIMEOUT_SECONDS` (10). The POST runs in a thread, off the event loop;
  a thread that overruns is abandoned and ends at its socket timeout.
- **Isolated:** any error in the step is logged and backs off; it never stops evaluation or the
  drain. Lock and statement timeouts skip the step like any other (0011).
- **At least once:** rows are deleted only after a 2xx, in the transaction that read them. A
  non-2xx, a timeout, a connection error or a redirect leaves them queued, and the next try waits
  5 s, doubling to at most 5 minutes. A crash between the POST and the delete sends the batch
  again; the records are identical.
- An OTLP partial success (`partialSuccess.rejectedLogRecords` in a 2xx answer) is not retried,
  as OTLP requires: the sink refused those records for good. It is logged as an error.
- **Backlog:** an export row older than `TUISKU_WORKER_BACKLOG_SECONDS` (by the database clock,
  which set `enqueued_at`) raises the existing `tuisku.meta.backlog` meta-detection with subject
  `export`. It pages at once through the owner trigger `tuisku_page_backlog`, and the
  `tuisku-meta` backlog rule groups it by subject, as for the evaluation queue and the outbox.
  The database's allowlists need no change: they restrict the API role's meta kinds, and
  `backlog` is the worker's.

### Export disabled

`TUISKU_EXPORT_OTLP_LOGS_URL` unset (the default) disables export. The triggers still enqueue,
because the database cannot know the worker's settings without a grant the worker should not
have. The worker discards queued rows older than `TUISKU_WORKER_BACKLOG_SECONDS`, at most 1000
per pass, and never runs the export backlog check. So the queue holds at most a few minutes of
events, and nothing pages. Rows younger than that are left alone, so during a rollout a replica
with export enabled still sends them. Every worker replica must have the same export settings:
a disabled replica discards what an enabled one could not send within the backlog limit.

## Consequences

- A deployment gets a copy of every finding and incident event outside Tuisku's database,
  through a pipeline it already operates, with no personal data unless it chooses to keep some
  entity kinds.
- Each event write costs one queue insert at commit. The queue is a working table that the
  worker empties.
- Records arrive at least once and roughly in commit order, not in event order: consumers
  deduplicate on `record_uid` and order by `event.at`.
- The sink's own durability (retention lock, replication) is the deployment's to configure;
  Tuisku's guarantee ends at the 2xx.
- Revision 0003 adds a trigger function, triggers on existing tables and grants, so it is not
  expand-only by the migration-safety convention, although an older image runs unchanged on it.
