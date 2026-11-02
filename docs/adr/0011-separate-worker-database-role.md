# 0011. Separate worker database role

Status: Accepted (2026-11-02). Amends [0004](0004-storage.md) section 3.

## Context

ADR 0004 gives the API and the worker one app role, `tuisku_app`. That role could insert
`tuisku`-evaluated detections, `rule_firings`, `detection_evidence` and the finding and incident
link tables, because the worker needs them.

The worker skips a row for a rule once a firing key exists for it, which is how firings stay
idempotent ([0006](0006-detection-rules-and-correlation.md)). Review found two ways for the app
role to forge such a key and so hide a page:

1. insert a throwaway rule detection, then a `row` key for the victim row;
2. append a `detection_evidence` row tying an old rule detection to the victim, then a `member`
   key.

The API faces the network and parses attacker-controlled input, so it is the most likely
component to be compromised. A compromised API must be able to add evidence, but it must not be
able to forge rule output or firing keys.

## Decision

- **Two runtime roles.** The API (ingest, read and triage) connects as the app role
  (`TUISKU_APP_ROLE`). `tuisku worker` connects as a separate worker role (`TUISKU_WORKER_ROLE`,
  default `tuisku_worker`). Neither owns the schema, and `tuisku migrate` grants both. Both are
  built into revisions 0001 and 0002, which had not been merged or deployed, so both revisions
  stay expand-only.
- **What the API role can write**, and nothing else:
  - `raw_records`, `raw_duplicates`: `INSERT`. Each raw record stores the source name it
    arrived with (`source_name`), set by a trigger from `sources` whatever the writer supplies,
    and rules match on that name.
  - `parse_attempts`, `observations`: `INSERT` only together with their record (a trigger):
    an attempt only for a raw record inserted in the same transaction, and an observation only
    for an attempt of the same raw record from the same transaction. So the API role cannot
    supersede a stored record's derivation and make its rows stale.
  - `detections`: `INSERT` of sensor detections, under the same same-transaction rule as
    observations. Of `tuisku`-evaluated rows, only its own
    ingest meta-detections: kinds `source_limit_exceeded`, `source_rate_limited` and
    `invalid_envelope`, with a source, identity equal to the kind, and the current 5-minute
    bucket by the database clock (a trigger).
  - `detection_observations`: `INSERT` only of links between a sensor detection and an
    observation of the same parse attempt, both from the same transaction (a trigger).
  - `evaluation_queue`: `INSERT` of `observation_id`, `detection_id` and `enqueued_at` only,
    and only for an observation or detection inserted in the same transaction (a trigger).
  - `meta_counters`: `SELECT`, `INSERT`, `UPDATE` (the breach-count upsert).
  - `sources`: `SELECT`, `INSERT`, `UPDATE (disabled_at)`. `source_tokens`: `SELECT`,
    `INSERT`, `UPDATE (revoked_at, last_used_at)`. Neither can be deleted, and sources are
    renamed only by the owner.
  - `operator_tokens`: `SELECT`, `INSERT` of tokens without a person (read, triage, admin;
    person-bound and approve tokens stay owner-only, ADR 0005), `UPDATE (revoked_at)` only,
    never `DELETE`.
  - `findings`: `UPDATE` of the triage columns only (`status`, `suppressed_until`,
    `suppression_reason`, `suppressed_at`, `count_at_suppression`, `updated_at`).
  - `incidents`: `UPDATE` of `status`, `disposition` and `updated_at` only.
    For both tables a trigger refuses any other change and any update of a resolved, expired or
    closed row. It requires a matching operator event inserted in the same transaction. Triage
    may set a finding only to `open`, `acknowledged`, `resolved` or `suppressed`, never
    `expired`. The trigger sets a suppression's count itself. It caps every suppression at
    30 days from the finding's first suppression, so a lift and re-suppress does not restart the
    clock.
  - `finding_events`, `incident_events`: `INSERT` only with an `operator:<uid>` actor naming a
    live operator token (not revoked, not expired, holding `triage` or `admin`), and only
    triage kinds (`status_changed` and `suppressed`
    for findings; `status_changed`, `reopened` and `note` for incidents) (a trigger).
  - `notifications`: nothing. The pages triage causes are written by owner triggers running as
    `SECURITY DEFINER`, whoever made the change: a finding leaving `suppressed` (to `open`,
    `acknowledged` or `resolved`, directly or through its incident being closed or resolved)
    pages every threshold crossed meanwhile, and an incident reopened pages an escalation.
    `notifications.created_at` is the database clock for every role.
- **What the API role cannot write**, at all: `detection_evidence`, `rule_firings`,
  `finding_detections`, `incident_findings`, `finding_overflow_groups`, `pack_loads`,
  `notification_deliveries`, `evaluation_dead_letter`, `evaluation_dead_letter_rules`,
  `evaluation_attempts`, `notifications`, new findings or incidents, rule detections, queue
  claims, updates or deletes, events with `system`, `rule:` or `investigator:` actors or
  non-triage kinds, and the worker's meta kinds (`evaluation_failed`,
  `notification_undeliverable`, `backlog`) in any bucket.
- **Functions and temporary tables.** No `tuisku_*` function is executable by PUBLIC. Firing a
  trigger needs no `EXECUTE`. Only the read-only helpers `tuisku_is_worker()`,
  `tuisku_xmin_is_current()` and `tuisku_current_bucket()` are granted, to both runtime roles.
  Every trigger function checks `TG_RELID`, `TG_WHEN`, `TG_OP` and `TG_LEVEL`, and refuses to
  run anywhere but on its own table. PUBLIC has no `TEMP` on the database, and the migration
  stops if a runtime role still has it. So no role can attach a Tuisku trigger function,
  least of all a `SECURITY DEFINER` pager, to a table of its own.
- **Delivery order.** The drain delivers the most severe notification first, then the oldest,
  so a backlog of lesser pages never holds back a newer high-severity one.
- **The worker role** writes all of the above that the API cannot. A queued row whose parse
  attempt was superseded is never dropped as stale: no reprocessing run exists yet, so the
  worker raises a `tuisku.meta.evaluation_failed` (subject `superseded_derivation`) and
  evaluates the row anyway. On every pass the worker also checks its own health: a queued row
  or an undelivered notification older than `TUISKU_WORKER_BACKLOG_SECONDS` (5 minutes) raises
  a `tuisku.meta.backlog`. That backlog pages at once, through a notification an owner trigger
  writes, and through the `tuisku-meta` pack. Its name is fixed in the
  trigger functions at migration time, like the grants.
- **Second line of defence.** A firing key of any kind is accepted only when its detection is
  rule output of the key's rule, and is linked to the key's row by a link inserted in the same
  transaction. A link row whose inserting transaction is still in progress, and which the session
  can see, can only be the session's own. So even the worker role cannot reuse old links to mark
  a row done.
- In single-role development setups (`TUISKU_APP_ROLE` unset), the owner does everything, as
  before.

## Consequences

- A deployment creates two login roles instead of one, and points `TUISKU_DATABASE_URL` for
  `tuisku worker` at the worker role.
- A compromised API can still triage, as operators can. Every such change is an attributed
  operator event, and every suppression ends within 30 days. It can still add sensor evidence
  and current-bucket ingest meta-detections, and it can still enqueue rows. It can no longer
  write rule output, firing keys, links, findings or incidents. It cannot drop, park or delete
  queue rows, pre-claim a worker notification or meta-detection slot, or rewrite a finding
  silently, so it cannot silence a rule.
- A compromised worker can still forge rule output. Protecting against that needs the worker to
  sign its output, which is out of scope here.
