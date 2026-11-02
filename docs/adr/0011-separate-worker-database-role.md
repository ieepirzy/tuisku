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
  - `raw_records`, `raw_duplicates`, `parse_attempts`, `observations`: `INSERT`.
  - `detections`: `INSERT` of sensor detections. Of `tuisku`-evaluated rows, only its own
    ingest meta-detections: kinds `source_limit_exceeded`, `source_rate_limited` and
    `invalid_envelope`, with a source, identity equal to the kind, and the current 5-minute
    bucket by the database clock (a trigger).
  - `detection_observations`: `INSERT` of links to sensor detections only (a trigger).
  - `evaluation_queue`: `INSERT` only.
  - `meta_counters`: `SELECT`, `INSERT`, `UPDATE` (the breach-count upsert).
  - `sources`, `source_tokens`: full DML, for administration.
  - `operator_tokens`: `SELECT`, `INSERT`, `UPDATE`, never `DELETE`; person-bound and approve
    tokens stay owner-only (ADR 0005).
  - `findings`: `UPDATE` of the triage columns only (`status`, `suppressed_until`,
    `suppression_reason`, `suppressed_at`, `count_at_suppression`, `updated_at`).
  - `incidents`: `UPDATE` of `status`, `disposition` and `updated_at` only.
    For both tables a trigger refuses any other change and any update of a resolved, expired or
    closed row. It requires a matching operator event inserted in the same transaction. It sets
    a new suppression's start and count itself, and caps every suppression at 30 days from when
    it began.
  - `finding_events`, `incident_events`: `INSERT` with an `operator:` actor only (a trigger).
  - `notifications`: `INSERT` with the dedupe-key prefixes triage emits only
    (`operator_escalation:` and `triage_threshold:`) (a trigger).
- **What the API role cannot write**, at all: `detection_evidence`, `rule_firings`,
  `finding_detections`, `incident_findings`, `finding_overflow_groups`, `pack_loads`,
  `notification_deliveries`, `evaluation_dead_letter`, `evaluation_dead_letter_rules`,
  `evaluation_attempts`, new findings or incidents, rule detections, queue claims, updates or
  deletes, events with `system`, `rule:` or `investigator:` actors, worker notification keys
  (`finding_opened:`, `finding_threshold:`, `finding_occurrence`'s `finding_detection:` and
  `finding_link:`, `escalation:`, `incident_opened:`, `overflow_group:`, `dead_letter:` and the
  rest), and the worker's meta kinds (`evaluation_failed`, `notification_undeliverable`) in any
  bucket.
- **The worker role** writes all of the above that the API cannot. Its name is fixed in the
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
