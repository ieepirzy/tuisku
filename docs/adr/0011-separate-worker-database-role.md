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
  default `tuisku_worker`). Neither owns the schema, and `tuisku migrate` grants both.
- **Only the worker writes rule output.** The worker role alone gets `INSERT` on `rule_firings`,
  `detection_evidence`, `finding_detections`, `incident_findings`, `finding_overflow_groups`,
  `pack_loads`, `notification_deliveries`, `findings` and `incidents`. Shared tables are guarded
  by triggers that compare `current_user` with the worker role, whose name is fixed in the
  trigger functions at migration time:
  - a detection with `evaluator = 'tuisku'` may be inserted only by the worker or the owner. The
    one exception is the API's own ingest meta-detections ([0005](0005-source-adapters-and-ingestion.md)),
    which are bucketed and have their kind as their identity, so they can never pass for rule
    output;
  - a `detection_observations` link to a `tuisku` detection may be inserted only by the worker;
  - a `finding_events` or `incident_events` row whose actor is not `operator:` may be inserted
    only by the worker.
- **The API keeps triage.** The app role keeps raw, observation and sensor-detection inserts and
  the queue. For triage it keeps `UPDATE` on findings and incidents, `INSERT` of operator events,
  and `INSERT` of notifications, which it needs for escalations.
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
- A compromised API can still triage, as operators can, and every such change is an attributed
  event. It can still add sensor evidence and ingest meta-detections. It can no longer write
  rule output, firing keys, links, findings or incidents, so it cannot silence a rule.
- A compromised worker can still forge rule output. Protecting against that needs the worker to
  sign its output, which is out of scope here.
