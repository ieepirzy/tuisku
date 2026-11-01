# 0007. Findings, incidents and their lifecycle

Status: Accepted (2026-11-01)

## Context

Detections are many and noisy. People and investigators need fewer, durable objects to work
with. Issue #1 says incidents are first-class investigations, "not transient alert blobs". An
incident has a timeline, entities, evidence, hypotheses, human decisions, proposed and executed
actions, and an outcome.

Existing systems handle this in a few ways:

- TheHive deduplicates alerts on `(type, source, sourceRef)` and merges them into cases.
- Elastic suppresses alerts by group-by fields within a window.
- OCSF has Detection Finding (2004), with `first_seen_time`, `last_seen_time` and `count`, and
  Incident Finding (2005).

Grouping keys are built from attacker-controlled values, so the grouping itself can be attacked.

## Decision

### Findings (deduplicated, deterministic)

- Findings are created only by pack rules ([0006](0006-detection-rules-and-correlation.md)).
  Sensor detections reach findings through a pack rule that selects them. That rule's
  `finding.group_by` decides how they split: the built-in default packs group sensor detections
  by `identity` plus the main entity, so different Suricata signatures do not merge.
- The **fingerprint** is the SHA-256 of the RFC 8785 (JCS) canonical JSON array
  `["finding", <rule id>, <rule rev>, [<group_by values in order>]]`. Canonical encoding means an
  attacker-chosen value cannot move field boundaries and collide with another group.
- **Attach or open.** A new firing for a fingerprint attaches to the existing finding only if
  all of these hold:
  - the finding is not `resolved`
  - its `last_seen` is within `window`
  - its `first_seen` is within `max_lifetime`

  Otherwise a new finding opens. Without the lifetime cap, a trickle of benign matches could
  keep one finding open forever and absorb later real activity.
- **Attaching** increments `count`, moves `last_seen`, which is the evaluation time of the
  newest row, and links the detection in `finding_detections`. The underlying detections are
  never merged or deleted.
- **Fields:**
  - `uid` and `fingerprint`
  - `title`
  - `severity_id`: the maximum of the finding's detections
  - `status`: `open | acknowledged | resolved | suppressed`
  - `first_seen`, `last_seen` and `count`
  - `entity_keys`: the union across detections
  - `rule_ref`
  - `explanation`: from the first detection, plus the latest correlation values
- **Suppressed** findings keep collecting evidence but trigger no notifications until their
  suppression expires. Suppression always has an expiry and a recorded reason.
- **Notifications** fire:
  - when a finding opens
  - when its `count` crosses 10, 100 and 1000
  - when its severity rises
- **Status mapping to OCSF `status_id`:**

  | Tuisku status | OCSF `status_id` |
  |---|---|
  | open | New |
  | acknowledged | In Progress |
  | suppressed | Suppressed |
  | resolved | Resolved |

### Incidents (durable investigations)

- **Opening.** An incident is opened either by a rule with `incident: open` (its fingerprint is
  the rule's finding fingerprint) or by an operator (a random fingerprint).
- **Uniqueness.** A partial unique index on `(fingerprint) WHERE status <> 'closed'` guarantees
  at most one live incident per fingerprint. A later finding with that fingerprint attaches to
  the live incident.
- **States:** `open → triaged → investigating → contained → resolved → closed`. Allowed
  transitions are listed in code and in tests:
  - forward one step, or skip forward
  - any state to `closed`, with a disposition
  - `contained` or `resolved` back to `investigating` (a reopen)

  `resolved` and `closed` are separate states because confirming that nothing recurs is a step
  of its own.
- **New evidence on a late-stage incident.** When a finding attaches to an incident that is
  `contained` or `resolved`, the incident returns to `investigating` with a `reopened` event,
  and an **escalation** notification fires. Escalation means exactly one of three things:
  - severity increased
  - evidence attached at `contained` or later
  - a reopen
- **Closing.** A disposition is required: `true_positive`, `benign_true_positive`,
  `false_positive`, `duplicate` or `inconclusive`. After an incident is closed, a new finding
  with the same fingerprint opens a new incident that links to the old one.
- **Timeline.** Every change appends an `incident_events` row with an `actor`, a `kind` and a
  JSON payload.
  - `actor`: `system`, `rule:<id>@<rev>`, `operator:<token id>`, or later
    `investigator:<session id>`.
  - `kind`: `opened`, `finding_attached`, `status_changed`, `reopened`, `note`,
    `hypothesis_added`, `hypothesis_confirmed`, `action_proposed`, `action_decided`,
    `action_executed`.

  The incident row is a projection of its timeline: current status, severity and counts.
- **Evidence.** An incident's evidence is the transitive closure of its findings, through their
  detections and observations, down to L0. It is computed, never copied.
- **Entities.** The union of `entity_keys` across the incident's findings, stored for lookup.
- **Hypotheses and actions** (L4 and response) attach through the timeline and their own tables
  once the agent layer lands ([0009](0009-agent-runtime-and-authority.md)). Response actions
  start proposal-only.

### Notifications

Tuisku emits **notification events** through a notifier interface. They fire when:

- a finding opens or crosses a threshold
- an incident opens or escalates
- a cap or limit is hit

The first implementation writes structured logs only. Which channels page whom is a deployment
decision, configured outside this repository. Notifications carry ids, titles, severities and
entity keys, never L0 bodies.

## Consequences

- Volume control (window, lifetime, group-by) is part of each rule and explicit, not a global
  knob.
- The incident timeline is the audit log. It is also exactly what an investigator, human or
  agent, reads first.
- OCSF Incident Finding and the Loimi export ([0008](0008-identifiers-and-interchange.md)) are
  projections of the incident and its timeline.
