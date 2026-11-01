# 0007. Findings, incidents and their lifecycle

Status: Accepted (2026-11-01)

## Context

Detections are many and noisy; people and investigators need fewer, durable objects. Issue #1
says incidents are first-class investigations, "not transient alert blobs", with a timeline,
entities, evidence, hypotheses, human decisions, proposed and executed actions, and an outcome.
Common practice: TheHive deduplicates alerts on `(type, source, sourceRef)` and merges them into
cases; Elastic suppresses alerts by group-by fields within a window. OCSF uses Detection Finding
(2004) with `first_seen_time`/`last_seen_time`/`count`, and Incident Finding (2005). Apogee's
finding lifecycle is OCSF-derived (`open|confirmed|dismissed|retested|closed`).

## Decision

### Findings (deduplicated, deterministic)

- A **finding** groups detections that share a **fingerprint** within a **window**:
  `fingerprint = sha256(rule identity ‖ values of the rule's finding.group_by fields)`. Rule
  identity is the rule id for `tuisku_rule` detections, and the sensor rule identity
  (`suricata:gid:sid`, `falco:<rule>`, `zeek:notice:<note>`) for sensor detections.
- While a finding is open and its `last_seen` is within the window, a new matching detection is
  linked to it: `count` increments, `last_seen` moves, and the detection is added to
  `finding_detections`. Otherwise a new finding is opened. The underlying detections are never
  merged or deleted.
- Fields: `uid`, `fingerprint`, `title`, `severity_id` (max of its detections), `status`
  (`open | acknowledged | resolved | suppressed`), `first_seen`, `last_seen`, `count`,
  `entity_keys` (union), `rule_ref`, `explanation` (from the first detection, plus the latest
  correlation values).
- Sensor detections become findings only when a pack rule selects them, so a deployment decides
  which Suricata categories or Falco priorities matter. The built-in packs include a
  conservative default: Suricata severity 1 and Falco Critical and above.

### Incidents (durable investigations)

- An **incident** is opened by a rule with `incident: open`, or by an operator. One open
  incident per fingerprint: a later finding with the same fingerprint attaches to the open
  incident instead of opening another.
- **States:** `open → triaged → investigating → contained → resolved → closed`. `resolved` and
  `closed` are separate because confirming that nothing recurs is its own step. Any state can
  move to `closed` with a disposition. Reopening is an event and returns the incident to
  `investigating`.
- **Disposition** (required to close): `true_positive`, `benign_true_positive`,
  `false_positive`, `duplicate`, `inconclusive`.
- **Timeline:** every change is an append-only `incident_events` row with `actor` (`system`,
  `rule:<id>@<rev>`, `operator:<name>`, later `investigator:<id>`), `kind` (`opened`,
  `finding_attached`, `status_changed`, `note`, `hypothesis_added`, `action_proposed`,
  `action_decided`, `action_executed`) and a JSON payload. The incident row is a projection of
  its timeline: current status, severity and counts.
- **Evidence** of an incident is the transitive closure of its findings, through their
  detections and observations, down to L0. It is computed, never copied.
- **Entities:** the union of `entity_keys` across its findings, stored for lookup.
- **Hypotheses and actions** (L4 and response) attach to incidents through the timeline and
  their own tables when the agent layer lands ([0009](0009-agent-runtime-and-authority.md)).
  Response actions start proposal-only.

### Notifications

When a rule's severity is `high` or above and it opens or escalates an incident, Tuisku emits a
**notification event** through a notifier interface. The first implementation writes structured
logs only. Which channels page whom (Telegram, Mira, a MiraDesign incident) is a deployment
decision that will be made separately.

## Consequences

- Volume control (window, group-by) is part of each rule and explicit, not a global knob.
- The incident timeline is the audit log. It is also exactly what an investigator, human or
  agent, reads first.
- OCSF Incident Finding and Loimi export ([0008](0008-identifiers-and-interchange.md)) are
  projections of incident plus timeline.
