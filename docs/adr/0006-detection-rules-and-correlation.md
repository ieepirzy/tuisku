# 0006. Deterministic rules, correlation and rule packs

Status: Accepted (2026-11-01)

## Context

Tuisku needs deterministic logic of its own on top of sensor verdicts. Examples:

- page on a single Harava refusal from an agent caller
- count refusals per caller per hour
- notice a rise in `likely` content signals
- later, correlate across sensors

That logic must be inspectable, testable and explainable ("why did this fire?"). Issue #1 says
it should also be shareable as community packs. Detection content tuned to a particular estate
must stay out of this public repository (principle 6 in
[0001](0001-service-boundary-and-principles.md)).

The Sigma correlation specification (2.x) already settles on a small set of deterministic
correlation types (`event_count`, `value_count`, `temporal`, `temporal_ordered`, and the
`value_*` aggregates). Each has a `group-by`, a `timespan` and a `condition`.

## Decision

### Rules are data

Rules live in **rule packs**: versioned directories with a `pack.yaml` manifest and rule files.
YAML is parsed with a safe loader. Rules have no expression evaluation, no templating and no
code.

```yaml
# pack.yaml
pack: harava                 # pack id
version: 1.0.0
authorship: tuisku           # tuisku | community | local  (ADR 0002)
license: MIT                 # the pack's licence; a rule may declare its own, which wins
description: Agent-safety signals from Harava.
params:                      # defaults; a deployment overrides them
  restricted_callers: [agents]
```

```yaml
# rules/agent-outbound-refused.yaml
id: 6c1f0f8e-…               # stable UUID; never reused
rev: 1                       # bump on any semantic change
name: harava.agent_outbound_refused
title: Agent caller had outbound data refused
severity: high               # informational | low | medium | high | critical
attack: [T1567]              # ATT&CK technique ids, verbatim, optional
select:                      # which rows feed the rule
  layer: observation         # observation | detection
  kind: harava.refusal       # the fact; the sensor's verdict is a separate detection row
  where:                     # all predicates must hold
    - {field: attributes.type, op: eq, value: outbound}
    - {field: attributes.caller, op: in, value: {param: restricted_callers}}
correlation:                 # optional; absent = each selected row fires on its own
  type: event_count
  group_by: [attributes.caller]
  timespan: 1h
  condition: {gte: 1}
finding:
  group_by: [attributes.caller]
  window: 1h
  max_lifetime: 24h
incident: open               # open | none
```

The field reference is built up from the following pieces.

- **Predicates** are a closed set: `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`,
  `exists`, `contains`, `startswith`, `cidr`. A predicate whose field is missing or has the
  wrong type evaluates to **false**; it never raises an error. One hostile field therefore
  cannot make a row fail evaluation for every rule.
- **Field paths** address either the row envelope or `attributes.*`. The envelope fields are:
  - `kind`
  - `source` (the source's *name*; the stored column is `source_id`)
  - `evaluator`, `authorship`
  - `identity` (detections)
  - `severity_id`
  - `entity_keys`
- **Correlation types**:
  - `event_count`
  - `value_count`: distinct values of a field
  - `value_sum`: sum of a numeric field. For metric samples, the field `delta` is computed as
    described under "Metric samples" below.
  - `baseline`: the current window's `value_sum` or `event_count`, compared with
    `factor × the mean of the previous N windows`, and never below `floor`. It takes
    `baseline: {windows: N, factor: F, floor: X}`.
  - `temporal` and `temporal_ordered` come later, when a rule needs them.
- **Params** let a pack ship generic defaults while a deployment supplies its own thresholds and
  lists. A param can supply a predicate value or a correlation number.
- **Feedback** is opt-in. Rules do not see `evaluator = tuisku` detections, which are other
  rules' output, unless `select.include_rule_output: true`. A rule can never select detections
  whose `identity` is its own id. When packs load, the selection graph between rules that
  include rule output must be acyclic; a pack that creates a cycle is rejected. Meta-detections
  (`tuisku.meta.*`) can always be selected by kind.

### Hard limits

These are checked when a pack loads, and a pack that breaks them is rejected:

- `timespan` and `window` ≤ 7 days, `max_lifetime` ≤ 30 days, baseline `windows` ≤ 30
- `group_by` ≤ 4 fields, with values truncated to 256 characters before grouping
- at most 1,000 open findings and 100 live incidents per rule

**At the cap, detection keeps working.** When a rule reaches its open-findings cap, it keeps
detecting:

- Further firings for new groups fold into one **overflow finding** for that rule. Its
  fingerprint is JCS `["overflow", <rule id>, <rule rev>]`, it has high severity, it records the
  `group_by` values in its evidence, and it sends a notification.
- At the live-incident cap, findings that would open new incidents attach instead to one
  overflow incident for the rule, keyed the same way, so nothing is left without an incident.
- Cap checks run under a per-rule advisory lock, so concurrent workers cannot overshoot.
- An attacker who sprays many distinct group values therefore gets one loud finding, not
  silence.
- Findings past `window` and `max_lifetime` expire automatically (see
  [0007](0007-findings-and-incidents.md)), so the cap drains.

Each rule evaluation runs under a Postgres `statement_timeout`.

### Where estate-specific content lives

Tuisku loads packs from the built-in `packs/` directory **and** from the directories listed in
`TUISKU_RULE_PACK_PATHS`, plus a params override file (`TUISKU_RULE_PARAMS_FILE`). A deployment
mounts its private packs and params from its own configuration repository.

The public repository ships only generic packs whose defaults come from the upstream product's
own defaults. For example, Harava's default restricted caller is `agents`, so the pack defaults
to it.

Every loaded pack and params file is recorded with its SHA-256, so a finding names exactly which
content produced it.

### Evaluation

- **Work queue, not a cursor.** The ingest transaction inserts one row per new observation or
  detection into `evaluation_queue`. Rows that commit late are never skipped, and several
  workers can run side by side.
  - **Claiming** is its own short transaction, which commits. A worker selects a batch with
    `FOR UPDATE SKIP LOCKED`, increments each row's `attempts`, and sets a lease
    (`claimed_until`). Expired leases are claimable again, so a crashed worker loses nothing.
  - **Evaluation** happens in a second transaction. Each row is evaluated under its own
    `SAVEPOINT`, and its queue row is deleted together with its results.
  - **Failures:** a row that fails alone is rolled back to its savepoint, with the error
    recorded. Other rows in the batch are unaffected. Deadlocks (SQLSTATE 40P01), serialization
    failures and lock timeouts are retried without counting as attempts.
  - **Dead letter:** after 5 counted attempts, a row moves to `evaluation_dead_letter` and
    raises a `tuisku.meta.evaluation_failed` meta-detection. A poison row can neither block the
    queue nor drag innocent rows with it.
  - **Serialized per group.** Before deciding whether a correlation fires, and before deciding
    whether a finding attaches or opens, a worker takes
    `pg_advisory_xact_lock(<64-bit hash of the key>)` for every key the row touches. It takes
    them in sorted order, so two workers cannot deadlock on them. Two workers that see rows of
    the same group therefore cannot both fire or both open a finding.
- **Current derivations only.** Reprocessing L0 with a new adapter version writes a new parse
  attempt and new rows, and **enqueues the new current rows**.
  - A worker skips queued *adapter-derived* rows whose parse attempt is no longer current.
  - Correlation queries count only adapter-derived rows from current attempts, which are
    defined in [0002](0002-epistemic-layers.md), so reprocessing never double-counts.
  - Rows without a parse attempt are always current: Tuisku rule output and meta-detections.
  - **Firing after reprocessing.** A firing is suppressed when a detection already exists for
    the same rule, group and overlapping window, if either of these holds:
    - that detection's finding is still attachable;
    - the rows behind the new firing come only from raw records that already contributed to
      that detection.

    Re-evaluation after reprocessing therefore never pages twice for the same evidence.
- **Windows.** A row's evaluation time is its `event_time`. It is its `received_at` instead
  when the row is flagged `clock_skew` (future-dated) or has no event time. The correlation
  window is `(t - timespan, t]`.
  - **Late rows:** a row is late when an evaluation for a later time has already happened for
    its group. A late row at time `t` is checked against **every** window that contains it.
    The worker queries `(t - timespan, t + timespan)` under the group's lock and slides over
    the window ends. This continues up to an allowed lateness of 24 hours by default, so
    out-of-order delivery still fires.
  - **Later than that,** a row is evaluated at `received_at`. Its lateness is recorded in the
    resulting detection's explanation, never by changing the row.
- **Firing.** A correlation fires when its condition first holds for a group in a window. It
  fires again for that group once `timespan` has passed since the last firing, **or as soon as
  the finding of the last firing leaves the attachable states**: resolved, expired, or resolved
  because its incident was resolved or closed. Closing an incident or resolving a finding
  re-arms the group immediately, so the next matching row fires and opens a new finding.
  Triage can never mute a rule.
  - Rows that match between firings, while the finding is still attachable, are linked to the
    most recent firing detection through the append-only `detection_evidence` table, with a
    timestamp. They also move the finding's `last_seen`. The chain finding → detection → rows
    stays complete.
  - At load time, a pack is rejected unless `finding.window >= correlation.timespan` and
    `finding.max_lifetime >= correlation.timespan`.
  - Rules without a `correlation` block fire once per selected row.
- **Metric samples** (OTLP cumulative counters) are turned into deltas at evaluation time.
  - **Series key:** metric name + label set + resource attributes.
  - **Within a series,** `delta = value - previous value` while `start_time` is unchanged.
  - **Reset:** a changed `start_time`, or a value lower than the previous one, is a reset. The
    new value itself is then the delta, because it counts from the new `start_time`.
  - **First sample ever seen for a series:** its full value counts only if its `start_time` is
    no earlier than the source's first `received_at` minus one export interval (default 60 s).
    That covers a counter that began while Tuisku was already listening. OTel counters appear
    only on their first increment, so the first refusal is counted. Otherwise the first sample
    is a baseline with delta 0, so connecting Tuisku to a long-running process does not
    produce a false spike.
  - **Delta temporality:** sums with delta temporality are taken as-is.
- **Output.** When a rule fires, the worker writes a detection with `evaluator = tuisku`, the
  pack's authorship, and `identity = <rule id>`. It then folds the detection into a **finding**
  ([0007](0007-findings-and-incidents.md)). The detection's `explanation` records:
  - the rule `id@rev`, and the pack name, version and SHA-256
  - the resolved params and the predicate results
  - the correlation value against its condition, plus the baseline figures when used
  - the ids of the rows that satisfied it

### Testing packs

Every rule ships at least one positive and one negative fixture: L0 lines run through the real
adapter, with timestamps on an injected clock. The pack test suite asserts exactly which rules
fire. A rule without fixtures fails CI.

## Consequences

- Detection content can be reviewed as data, tested offline, and shared without code.
- The rule language is deliberately small. Anything it cannot express becomes new engine code
  with its own tests, not an escape hatch.
- One SQL query per evaluation is fine at the first target's volume. Higher volume needs
  incremental aggregates, which is a later decision.
- Sigma *detection* rules (SigmaHQ, DRL 1.1) are not bundled. A converter can be added later;
  converted rules must keep their original id, author attribution and licence.
