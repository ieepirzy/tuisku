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
  layer: detection           # observation | detection
  kind: harava.outbound_refused
  where:                     # all predicates must hold
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
  `exists`, `contains`, `startswith`, `cidr`.
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
- **Feedback** is opt-in: rules do not see `evaluator = tuisku` detections (other rules' output)
  unless `select.include_rule_output: true`.

### Hard limits

These are checked when a pack loads, and a pack that exceeds them is rejected:

- `timespan` and `window` ≤ 7 days, `max_lifetime` ≤ 30 days, baseline `windows` ≤ 30
- `group_by` ≤ 4 fields, values truncated to 256 characters before grouping
- at most 1,000 open findings and 100 open incidents per rule

Each rule evaluation runs under a Postgres `statement_timeout`. Reaching a cap raises a
`tuisku.rule.cap_reached` meta-detection. It does not silently stop alerting.

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
  detection into `evaluation_queue`. Workers (`tuisku worker`) claim batches with
  `FOR UPDATE SKIP LOCKED`, evaluate them, and delete the queue rows in the same transaction as
  their results. Rows that commit late are therefore never skipped, and several workers can run
  side by side.
- **Current derivations only.** Reprocessing L0 with a new adapter version writes new rows and
  marks the new parse attempt current. It enqueues nothing unless the operator asks for
  re-evaluation. Correlation queries count only rows from current parse attempts, so
  reprocessing never double-counts.
- **Windows.** A row's evaluation time is its `event_time`, or `received_at` when the row is
  flagged `clock_skew` or has no event time. The correlation window is
  `(t - timespan, t]`.
  - Late rows, within an allowed lateness of 1 hour by default, are evaluated against the
    window they belong to.
  - Rows later than that are evaluated at `received_at` and flagged `late`.
- **Firing.** A correlation fires when its condition first holds for a group in a window. It
  fires again for that group only after `timespan` has passed since the last firing. Matching
  rows between firings are linked as evidence to the existing finding rather than producing new
  detections. Rules without a `correlation` block fire once per selected row.
- **Metric samples** (OTLP cumulative counters) become deltas at evaluation time:
  - The series key is metric name + label set + resource attributes.
  - Within a series, `delta = value - previous value` while `start_time` is unchanged.
  - A changed `start_time`, or a value lower than the previous one, is a **reset**. The new
    value itself is then the delta, because it counts from the new `start_time`.
  - The first sample ever seen for a series counts its full value, since OTel counters appear
    only on their first increment. This way the first refusal after a restart is counted.
  - Sums with delta temporality are taken as-is.
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
