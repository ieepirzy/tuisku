# 0006. Deterministic rules, correlation and rule packs

Status: Accepted (2026-11-01)

## Context

Tuisku needs its own deterministic logic on top of sensor verdicts. Examples: paging on a single
Harava refusal from an agent caller, counting refusals per caller per hour, a rise in
`likely` content signals, and later cross-sensor correlation. That logic must be inspectable,
testable and explainable ("why did this fire?"). It must also be shareable as community packs
(issue #1). Detection content tuned to a particular estate must stay out of this public
repository (principle 6 in [0001](0001-service-boundary-and-principles.md)).

The Sigma correlation specification (2.x) has already settled on a small set of deterministic
correlation types (`event_count`, `value_count`, `temporal`, `temporal_ordered`, plus
`value_sum`/`value_avg`/`value_percentile`), each with `group-by`, `timespan` and a `condition`.

## Decision

### Rules are data

Rules live in **rule packs**: versioned directories with a `pack.yaml` manifest and rule files.
YAML is parsed with a safe loader, and there is no expression evaluation, templating or code
in rules.

```yaml
# pack.yaml
pack: harava            # pack id
version: 1.0.0
license: MIT
description: Agent-safety signals from Harava.
params:                 # defaults; a deployment overrides them
  restricted_callers: [agents]
```

```yaml
# rules/agent-outbound-refused.yaml
id: 6c1f0f8e-…           # stable UUID; never reused
rev: 1                   # bump on any semantic change
name: harava.agent_outbound_refused
title: Agent caller had outbound data refused
severity: high           # OCSF severity names: informational|low|medium|high|critical
attack: [T1567]          # ATT&CK technique ids, verbatim, optional
select:                  # which L1/L2 rows feed the rule
  layer: detection       # observation | detection
  kind: harava.outbound_refused
  where:                 # all predicates must hold
    - {field: attributes.caller, op: in, value: {param: restricted_callers}}
correlation:             # optional; absent = every selected row fires
  type: event_count      # event_count | value_count | value_sum
  group_by: [attributes.caller]
  timespan: 1h
  condition: {gte: 1}
finding:
  group_by: [attributes.caller]   # dedup key fields (with rule id)
  window: 1h
incident: open                    # open | none
```

- **Predicates** are a closed set: `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`,
  `exists`, `contains`, `startswith`, `cidr`. Field paths address the row envelope (`kind`,
  `source`, `origin`, `severity_id`, `entity_keys`) or `attributes.*`.
- **Correlation types** follow Sigma's semantics: `event_count`, `value_count` (distinct values
  of a field) and `value_sum` (sum of a numeric field, used for metric deltas) come first.
  `temporal` and `temporal_ordered` follow when a rule needs them.
- **Params** let a pack ship generic defaults while a deployment supplies its own thresholds and
  lists.

### Where estate-specific content lives

Tuisku loads packs from the built-in `packs/` directory **and** from directories listed in
`TUISKU_RULE_PACK_PATHS`, plus a params override file (`TUISKU_RULE_PARAMS_FILE`). The first
deployment mounts its private packs and params from its own configuration repository. The
public repository ships only generic packs whose defaults come from the upstream product's own
defaults: for example, Harava's default restricted caller is `agents`, so the pack defaults to
it. Every loaded pack and params file is recorded with its SHA-256, so a finding names exactly
which content produced it.

### Evaluation

- A worker process (`tuisku worker`) consumes new observations and detections in id order,
  using a per-rule cursor table and `FOR UPDATE SKIP LOCKED`, so several workers can run safely
  and a restart resumes where it stopped.
- For each matching row, the worker evaluates the correlation over the rule's `timespan` with
  SQL over the stored rows. State lives in Postgres, not in memory, so results are reproducible
  by re-running.
- **Metric samples** (OTLP cumulative counters) are turned into deltas at evaluation time,
  keyed by series identity (metric name + label set + resource + `start_time`). A counter reset,
  seen as a new start time or a lower value, starts a new series rather than producing a
  negative delta.
- **Baselines** ("a rise in `likely` against its baseline") start as deterministic comparisons:
  the sum over the current window against a multiple of the trailing average of the previous *N*
  windows, with a floor. Both numbers are params. Statistical anomaly detection is out of scope
  until there is data to validate it.
- When a rule fires, the worker creates a `tuisku_rule` **detection** and folds it into a
  **finding** ([0007](0007-findings-and-incidents.md)). The detection's `explanation` records
  the rule `id@rev`, pack name, version and SHA-256, the resolved params, the predicate results,
  the correlation value against its condition, and the ids of the rows that satisfied it.

### Testing packs

Every rule ships at least one positive and one negative fixture (L0 lines through the real
adapter), and the pack test suite asserts exactly which rules fire. A rule without fixtures
fails CI.

## Consequences

- Detection content is reviewable as data, testable offline, and shareable without code.
- The rule language is deliberately small. Anything it cannot express is new engine code with
  its own tests, not an escape hatch.
- Running SQL per evaluation is fine at the first target's volume. Higher volume will need
  incremental aggregates, which is a later decision.
- Sigma *detection* rules (SigmaHQ, DRL 1.1) are not bundled. A Sigma import path can be added
  later as a converter into this format, keeping each rule's original id and licence.
