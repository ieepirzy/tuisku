# 0013. Deployment-neutral names for built-in adapters and packs

Status: Accepted (2026-11-23)

## Context

This repository is public ([0001](0001-service-boundary-and-principles.md), principle 6; AGENTS.md).
One built-in adapter and its rule pack were named after the deploying organisation's own egress
gateway, and the adapter matched that gateway's logger and metric names literally. The ADRs and
fixtures also named other internal services of that organisation. A service name tells a reader
what the organisation runs and how it is put together, which is the kind of estate detail the
repository already keeps out (detection logic, thresholds, hostnames, topology).

## Decision

- **Built-in adapters and packs are named for the role of the source, not for a product a
  deployment runs.** The egress gateway adapter and pack are `egress-guard`: they read an agent
  egress safety proxy (an outbound fetch gateway that agents call to fetch URLs, and that refuses
  unsafe outbound requests and destinations). Tuisku's own vocabulary for it (observation and
  detection kinds, detection identities, `caller:egress-guard/<name>` entity keys, rule names)
  uses that name.
- **A source's own names are configuration, with neutral defaults.** The adapter recognises
  refusals from `<logger_prefix>.api` and `<logger_prefix>.mcp`, and checks the label values of
  `<metric_prefix>.outbound.refused`, `<metric_prefix>.destination.refused` and
  `<metric_prefix>.content.signals`; both prefixes are adapter options defaulting to
  `egress_guard`. Metric names are stored verbatim in `metric.sample` observations (an adapter
  never rewrites what the sensor sent), so the pack matches them through the params
  `destination_refused_metric` and `content_signals_metric`, which a deployment sets in
  `TUISKU_RULE_PARAMS_FILE`. A deployment's real names live only in its own configuration
  repository.
- **Unknown adapter option keys are refused** by this adapter, so a misspelt prefix fails every
  record loudly instead of turning refusals into generic log lines.
- **Documents name roles** ("the egress gateway", "the artifact store", "the red-team service").
  The earlier ADRs were edited to do so; the edits change no decision and each carries an
  "Edited 2026-11-23" note.
- **A test guards against regressions.** `tests/test_no_internal_names.py` tokenises every tracked
  text file and fails, with `file:line` and the token, on any name in its list. The list holds
  SHA-256 digests of the lowercase names, never the names. Comments in merged migration
  revisions, which are never edited, are listed as exact `(file, line, digest)` exceptions.

## Consequences

- The rename is not a schema change: no revision held any of these names. Rows already stored
  keep the kinds and entity keys they were written with; evidence is never rewritten
  ([0002](0002-epistemic-layers.md)), so queries over older history use the old kinds.
- The five pack rules changed their selects, so their `rev` is 2 and the pack is version 2.0.0;
  the adapter is version 2.0.0.
- A deployment that registered a source with the old adapter name, or keyed its params file by
  the old pack id, must change both in its configuration repository when it upgrades: the old
  adapter name is unknown (records fail to parse) and a params file naming an unknown pack stops
  the worker from loading packs. It also sets the two adapter options and the two pack params to
  its gateway's names. `tuisku source ensure` does not change an existing source's adapter, so
  the deployment registers a new source (with its token) or updates the `sources` row as the
  database owner.
- The digest list can be reversed by guessing a candidate name, so it hides names from casual
  reading and search, not from someone who already suspects one.
