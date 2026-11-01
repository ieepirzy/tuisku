# 0001. Service boundary and design principles

Status: Accepted (2026-11-01)

## Context

Issue #1 defines Tuisku as an open-source intrusion detection and agentic blue-team framework.
Deterministic systems detect and preserve evidence; agents investigate that evidence. Tuisku is
deliberately not "an LLM watching logs", not a SIEM clone, not a replacement for mature sensors,
and not part of Apogee.

## Decision

Tuisku owns the layer **above** sensors: ingestion, normalization, provenance, deterministic
detection and correlation, the evidence graph, incidents, investigation tooling, and
policy-bounded response. Sensors (Suricata, Zeek, Falco, Harava and later others) stay
upstream, behind versioned adapters ([0005](0005-source-adapters-and-ingestion.md)).

Principles every later decision must keep:

1. **The deterministic substrate stands alone.** Everything up to and including incidents works,
   and can be audited, with no agent and no model configured. Agents are a consumer of that
   substrate, never a dependency of it.
2. **Evidence is preserved, never rewritten.** What a sensor sent is stored byte-for-byte with
   its hash. Everything derived from it says what it was derived from and by which versioned
   code ([0002](0002-epistemic-layers.md)).
3. **Every conclusion can answer "why".** A detection names the rule or mechanism and the
   inputs that made it fire; a finding names its detections; an agent claim names its evidence.
4. **Knowledge is not authority.** A finding, a hypothesis or a recommendation never grants
   permission to act. Response is a separate, policy-gated path
   ([0009](0009-agent-runtime-and-authority.md)).
5. **Telemetry is attacker-controlled input.** DNS names, URLs, user agents, process command
   lines and file names in sensor output are written by whoever is attacking. They are data to
   parse and quote, never instructions to follow, and never trusted to be well-formed.
6. **Public code, private tuning.** This repository is public (MIT). It holds the engine,
   adapters, generic rule packs and fixtures. Detection thresholds, allow-lists, hostnames,
   topology and rules tuned to a specific deployment live in that deployment's own configuration
   (for the first deployment: the operator's private infra repository), loaded at runtime
   ([0006](0006-detection-rules-and-correlation.md)). No real telemetry, secrets or personal data
   are committed; fixtures are synthetic or from public sample sets.
7. **Small first.** The first milestone proves the loop
   telemetry → observation → detection → finding → incident on real sensor formats, before
   breadth.

## Consequences

- The agent layer can be swapped or absent; the data model cannot depend on it.
- Adapters carry real weight: they are where provenance and layer separation are decided.
- Deployment-specific detection content needs a loading path from outside the image from the
  start.
- Licensing boundaries stay explicit: third-party rule sets (Sigma rules under DRL 1.1, ET Open,
  Falco rules) are referenced or fetched at runtime with their own licences, never vendored into
  the MIT tree. Schema specifications we align to (OCSF, Apache-2.0) are attributed in `NOTICE`.
