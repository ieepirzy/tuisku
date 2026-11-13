# Architecture decision records

These records are the architecture pass that issue #1 asked for. Each one states a decision, the
context that forced it, and what it costs. They are settled until a later ADR supersedes them;
change one only with new evidence, by writing a new ADR that names the one it replaces.

| # | Title | Status |
|---|---|---|
| [0001](0001-service-boundary-and-principles.md) | Service boundary and design principles | Accepted |
| [0002](0002-epistemic-layers.md) | Epistemic layers and the evidence model | Accepted |
| [0003](0003-canonical-event-model.md) | Canonical event model: OCSF-aligned, versioned, with a provenance envelope | Accepted |
| [0004](0004-storage.md) | Storage: Postgres, plain SQL, append-only evidence | Accepted |
| [0005](0005-source-adapters-and-ingestion.md) | Source adapter contract and ingestion path | Accepted |
| [0006](0006-detection-rules-and-correlation.md) | Deterministic rules, correlation and rule packs | Accepted |
| [0007](0007-findings-and-incidents.md) | Findings, incidents and their lifecycle | Accepted |
| [0008](0008-identifiers-and-interchange.md) | Identifiers, vocabularies, and interchange with Loimi and Apogee | Accepted |
| [0009](0009-agent-runtime-and-authority.md) | Agent runtime interface and response authority | Accepted (design; not built yet) |
| [0010](0010-deployment-topology.md) | Deployment topology for the first target | Accepted |
| [0011](0011-separate-worker-database-role.md) | Separate worker database role (amends 0004 §3) | Accepted |
| [0012](0012-export-of-finding-and-incident-events.md) | Export of finding and incident events to an append-only sink | Accepted |

Status words: *Accepted* (in force), *Superseded by NNNN*, *Proposed* (not in force).

The research these ADRs rest on (OCSF, STIX 2.1, Sigma correlations, sensor output formats,
Community ID, collector transports, and the neighbouring Loimi, Apogee and Harava services) is
summarised in the ADRs that use it, with links to primary sources.

## Decided later, on purpose

Issue #1 lists more architecture work than this first pass decides. These items are deferred,
not forgotten:

- **Pack contents beyond detections**: investigation playbooks, agent hints, telemetry
  requirements, false-positive and applicability metadata. When these land, agent hints are
  stored and served as hints and are never treated as evidence (ADR 0002).
- **Test and replay architecture** beyond what ADRs 0004 to 0006 fix: an injected clock,
  fixture packs, and golden adapter outputs. A full end-to-end replay harness
  (telemetry → incident → agent analysis) comes with the agent layer.
- **Response policy and approval**: ADR 0009 fixes human-only approval and closed catalogues.
  A containment ADR will design autonomous actions.
- **The first milestone's agent half**: a Miragen-backed investigator through the ADR 0009
  interface. The deterministic half comes first.
- **Dashboards** (issue #2): trends are queryable from the API; a dashboard is a follow-up.
- **Tenancy**: entity keys gain an estate qualifier if Tuisku ever watches more than one estate.
- **Partitioning, cold storage and incremental aggregates** (ADRs 0004, 0006), when volume
  requires them.
