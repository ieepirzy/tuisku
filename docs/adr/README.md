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

Status words: *Accepted* (in force), *Superseded by NNNN*, *Proposed* (not in force).

The research these ADRs rest on (OCSF, STIX 2.1, Sigma correlations, sensor output formats,
Community ID, collector transports, and the neighbouring Loimi, Apogee and Harava services) is
summarised in the ADRs that use it, with links to primary sources.
