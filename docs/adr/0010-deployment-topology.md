# 0010. Deployment topology for the first target

Status: Accepted (2026-11-01)

## Context

Tuisku is not deployed anywhere yet. Its first target is intrusion detection and cyber-defense
on a small Kubernetes cluster that is managed with GitOps and gives each service its own Postgres
database. Which sensors to run, and what Tuisku agents may do, are decisions for the deploying
estate.

This ADR describes Tuisku's own topology in generic terms. The estate-specific manifests live
in the estate's own configuration repository (principle 6 in [0001](0001-service-boundary-and-principles.md)).

## Decision

### Tuisku processes (one image, several roles)

| Role | Command | Scaling | Notes |
|---|---|---|---|
| API | `tuisku api` | 1–N stateless | ingest, read API |
| Investigation surface | `tuisku investigate` (later) | 0–N | the MCP tool surface; its own database role ([0009](0009-agent-runtime-and-authority.md)) |
| Worker | `tuisku worker` | 1–N | rule evaluation, findings, incidents ([0006](0006-detection-rules-and-correlation.md)) |
| Migrate | `tuisku migrate` | one-shot Job before rollout | never on API boot |

Also:

- Postgres 16 is a dedicated database.
- The image runs as non-root.
- Configuration comes from environment variables (`TUISKU_*`), and rule packs and params are
  mounted from deployment configuration.

### Data paths

- **Sensors → shipper → Tuisku.** The shipper is Vector or an equivalent. It tails sensor output
  files or container logs, ships raw lines as NDJSON envelopes with acknowledgements, and keeps
  a disk buffer ([0005](0005-source-adapters-and-ingestion.md)). An OpenTelemetry Collector
  (`filelog` receiver) can ship the same raw lines as OTLP/HTTP JSON logs instead. Each sensor deployment is one
  Tuisku source with its own token.
- **OTLP metrics → collector → Tuisku.** Sources that emit OTLP, Harava first, reach Tuisku
  through an OpenTelemetry Collector pipeline that fans out to Tuisku's OTLP endpoint (JSON),
  in addition to the metrics store.
- **Harava.** Harava's refusal events are plain-text log lines; it exports metrics and traces
  over OTLP, but not logs. Its refusal log lines are therefore shipped raw from the container
  log, and its metrics arrive over OTLP when a collector forwards them. The adapter accepts the
  bare line, the Docker json-file wrapper and the CRI format.

### Sensors (deployed by the estate, not by Tuisku)

These are recommendations for the estate's sensor decision, not assumptions Tuisku depends on:

- **Runtime (host):** an eBPF-based runtime sensor, such as Falco with the `modern_ebpf` driver
  or Tetragon. Either needs host-level access, which admission policy must explicitly allow.
  Workloads in sandboxed container runtimes need the sandbox's own monitoring; the deploying
  estate should check its coverage.
- **Network:** flow logs from the cluster network plugin, where available, give L3/L4 and DNS
  visibility without a new sensor. An adapter for them is a natural next step. Suricata or Zeek
  in AF_PACKET mode on a host-networked node adds L7 signatures and protocol logs where deep
  inspection is wanted, for example where traffic enters or leaves the cluster.
- **Application signals:** Harava's agent-safety signals (issue #2) need no new sensor.

### Exposure

The ingest and read APIs are cluster-internal and reached through a Service. Default-deny
network policy admits only the shippers, the collector and operator tooling. Tuisku has no
public endpoint in the first milestone.

## Consequences

- A deployment can start with application signals alone (such as Harava's), then add sensors,
  with no Tuisku change.
- Shipping logs to the estate's own log store and also to Tuisku is a
  fan-out at the shipper, not a dependency between the two.
