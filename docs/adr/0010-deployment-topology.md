# 0010. Deployment topology for the first target

Status: Accepted (2026-11-01)

## Context

Tuisku is not deployed anywhere yet. Its first target is intrusion detection and cyber-defense
on the operator's Kubernetes cluster, which is managed with GitOps, gives each service its
own Postgres database, and has an OpenTelemetry collector. No IDS or runtime sensor runs there
yet. Which sensors to run, and what Tuisku agents may do, are open decisions for that estate.

This ADR describes Tuisku's own topology in generic terms. The estate-specific manifests live
in the estate's own configuration repository (principle 6 in [0001](0001-service-boundary-and-principles.md)).

## Decision

### Tuisku processes (one image, several roles)

| Role | Command | Scaling | Notes |
|---|---|---|---|
| API | `tuisku api` | 1–N stateless | ingest, read API, later the MCP tool surface |
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
  a disk buffer ([0005](0005-source-adapters-and-ingestion.md)). Each sensor deployment is one
  Tuisku source with its own token.
- **OTLP metrics → collector → Tuisku.** Sources that emit OTLP, Harava first, reach Tuisku
  through an OpenTelemetry Collector pipeline that fans out to Tuisku's OTLP endpoint (JSON),
  in addition to the metrics store.
- **Harava today.** Harava's refusal events exist only as plain-text log lines (it does not
  export OTLP logs), and its OTLP export is off until a collector is wired to it. The
  first Harava ingestion path is therefore its container log lines, shipped raw. The adapter
  accepts the bare line, the Docker json-file wrapper and the CRI format.

### Sensors (deployed by the estate, not by Tuisku)

These are recommendations for the estate's sensor decision, not assumptions Tuisku depends on:

- **Runtime (host):** Falco with the `modern_ebpf` driver, or Tetragon (it fits an existing
  Cilium install). Both need host-level access, which admission policy must explicitly allow.
  Workloads in sandboxed runtimes such as gVisor are invisible to host eBPF syscall hooks;
  covering them needs the sandbox's own runtime monitoring.
- **Network:** on Cilium clusters, Hubble flow logs give L3/L4 and DNS visibility with no new sensor (an
  adapter is a natural next step after this milestone). Suricata or Zeek in AF_PACKET mode on a
  node with host networking adds L7 signatures and protocol logs where deep inspection is
  wanted, for example on the nodes where ingress and egress traffic leave the cluster.
- **Application signals:** Harava's agent-safety signals (issue #2) need no new sensor.

### Exposure

The ingest and read APIs are cluster-internal and reached through a Service. Default-deny
network policy admits only the shippers, the collector and operator tooling. Tuisku has no
public endpoint in the first milestone.

## Consequences

- The first deployment can start with Harava logs alone, then add sensors as the estate decides
  its sensors, with no Tuisku change.
- Shipping logs to the estate's own log store and also to Tuisku is a
  fan-out at the shipper, not a dependency between the two.
- Manifests in the estate repository stay suspended until the operator resumes them.
