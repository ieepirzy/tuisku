# 0003. Canonical event model: OCSF-aligned, versioned, with a provenance envelope

Status: Accepted (2026-11-01)

## Context

Adapters need one target shape. Options considered:

- **OCSF** (Open Cybersecurity Schema Framework, Linux Foundation, Apache-2.0; 1.9.0 current).
  Class-based (`class_uid`, `category_uid`, `activity_id`), with Detection Finding (2004),
  Network/HTTP/DNS Activity, Process and File System Activity, a flat `observables[]` index,
  `raw_data`/`raw_data_hash`, and an `unmapped` object for source fields with no home.
- **Elastic ECS** — being folded into OpenTelemetry semantic conventions; good field names, weaker
  finding model.
- **OpenTelemetry semantic conventions** — the transport vocabulary (`host.name`, `k8s.*`,
  `service.name`); its `security_rule.*` attributes are still at Development stability.
- **STIX 2.1** — an exchange format for threat intelligence (SCOs, Indicators, Sightings), not an
  event-storage model.

## Decision

1. **Observations and detections store an OCSF-shaped JSON payload** (`attributes`) for the
   classes we use, pinned to one OCSF version (`ocsf_version` column, initially `1.9.0`). We
   adopt OCSF's *shape and names*, not its full required-field validation; adapters fill what the
   source actually provides and never invent values to satisfy a schema.
2. **A Tuisku envelope wraps every row** with what OCSF does not model as first-class:
   `source_id`, `raw_record_id`, `adapter`, `adapter_version`, `kind`, `event_time` (when it
   happened, per the sensor), `received_at` (when Tuisku got it), `entity_keys`
   ([0008](0008-identifiers-and-interchange.md)), and `community_id` where a flow is involved.
3. **`kind`** is a short, stable Tuisku name for what the row is (`network.flow`, `dns.answer`,
   `http.request`, `tls.handshake`, `file.transfer`, `process.exec`, `metric.sample`,
   `harava.outbound_refused`, …). Rules match on `kind` and attributes; `ocsf_class_uid` is
   stored alongside for export.
4. **Nothing is dropped silently.** Source fields with no OCSF home go to `unmapped`, exactly as
   received. The full original is always in L0.
5. **Community ID v1** is computed by Tuisku from the 5-tuple (using the reference `communityid`
   package, BSD-3) for every flow-bearing observation. If the sensor also reported one and they
   differ, the observation records both and flags the mismatch (usually a seed or config
   difference between sensors). This is the cross-sensor join key between Suricata, Zeek and
   anything else that sees the same flow.
6. **Sensor-scoped identifiers are scoped.** Suricata `flow_id` and Zeek `uid` are unique only
   within one sensor process; they are stored as correlation keys qualified by `source_id`,
   never treated as global ids.
7. **Export formats are mappings, not storage**: OCSF Detection/Incident Finding for SIEM
   interop, STIX 2.1 bundles (Observed Data, Indicator, Sighting) for intelligence sharing. They
   are produced on demand from stored rows.

## Consequences

- One rule language works across sensors because fields have OCSF names
  (`src_endpoint.ip`, `dst_endpoint.port`, `process.cmd_line`, …).
- When OCSF moves, we pin and migrate deliberately; old rows keep the version they were written
  with.
- `NOTICE` attributes OCSF (Apache-2.0).
