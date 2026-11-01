# 0005. Source adapter contract and ingestion path

Status: Accepted (2026-11-01)

## Context

Tuisku must take in Suricata EVE JSON, Zeek JSON logs, Falco JSON, and Harava's plain-text log
lines and OTLP metrics, and later more. Industry practice is to parse in the shipping pipeline
(Logstash, Vector remaps). That would put normalization, and therefore provenance, outside
Tuisku. Shippers deliver at least once, so duplicates arrive.

## Decision

### Transport

- Tuisku exposes **one ingest API** per source: `POST /v1/sources/{source}/records`, body
  `application/x-ndjson`. Each line is an envelope:
  `{"raw": "<the original line, as a string>", "collector": {...optional receipt metadata...}}`.
  `collector` carries what the shipper knows (host, file path, offset, container, pod); it is
  stored as receipt metadata, never trusted as evidence about the event.
- **Shippers ship raw lines, they do not parse.** Recommended: Vector (or Fluent Bit / the OTel
  Collector `filelog` receiver) tailing sensor output files with checkpointed offsets, an
  `http` sink to Tuisku, end-to-end acknowledgements and a disk buffer. Falco writes to a file
  that the same shipper tails, rather than relying on falcosidekick's webhook, which has no
  durable queue.
- **OTLP sources** (Harava exports OTLP/HTTP metrics) are accepted at
  `POST /v1/sources/{source}/otlp/v1/metrics` with OTLP JSON encoding. The whole request body is
  one L0 record; the adapter expands it into datapoints. An OpenTelemetry Collector in front
  (with the `otlphttp` exporter set to JSON) provides retries and queueing. Protobuf
  encoding is a follow-up.
- Tuisku answers **2xx only after the transaction commits**, with a per-line result
  (`accepted | duplicate | failed`), so a shipper retrying a partial batch is safe.
- Limits are enforced at the boundary: maximum body size, maximum line length, maximum lines
  per request. Oversized input is rejected with 413, not truncated.

### Sources and authentication

- A **source** is a registered sender: a name, an adapter (`suricata`, `zeek`, `falco`,
  `harava`), adapter options, and a bearer token. Only the token's SHA-256 is stored; the token
  is shown once at creation (`tuisku source add`). A token is valid for its source only. A
  source can be disabled without deleting its history.
- Read endpoints (findings, incidents) use separate operator tokens with the same storage rule.

### Adapter contract

An adapter is a Python object registered under a name with a semantic version:

```python
class Adapter(Protocol):
    name: str               # "suricata"
    version: str            # "1.0.0" — bump on any change to output for the same input
    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult: ...
```

`ParseResult` holds zero or more `ObservationDraft`s and `DetectionDraft`s, where detections
reference observations from the same result by index. Rules:

1. **Pure and deterministic.** No I/O, no clock, no randomness, no network lookups, no
   enrichment. The same bytes and options always give the same drafts. (Enrichment, such as
   asset inventory or GeoIP, is a separate, later, versioned step over stored observations.)
2. **Split mixed layers** ([0002](0002-epistemic-layers.md)): sensor facts become observations;
   sensor verdicts become detections with an origin of `sensor_native` or `community_rule`.
3. **Keep everything.** Fields with no OCSF home go to `unmapped`. Unknown `event_type`s produce
   a generic observation (`kind = "<adapter>.unknown"`) rather than being dropped.
4. **Fail loudly, per record.** An exception or validation error marks that L0 record
   `parse_status = 'failed'` with the error text (truncated, never including the raw body); the
   rest of the batch continues.
5. **Treat every field as hostile.** Bounded string lengths, strict types, no `eval`, no
   regex with catastrophic backtracking on untrusted input, IP addresses parsed with `ipaddress`.
6. **Respect upstream privacy guarantees.** For example, Harava never logs the refused URL or
   value; its adapter must not try to reconstruct or enrich them.
7. **Fixtures are the spec.** Each adapter ships fixtures (synthetic, or from public sample
   sets) and golden expected outputs; a change in output without a version bump fails the tests.

Parsing runs **inside the ingest transaction**: insert raw record (on conflict, report
duplicate and stop), run the adapter, insert observations and detections. Rules and
correlation run asynchronously ([0006](0006-detection-rules-and-correlation.md)), so slow rules
never back-pressure sensors.

### First adapters

| Adapter | Input | Observations | Detections |
|---|---|---|---|
| `suricata` | EVE JSON (`alert`, `flow`, `dns` v2/v3, `http`, `tls`, `fileinfo`, `anomaly`; others generic) | flow/dns/http/tls/file facts | `alert` → `community_rule` (`gid:sid:rev`, signature, category, metadata); `anomaly` → `sensor_native` |
| `zeek` | JSON logs (`conn`, `dns`, `http`, `ssl`, `files`, `notice`, `weird`), epoch or ISO-8601 `ts`; log path from the envelope's `collector.path` or an adapter option | conn/dns/http/ssl/files facts | `notice`, `weird` → `sensor_native` |
| `falco` | Falco JSON output (`rule`, `priority`, `source`, `tags`, `time`, `output_fields`) | process/file/container facts from `output_fields` | the rule match → `community_rule` (rule name, priority, ATT&CK ids parsed from tags) |
| `harava` | plain-text log lines, bare or wrapped by Docker json-file or CRI; OTLP JSON metrics | refusal events; metric samples (cumulative values with series key and start time) | `outbound data refused`, `destination refused`, `MCP refuses to serve` → `sensor_native` |

## Consequences

- Shipper configuration is minimal and identical across sensors.
- All normalization is reproducible from L0 inside Tuisku.
- A per-source token compromise lets an attacker inject records for that source only. Injected
  records still carry their source and receipt metadata, and the source can be disabled.
  Detections from a single source should be read with that in mind.
