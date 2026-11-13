# 0005. Source adapter contract and ingestion path

Status: Accepted (2026-11-01). Amended 2026-11-13: OTLP/HTTP JSON logs transport and
`tuisku source ensure`.

## Context

Tuisku must ingest Suricata EVE JSON, Zeek JSON logs, Falco JSON, and Harava's plain-text log
lines and OTLP metrics, with more to come. Industry practice is to parse in the shipping
pipeline (Logstash, Vector remaps). That would put normalization, and with it provenance,
outside Tuisku. Shippers deliver at least once, so duplicates arrive. Every sender is a
potential attacker: anyone who holds a source token, and anyone who can influence what a
sensor sees.

## Decision

### Transport

- Tuisku exposes **one ingest API** per source: `POST /v1/sources/{source}/records`, with body
  type `application/x-ndjson`. Each line is an envelope:
  `{"raw": "<the original line, as a string>", "collector": {...optional receipt metadata...}}`.
  `collector` holds what the shipper knows: host, file path, offset, container, pod. It is
  stored as receipt metadata, size-capped, and never trusted as evidence about the event.
- **Shippers ship raw lines; they do not parse.** Recommended setup:
  - Vector (or Fluent Bit, or the OTel Collector `filelog` receiver) tails sensor output files
    with checkpointed offsets.
  - An `http` sink sends to Tuisku, with end-to-end acknowledgements and a disk buffer.
  - Falco writes to a file that the same shipper tails, rather than using falcosidekick's
    webhook, which has no durable queue.
- **OTLP sources** (Harava exports OTLP/HTTP metrics) post to
  `POST /v1/sources/{source}/otlp/v1/metrics` using OTLP JSON encoding. The whole request body
  is one L0 record, and the adapter expands it into metric samples. An OpenTelemetry Collector
  in front (with the `otlphttp` exporter set to JSON) provides retries and queueing. Protobuf
  encoding is a follow-up. Only cumulative-temporality sums are interpreted; other metric types
  are kept as generic observations.
- **OTLP logs** (amended 2026-11-13) post to `POST /v1/sources/{source}/otlp/v1/logs` using
  OTLP/HTTP JSON encoding, so the OpenTelemetry Collector (`filelog` receiver, `otlphttp`
  exporter with `encoding: json`) can ship any sensor's lines with its own checkpointing,
  queueing and retries. Unlike metrics, each `logRecord` is **one L0 record, handled exactly as
  one NDJSON envelope**:
  - `raw` is the record's `body.stringValue`, byte for byte, stored with transport
    `otlp_logs_json`, and the source's adapter parses it as it would the same NDJSON line.
  - A body of any other `AnyValue` kind is **refused** (`rejected`, `body_not_string`), not
    re-serialized: a collector that parsed the line has already replaced what the sensor wrote,
    and parsing belongs to the adapter.
  - `collector` is the resource attributes merged with the record's attributes (the record's
    win), keyed by their OpenTelemetry names, plus the record's observed and event timestamps.
    It is the same untrusted receipt metadata as an envelope's `collector`, under the same cap.
    No adapter reads `collector`; the asset in an event comes from the event itself.
  - The per-request limits apply per record (the line limit counts log records). A body that
    is not an OTLP/JSON logs request gets 400 and an `invalid_envelope` meta-detection.
  - The answer is an OTLP `ExportLogsServiceResponse`: `partialSuccess.rejectedLogRecords`
    counts the rejected records, and an extra `results` field gives each record's outcome.
- Tuisku answers **2xx only after the transaction commits**. Each record runs inside its own
  `SAVEPOINT`, so a database error on one record cannot abort the batch. The response gives one
  result per line:
  - `accepted`: the raw record is stored. Its parse may still have failed; the response then
    adds `parse: failed`.
  - `duplicate`: the record was already stored.
  - `rejected`: the record is *not* stored because its envelope is malformed. Example: `raw`
    is missing or not a string.
  - A line longer than the line limit is **not** rejected. It is stored with its body truncated
    to the limit, its sha256 computed over the full line, and the flag `truncated`. It gets no
    parse attempt (`parse: skipped`) and raises the source's limit meta-detection. Over-long
    output from a sensor is therefore never silently lost.

  A shipper can therefore safely retry a partial batch.

### Limits (enforced at the boundary; configurable)

- **Request size**
  - Body size: 5 MiB. Larger bodies get 413 and are not truncated. OTLP exporters and log
    shippers usually do not retry a 413. Losslessness therefore depends on shipper settings,
    which the deployment guide states per shipper. For Vector:
    - the sink batch `max_bytes` must be below the body limit;
    - the file source's `max_line_bytes` must be at least the line limit, because Vector
      otherwise drops long lines before they reach Tuisku.
  - Lines per request: 5,000.
  - Line length: 256 KiB.
  - `collector` object: 4 KiB.
- **Parsed structure**
  - JSON nesting depth: 64.
  - Object keys per record: 4,096.
  - OTLP datapoints per body: 10,000. For OTLP bodies the datapoint cap and the body-size cap replace the
    key-count limit, which a 10,000-point body would otherwise exceed.
- **Per-source rate:** a token bucket of records per second. When the bucket is empty Tuisku
  returns 429. Shippers buffer and retry, so evidence is delayed, not lost.
- **Breaches:** exceeding a limit is recorded as a **meta-detection**, never silently absorbed.
  A meta-detection has:
  - kind `tuisku.meta.<name>`, for example `tuisku.meta.source_limit_exceeded`
  - evaluator `tuisku`, authorship `tuisku`, and no raw record
  - the source as an entity key

  At most one meta-detection is written per source, kind, *subject* and 5-minute bucket. The
  subject is the limit name for limit breaches and the rule id for `evaluation_failed`. A unique
  key on `(source_id, kind, subject, bucket)` with `ON CONFLICT DO NOTHING` enforces this, so it
  also holds across API replicas, and one failing rule cannot hide another. Repeats are counted
  in a mutable working table, `meta_counters`, never by updating the detection. Rules can select
  meta-detections by kind.

### Sources, tokens and roles

- A **source** is a registered sender. It has a name, an adapter (`suricata`, `zeek`, `falco`,
  `harava`), adapter options, and one or more **tokens**.
- **Token format and storage**
  - Tokens are 256-bit random values with a recognisable prefix (`tsk_src_`), so secret
    scanners catch leaks.
  - Only the SHA-256 is stored.
  - A token is shown once, when it is created.
- **Declarative registration** (amended 2026-11-13). `tuisku source ensure` creates a source if
  it is absent and registers a token that the deployment generated and holds in an environment
  variable (format checked, never printed), if its SHA-256 is not registered yet. It never
  changes an existing source or token: different adapter or options, a disabled source, and a
  revoked, expired or foreign token are errors. A deployment can therefore keep source tokens
  in its own secret store and run the command as a Job on every deploy, with the same database
  rights as `tuisku source add`.
- **Token lifecycle**
  - Each token has an optional expiry.
  - A source can hold several active tokens at once, so a token can be rotated without a gap
    and a leaked token revoked without disabling the source.
  - A token is valid only for its own source.
- **Operator tokens** (`tsk_op_`) carry a role, and each role includes the ones before it:
  - `read`: findings, incidents, evidence
  - `triage`: status changes, notes, dispositions, suppression
  - `admin`: sources, tokens, packs
- **Approval is separate from triage.** The `approve` role confirms hypotheses and approves
  proposed actions and evidence requests ([0009](0009-agent-runtime-and-authority.md)).
  - **Issued out of band.** Approve tokens and **person-bound operator tokens** cannot be
    created through the API, not even by an admin. A trigger on the token table rejects any row
    with the `approve` role or a non-null person unless `current_user = 'tuisku_owner'`. Such
    tokens are created only by `tuisku approver add --person …` and
    `tuisku operator-token add --person …`, which connect as the database owner. The API and
    worker never use that role.
    - API admins can create only tokens without a person.
    - An admin therefore cannot invent a person to start a session or to approve one.
    - Binding persons to an external identity provider (OIDC) is a later step. Until then, the
      person is whoever the database owner records.
  - **Four-eyes.** An approval is refused when the approving person is the person who started
    the investigator session that made the proposal.
  - **Network.** Deployments must keep operator and approve tokens off the network that the
    investigator runtime can reach.
- **Every request is attributed.** The token id is recorded on every raw record and on every
  timeline event the token causes.
- **Transport:** comparison is between hashes. TLS is terminated by the deployment (mesh or
  ingress) and is required outside a trusted network.

### Adapter contract

An adapter is a Python object registered under a name with a semantic version:

```python
class Adapter(Protocol):
    name: str  # "suricata"
    version: str  # "1.0.0" — bump on any change to output for the same input

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult: ...
```

`ParseResult` holds zero or more `ObservationDraft`s and `DetectionDraft`s. A detection draft
references observations from the same result by index, and carries `evaluator = sensor`, an
`authorship` ([0002](0002-epistemic-layers.md)) and a stable `identity` string
(`suricata:1:2045001`, `falco:Terminal shell in container`, `zeek:notice:Scan::Port_Scan`,
`harava:outbound_refused`). Rules:

1. **Pure and deterministic.** No I/O, no clock, no randomness, no network lookups, no
   enrichment. The same bytes and options always give the same drafts. Enrichment, such as asset
   inventory or GeoIP, is a separate, later, versioned step over stored observations.
2. **Split mixed layers.** Sensor facts become observations; sensor verdicts become detections.
3. **Keep everything.** Fields with no OCSF home go to `unmapped`. An unknown record type becomes
   a generic observation (`kind = "<adapter>.unknown"`) and is never dropped.
4. **Fail loudly, per record.** An exception or validation error is recorded as a failed
   `parse_attempts` row for that raw record and adapter version. The error text is truncated
   and never includes the raw body. The rest of the batch continues.
5. **Treat every field as hostile.**
   - bounded string lengths and strict types
   - no `eval`
   - IP addresses parsed with `ipaddress`
   - text formats parsed with anchored patterns whose matching is linear in input length (no
     nested quantifiers), and input capped before matching
6. **Respect upstream privacy guarantees.** For example, Harava never logs the refused URL or
   value. Its adapter must not try to reconstruct or enrich them.
7. **Fixtures are the spec.** Each adapter ships fixtures (synthetic, or from public sample sets
   whose licence is recorded) with golden expected outputs. A change in output without a version
   bump fails the tests.

Parsing runs **inside the ingest transaction**:

1. Insert the raw record. On conflict, record the duplicate receipt and stop.
2. Run the adapter.
3. Insert observations, detections and the parse attempt.
4. Enqueue the new rows for rule evaluation ([0006](0006-detection-rules-and-correlation.md)).

The adapter runs on already size-capped input with a per-record time budget. Rules and
correlation run asynchronously, so slow rules never apply back-pressure to sensors.

### First adapters

| Adapter | Input | Observations | Detections |
|---|---|---|---|
| `suricata` | EVE JSON: `alert`, `flow`, `dns` v2/v3, `http`, `tls`, `fileinfo`, `anomaly`; other types become generic | flow, DNS, HTTP, TLS and file facts | `alert` → authorship `local` for sids 1000000–1999999, `builtin` for 2200000–2299999, otherwise `community` (`gid:sid:rev`, signature, category, metadata); `anomaly` → `builtin` |
| `zeek` | JSON logs: `conn`, `dns`, `http`, `ssl`, `files`, `notice`, `weird`; epoch or ISO-8601 `ts`. The log type comes from the source's adapter option `log` (one source per log stream), or failing that from the record's own required fields, never from `collector` | conn, DNS, HTTP, SSL and file facts | `notice`, `weird` → `builtin` |
| `falco` | Falco JSON output: `rule`, `priority`, `source`, `tags`, `time`, `output_fields` | process, file and container facts from `output_fields` | rule match → `community`, or `local` if the rule name is listed in adapter options; priority mapped to severity; ATT&CK ids parsed from tags |
| `harava` | plain-text log lines (bare, or wrapped in Docker json-file or CRI format); OTLP JSON metrics | `harava.refusal` (one per refusal line); `harava.mcp_refused_to_serve` (a misconfiguration, so an observation only); `metric.sample` | `harava.outbound_refused` and `harava.destination_refused` → `builtin`. Destination refusals are logged only at the `admission` stage, so the adapter sets `stage = admission` |

## Consequences

- **Line-oriented text sources can be forged from inside.** A log message that contains a newline
  or a crafted exception text, or a continuation chunk of an over-long line (Docker splits at 16
  KiB, CRI writes partial `P` chunks), arrives as a separate line. Such a line can look exactly
  like a sensor verdict. Adapters flag partial and continuation chunks where the wrapper allows
  it. Pack rules that page on a text-log verdict should require corroboration from an
  independent channel of the same sensor where one exists, for example Harava's refusal
  counters over OTLP; without it, they should lower the severity.

- Shipper configuration is minimal and the same across sensors.
- All normalization can be reproduced from L0 inside Tuisku.
- Compromising one source token lets an attacker inject records for that source only. Injected
  records still carry their source, token id and receipt metadata, and that token can be revoked
  without a detection gap. Evidence that rests on a single source should be read with this in
  mind, and any future automated response must require corroboration
  ([0009](0009-agent-runtime-and-authority.md)).
