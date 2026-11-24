# 0013. Shirudo keepalives as a source

Status: Accepted (2026-11-24)

## Context

[Shirudo](https://github.com/shirudo-dev/shirudo) is an open-source Linux runtime that loads
signed eBPF programs and Java agents ("shields", called upatches in its code) to block exploit
paths on running systems until a real patch lands. Its targets pull signed packages from an
OCI registry, verify them in the kernel, and measure every load into a TPM register. It is
pre-release (`0.0.0-dev`) and needs a patched bpf-next kernel, a TPM 2.0 and a measured
unified kernel image.

A Shirudo target reports on itself over OTLP/HTTP JSON, and nothing else:

- a **keepalive** about once a minute (`shirudo status --otel`): one log record, event name
  `shirudo.keepalive`, whose `body.stringValue` is a compact JSON object of at most 4095 bytes
  (schema `shirudo.keepalive/1`, 23 keys in a fixed order) and whose one attribute,
  `shirudo.quote`, is a TPM quote of those bytes. The body carries the verdict of
  `shirudo status`, seven two-bit conditions, flag bits, 43 tamper counters and 22 integrity
  counters (refusals by Shirudo's guards since boot), the upatch tree position and a digest of
  the loaded set. It names no host and carries no time: the attestation key in the quote
  identifies the node, and the quote's TPM clock orders its keepalives;
- **map snapshots** (`shirudo upatch map --all`): what each upatch's BPF maps collected, as a
  log record whose body is whatever the upatch's signed Lua decoder returns (a structure, by
  default) or as metrics. Their fields differ per upatch.

Shirudo's documentation recommends three alerts on the keepalive (a verdict other than `ok`, a
rise of a tamper counter within one boot, and a target gone silent) and says plainly that
telemetry is the target's own account: root on a target can stop it or forge it, map snapshots
are not signed at all, and only `shirudo attest verify` proves what a target runs.

Several things in Tuisku shape how this fits:

- The OTLP logs endpoint hands an adapter only `body.stringValue`. Attributes and resource go to
  `collector`, which no adapter reads ([0005](0005-source-adapters-and-ingestion.md)), and a
  structured body is rejected as `body_not_string`.
- Rules can only see a rise in a counter through `metric.sample` deltas
  ([0006](0006-detection-rules-and-correlation.md), "Metric samples"), ordered by event time.
- Raw records are unique per source by the digest of the body
  ([0004](0004-storage.md) §5). The rule assumes sensors put a timestamp in every record;
  a keepalive has none.

## Decision

### A `shirudo` adapter for the keepalive

Tuisku ships a `shirudo` adapter (version 1.0.0) that interprets the keepalive and nothing
else. A valid `shirudo.keepalive/1` body becomes:

- one `shirudo.keepalive` observation with every field checked (hashes, the boot UUID, bounded
  printable strings, unsigned 64-bit integers), the conditions decoded by name
  (`not_evaluated`, `ok`, `warn`, `alert`), the flag bits by name, the counter arrays verbatim
  plus their totals and the non-zero counters by name;
- two `metric.sample` observations, `shirudo.tamper` and `shirudo.integrity`: the sum of each
  counter array as a cumulative, monotonic counter with the label `boot_id` and no
  `start_time`, and the non-zero counters by name in `counters`. No sample is written when the
  target reports a counter array as unreadable (`null`);
- when the verdict is not `ok`, one sensor detection `shirudo.status`, authorship `builtin`
  (it is Shirudo's own evaluation), identity `shirudo:verdict:<verdict>`. Severity follows the
  keepalive's own: `tampered` and `lsm-off` critical, `degraded` medium, `init-pending` and
  `reboot-pending` low, and any verdict this adapter does not know high, because Shirudo sends
  every verdict but the known WARN ones at ERROR.

Conditions, counters and flag bits that a newer Shirudo appends are kept under positional
names (`condition_7`, `counter_44`, `bit_9`) and flagged, as the format promises to append
rather than reorder. A body that claims `shirudo.keepalive/1` but breaks it becomes
`shirudo.unknown` with `reason: invalid_keepalive`. Another keepalive schema, any other JSON
object and an OTLP metrics request become `shirudo.unknown` with `unsupported_schema`,
`not_a_keepalive` or `otlp_metrics_not_interpreted`, and stay in the raw record.

### Per-boot series, so a reboot is a baseline

The counters start at zero at every boot and only grow within one. Each boot is therefore its
own series (`boot_id` in the labels), with no `start_time`. Under 0006 the first sample of a
series without a `start_time` is a baseline with delta 0. The refusals a normal boot makes
before its first keepalive (systemd's own BPF loads, for example) never fire, and neither does
a reboot. A rise between two keepalives of one boot is a positive delta. This is the comparison
Shirudo's own examples make (`max - min` of the counter sum per `boot_id`). Refusals between
boot and the first keepalive are not seen; the first keepalive follows boot by about five
seconds.

Totals, not one series per counter: 65 samples a minute per target would dominate the
observation table for counters that are almost always zero, and the sample's `counters` names
which ones moved.

### Event time is the receipt time

Every row the adapter writes takes the raw record's `received_at` as its event time and says so
(`time_source: received_at`). This is the first adapter to do so. The keepalive carries no time,
the record's `timeUnixNano` is display-only by Shirudo's own account, and the quote's clock is in
`collector`. Metric deltas need an order, and a keepalive goes out once a minute, so arrival
order is the target's order unless a pipeline reorders them. A collector between the target
and Tuisku should therefore send this source's records from one queue consumer. The adapter
stays deterministic: `received_at` is part of the raw record, so reprocessing gives the same
rows.

### The quote is kept, not checked

The quote reaches Tuisku as an OTLP attribute and stays in the raw record's `collector`, under
the 4 KiB cap, where `shirudo-quote-check` can verify it offline. Tuisku does not verify it and
draws no trust from it: a quote proves the body is unchanged since some key signed it, not that
the key is in a TPM. Keepalive rows are what a target says about itself.

### Identical keepalives are duplicates

A target whose state does not change sends byte-identical bodies, and 0004 §5 stores the first
and counts the rest in `raw_duplicates`. That is intended. It keeps a steady fleet to one stored
keepalive per state change, and every receipt stays countable. The cost is that the same state
does not produce a second detection: a target that stays `tampered` raises one detection, and
after an operator closes its incident nothing fires again until the keepalive changes (its
counters or tree move). A deployment that needs a page for a state that persists watches the
target's keepalives where they are also stored.

### A generic `shirudo` pack

The built-in `shirudo` pack follows Shirudo's recommended alerts:

- `shirudo.verdict_critical`: a `shirudo.status` detection at high or above opens an incident;
- `shirudo.verdict_degraded`: `degraded` becomes a finding;
- `shirudo.tamper_rise` and `shirudo.integrity_rise`: the counter sum rose within one boot by
  at least 1 in 10 minutes (params `tamper_rise_threshold`, `integrity_rise_threshold`); each
  opens an incident;
- `shirudo.invalid_keepalive`: a body that breaks the format it claims.

A target gone silent is not covered. Tuisku has no rule for records that do not arrive.

### Out of scope

- **Map snapshots and decoder metrics.** Their fields are per upatch; rules for them are a
  deployment's own, and a later adapter version can interpret decoders that ship as fixtures.
  Structured snapshot bodies are refused by the OTLP logs endpoint, so a deployment that also
  exports snapshots sends Shirudo's telemetry to an OpenTelemetry Collector and forwards only
  the keepalives (instrumentation scope `shirudo.keepalive`) to Tuisku, with the body as it
  arrived.
- **Tuisku acting on Shirudo.** Drafting or deploying a shield from an incident is a response
  action under [0009](0009-agent-runtime-and-authority.md): a closed catalogue, human
  approval, and Shirudo's operator key never in Tuisku. It needs its own ADR.
- **Coexistence.** On an enforcing Shirudo target only signed upatches may load BPF programs,
  so Falco's eBPF drivers cannot run there. That is a deployment choice, not Tuisku's.

## Consequences

- Deployments that run Shirudo get its three recommended alerts, minus silence, from the
  keepalive alone, through the existing OTLP logs endpoint.
- The `received_at` event time and the deduplication of identical keepalives are specific to
  this source and are stated in its rows and in this record.
- Shirudo's format is young. The adapter pins `shirudo.keepalive/1` and keeps anything else as
  `shirudo.unknown`, so a format change shows up as unknown rows, not as wrong ones.
