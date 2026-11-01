# 0002. Epistemic layers and the evidence model

Status: Accepted (2026-11-01)

## Context

Issue #1 makes epistemic separation a hard requirement: the system must keep apart directly
observed fact, deterministic detector output, community-supplied rule interpretation, and agent
inference. Real sensor records mix these. A Suricata `alert` carries a 5-tuple (a fact about
packets seen) and a signature verdict (a community rule author's interpretation). A Falco event
carries process fields (fact) and a rule name (interpretation). If one row holds both, the
distinction is lost the moment it is stored.

Neighbouring systems already draw similar lines: Apogee's claims carry an epistemic status of
`observed | inferred | verified | unknown` with mandatory evidence references, and Loimi
separates deterministic
provenance from suggested relevance.

## Decision

Tuisku stores information in five layers. The layer is a property of the **table**, not a
column value, so a row cannot drift between layers.

| Layer | Table(s) | Produced by | Example |
|---|---|---|---|
| L0 raw record | `raw_records` | the sender, verbatim | one EVE JSON line, one log line, one OTLP request body |
| L1 observation | `observations` | a versioned adapter, deterministically from L0 | a network flow, a DNS answer, a process exec, a metric delta |
| L2 detection | `detections` | a deterministic mechanism | Zeek `notice`, Suricata signature match, Falco rule match, Harava refusal, a Tuisku rule |
| L3 finding / incident | `findings`, `incidents` | Tuisku's deterministic rules and humans | "agent caller had outbound data refused 3× in 1h" |
| L4 inference | `hypotheses` (later) | an agent or other investigator | "likely objective: exfiltration via an agent tool" |

Detections carry an **origin** that keeps the third epistemic category (community
interpretation) visible:

- `sensor_native` — the sensor's own built-in logic (Zeek `notice`/`weird`, Suricata `anomaly`,
  Harava's refusal checks).
- `community_rule` — a third-party rule evaluated by a sensor (a Suricata signature with its
  `gid:sid:rev`, a Falco rule). The rule identity, revision and ruleset travel with it.
- `tuisku_rule` — a rule from a Tuisku rule pack, evaluated by Tuisku
  ([0006](0006-detection-rules-and-correlation.md)).

Rules for every layer:

1. **Adapters split mixed records.** A Suricata alert becomes one L1 observation (the flow facts)
   and one L2 detection (`community_rule`) that references it. Neither copies the other's fields.
2. **References point down, never up.** Each derived row names the rows it was derived from
   (`raw_record_id`; detection → observations; finding → detections; incident → findings;
   hypothesis → any lower-layer ids). Nothing at a lower layer is changed by anything above it.
3. **Derivations are versioned.** Every L1/L2 row records `adapter@version` (or rule
   `id@rev` and pack version). Re-running a newer adapter over the same L0 produces new rows;
   it does not edit old ones.
4. **L0 is never deleted by the application.** Retention is an explicit, configured policy
   ([0004](0004-storage.md)), not a side effect.
5. **Agent output never lands in L0–L3 tables.** An investigator writes L4 hypotheses that must
   cite at least one lower-layer id and carry an epistemic status (`observed | inferred |
   verified | unknown`, matching Apogee) and a confidence. A human decision on an incident is
   recorded as a timeline event with the human as actor, not as a rewrite.
6. **Parse failures are evidence too.** A raw record an adapter cannot parse is stored with
   `parse_status = 'failed'` and the error, and is visible to operators. Malformed input aimed at
   the parser is itself a signal.

## Consequences

- Queries across layers need joins; that is the price of never confusing them.
- An investigator (or a person) can always ask "which of this is fact, which is someone's rule,
  which is a guess", and get an answer from the schema rather than from prose.
- Reprocessing with a fixed adapter is safe and auditable.
