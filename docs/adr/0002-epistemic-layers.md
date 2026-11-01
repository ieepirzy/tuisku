# 0002. Epistemic layers and the evidence model

Status: Accepted (2026-11-01)

## Context

Issue #1 makes epistemic separation a hard requirement. The system must keep apart four kinds
of knowledge:

1. directly observed fact
2. deterministic detector output
3. community-supplied knowledge or rule interpretation
4. agent inference

Real sensor records mix these. A Suricata `alert` carries a 5-tuple, which is a fact about
packets seen, and a signature verdict, which is a rule author's interpretation. A Falco event
carries process fields (fact) and a rule name (interpretation). If one row holds both, the
distinction is lost the moment it is stored. The same rule can also be written by one party and
evaluated by another: a community pack can be evaluated by Tuisku, and an operator's local
Suricata rule is evaluated by Suricata.

Neighbouring systems draw similar lines. Apogee's claims carry an epistemic status
(`observed | inferred | verified | unknown`) with evidence references. Loimi separates
deterministic provenance from suggested relevance.

## Decision

### Layers are tables

| Layer | Table(s) | Produced by | Example |
|---|---|---|---|
| L0 raw record | `raw_records` (+ `parse_attempts`, `raw_duplicates`) | the sender, verbatim | one EVE JSON line, one log line, one OTLP request body |
| L1 observation | `observations` | a versioned adapter, deterministically from L0 | a network flow, a DNS answer, a process exec, a metric sample |
| L2 detection | `detections` | a deterministic mechanism evaluating a rule or built-in check | Zeek `notice`, Suricata signature match, Falco rule match, Harava refusal, a Tuisku pack rule |
| L3 finding / incident | `findings`, `incidents`, `incident_events` | Tuisku's deterministic grouping, and people | "the agent caller had outbound data refused 3× in 1h" |
| L4 inference | `hypotheses`, `investigator_sessions`, `tool_calls`, `proposed_actions`, `evidence_requests` (later) | an agent or other investigator | "likely objective: exfiltration through an agent tool" |

A row's layer is fixed by the table it is in and cannot change.

### Inside L2: who wrote the rule, and who ran it

Every detection has two required columns, which keep issue #1's third category visible. They
are not merged into one flag:

- `evaluator`: `sensor` (Suricata, Zeek, Falco, Harava decided) or `tuisku` (a Tuisku rule pack
  rule fired in the worker).
- `authorship`: who wrote the logic.
  - `builtin`: shipped with the sensor as its own logic. Examples: Zeek's notice scripts,
    Suricata's protocol anomaly checks, Harava's refusal checks.
  - `community`: a third-party rule set, such as ET Open, Falco's default rules, or a community
    Tuisku pack.
  - `local`: written by the deploying estate.
  - `tuisku`: a pack shipped in this repository.

Adapters infer authorship conservatively and allow an override through adapter options.
Suricata signature ids 1000000–1999999 are reserved for local rules by convention; every other
sid is `community`. Falco rules default to `community`, and a deployment can list its local rule
names. A pack declares its authorship in its manifest ([0006](0006-detection-rules-and-correlation.md)).

### Rules for every layer

1. **Adapters split mixed records.** A Suricata alert becomes one L1 observation (the flow facts)
   and one L2 detection (evaluator `sensor`, authorship by sid) that references it. Neither
   copies the other's fields.
2. **References point down, never up.** Each derived row names what it was derived from:
   - an observation names its `raw_record_id`
   - a detection names its observations
   - a finding names its detections
   - an incident names its findings
   - a hypothesis names lower-layer ids

   Nothing at a lower layer is changed by anything above it.
3. **Derivations are versioned.** Every L1/L2 row records the `parse_attempt_id` that produced
   it, and through that `adapter@version`. For a rule, it records `id@rev` plus the pack version
   and hash. Re-running a newer adapter over the same L0 writes a new parse attempt and new rows.
   The **current** derivation of a raw record is derived, not stored: it is the newest
   *successful* parse attempt, so a newer attempt that fails leaves the previous one current. Old
   rows stay, and rules read only rows from current attempts
   ([0006](0006-detection-rules-and-correlation.md)).
4. **Evidence rows are never deleted by the application.** Retention clears L0 bodies and
   redacts L1/L2 payloads through one audited database function. It keeps the rows, their hashes
   and a tombstone ([0004](0004-storage.md)).
5. **Agent output never lands in L0–L3 tables.** Everything an investigator produces is stored
   in L4 tables: hypotheses, session records (the harness declaration, the model, usage and the
   tool-call log), and proposed actions and evidence requests.
   - A hypothesis must cite at least one lower-layer id. It carries the status `inferred` or
     `unknown` and a confidence.
   - The incident timeline (L3) may record *that* an L4 row was added. It does this only as a
     server-written event whose actor and L4 row id are set by Tuisku. It never copies L4
     content.
   - An agent cannot label its own output as observed or verified. Confirming a hypothesis is a
     human act, recorded as a timeline event with an approving person as the actor
     ([0009](0009-agent-runtime-and-authority.md)).
6. **Parse failures are evidence too.** When an adapter cannot parse a raw record, that is
   recorded in `parse_attempts` with the error. The raw record itself is never updated. Malformed
   input aimed at the parser is itself a signal, and operators can see it.

## Consequences

- Queries across layers need joins. That is the price of never confusing them.
- An investigator, human or agent, can ask "which of this is fact, which is whose rule, which is
  a guess" and get the answer from the schema rather than from prose.
- Reprocessing with a fixed adapter is safe and auditable, and it does not count events twice.
