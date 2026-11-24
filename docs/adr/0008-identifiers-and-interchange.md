# 0008. Identifiers, vocabularies, and interchange with other systems

Status: Accepted (2026-11-01)

Edited 2026-11-23 and 2026-11-24: wording generalised.

## Context

Tuisku will later exchange knowledge with other systems. Neither side may own the other
(issue #1).

What interchange needs is a contract on Tuisku's side, not knowledge of how the other systems
store their data:

- A record Tuisku exports is immutable. A later change is a new record that supersedes it.
- Each exported record carries a kind, its event time, its properties, and one-hop provenance:
  the records it was derived from.
- The same thing (an address, a domain, a file digest, an attack technique, a weakness) is
  written the same way on every side, so systems correlate by value instead of by shared tables.

## Decision

### Entity keys

Every observation, detection, finding and incident carries `entity_keys text[]`. These are
typed, normalized keys that make pivots and cross-system links possible:

| Key | Form | Normalization |
|---|---|---|
| IP address | `ip:203.0.113.5`, `ip:2001:db8::1` | `ipaddress` compressed form |
| Domain | `domain:example.com` | lowercase, IDNA A-label, no trailing dot |
| Host / node | `host:<hostname>` | lowercase |
| Kubernetes workload | `k8s:<namespace>/<pod>`; `k8s-ns:<namespace>` | as reported |
| Container image | `image:<repository>` | as reported |
| File / artifact | `sha256:<hex>` | lowercase hex |
| Process | `process:<host>/<pid>/<start>` when the start time is known | |
| Caller / identity | `caller:<source>/<name>` (for example `caller:egress-guard/example-agent`); later `identity:<idp>/<subject>` | |

A cluster or tenant qualifier can be prefixed when Tuisku watches more than one estate. That is
a later decision; keys are strings, so adding it is a data migration, not a schema change.

### External vocabularies, verbatim

These go in attributes and are never Tuisku enums:

- MITRE ATT&CK technique ids (`T1567`, `T1059.004`), recorded with the ATT&CK version they were
  mapped against.
- Sensor rule identities: Suricata `gid:sid:rev`, Falco rule name, Zeek notice name.
- CVE ids, CWE ids and CVSS v4 vectors when present.
- OCSF class and status names for export.

### STIX 2.1 identity for shareable things

Objects that leave Tuisku as STIX get ids by the STIX rules:

- **Cyber observables (SCOs):** UUIDv5 in the STIX SCO namespace
  (`00abedb4-aa42-466c-9c01-fed23315a9b7`), computed over the ID-contributing properties
  serialized with RFC 8785 (JCS). The same IP, domain or file hash therefore gets the same id
  from Tuisku or anyone else.
- **Domain and relationship objects** (`indicator`, `sighting`, `observed-data`, `grouping`,
  `note`): UUIDv5 in a **Tuisku-specific namespace**
  (`e45f460c-9810-4548-8a33-e0b6397b6608`), computed over the Tuisku `uid` of the source row.
  Re-exporting the same row is then idempotent, and the SCO namespace is never used for SDOs.
  STIX 2.1 recommends (SHOULD) UUIDv4 for these objects; we deviate on purpose so that exports
  are idempotent.

This prepares the purple-team loop: an offensive-security tool can later publish
*expected indicators* (`indicator` linked to an `attack-pattern`), and Tuisku records a STIX
`sighting` when an observation matches one.

### Export to a knowledge store (curated, not raw)

- Tuisku keeps its operational state (L0–L3, incidents) in its own Postgres. It **exports
  curated, durable records to a knowledge store**: closed or escalated incidents, their
  findings, and later L4 hypotheses. Raw telemetry and observations are never exported:
  telemetry can contain personal data, and Tuisku keeps it under its own retention policy.
- Kinds are Tuisku's own, prefixed `tuisku_`: `tuisku_incident`, `tuisku_finding`, and later
  `tuisku_hypothesis`, `tuisku_rule_pack` (a pack version as published). Each incident status
  change after export is exported as a new record that supersedes the previous one. A record's
  time is the event time, and its properties carry the entity keys, ATT&CK ids, rule refs and
  Tuisku `uid`s.
- **Personal data is minimised on export.** IP, identity and caller entity keys are
  pseudonymised by default. The pseudonym is HMAC-SHA-256 under a deployment-held key, with the
  type prefix kept (`ip:hmac:…`). Correlation inside the estate still works, and the raw values
  stay in Tuisku under its retention policy. Notifications follow the same rule. Exported
  hypotheses are labelled `inference`, so no reader, including another agent, takes them for
  fact.
- **STIX exports choose per channel.** A pseudonym cannot be a STIX SCO value. Each STIX channel
  is therefore configured one of two ways:
  - **real values:** for trusted sharing, with deterministic SCO ids
  - **no SCOs:** SDOs only, with entity references in a custom `x_tuisku_entity_keys` property
    holding the pseudonyms
- Provenance stays one hop: a `tuisku_finding` names the `tuisku_rule_pack` record it came
  from; a `tuisku_hypothesis` names the findings it cites.
- Export is a separate, idempotent job keyed by Tuisku `uid`. It is not in the first milestone.
  Tuisku's preconditions for building it: a property schema for each `tuisku_*` kind, and a
  destination that restricts who can read security records.

### Links, not foreign keys

Across systems, references are the other system's record ids, STIX ids, or entity keys. No cross-database
foreign keys and no shared tables.

## Consequences

- Correlating Tuisku with another system is a join on entity keys and ATT&CK ids, with no
  shared schema.
- Agents (Tuisku's own, or ones an agent runtime hosts) can pivot on keys without
  knowing sensor formats.
- A knowledge store that receives exports stays a knowledge store, not a SIEM.
