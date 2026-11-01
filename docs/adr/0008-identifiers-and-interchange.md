# 0008. Identifiers, vocabularies, and interchange with Loimi and Apogee

Status: Accepted (2026-11-01)

## Context

Tuisku must later exchange knowledge with **Loimi** (the organization's immutable artifact store
with provenance) and **Apogee** (offensive security: "how can this system be broken?") without
either owning the other (issue #1). Facts from the neighbours:

- Loimi artifacts are immutable, have a free-text `kind`, `properties` JSON, one-hop `sources`
  provenance, an `as_of` event time, and supersession for change. It is a general knowledge
  store, not a security data store.
- Apogee keeps mutable operational state in its own database and durable findings in Loimi,
  under `apogee_*` kinds. It records CVSS vectors and CWE ids verbatim, uses an OCSF-derived
  status lifecycle, and makes claims with `observed | inferred | verified | unknown` status plus
  evidence references. Its digests are algorithm-prefixed (`sha256:…`), and a target is a domain.

## Decision

### Entity keys

Every observation, detection, finding and incident carries `entity_keys text[]`. These are
typed, normalized keys that make pivots and cross-system links possible:

| Key | Form | Normalization |
|---|---|---|
| IP address | `ip:203.0.113.5`, `ip:2001:db8::1` | `ipaddress` compressed form |
| Domain | `domain:example.com` | lowercase, IDNA A-label, no trailing dot (matches Apogee's target domain) |
| Host / node | `host:<hostname>` | lowercase |
| Kubernetes workload | `k8s:<namespace>/<pod>`; `k8s-ns:<namespace>` | as reported |
| Container image | `image:<repository>` | as reported |
| File / artifact | `sha256:<hex>` | lowercase hex (matches Apogee's digests) |
| Process | `process:<host>/<pid>/<start>` when the start time is known | |
| Caller / identity | `caller:<source>/<name>` (for example `caller:harava/agents`); later `identity:<idp>/<subject>` | |

A cluster or tenant qualifier can be prefixed when Tuisku watches more than one estate. That is
a later decision; keys are strings, so adding it is a data migration, not a schema change.

### External vocabularies, verbatim

These go in attributes and are never Tuisku enums:

- MITRE ATT&CK technique ids (`T1567`, `T1059.004`), recorded with the ATT&CK version they were
  mapped against.
- Sensor rule identities: Suricata `gid:sid:rev`, Falco rule name, Zeek notice name.
- CVE, CWE and CVSS v4 vectors when present, the same as Apogee.
- OCSF class and status names for export.

### STIX 2.1 identity for shareable things

Objects that leave Tuisku as STIX get ids by the STIX rules:

- **Cyber observables (SCOs):** UUIDv5 in the STIX SCO namespace
  (`00abedb4-aa42-466c-9c01-fed23315a9b7`), computed over the ID-contributing properties
  serialized with RFC 8785 (JCS). The same IP, domain or file hash therefore gets the same id
  from Tuisku, Apogee or anyone else.
- **Domain and relationship objects** (`indicator`, `sighting`, `observed-data`, `grouping`,
  `note`): UUIDv5 in a **Tuisku-specific namespace**
  (`e45f460c-9810-4548-8a33-e0b6397b6608`), computed over the Tuisku `uid` of the source row.
  Re-exporting the same row is then idempotent, and the SCO namespace is never used for SDOs. This prepares the purple-team loop: Apogee can later publish
*expected indicators* (`indicator` linked to an `attack-pattern`), and Tuisku records a STIX
`sighting` when an observation matches one.

### Loimi export (curated, not raw)

- Tuisku keeps its operational state (L0–L3, incidents) in its own Postgres. It **exports
  curated, durable records to Loimi**: closed or escalated incidents, their findings, and later
  L4 hypotheses. Raw telemetry and observations are never exported: telemetry can contain
  personal data, and Loimi is not meant to hold it.
- Kinds, prefixed like Apogee's: `tuisku_incident`, `tuisku_finding`, and later
  `tuisku_hypothesis`, `tuisku_rule_pack` (a pack version as published). Each incident status
  change after export is a Loimi supersession. `as_of` is the event time and `properties` carry
  the entity keys, ATT&CK ids, rule refs and Tuisku `uid`s.
- **Personal data is minimised on export.** IP, identity and caller entity keys are
  pseudonymised by default, using HMAC-SHA-256 with a deployment-held key and the type prefix
  kept (`ip:hmac:…`). Correlation inside the estate still works, and the raw values stay in
  Tuisku under its retention policy. Exported hypotheses are labelled `inference`, so a reader,
  including another agent, never takes them for fact. Notifications and STIX exports follow the
  same rule unless a deployment explicitly turns it off for a channel.
- Provenance stays one hop: a `tuisku_finding` lists the `tuisku_rule_pack` artifact it came
  from in `sources`; a `tuisku_hypothesis` lists the findings it cites.
- Export is a separate, idempotent job keyed by Tuisku `uid`. It is not in the first milestone.
  Registering the `tuisku_*` kinds with property schemas, and the access model
  for security records, are agreed with Loimi before export is built.

### Links, not foreign keys

Across systems, references are Loimi artifact ids, STIX ids, or entity keys. No cross-database
foreign keys and no shared tables.

## Consequences

- Correlating Tuisku and Apogee is a join on entity keys and ATT&CK ids, with no shared schema.
- Agents (Tuisku's own or Miragen-hosted) can pivot on keys without knowing sensor formats.
- Loimi stays a knowledge store, not a SIEM.
