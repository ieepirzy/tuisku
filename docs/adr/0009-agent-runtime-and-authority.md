# 0009. Agent runtime interface and response authority

Status: Accepted as design (2026-11-01). Not built in the first milestone.

## Context

Issue #1 sets these requirements for agents:

- Agents investigate evidence through controlled tools.
- Their conclusions cite evidence.
- The runtime is harness-swappable by contract. Miragen is the reference runtime; alternatives
  include local or open models, third-party frameworks, and non-agent investigators.
- Authority is tiered: observe, investigate, recommend, contain, remediate.

Prompt injection is Tuisku's central design problem. Every string an agent reads from telemetry
may have been written by the attacker. What agents may do autonomously is a decision each
deploying estate makes for itself.

Anthropic's guidance for Claude-based agents is to put rules that must hold every time into
deterministic controls: deny rules, hooks, sandboxing, a narrow tool surface. Prompts are not
enough, because model judgement can be wrong (Claude Code best practices,
https://code.claude.com/docs/en/best-practices). Its Agent SDK documentation also says:
*"Unless previously approved, Anthropic does not allow third party developers to offer claude.ai
login or rate limits for their products, including agents built on the Claude Agent SDK"*
(https://code.claude.com/docs/en/agent-sdk/overview).

## Decision

### Tuisku exposes tools; the harness brings the model

1. Tuisku publishes an **investigation tool surface** over MCP, mirrored as an HTTP API. Each
   session is scoped to one incident. The tools:
   - read the incident and its timeline
   - list and get findings, detections and observations by id
   - pivot by entity key and time range
   - fetch a **redacted** view of an L0 record (see "Data handling")
   - run bounded, pre-defined queries, for example "other flows for this community id ±1h"
   - file an evidence request, chosen from a closed catalogue
   - submit hypotheses
   - propose actions, chosen from a closed catalogue
2. **Authority is enforced by the tool surface, not by the prompt.** Each investigator session
   gets a short-lived token (`tsk_inv_`) bound to one incident and one tier. The token expires
   when the session ends or the incident closes. The tiers:

   | Tier | Adds |
   |---|---|
   | `observe` | read-only tools |
   | `investigate` | bounded queries, evidence requests and raw-view access |
   | `recommend` | `propose_action` |

   `contain` and `remediate` are not exposed until a later ADR designs them as a security
   boundary. No Tuisku tool runs shell commands, reaches the open network, or changes
   infrastructure.
3. **The harness's own tools count too.** A harness may mount other tools beside Tuisku's: other
   MCP servers, shell, web fetch. An injected instruction could use those tools to exfiltrate data
   or act. The runtime contract therefore works like this:
   - The harness answers `start` with its complete tool list and network egress policy. That
     answer is the declaration.
   - Tuisku compares the declaration with a deployment allowlist for the tier, and **refuses**
     the session if it includes anything beyond Tuisku's tools and that allowlist.
   - The declaration is stored in the session's L4 record (`investigator_sessions`). The
     timeline only notes, by id, that a session started.
   - **Who can start a session.** Only the API, connecting as `tuisku_app`, can create the
     session row and its `tsk_inv_` token, and it does so only inside `start()`. A session can
     only be started with a person-bound operator token. That person is recorded as
     `started_by`, together with the session's tier and incident. Tuisku never starts sessions
     automatically; automatic starts are a later decision.
   - **Four-eyes.** The four-eyes rule compares *persons*, not tokens: a person never approves
     proposals from a session they started.
   - **The tool surface is a separate process** (`tuisku investigate`). It connects to Postgres
     as a separate `tuisku_investigator` role, which has no `tuisku_app` credentials.
     - **Reads:** the role can `SELECT` only what its tier allows.
     - **Writes:** it can `INSERT` into `hypotheses`, `tool_calls`, `proposed_actions` and
       `evidence_requests`, and nothing else. It cannot write `investigator_sessions`, and it
       cannot write L0–L3.
   - **Timeline events from L4 rows.** The matching timeline events (`hypothesis_added`,
     `evidence_requested`, `action_proposed`) are written by an `AFTER INSERT` trigger on each L4
     table. The trigger is owned by `tuisku_owner` and runs as `SECURITY DEFINER`.
     - It first checks that the referenced session exists, has not ended, and belongs to the
       same incident.
     - It also checks that the kind of row is allowed for that session's tier. For example, an
       `observe` session cannot insert `proposed_actions`.
     - It then writes only the L4 row id, the session id and an actor taken from the
       Tuisku-written session row.
   - **Session binding.** The surface sets the session id from the verified `tsk_inv_` token on
     each request.

   A declaration is only a claim, so the deployment must also enforce it: run the investigator
   runtime with no tools other than Tuisku's MCP server, and deny network egress except to the
   model provider and Tuisku.
4. **The runtime contract** is a small interface that **Tuisku calls on the harness**:
   - `start(incident, budget) -> declaration`: the harness describes itself. No token is
     issued yet.
   - `begin(session, token)`: called only after the declaration passed the check. It hands
     over the session's `tsk_inv_` token.
   - `continue(session, new_evidence)`
   - `cancel(session)`

   A person-bound operator action triggers the call. The harness never holds operator tokens;
   it gets only its session's `tsk_inv_` token.

   **Session lifecycle.** The session's end, its outcome and its token usage are recorded in an
   append-only `investigator_session_events` table. Only `tuisku_app` writes to it, from the
   calls above and from token expiry. The L4 trigger's "has not ended" check reads this table.

   The caller does not pick the session's **tier**. It comes from deployment policy, optionally
   raised for one incident by an `approve`-role operator, and is recorded at session start.

   Results come back only through the tools (`submit_hypothesis`, `propose_action`). Tuisku
   stores the session record in L4 tables (`investigator_sessions`, `tool_calls`), not in the
   incident timeline. The record holds:
   - the harness name and version
   - the model identifier the harness reports
   - the declaration
   - token usage
   - the tool-call log

   The timeline only records, as server-written events, that a session started or ended and its
   id ([0002](0002-epistemic-layers.md)). Tuisku does not depend on any harness's internals.
5. **Model credentials belong to the harness, not to Tuisku.** Tuisku never stores, requests or
   brokers model credentials, and it ships no login flow. Each deployment chooses how its harness
   authenticates, in line with the model provider's terms, including the restriction quoted
   above.

### Hypotheses are evidence-bound inference

- `submit_hypothesis` is validated deterministically. A hypothesis must carry:
  - at least one cited L0–L3 id that belongs to the session's incident
  - an epistemic status of `inferred` or `unknown`
  - a confidence between 0 and 1
  - optionally, an ATT&CK technique and an objective

  A hypothesis whose citations do not resolve is rejected, not stored.
- Hypotheses are L4 rows ([0002](0002-epistemic-layers.md)). They never change lower layers and
  are always shown labelled as inference. Only a human can mark one confirmed, as a timeline
  event.

### Actions and evidence requests

- **Closed catalogues.** Actions and evidence requests come from typed catalogues; there are no
  free-form commands. Example actions: "isolate workload X with a network policy", "revoke token
  Y", "open a ticket". Example evidence requests: "pull the pod's recent logs", "capture flows
  for N minutes".
- **Tainted parameters.** Any parameter derived from an attacker-controlled field is marked as
  tainted and shown that way to the approver. An evidence request never makes Tuisku contact a
  host named in telemetry.
- **Approval.** Until a containment ADR exists, only a person holding an `approve`-role token
  approves an action or an evidence request ([0005](0005-source-adapters-and-ingestion.md)).
  The person must differ from whoever started the session. No policy may auto-approve, and agent
  confidence or hypotheses are never inputs to approval. Execution credentials are never
  reachable from investigator sessions.
- **Corroboration.** Any future automated response must require corroborating evidence from more
  than one source, because a single compromised source token can forge evidence for its source
  ([0005](0005-source-adapters-and-ingestion.md)).

### Data handling

- **Redaction by default.** Agent tools return redacted views. Secrets and credentials are
  removed, including authorization headers, tokens in URLs and key-like strings. Personal-data
  fields such as user identifiers are pseudonymised. An agent cannot unlock unredacted L0
  itself. Unredacted L0 is only available through an evidence request that a person approves,
  and the request and approval are both recorded.
- **The model provider is a data processor.** Anything shown to an agent is sent to its model
  provider. A deployment that turns the agent layer on documents that provider as a processor
  and assesses data protection impact (a DPIA where GDPR applies) before enabling it on
  user-traffic sources.

### Prompt-injection posture

- Telemetry text reaches the model only inside clearly delimited, typed tool results, as JSON
  fields. It is never spliced into instructions. Fields known to be attacker-controlled (URLs,
  DNS names, user agents, command lines, file names, HTTP bodies) are marked as such in the
  result schema.
- The tier bounds what an injected instruction can achieve. At most, it produces a wrong
  hypothesis or a proposal that a human must approve. Nothing the agent writes executes.
- Harava's content-signal verdicts, and similar injection detectors, can be applied to evidence
  text before it is shown. Their results are ordinary L1/L2 rows from their own adapters. They
  appear as evidence like anything else and are not special-cased.

## Consequences

- The deterministic core ships first and is useful on its own. The agent layer plugs in later,
  with no schema changes beyond the L4 tables (`hypotheses`, `investigator_sessions`, `tool_calls`, `proposed_actions`, `evidence_requests`).
- Swapping Miragen for another harness changes no Tuisku code.
- Autonomous containment needs its own ADR, and the deploying estate's own decision.
