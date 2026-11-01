# 0009. Agent runtime interface and response authority

Status: Accepted as design (2026-11-01). Not built in the first milestone.

## Context

Issue #1 sets these requirements. Agents investigate evidence through controlled tools. Their
conclusions cite evidence. The runtime is harness-swappable by contract: Miragen is the
reference, and alternatives include local or open models, third-party frameworks and
non-agent investigators. Authority is tiered: observe, investigate, recommend, contain,
remediate.

Prompt injection is Tuisku's central design problem: every string an agent reads from telemetry
may have been written by the attacker. What agents may do autonomously is a decision each
deploying estate makes for itself; for the first deployment it is still open.

Anthropic's guidance for Claude-based agents: rules that must hold every time belong in
deterministic controls (deny rules, hooks, sandboxing, a narrow tool surface), not in prompts,
because model judgement can be wrong (Claude Code best practices,
https://code.claude.com/docs/en/best-practices). Its Agent SDK documentation adds: *"Unless
previously approved, Anthropic does not allow third party developers to offer claude.ai login
or rate limits for their products, including agents built on the Claude Agent SDK"*
(https://code.claude.com/docs/en/agent-sdk/overview).

## Decision

### Tuisku exposes tools; the harness brings the model

1. Tuisku publishes an **investigation tool surface**, served over MCP and mirrored as an HTTP
   API, scoped to one incident per session:
   - read the incident and its timeline
   - list and get findings, detections and observations by id
   - pivot by entity key and time range
   - fetch an L0 record's body, quoted and size-capped
   - run bounded, pre-defined queries such as "other flows for this community id ±1h" or "DNS
     answers for this domain"
   - request more evidence, as a recorded request that a human or a deterministic collector
     fulfils
   - submit hypotheses
   - propose actions
2. **Authority is enforced by the tool surface, not by the prompt.** Each investigator session
   gets a token bound to one incident and one tier:
   - `observe`: reads only
   - `investigate`: adds bounded queries and evidence requests
   - `recommend`: adds `propose_action`
   - `contain` and `remediate`: not exposed until a later ADR designs them as a security
     boundary

   A tool the tier lacks does not exist for that session. No tool runs shell commands, reaches
   the open network, or changes infrastructure.
3. **The runtime contract** is a small interface: `start(incident, tier, budget)`,
   `continue(session, new_evidence)`, `cancel(session)`. Results come back only through the
   tools (`submit_hypothesis`, `propose_action`). Tuisku records the harness name and version,
   the model identifier the harness reports, the session id, token usage and tool-call log in
   the incident timeline. Tuisku does not depend on any harness's internals.
4. **Model credentials belong to the harness, not to Tuisku.** Tuisku never stores, requests or
   brokers model credentials, and it ships no login flow. Whether a given deployment's harness
   authenticates with an API key or with a subscription is a decision for whoever runs that
   harness, and must follow the model provider's terms. For Claude that means the restriction
   quoted above. The first deployment's operator intends to use subscription login. Before that
   is wired up, the operator confirms it is permitted for this use.

### Hypotheses are evidence-bound

- `submit_hypothesis` validates deterministically. It requires at least one cited id from L0–L3
  that belongs to the session's incident, an epistemic status (`observed | inferred | verified
  | unknown`), a confidence between 0 and 1, and optional ATT&CK technique and objective. A
  hypothesis whose citations do not resolve is rejected, not stored.
- Hypotheses are L4 rows ([0002](0002-epistemic-layers.md)). They never change lower layers and
  are shown labelled as inference.

### Prompt-injection posture

- Telemetry text reaches the model only inside clearly delimited, typed tool results, as JSON
  fields, never spliced into instructions. Fields known to be attacker-controlled (URLs, DNS
  names, user agents, command lines, file names, HTTP bodies) are marked as such in the result
  schema.
- What an injected instruction can achieve is bounded by the tier: at most, a wrong hypothesis
  or a proposed action that a human or policy must approve. Nothing the agent writes executes.
- Harava's content-signal verdicts, and similar injection detectors, can be applied to evidence
  text before it is shown. A `likely` verdict is recorded on the incident as a signal in its own
  right.

## Consequences

- The deterministic core ships and is useful first. The agent layer plugs in later without
  schema changes beyond `hypotheses` and `proposed_actions` tables.
- Swapping Miragen for another harness changes no Tuisku code.
- Autonomous containment needs its own ADR, and the deploying estate's own decision.
