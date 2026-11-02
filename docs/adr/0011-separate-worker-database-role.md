# 0011. Separate worker database role

Status: Accepted (2026-11-02). Amends [0004](0004-storage.md) section 3.

## Context

ADR 0004 gives the API and the worker one app role, `tuisku_app`. That role could insert
`tuisku`-evaluated detections, `rule_firings`, `detection_evidence` and the finding and incident
link tables, because the worker needs them.

The worker skips a row for a rule once a firing key exists for it, which is how firings stay
idempotent ([0006](0006-detection-rules-and-correlation.md)). Review found two ways for the app
role to forge such a key and so hide a page:

1. insert a throwaway rule detection, then a `row` key for the victim row;
2. append a `detection_evidence` row tying an old rule detection to the victim, then a `member`
   key.

The API faces the network and parses attacker-controlled input, so it is the most likely
component to be compromised. A compromised API must be able to add evidence, but it must not be
able to forge rule output or firing keys.

## Decision

- **Two runtime roles.** The API (ingest, read and triage) connects as the app role
  (`TUISKU_APP_ROLE`). `tuisku worker` connects as a separate worker role (`TUISKU_WORKER_ROLE`,
  default `tuisku_worker`). Neither owns the schema, and `tuisku migrate` grants both. Both are
  built into revisions 0001 and 0002, which had not been merged or deployed, so both revisions
  stay expand-only.
- **What the API role can write**, and nothing else:
  - `raw_records`, `raw_duplicates`: `INSERT`. Each raw record stores the source name it
    arrived with (`source_name`), set by a trigger from `sources` whatever the writer supplies,
    and rules match on that name.
  - `parse_attempts`, `observations`: `INSERT` only together with their record (a trigger):
    an attempt only for a raw record inserted in the same transaction, and an observation only
    for an attempt of the same raw record from the same transaction. So the API role cannot
    supersede a stored record's derivation and make its rows stale.
  - `detections`: `INSERT` of sensor detections, under the same same-transaction rule as
    observations. Of `tuisku`-evaluated rows, only its own
    ingest meta-detections: kinds `source_limit_exceeded`, `source_rate_limited` and
    `invalid_envelope`, with a source, identity equal to the kind, and the current 5-minute
    bucket by the database clock (a trigger).
  - `detection_observations`: `INSERT` only of links between a sensor detection and an
    observation of the same parse attempt, both from the same transaction (a trigger).
  - `evaluation_queue`: `INSERT` of `observation_id`, `detection_id` and `enqueued_at` only,
    and only for an observation or detection inserted in the same transaction (a trigger).
  - `meta_counters`: `SELECT`, `INSERT`, `UPDATE (count)` (the breach-count upsert), only for
    its own ingest kinds with a source (a trigger). Row-level security hides every other
    counter from it, so it cannot row-lock the worker's.
  - `sources`, `source_tokens`: `SELECT`, `INSERT`, never `UPDATE` or `DELETE`. A source is
    disabled by inserting a `source_admin_requests` row, and a token revoked by inserting a
    `token_revocations` row; owner triggers apply both. Both request tables are append-only.
    When a token was last used is kept in the API-only `source_token_usage` table, which the
    worker never reads. Sources are renamed only by the owner.
  - `operator_tokens`: `SELECT`, `INSERT` of tokens without a person (read, triage, admin;
    person-bound and approve tokens stay owner-only, ADR 0005), never `UPDATE` or `DELETE`. A
    token is revoked by inserting an `operator_token_revocations` row (append-only), which an
    owner trigger applies, so a revocation cannot be undone; authentication and triage also
    check the revocation rows. Person-bound and approve tokens are revoked only by the owner.
    On `operator_tokens`, `sources` and `source_tokens` rows the API role creates, a trigger
    sets `created_at` (and any `revoked_at` or `disabled_at` given) to `now()`. The worker
    never reads `operator_tokens`.
  - `triage_requests`: `INSERT` only (append-only, `requested_at` forced to `now()`). The API
    role has no `UPDATE` on `findings` or `incidents` and no `INSERT` on their events. Each
    triage request is applied by an owner trigger (`SECURITY DEFINER`) with the rules of ADR
    0007. The actor must be an `operator:<uid>` naming a live operator token (not revoked, not
    expired, holding `triage` or `admin`), and the request must come with that token's bearer
    secret: the API sets it for the transaction only (`set_config('tuisku.operator_token', ...,
    true)`, cleared after the insert, never stored), and the trigger hashes it and matches it
    against the token's `token_sha256`. A missing or mismatched secret is refused. This stops
    the API role from attributing triage to an operator whose token it has not seen. It does
    not stop a compromised API process from reusing a token presented to it while it is
    compromised, or from triaging as a token it issued itself; both are attributed to that
    token. Only attachable findings change, and a finding is
    never set to `expired`. A suppression needs an expiry and a reason, and ends within 30
    days of the finding's first suppression, so a lift and re-suppress does not restart the
    clock. The trigger sets the suppression's start and count itself. Incidents move only
    along the transition table, and closing needs a disposition. Closing or resolving an
    incident resolves its attachable findings. Every change writes its event. A refused
    request raises SQLSTATE `TK404` (no such target) or `TK409` (not allowed), which the API
    answers 404 and 409, as before.
  - `notifications`: nothing. The pages triage causes are written by owner triggers running as
    `SECURITY DEFINER`, whoever made the change: a finding leaving `suppressed` (to `open`,
    `acknowledged` or `resolved`, directly or through its incident being closed or resolved)
    pages every threshold crossed meanwhile, and an incident reopened pages an escalation.
    `notifications.created_at` is the database clock for every role.
- **What the API role cannot write**, at all: `detection_evidence`, `rule_firings`,
  `finding_detections`, `incident_findings`, `finding_overflow_groups`, `pack_loads`,
  `notification_deliveries`, `evaluation_dead_letter`, `evaluation_dead_letter_rules`,
  `evaluation_attempts`, `notifications`, new findings or incidents, rule detections, queue
  claims, updates or deletes, any `UPDATE` of a table the worker reads or writes, any event,
  and the worker's meta kinds (`evaluation_failed`,
  `notification_undeliverable`, `backlog`) in any bucket.
- **Functions and temporary tables.** No `tuisku_*` function is executable by PUBLIC. Firing a
  trigger needs no `EXECUTE`. Only the read-only helpers `tuisku_is_worker()`,
  `tuisku_xmin_is_current()` and `tuisku_current_bucket()` are granted, to both runtime roles.
  Every trigger function checks `TG_RELID`, `TG_WHEN`, `TG_OP` and `TG_LEVEL`, and refuses to
  run anywhere but on its own table. PUBLIC has no `TEMP` on the database, and the migration
  stops if a runtime role still has it. So no role can attach a Tuisku trigger function,
  least of all a `SECURITY DEFINER` pager, to a table of its own.
- **No row locks the worker waits on, no table locks, no advisory locks.** A row lock needs
  `UPDATE` (or `DELETE`). The only tables the API role may update are `meta_counters` (its own
  ingest counters; row-level security hides the rest) and `source_token_usage`, neither of
  which the worker locks or writes. So `FOR UPDATE`,
  `FOR NO KEY UPDATE`, `FOR SHARE` and `FOR KEY SHARE` are refused on every other table. `LOCK
  TABLE` above `ROW EXCLUSIVE` needs table-level `UPDATE`, `DELETE` or `TRUNCATE`, which the
  API role holds only on `source_token_usage`. Postgres checks no privilege on advisory locks,
  so the worker uses none. The drain takes a row lock on the worker-only `worker_locks` table,
  and group and rule serialization take row locks on the worker-only `group_locks` table (one
  row per key, in sorted key order). `group_locks` keeps one small row per group key ever
  seen. The worker connection runs with `lock_timeout` and `statement_timeout`.
  One lock remains: an open, uncommitted triage request holds its finding or incident rows
  through the owner trigger, for as long as the API keeps the transaction open. That delays
  only that finding's bookkeeping, within the lock timeout. A firing it holds up for a rule
  without a correlation pages at once as `evaluation_delayed`, in a transaction of its own
  that writes only the worker-only outbox. A timeout anywhere in a row's processing,
  dead-lettering included, retries that row later and never cancels the drain. The backlog
  check pages if the queue falls behind. The migration lock (`tuisku migrate`) is still an
  advisory lock: a compromised API process could delay a migration, but no evaluation or page.
- **A database of its own.** `REVOKE TEMP ON DATABASE ... FROM PUBLIC` is database-wide, so
  Tuisku expects a database of its own. Any role may still create large objects
  (`lo_create()`), and the API role may insert evidence as fast as Postgres accepts it.
  Deployments set a disk quota, or at least disk alerts.
- **Delivery order.** The drain delivers pages about Tuisku itself first: backlog and
  dead-letter pages, and pages of `tuisku-meta` findings (which include
  `notification_undeliverable` and `evaluation_failed`). A trigger sets `notifications.meta`
  from what the page refers to, whatever the writer supplies. Then the most severe first, then
  the oldest, so a backlog of lesser pages never holds back a newer high-severity one.
- **Pages triage and expiry cause.** A finding leaving `suppressed` by any route (triage, the
  suppression's own expiry, its incident closing, or the finding expiring while suppressed)
  pages every threshold crossed meanwhile and one `finding_suppression_ended` summary with the
  count accumulated during the suppression. An incident reopened pages an escalation at most
  once per incident per 5-minute bucket, however often a request bounces it.
- **The worker role** writes all of the above that the API cannot. A queued row whose parse
  attempt was superseded is never dropped as stale: no reprocessing run exists yet, so the
  worker raises a `tuisku.meta.evaluation_failed` (subject `superseded_derivation`) and
  evaluates the row anyway. On every pass the worker also checks its own health: a queued row
  or an undelivered notification older than `TUISKU_WORKER_BACKLOG_SECONDS` (5 minutes) raises
  a `tuisku.meta.backlog`. That backlog pages at once, through a notification an owner trigger
  writes, and through the `tuisku-meta` pack. Its name is fixed in the
  trigger functions at migration time, like the grants.
- **Second line of defence.** A firing key of any kind is accepted only when its detection is
  rule output of the key's rule, and is linked to the key's row by a link inserted in the same
  transaction. A link row whose inserting transaction is still in progress, and which the session
  can see, can only be the session's own. So even the worker role cannot reuse old links to mark
  a row done.
- In single-role development setups (`TUISKU_APP_ROLE` unset), the owner does everything, as
  before.

## Availability limits

- A compromised API process shares the database, so it can still exhaust what the database
  shares: connections, CPU, I/O, disk, and, through long transactions, vacuum. The migration
  caps the app role (`ALTER ROLE ... CONNECTION LIMIT`, `TUISKU_APP_ROLE_CONNECTION_LIMIT`,
  default 20) and sets role defaults for `statement_timeout` (30 s) and
  `idle_in_transaction_session_timeout` (60 s). The role may override both defaults with `SET`,
  so they bound mistakes, not an attacker. The README describes `reserved_connections` and
  `pg_use_reserved_connections` (Postgres 16) to keep slots free for the worker.
- Integrity is enforced: no role but the worker writes rule output, findings, incidents or
  pages, and every change by the API role is an attributed request. Availability is not
  prevented, only detected, and only from outside what a compromised API controls. The worker
  process serves its own health: `tuisku worker --health-port` (or
  `TUISKU_WORKER_HEALTH_PORT`) is a minimal, unauthenticated HTTP listener answering
  `{"status": "ok"}` with 200 while its last healthy pass is newer than
  `TUISKU_WORKER_HEARTBEAT_STALE_SECONDS` (120 s), and 503 otherwise. A pass is healthy when
  every step ran and the oldest undelivered notification is within
  `TUISKU_WORKER_BACKLOG_SECONDS`. It reports status only. `TUISKU_WORKER_DEADMAN_URL`, when
  set, is fetched after each round of healthy passes, so a dead-man's-switch service notices
  when the calls stop. A monitor outside Tuisku must use one of the two, because a stalled
  worker cannot page about itself.
- The worker also writes a heartbeat row (`worker_heartbeats`, worker-only to write) every
  pass. `GET /v1/worker/health` on the API shows it with the backlog figures, but only to the
  `read` role and marked `advisory`: a compromised API could answer it however it liked.
- The sweep that expires findings claims with `SKIP LOCKED`. A finding row held by an open
  triage request is skipped until the next pass, which only delays its expiry.

## Consequences

- A deployment creates two login roles instead of one, and points `TUISKU_DATABASE_URL` for
  `tuisku worker` at the worker role.
- A compromised API can still triage, as operators can, through triage requests. Every such
  change is an attributed operator event, and every suppression ends within 30 days. It can
  still exhaust shared database resources (see Availability limits). It can still add sensor evidence
  and current-bucket ingest meta-detections, and it can still enqueue rows. It can no longer
  write rule output, firing keys, links, findings or incidents. It cannot drop, park or delete
  queue rows, pre-claim a worker notification or meta-detection slot, or rewrite a finding
  silently, so it cannot silence a rule.
- A compromised worker can still forge rule output. Protecting against that needs the worker to
  sign its output, which is out of scope here.
