"""Rules, findings, incidents and notifications (ADRs 0006 and 0007).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-02

Layer L3 (ADR 0002): findings and incidents are mutable projections; every change to one appends
a ``finding_events`` or ``incident_events`` row. The histories, the link tables that build
evidence closures (``finding_detections``, ``incident_findings``), the firing keys
(``rule_firings``), the overflow groups and ``pack_loads`` are append-only (ADR 0004 section 4),
guarded by the same grants and triggers as revision 0001, and so are the notification outbox
and its delivery log. Event, link, firing and pack-load timestamps are set to the database's
``now()`` by a trigger, so the app role cannot supply them (ADR 0004 section 3).
"""

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = True

# Append-only tables added here (ADR 0004 section 4).
EVIDENCE_TABLES = (
    "finding_events",
    "finding_detections",
    "finding_overflow_groups",
    "incident_events",
    "incident_findings",
    "rule_firings",
    "pack_loads",
    "notifications",
    "notification_deliveries",
)
# Mutable working tables (ADR 0011: the worker role creates findings and incidents; the API
# role only triages them).
WORKING_TABLES = (
    "findings",
    "incidents",
    "evaluation_dead_letter_rules",
    "evaluation_attempts",
)
# Worker-only lock tables: the API role gets no privilege at all on them.
LOCK_TABLES = ("worker_locks", "group_locks")
# What the API role (ingest and triage) may write here; it reads everything (ADR 0011).
# The API role writes no notifications at all: the pages triage causes are written by owner
# triggers (SECURITY DEFINER) below.
API_INSERT = ("finding_events", "incident_events")
# Triage changes only these columns (column-level grants; a trigger checks the rest).
FINDING_TRIAGE_COLUMNS = (
    "status",
    "suppressed_until",
    "suppression_reason",
    "suppressed_at",
    "count_at_suppression",
    "updated_at",
)
INCIDENT_TRIAGE_COLUMNS = ("status", "disposition", "updated_at")
# Operator (triage) event kinds; every other kind is the worker's (ADR 0011).
OPERATOR_FINDING_EVENT_KINDS = ("status_changed", "suppressed")
OPERATOR_INCIDENT_EVENT_KINDS = ("status_changed", "reopened", "note")
# Timestamp columns the trigger forces to the database's now(), so the app role cannot supply
# them: the histories, the links that build evidence closures, the firing keys and pack loads.
FORCED_TIME_COLUMNS = (
    ("finding_events", "at"),
    ("incident_events", "at"),
    ("finding_detections", "linked_at"),
    ("incident_findings", "linked_at"),
    ("finding_overflow_groups", "linked_at"),
    ("rule_firings", "created_at"),
    ("pack_loads", "loaded_at"),
    ("notification_deliveries", "at"),
    ("notifications", "created_at"),
)

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

TABLES_SQL = """
-- Every loaded pack, with its content hash (ADR 0006) and its longest lookback, which sets the
-- retention floor for L1/L2 rows (ADR 0004 section 3).
CREATE TABLE pack_loads (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid                  uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    pack                 text NOT NULL CHECK (char_length(pack) BETWEEN 1 AND 64),
    version              text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
    authorship           text NOT NULL CHECK (authorship IN ('tuisku', 'community', 'local')),
    sha256               bytea NOT NULL CHECK (octet_length(sha256) = 32),
    params_sha256        bytea CHECK (octet_length(params_sha256) = 32),
    max_lookback_seconds bigint NOT NULL CHECK (max_lookback_seconds >= 0),
    rules                jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'array'),
    loaded_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE incidents (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid                  uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    fingerprint          bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    title                text NOT NULL CHECK (char_length(title) <= 1024),
    severity_id          smallint NOT NULL CHECK (severity_id BETWEEN 0 AND 6),
    status               text NOT NULL DEFAULT 'open' CHECK (status IN
                             ('open', 'triaged', 'investigating', 'contained', 'resolved',
                              'closed')),
    disposition          text CHECK (disposition IN ('true_positive', 'benign_true_positive',
                             'false_positive', 'duplicate', 'inconclusive')),
    rule_id              uuid,
    rule_rev             integer,
    overflow             boolean NOT NULL DEFAULT false,
    entity_keys          text[] NOT NULL DEFAULT '{}',
    finding_count        integer NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    -- A new incident for the fingerprint of a closed one links to it (ADR 0007).
    previous_incident_id bigint REFERENCES incidents (id),
    opened_at            timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    CONSTRAINT incidents_disposition_iff_closed CHECK ((status = 'closed') = (disposition IS NOT NULL))
);
-- At most one live incident per fingerprint (ADR 0007 "Uniqueness").
CREATE UNIQUE INDEX incidents_live_fingerprint_key ON incidents (fingerprint)
    WHERE status <> 'closed';
CREATE INDEX incidents_rule_status_idx ON incidents (rule_id, status);
CREATE INDEX incidents_entity_keys_idx ON incidents USING gin (entity_keys);

CREATE TABLE findings (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid                  uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    -- SHA-256 of JCS ["finding", rule id, rev, [group values]] or ["overflow", rule id, rev].
    fingerprint          bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    rule_id              uuid NOT NULL,
    rule_rev             integer NOT NULL CHECK (rule_rev >= 1),
    overflow             boolean NOT NULL DEFAULT false,
    title                text NOT NULL CHECK (char_length(title) <= 1024),
    severity_id          smallint NOT NULL CHECK (severity_id BETWEEN 0 AND 6),
    status               text NOT NULL DEFAULT 'open' CHECK (status IN
                             ('open', 'acknowledged', 'resolved', 'suppressed', 'expired')),
    first_seen           timestamptz NOT NULL,
    last_seen            timestamptz NOT NULL,
    count                bigint NOT NULL DEFAULT 1 CHECK (count >= 1),
    entity_keys          text[] NOT NULL DEFAULT '{}',
    group_values         jsonb NOT NULL CHECK (jsonb_typeof(group_values) = 'array'),
    rule_ref             jsonb NOT NULL CHECK (jsonb_typeof(rule_ref) = 'object'),
    explanation          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(explanation) = 'object'),
    window_seconds       integer NOT NULL CHECK (window_seconds > 0),
    max_lifetime_seconds integer NOT NULL CHECK (max_lifetime_seconds > 0),
    notify               text NOT NULL CHECK (notify IN ('each', 'thresholds')),
    suppressed_until     timestamptz,
    suppression_reason   text CHECK (char_length(suppression_reason) <= 1000),
    -- When the current suppression began and the count then: re-suppressing never extends past
    -- 30 days from the start, and thresholds crossed while suppressed page when it lifts.
    suppressed_at        timestamptz,
    count_at_suppression bigint,
    incident_id          bigint REFERENCES incidents (id),
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    -- Suppression always has an expiry and a reason (ADR 0007); overflow findings never.
    CONSTRAINT findings_suppression_check CHECK (
        (status = 'suppressed') = (suppressed_until IS NOT NULL AND suppression_reason IS NOT NULL)
    ),
    CONSTRAINT findings_suppressed_at_check CHECK (
        (status = 'suppressed') = (suppressed_at IS NOT NULL AND count_at_suppression IS NOT NULL)
    ),
    CONSTRAINT findings_overflow_not_suppressed CHECK (NOT (overflow AND status = 'suppressed')),
    CONSTRAINT findings_seen_order CHECK (first_seen <= last_seen)
);
-- At most one attachable finding per fingerprint.
CREATE UNIQUE INDEX findings_attachable_fingerprint_key ON findings (fingerprint)
    WHERE status IN ('open', 'acknowledged', 'suppressed');
CREATE INDEX findings_fingerprint_idx ON findings (fingerprint, id DESC);
CREATE INDEX findings_rule_status_idx ON findings (rule_id, status);
CREATE INDEX findings_incident_id_idx ON findings (incident_id);
CREATE INDEX findings_entity_keys_idx ON findings USING gin (entity_keys);

CREATE TABLE finding_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid        uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    finding_id bigint NOT NULL REFERENCES findings (id),
    at         timestamptz NOT NULL DEFAULT now(),  -- forced to now() by trigger
    actor      text NOT NULL CHECK (actor ~ '^(system|rule:[0-9a-f-]{36}@[0-9]+|operator:[0-9a-f-]{36})$'),
    kind       text NOT NULL CHECK (kind IN ('opened', 'detection_attached', 'evidence_linked',
                   'status_changed', 'severity_changed', 'suppressed', 'suppression_expired',
                   'incident_linked')),
    old_value  jsonb,
    new_value  jsonb,
    reason     text CHECK (char_length(reason) <= 1000),
    payload    jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX finding_events_finding_id_idx ON finding_events (finding_id, id);

CREATE TABLE finding_detections (
    finding_id   bigint NOT NULL REFERENCES findings (id),
    detection_id bigint NOT NULL REFERENCES detections (id),
    linked_at    timestamptz NOT NULL,
    PRIMARY KEY (finding_id, detection_id)
);
CREATE UNIQUE INDEX finding_detections_detection_id_key ON finding_detections (detection_id);

-- Groups folded into a rule's overflow finding (ADR 0006 "At the cap"); one notification each.
CREATE TABLE finding_overflow_groups (
    finding_id   bigint NOT NULL REFERENCES findings (id),
    group_key    bytea NOT NULL CHECK (octet_length(group_key) = 32),
    group_values jsonb NOT NULL CHECK (jsonb_typeof(group_values) = 'array'),
    detection_id bigint NOT NULL REFERENCES detections (id),
    linked_at    timestamptz NOT NULL,
    PRIMARY KEY (finding_id, group_key)
);

CREATE TABLE incident_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid         uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    incident_id bigint NOT NULL REFERENCES incidents (id),
    at          timestamptz NOT NULL DEFAULT now(),  -- forced to now() by trigger
    actor       text NOT NULL CHECK (actor ~
                    '^(system|rule:[0-9a-f-]{36}@[0-9]+|operator:[0-9a-f-]{36}|investigator:[0-9a-f-]{36})$'),
    kind        text NOT NULL CHECK (kind IN ('opened', 'finding_attached', 'status_changed',
                    'reopened', 'note', 'session_started', 'session_ended', 'hypothesis_added',
                    'hypothesis_confirmed', 'evidence_requested', 'evidence_decided',
                    'action_proposed', 'action_decided', 'action_executed')),
    payload     jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(payload) = 'object')
);
CREATE INDEX incident_events_incident_id_idx ON incident_events (incident_id, id);

CREATE TABLE incident_findings (
    incident_id bigint NOT NULL REFERENCES incidents (id),
    finding_id  bigint NOT NULL REFERENCES findings (id),
    linked_at   timestamptz NOT NULL,
    PRIMARY KEY (incident_id, finding_id)
);
CREATE INDEX incident_findings_finding_id_idx ON incident_findings (finding_id);

-- Idempotency keys for firings (ADR 0006 "Idempotent firings"). Every row that fired, was
-- linked, or was a member of a firing's window has one entry per (rule, rev), so no row is
-- counted twice for a rule; a correlation also has one per group and window start.
-- firing_detection_id is the detection written by the firing (row, correlation), the firing a
-- row was linked to (link), or the firing whose window it was in (member).
CREATE TABLE rule_firings (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id             uuid NOT NULL,
    rule_rev            integer NOT NULL CHECK (rule_rev >= 1),
    kind                text NOT NULL CHECK (kind IN ('row', 'correlation', 'link', 'member')),
    observation_id      bigint REFERENCES observations (id),
    detection_id        bigint REFERENCES detections (id),
    group_key           bytea NOT NULL CHECK (octet_length(group_key) = 32),
    window_start        timestamptz,
    eval_time           timestamptz NOT NULL,
    firing_detection_id bigint NOT NULL REFERENCES detections (id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT rule_firings_one_row CHECK (num_nonnulls(observation_id, detection_id) = 1),
    CONSTRAINT rule_firings_window_iff_correlation CHECK (
        (kind = 'correlation') = (window_start IS NOT NULL)
    )
);
CREATE UNIQUE INDEX rule_firings_row_key
    ON rule_firings (rule_id, rule_rev, observation_id, detection_id) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX rule_firings_window_key
    ON rule_firings (rule_id, rule_rev, group_key, window_start) WHERE kind = 'correlation';
CREATE INDEX rule_firings_group_idx ON rule_firings (rule_id, rule_rev, group_key, id DESC)
    WHERE kind IN ('row', 'correlation');

-- Notification outbox (ADR 0007): written in the evaluation transaction, delivered after it
-- commits. dedupe_key makes every notification idempotent. Append-only, like the delivery log
-- beside it, so a compromised app process cannot delete or mark away a page unnoticed.
CREATE TABLE notifications (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid          uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    dedupe_key   text NOT NULL UNIQUE CHECK (char_length(dedupe_key) <= 300),
    kind         text NOT NULL CHECK (char_length(kind) <= 64),
    severity_id  smallint NOT NULL CHECK (severity_id BETWEEN 0 AND 6),
    payload      jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at   timestamptz NOT NULL
);

CREATE TABLE notification_deliveries (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    notification_id bigint NOT NULL REFERENCES notifications (id),
    at              timestamptz NOT NULL DEFAULT now(),  -- forced to now() by trigger
    status          text NOT NULL CHECK (status IN ('delivered', 'failed')),
    error           text CHECK (char_length(error) <= 500)
);
CREATE INDEX notification_deliveries_notification_idx
    ON notification_deliveries (notification_id, status);

-- The worker's own locks (ADR 0011). Postgres checks no privilege on advisory locks, so any
-- role could hold an advisory key and stall the worker. Row locks on these worker-only tables
-- need UPDATE, which only the worker role has. `worker_locks` holds singletons (the notification
-- drain); `group_locks` serializes each rule's groups and cap checks, one row per key, locked
-- in sorted key order.
CREATE TABLE worker_locks (
    name text PRIMARY KEY CHECK (char_length(name) BETWEEN 1 AND 64)
);
CREATE TABLE group_locks (
    key text PRIMARY KEY CHECK (char_length(key) BETWEEN 1 AND 64)
);

-- Failure counts per (queue row, rule) (ADR 0006): lease expiries and crashes never count, and
-- uncounted transient retries are capped.
CREATE TABLE evaluation_attempts (
    queue_id   bigint NOT NULL,
    rule_id    uuid NOT NULL,
    attempts   integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    transient  integer NOT NULL DEFAULT 0 CHECK (transient >= 0),
    last_error text,
    PRIMARY KEY (queue_id, rule_id)
);

-- Per-rule dead letters (ADR 0006): one row per (queue row, rule) that failed 5 attempts.
CREATE TABLE evaluation_dead_letter_rules (
    queue_id       bigint NOT NULL,
    observation_id bigint REFERENCES observations (id),
    detection_id   bigint REFERENCES detections (id),
    rule_id        uuid NOT NULL,
    rule_rev       integer NOT NULL,
    attempts       integer NOT NULL CHECK (attempts >= 0),
    last_error     text,
    moved_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (queue_id, rule_id),
    CONSTRAINT evaluation_dead_letter_rules_one_target
        CHECK (num_nonnulls(observation_id, detection_id) = 1)
);

-- Claiming (ADR 0006): unclaimed or lease-expired rows, oldest first.
-- Correlation windows over metric samples are read per metric name (ADR 0006).
CREATE INDEX observations_metric_eval_time_idx
    ON observations ((attributes ->> 'metric'), eval_time) WHERE kind = 'metric.sample';
CREATE INDEX evaluation_queue_claim_idx ON evaluation_queue (claimed_until NULLS FIRST, id);
-- Evidence closures walk these links downwards (ADR 0004 section 4).
CREATE INDEX detection_evidence_observation_id_idx ON detection_evidence (observation_id)
    WHERE observation_id IS NOT NULL;
CREATE INDEX detection_evidence_detection_ref_id_idx ON detection_evidence (detection_ref_id)
    WHERE detection_ref_id IS NOT NULL;
"""

# ADR 0004 section 3: "A trigger sets event timestamps to the database's now(), and the app role
# cannot supply them." Holds are computed from these timestamps.
FORCE_TIME_FUNCTION_SQL = """
CREATE FUNCTION tuisku_force_event_time() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.finding_events'::regclass::oid, 'public.incident_events'::regclass::oid, 'public.finding_detections'::regclass::oid, 'public.incident_findings'::regclass::oid, 'public.finding_overflow_groups'::regclass::oid, 'public.rule_firings'::regclass::oid, 'public.pack_loads'::regclass::oid, 'public.notification_deliveries'::regclass::oid, 'public.notifications'::regclass::oid) OR TG_WHEN <> 'BEFORE' OR TG_OP NOT IN ('INSERT')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- TG_ARGV[0] names the timestamp column of the table.
    NEW := jsonb_populate_record(NEW, jsonb_build_object(TG_ARGV[0], now()));
    RETURN NEW;
END
$$;
"""

# A firing key must be consistent with what the worker wrote in the same transaction, so a
# forged key cannot make the worker skip a row for a rule (ADR 0011 adds the role split; this is
# the second line of defence):
# - it points at a tuisku detection whose identity is the key's rule;
# - for every kind, the detection is linked to the key's row (detection_observations or
#   detection_evidence) by a link inserted in this very transaction
#   (tuisku_xmin_is_current(), from revision 0001).
FIRING_IDENTITY_FUNCTION_SQL = """
CREATE FUNCTION tuisku_check_firing_identity() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.rule_firings'::regclass::oid) OR TG_WHEN <> 'BEFORE' OR TG_OP NOT IN ('INSERT')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.detections d
        WHERE d.id = NEW.firing_detection_id AND d.evaluator = 'tuisku'
          AND d.identity = NEW.rule_id::text
    ) THEN
        RAISE EXCEPTION 'rule_firings: detection % is not output of rule %',
            NEW.firing_detection_id, NEW.rule_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.detection_observations l
        WHERE l.detection_id = NEW.firing_detection_id
          AND l.observation_id = NEW.observation_id
          AND public.tuisku_xmin_is_current(l.xmin)
    ) AND NOT EXISTS (
        SELECT 1 FROM public.detection_evidence e
        WHERE e.detection_id = NEW.firing_detection_id
          AND (e.observation_id = NEW.observation_id OR e.detection_ref_id = NEW.detection_id)
          AND public.tuisku_xmin_is_current(e.xmin)
    ) THEN
        RAISE EXCEPTION 'rule_firings: % key for a row not linked to detection % in this '
            'transaction', NEW.kind, NEW.firing_detection_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER rule_firings_identity BEFORE INSERT ON rule_firings
    FOR EACH ROW EXECUTE FUNCTION tuisku_check_firing_identity();
"""


# ADR 0011: events with a system or rule actor are the worker's alone; the API writes only
# operator events. tuisku_is_worker() comes from revision 0001.
def _sql_array(values: tuple[str, ...]) -> str:
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]::text[]"


EVENT_ACTOR_SQL = f"""
CREATE FUNCTION tuisku_events_operator_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    kinds text[];
BEGIN
    IF TG_RELID NOT IN ('public.finding_events'::regclass::oid, 'public.incident_events'::regclass::oid) OR TG_WHEN <> 'BEFORE' OR TG_OP NOT IN ('INSERT')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    IF NEW.actor NOT LIKE 'operator:%' THEN
        RAISE EXCEPTION 'only the worker role writes % events (ADR 0011)', NEW.actor
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- The operator must be a live operator token: the API cannot invent one.
    IF NEW.actor !~ '^operator:[0-9a-f-]{{36}}$' OR NOT EXISTS (
        SELECT 1 FROM public.operator_tokens t
        WHERE t.uid = substring(NEW.actor FROM 10)::uuid AND t.revoked_at IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())
          AND t.roles && ARRAY['triage', 'admin']::text[]
    ) THEN
        RAISE EXCEPTION 'no live operator token with the triage role: %', NEW.actor
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    kinds := CASE TG_TABLE_NAME
        WHEN 'finding_events' THEN {_sql_array(OPERATOR_FINDING_EVENT_KINDS)}
        ELSE {_sql_array(OPERATOR_INCIDENT_EVENT_KINDS)} END;
    IF NOT (NEW.kind = ANY (kinds)) THEN
        RAISE EXCEPTION 'operators write only triage events, not % (ADR 0011)', NEW.kind
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER finding_events_actor BEFORE INSERT ON finding_events
    FOR EACH ROW EXECUTE FUNCTION tuisku_events_operator_only();
CREATE TRIGGER incident_events_actor BEFORE INSERT ON incident_events
    FOR EACH ROW EXECUTE FUNCTION tuisku_events_operator_only();
"""


# ADR 0011: what the API role may do to findings, incidents and notifications. The worker (and
# the owner) are not restricted here. For the API role:
# - only triage columns may change; window, lifetime, counts, severity and every other column
#   are refused (the column grants refuse them too);
# - a suppression starts now, by the database clock, records the count then, and never runs
#   past 30 days from when it began, however often it is renewed;
# - every change needs a matching operator event inserted in the same transaction (the same
#   xmin check as firing keys), so no triage change is silent;
# - only the notification dedupe-key prefixes triage emits are accepted, so the API cannot
#   pre-claim a key the worker will use and swallow that page.
TRIAGE_GUARD_SQL = f"""
CREATE FUNCTION tuisku_findings_triage_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    began timestamptz;
BEGIN
    IF TG_RELID NOT IN ('public.findings'::regclass::oid) OR TG_WHEN <> 'BEFORE' OR TG_OP NOT IN ('UPDATE')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    -- Triage sets these states only; expiry is the worker's.
    IF NEW.status NOT IN ('open', 'acknowledged', 'resolved', 'suppressed') THEN
        RAISE EXCEPTION 'triage cannot set a finding to % (ADR 0011)', NEW.status
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (to_jsonb(NEW) - {_sql_array(FINDING_TRIAGE_COLUMNS)})
       IS DISTINCT FROM (to_jsonb(OLD) - {_sql_array(FINDING_TRIAGE_COLUMNS)}) THEN
        RAISE EXCEPTION 'triage may change only a finding''s status and suppression (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.status NOT IN ('open', 'acknowledged', 'suppressed') THEN
        RAISE EXCEPTION 'a % finding can no longer change', OLD.status
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.status = 'suppressed' THEN
        IF OLD.status = 'suppressed' THEN
            NEW.count_at_suppression := OLD.count_at_suppression;
        ELSE
            NEW.count_at_suppression := OLD.count;
        END IF;
        -- The 30 days run from the finding's first suppression ever, so lifting and
        -- re-suppressing (a bounce) never restarts the clock. The operator event for this
        -- change is already written, so the earliest one is never later than now().
        SELECT min(e.at) INTO began FROM public.finding_events e
        WHERE e.finding_id = NEW.id AND e.kind = 'suppressed';
        began := least(coalesce(began, now()), coalesce(OLD.suppressed_at, now()), now());
        NEW.suppressed_at := began;
        IF NEW.suppressed_until IS NULL OR NEW.suppressed_until > began + interval '30 days' THEN
            RAISE EXCEPTION 'a suppression ends within 30 days of when it began (ADR 0007)'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.finding_events e
        WHERE e.finding_id = NEW.id AND e.actor LIKE 'operator:%'
          AND e.new_value ->> 'status' = NEW.status
          AND public.tuisku_xmin_is_current(e.xmin)
    ) THEN
        RAISE EXCEPTION 'a triage change needs its operator event in the same transaction'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER findings_triage_guard BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION tuisku_findings_triage_guard();

CREATE FUNCTION tuisku_incidents_triage_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.incidents'::regclass::oid) OR TG_WHEN <> 'BEFORE' OR TG_OP NOT IN ('UPDATE')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - {_sql_array(INCIDENT_TRIAGE_COLUMNS)})
       IS DISTINCT FROM (to_jsonb(OLD) - {_sql_array(INCIDENT_TRIAGE_COLUMNS)}) THEN
        RAISE EXCEPTION 'triage may change only an incident''s status and disposition (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.status = 'closed' THEN
        RAISE EXCEPTION 'a closed incident can no longer change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.incident_events e
        WHERE e.incident_id = NEW.id AND e.actor LIKE 'operator:%'
          AND e.kind IN ('status_changed', 'reopened') AND e.payload ->> 'to' = NEW.status
          AND public.tuisku_xmin_is_current(e.xmin)
    ) THEN
        RAISE EXCEPTION 'a triage change needs its operator event in the same transaction'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER incidents_triage_guard BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION tuisku_incidents_triage_guard();

-- Pages triage causes, written by the owner (SECURITY DEFINER) whoever made the change, so the
-- API role needs no notification privilege at all (ADR 0011):
-- - a finding leaving `suppressed` (to open, acknowledged or resolved, also through an incident
--   being closed or resolved) pages every threshold crossed while it was suppressed (ADR 0007);
-- - an incident reopened (contained or resolved back to investigating) pages an escalation.
CREATE FUNCTION tuisku_page_lifted_thresholds() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    threshold integer;
BEGIN
    IF TG_RELID NOT IN ('public.findings'::regclass::oid) OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('UPDATE')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.status = 'suppressed' AND NEW.status IN ('open', 'acknowledged', 'resolved') THEN
        FOREACH threshold IN ARRAY ARRAY[10, 100, 1000] LOOP
            IF coalesce(OLD.count_at_suppression, NEW.count) < threshold
               AND threshold <= NEW.count THEN
                INSERT INTO public.notifications (dedupe_key, kind, severity_id, payload,
                                                  created_at)
                VALUES (
                    'finding_threshold:' || NEW.uid || ':' || threshold,
                    'finding_threshold',
                    NEW.severity_id,
                    jsonb_build_object(
                        'finding_uid', NEW.uid::text,
                        'rule', NEW.rule_id::text || '@' || NEW.rule_rev,
                        'title', NEW.title,
                        'entity_keys', to_jsonb(NEW.entity_keys[1:32]),
                        'count', NEW.count,
                        'threshold', threshold,
                        'reason', 'crossed while suppressed'
                    ),
                    now()
                )
                ON CONFLICT (dedupe_key) DO NOTHING;
            END IF;
        END LOOP;
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER findings_page_lifted_thresholds AFTER UPDATE OF status ON findings
    FOR EACH ROW EXECUTE FUNCTION tuisku_page_lifted_thresholds();

CREATE FUNCTION tuisku_page_reopened_incident() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.incidents'::regclass::oid) OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('UPDATE')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.status IN ('contained', 'resolved') AND NEW.status = 'investigating' THEN
        INSERT INTO public.notifications (dedupe_key, kind, severity_id, payload, created_at)
        VALUES (
            'escalation:' || NEW.uid || ':reopened:' || pg_current_xact_id()::text,
            'incident_escalated',
            NEW.severity_id,
            jsonb_build_object(
                'incident_uid', NEW.uid::text,
                'title', NEW.title,
                'reason', 'reopened',
                'entity_keys', to_jsonb(NEW.entity_keys[1:32])
            ),
            now()
        )
        ON CONFLICT (dedupe_key) DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER incidents_page_reopened AFTER UPDATE OF status ON incidents
    FOR EACH ROW EXECUTE FUNCTION tuisku_page_reopened_incident();

-- A backlog meta-detection pages at once, by its own notification, rather than waiting for the
-- (backed-up) queue to bring it to the tuisku-meta rule.
CREATE FUNCTION tuisku_page_backlog() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.detections'::regclass::oid) OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('INSERT')
       OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    INSERT INTO public.notifications (dedupe_key, kind, severity_id, payload, created_at)
    VALUES (
        'backlog:' || NEW.uid,
        'tuisku_backlog',
        NEW.severity_id,
        jsonb_build_object(
            'detection_uid', NEW.uid::text,
            'title', NEW.title,
            'subject', NEW.subject,
            'entity_keys', to_jsonb(NEW.entity_keys)
        ),
        now()
    )
    ON CONFLICT (dedupe_key) DO NOTHING;
    RETURN NULL;
END
$$;
CREATE TRIGGER detections_page_backlog AFTER INSERT ON detections
    FOR EACH ROW WHEN (NEW.kind = 'tuisku.meta.backlog')
    EXECUTE FUNCTION tuisku_page_backlog();
"""


def _role(name: str) -> str | None:
    role = context.config.attributes.get(name)
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError(f"{name} must be a lowercase Postgres role name")
    return role


# ADR 0011: no tuisku_* function is callable by PUBLIC (see revision 0001); this revision's
# functions, the SECURITY DEFINER pagers included, get the same treatment.
REVOKE_FUNCTIONS_SQL = """
DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname LIKE 'tuisku\\_%'
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END
$$;
"""


def upgrade() -> None:
    op.execute(TABLES_SQL)
    op.execute(FORCE_TIME_FUNCTION_SQL)
    for table, column in FORCED_TIME_COLUMNS:
        op.execute(
            f"CREATE TRIGGER {table}_force_time BEFORE INSERT ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION tuisku_force_event_time('{column}')"
        )
    op.execute(FIRING_IDENTITY_FUNCTION_SQL)
    op.execute(EVENT_ACTOR_SQL)
    op.execute(TRIAGE_GUARD_SQL)
    op.execute(REVOKE_FUNCTIONS_SQL)
    # The evidence trigger function comes from revision 0001.
    for table in EVIDENCE_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_append_only_row BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION tuisku_reject_evidence_change()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_append_only_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION tuisku_reject_evidence_change()"
        )

    app, worker = _role("app_role"), _role("worker_role")
    if app is None:
        return  # single-role setup: the migrating role does everything
    if worker is None:
        raise ValueError("a separate worker role is required with an app role (ADR 0011)")
    # The worker writes rule output, firing keys, links, findings and incidents (ADR 0011).
    op.execute(f'GRANT SELECT, INSERT ON {", ".join(EVIDENCE_TABLES)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {", ".join(WORKING_TABLES)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON {", ".join(LOCK_TABLES)} TO "{worker}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{worker}"')
    # The API reads all of it (but the lock tables) and writes only triage: status updates and
    # operator events. Owner triggers write the pages triage causes.
    op.execute(f'GRANT SELECT ON {", ".join(EVIDENCE_TABLES + WORKING_TABLES)} TO "{app}"')
    op.execute(f'GRANT INSERT ON {", ".join(API_INSERT)} TO "{app}"')
    op.execute(f'GRANT UPDATE ({", ".join(FINDING_TRIAGE_COLUMNS)}) ON findings TO "{app}"')
    op.execute(f'GRANT UPDATE ({", ".join(INCIDENT_TRIAGE_COLUMNS)}) ON incidents TO "{app}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{app}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER detections_page_backlog ON detections")
    op.execute("DROP INDEX evaluation_queue_claim_idx")
    op.execute("DROP INDEX observations_metric_eval_time_idx")
    op.execute("DROP INDEX detection_evidence_observation_id_idx")
    op.execute("DROP INDEX detection_evidence_detection_ref_id_idx")
    op.execute(
        "DROP TABLE worker_locks, group_locks, evaluation_attempts, evaluation_dead_letter_rules, "
        "notification_deliveries, "
        "notifications, rule_firings, incident_findings, "
        "incident_events, finding_overflow_groups, finding_detections, finding_events, findings, "
        "incidents, pack_loads"
    )
    op.execute(
        "DROP FUNCTION tuisku_force_event_time(), tuisku_check_firing_identity(), "
        "tuisku_events_operator_only(), "
        "tuisku_findings_triage_guard(), tuisku_incidents_triage_guard(), "
        "tuisku_page_lifted_thresholds(), tuisku_page_reopened_incident(), tuisku_page_backlog()"
    )
