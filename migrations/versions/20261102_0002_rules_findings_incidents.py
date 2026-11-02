"""Rules, findings, incidents and notifications (ADRs 0006 and 0007).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-02

Layer L3 (ADR 0002): findings and incidents are mutable projections; every change to one appends
a ``finding_events`` or ``incident_events`` row. The histories, the link tables that build
evidence closures (``finding_detections``, ``incident_findings``), the firing keys
(``rule_firings``), the overflow groups and ``pack_loads`` are append-only (ADR 0004 section 4),
guarded by the same grants and triggers as revision 0001. Event timestamps are set to the
database's ``now()`` by a trigger, so the app role cannot supply them (ADR 0004 section 3).
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
)
# Mutable working tables the app role may change.
WORKING_TABLES = ("findings", "incidents", "notifications", "evaluation_dead_letter_rules")
# Histories whose timestamp column the trigger forces to now().
EVENT_TABLES = ("finding_events", "incident_events")

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
    incident_id          bigint REFERENCES incidents (id),
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    -- Suppression always has an expiry and a reason (ADR 0007); overflow findings never.
    CONSTRAINT findings_suppression_check CHECK (
        (status = 'suppressed') = (suppressed_until IS NOT NULL AND suppression_reason IS NOT NULL)
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
-- commits. dedupe_key makes every notification idempotent.
CREATE TABLE notifications (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid          uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    dedupe_key   text NOT NULL UNIQUE CHECK (char_length(dedupe_key) <= 300),
    kind         text NOT NULL CHECK (char_length(kind) <= 64),
    severity_id  smallint NOT NULL CHECK (severity_id BETWEEN 0 AND 6),
    payload      jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at   timestamptz NOT NULL,
    delivered_at timestamptz
);
CREATE INDEX notifications_undelivered_idx ON notifications (id) WHERE delivered_at IS NULL;

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
CREATE INDEX evaluation_queue_claim_idx ON evaluation_queue (claimed_until NULLS FIRST, id);
-- Evidence closures walk these links downwards (ADR 0004 section 4).
CREATE INDEX detection_evidence_observation_id_idx ON detection_evidence (observation_id)
    WHERE observation_id IS NOT NULL;
CREATE INDEX detection_evidence_detection_ref_id_idx ON detection_evidence (detection_ref_id)
    WHERE detection_ref_id IS NOT NULL;
"""

# ADR 0004 section 3: "A trigger sets event timestamps to the database's now(), and the app role
# cannot supply them." Holds are computed from these timestamps.
EVENT_TIME_FUNCTION_SQL = """
CREATE FUNCTION tuisku_force_event_time() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    NEW.at := now();
    RETURN NEW;
END
$$;
"""


def _app_role() -> str | None:
    role = context.config.attributes.get("app_role")
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError("app_role must be a lowercase Postgres role name")
    return role


def upgrade() -> None:
    op.execute(TABLES_SQL)
    op.execute(EVENT_TIME_FUNCTION_SQL)
    for table in EVENT_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_force_time BEFORE INSERT ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION tuisku_force_event_time()"
        )
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

    role = _app_role()
    if role is None:
        return  # single-role setup: the migrating role is also the app role
    op.execute(f'GRANT SELECT, INSERT ON {", ".join(EVIDENCE_TABLES)} TO "{role}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {", ".join(WORKING_TABLES)} TO "{role}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{role}"')


def downgrade() -> None:
    op.execute("DROP INDEX evaluation_queue_claim_idx")
    op.execute("DROP INDEX detection_evidence_observation_id_idx")
    op.execute("DROP INDEX detection_evidence_detection_ref_id_idx")
    op.execute(
        "DROP TABLE evaluation_dead_letter_rules, notifications, rule_firings, incident_findings, "
        "incident_events, finding_overflow_groups, finding_detections, finding_events, findings, "
        "incidents, pack_loads"
    )
    op.execute("DROP FUNCTION tuisku_force_event_time()")
