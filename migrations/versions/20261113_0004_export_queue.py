"""Export queue for finding and incident events (ADR 0012).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-13

Every ``finding_events`` and ``incident_events`` row is exported at least once to an
append-only sink (ADR 0012). An owner-defined trigger (``SECURITY DEFINER``) enqueues one
``export_queue`` row per event in the same transaction as the event, so no event can commit
without its queue row, and the worker drains the queue: it reads a batch, sends it, and deletes
what the sink acknowledged. It is a queue, not an id cursor, because identity values are not
commit-ordered: a cursor would skip an event whose transaction commits after one with a higher
id has been exported.

The trigger is a deferred constraint trigger, so it runs at commit and snapshots the event and
the finding or incident as the event's transaction left it (an event is often written just
before the update it records). Times are rendered as text in SQL, in UTC, whatever the session
time zone, so an out-of-range value ('-infinity', a BC date) is carried as text and can never
make a record unencodable. The trigger only reads and inserts; it never raises on missing data,
so export can never block evaluation or triage.

Enqueueing is gated by ``export_state.enabled``, which only the owner writes: ``tuisku migrate``
sets it when asked (``TUISKU_EXPORT_ENQUEUE=on|off``) and otherwise leaves it (ADR 0012). Off,
the default, the trigger writes nothing.

The queue is a working table, not evidence: the evidence stays in the event tables. The worker
role gets ``SELECT`` and ``DELETE`` on it and ``SELECT`` on ``export_state``; exporters take
turns through a short lease on the worker-only ``worker_locks`` row ``export`` (two new nullable
columns, seeded here). The API role gets nothing.

It also refuses triage requests whose suppression expiry is not a finite time in the future
(a separate ``BEFORE INSERT`` check beside ``tuisku_apply_triage``, which is left as it is), so
no suppression can carry '-infinity' or a past time.

Not expand-only by the convention: it adds trigger functions, triggers on existing tables and
grants, which the migration-safety checker does not read. Nothing it adds changes what an older
image reads or writes, but an older worker does not drain the queue (ADR 0012, "Rollback").
"""

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = False

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

TABLE_SQL = """
-- One row per finding or incident event not yet acknowledged by the export sink (ADR 0012).
-- `event` is the event and `state` the finding or incident, as the event's transaction
-- committed them.
CREATE TABLE export_queue (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    stream            text NOT NULL CHECK (stream IN ('finding', 'incident')),
    finding_event_id  bigint REFERENCES finding_events (id),
    incident_event_id bigint REFERENCES incident_events (id),
    event             jsonb NOT NULL CHECK (jsonb_typeof(event) = 'object'),
    state             jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object'),
    enqueued_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT export_queue_one_event CHECK (
        (stream = 'finding' AND finding_event_id IS NOT NULL AND incident_event_id IS NULL)
        OR (stream = 'incident' AND incident_event_id IS NOT NULL AND finding_event_id IS NULL)
    )
);
-- The backlog check reads the oldest row.
CREATE INDEX export_queue_enqueued_at_idx ON export_queue (enqueued_at);

-- Whether the triggers enqueue (ADR 0012). One row; only the owner writes it (`tuisku migrate`
-- sets it from whether an export URL is configured). Off until then.
CREATE TABLE export_state (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled    boolean NOT NULL DEFAULT false,
    changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO export_state (enabled) VALUES (false);

-- Exporters take turns by a short lease on this worker-only row, never by a lock held across
-- the HTTP request (ADR 0012).
ALTER TABLE worker_locks
    ADD COLUMN holder text CHECK (char_length(holder) <= 200),
    ADD COLUMN lease_until timestamptz;
INSERT INTO worker_locks (name) VALUES ('export') ON CONFLICT (name) DO NOTHING;
"""

# A time as RFC 3339 UTC text, whatever the session's TimeZone; out-of-range values as text.
TIME_SQL = """
CREATE FUNCTION tuisku_export_time(t timestamptz) RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN t IS NULL THEN NULL
        WHEN NOT isfinite(t) THEN t::text
        ELSE to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
             || CASE WHEN t < '0001-01-01 00:00:00+00' THEN ' BC' ELSE '' END
    END
$$;
"""

# Owner-defined, SECURITY DEFINER (no runtime role may insert into the queue), pinned to the two
# event tables like every Tuisku trigger function (ADR 0011). The snapshot leaves out free text a
# person typed on the projection (suppression_reason) and telemetry-derived grouping values
# (group_values, explanation); the exporter pseudonymises entity keys and the event's reason
# (ADR 0012).
ENQUEUE_SQL = """
CREATE FUNCTION tuisku_enqueue_export() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    state jsonb;
    event jsonb;
BEGIN
    IF TG_RELID NOT IN ('public.finding_events'::regclass::oid,
                        'public.incident_events'::regclass::oid)
       OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('INSERT') OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT coalesce((SELECT s.enabled FROM public.export_state s), false) THEN
        RETURN NULL;  -- export is off: nothing to write (ADR 0012)
    END IF;
    event := jsonb_build_object(
        'uid', NEW.uid,
        'at', public.tuisku_export_time(NEW.at),
        'at_unix_nano', CASE WHEN isfinite(NEW.at) AND NEW.at >= '1970-01-01 00:00:00+00'
                                  AND NEW.at < '2262-01-01 00:00:00+00'
                             THEN (floor(extract(epoch FROM NEW.at) * 1000000) * 1000)::text
                             ELSE '0' END,
        'actor', NEW.actor,
        'kind', NEW.kind,
        'payload', NEW.payload);
    IF TG_TABLE_NAME = 'finding_events' THEN
        event := event || jsonb_build_object(
            'old_value', NEW.old_value, 'new_value', NEW.new_value, 'reason', NEW.reason);
        SELECT jsonb_build_object(
                   'uid', f.uid,
                   'rule_id', f.rule_id,
                   'rule_rev', f.rule_rev,
                   'rule_ref', f.rule_ref,
                   'overflow', f.overflow,
                   'title', f.title,
                   'severity_id', f.severity_id,
                   'status', f.status,
                   'count', f.count,
                   'entity_keys', to_jsonb(f.entity_keys),
                   'first_seen', public.tuisku_export_time(f.first_seen),
                   'last_seen', public.tuisku_export_time(f.last_seen),
                   'suppressed_until', public.tuisku_export_time(f.suppressed_until),
                   'incident_uid', i.uid,
                   'updated_at', public.tuisku_export_time(f.updated_at))
          INTO state
          FROM public.findings f LEFT JOIN public.incidents i ON i.id = f.incident_id
         WHERE f.id = NEW.finding_id;
        INSERT INTO public.export_queue (stream, finding_event_id, event, state)
        VALUES ('finding', NEW.id, event, coalesce(state, '{}'::jsonb));
    ELSE
        event := event || jsonb_build_object('old_value', NULL, 'new_value', NULL,
                                             'reason', NULL);
        SELECT jsonb_build_object(
                   'uid', i.uid,
                   'title', i.title,
                   'severity_id', i.severity_id,
                   'status', i.status,
                   'disposition', i.disposition,
                   'rule_id', i.rule_id,
                   'rule_rev', i.rule_rev,
                   'overflow', i.overflow,
                   'entity_keys', to_jsonb(i.entity_keys),
                   'finding_count', i.finding_count,
                   'opened_at', public.tuisku_export_time(i.opened_at),
                   'updated_at', public.tuisku_export_time(i.updated_at),
                   'previous_incident_uid', p.uid)
          INTO state
          FROM public.incidents i LEFT JOIN public.incidents p ON p.id = i.previous_incident_id
         WHERE i.id = NEW.incident_id;
        INSERT INTO public.export_queue (stream, incident_event_id, event, state)
        VALUES ('incident', NEW.id, event, coalesce(state, '{}'::jsonb));
    END IF;
    RETURN NULL;
END
$$;
-- Deferred: runs at commit, in the event's transaction, so the snapshot is what it committed.
CREATE CONSTRAINT TRIGGER finding_events_export AFTER INSERT ON finding_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION tuisku_enqueue_export();
CREATE CONSTRAINT TRIGGER incident_events_export AFTER INSERT ON incident_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION tuisku_enqueue_export();
"""

# A suppression expiry must be a finite time in the future, for every role. The upper bound
# (30 days from when the suppression began) stays in tuisku_apply_triage (revision 0002), which
# this leaves untouched; the API checks the same with its own clock (store/lifecycle.py).
TRIAGE_EXPIRY_SQL = """
CREATE FUNCTION tuisku_check_triage_expiry() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_RELID NOT IN ('public.triage_requests'::regclass::oid) OR TG_WHEN <> 'BEFORE'
       OR TG_OP NOT IN ('INSERT') OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- isfinite() is redundant with the bounds ('-infinity' fails > now(), 'infinity' fails
    -- tuisku_apply_triage's 30-day bound); it is kept so this check alone refuses both.
    IF NEW.suppressed_until IS NOT NULL
       AND NOT (isfinite(NEW.suppressed_until) AND NEW.suppressed_until > now()) THEN
        RAISE EXCEPTION 'suppression expiry must be in the future and within 30 days of when '
            'the suppression began' USING ERRCODE = 'TK409';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER triage_requests_check_expiry BEFORE INSERT ON triage_requests
    FOR EACH ROW EXECUTE FUNCTION tuisku_check_triage_expiry();
"""

# ADR 0011: no tuisku_* function is executable by PUBLIC.
REVOKE_SQL = (
    "REVOKE EXECUTE ON FUNCTION tuisku_export_time(timestamptz), tuisku_enqueue_export(), "
    "tuisku_check_triage_expiry() FROM PUBLIC"
)


def _role(name: str) -> str | None:
    role = context.config.attributes.get(name)
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError(f"{name} must be a lowercase Postgres role name")
    return role


def upgrade() -> None:
    op.execute(TABLE_SQL)
    op.execute(TIME_SQL)
    op.execute(ENQUEUE_SQL)
    op.execute(TRIAGE_EXPIRY_SQL)
    op.execute(REVOKE_SQL)
    app, worker = _role("app_role"), _role("worker_role")
    if app is None:
        return  # single-role setup: the migrating role does everything
    if worker is None:
        raise ValueError("a separate worker role is required with an app role (ADR 0011)")
    # The worker drains: it reads a batch and deletes what the sink acknowledged. No INSERT or
    # UPDATE on the queue (only the trigger enqueues) and no sequence. It reads, never writes,
    # export_state. The API role gets nothing at all.
    op.execute(f'GRANT SELECT, DELETE ON export_queue TO "{worker}"')
    op.execute(f'GRANT SELECT ON export_state TO "{worker}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER triage_requests_check_expiry ON triage_requests")
    op.execute("DROP TRIGGER incident_events_export ON incident_events")
    op.execute("DROP TRIGGER finding_events_export ON finding_events")
    op.execute("DROP TABLE export_queue, export_state")
    op.execute("DELETE FROM worker_locks WHERE name = 'export'")
    op.execute("ALTER TABLE worker_locks DROP COLUMN holder, DROP COLUMN lease_until")
    op.execute(
        "DROP FUNCTION tuisku_enqueue_export(), tuisku_export_time(timestamptz), "
        "tuisku_check_triage_expiry()"
    )
