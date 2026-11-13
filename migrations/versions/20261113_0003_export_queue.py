"""Export queue for finding and incident events (ADR 0012).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-13

Every ``finding_events`` and ``incident_events`` row is exported at least once to an
append-only sink (ADR 0012). An owner-defined trigger (``SECURITY DEFINER``) enqueues one
``export_queue`` row per event in the same transaction as the event, so no event can commit
without its queue row, and the worker drains the queue: it reads a batch, sends it, and deletes
what the sink acknowledged. It is a queue, not an id cursor, because identity values are not
commit-ordered: a cursor would skip an event whose transaction commits after one with a higher
id has been exported.

The trigger is a deferred constraint trigger, so it runs at commit and snapshots the finding or
incident as the event's transaction left it (an event is often written just before the update
it records). It only reads the projection and inserts; it never raises on missing data, so
export can never block evaluation or triage.

The queue is a working table, not evidence: the evidence stays in the event tables. The worker
role gets ``SELECT`` and ``DELETE`` on it and nothing else; the API role gets nothing. Only the
trigger inserts.

Not expand-only by the convention: it adds a trigger function, triggers on existing tables and
grants, which the migration-safety checker does not read. Nothing it adds changes what an older
image reads or writes; an older worker simply leaves the queue alone.
"""

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = False

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

TABLE_SQL = """
-- One row per finding or incident event not yet acknowledged by the export sink (ADR 0012).
-- `state` is the finding or incident as the event's transaction committed it.
CREATE TABLE export_queue (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    stream            text NOT NULL CHECK (stream IN ('finding', 'incident')),
    finding_event_id  bigint REFERENCES finding_events (id),
    incident_event_id bigint REFERENCES incident_events (id),
    state             jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object'),
    enqueued_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT export_queue_one_event CHECK (
        (stream = 'finding' AND finding_event_id IS NOT NULL AND incident_event_id IS NULL)
        OR (stream = 'incident' AND incident_event_id IS NOT NULL AND finding_event_id IS NULL)
    )
);
-- The backlog check reads the oldest row.
CREATE INDEX export_queue_enqueued_at_idx ON export_queue (enqueued_at);
"""

# Owner-defined, SECURITY DEFINER (no runtime role may insert into the queue), pinned to the two
# event tables like every Tuisku trigger function (ADR 0011). The snapshot leaves out free text a
# person typed (suppression_reason) and telemetry-derived grouping values (group_values,
# explanation); entity keys are redacted by the exporter (ADR 0012).
ENQUEUE_SQL = """
CREATE FUNCTION tuisku_enqueue_export() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    state jsonb;
BEGIN
    IF TG_RELID NOT IN ('public.finding_events'::regclass::oid,
                        'public.incident_events'::regclass::oid)
       OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('INSERT') OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION '% used out of place (ADR 0011)', TG_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_TABLE_NAME = 'finding_events' THEN
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
                   'first_seen', f.first_seen,
                   'last_seen', f.last_seen,
                   'suppressed_until', f.suppressed_until,
                   'incident_uid', i.uid,
                   'updated_at', f.updated_at)
          INTO state
          FROM public.findings f LEFT JOIN public.incidents i ON i.id = f.incident_id
         WHERE f.id = NEW.finding_id;
        INSERT INTO public.export_queue (stream, finding_event_id, state)
        VALUES ('finding', NEW.id, coalesce(state, '{}'::jsonb));
    ELSE
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
                   'opened_at', i.opened_at,
                   'updated_at', i.updated_at,
                   'previous_incident_uid', p.uid)
          INTO state
          FROM public.incidents i LEFT JOIN public.incidents p ON p.id = i.previous_incident_id
         WHERE i.id = NEW.incident_id;
        INSERT INTO public.export_queue (stream, incident_event_id, state)
        VALUES ('incident', NEW.id, coalesce(state, '{}'::jsonb));
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

# ADR 0011: no tuisku_* function is executable by PUBLIC.
REVOKE_SQL = "REVOKE EXECUTE ON FUNCTION tuisku_enqueue_export() FROM PUBLIC"


def _role(name: str) -> str | None:
    role = context.config.attributes.get(name)
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError(f"{name} must be a lowercase Postgres role name")
    return role


def upgrade() -> None:
    op.execute(TABLE_SQL)
    op.execute(ENQUEUE_SQL)
    op.execute(REVOKE_SQL)
    app, worker = _role("app_role"), _role("worker_role")
    if app is None:
        return  # single-role setup: the migrating role does everything
    if worker is None:
        raise ValueError("a separate worker role is required with an app role (ADR 0011)")
    # The worker drains: it reads a batch and deletes what the sink acknowledged. No INSERT or
    # UPDATE (only the trigger enqueues; delivery backoff is kept in the worker's memory) and no
    # sequence. The API role gets nothing at all.
    op.execute(f'GRANT SELECT, DELETE ON export_queue TO "{worker}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER incident_events_export ON incident_events")
    op.execute("DROP TRIGGER finding_events_export ON finding_events")
    op.execute("DROP TABLE export_queue")
    op.execute("DROP FUNCTION tuisku_enqueue_export()")
