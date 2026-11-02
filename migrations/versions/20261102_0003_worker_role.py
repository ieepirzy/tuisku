"""Separate worker role (ADR 0011): only the worker writes rule output and firing keys.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-02

A compromised API process must not be able to forge rule output or firing keys, because a
forged firing key makes the worker skip a row and so hides a page. The worker connects as its
own role (TUISKU_WORKER_ROLE); the API keeps what ingest and triage need. Enforced twice:

- grants: the worker role is granted what it reads and writes on revision 0001's tables, and the
  API role loses INSERT on ``detection_evidence``, which only the worker writes;
- triggers, for rows the API must still insert into shared tables: a ``tuisku``-evaluated
  detection may be inserted only by the worker (or the owner), except the API's own ingest
  meta-detections; a ``detection_observations`` link to such a detection likewise; and a finding
  or incident event whose actor is not ``operator:`` likewise.

The worker role's name is fixed into the trigger functions at migration time, like the grants.
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
# False: it REVOKEs a privilege from the app role. An older image never used it (the API never
# wrote detection_evidence), but the change is not purely additive.
expand_only = False

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

WORKER_READ = ("raw_records", "parse_attempts", "observations", "sources")
WORKER_INSERT = ("detections", "detection_observations", "detection_evidence")
WORKER_WORKING = ("evaluation_queue", "evaluation_dead_letter", "meta_counters")


def _role(name: str) -> str | None:
    role = context.config.attributes.get(name)
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError(f"{name} must be a lowercase Postgres role name")
    return role


def _functions_sql(worker: str | None) -> str:
    worker_literal = f"'{worker}'" if worker else "NULL"  # validated against _ROLE_NAME
    return f"""
CREATE FUNCTION tuisku_is_worker() RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    SELECT current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class
                           WHERE oid = 'public.detections'::regclass)
        OR current_user IS NOT DISTINCT FROM {worker_literal}::name
$$;

CREATE FUNCTION tuisku_detections_worker_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.evaluator = 'tuisku' AND NOT public.tuisku_is_worker()
       -- the API's own ingest meta-detections (ADR 0005): identity is the kind, bucketed
       AND NOT (NEW.kind LIKE 'tuisku.meta.%' AND NEW.identity = NEW.kind
                AND NEW.bucket_start IS NOT NULL)
    THEN
        RAISE EXCEPTION 'only the worker role writes tuisku-evaluated detections (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER detections_worker_only BEFORE INSERT ON detections
    FOR EACH ROW EXECUTE FUNCTION tuisku_detections_worker_only();

CREATE FUNCTION tuisku_rule_links_worker_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT public.tuisku_is_worker() AND EXISTS (
        SELECT 1 FROM public.detections d
        WHERE d.id = NEW.detection_id AND d.evaluator = 'tuisku'
    ) THEN
        RAISE EXCEPTION 'only the worker role links rule output to evidence (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER detection_observations_worker_only BEFORE INSERT ON detection_observations
    FOR EACH ROW EXECUTE FUNCTION tuisku_rule_links_worker_only();

CREATE FUNCTION tuisku_events_operator_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.actor NOT LIKE 'operator:%' AND NOT public.tuisku_is_worker() THEN
        RAISE EXCEPTION 'only the worker role writes % events (ADR 0011)', NEW.actor
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


def upgrade() -> None:
    app, worker = _role("app_role"), _role("worker_role")
    op.execute(_functions_sql(worker if app else None))
    if app is None:
        return  # single-role setup: the migrating role (the owner) does everything
    if worker is None:
        raise ValueError("a separate worker role is required with an app role (ADR 0011)")
    op.execute(f'GRANT SELECT ON {", ".join(WORKER_READ)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT ON {", ".join(WORKER_INSERT)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {", ".join(WORKER_WORKING)} TO "{worker}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{worker}"')
    op.execute(f'REVOKE INSERT ON detection_evidence FROM "{app}"')


def downgrade() -> None:
    op.execute("DROP TRIGGER detections_worker_only ON detections")
    op.execute("DROP TRIGGER detection_observations_worker_only ON detection_observations")
    op.execute("DROP TRIGGER finding_events_actor ON finding_events")
    op.execute("DROP TRIGGER incident_events_actor ON incident_events")
    op.execute(
        "DROP FUNCTION tuisku_detections_worker_only(), tuisku_rule_links_worker_only(), "
        "tuisku_events_operator_only(), tuisku_is_worker()"
    )
    app = _role("app_role")
    if app is not None:
        op.execute(f'GRANT INSERT ON detection_evidence TO "{app}"')
