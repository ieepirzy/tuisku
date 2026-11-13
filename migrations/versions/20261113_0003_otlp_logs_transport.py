"""raw_records.transport: allow 'otlp_logs_json' (ADR 0005, OTLP/HTTP JSON logs).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-13

A record that arrives as one ``logRecord`` of an OTLP/HTTP JSON logs request is stored with
transport ``otlp_logs_json``: its body is that record's ``body.stringValue``, not the request
body (which ``otlp_json``, the metrics transport, stores whole). Keeping the two apart keeps the
L0 provenance exact.

The CHECK is widened, never narrowed: every value the previous release writes is still valid,
so the previous image runs unchanged on this schema. Tyyni's allowlist still reads a dropped
and re-added constraint as ``contract``, so this revision is declared ``expand_only = False``
and a rollback across it escalates to a person. The new constraint is added ``NOT VALID`` and
then validated, so the table is locked exclusively only for the catalogue change and the scan
runs under a lock that lets ingest continue.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = False


def upgrade() -> None:
    op.execute("ALTER TABLE raw_records DROP CONSTRAINT raw_records_transport_check")
    op.execute(
        "ALTER TABLE raw_records ADD CONSTRAINT raw_records_transport_check "
        "CHECK (transport IN ('ndjson', 'otlp_json', 'otlp_logs_json')) NOT VALID"
    )
    op.execute("ALTER TABLE raw_records VALIDATE CONSTRAINT raw_records_transport_check")


def downgrade() -> None:
    # Fails while any otlp_logs_json record exists: evidence is never deleted to make room.
    op.execute("ALTER TABLE raw_records DROP CONSTRAINT raw_records_transport_check")
    op.execute(
        "ALTER TABLE raw_records ADD CONSTRAINT raw_records_transport_check "
        "CHECK (transport IN ('ndjson', 'otlp_json'))"
    )
