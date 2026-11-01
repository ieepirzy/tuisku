"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

from collections.abc import Sequence

from alembic import op

revision: str = ${repr(up_revision)}
down_revision: str | Sequence[str] | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = False


def upgrade() -> None:
    # Raw SQL only, e.g. op.execute("CREATE TABLE ...").
    ${upgrades if upgrades else 'raise NotImplementedError("write the upgrade with op.execute()")'}


def downgrade() -> None:
    ${downgrades if downgrades else 'raise NotImplementedError("write the downgrade with op.execute()")'}
