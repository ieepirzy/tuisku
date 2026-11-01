"""Evidence store: sources, tokens, L0-L2 evidence tables and the evaluation queue.

Revision ID: 0001
Revises:
Create Date: 2026-11-01

Layers (ADR 0002): raw_records / raw_duplicates / parse_attempts are L0, observations L1,
detections L2. Evidence tables are append-only (ADR 0004 sections 3-4): the app role gets only
SELECT and INSERT on them, and row and statement triggers reject UPDATE, DELETE and TRUNCATE
for everyone, including the owner, as a second line of defence.
"""

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tyyni migration-safety declaration (required; see AGENTS.md). Set to True only
# when this revision is expand-only: it only adds tables, nullable or defaulted
# columns, or plain indexes. Keep exactly one plain line: `= True` or `= False`.
expand_only = True

# Append-only tables (ADR 0004 section 4).
EVIDENCE_TABLES = (
    "raw_records",
    "raw_duplicates",
    "parse_attempts",
    "observations",
    "detections",
    "detection_observations",
    "detection_evidence",
)
# Mutable working tables the app role may change.
WORKING_TABLES = (
    "sources",
    "source_tokens",
    "operator_tokens",
    "evaluation_queue",
    "evaluation_dead_letter",
)

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

# Kinds are short, stable names such as network.flow or tuisku.meta.source_limit_exceeded.
_KIND_CHECK = "char_length(kind) BETWEEN 1 AND 128 AND kind ~ '^[a-z0-9][a-z0-9_.:-]*$'"
# A row's evaluation time (ADR 0006): its event_time, or received_at when the event time is
# missing or the row is flagged clock_skew (future-dated beyond the tolerance, ADR 0004 s6).
_EVAL_TIME_CHECK = (
    "eval_time = CASE WHEN event_time IS NULL OR 'clock_skew' = ANY (flags) "
    "THEN received_at ELSE event_time END"
)

TABLES_SQL = f"""
CREATE TABLE sources (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid             uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    name            text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9_.-]{{0,62}}$'),
    adapter         text NOT NULL CHECK (char_length(adapter) BETWEEN 1 AND 64),
    adapter_options jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(adapter_options) = 'object'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    disabled_at     timestamptz
);

CREATE TABLE source_tokens (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid          uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    source_id    bigint NOT NULL REFERENCES sources (id),
    token_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    label        text CHECK (char_length(label) <= 200),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    -- Working column (not evidence): updated at most once a minute per token.
    last_used_at timestamptz
);
CREATE INDEX source_tokens_source_id_idx ON source_tokens (source_id);

CREATE TABLE operator_tokens (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid          uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    -- The named person the token is bound to (ADR 0005); required for `approve`.
    person       text CHECK (char_length(person) BETWEEN 1 AND 200),
    roles        text[] NOT NULL CHECK (
                     cardinality(roles) >= 1
                     AND array_position(roles, NULL) IS NULL
                     AND roles <@ ARRAY['read', 'triage', 'admin', 'approve']::text[]
                 ),
    token_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    CONSTRAINT operator_tokens_approve_needs_person
        CHECK (NOT ('approve' = ANY (roles)) OR person IS NOT NULL)
);

-- L0: the record exactly as received.
CREATE TABLE raw_records (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid         uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    source_id   bigint NOT NULL REFERENCES sources (id),
    token_id    bigint NOT NULL REFERENCES source_tokens (id),
    -- NDJSON: digest of the UTF-8 bytes of the envelope's raw string; OTLP: of the body.
    sha256      bytea NOT NULL CHECK (octet_length(sha256) = 32),
    received_at timestamptz NOT NULL,
    transport   text NOT NULL CHECK (transport IN ('ndjson', 'otlp_json')),
    -- Shipper-supplied receipt metadata; untrusted, never evidence about the event.
    collector   jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(collector) = 'object'),
    -- NULL once retention clears it (ADR 0004 section 9); sha256 and body_size stay.
    body        bytea,
    body_size   integer NOT NULL CHECK (body_size >= 0),
    CONSTRAINT raw_records_source_sha256_key UNIQUE (source_id, sha256)
);
CREATE INDEX raw_records_source_received_idx ON raw_records (source_id, received_at);

CREATE TABLE raw_duplicates (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    raw_record_id bigint NOT NULL REFERENCES raw_records (id),
    received_at   timestamptz NOT NULL,
    token_id      bigint NOT NULL REFERENCES source_tokens (id)
);
CREATE INDEX raw_duplicates_raw_record_id_idx ON raw_duplicates (raw_record_id);

CREATE TABLE parse_attempts (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid             uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    raw_record_id   bigint NOT NULL REFERENCES raw_records (id),
    adapter         text NOT NULL,
    -- NULL only when the source's adapter is not available in this build.
    adapter_version text,
    status          text NOT NULL CHECK (status IN ('ok', 'failed')),
    error           text CHECK (char_length(error) <= 1000),
    created_at      timestamptz NOT NULL,
    CONSTRAINT parse_attempts_error_iff_failed CHECK ((status = 'failed') = (error IS NOT NULL)),
    CONSTRAINT parse_attempts_version_if_ok CHECK (status = 'failed' OR adapter_version IS NOT NULL)
);
CREATE INDEX parse_attempts_raw_record_id_idx ON parse_attempts (raw_record_id);

-- L1: facts derived by a versioned adapter from one raw record.
CREATE TABLE observations (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    raw_record_id    bigint NOT NULL REFERENCES raw_records (id),
    parse_attempt_id bigint NOT NULL REFERENCES parse_attempts (id),
    source_id        bigint NOT NULL REFERENCES sources (id),
    kind             text NOT NULL CHECK ({_KIND_CHECK}),
    event_time       timestamptz,
    received_at      timestamptz NOT NULL,
    eval_time        timestamptz NOT NULL,
    ocsf_class_uid   integer,
    ocsf_version     text NOT NULL,
    attributes       jsonb NOT NULL CHECK (jsonb_typeof(attributes) = 'object'),
    unmapped         jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(unmapped) = 'object'),
    entity_keys      text[] NOT NULL DEFAULT '{{}}',
    community_id     text CHECK (char_length(community_id) <= 128),
    -- Sensor-scoped join keys, values qualified as '<source_id>:<value>' (ADR 0003 s7).
    correlation      jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(correlation) = 'object'),
    flags            text[] NOT NULL DEFAULT '{{}}',
    CONSTRAINT observations_eval_time_check CHECK ({_EVAL_TIME_CHECK})
);
CREATE INDEX observations_entity_keys_idx ON observations USING gin (entity_keys);
CREATE INDEX observations_kind_eval_time_idx ON observations (kind, eval_time);
CREATE INDEX observations_source_received_idx ON observations (source_id, received_at);
CREATE INDEX observations_community_id_idx ON observations (community_id)
    WHERE community_id IS NOT NULL;
CREATE INDEX observations_raw_record_id_idx ON observations (raw_record_id);
CREATE INDEX observations_parse_attempt_id_idx ON observations (parse_attempt_id);

-- L2: verdicts of deterministic mechanisms (ADR 0002): sensor-evaluated (from a raw record)
-- or tuisku-evaluated (pack rules and meta-detections, no raw record).
CREATE TABLE detections (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    raw_record_id    bigint REFERENCES raw_records (id),
    parse_attempt_id bigint REFERENCES parse_attempts (id),
    source_id        bigint REFERENCES sources (id),
    evaluator        text NOT NULL CHECK (evaluator IN ('sensor', 'tuisku')),
    authorship       text NOT NULL CHECK (authorship IN ('builtin', 'community', 'local', 'tuisku')),
    kind             text NOT NULL CHECK ({_KIND_CHECK}),
    identity         text NOT NULL CHECK (char_length(identity) BETWEEN 1 AND 512),
    title            text NOT NULL CHECK (char_length(title) <= 1024),
    severity_id      smallint NOT NULL CHECK (severity_id BETWEEN 0 AND 6),
    event_time       timestamptz,
    received_at      timestamptz NOT NULL,
    eval_time        timestamptz NOT NULL,
    ocsf_version     text NOT NULL,
    rule_ref         jsonb NOT NULL CHECK (jsonb_typeof(rule_ref) = 'object'),
    attack           text[] NOT NULL DEFAULT '{{}}',
    attributes       jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(attributes) = 'object'),
    entity_keys      text[] NOT NULL DEFAULT '{{}}',
    explanation      jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(explanation) = 'object'),
    flags            text[] NOT NULL DEFAULT '{{}}',
    CONSTRAINT detections_eval_time_check CHECK ({_EVAL_TIME_CHECK}),
    -- Sensor verdicts come from a parsed raw record and are never tuisku-authored;
    -- tuisku-evaluated rows have no raw record.
    CONSTRAINT detections_provenance_check CHECK (
        (evaluator = 'sensor' AND authorship <> 'tuisku' AND raw_record_id IS NOT NULL
             AND parse_attempt_id IS NOT NULL AND source_id IS NOT NULL)
        OR (evaluator = 'tuisku' AND raw_record_id IS NULL AND parse_attempt_id IS NULL)
    )
);
CREATE INDEX detections_entity_keys_idx ON detections USING gin (entity_keys);
CREATE INDEX detections_kind_eval_time_idx ON detections (kind, eval_time);
CREATE INDEX detections_source_received_idx ON detections (source_id, received_at);
CREATE INDEX detections_raw_record_id_idx ON detections (raw_record_id);
CREATE INDEX detections_parse_attempt_id_idx ON detections (parse_attempt_id);

CREATE TABLE detection_observations (
    detection_id   bigint NOT NULL REFERENCES detections (id),
    observation_id bigint NOT NULL REFERENCES observations (id),
    PRIMARY KEY (detection_id, observation_id)
);
CREATE INDEX detection_observations_observation_id_idx
    ON detection_observations (observation_id);

-- Rows matched between correlation firings, linked to the latest firing (ADR 0006).
CREATE TABLE detection_evidence (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id     bigint NOT NULL REFERENCES detections (id),
    observation_id   bigint REFERENCES observations (id),
    detection_ref_id bigint REFERENCES detections (id),
    linked_at        timestamptz NOT NULL,
    CONSTRAINT detection_evidence_one_target CHECK (num_nonnulls(observation_id, detection_ref_id) = 1)
);
CREATE INDEX detection_evidence_detection_id_idx ON detection_evidence (detection_id);

-- Work queue for rule evaluation (ADR 0006); rows are deleted when evaluated.
CREATE TABLE evaluation_queue (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    observation_id bigint REFERENCES observations (id),
    detection_id   bigint REFERENCES detections (id),
    enqueued_at    timestamptz NOT NULL DEFAULT now(),
    attempts       integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error     text,
    CONSTRAINT evaluation_queue_one_target CHECK (num_nonnulls(observation_id, detection_id) = 1)
);

CREATE TABLE evaluation_dead_letter (
    id             bigint PRIMARY KEY,  -- the evaluation_queue id it had
    observation_id bigint REFERENCES observations (id),
    detection_id   bigint REFERENCES detections (id),
    enqueued_at    timestamptz NOT NULL,
    attempts       integer NOT NULL CHECK (attempts >= 0),
    last_error     text,
    moved_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evaluation_dead_letter_one_target CHECK (num_nonnulls(observation_id, detection_id) = 1)
);
"""

# ADR 0004 sections 3-4: evidence rows are never updated or deleted by anything but the
# retention function. That function (tuisku_apply_retention(), SECURITY DEFINER, owned by the
# owner role) is not built yet. When it lands, this trigger gains exactly one exception:
# current_user is the owner role AND the UPDATE only sets payload columns (body, attributes,
# unmapped, explanation) to NULL. Until then it rejects every UPDATE, DELETE and TRUNCATE.
TRIGGER_FUNCTION_SQL = """
CREATE FUNCTION tuisku_reject_evidence_change() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'evidence table %.% is append-only: % is not allowed (ADR 0004)',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
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
    op.execute(TRIGGER_FUNCTION_SQL)
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
    op.execute(
        "DROP TABLE evaluation_dead_letter, evaluation_queue, detection_evidence, "
        "detection_observations, detections, observations, parse_attempts, raw_duplicates, "
        "raw_records, operator_tokens, source_tokens, sources"
    )
    op.execute("DROP FUNCTION tuisku_reject_evidence_change()")
