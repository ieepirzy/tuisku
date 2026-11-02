"""Evidence store: sources, tokens, L0-L2 evidence tables and the evaluation queue.

Revision ID: 0001
Revises:
Create Date: 2026-11-01

Layers (ADR 0002): raw_records / raw_duplicates / parse_attempts are L0, observations L1,
detections L2. Evidence tables are append-only (ADR 0004 sections 3-4): the app role gets only
SELECT and INSERT on them, and row and statement triggers reject UPDATE, DELETE and TRUNCATE
for everyone, including the owner, as a second line of defence.

The worker connects as its own role (TUISKU_WORKER_ROLE, ADR 0011), so a compromised API process
cannot forge rule output: only the worker role may insert into detection_evidence, and a trigger
keeps tuisku-evaluated detections and links to them to the worker role, except the API's own
bucketed ingest meta-detections.
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
    "meta_counters",
)

# ADR 0011: the worker connects as its own role. Only it writes rule output: the API role never
# gets INSERT on detection_evidence, and a trigger keeps tuisku-evaluated detections (and links
# to them) to the worker, apart from the API's own ingest meta-detections.
API_INSERT = tuple(t for t in EVIDENCE_TABLES if t != "detection_evidence")
API_ADMIN = ("sources", "source_tokens")
WORKER_READ = ("raw_records", "parse_attempts", "observations", "sources")
WORKER_INSERT = ("detections", "detection_observations", "detection_evidence")
WORKER_WORKING = ("evaluation_queue", "evaluation_dead_letter", "meta_counters")

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
    -- The source's name when the record arrived: evidence keeps it even if the source is
    -- renamed later, and rules match on it (ADR 0011).
    source_name text NOT NULL CHECK (char_length(source_name) BETWEEN 1 AND 63),
    token_id    bigint NOT NULL REFERENCES source_tokens (id),
    -- NDJSON: digest of the UTF-8 bytes of the envelope's raw string; OTLP: of the body.
    sha256      bytea NOT NULL CHECK (octet_length(sha256) = 32),
    received_at timestamptz NOT NULL,
    transport   text NOT NULL CHECK (transport IN ('ndjson', 'otlp_json')),
    -- Shipper-supplied receipt metadata; untrusted, never evidence about the event.
    collector   jsonb NOT NULL DEFAULT '{{}}' CHECK (jsonb_typeof(collector) = 'object'),
    -- NULL once retention clears it (ADR 0004 section 9); sha256 and body_size stay.
    body        bytea,
    -- Size of the record as received; sha256 always covers all of it.
    body_size   integer NOT NULL CHECK (body_size >= 0),
    -- An over-long line is stored cut to the line limit, unparsed (ADR 0005).
    truncated   boolean NOT NULL DEFAULT false,
    CONSTRAINT raw_records_source_sha256_key UNIQUE (source_id, sha256),
    CONSTRAINT raw_records_truncation_check CHECK (
        body IS NULL
        OR (NOT truncated AND octet_length(body) = body_size)
        OR (truncated AND octet_length(body) < body_size)
    )
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
-- The current derivation of a raw record is its newest successful attempt (ADR 0002 rule 3).
CREATE INDEX parse_attempts_current_idx ON parse_attempts (raw_record_id, id DESC)
    WHERE status = 'ok';

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
    -- Meta-detections (ADR 0005): what the breach is about (the limit name, or the rule id
    -- for evaluation failures) and the 5-minute bucket. One row per source, kind, subject
    -- and bucket. Other detections keep subject '' and bucket_start NULL.
    subject          text NOT NULL DEFAULT '' CHECK (char_length(subject) <= 200),
    bucket_start     timestamptz,
    CONSTRAINT detections_bucket_only_meta CHECK (
        bucket_start IS NULL OR (evaluator = 'tuisku' AND kind LIKE 'tuisku.meta.%')
    ),
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
-- At most one meta-detection per source, kind, subject and bucket, across replicas (ADR 0005).
-- NULLS NOT DISTINCT: a meta-detection without a source is still deduplicated.
CREATE UNIQUE INDEX detections_meta_bucket_key
    ON detections (source_id, kind, subject, bucket_start) NULLS NOT DISTINCT
    WHERE bucket_start IS NOT NULL;

-- Working table: how many breaches each meta-detection bucket absorbed. Detections are
-- append-only, so repeats are counted here instead (ADR 0005).
CREATE TABLE meta_counters (
    source_id    bigint REFERENCES sources (id),
    kind         text NOT NULL,
    subject      text NOT NULL DEFAULT '',
    bucket_start timestamptz NOT NULL,
    count        bigint NOT NULL DEFAULT 0 CHECK (count >= 0),
    CONSTRAINT meta_counters_key UNIQUE NULLS NOT DISTINCT (source_id, kind, subject, bucket_start)
);

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
    -- Worker lease (ADR 0006): a row whose lease expired is claimable again.
    claimed_until  timestamptz,
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


# ADR 0005: approve tokens and person-bound operator tokens are issued out of band, only by the
# database owner (`tuisku approver add`, `tuisku operator-token add --person`). The API and
# worker connect as the app role, so this holds even against a compromised admin API.
PERSON_TOKEN_FUNCTION_SQL = """
CREATE FUNCTION tuisku_person_tokens_owner_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF (NEW.person IS NOT NULL OR 'approve' = ANY (NEW.roles))
       AND current_user <> (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID)
    THEN
        RAISE EXCEPTION 'person-bound and approve operator tokens are issued only by the '
            'database owner (ADR 0005)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER operator_tokens_person_owner_only BEFORE INSERT OR UPDATE ON operator_tokens
    FOR EACH ROW EXECUTE FUNCTION tuisku_person_tokens_owner_only();
"""


def _role(name: str) -> str | None:
    role = context.config.attributes.get(name)
    if not role:
        return None
    if not isinstance(role, str) or not _ROLE_NAME.fullmatch(role):
        raise ValueError(f"{name} must be a lowercase Postgres role name")
    return role


def _worker_functions_sql(worker: str | None) -> str:
    """ADR 0011 triggers. The worker role's name is fixed into the function at migration time,
    like the grants; in single-role setups only the owner qualifies (and does everything)."""
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

-- True when a row's inserting transaction is this one (or one of its subtransactions). A row
-- whose inserting transaction is still in progress and that we can see can only be our own
-- (another session's uncommitted rows are invisible), so its xmin, widened to 64 bits with the
-- current epoch, must have pg_xact_status() 'in progress'.
CREATE FUNCTION tuisku_xmin_is_current(x xid) RETURNS boolean
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
    cur      bigint := pg_current_xact_id()::text::bigint;
    full_xid bigint := ((cur >> 32) << 32) + x::text::bigint;
BEGIN
    IF full_xid - cur > 2147483648 THEN
        full_xid := full_xid - 4294967296;  -- the xid is from the previous epoch
    END IF;
    RETURN full_xid >= 3 AND pg_xact_status(full_xid::text::xid8) = 'in progress';
END
$$;

-- Derivations come with their raw record (ADR 0002, ADR 0011): for any role but the worker and
-- the owner, a parse attempt is accepted only for a raw record inserted in this transaction, and
-- an observation or sensor detection only for a parse attempt inserted in this transaction for
-- the same raw record. Otherwise the API role could add an `ok` attempt to a victim's raw
-- record, make its real rows stale and hide them from rules and readers, or attach fake rows.
CREATE FUNCTION tuisku_derivation_same_transaction() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'parse_attempts' THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.raw_records r
            WHERE r.id = NEW.raw_record_id AND public.tuisku_xmin_is_current(r.xmin)
        ) THEN
            RAISE EXCEPTION 'a parse attempt is written with its raw record (ADR 0011)'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
    ELSIF TG_TABLE_NAME = 'detections' THEN
        IF NEW.evaluator <> 'sensor' THEN
            RETURN NEW;  -- tuisku-evaluated rows: tuisku_detections_worker_only()
        END IF;
    END IF;
    -- An observation or a sensor detection.
    IF NOT EXISTS (
        SELECT 1 FROM public.parse_attempts p
        WHERE p.id = NEW.parse_attempt_id AND p.raw_record_id = NEW.raw_record_id
          AND public.tuisku_xmin_is_current(p.xmin)
    ) THEN
        RAISE EXCEPTION 'a derived row is written with its parse attempt (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER parse_attempts_same_transaction BEFORE INSERT ON parse_attempts
    FOR EACH ROW EXECUTE FUNCTION tuisku_derivation_same_transaction();
CREATE TRIGGER observations_same_transaction BEFORE INSERT ON observations
    FOR EACH ROW EXECUTE FUNCTION tuisku_derivation_same_transaction();
CREATE TRIGGER detections_same_transaction BEFORE INSERT ON detections
    FOR EACH ROW EXECUTE FUNCTION tuisku_derivation_same_transaction();

-- Ingest enqueues only what it has just written (ADR 0011): for any role but the worker and the
-- owner, a queue row may name only an observation or detection inserted in this transaction.
-- So the API role cannot flood the queue with existing rows, or re-enqueue them.
CREATE FUNCTION tuisku_queue_same_transaction() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    IF NOT (
        EXISTS (SELECT 1 FROM public.observations o WHERE o.id = NEW.observation_id
                AND public.tuisku_xmin_is_current(o.xmin))
        OR EXISTS (SELECT 1 FROM public.detections d WHERE d.id = NEW.detection_id
                   AND public.tuisku_xmin_is_current(d.xmin))
    ) THEN
        RAISE EXCEPTION 'only rows written in this transaction are enqueued (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER evaluation_queue_same_transaction BEFORE INSERT ON evaluation_queue
    FOR EACH ROW EXECUTE FUNCTION tuisku_queue_same_transaction();

-- A raw record's source_name is the source's name at receipt, set here whatever was supplied,
-- so evidence keeps the name it arrived with and no writer can fake it (ADR 0011).
CREATE FUNCTION tuisku_raw_source_name() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    SELECT s.name INTO NEW.source_name FROM public.sources s WHERE s.id = NEW.source_id;
    RETURN NEW;
END
$$;
CREATE TRIGGER raw_records_source_name BEFORE INSERT ON raw_records
    FOR EACH ROW EXECUTE FUNCTION tuisku_raw_source_name();

CREATE FUNCTION tuisku_current_bucket() RETURNS timestamptz
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    -- The 5-minute meta-detection bucket containing the transaction's now() (ADR 0005).
    SELECT to_timestamp(floor(extract(epoch FROM now()) / 300) * 300)
$$;

CREATE FUNCTION tuisku_detections_worker_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.evaluator = 'tuisku' AND NOT public.tuisku_is_worker()
       -- The API's own ingest meta-detections (ADR 0005): only its kinds, for a source, and
       -- only for the current 5-minute bucket by the database clock, so it cannot pre-claim a
       -- bucket and silence a later breach. evaluation_failed and notification_undeliverable
       -- are the worker's.
       AND NOT (NEW.kind IN ('tuisku.meta.source_limit_exceeded',
                             'tuisku.meta.source_rate_limited',
                             'tuisku.meta.invalid_envelope')
                AND NEW.identity = NEW.kind AND NEW.source_id IS NOT NULL
                AND NEW.bucket_start = public.tuisku_current_bucket())
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
    IF public.tuisku_is_worker() THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.detections d
        WHERE d.id = NEW.detection_id AND d.evaluator = 'tuisku'
    ) THEN
        RAISE EXCEPTION 'only the worker role links rule output to evidence (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Ingest links a sensor detection to observations of the same record, in the same
    -- transaction; never existing rows to each other.
    IF NOT EXISTS (
        SELECT 1 FROM public.detections d JOIN public.observations o
            ON o.parse_attempt_id = d.parse_attempt_id
        WHERE d.id = NEW.detection_id AND o.id = NEW.observation_id
          AND public.tuisku_xmin_is_current(d.xmin) AND public.tuisku_xmin_is_current(o.xmin)
    ) THEN
        RAISE EXCEPTION 'a sensor detection is linked with its record (ADR 0011)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER detection_observations_worker_only BEFORE INSERT ON detection_observations
    FOR EACH ROW EXECUTE FUNCTION tuisku_rule_links_worker_only();
"""


def upgrade() -> None:
    op.execute(TABLES_SQL)
    op.execute(TRIGGER_FUNCTION_SQL)
    op.execute(PERSON_TOKEN_FUNCTION_SQL)
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
    op.execute(_worker_functions_sql(worker if app else None))
    if app is None:
        return  # single-role setup: the migrating role (the owner) does everything
    if worker is None:
        raise ValueError("a separate worker role is required with an app role (ADR 0011)")
    op.execute(f'GRANT SELECT ON {", ".join(EVIDENCE_TABLES)} TO "{app}"')
    op.execute(f'GRANT INSERT ON {", ".join(API_INSERT)} TO "{app}"')
    # Sources and tokens: created by the API role, then only disabled or revoked; never renamed
    # or deleted (renames go through the owner CLI), so evidence keeps its provenance.
    op.execute(f'GRANT SELECT, INSERT ON {", ".join(API_ADMIN)} TO "{app}"')
    op.execute(f'GRANT UPDATE (disabled_at) ON sources TO "{app}"')
    op.execute(f'GRANT UPDATE (revoked_at, last_used_at) ON source_tokens TO "{app}"')
    # Tokens are revoked, never deleted, so their history stays (ADR 0005).
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON operator_tokens TO "{app}"')
    # Ingest only enqueues; only the worker claims, updates or deletes queue rows, so the API
    # cannot drop or park a row before it is evaluated (ADR 0011).
    op.execute(
        f'GRANT INSERT (observation_id, detection_id, enqueued_at) ON evaluation_queue TO "{app}"'
    )
    # Ingest counts breach repeats (an upsert); it never deletes counters.
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON meta_counters TO "{app}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{app}"')
    op.execute(f'GRANT SELECT ON {", ".join(WORKER_READ)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT ON {", ".join(WORKER_INSERT)} TO "{worker}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {", ".join(WORKER_WORKING)} TO "{worker}"')
    op.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{worker}"')


def downgrade() -> None:
    op.execute(
        "DROP TABLE meta_counters, evaluation_dead_letter, evaluation_queue, detection_evidence, "
        "detection_observations, detections, observations, parse_attempts, raw_duplicates, "
        "raw_records, operator_tokens, source_tokens, sources"
    )
    op.execute(
        "DROP FUNCTION tuisku_reject_evidence_change(), tuisku_person_tokens_owner_only(), "
        "tuisku_detections_worker_only(), tuisku_rule_links_worker_only(), tuisku_is_worker(), "
        "tuisku_current_bucket(), tuisku_derivation_same_transaction(), "
        "tuisku_xmin_is_current(xid), tuisku_queue_same_transaction(), tuisku_raw_source_name()"
    )
