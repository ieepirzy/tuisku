"""Runtime settings, read from environment variables prefixed with ``TUISKU_``.

The database URL is a secret: it is held as ``SecretStr`` so it never appears in
``repr()``, logs or validation errors.
"""

from __future__ import annotations

import re
from typing import Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ALLOWED_SCHEMES = frozenset({"postgresql", "postgres"})
# A plain, unquoted Postgres role name: it is interpolated into GRANT statements.
_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class ConfigError(RuntimeError):
    """A setting required by the requested command is missing or invalid."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TUISKU_",
        extra="ignore",
        hide_input_in_errors=True,
    )

    # Required by `tuisku api` and `tuisku migrate`; see require_database_url().
    database_url: SecretStr | None = None
    build_revision: str = "unknown"
    pool_min_size: int = Field(default=1, ge=0)
    pool_max_size: int = Field(default=10, ge=1)
    # Upper bound on how long /v1/ready waits for a pooled connection.
    ready_timeout_seconds: float = Field(default=2.0, gt=0)
    # Path to alembic.ini; relative paths resolve against the working directory.
    alembic_config: str = "alembic.ini"
    # How long `tuisku migrate` waits for another migrator's advisory lock.
    migration_lock_timeout_seconds: float = Field(default=300.0, gt=0)
    # Postgres lock_timeout for migration DDL, so a blocked ALTER fails fast
    # instead of queueing every other query on the table behind it.
    migration_ddl_lock_timeout_seconds: float = Field(default=30.0, gt=0)
    # Role the API and worker connect as (ADR 0004). When set, `tuisku migrate` grants it
    # SELECT, INSERT on evidence tables and full DML on working tables. Unset: no grants
    # (single-role development setups).
    app_role: str | None = None
    # Role the worker connects as (ADR 0011). With app_role set, `tuisku migrate` grants it what
    # the worker writes (rule output, firing keys, links, findings, incidents) and the app role
    # loses those writes. Ignored in single-role setups (app_role unset).
    worker_role: str = "tuisku_worker"
    # Availability limits `tuisku migrate` sets on the app role (ADR 0011): a connection limit,
    # and defaults (a session can override them) for statement and idle-in-transaction timeouts.
    app_role_connection_limit: int = Field(default=20, ge=1)
    app_role_statement_timeout_seconds: float = Field(default=30.0, gt=0)
    app_role_idle_in_transaction_seconds: float = Field(default=60.0, gt=0)

    # Ingest limits (ADR 0005), enforced at the HTTP boundary.
    ingest_max_body_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    ingest_max_lines: int = Field(default=5000, ge=1)
    ingest_max_line_bytes: int = Field(default=256 * 1024, ge=1)
    ingest_max_collector_bytes: int = Field(default=4096, ge=2)
    # Per-source token bucket, in records per second. In-process: each API replica keeps
    # its own buckets, so the effective limit is replicas x rate.
    ingest_rate_per_second: float = Field(default=1000.0, gt=0)
    ingest_rate_burst: float = Field(default=10000.0, ge=1)
    # 429s are counted in process and written at most this often per source (and at shutdown).
    ingest_rate_breach_flush_seconds: float = Field(default=10.0, gt=0)
    # Wall-clock budget for one ingest request. Once spent, the remaining lines are not
    # processed and the answer is 503 with Retry-After (already processed lines are kept).
    ingest_request_budget_seconds: float = Field(default=10.0, gt=0)
    # Worker threads that run adapters, off the event loop.
    ingest_parse_threads: int = Field(default=4, ge=1)
    # Wall-clock deadline for one record's parse. An overrunning parse is abandoned (its thread
    # cannot be killed) and the record is kept with a failed `time_budget` parse attempt.
    ingest_parse_timeout_seconds: float = Field(default=2.0, gt=0)
    # An event_time further than this in the future of received_at is flagged clock_skew
    # and evaluated at received_at (ADR 0004 section 6).
    clock_skew_tolerance_seconds: float = Field(default=300.0, ge=0)

    # Rule packs (ADR 0006). The built-in directory resolves against the working directory, like
    # alembic_config. Extra pack directories are separated by os.pathsep (":" on Linux).
    builtin_packs_dir: str = "packs"
    rule_pack_paths: str = ""
    rule_params_file: str | None = None

    # Worker (ADR 0006). The caps are the ADR's hard limits and can only be lowered.
    worker_batch_size: int = Field(default=100, ge=1, le=10_000)
    worker_lease_seconds: float = Field(default=120.0, gt=0)
    worker_poll_seconds: float = Field(default=1.0, gt=0)
    worker_statement_timeout_seconds: float = Field(default=10.0, gt=0)
    worker_max_open_findings: int = Field(default=1000, ge=1, le=1000)
    worker_max_live_incidents: int = Field(default=100, ge=1, le=100)
    # A counter's first sample counts in full when its start_time is within one export
    # interval of the source's first receipt (ADR 0006 "Metric samples").
    worker_export_interval_seconds: float = Field(default=60.0, gt=0)
    worker_allowed_lateness_seconds: float = Field(default=86400.0, ge=0)
    # Queued rows or undelivered notifications older than this page as tuisku.meta.backlog.
    worker_backlog_seconds: float = Field(default=300.0, gt=0)

    @field_validator("database_url")
    @classmethod
    def _check_scheme(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value()
        scheme = urlsplit(raw).scheme
        if scheme not in _ALLOWED_SCHEMES:
            # Never echo the value: it may carry a password.
            raise ValueError("must be a postgresql:// URL")
        return value

    @field_validator("worker_role")
    @classmethod
    def _check_worker_role(cls, value: str) -> str:
        if not _ROLE_NAME.fullmatch(value):
            raise ValueError("must be a lowercase Postgres role name ([a-z_][a-z0-9_]*)")
        return value

    @field_validator("app_role")
    @classmethod
    def _check_app_role(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not _ROLE_NAME.fullmatch(value):
            raise ValueError("must be a lowercase Postgres role name ([a-z_][a-z0-9_]*)")
        return value

    @model_validator(mode="after")
    def _check_pool_bounds(self) -> Self:
        if self.pool_min_size > self.pool_max_size:
            raise ValueError("pool_min_size must not exceed pool_max_size")
        return self

    def require_database_url(self) -> str:
        """Return the database URL, or raise ConfigError when it is not configured."""
        if self.database_url is None:
            raise ConfigError("TUISKU_DATABASE_URL is required")
        return self.database_url.get_secret_value()
