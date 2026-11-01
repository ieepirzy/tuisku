"""Runtime settings, read from environment variables prefixed with ``TUISKU_``.

The database URL is a secret: it is held as ``SecretStr`` so it never appears in
``repr()``, logs or validation errors.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ALLOWED_SCHEMES = frozenset({"postgresql", "postgres"})


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

    def require_database_url(self) -> str:
        """Return the database URL, or raise ConfigError when it is not configured."""
        if self.database_url is None:
            raise ConfigError("TUISKU_DATABASE_URL is required")
        return self.database_url.get_secret_value()
