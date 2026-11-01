import pytest
from pydantic import ValidationError

from tuisku.config import ConfigError, Settings

SECRET_URL = "postgresql://tuisku:s3cret-pw@db.example:5432/tuisku"


def test_reads_prefixed_environment(monkeypatch) -> None:
    monkeypatch.setenv("TUISKU_DATABASE_URL", SECRET_URL)
    monkeypatch.setenv("TUISKU_BUILD_REVISION", "deadbeef")
    settings = Settings()
    assert settings.require_database_url() == SECRET_URL
    assert settings.build_revision == "deadbeef"


def test_database_url_is_required_for_db_commands(monkeypatch) -> None:
    monkeypatch.delenv("TUISKU_DATABASE_URL", raising=False)
    with pytest.raises(ConfigError, match="TUISKU_DATABASE_URL is required"):
        Settings().require_database_url()


def test_rejects_non_postgres_url_without_echoing_it() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Settings(database_url="mysql://root:s3cret-pw@localhost/x")  # type: ignore[arg-type]
    assert "s3cret-pw" not in str(excinfo.value)


def test_secret_never_appears_in_repr() -> None:
    settings = Settings(database_url=SECRET_URL)  # type: ignore[arg-type]
    assert "s3cret-pw" not in repr(settings)
    assert "s3cret-pw" not in str(settings.model_dump())


def test_pool_bounds_are_validated() -> None:
    with pytest.raises(ValidationError):
        Settings(pool_max_size=0)


def test_pool_min_must_not_exceed_max() -> None:
    with pytest.raises(ValidationError, match="pool_min_size must not exceed pool_max_size"):
        Settings(pool_min_size=5, pool_max_size=2)
