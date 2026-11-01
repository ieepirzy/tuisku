from fastapi.testclient import TestClient

from tests.conftest import UNREACHABLE_DATABASE_URL, make_settings
from tuisku.api.app import create_app


def test_health_is_ok_without_a_database() -> None:
    app = create_app(make_settings(UNREACHABLE_DATABASE_URL))
    with TestClient(app) as client:
        response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "revision": "test-revision"}


def test_build_revision_comes_from_env(monkeypatch) -> None:
    monkeypatch.setenv("TUISKU_BUILD_REVISION", "abc123")
    monkeypatch.setenv("TUISKU_DATABASE_URL", UNREACHABLE_DATABASE_URL)
    with TestClient(create_app()) as client:
        assert client.get("/v1/health").json()["revision"] == "abc123"
