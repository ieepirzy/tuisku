from fastapi.testclient import TestClient

from tests.conftest import UNREACHABLE_DATABASE_URL, make_settings
from tuisku.api.app import create_app


def test_ready_when_database_is_up(database_url: str) -> None:
    with TestClient(create_app(make_settings(database_url))) as client:
        response = client.get("/v1/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "revision": "test-revision", "database": "ok"}


def test_ready_is_503_when_database_is_down() -> None:
    settings = make_settings(UNREACHABLE_DATABASE_URL, ready_timeout_seconds=0.5)
    with TestClient(create_app(settings)) as client:
        response = client.get("/v1/ready")
    assert response.status_code == 503
    body = response.json()
    assert body == {"status": "unavailable", "revision": "test-revision", "database": "unreachable"}
    assert "unused" not in response.text  # no connection details leak
