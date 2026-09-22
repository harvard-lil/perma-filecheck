import json

from fastapi.testclient import TestClient

from main import app


def test_access_record_attribution(monkeypatch, capsys):
    monkeypatch.setenv("SERVICE_NAME", "perma-filecheck")
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("SENTRY_RELEASE", "test-release")
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    monkeypatch.setattr("main.clamav_ping", lambda: True)
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    record = json.loads(capsys.readouterr().out)
    assert record["event"] == "http_access"
    assert record["service"] == "perma-filecheck"
    assert record["environment"] == "staging"
    assert record["release"] == "test-release"
    assert record["client_ip"] is None
