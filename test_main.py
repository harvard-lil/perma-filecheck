import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from main import app, clamav_ping


client = TestClient(app)
assets = Path(__file__).parent / "test_assets"


def post_asset(asset_path):
    return client.post("/scan/", files={"file": (asset_path, assets.joinpath(asset_path).read_bytes())})


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"healthy", "unhealthy"}


@pytest.mark.parametrize("asset_path,expected_response", [
        # valid files
        ("test.gif", {"safe": True, "reason": "file is safe"}),
        ("test.jpg", {"safe": True, "reason": "file is safe"}),
        ("test.jpeg", {"safe": True, "reason": "file is safe"}),
        ("test.pdf", {"safe": True, "reason": "file is safe"}),
        ("test.png", {"safe": True, "reason": "file is safe"}),
        # invalid files
        ("unknown.foo", {"safe": False, "reason": "unrecognized file type"}),
        ("test.tif", {"safe": False, "reason": "invalid file type"}),
        ("eicar-standard-antivirus-test-file-adobe-acrobat-attachment.pdf", {"safe": False, "reason": "virus detected"}),
        ("misnamed.jpg", {"safe": False, "reason": "invalid file extension"}),
    ])
def test_response(asset_path, expected_response, monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    response = post_asset(asset_path)
    assert response.status_code == 200
    assert response.json() == expected_response


def test_clamav_not_available(monkeypatch):
    def raise_error():
        raise subprocess.CalledProcessError(
            returncode=2,
            cmd=["clamdscan", "--version"],
        )

    monkeypatch.setattr("main.clamav_signature_age", raise_error)
    assert post_asset("test.gif").json() == {
        "safe": False,
        "reason": "clamav not available",
    }


def test_clamav_ping_exception(monkeypatch):
    def raise_error(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("main.subprocess.run", raise_error)
    assert clamav_ping() is False


def test_health_version_check_failed(monkeypatch):
    def raise_error():
        raise RuntimeError("boom")

    monkeypatch.setattr("main.clamav_signature_age", raise_error)
    response = client.get("/health")
    assert response.json() == {
        "status": "unhealthy",
        "reason": "clamav version check failed",
    }


def test_health_daemon_not_responding(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    monkeypatch.setattr("main.clamav_ping", lambda: False)

    response = client.get("/health")
    assert response.json() == {
        "status": "unhealthy",
        "reason": "clamav daemon not responding",
    }


def test_health_signatures_outdated(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 60 * 60 * 24 * 8)
    monkeypatch.setattr("main.clamav_ping", lambda: True)

    response = client.get("/health")
    assert response.json() == {
        "status": "unhealthy",
        "reason": "clamav signatures outdated",
    }


def test_scan_signatures_outdated(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 60 * 60 * 24 * 8)

    response = post_asset("test.gif")
    assert response.json() == {
        "safe": False,
        "reason": "clamav signatures outdated",
    }


def test_scan_file_too_large(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    monkeypatch.setattr("main.MAX_FILE_SIZE", 1)

    response = client.post(
        "/scan/",
        files={"file": ("test.gif", b"GIF89a")},
    )

    assert response.json() == {
        "safe": False,
        "reason": "file too large",
    }


def test_health_healthy(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    monkeypatch.setattr("main.clamav_ping", lambda: True)

    response = client.get("/health")
    assert response.json() == {
        "status": "healthy",
    }
