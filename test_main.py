import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from main import app, clamav_ping, clamav_signature_age


client = TestClient(app)
assets = Path(__file__).parent / "test_assets"


def post_asset(asset_path):
    contents = assets.joinpath(asset_path).read_bytes()
    return client.post("/scan/", files={"file": (asset_path, contents)})


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"healthy", "unhealthy"}


@pytest.mark.parametrize(
    "asset_path,verdict,reason",
    [
        # valid files
        ("test.gif", "clean", "file is safe"),
        ("test.jpg", "clean", "file is safe"),
        ("test.jpeg", "clean", "file is safe"),
        ("test.pdf", "clean", "file is safe"),
        ("test.png", "clean", "file is safe"),
        # invalid files
        ("unknown.foo", "rejected", "unrecognized file type"),
        ("test.tif", "rejected", "invalid file type"),
        (
            "eicar-standard-antivirus-test-file-adobe-acrobat-attachment.pdf",
            "unsafe",
            "virus detected",
        ),
        ("misnamed.jpg", "rejected", "invalid file extension"),
    ],
)
def test_response(asset_path, verdict, reason, monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    response = post_asset(asset_path)
    assert response.status_code == 200
    assert response.json() == {
        "safe": verdict == "clean",
        "verdict": verdict,
        "reason": reason,
    }


def test_clamav_not_available(monkeypatch):
    def raise_error():
        raise subprocess.CalledProcessError(
            returncode=2,
            cmd=["clamdscan", "--version"],
        )

    monkeypatch.setattr("main.clamav_signature_age", raise_error)
    assert post_asset("test.gif").json() == {
        "safe": False,
        "verdict": "unavailable",
        "reason": "clamav not running",
    }


def test_clamav_ping_exception(monkeypatch):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError("clamdscan")

    monkeypatch.setattr("main.subprocess.run", raise_error)
    assert clamav_ping() is False


def test_health_version_check_failed(monkeypatch):
    def raise_error():
        raise subprocess.CalledProcessError(returncode=2, cmd=["clamdscan"])

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
        "verdict": "unavailable",
        "reason": "clamav out of date",
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
        "verdict": "rejected",
        "reason": "file too large",
    }


def test_health_healthy(monkeypatch):
    monkeypatch.setattr("main.clamav_signature_age", lambda: 0)
    monkeypatch.setattr("main.clamav_ping", lambda: True)

    response = client.get("/health")
    assert response.json() == {
        "status": "healthy",
    }


def test_scan_file_timeout(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="clamdscan", timeout=30)

    monkeypatch.setattr("main.subprocess.run", raise_timeout)

    from main import scan_file
    assert scan_file("/tmp/test") == (False, "clamav not running")


def test_scan_file_process_start_error(monkeypatch):
    def raise_error(*args, **kwargs):
        raise FileNotFoundError("clamdscan")

    monkeypatch.setattr("main.subprocess.run", raise_error)

    from main import scan_file
    assert scan_file("/tmp/test") == (False, "clamav not running")


def test_clamav_signature_age_is_recomputed(monkeypatch):
    run = Mock(return_value=Mock(
        stdout="ClamAV 1.4.3/28033/Mon Jun 16 00:00:00 2025",
    ))
    monkeypatch.setattr("main.subprocess.run", run)

    clamav_signature_age()
    clamav_signature_age()

    assert run.call_count == 2


def test_scan_file_unexpected_return_code(monkeypatch, tmp_path):
    class Result:
        returncode = 2
        stdout = ""
        stderr = "clamd: connection refused"

    monkeypatch.setattr(
        "main.subprocess.run", lambda *args, **kwargs: Result()
    )

    from main import scan_file

    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello")

    assert scan_file(str(test_file)) == (False, "clamav not running")
