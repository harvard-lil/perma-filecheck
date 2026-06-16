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


def test_scan_file_unexpected_return_code(monkeypatch, tmp_path):
    class Result:
        returncode = 2

    monkeypatch.setattr("main.subprocess.run", lambda *args, **kwargs: Result())

    from main import scan_file

    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello")

    assert scan_file(str(test_file)) == (False, "clamav scan failed")


def test_scan_file_timeout(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="clamdscan", timeout=30)

    monkeypatch.setattr("main.subprocess.run", raise_timeout)

    from main import scan_file
    assert scan_file("/tmp/test") == (False, "clamav scan timed out")


def test_scan_file_subprocess_exception(monkeypatch):
    def raise_error(*args, **kwargs):
        raise RuntimeError("unexpected error")

    monkeypatch.setattr("main.subprocess.run", raise_error)

    from main import scan_file
    assert scan_file("/tmp/test") == (False, "clamav scan failed: unexpected error")


def test_clamav_not_available_cache_cleared(monkeypatch):
    from main import clamav_signature_age

    def raise_error():
        raise subprocess.CalledProcessError(returncode=2, cmd=["clamdscan"])

    # Use the real lru_cache-wrapped function so cache_clear exists and is exercised
    clamav_signature_age.cache_clear()
    monkeypatch.setattr("main.clamav_signature_age", raise_error)
    # Restore cache_clear on the mock so hasattr check passes and line 147 is hit
    raise_error.cache_clear = clamav_signature_age.cache_clear

    response = post_asset("test.gif")
    assert response.json() == {"safe": False, "reason": "clamav not available"}