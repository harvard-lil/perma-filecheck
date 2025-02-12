import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app


## helpers

client = TestClient(app)
assets = Path(__file__).parent / "test_assets"


def post_asset(asset_path):
    return client.post("/scan/", files={"file": (asset_path, assets.joinpath(asset_path).read_bytes())})


## tests

def test_home():
    assert client.get("/").json() == {"hello": "world"}


@pytest.mark.parametrize("asset_path,expected_response", [
    # valid files
    ("test.gif",  {"safe": True}),
    ("test.jpg", {"safe": True}),
    ("test.jpeg", {"safe": True}),
    ("test.pdf", {"safe": True}),
    ("test.png", {"safe": True}),
    # invalid files
    ("unknown.foo", {"safe": False, "reason": "unrecognized file type"}),
    ("test.tif", {"safe": False, "reason": "invalid file type"}),
    ("eicar-standard-antivirus-test-file-adobe-acrobat-attachment.pdf", {"safe": False, "reason": "clamav"}),
    ("misnamed.jpg", {"safe": False, "reason": "invalid file extension"}),
])
def test_response(asset_path, expected_response):
    response = post_asset(asset_path)
    assert response.status_code == 200
    assert response.json() == expected_response


def test_clamd_not_running(monkeypatch):
    def clamd_version():
        return subprocess.CompletedProcess(
            args=['clamdscan', '--version'],
            returncode=0,
            stdout=b'ClamAV 0.102.4\n',
            stderr=b'ERROR: Could not connect to clamd on LocalSocket /var/run/clamav/clamd.ctl: No such file or directory\n',
        )
    monkeypatch.setattr("main.clamd_version", clamd_version)
    assert post_asset("test.gif").json() == {"safe": False, "reason": "clamav not running"}


def test_clamd_out_of_date(monkeypatch):
    def clamd_version():
        return subprocess.CompletedProcess(
            args=['clamdscan', '--version'],
            returncode=0,
            stdout=b'ClamAV 0.102.4/25969/Mon Oct 16 12:22:44 2020\n',
            stderr=b'',
        )
    monkeypatch.setattr("main.clamd_version", clamd_version)
    assert post_asset("test.gif").json() == {"safe": False, "reason": "clamav out of date"}
