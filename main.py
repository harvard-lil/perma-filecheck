import os
import subprocess
from tempfile import NamedTemporaryFile
from datetime import datetime, timezone
from functools import lru_cache
import filetype
from fastapi import FastAPI, File, UploadFile
from dateutil.parser import parse
import tempfile

app = FastAPI()

# Allowed MIME types and their valid file extensions
allowed_types = {
    "image/jpeg": {"jpeg", "jpg"},
    "image/gif": {"gif"},
    "image/png": {"png"},
    "application/pdf": {"pdf"}
}

MAX_FILE_SIZE = 1024 * 1024 * 200  # 200 MB
MAX_SIGNATURE_AGE = 60 * 60 * 24 * 7  # 7 days


@lru_cache(maxsize=1)
def clamav_signature_age():
    """
    Returns the age of ClamAV's virus signatures in seconds.
    Result is cached to avoid repeated subprocess calls on every request.
    Cache should be cleared if clamd becomes unavailable, so it re-checks
    after recovery rather than serving a stale result.
    """
    result = subprocess.run(
        ["clamdscan", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )

    # Version string format: "ClamAV x.x.x/28033/Mon Jun 16 ..."
    timestamp = result.stdout.strip().rsplit("/", 1)[-1]
    sig_time = parse(timestamp)

    if sig_time.tzinfo is None:
        sig_time = sig_time.replace(tzinfo=timezone.utc)

    return (datetime.now(timezone.utc) - sig_time).total_seconds()


def scan_file(path: str):
    """
    Scans a file at the given path using clamd.
    Returns (safe: bool, reason: str | None).
    Exceptions are caught to prevent unhandled 500s if clamd is unavailable.
    """
    try:
        result = subprocess.run(
            ["clamdscan", "--fdpass", "--no-summary", path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        # clamd took too long — likely mid-reload or overloaded
        return False, "clamav scan timed out"
    except Exception as e:
        # clamdscan binary missing or other unexpected error
        return False, f"clamav scan failed: {e}"

    if result.returncode == 0:
        return True, None
    if result.returncode == 1:
        # returncode 1 means a virus was detected
        return False, "virus detected"
    # returncode 2 means clamd error (daemon unavailable, permission issue, etc.)
    return False, "clamav scan failed"


def clamav_ping():
    """
    Checks if the clamd daemon is reachable by scanning an empty temp file.
    Returns True if clamd responds (clean or infected), False if unreachable.
    """
    with tempfile.NamedTemporaryFile() as tmp:
        try:
            result = subprocess.run(
                ["clamdscan", "--no-summary", tmp.name],
                capture_output=True,
                text=True,
            )
            return result.returncode in (0, 1)  # 0 = clean, 1 = infected
        except Exception:
            return False


@app.get("/health")
async def health():
    """
    Health check endpoint. Returns unhealthy if:
    - clamd is not running or version check fails
    - clamd daemon is not responding to scan requests
    - virus signatures are older than MAX_SIGNATURE_AGE (7 days)
    """
    try:
        age = clamav_signature_age()
    except Exception:
        return {
            "status": "unhealthy",
            "reason": "clamav version check failed",
        }

    if not clamav_ping():
        return {
            "status": "unhealthy",
            "reason": "clamav daemon not responding",
        }

    if age > MAX_SIGNATURE_AGE:
        return {
            "status": "unhealthy",
            "reason": "clamav signatures outdated",
        }

    return {
        "status": "healthy"
    }


@app.post("/scan/")
async def scan(file: UploadFile = File(...)):
    """
    Accepts a file upload and scans it with ClamAV.
    Returns {"safe": bool, "reason": str}.
    Files are passed through (safe=False) rather than raising 500s
    if clamd is temporarily unavailable.
    """
    # Check signature age before scanning; clear cache if clamd is unreachable
    # so it re-checks after recovery rather than serving a stale cached result
    try:
        if clamav_signature_age() > MAX_SIGNATURE_AGE:
            return {
                "safe": False,
                "reason": "clamav signatures outdated"
            }
    except Exception:
        if hasattr(clamav_signature_age, 'cache_clear'):
            clamav_signature_age.cache_clear()
        return {
            "safe": False,
            "reason": "clamav not available"
        }

    _, ext = os.path.splitext(file.filename)
    extension = ext.lower().lstrip(".")

    # Read just enough bytes for filetype magic number detection
    header = await file.read(261)
    await file.seek(0)

    guess = filetype.guess(header)

    if not guess:
        return {"safe": False, "reason": "unrecognized file type"}

    if guess.mime not in allowed_types:
        return {"safe": False, "reason": "invalid file type"}

    # Ensure the file extension matches the detected MIME type
    if extension not in allowed_types[guess.mime]:
        return {"safe": False, "reason": "invalid file extension"}

    size = 0

    # Stream file into a temp file for clamd scanning, enforcing size limit
    with NamedTemporaryFile(delete=True) as tmp:
        while True:
            chunk = await file.read(8192)
            if not chunk:
                break

            size += len(chunk)

            if size > MAX_FILE_SIZE:
                return {"safe": False, "reason": "file too large"}

            tmp.write(chunk)

        # Ensure all bytes are flushed to disk before passing path to clamd
        tmp.flush()
        os.fsync(tmp.fileno())

        safe, reason = scan_file(tmp.name)

        if not safe:
            return {"safe": False, "reason": reason}

    return {"safe": True, "reason": "file is safe"}