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

allowed_types = {
    "image/jpeg": {"jpeg", "jpg"},
    "image/gif": {"gif"},
    "image/png": {"png"},
    "application/pdf": {"pdf"},
}

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
MAX_SIGNATURE_AGE = 60 * 60 * 24 * 7  # 7 days


@lru_cache(maxsize=1)
def clamav_signature_age():
    result = subprocess.run(
        ["clamdscan", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )

    timestamp = result.stdout.strip().rsplit("/", 1)[-1]
    sig_time = parse(timestamp)

    if sig_time.tzinfo is None:
        sig_time = sig_time.replace(tzinfo=timezone.utc)

    return (datetime.now(timezone.utc) - sig_time).total_seconds()


def scan_file(path: str):
    result = subprocess.run(
        ["clamdscan", "--fdpass", "--no-summary", path],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode == 0:
        return True, None
    elif result.returncode == 1:
        return False, "virus detected"
    else:
        return False, "scan error"


def clamav_ping():
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
    try:
        if clamav_signature_age() > MAX_SIGNATURE_AGE:
            return {
                "safe": False,
                "reason": "clamav signatures outdated"
            }
    except Exception:
        return {
            "safe": False,
            "reason": "clamav not available"
        }

    if not file.filename:
        return {"safe": False, "reason": "missing filename"}

    _, ext = os.path.splitext(file.filename)
    extension = ext.lower().lstrip(".")

    header = await file.read(261)
    await file.seek(0)

    guess = filetype.guess(header)

    if not guess:
        return {"safe": False, "reason": "unrecognized file type"}

    if guess.mime not in allowed_types:
        return {"safe": False, "reason": "invalid file type"}

    if extension not in allowed_types[guess.mime]:
        return {"safe": False, "reason": "invalid file extension"}

    size = 0

    with NamedTemporaryFile(delete=True) as tmp:

        while True:
            chunk = await file.read(8192)
            if not chunk:
                break

            size += len(chunk)

            if size > MAX_FILE_SIZE:
                return {"safe": False, "reason": "file too large"}

            tmp.write(chunk)

        tmp.flush()
        os.fsync(tmp.fileno())

        safe, reason = scan_file(tmp.name)

        if not safe:
            return {"safe": False, "reason": reason}

    return {"safe": True, "reason": "file is safe"}
