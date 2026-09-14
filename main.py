import logging
import os
import subprocess
from datetime import datetime, timezone
from enum import Enum
from tempfile import NamedTemporaryFile

import filetype
from dateutil.parser import ParserError, parse
from fastapi import FastAPI, File, Response, UploadFile, status
from pydantic import BaseModel

app = FastAPI()

# Configure logging to stdout so logs are picked up by the container runtime
# (e.g. CloudWatch Logs via ECS awslogs driver)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("filecheck")

# Allowed MIME types and their valid file extensions
allowed_types = {
    "image/jpeg": {"jpeg", "jpg"},
    "image/gif": {"gif"},
    "image/png": {"png"},
    "application/pdf": {"pdf"}
}

MAX_FILE_SIZE = 1024 * 1024 * 200  # 200 MB
MAX_SIGNATURE_AGE = 60 * 60 * 24 * 2  # 2 days


class ScanVerdict(str, Enum):
    CLEAN = "clean"
    UNSAFE = "unsafe"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class ScanResult(BaseModel):
    safe: bool
    verdict: ScanVerdict
    reason: str


def scan_result(verdict: ScanVerdict, reason: str) -> ScanResult:
    return ScanResult(
        safe=verdict is ScanVerdict.CLEAN,
        verdict=verdict,
        reason=reason,
    )


def clamav_signature_age():
    """
    Returns the age of ClamAV's virus signatures in seconds.

    Do not cache the numeric age: a cached value never increases and can leave
    an old signature database reporting as healthy for the life of the task.
    """
    result = subprocess.run(
        ["clamdscan", "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )

    # Version string format: "ClamAV x.x.x/28033/Mon Jun 16 ..."
    timestamp = result.stdout.strip().rsplit("/", 1)[-1]
    sig_time = parse(timestamp)

    if sig_time.tzinfo is None:
        sig_time = sig_time.replace(tzinfo=timezone.utc)

    age = (datetime.now(timezone.utc) - sig_time).total_seconds()
    logger.info("ClamAV signature age check: %.0f seconds", age)
    return age


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
        logger.error("clamdscan timed out scanning %s", path)
        return False, "clamav not running"
    except OSError as error:
        # Expected process-start failures include a missing binary and denied
        # execution. Keep environment details in logs, not the API response.
        logger.error("could not start clamdscan for %s: %s", path, error)
        return False, "clamav not running"

    if result.returncode == 0:
        return True, None
    if result.returncode == 1:
        # returncode 1 means a virus was detected
        logger.warning("Virus detected in %s: %s", path, result.stdout.strip())
        return False, "virus detected"
    # returncode 2 means a clamd error, including an unavailable daemon or a
    # permission problem.
    logger.error(
        "clamdscan returned code %s for %s: %s",
        result.returncode,
        path,
        result.stdout.strip() or result.stderr.strip(),
    )
    return False, "clamav not running"


def clamav_ping():
    """
    Checks if the clamd daemon is reachable by scanning an empty temp file.
    Returns True if clamd responds (clean or infected), False if unreachable.
    """
    with NamedTemporaryFile() as tmp:
        try:
            result = subprocess.run(
                ["clamdscan", "--no-summary", tmp.name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode in (0, 1)  # 0 = clean, 1 = infected
        except (OSError, subprocess.SubprocessError) as error:
            logger.error("clamav_ping failed: %s", error)
            return False


@app.get("/health")
async def health(response: Response):
    """
    Health check endpoint. Returns HTTP 503 with reason if:
    - clamd is not running or version check fails
    - clamd daemon is not responding to scan requests
    - virus signatures are older than MAX_SIGNATURE_AGE

    Returns HTTP 200 if all checks pass.
    """
    try:
        age = clamav_signature_age()
    except (
        OSError,
        subprocess.SubprocessError,
        ParserError,
        OverflowError,
    ) as error:
        logger.error(
            "Health check failed: clamav version check failed: %s",
            error,
        )
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "reason": "clamav version check failed",
        }

    if not clamav_ping():
        logger.error("Health check failed: clamav daemon not responding")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "reason": "clamav daemon not responding",
        }

    if age > MAX_SIGNATURE_AGE:
        logger.warning(
            "Health check failed: signatures outdated (age=%.0fs, max=%ds)",
            age, MAX_SIGNATURE_AGE,
        )
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "reason": "clamav signatures outdated",
        }

    return {
        "status": "healthy"
    }


@app.post("/scan/", response_model=ScanResult)
async def scan(file: UploadFile = File(...)):
    """
    Accepts a file upload and scans it with ClamAV.
    The verdict is machine-readable so callers can distinguish an unsafe or
    invalid file from an unavailable scanner without parsing reason strings.
    """
    filename = file.filename or ""
    logger.info("Scan requested for file: %r", filename)

    # Check signature age before accepting the file for scanning.
    try:
        if clamav_signature_age() > MAX_SIGNATURE_AGE:
            logger.warning(
                "Rejecting scan for %r: signatures outdated",
                filename,
            )
            return scan_result(
                ScanVerdict.UNAVAILABLE,
                "clamav out of date",
            )
    except (
        OSError,
        subprocess.SubprocessError,
        ParserError,
        OverflowError,
    ) as error:
        logger.error(
            "clamav not available while scanning %r: %s",
            filename,
            error,
        )
        return scan_result(ScanVerdict.UNAVAILABLE, "clamav not running")

    _, ext = os.path.splitext(filename)
    extension = ext.lower().lstrip(".")

    # Read just enough bytes for filetype magic number detection
    header = await file.read(261)
    await file.seek(0)

    guess = filetype.guess(header)

    if not guess:
        logger.warning("Rejecting %r: unrecognized file type", filename)
        return scan_result(ScanVerdict.REJECTED, "unrecognized file type")

    if guess.mime not in allowed_types:
        logger.warning(
            "Rejecting %r: invalid file type (%s)", filename, guess.mime
        )
        return scan_result(ScanVerdict.REJECTED, "invalid file type")

    # Ensure the file extension matches the detected MIME type
    if extension not in allowed_types[guess.mime]:
        logger.warning(
            "Rejecting %r: extension does not match detected type (%s)",
            filename, guess.mime,
        )
        return scan_result(ScanVerdict.REJECTED, "invalid file extension")

    size = 0

    # Stream file into a temp file for clamd scanning, enforcing size limit
    with NamedTemporaryFile(delete=True) as tmp:
        while True:
            chunk = await file.read(8192)
            if not chunk:
                break

            size += len(chunk)

            if size > MAX_FILE_SIZE:
                logger.warning("Rejecting %r: exceeds max file size", filename)
                return scan_result(ScanVerdict.REJECTED, "file too large")

            tmp.write(chunk)

        # Ensure all bytes are flushed to disk before passing path to clamd
        tmp.flush()
        os.fsync(tmp.fileno())

        safe, reason = scan_file(tmp.name)

        if not safe:
            verdict = (
                ScanVerdict.UNSAFE
                if reason == "virus detected"
                else ScanVerdict.UNAVAILABLE
            )
            logger.warning(
                "Scan result for %r: %s (%s)",
                filename,
                verdict.value,
                reason,
            )
            return scan_result(verdict, reason)

    logger.info("Scan result for %r: safe", filename)
    return scan_result(ScanVerdict.CLEAN, "file is safe")
