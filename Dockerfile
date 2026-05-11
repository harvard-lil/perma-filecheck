FROM python:3.13-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache \
        bash \
        clamav \
        clamav-daemon \
        freshclam \
        ca-certificates \
    && mkdir -p /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chown -R clamav:clamav /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chmod -R 775 /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    && printf '%s\n' \
        'LogTime yes' \
        'PidFile /var/run/clamav/clamd.pid' \
        'LocalSocket /var/run/clamav/clamd.ctl' \
        'LocalSocketMode 666' \
        'FixStaleSocket yes' \
        'DatabaseDirectory /var/lib/clamav' \
        'User clamav' \
        'Foreground false' \
        'TCPSocket 3310' \
        'TCPAddr 127.0.0.1' \
        > /etc/clamav/clamd.conf \
    && printf '%s\n' \
        'DatabaseDirectory /var/lib/clamav' \
        'LogTime yes' \
        'DatabaseMirror database.clamav.net' \
        > /etc/clamav/freshclam.conf

WORKDIR /app

RUN python -m pip install --upgrade "pip>=26.1" \
    && pip install --upgrade \
        "anyio>=4.13.0" \
        "certifi>=2026.4.22" \
        "charset-normalizer>=3.4.7" \
        "fastapi>=0.136.1" \
        "filetype>=1.2.0" \
        "h11>=0.16.0" \
        "httpcore>=1.0.9" \
        "httpx>=0.28.1" \
        "idna>=3.14" \
        "pydantic>=2.13.4" \
        "python-dateutil>=2.9.0.post0" \
        "python-multipart>=0.0.20" \
        "requests>=2.33.1" \
        "six>=1.17.0" \
        "sniffio>=1.3.1" \
        "starlette>=1.0.0" \
        "typing-extensions>=4.15.0" \
        "urllib3>=2.7.0" \
        "uvicorn>=0.46.0"

COPY entrypoint.sh /entrypoint.sh
COPY main.py .

RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]
