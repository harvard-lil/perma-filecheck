FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

FROM python:3.13-alpine@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a AS python-dependencies

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_LINK_MODE=copy

WORKDIR /app

COPY --from=uv /uv /bin/uv
COPY pyproject.toml uv.lock ./

RUN uv sync --locked --no-dev --no-install-project --no-cache

FROM python-dependencies AS python-test-dependencies

WORKDIR /test
ENV UV_PROJECT_ENVIRONMENT=/test/.venv
COPY pyproject.toml uv.lock ./

RUN uv sync --locked --no-install-project --no-cache


FROM python:3.13-alpine@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a AS runtime-base

# Keep Python output unbuffered and disable bytecode/pip noise
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/app/.venv/bin:$PATH"

# Install ClamAV and configure it
RUN apk add --no-cache \
        bash \
        clamav \
        clamav-daemon \
        freshclam \
        ca-certificates \
        'libuuid>=2.42.3-r1' \
        su-exec \
    # Run the network-facing application separately from the ClamAV daemon.
    && adduser -S -D -H -G clamav filecheck \
    # Create required runtime directories and set permissions for clamav user
    && mkdir -p /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chown -R clamav:clamav /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chmod -R 775 /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav \
    # Configure clamd daemon: use local socket + TCP, run as clamav user
    && printf '%s\n' \
        'LogTime yes' \
        'PidFile /var/run/clamav/clamd.pid' \
        'LocalSocket /var/run/clamav/clamd.ctl' \
        'LocalSocketGroup clamav' \
        'LocalSocketMode 660' \
        'FixStaleSocket yes' \
        'DatabaseDirectory /var/lib/clamav' \
        'User clamav' \
        'Foreground false' \
        'SelfCheck 600' \
        'ConcurrentDatabaseReload yes' \
        'TCPSocket 3310' \
        'TCPAddr 127.0.0.1' \
        > /etc/clamav/clamd.conf \
    # Check hourly in the background and ask clamd to adopt successful updates.
    # ConcurrentDatabaseReload keeps the old engine serving scans until the new
    # database has loaded.
    && printf '%s\n' \
        'DatabaseDirectory /var/lib/clamav' \
        'DatabaseOwner clamav' \
        'LogTime yes' \
        'DatabaseMirror database.clamav.net' \
        'Checks 24' \
        'NotifyClamd /etc/clamav/clamd.conf' \
        'PidFile /var/run/clamav/freshclam.pid' \
        > /etc/clamav/freshclam.conf

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
# Single worker: clamd is a shared resource, multiple workers offer no benefit
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--log-level", "info"]


FROM runtime-base AS runtime-image

COPY --from=python-dependencies /app/.venv /app/.venv
COPY --chown=filecheck:clamav main.py ./

# The production process never installs packages. Remove pip and its vendored
# build-time libraries from the runtime environment and system Python.
RUN rm -rf \
        /app/.venv/bin/pip* \
        /app/.venv/lib/python*/site-packages/pip \
        /app/.venv/lib/python*/site-packages/pip-*.dist-info \
        /usr/local/bin/pip* \
        /usr/local/lib/python*/site-packages/pip \
        /usr/local/lib/python*/site-packages/pip-*.dist-info


# The service in this stage runs the production image above. Test tools live in
# their own virtual environment and are invoked explicitly, so they do not
# replace or extend the Python environment the deployed Uvicorn process uses.
FROM runtime-image AS test

COPY --from=python-test-dependencies /test/.venv /test/.venv
COPY --chown=filecheck:clamav test_main.py pyproject.toml ./
COPY --chown=filecheck:clamav test_assets ./test_assets


# Local development shares the production runtime and the isolated test tools.
FROM test AS dev

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]


# Keep the deployable target last for callers that do not pass --target.
FROM runtime-image AS runtime
