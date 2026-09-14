Microservice to check files for expected file type, extension, and antivirus.

[![Tests](https://github.com/harvard-lil/perma-filecheck/actions/workflows/tests.yml/badge.svg)](https://github.com/harvard-lil/perma-filecheck/actions)

## Local install

    docker compose up --build
    docker compose exec web bash

Commands starting with `#` are run inside `docker compose exec web bash`.

## Local development

Compose builds the `dev` target locally and starts Uvicorn with automatic
reload on port 8080. The target extends the same runtime and isolated test-tool
layers used by CI; no registry login is required. Source files are mounted from
the checkout. ClamAV signatures persist in the `clamav_data` volume between
rebuilds; `docker compose down --volumes` removes that cache.

Perma can build this target directly from a pinned Git commit, or set its
`FILECHECK_BUILD_CONTEXT` to a local checkout while working on both services.

Check a file:

    curl -F 'file=@test_assets/test.gif' http://127.0.0.1:8080/scan/
    {"safe":true,"verdict":"clean","reason":"file is safe"}

Add a dependency and update the lock file used by the image:

    uv add <packagename>
    docker compose up -d --build

Run lints and tests:

    docker compose exec web /test/.venv/bin/flake8 main.py test_main.py
    docker compose exec web /test/.venv/bin/python -m pytest

Tests will fail if test coverage goes below 100%.

## Result protocol

`verdict` is the machine-readable decision field for new callers:

| Verdict | Meaning | Perma behavior |
|---|---|---|
| `clean` | ClamAV completed and found no malware | accept |
| `unsafe` | ClamAV found malware | reject |
| `rejected` | File type, extension, or size is invalid | reject |
| `unavailable` | ClamAV could not provide a trustworthy result | log and fail open |

`safe` and `reason` remain compatible with the current Perma client. Scanner
failures use `safe: false` with the exact reason `clamav not running`, while
stale signatures use `safe: false` with `clamav out of date`; Perma recognizes
those two reasons and fails open. Other `safe: false` results are rejected.
New clients should use `verdict` instead of parsing `reason`.

## Deployment

The service has no application authentication. Network access is therefore an
access boundary: each tier uses an internal ALB whose ingress is
limited to that tier's Perma EC2 security group.

The network-facing Uvicorn process runs as the unprivileged `filecheck` user;
the entrypoint starts signature update and `clamd` before dropping privileges.
Python dependencies come from `uv.lock`; the final image excludes test
dependencies, uv, and pip. The test target derives from that runtime image
and adds its tools in a separate virtual environment, so the service under test
still starts with the production Python environment. Deployment workflows pin
all third-party actions by commit. Both tiers' ECS tasks use a read-only root
filesystem with dedicated writable ClamAV and temporary-file volumes and do
not assign the application an AWS task role.

An empty task volume downloads its initial ClamAV database before the service
becomes ready. After that, `freshclam` checks hourly in the background and
notifies `clamd` of successful updates. Concurrent database reload keeps scans
on the previous engine until the updated engine is ready; capture requests do
not run `freshclam`.

Pull requests build and test locally without registry credentials. A push to
`main` builds the runtime and test targets, runs the service checks against the
test image, and publishes that runtime image to the private `perma-filecheck`
ECR repository under the commit SHA. `BUILD_AWS_ROLE_TO_ASSUME` identifies a
main-branch build role limited to that repository; builds cannot deploy.

A staging merge resolves the image published for the merged main commit and
deploys its digest without rebuilding. A production merge reads the
digest-pinned image from staging's running ECS task definition and promotes
that same digest. The tiers add `staging-deployed-<commit>` and
`prod-deployed-<commit>` retention tags and maintain separate
`staging-latest` and `prod-latest` Terraform placeholders. ECS runs the images
by digest, so a moving tag is never used to decide what a deployment ships.
