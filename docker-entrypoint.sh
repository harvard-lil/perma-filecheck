#!/bin/bash
# see https://docs.docker.com/engine/reference/builder/#entrypoint
# and https://success.docker.com/article/use-a-script-to-initialize-stateful-container-data
set -e

if [ "$1" = '/bin/bash' ] || [ "$1" = 'uvicorn' ]; then
    freshclam
    service clamav-daemon start
fi

exec "$@"