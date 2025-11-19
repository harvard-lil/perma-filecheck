#!/bin/bash
set -e

if [ "$1" = '/bin/bash' ] || [ "$1" = 'uvicorn' ]; then
    # Update virus definitions and start ClamAV daemon in background
    freshclam && clamd &
fi

exec "$@"