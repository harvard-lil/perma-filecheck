#!/bin/bash
set -e

if [ "$1" = "/bin/bash" ] || [ "$1" = "uvicorn" ]; then

    echo "-------------------------------------"
    echo "Updating ClamAV signatures..."
    echo "-------------------------------------"

    freshclam || echo "WARNING: freshclam update failed"

    echo "-------------------------------------"
    echo "Starting ClamAV daemon..."
    echo "-------------------------------------"

    clamd &

    echo "Waiting for clamd socket..."

    for i in {1..30}; do
        if [ -S /var/run/clamav/clamd.ctl ]; then
            echo "ClamAV daemon ready!"
            break
        fi
        sleep 1
    done

    if [ ! -S /var/run/clamav/clamd.ctl ]; then
        echo "ERROR: clamd failed to start"
        exit 1
    fi
fi

exec "$@"
