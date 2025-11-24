#!/bin/bash
set -e

# Only initialize ClamAV when starting the app or opening a shell
if [ "$1" = "/bin/bash" ] || [ "$1" = "uvicorn" ]; then
    
    echo "Updating ClamAV signatures..."
    freshclam

    echo "Starting clamd in background..."
    clamd &

    # Wait until clamd is fully ready (important!)
    echo "Waiting for clamd socket..."
    until [ -S /var/run/clamav/clamd.ctl ]; do
        sleep 1
    done
    echo "ClamAV daemon ready!"
fi

# Run the main CMD
exec "$@"
