#!/bin/bash
set -eu

if [ "${1:-}" = "/bin/bash" ] || [ "${1:-}" = "uvicorn" ]; then

    # ECS mounts empty writable volumes over these paths when the container's
    # root filesystem is read-only. Restore the ownership/mode those mounts
    # need before starting either daemon.
    chown -R clamav:clamav \
        /run/clamav /var/run/clamav /var/log/clamav /var/lib/clamav
    chmod 1777 /tmp

    # clamd cannot start without a database. An empty ECS scratch volume needs
    # one initial synchronous download; existing databases refresh in the
    # background and do not delay application startup.
    if ! compgen -G '/var/lib/clamav/*.c[lv]d' >/dev/null; then
        echo "-------------------------------------"
        echo "Downloading initial ClamAV signatures..."
        echo "-------------------------------------"
        freshclam
    fi

    echo "-------------------------------------"
    echo "Starting ClamAV daemon..."
    echo "-------------------------------------"

    # clamd daemonizes itself. Starting it without shell backgrounding lets an
    # immediate configuration or database error fail the container startup.
    clamd

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

    echo "Starting hourly ClamAV signature checks in the background..."
    freshclam --daemon --foreground --stdout &
fi

exec su-exec filecheck "$@"
