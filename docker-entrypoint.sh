#!/bin/sh
set -eu
# One-time ownership migration of daemon-owned files in the named data volume.
# Do not traverse mounted blocklist folders or change the host's zone/config files.
mkdir -p /var/lib/aegisdns /run/aegisdns
chown aegis:aegis /var/lib/aegisdns /run/aegisdns
for name in analytics.db analytics.db-wal analytics.db-shm admin-password policy.json devices.json telegram.json dhcp.json dhcp-leases.json upstream.json blocklist-snapshot.json root.key; do
    if [ -f "/var/lib/aegisdns/$name" ] && [ ! -L "/var/lib/aegisdns/$name" ]; then
        chown aegis:aegis "/var/lib/aegisdns/$name"
        chmod 600 "/var/lib/aegisdns/$name"
    fi
done
# Only low-port binding survives privilege drop. No shell actions are enabled by default.
exec setpriv --reuid=aegis --regid=aegis --clear-groups \
    --inh-caps=+net_bind_service --ambient-caps=+net_bind_service --no-new-privs \
    /usr/local/bin/aegisdnsd
