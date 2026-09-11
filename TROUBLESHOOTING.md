# AegisDNS troubleshooting

## The dashboard asks for a password

The username is `admin`. On Linux, retrieve the generated password with:

```bash
aegis credentials
```

With Docker directly:

```bash
docker exec aegisdns cat /var/lib/aegisdns/admin-password
```

If `AEGIS_ADMIN_PASSWORD` is set in `.env`, use that value instead.

## Port 53 is already in use

Find the owner before stopping anything:

```bash
sudo ss -lntup '( sport = :53 )'
```

On Linux, `systemd-resolved` may own the local stub. The `aegis start` command backs up the current resolver configuration before changing it. On Windows, Internet Connection Sharing can bind port 53; stop the `SharedAccess` service from an elevated PowerShell session if needed.

## Docker cannot download images

Do not point the host at AegisDNS until the image and container are ready. Temporarily restore a working system resolver, build the image, start AegisDNS, verify a query, and then enable it as the host resolver.

```bash
docker compose build
docker compose up -d
dig @127.0.0.1 example.com
```

## Per-device rules show one address

Docker Desktop on Windows and macOS can replace client addresses with a VM or gateway address. Run AegisDNS on Linux with `network_mode: host` when distinct client identity is required. Confirm what the daemon sees in the dashboard's live query view.

## Tailscale peers do not appear

Peer discovery is an explicit opt-in because the LocalAPI socket carries broader Tailscale authority. Start with the override and check that the socket exists:

```bash
docker compose -f docker-compose.yml -f docker-compose.tailscale.yml up -d
sudo tailscale status
ls -l /var/run/tailscale/tailscaled.sock
docker exec aegisdns test -S /var/run/tailscale/tailscaled.sock
```

Peer discovery is optional. Register a device manually if the host does not expose Tailscale LocalAPI.

## A custom action does not connect

Action domains resolve to `AEGIS_HOST_IP` and use port `5381`. Confirm that `.env` contains an address assigned to this host and reachable by the caller. Requests must be POST with JSON and a valid bearer token.

```bash
curl -v -X POST http://action.aegis:5381 \
  -H 'Authorization: Bearer YOUR_ACTION_TOKEN' \
  -H 'Content-Type: application/json' -d '{}'
```

Use Tailscale or a TLS reverse proxy when the caller is not on a trusted local network.

## DNSSEC failures are slow or return SERVFAIL

`SERVFAIL` is expected for a zone with invalid DNSSEC. Check the trust anchor and Unbound logs:

```bash
docker logs aegisdns
docker exec aegisdns test -s /var/lib/aegisdns/root.key
dig @127.0.0.1 cloudflare.com A +dnssec
dig @127.0.0.1 dnssec-failed.org A
```

The valid query should include the `ad` flag; the deliberately broken zone should return `SERVFAIL`.

## A setting in `config.json` has no effect

Check the daemon log first. An unparseable file is reported and the built-in defaults are used:

```bash
docker logs aegisdns 2>&1 | grep -i 'config.json'
```

Confirm the daemon is reading the file you edited. It uses the first of these that exists: `$AEGIS_CONFIG`, then `config.json` in the data directory, then `/app/config.json`. The supplied Compose file sets `AEGIS_CONFIG=/app/config.json` and bind-mounts the repository copy there:

```bash
docker exec aegisdns sh -c 'echo "$AEGIS_CONFIG"; cat "$AEGIS_CONFIG"'
```

Settings are read at startup, so restart after editing:

```bash
aegis restart
```

Every section is optional and unknown keys are ignored, so a typo in a key name silently leaves the default in place. Compare against the table in the README.

Verify that the resolver settings were applied by inspecting the generated Unbound configuration:

```bash
docker exec aegisdns grep -E 'do-ip4|do-ip6|qname-minimisation|module-config' /run/aegisdns/unbound.conf
```

## A client is temporarily rate-limited

The guard activates after 12,000 DNS queries from one client in 60 seconds and releases automatically after 60 seconds. It applies to LAN, Tailscale, and loopback clients. Use the dashboard quarantine view to release it sooner. This mechanism only blocks DNS responses; it does not isolate other traffic.

## Check service health

```bash
aegis status
docker compose ps
docker logs --tail 100 aegisdns
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com A +tcp
```
