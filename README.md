<p align="center">
  <img src="assets/AegisDNS.png" alt="AegisDNS" width="220">
</p>

<h1 align="center">AegisDNS</h1>

<p align="center">
  Self-hosted DNS filtering, privacy controls, and network visibility.<br>
  Built with Rust and Unbound. Free and open source under the MIT license.
</p>

<p align="center">
  <a href="#quick-start">Get started</a> ·
  <a href="#features">Features</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="TROUBLESHOOTING.md">Troubleshooting</a> ·
  <a href="#contributing">Contribute</a> ·
  <a href="https://github.com/sponsors/Harshil-Anuwadia">Sponsor</a>
</p>

<p align="center">
  <img src="assets/demo.gif" alt="AegisDNS dashboard demo" width="900">
</p>

---

AegisDNS gives you control over the DNS requests made by devices on your network. It combines domain filtering, device-specific rules, heuristic risk checks, and local query analytics with a validating Unbound resolver.

Use the dashboard or CLI to investigate requests, adjust filtering, explore domain relationships, and manage privacy budgets. The complete software is free to download, modify, and self-host, including for commercial use. No subscription or project account is required to run it.

## Features

| Area | Capabilities |
| --- | --- |
| **DNS resolution** | Recursive resolution through Unbound, DNSSEC validation, QNAME minimization, UDP/TCP, and optional DNS-over-TLS forwarding. |
| **Filtering** | Global and per-device allow/deny rules, blocklists, scheduled rules, SafeSearch, and device filtering profiles. |
| **Risk checks** | Domain-entropy scoring, typosquatting checks, IP-rotation tracking, response inspection, and per-client rate containment. |
| **Query visibility** | Live feed using Server-Sent Events, recent request inspection, domain rankings, and CSV/JSON history exports. |
| **Domain relationships** | An interactive graph of observed links between devices, domains, aliases, IP addresses, and related infrastructure. |
| **Privacy budgets** | Per-device DNS exposure estimates with optional daily limits on recognized tracking activity. |
| **Network management** | Optional DHCP, local DNS zones, device registration, and Tailscale peer discovery. |
| **Integrations** | Optional Telegram alerts and authenticated custom endpoints for HTTPS webhooks, approved executables, or HTML responses. |
| **Dashboard** | Responsive React interface, dark and light themes, keyboard command search, and explicit loading, empty, and error states. |

Risk checks are heuristics. They can produce false positives and do not establish that a domain is malicious or safe. DNS filtering applies to requests that reach AegisDNS; it cannot inspect encrypted application content or control devices using a different resolver.

## Quick start

### Requirements

- A Linux host with a stable LAN or Tailscale address.
- Git, curl, Python 3.10 or newer, and a regular user account with sudo access.
- Local, rootful Docker Engine and the Docker Compose plugin. The interactive installer offers to install missing Docker using its official script.
- Port 53 available for DNS over both UDP and TCP.

The supplied Compose configuration uses Linux host networking to preserve client IP addresses. Windows includes an `install.bat` helper, but Docker Desktop networking can obscure client identity. Use native Linux when per-device filtering or DHCP is required.

### Install on Linux

Run these commands in a fresh checkout as your regular user, not as root:

```bash
git clone https://github.com/Harshil-Anuwadia/aegisdns.git
cd aegisdns
./install.sh
```

The installer creates `openroot.json` from its example when missing and preserves an existing local-zone configuration.

The guided terminal installer validates your configuration, builds the images, installs the `aegis` CLI, and starts the service. It backs up host DNS before changing it, then checks protected dashboard access and DNS over UDP and TCP. Tailscale is the default network path; the installer uses its connected IPv4 address and offers the official installer when needed. Use `./install.sh --no-tailscale` for a LAN address or `./install.sh --no-start` to prepare without starting.

Progress follows actual setup stages. Existing configuration is preserved, private logs help diagnose failures, and a failed startup triggers stop-and-restore recovery. See the [installation and removal guide](docs/INSTALLATION.md) for unattended setup, recovery, and platform limits.

After setup, check the service and retrieve your dashboard credentials:

```bash
aegis status
aegis credentials
```

Open **http://localhost:5380** on the DNS host and sign in as **`admin`**. If you supplied `AEGIS_ADMIN_PASSWORD`, use that password instead of the generated credential.

For a remote host, use an SSH tunnel to reach the loopback-only dashboard:

```bash
ssh -L 5380:127.0.0.1:5380 user@dns-host
```

Then open `http://localhost:5380` on your own computer.

### Verify before changing network DNS

Using `dig`, check both transports on the DNS host:

```bash
dig @127.0.0.1 example.com
dig @127.0.0.1 example.com +tcp
```

Once resolution works, configure a test device to use the host's reachable IP address as its DNS server. Confirm that its requests appear in the query log before changing your router's DHCP settings or the rest of your network. Keep the host's existing DNS working during the initial image build.

### Manual Docker deployment

From a fresh checkout, prepare the bind-mounted configuration files:

```bash
cp config.example.json config.json
cp openroot.example.json openroot.json
```

Set `host_ips` in `config.json` for your host. Create a `.env` file with a reachable IPv4 address assigned to that host; replace the example below:

```dotenv
AEGIS_HOST_IP=192.168.1.10
TZ=UTC
```

Then build and start the services:

```bash
docker compose up -d --build
docker compose ps
docker exec aegisdns cat /var/lib/aegisdns/admin-password
```

The Docker build includes the compiled dashboard and Unbound dependencies. Do not overwrite existing configuration files when updating an installation.

## Everyday commands

| Command | Purpose |
| --- | --- |
| `aegis start` / `aegis stop` | Start or stop the service. |
| `aegis restart` | Restart the service. |
| `aegis status` | Inspect service status. |
| `aegis logs -f` | Follow service logs. |
| `aegis dashboard` | Open the dashboard. |
| `aegis credentials` | Retrieve dashboard credentials. |
| `aegis allow example.com` | Add a global allow rule. |
| `aegis deny example.com` | Add a global deny rule. |
| `aegis policy` | Inspect configured domain rules. |
| `aegis devices` | List registered devices. |
| `aegis help` | Show the full command reference. |

The dashboard also provides scoped device rules, schedules, blocklist management, privacy budgets, diagnostics, and settings. Use **Ctrl+K** or **⌘K** to navigate pages or investigate a domain.

## How it works

```text
Devices ── DNS / UDP + TCP :53 ──► AegisDNS
                                  │
                                  ├── Policy and risk checks
                                  ├── Unbound :5353 ──► Authoritative DNS or configured forwarders
                                  ├── Openroot :5354 ──► Local zone records
                                  └── Local analytics and relationship observations
                                               │
                                      Dashboard / API :5380

Authenticated HTTP POST :5381 ──► Custom action endpoint
```

Unbound handles external DNS resolution, validation, and response caching. AegisDNS applies policy before resolution and inspects returned data, including CNAME targets, against the requesting device's rules. Query records and relationship observations are stored locally in SQLite.

Custom actions use a separate authenticated HTTP listener. **A DNS lookup does not execute a webhook or command.**

## Uninstall

```bash
aegis uninstall
# Or, from the checkout:
./uninstall.sh
```

Removal stops this installation, restores its saved host DNS state, and removes its matching CLI link. Stored data is kept by default. To also delete the Compose-managed data volume, run `./uninstall.sh --purge` and confirm `DELETE`. Configuration, local blocklists, source, Docker, and Tailscale remain. Move client devices to another DNS resolver before removal. If restoration fails, the backup and recovery tools are retained.

## Configuration

The default container stores persistent application data under `/var/lib/aegisdns` in the `aegisdns_data` Compose volume. The repository's `config.json`, `openroot.json`, and `blocklists/` directory are bind-mounted separately.

| Setting | Purpose |
| --- | --- |
| `AEGIS_HOST_IP` | Host IPv4 address used for custom-action DNS answers and the default action listener. Set by the installer or in `.env`. |
| `AEGIS_ADMIN_PASSWORD` | Optional admin password override, 16–256 characters. Otherwise, a generated password is persisted in the data directory. |
| `AEGIS_FAVICON_REMOTE_LOOKUP` | Disabled by default. Set to `true` only if you accept that Google’s favicon service receives the domain names displayed in the dashboard. |
| `TZ` | Server timezone for schedules; the supplied Compose default is `UTC`. Daily analytics and privacy budgets use UTC. |
| `AEGIS_ACTION_EXECUTABLES` | Colon-separated absolute executable paths permitted for shell-type actions. Empty by default. |
| `AEGIS_IP_METADATA` | Optional path to a local CIDR/ASN/country metadata file. Defaults to `ip-metadata.csv` in the data directory. |

The supplied Compose file forwards `AEGIS_HOST_IP`, `AEGIS_ADMIN_PASSWORD`, and `TZ`. To use another daemon environment setting, explicitly add it to the service's `environment` mapping in a Compose override and mount any required files. Adding a variable to `.env` alone does not pass it into the container.

### Upstream resolution

By default, Unbound performs recursive resolution. In **Upstream DNS**, you can configure forwarding with either forward-first or forward-only behavior.

Examples of supported endpoint formats:

```text
9.9.9.9:53
tls://9.9.9.9:853#dns.quad9.net
```

Use one endpoint per line. Do not mix plaintext and TLS endpoints in the same configuration. DNS-over-TLS requires an IP address and certificate hostname; this forwarding configuration does not accept DoH URLs.

### Tailscale and DHCP

Clients can reach AegisDNS through a configured Tailscale connection without enabling automatic peer discovery. To enable discovery through the host's Tailscale LocalAPI socket, use the supplied opt-in override:

```bash
docker compose -f docker-compose.yml -f docker-compose.tailscale.yml up -d
```

The override grants the container access to the host Tailscale socket. See [troubleshooting](TROUBLESHOOTING.md#tailscale-peers-do-not-appear) for requirements.

DHCP is disabled by default. Configure it in **Settings** only when AegisDNS is intended to provide address assignment on that network. Saving DHCP settings does not restart DNS automatically; restart the service when ready to apply them.

### Relationship graph and privacy budgets

The graph displays recorded DNS relationships and observation counts over a selected history window. ASN and country enrichment requires a local metadata file; no external enrichment service is needed. Its format is:

```text
# CIDR,ASN,country,organization
203.0.113.0/24,AS64500,US,Example Network
2001:db8::/32,AS64501,DE,Example IPv6 Network
```

These are documentation-only example ranges. Supply actual metadata for your deployment. The daemon reads the file at startup. Certificate-related observations come from TLSA records, not active HTTPS certificate scanning.

Privacy budget enforcement is off by default. When enabled, it limits recognized tracking activity after a device reaches its configured daily score. Scores reset at 00:00 UTC; explicit allow rules and bypass profiles take precedence over this content filtering.

The score is a **DNS exposure estimate**, not a privacy guarantee. Company and application associations are inferred from domain patterns. Identifier-like hostnames are not confirmed advertising IDs, and activity between 00:00 and 06:00 UTC is not proof that a device was idle.

## Data and security

- **Local analysis:** policy evaluation, risk calculations, and query storage run on your host. DNS resolution still contacts authoritative servers or configured forwarders. Blocklist updates and enabled integrations, including Telegram and webhooks, make their own outbound requests.
- **Protected administration:** the dashboard and management API require HTTP Basic authentication. The admin listener binds to loopback by default. Use an SSH tunnel or a TLS reverse proxy for remote administration.
- **Request protection:** state-changing API requests require `X-Aegis-Request: 1`; cross-site administration is rejected.
- **Separate action authentication:** custom endpoints require an authenticated POST. Bearer tokens are stored as hashes. Shell-type actions require an approved executable and a JSON argument array; they do not run arbitrary shell strings. Use TLS when carrying credentials across an untrusted network.
- **Container boundaries:** the supplied deployment uses read-only root filesystems, writable data volumes, and restricted capabilities. The entrypoint performs ownership setup before dropping privileges for the daemon.
- **Bounded retention:** query and relationship records are pruned after 30 days and also subject to row caps. Retained history can therefore be shorter on busy installations. The dashboard supports explicit history deletion and export.

Only expose DNS to networks you intend to serve. Per-device policy depends on the source IP address visible to AegisDNS; NAT or a router acting as a DNS proxy may merge multiple clients under one address.

### API example

Use `curl --user admin` to enter the password interactively:

```bash
# Read network statistics.
curl --user admin http://localhost:5380/api/stats

# Add a global block rule.
curl --user admin \
  -H 'X-Aegis-Request: 1' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}' \
  http://localhost:5380/api/deny
```

The current route definitions live in [the web server](crates/daemon/src/web.rs); the dashboard's request client is in [ui/src/api.ts](ui/src/api.ts).

## Development

The backend is a Rust workspace. A source build requires a Rust toolchain and the native build dependencies used in the [Dockerfile](Dockerfile), including Clang, pkg-config, and OpenSSL development headers. Running the complete service also requires Unbound, its trust-anchor tooling, local configuration, and the dashboard assets.

```bash
cargo build --release --locked
cargo test --workspace --locked
```

The daemon binary is produced at `target/release/aegisdnsd`. For an integrated deployment, use Docker Compose rather than treating the binary alone as a complete installation.

For the dashboard, use Node.js 22 or later:

```bash
cd ui
npm ci
npm run dev
```

The development server runs at `http://127.0.0.1:5173` and proxies API requests to the daemon at `127.0.0.1:5380`. See [dashboard development](ui/README.md) for production builds and browser testing.

| Path | Responsibility |
| --- | --- |
| `crates/daemon` | DNS proxy, administration API, integrations, privacy controls, and relationship recording. |
| `crates/resolver` | Unbound lifecycle and resolver configuration. |
| `crates/policy`, `crates/risk` | Rule evaluation and heuristic domain checks. |
| `crates/blocklist` | Source fetching, parsing, compilation, and snapshots. |
| `crates/analytics` | SQLite persistence, telemetry, and historical queries. |
| `crates/config`, `crates/diagnostics` | Configuration, validation, and policy diagnostics. |
| `crates/openroot` | Local-zone DNS service. |
| `ui` | React/TypeScript dashboard and browser tests. |
| `aegis` | Linux management CLI. |

## Updates and backups

Before updating, back up the application data volume and your repository-side configuration: `.env`, `config.json`, `openroot.json`, and any custom blocklists. Stop the service for a consistent filesystem-level backup of SQLite, or use a SQLite-aware backup process.

For an installer-managed checkout, `aegis update` pulls source changes, rebuilds the images, and restarts the service. Review local modifications before updating. A service restart briefly interrupts DNS resolution. Do not use `docker compose down -v` when you intend to preserve application data.

## Contributing

Bug reports, tests, documentation, and code contributions are welcome.

1. Check [existing issues](https://github.com/Harshil-Anuwadia/aegisdns/issues) before opening a report.
2. For bugs, include the revision, host environment, deployment method, reproduction steps, and expected versus actual behavior. Remove credentials and private DNS data from logs.
3. Discuss substantial behavior changes before starting a large pull request.
4. Keep changes focused, run the relevant backend or frontend checks, and document any changed configuration or behavior.

AI-assisted contributions are welcome under the same review standard: understand the change, verify its behavior, and explain its limitations.

For security vulnerabilities, use the repository's **Security** tab to check available private reporting options. Avoid disclosing exploit details or sensitive information in a public issue.

## Support and funding

Start with [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for setup and operational issues. Community support is provided through [GitHub issues](https://github.com/Harshil-Anuwadia/aegisdns/issues).

AegisDNS is maintained by Harshil Anuwadia. [GitHub sponsorship](https://github.com/sponsors/Harshil-Anuwadia) is optional and supports development and maintenance. Organizations can also [fund public improvements or discuss deployment assistance](SPONSORSHIP.md).

Everyone receives the same software. Sponsorship does not unlock features, provide access to users' DNS history, or influence filtering decisions. See the [sponsor directory](SPONSORS.md) for public acknowledgments.

## License

AegisDNS is distributed under the [MIT license](LICENSE).
