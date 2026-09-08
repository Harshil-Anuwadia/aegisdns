<p align="center">
  <img src="assets/logo.png" alt="AegisDNS" width="280">
</p>

<h1 align="center">AegisDNS</h1>

<p align="center"><strong>v1.0 "Keystone"</strong></p>

<p align="center">
  A self-hosted DNS firewall that actually catches zero-day threats.<br>
  No cloud. No subscription. No selling your query history.<br>
  Just you, your hardware, and math.
</p>

<p align="center">
  <a href="#install-it">Install</a> •
  <a href="#what-makes-aegisdns-different">Why AegisDNS</a> •
  <a href="#features">Features</a> •
  <a href="#the-honest-comparison">Comparison</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#troubleshooting">Help</a>
</p>

---

## Why I built this

I got tired of the tradeoff.

Every DNS service that actually protects you (the ones that catch phishing, block malware callbacks, and detect botnets) wants your data. Your entire browsing history flows through their servers, gets logged, gets "anonymized" (sure), and you pay a monthly fee for the privilege of handing it over.

Pi-hole is self-hosted, which is great for privacy. But it only checks domains against a static text file. If a piece of malware generates a random domain name five minutes from now, Pi-hole will let it through because no human has added it to a list yet.

So I built AegisDNS. It runs on your own machine. Your DNS queries never leave your network. And instead of relying only on lists, it does real math on every query: Shannon entropy to catch algorithmically generated malware domains, Levenshtein distance to catch phishing lookalikes, and IP rotation tracking to catch botnets. The same techniques that commercial DNS firewalls charge enterprise customers for. Except this is free, it's open source, and your data stays yours.

Privacy is a right. Not a subscription.

---

## A note about AI

I used AI tools to help write parts of this codebase. I'm not going to hide that or pretend otherwise.

AI helped me move faster, catch edge cases, and write better Rust. But every architectural decision, from the entropy thresholds to the SSRF protections and the policy evaluation order, is intentional design work. I reviewed, tested, and understood every line that went into this project.

I think the "did you use AI" debate misses the point. The point is: does the code work? Is it secure? Does it solve a real problem? I'll let the source code answer that.

---

## Install it

You need a Linux machine with Docker. A Raspberry Pi 4, an old laptop, a VPS; anything works.

```bash
git clone https://github.com/Harshil-Anuwadia/aegisdns.git
cd aegisdns
./install.sh
```

That's it. The installer handles Docker, Tailscale (optional), and configuration. When it's done:

```bash
aegis start          # Start AegisDNS
aegis credentials    # Get your admin password
aegis dashboard      # Open the web UI
```

The dashboard runs on `http://localhost:5380`. Point your router's DNS to your AegisDNS machine's IP, and every device on your network is protected.

**Without Tailscale:**
```bash
./install.sh --no-tailscale
```

**Manual Docker deployment:**
```bash
docker compose build
docker compose up -d
docker exec aegisdns cat /var/lib/aegisdns/admin-password
```

**Windows / macOS:** `install.bat` runs the Linux image through Docker Desktop. Global policy works; per-device rules may not distinguish clients behind Docker's NAT layer. For full per-device support, use Linux with host networking.

---

## What makes AegisDNS different

Most DNS blockers are glorified `grep` commands. They download a list of known bad domains, and if a query matches, they block it. That worked in 2015. It doesn't work now.

Modern malware doesn't use `evil-malware.com`. It generates random domain names on the fly (`xk7m2qzp9a.xyz`) and rotates through thousands of them. By the time a human researcher finds one and adds it to a blocklist, the malware has already moved on to the next hundred.

AegisDNS doesn't just check lists. It thinks.

### Malware detection (DGA)
Every DNS query gets scored using **Shannon entropy**, a mathematical measure of randomness. Normal domains like `google.com` have low entropy. Machine-generated domains like `xk7m2qzp9a.xyz` have high entropy. AegisDNS catches them in real time, before any blocklist knows they exist.

### Phishing detection (Typosquatting)
AegisDNS calculates the **Levenshtein distance** against 50+ high-value brands (banks, payment processors, crypto exchanges). If someone tries to visit `paypa1-secure-login.com`, AegisDNS strips common phishing suffixes (`-secure`, `-login`, `-verify`), measures the edit distance to `paypal`, and blocks it instantly.

### Botnet detection (Fast-Flux)
Botnets hide their command servers behind rapidly rotating IP addresses using a technique called Fast-Flux. AegisDNS tracks IP history for every domain in a sliding 10-minute window with LRU eviction. If a single domain resolves to 5+ unique IPs in that window, it gets flagged. Major CDNs (Google, Cloudflare, Akamai) are whitelisted to prevent false positives.

### Everything stays local
Your DNS queries never touch a third-party server for analysis. The entropy math, the string distance, the IP tracking; it all runs locally on your hardware. The only outbound connections AegisDNS makes are recursive DNS resolution (to the actual DNS root servers or your configured forwarder) and blocklist downloads (HTTPS only).

---

## Features

### DNS & Resolution
- Full **recursive DNS resolution** through a supervised Unbound instance
- **DNSSEC** validation with automatic root trust anchor management
- **QNAME minimisation**: upstream servers only see the minimum they need
- **UDP and TCP** with automatic TCP fallback for truncated responses
- Configurable **DNS-over-TLS** forwarding (e.g., `tls://9.9.9.9:853#dns.quad9.net`)
- Per-client **rate limiting** (12,000 queries/60s) to contain DNS abuse
- Response validation: IDs, question matching, private-address rejection

### Security Engine
- **Shannon entropy scoring** for DGA/malware domain detection
- **Levenshtein distance** for typosquatting/phishing protection
- **Fast-Flux IP tracking** with LRU eviction and CDN whitelisting
- **SSRF protection** on webhooks and blocklist fetches (no private IP resolution, no redirects)
- **Shell injection prevention**: commands are JSON argument arrays, never shell strings
- **Token hashing**: action tokens stored as SHA-256, verified with constant-time comparison

### Policy & Filtering
- Global and **per-device** allow/deny rules
- **Time-based schedules** with overnight wrap-around support
- **SafeSearch** enforcement
- Blocklists: hosts files, AdBlock syntax, exception rules (`@@||allowed.example^`)
- **Last-known-good snapshots**: a failed blocklist download never wipes your active rules
- Local zone forwarding (`.lan`, `.aegis`, `.home.arpa`)

### Analytics & Dashboard
- **Real-time query log** with WebSocket live feed
- Per-second telemetry: queries, blocks, cache hits, latency
- **Per-device dashboards** with top domains, blocked domains, and insights
- Domain insights: first seen, last seen, request breakdown by device
- **Heuristic domain classification**: automatically groups CDN/infrastructure noise without hardcoded lists
- SQLite with WAL mode, async batched writes (DNS resolution is never blocked by disk I/O)
- 30-day retention + 1M row hard cap (safe for Raspberry Pi SD cards)
- CSV/JSON export

### Networking
- Built-in **DHCP server** with automatic device hostname registration
- **Tailscale** integration for remote access and peer discovery
- Custom **DNS Action Engine**: trigger webhooks or sandboxed scripts from DNS queries
- Host networking preserves real client IPs (no Docker NAT masking)

### Hardening
- Read-only container filesystem with tmpfs for `/run` and `/tmp`
- All Linux capabilities dropped except `NET_BIND_SERVICE`
- `no-new-privileges`, PID limit (256), non-root UID (10001)
- HTTP security headers: CSP, HSTS, X-Frame-Options, CORS rejection
- Same-origin enforcement via `X-Aegis-Request` header
- 200ms delay on failed auth attempts (brute-force slowdown)
- Atomic file writes with `fsync` + rename (no partial configs on crash)

---

## The honest comparison

I'm not going to pretend AegisDNS is perfect or that the alternatives are trash. Every tool has a purpose. Here's where they each shine and where they fall short.

| | **AegisDNS** | **Pi-hole** | **AdGuard Home** | **NextDNS** |
|:--|:--|:--|:--|:--|
| **Runs on your hardware** | ✅ | ✅ | ✅ | ❌ Cloud only |
| **Your queries stay private** | ✅ | ✅ | ✅ | ❌ Sent to their servers |
| **DGA detection (entropy)** | ✅ Built-in | ❌ | ❌ | ✅ Cloud ML |
| **Phishing detection (typosquatting)** | ✅ Built-in | ❌ | ❌ (paid DNS only) | ✅ Cloud ML |
| **Fast-Flux / botnet detection** | ✅ Built-in | ❌ | ❌ | Partial |
| **DNSSEC validation** | ✅ Local Unbound | ❌ Relies on upstream | ✅ | ✅ |
| **Per-device policies** | ✅ With real client IPs | ✅ | ✅ | Limited (sees router IP) |
| **Built-in DHCP** | ✅ Auto-registers hostnames | ✅ | ✅ | ❌ |
| **Time-based schedules** | ✅ | ❌ | ✅ | ✅ |
| **Custom DNS actions** | ✅ Webhooks + scripts | ❌ | ❌ | ❌ |
| **Written in** | Rust | PHP + C (dnsmasq) | Go | Proprietary |
| **Price** | Free forever | Free | Free | Freemium (300k queries/mo) |
| **Open source** | ✅ MIT | ✅ GPL | ✅ GPL | ❌ |

**The short version:**
- **Pi-hole** is a great ad blocker. It is not a security tool. It has zero algorithmic threat detection.
- **AdGuard Home** is a modern Pi-hole with better UX and DoH/DoT support. But its open-source version still relies entirely on static lists for threat detection.
- **NextDNS** has excellent security, but you're sending every URL you visit to a company's servers. For some people that's fine. For me, it defeats the entire point.
- **AegisDNS** gives you NextDNS-level threat detection running entirely on your own hardware. Your data never leaves your network.

---

## Architecture

```
Client Device ──► AegisDNS (port 53) ──► Policy Engine ──► Unbound (port 5353) ──► Internet
                       │                      │
                       │                      ├── Blocklist check
                       │                      ├── Per-device rules
                       │                      ├── Schedule evaluation
                       │                      ├── DGA entropy scoring
                       │                      ├── Typosquatting check
                       │                      └── Fast-Flux tracking
                       │
                       ├── Analytics DB (SQLite/WAL, async writes)
                       ├── DHCP Server (optional, auto-registers devices)
                       ├── Action Engine (webhooks, scripts)
                       └── Dashboard (localhost:5380)
```

AegisDNS is a Rust workspace with clean crate boundaries:

| Crate | Purpose |
|:--|:--|
| `daemon` | DNS proxy, web server, DHCP, Tailscale integration |
| `config` | Configuration, atomic writes, domain validation, address classification |
| `policy` | Rule evaluation: schedules, device rules, global rules, typosquatting |
| `risk` | DGA entropy scoring, Fast-Flux detection |
| `analytics` | SQLite storage, query recording, telemetry, domain classification |
| `blocklist` | List downloading, parsing (hosts/AdBlock), compilation, snapshotting |
| `resolver` | Unbound lifecycle management, DNSSEC, upstream config generation |
| `openroot` | Local zone DNS server for custom TLDs |

---

## Configuration

The installer creates `.env` and `config.json`. The only required value is `AEGIS_HOST_IP`: an IP address your clients can reach (usually your Tailscale or LAN IP).

```json
{
  "host_ips": [
    "127.0.0.1",
    "192.168.1.100",
    "100.x.x.x"
  ]
}
```

### Upstream DNS

By default, Unbound resolves from the DNS root; no third-party forwarder involved. You can configure a forwarder in the dashboard:

```
tls://9.9.9.9:853#dns.quad9.net
```

Both IP and TLS hostname are required. This prevents DNS bootstrap loops where the forwarder's own hostname would need resolution.

### Tailscale

Add your AegisDNS machine's Tailscale IP as a nameserver in the Tailscale admin console with "Override local DNS" enabled. Every device on your tailnet is now protected.

Peer discovery (auto-registering Tailscale devices) is opt-in because it expands container authority over the host Tailscale service:

```bash
docker compose -f docker-compose.yml -f docker-compose.tailscale.yml up -d
```

### Environment variables

| Variable | Default | Purpose |
|:--|:--|:--|
| `AEGIS_HOST_IP` | Detected by installer | IP for action server binding and DNS responses |
| `AEGIS_ADMIN_PASSWORD` | Auto-generated (64 chars) | Dashboard login password |
| `AEGIS_ACTION_EXECUTABLES` | Empty (disabled) | Colon-separated list of allowed executable paths |
| `TZ` | `UTC` | Timezone for logs and schedules |

---

## Dashboard & API

The dashboard is at `http://localhost:5380`. Username is `admin`.

Every API call requires HTTP Basic auth. State-changing calls also require the `X-Aegis-Request: 1` header (same-origin protection against CSRF):

```bash
# Read stats
curl --user 'admin:YOUR_PASSWORD' http://localhost:5380/api/stats

# Block a domain
curl --user 'admin:YOUR_PASSWORD' \
  -H 'X-Aegis-Request: 1' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}' \
  http://localhost:5380/api/deny
```

If you expose the dashboard beyond localhost, put it behind a TLS reverse proxy (Caddy, nginx, Tailscale Serve). AegisDNS sets HSTS headers so browsers will enforce HTTPS once configured.

---

## Custom actions

AegisDNS lets you trigger real-world actions when a DNS query matches a custom domain. This is genuinely unique; no other DNS server does this.

Register `.aegis`, `.lan`, `.root`, or `.home.arpa` domains as action triggers. When queried, they can fire a webhook, run a sandboxed script, or serve a custom HTML page.

```bash
curl -X POST http://deploy.aegis:5381 \
  -H 'Authorization: Bearer YOUR_ACTION_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"version": "1.2.3"}'
```

Shell actions are disabled by default. Each executable must be explicitly allowlisted in `AEGIS_ACTION_EXECUTABLES`. Commands are JSON arrays and never pass through a shell. Action tokens are stored as SHA-256 hashes and verified with constant-time comparison.

---

## Building from source

```bash
# Dependencies: Rust, Clang, OpenSSL dev headers, Unbound, unbound-anchor
cargo build --release --locked
cargo test --workspace --locked
```

The release binary lands at `target/release/aegisdnsd`.

For production, use the Docker image. It includes Unbound, trust anchors, and runs in a hardened container:

```bash
docker compose build
docker compose up -d
```

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues including port 53 conflicts, Docker DNS during builds, per-device rule debugging, DNSSEC failures, and rate limiting behavior.

Quick health check:

```bash
aegis status
dig @127.0.0.1 example.com
dig @127.0.0.1 example.com +tcp
```

---

## Contributing

This project is MIT licensed. Fork it, improve it, break it, fix it, ship it.

If you find a security vulnerability, please open a private security advisory on GitHub instead of a public issue.

---

## License

[MIT](LICENSE): do whatever you want with it.

Privacy shouldn't cost money. This code is free, and it always will be.
