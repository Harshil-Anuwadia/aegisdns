# AegisDNS

I built AegisDNS because I needed a simple and strict DNS blocker. I did not want to pay for cloud services or rely on public providers that log my data. I also did not want a single policy that blocks everyone on my network the exact same way.

AegisDNS is a 100% free and open-source, self-hosted DNS proxy written in Rust. Anybody can use it, modify it, or host it themselves. It handles ad-blocking, malware protection, and per-device policies at the network level. It integrates perfectly with Tailscale, which means you can control exactly what your devices are allowed to access from anywhere in the world, without installing any blocking apps on your phone or laptop.

---

## 1. Why Free and Open Source?

Security tools should not be hidden behind paywalls or closed-source code. By making AegisDNS completely free and open source, anybody can verify the code, compile it from source, and confirm that their data is never being tracked, sold, or logged.

1. **No Client Setup:** Managing browser extensions across phones and tablets is hard. AegisDNS handles the security at the DNS level. If your device is connected to Tailscale, it is protected.
2. **True Privacy:** I do not want to forward queries to Cloudflare or Google. AegisDNS has Unbound built-in. It talks to the internet Root Servers directly. Your data never leaves your server.
3. **Per-Device Blocking:** I wanted to block social media on my phone, but leave it allowed on my desktop. AegisDNS links your Tailscale IP to specific rules, so you get device-level blocking.

---

## 2. Technical Architecture

I wrote the backend in Rust to make it fast and stable. Anyone is welcome to read the source code or submit changes. The system is split into smaller modules:

### `aegisdnsd` (The Core Daemon)
This is the main program. It uses `tokio` for async networking. It listens on `0.0.0.0:53` to catch all incoming DNS queries. If a query is allowed by the rules, it forwards it to the internal resolver at `127.0.0.1:5353`.

### `resolver` (The Unbound Engine)
Instead of writing a custom recursive DNS engine, the app uses `unbound`. The resolver module writes a safe config and starts Unbound in the background on localhost. The recursive engine is never exposed directly to the outside network. This guarantees privacy.

### `policy` (The Rules Engine)
This is the memory module that handles the blocking logic. It manages Global Allows, Global Denies, and Device-Specific rules. It instantly saves any changes you make to `/var/lib/aegisdns/policy.json`.

### `blocklist`
This module runs in the background and downloads massive lists of known bad domains from public open-source lists like URLhaus and StevenBlack. It loads millions of rules into memory so DNS queries can be checked instantly without slowing down your internet.

### `risk` (Threat Engine)
If a domain is not in a blocklist, this module checks it live. It looks for:
- Randomly generated malware domains using basic math.
- Fake typo domains trying to look like real sites (for example, `g0ogle.com`).
- Suspicious or cheap domain endings (TLDs).

### `web` (The API)
A fast API built with `axum`. It listens on `0.0.0.0:5380` and serves the web dashboard. The dashboard is just HTML and Javascript, and it runs entirely in your browser.

---

## 3. Installation & Setup

I packaged the entire project with Docker so anybody can deploy it instantly on any system without dealing with errors or installing dependencies.

### Automated Setup (Linux & macOS)
I wrote an install script that handles everything. It checks for Docker, fixes native Linux port 53 conflicts (like systemd-resolved), and builds the Docker container automatically.

Run this command in your terminal:
```bash
sudo ./install.sh
```

### Windows Deployment
If you are using Windows, install Docker Desktop first. Make sure the Windows "Internet Connection Sharing" service is disabled so port 53 is open. Then run the batch script:

```cmd
install.bat
```

### Manual Docker Deployment
If you already know how to use Docker and prefer to run it manually:
```bash
docker compose up -d --build
```
*Note: The `docker-compose.yml` file uses `network_mode: "host"`. You must keep this. If you change it to bridge mode, Docker will hide the real client IPs, which breaks the per-device blocking completely.*

---

## 4. Tailscale & Network Routing

Tailscale is a free VPN that lets your devices talk to each other securely.

### Setup Global Tailscale Blocking (MagicDNS)
To force every device on your Tailscale network to use AegisDNS automatically:
1. Log into your [Tailscale Admin Console](https://login.tailscale.com/admin/dns).
2. Go to the **DNS** tab.
3. Add a **Custom Nameserver** and enter the Tailscale IP of your AegisDNS machine.
4. Turn ON **Override local DNS**.

### Disable Secure DNS
Modern web browsers (like Chrome, Brave, and Firefox) try to bypass local DNS by using "Secure DNS" (DoH). If DoH is turned on, AegisDNS cannot block the traffic. 
You must turn OFF "Secure DNS" or "DNS over HTTPS" in the browser settings. Once this is off, nobody can bypass the blocking.

---

## 5. Using the API

Because this is an open project, the dashboard is completely separate from the backend. If you want to build your own dashboard, make an app, or write scripts, you can use the API directly. Here are the public endpoints:

| Endpoint | Method | Payload |
|---|---|---|
| `/api/stats` | GET | `?device_id=IP` |
| `/api/policy` | GET | None |
| `/api/allow` | POST | `{"domain":"example.com", "device_id":"100.x.x.x"}` |
| `/api/deny` | POST | `{"domain":"example.com", "device_id":"100.x.x.x"}` |
| `/api/policy/remove`| POST | `{"domain":"example.com", "device_id":"100.x.x.x"}` |
| `/api/safesearch` | POST | `{"enabled":true}` |
| `/api/risk` | POST | `{"domain":"example.com"}` |

---

## 6. Building from Source

If you do not want to use Docker, anybody can build the code from source. 

1. Install Rust via `rustup`.
2. Install `unbound`, `clang`, and `libssl-dev` using your package manager (like apt or dnf).
3. Build the project:
```bash
cargo build --release
```
4. Run it as root so it can bind to port 53:
```bash
sudo target/release/aegisdnsd
```

---

## 7. How to Contribute

This project is completely open source. Anybody is free to use it, fork it, and modify it. If you want to help make it better:
- Report any bugs you find in the Issues tab.
- Submit changes or new features by opening a Pull Request.
- Share it with others who want privacy and control over their own networks.

---

## 8. Transparency & Acknowledgements

I want to be completely honest: I built AegisDNS with the help of Artificial Intelligence. I used AI as an advanced pair-programmer to help me understand complex networking logic, design the modular Rust architecture, write the automated Docker deployment scripts, and refine the heuristic threat engine.

I believe in building good software, and I believe in using the best tools available to make that happen. The AI helped me bring this vision to life much faster than I could have alone, but every feature, strict blocking rule, and design choice was personally directed by me to solve real problems I was facing.
