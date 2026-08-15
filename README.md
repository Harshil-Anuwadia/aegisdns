# AegisDNS

I built AegisDNS because I am completely fed up with being tracked. I am tired of my phone, my Windows PC, and my Smart TV secretly phoning home behind my back, logging what I do, and selling my data. I know exactly how these tracking networks operate under the hood, and I refuse to pay a cloud DNS provider just so they can log my traffic instead.

So I coded my own solution from scratch. AegisDNS is 100% free, open source, and written in Rust so it's crazy fast. It doesn't just block simple ads. It aggressively cuts off OS level telemetry, Smart TV spyware, and hardcoded trackers right at the network level. You run it yourself. Paired with Tailscale, it gives you absolute control over all your devices anywhere in the world, without dealing with annoying blocker apps on every phone or laptop.

---

## 1. Why Free and Open Source?

Security tools shouldn't be locked inside black boxes, and you definitely shouldn't have to pay a monthly subscription just to keep companies from spying on you. Because this is free and open source, anyone can look at the Rust code, compile it themselves, and know exactly what is happening to their data.

Trying to install adblockers on every single phone, tablet, and PC in the house is a huge pain. AegisDNS intercepts the traffic at the DNS level instead. If your device connects, the trackers are blocked. That is it.

I also refuse to forward my internet traffic to Google or Cloudflare. AegisDNS runs its own internal Unbound resolver. It talks directly to the root internet servers, meaning your DNS logs never leave your own hardware.

Global blocklists are too rigid anyway. I wanted strict blocking for my phone to stop wasting time, but a more relaxed policy for my work PC. AegisDNS lets you link specific rules to your device IP, giving you total control.

---

## 2. Installation & Setup

I packaged the entire project with Docker so anybody can deploy it instantly on any system without dealing with errors or installing dependencies.

### Automated Setup (Windows)
If you are using Windows, install Docker Desktop first. Make sure the Windows "Internet Connection Sharing" service is disabled so port 53 is open. Then run the batch script:

```cmd
install.bat
```

If you encounter any network errors, run `fix-windows.bat`.

### Manual Docker Deployment
If you already know how to use Docker and prefer to run it manually:
```bash
docker compose up -d --build
```
*Note: The `docker-compose.yml` file uses `network_mode: "host"`. You must keep this. If you change it to bridge mode, Docker will hide the real client IPs, which breaks the per-device blocking completely.*

### The Docker Desktop IP Mirage
Because Docker Desktop runs inside a hidden virtual machine on Windows and Mac, it completely breaks how IP addresses work. Docker forces all incoming DNS queries through its own NAT proxy, meaning every single device on your network (your phone, your smart TV) gets its IP overwritten to `172.18.0.1`. 

Because AegisDNS can only see that one fake IP, the "Per-Device" rules on the dashboard will not work properly. If you block YouTube for one device, it blocks it for the entire house. 

If you want absolute control over individual devices, you have to get AegisDNS off Docker Desktop and run it natively on a Linux machine (like a Raspberry Pi or an old Ubuntu laptop) where `network_mode: "host"` actually works.

---

## 3. Configuration Files (`config.json`)

I added a lightweight `config.json` file to fix the nightmare that is Docker networking. This file mounts straight into the container and sits right next to your `docker-compose.yml`.

### `config.json` (Host IPs)
This tells the Rust backend exactly which IP addresses belong to the server itself (like your Tailscale IP, your local network IP, and localhost).

```json
{
  "host_ips": [
    "100.x.x.x",
    "192.168.1.x",
    "127.0.0.1"
  ]
}
```

**Why do you need this?** Because Docker network translation is notorious for destroying client IP tracking. If I didn't add this, the server would get confused and start logging its own internal system queries as if they were coming from a user device. By explicitly telling the engine what its own IPs are, it effortlessly filters them out. Your dashboard stays absolutely clean, showing only the actual phones and PCs on your network trying to sneak data out.

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

## 5. Technical Architecture

I wrote the backend in Rust to make it fast and stable. The system is split into multiple highly-specialized modules:

### `aegisdnsd` (The Core Daemon)
This is the main program. It uses `tokio` for async networking and listens on `0.0.0.0:53` to catch all incoming DNS queries. It features a hyper-fast **LRU DNS Cache** powered by `moka`, which caches standard queries to return them in microseconds without touching upstream servers.

### `resolver` (The Unbound Engine & Failover)
Instead of relying on basic forwarders, AegisDNS uses an ultra-robust **Multi-Upstream Failover** loop. It routes queries locally to Unbound (`127.0.0.1:5353`), but if resolution times out or fails, it instantly falls back to Quad9 (Malware blocking) and then Google DNS to ensure rock-solid internet stability.

### `blocklist` (The Telemetry Fortress)
This module runs in the background and downloads massive lists of known bad domains. It features a custom parser that reads millions of rules—including complex AdGuard syntax. AegisDNS is pre-loaded with the **Deep Ocean Telemetry Blocklists**:
- **1Hosts (Xtra):** Over 1 million rules blocking ads, tracking, and telemetry.
- **Hagezi Native Trackers:** Blocks native OS telemetry from Apple, Windows, and Amazon.
- **Xiaomi & Chinese Phone Aggressive Telemetry:** Blocks hardcoded smartphone spyware.
- **Perflyst SmartTV & Appliance:** Targets hidden IoT spying on your network.
- **OISD Big & AdGuard DNS Filter:** Flawless general-purpose ad/malware blocking.

### `risk` (Threat Engine)
If a domain is not in a blocklist, this module checks it live. It executes deep analysis:
- **Fast-Flux Detection:** Tracks resolving IPs dynamically. If a domain rapidly switches IP addresses across non-CDN networks, it is blocked as a malware C&C server.
- **Levenshtein Brand Protection:** Automatically flags typo-squatting attempts targeting major brands (e.g., `paypa1.com`).
- **Newly Registered Domain (NRD) Heuristics:** Blocks highly-entropic domains lacking vowels that match suspicious TLDs (`.xyz`, `.top`).

### `anomaly` (IoT Behavioral Quarantine)
AegisDNS actively monitors the behavior of every device on your network using a sliding window algorithm. If a device suddenly spams DNS queries (e.g., a hacked Smart TV making 10x its normal baseline, or >500 queries in 60s), it is instantly placed into **Quarantine**, entirely cutting off its internet access until you manually unblock it.

### `web` (The API)
A fast API built with `axum`. It listens on `0.0.0.0:5380` and serves the web dashboard. The dashboard runs entirely in your browser and includes a dedicated panel to manage Quarantined Devices.

---

## 6. Using the API

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

## 7. Building from Source

If you do not want to use Docker, anybody can build the code from source. 

1. Install Rust via `rustup`.
2. Install `unbound` and `clang` using your package manager.
3. Build the project:
```powershell
cargo build --release
```
4. Run it as Administrator so it can bind to port 53:
```powershell
.\target\release\aegisdnsd.exe
```

---

## 8. How to Contribute

This project is completely open source. Anybody is free to use it, fork it, and modify it. If you want to help make it better:
- Report any bugs you find in the Issues tab.
- Submit changes or new features by opening a Pull Request.
- Share it with others who want privacy and control over their own networks.

---

## 9. Transparency and Acknowledgements

I want to be totally upfront about this. I built AegisDNS with the help of AI. I was so angry about how broken privacy has become that I needed to build a real hardcore solution right away. I used AI as a pair programmer to help me architect the Rust engine, write the Docker scripts, and dial in the complex threat detection logic fast.

I don't care about tech hype. I just care about building tools that actually solve the problem. The AI helped me write the code faster, but every single strict blocking rule, privacy feature, and core design choice came straight from my own frustration with how our data is being stolen. I built exactly what I needed to take back control of my network, and I'm putting it out there for free so you can too.
