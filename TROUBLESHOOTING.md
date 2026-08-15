# Troubleshooting AegisDNS on Windows & Docker

When running AegisDNS via Docker Desktop on Windows, you are routing system-level network traffic (port 53) into a virtualized Linux container. This can occasionally clash with other VPNs, Windows services, or Docker's internal networking.

If you encounter issues during installation or usage, check the solutions below.

## 1. Installation Fails: `dial tcp: lookup registry-1.docker.io: no such host`

**The Problem:**
During `install.bat`, Docker is completely unable to connect to the internet to download the Rust or Debian images. This happens because your Windows DNS is currently set to `127.0.0.1`, but the AegisDNS container isn't running yet, so you have no active DNS resolver.

**The Fix:**
1. Open Windows **Network Settings** -> **Wi-Fi** (or Ethernet) -> **Hardware Properties**.
2. Edit your **DNS server assignment** and temporarily change it from `127.0.0.1` back to **Automatic (DHCP)** (or `8.8.8.8`).
3. Run `install.bat`.
4. Once the installation completes successfully, set your DNS back to `127.0.0.1`.

---

## 2. Docker Fails with IPv6: `dial tcp [::1]:443: connectex: actively refused`

**The Problem:**
Docker Desktop on Windows has a known bug where it attempts to route internet traffic through an internal IPv6 loopback address (`::1`) and fails, preventing any images from being pulled.

**The Fix:**
Force Docker Desktop to use IPv4 and public DNS:
1. Open **Docker Desktop**.
2. Click the **⚙️ Settings** icon (top right) -> **Docker Engine**.
3. Add the following to your JSON configuration:
```json
{
  "dns": ["8.8.8.8", "1.1.1.1"],
  "ipv6": false
}
```
4. Click **Apply & restart**. Run `install.bat` again.

---

## 3. Total Internet Loss / Timeout (Even with 8.8.8.8)

**The Problem:**
If your browser cannot load any websites, and running `ping google.com` fails, but `ping 8.8.8.8` succeeds, your DNS traffic (UDP Port 53) is being actively blocked or hijacked by another application on your PC.

**Common Culprits:**
* **Tailscale (or other VPNs):** Tailscale's "MagicDNS" aggressively intercepts all DNS traffic. If the Tailscale backend crashes or loses connection to its tunnel, it will silently drop all your DNS queries, completely killing your internet. **Fix:** Right-click Tailscale in your system tray and select **Exit** or **Disconnect**.
* **Windows ICS:** The Windows "Internet Connection Sharing" service (SharedAccess) binds to UDP port 53. If it runs at the same time as AegisDNS, traffic will conflict. **Fix:** Open PowerShell as Administrator and run `Stop-Service SharedAccess -Force`.

---

## 4. Legitimate Sites (YouTube, Docker) Blocked as "Fast-Flux"

**The Problem:**
You see warnings in the Docker logs like `WARN aegisdnsd::proxy: Fast-flux detected for domain: registry-1.docker.io` and the site refuses to load. Massive global CDNs (like Google, YouTube, Cloudflare) rotate their IP addresses rapidly across many subnets, which triggers our botnet detection heuristic.

**The Fix:**
This has been resolved in the latest release! The AegisDNS `FastFluxDetector` now hardcodes an extensive whitelist of major tech platforms and CDNs. It also requires a domain to hit >10 unique `/16` subnets (up from 5) within a 10-minute window before triggering a quarantine. Ensure you pull the latest code and rebuild.

---

## 5. Docker Pulls Triggering "Anomaly Detected / Quarantine"

**The Problem:**
When you build a large Docker image or run `npm install`, your machine makes thousands of DNS queries in seconds. AegisDNS sees this massive spike (e.g., >500 queries a minute) and automatically quarantines your IP (`172.18.0.1` or `127.0.0.1`), cutting off your internet.

**The Fix:**
This is also resolved in the latest release. The `AnomalyDetector` now automatically whitelists local Docker bridge networks (`172.x.x.x`), Tailscale IPs (`100.x.x.x`), and localhost (`127.x.x.x`). The baseline threshold for external devices has also been increased to a more lenient 2,500 queries per minute to prevent false positives during heavy browsing.
