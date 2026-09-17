#!/usr/bin/env python3
"""Narrow root helper for AegisDNS Tailscale Serve control.

The systemd socket supplies one request on stdin and receives one JSON response
on stdout. Only the AegisDNS root handler may be created or removed.
"""
import json
import subprocess
import sys

TARGET = "http://127.0.0.1:5380"


def run(*args, timeout=15):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)


def state():
    status = run("tailscale", "status", "--json")
    if status.returncode:
        return {"success": True, "available": False, "enabled": False, "message": "Tailscale is not connected on this server."}
    try:
        info = json.loads(status.stdout)
        dns_name = str(info.get("Self", {}).get("DNSName", "")).rstrip(".")
    except (ValueError, TypeError):
        dns_name = ""
    if not dns_name:
        return {"success": True, "available": False, "enabled": False, "message": "Tailscale has no MagicDNS name for this server."}
    served = run("tailscale", "serve", "status", "--json")
    try:
        config = json.loads(served.stdout) if served.returncode == 0 else {}
        config = config if isinstance(config, dict) else {}
    except (ValueError, TypeError):
        config = {}
    host_port = f"{dns_name}:443"
    handler = config.get("Web", {}).get(host_port, {}).get("Handlers", {}).get("/", {})
    proxy = handler.get("Proxy") if isinstance(handler, dict) else None
    return {
        "success": True,
        "available": True,
        "enabled": proxy == TARGET,
        "conflict": bool(proxy and proxy != TARGET),
        "url": f"https://{dns_name}",
        "dns_name": dns_name,
        "message": "Mobile access is ready." if proxy == TARGET else ("Port 443 already serves another application." if proxy else "Mobile access is off."),
    }


def change(enabled):
    current = state()
    if not current.get("available"):
        return {**current, "success": False}
    if enabled and current.get("conflict"):
        return {**current, "success": False, "message": "Tailscale Serve already has a different root application. AegisDNS left it unchanged."}
    if bool(current.get("enabled")) == enabled:
        return current
    args = ["tailscale", "serve"]
    if enabled:
        args += ["--bg", TARGET]
    else:
        args += ["--https=443", "off"]
    result = run(*args, timeout=30)
    if result.returncode:
        detail = (result.stderr or result.stdout or "Tailscale rejected the request.").strip()[:500]
        return {**current, "success": False, "message": detail}
    return state()


def main():
    try:
        request = json.loads(sys.stdin.buffer.readline(4097))
        action = request.get("action")
        response = state() if action == "status" else change(action == "enable") if action in ("enable", "disable") else {"success": False, "available": True, "enabled": False, "message": "Unsupported request."}
    except Exception as error:
        response = {"success": False, "available": False, "enabled": False, "message": f"Mobile access helper failed: {str(error)[:300]}"}
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
