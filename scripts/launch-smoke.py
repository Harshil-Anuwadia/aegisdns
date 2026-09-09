#!/usr/bin/env python3
"""Check a built image in a disposable container, without changing host DNS."""
import argparse
import base64
import json
import re
import socket
import struct
import subprocess
import sys
import time


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], capture_output=True, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="aegisdns:launch-check")
    parser.add_argument("--resolve", action="store_true", help="Also require external DNS resolution; needs outbound DNS access")
    args = parser.parse_args()
    # Deliberately synthetic credential, scoped to the disposable container.
    password = "disposable-launch-smoke-password"
    cid = docker("run", "--detach", "--rm", "--read-only",
                 "--tmpfs", "/run", "--tmpfs", "/tmp",
                 "--tmpfs", "/var/lib/aegisdns:rw,nosuid,size=128m",
                 "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
                 "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
                 "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
                 "--pids-limit", "256", "-p", "127.0.0.1::53/udp", "-p", "127.0.0.1::53/tcp",
                 "-e", "AEGIS_HOST_IP=127.0.0.1", "-e", f"AEGIS_ADMIN_PASSWORD={password}",
                 args.image, text=True).stdout.strip()
    try:
        def http(path, method="GET", payload=None, authenticated=True, mutation_header=True):
            body = json.dumps(payload).encode() if payload is not None else b""
            headers = [f"{method} {path} HTTP/1.1", "Host: localhost", "Connection: close", f"Content-Length: {len(body)}"]
            if authenticated:
                token = base64.b64encode(f"admin:{password}".encode()).decode()
                headers.append(f"Authorization: Basic {token}")
            if payload is not None:
                headers.append("Content-Type: application/json")
            if mutation_header:
                headers.append("X-Aegis-Request: 1")
            raw = docker("exec", "-i", "--user", "10001:10001", cid, "bash", "-c",
                         "exec 3<>/dev/tcp/127.0.0.1/5380; cat >&3; cat <&3",
                         input="\r\n".join(headers).encode() + b"\r\n\r\n" + body, timeout=15).stdout
            head, content = raw.split(b"\r\n\r\n", 1)
            return int(head.split()[1]), content

        for attempt in range(30):
            try:
                if http("/", authenticated=False)[0] == 401:
                    break
            except (subprocess.SubprocessError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Admin listener did not become available")

        status, page = http("/")
        assert status == 200 and b'id="root"' in page, "Compiled dashboard missing"
        asset = re.search(rb'src="(/assets/[^\"]+\.js)"', page)
        assert asset and http(asset[1].decode())[0] == 200, "Dashboard script missing"
        assert http("/api/deny", "POST", {"domain": "example.com"}, mutation_header=False)[0] == 403
        status, saved = http("/api/deny", "POST", {"domain": "example.com"})
        assert status == 200 and json.loads(saved)["success"], "Rule could not be saved"

        query = struct.pack("!HHHHHH", 4217, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"

        def dns(tcp):
            protocol = "tcp" if tcp else "udp"
            port = int(docker("port", cid, f"53/{protocol}", text=True).stdout.strip().rsplit(":", 1)[1])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
                sock.settimeout(15)
                sock.connect(("127.0.0.1", port))
                if tcp:
                    def receive(count):
                        data = b""
                        while len(data) < count:
                            chunk = sock.recv(count - len(data))
                            if not chunk:
                                raise RuntimeError("Truncated TCP DNS frame")
                            data += chunk
                        return data
                    sock.sendall(struct.pack("!H", len(query)) + query)
                    result = receive(struct.unpack("!H", receive(2))[0])
                else:
                    sock.send(query)
                    result = sock.recv(65535)
            assert len(result) >= 12 and struct.unpack("!H", result[:2])[0] == 4217
            return result[3] & 15, struct.unpack("!H", result[6:8])[0]

        for tcp in (False, True):
            assert dns(tcp)[0] == 3, f"Blocked query was not NXDOMAIN over {'TCP' if tcp else 'UDP'}"
        for endpoint in ("/api/stats", "/api/graph", "/api/privacy"):
            status, body = http(endpoint)
            assert status == 200 and isinstance(json.loads(body), dict), endpoint
        print("PASS: compiled assets, admin authentication, mutation protection, saved policy, UDP/TCP blocking, analytics APIs")
        if args.resolve:
            assert json.loads(http("/api/allow", "POST", {"domain": "example.com"})[1])["success"]
            # The admin listener can be ready before Unbound has bootstrapped
            # its trust anchor. Allow a bounded cold-start grace period.
            deadline = time.monotonic() + 90
            for tcp in (False, True):
                while True:
                    try:
                        code, answers = dns(tcp)
                        if code == 0 and answers > 0:
                            break
                        failure = f"rcode={code}, answers={answers}"
                    except TimeoutError:
                        failure = "query timed out"
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"External DNS failed over {'TCP' if tcp else 'UDP'}: {failure}")
                    time.sleep(2)
            print("PASS: external DNS resolution over UDP and TCP through Unbound")
            # Exercise the exact root-NS readiness probe used by the installer.
            from setup import dns_check
            for tcp in (False, True):
                protocol = "tcp" if tcp else "udp"
                port = int(docker("port", cid, f"53/{protocol}", text=True).stdout.strip().rsplit(":", 1)[1])
                assert dns_check(port=port, tcp=tcp), f"Installer readiness failed over {protocol}"
            print("PASS: installer DNS readiness probes over UDP and TCP")
    except Exception:
        logs = docker("logs", "--tail", "60", cid, text=True)
        print(logs.stdout + logs.stderr, file=sys.stderr)
        raise
    finally:
        docker("rm", "--force", cid)


if __name__ == "__main__":
    main()
