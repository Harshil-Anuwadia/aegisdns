"""Tests for the narrowly scoped Tailscale Serve helper."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mobile_access_helper", SOURCE / "scripts/mobile-access-helper.py"
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def result(payload="", returncode=0):
    return subprocess.CompletedProcess([], returncode, payload, "")


class MobileAccessHelperTests(unittest.TestCase):
    def test_status_recognises_only_the_aegisdns_root_handler(self):
        serve = {"Web": {"host.example.ts.net:443": {"Handlers": {
            "/": {"Proxy": helper.TARGET}, "/other": {"Proxy": "http://127.0.0.1:9000"}
        }}}}
        with patch.object(helper, "run", side_effect=[
            result(json.dumps({"Self": {"DNSName": "host.example.ts.net."}})),
            result(json.dumps(serve)),
        ]):
            status = helper.state()
        self.assertTrue(status["enabled"])
        self.assertFalse(status["conflict"])
        self.assertEqual(status["url"], "https://host.example.ts.net")

    def test_enable_never_overwrites_an_existing_root_application(self):
        serve = {"Web": {"host.example.ts.net:443": {"Handlers": {
            "/": {"Proxy": "http://127.0.0.1:9000"}
        }}}}
        responses = [
            result(json.dumps({"Self": {"DNSName": "host.example.ts.net"}})),
            result(json.dumps(serve)),
        ]
        with patch.object(helper, "run", side_effect=responses) as run:
            status = helper.change(True)
        self.assertFalse(status["success"])
        self.assertTrue(status["conflict"])
        self.assertEqual(run.call_count, 2)

    def test_disconnected_tailscale_is_unavailable(self):
        with patch.object(helper, "run", return_value=result(returncode=1)):
            status = helper.state()
        self.assertFalse(status["available"])
        self.assertFalse(status["enabled"])


if __name__ == "__main__":
    unittest.main()
