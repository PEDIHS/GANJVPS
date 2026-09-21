import json
import tempfile
import unittest
from pathlib import Path

import web_panel


class WebPanelTests(unittest.TestCase):
    def test_password_is_argon2_hashed(self):
        old_auth = web_panel.AUTH_FILE
        try:
            root = Path(tempfile.mkdtemp(prefix="ganj-web-auth-"))
            web_panel.AUTH_FILE = root / "web-auth.json"
            web_panel.configure_web_user("pedram", "very-strong-test-password")
            data = json.loads(web_panel.AUTH_FILE.read_text())
            self.assertEqual(data["username"], "pedram")
            self.assertTrue(str(data["password_hash"]).startswith("$argon2"))
            self.assertNotIn("very-strong-test-password", web_panel.AUTH_FILE.read_text())
            self.assertTrue(
                web_panel.PASSWORD_HASHER.verify(
                    data["password_hash"],
                    "very-strong-test-password",
                )
            )
        finally:
            web_panel.AUTH_FILE = old_auth

    def test_managed_gateway_endpoint_is_hidden(self):
        old_rank = web_panel.ganj_vps.rank_gateways
        old_current = web_panel.ganj_vps._current_wireguard_endpoint
        try:
            web_panel.ganj_vps.rank_gateways = lambda: [
                {
                    "id": "turkey-1",
                    "name": "Türkiye",
                    "endpoint": "secret-central.example:51820",
                    "latency_ms": 37.2,
                    "source": "central",
                },
                {
                    "id": "local-1",
                    "name": "Local Lab",
                    "endpoint": "198.51.100.1:51820",
                    "latency_ms": 50,
                    "source": "local",
                },
            ]
            web_panel.ganj_vps._current_wireguard_endpoint = (
                lambda: "secret-central.example:51820"
            )
            payload = web_panel._gateway_payload()
            self.assertEqual(payload["current_id"], "turkey-1")
            central = next(x for x in payload["items"] if x["id"] == "turkey-1")
            local = next(x for x in payload["items"] if x["id"] == "local-1")
            self.assertNotIn("endpoint", central)
            self.assertEqual(local["endpoint"], "198.51.100.1:51820")
            self.assertTrue(central["active"])
        finally:
            web_panel.ganj_vps.rank_gateways = old_rank
            web_panel.ganj_vps._current_wireguard_endpoint = old_current

    def test_log_redaction_hides_control_plane_and_secrets(self):
        old_cfg = web_panel.ganj_vps.CONFIG_FILE
        try:
            root = Path(tempfile.mkdtemp(prefix="ganj-web-log-"))
            cfg = root / "agent.json"
            cfg.write_text(
                json.dumps({"central": "https://central.hidden.example/ganj-agent"})
            )
            web_panel.ganj_vps.CONFIG_FILE = cfg
            output = web_panel._redact_text(
                "POST https://central.hidden.example/ganj-agent "
                "token=abc123 password=hunter2"
            )
            self.assertNotIn("central.hidden.example", output)
            self.assertNotIn("abc123", output)
            self.assertNotIn("hunter2", output)
            self.assertIn("[GANJ CONTROL]", output)
            self.assertIn("[REDACTED]", output)
        finally:
            web_panel.ganj_vps.CONFIG_FILE = old_cfg

    def test_ui_contains_mobile_navigation_and_core_sections(self):
        html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text()
        self.assertIn("@media(max-width:760px)", html)
        self.assertIn('class="bottom-nav"', html)
        self.assertIn('id="page-dashboard"', html)
        self.assertIn('id="page-locations"', html)
        self.assertIn('id="page-panel"', html)
        self.assertIn('id="page-gateways"', html)
        self.assertIn('id="page-tools"', html)
        self.assertIn("مصرف ترافیک لایسنس", html)


if __name__ == "__main__":
    unittest.main()
