import unittest

import web_publish


SAMPLE = """global
    log /dev/log local0

defaults
    mode tcp

frontend ft_single_443
    mode tcp
    bind 0.0.0.0:443
    tcp-request inspect-delay 5s
    default_backend be_panel

backend be_panel
    mode tcp
    server panel 127.0.0.1:8443
"""


class WebPublishTests(unittest.TestCase):
    def test_domain_validation(self):
        self.assertEqual(
            web_publish._domain("Panel.Example.COM."),
            "panel.example.com",
        )
        for invalid in ("", "localhost", "-bad.example.com", "bad_domain.com"):
            with self.assertRaises(RuntimeError):
                web_publish._domain(invalid)

    def test_sni_route_is_inserted_before_existing_default(self):
        rendered = web_publish._insert_sni_block(
            SAMPLE,
            "panel.example.com",
        )
        self.assertIn(
            "acl sni_ganj_web req.ssl_sni -i panel.example.com",
            rendered,
        )
        self.assertLess(
            rendered.index("use_backend be_ganj_web_tls"),
            rendered.index("default_backend be_panel"),
        )
        self.assertIn("server panel 127.0.0.1:8443", rendered)

    def test_http_route_preserves_acme_and_redirects_other_paths(self):
        block = web_publish._http_block()
        self.assertIn("bind 0.0.0.0:80", block)
        self.assertIn("/.well-known/acme-challenge/", block)
        self.assertIn("127.0.0.1:9880", block)
        self.assertIn("redirect scheme https", block)

    def test_tls_frontend_uses_proxy_protocol_and_loopback_app(self):
        block = web_publish._tls_block(
            web_publish.Path("/etc/haproxy/certs/ganj-web.pem")
        )
        self.assertIn("127.0.0.1:9878", block)
        self.assertIn("send-proxy-v2", block)
        self.assertIn("accept-proxy ssl", block)
        self.assertIn("127.0.0.1:9877", block)
        self.assertIn("Strict-Transport-Security", block)

    def test_strip_blocks_keeps_existing_reality_routes(self):
        combined = (
            SAMPLE.rstrip()
            + "\n\n"
            + web_publish._http_block()
            + "\n\n"
            + web_publish._tls_block(web_publish.Path("/tmp/web.pem"))
            + "\n"
        )
        cleaned = web_publish._strip_web_blocks(combined)
        self.assertNotIn(web_publish.HTTP_BEGIN, cleaned)
        self.assertNotIn(web_publish.TLS_BEGIN, cleaned)
        self.assertIn("frontend ft_single_443", cleaned)
        self.assertIn("backend be_panel", cleaned)

    def test_installer_prompts_for_domain_and_certificate_choice(self):
        text = (
            web_publish.Path(__file__).resolve().parents[1] / "install.sh"
        ).read_text()
        self.assertIn("Domain / subdomain (blank = local only)", text)
        self.assertIn("Existing TLS certificate", text)
        self.assertIn("apt-get install -y certbot", text)
        self.assertIn("--auto-cert", text)
        self.assertIn("Routes active: / · /api/* · /api/events · /healthz", text)


if __name__ == "__main__":
    unittest.main()
