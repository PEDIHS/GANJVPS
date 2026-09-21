import copy
import tempfile
import unittest
from pathlib import Path

import ganj_vps
import panel_sync
from panel_sync import _alloc_ports, _location_map, choose_port_block, PasarGuardAdapter, SanaeiAdapter


def without_live_ports(fn):
    def wrapped(*args, **kwargs):
        old = panel_sync.system_listening_ports
        panel_sync.system_listening_ports = lambda: set()
        try:
            return fn(*args, **kwargs)
        finally:
            panel_sync.system_listening_ports = old
    return wrapped


class WireGuardSelfHealTests(unittest.TestCase):
    def test_parse_peer_config_and_endpoint(self):
        peer = ganj_vps._parse_wireguard_peer_config(
            "[Interface]\nPrivateKey = local\n\n"
            "[Peer]\nPublicKey = server-key\n"
            "Endpoint = gateway.example.test:51820\n"
        )
        self.assertEqual(peer["public_key"], "server-key")
        self.assertEqual(peer["endpoint"], "gateway.example.test:51820")
        self.assertEqual(
            ganj_vps._split_wireguard_endpoint(peer["endpoint"]),
            ("gateway.example.test", "51820"),
        )
        self.assertEqual(
            ganj_vps._split_wireguard_endpoint("[2001:db8::1]:51820"),
            ("2001:db8::1", "51820"),
        )

    def test_endpoint_refresh_updates_stale_dns_target(self):
        old_conf = ganj_vps.WG_CONF
        old_which = ganj_vps.shutil.which
        old_host = ganj_vps.socket.gethostbyname
        old_run = ganj_vps.run
        tmp = Path(tempfile.mkdtemp(prefix="ganj-vps-wg-test-")) / "ganj-vps.conf"
        tmp.write_text(
            "[Interface]\nPrivateKey = local\n\n"
            "[Peer]\nPublicKey = server-key\n"
            "Endpoint = gateway.example.test:51820\n",
            encoding="utf-8",
        )
        calls = []
        def fake_run(cmd, timeout=20, check=False):
            calls.append(cmd)
            class Result:
                returncode = 0
                stdout = "server-key 198.51.100.10:51820\n" if cmd[:4] == ["wg", "show", "ganj-vps", "endpoints"] else ""
                stderr = ""
            return Result()
        try:
            ganj_vps.WG_CONF = tmp
            ganj_vps.shutil.which = lambda name: "/usr/bin/wg" if name == "wg" else old_which(name)
            ganj_vps.socket.gethostbyname = lambda host: "198.51.100.20"
            ganj_vps.run = fake_run
            self.assertTrue(ganj_vps.refresh_wireguard_endpoint_dns())
            self.assertIn(
                ["wg", "set", "ganj-vps", "peer", "server-key", "endpoint", "gateway.example.test:51820"],
                calls,
            )
        finally:
            ganj_vps.WG_CONF = old_conf
            ganj_vps.shutil.which = old_which
            ganj_vps.socket.gethostbyname = old_host
            ganj_vps.run = old_run



class GatewayManagerTests(unittest.TestCase):
    def test_gateway_candidate_normalization_and_ranking(self):
        old_ping = ganj_vps.ping_latency_ms
        old_conf = ganj_vps.WG_CONF
        old_gateways = ganj_vps.GATEWAYS_FILE
        tmpdir = Path(tempfile.mkdtemp(prefix="ganj-vps-gateway-test-"))
        try:
            ganj_vps.WG_CONF = tmpdir / "wg.conf"
            ganj_vps.WG_CONF.write_text(
                "[Interface]\nPrivateKey = local\n\n"
                "[Peer]\nPublicKey = server-key\nEndpoint = current.example:51820\n",
                encoding="utf-8",
            )
            ganj_vps.GATEWAYS_FILE = tmpdir / "gateways.json"
            ganj_vps.save_json(ganj_vps.GATEWAYS_FILE, {
                "gateways": [{"id": "local", "name": "Local", "endpoint": "local.example:51820"}],
            })
            ganj_vps.ping_latency_ms = lambda host: {
                "fast.example": 12.0,
                "slow.example": 55.0,
                "local.example": 30.0,
                "current.example": 40.0,
            }.get(host)
            desired = {
                "gateway": {
                    "candidates": [
                        {"id": "slow", "endpoint": "slow.example:51820"},
                        {"id": "fast", "endpoint": "fast.example:51820"},
                    ]
                }
            }
            ranked = ganj_vps.rank_gateways(desired)
            self.assertEqual(ranked[0]["id"], "fast")
            self.assertEqual(ranked[0]["latency_ms"], 12.0)
            self.assertTrue(any(x["id"] == "local" for x in ranked))
            self.assertTrue(any(x["id"] == "current" for x in ranked))
        finally:
            ganj_vps.ping_latency_ms = old_ping
            ganj_vps.WG_CONF = old_conf
            ganj_vps.GATEWAYS_FILE = old_gateways

    def test_gateway_switch_rewrites_endpoint_and_rolls_back_on_failure(self):
        old_conf = ganj_vps.WG_CONF
        old_state = ganj_vps.STATE_FILE
        old_run = ganj_vps.run
        old_ping_ok = ganj_vps.gateway_ping_ok
        old_latency = ganj_vps.ping_latency_ms
        tmpdir = Path(tempfile.mkdtemp(prefix="ganj-vps-switch-test-"))
        config = (
            "[Interface]\nAddress = 10.60.0.2/32\nPrivateKey = local\n\n"
            "[Peer]\nPublicKey = server-key\nEndpoint = old.example:51820\n"
            "AllowedIPs = 10.60.0.0/16\n"
        )
        try:
            ganj_vps.WG_CONF = tmpdir / "wg.conf"
            ganj_vps.STATE_FILE = tmpdir / "state.json"
            ganj_vps.WG_CONF.write_text(config, encoding="utf-8")
            class Result:
                returncode = 0
                stdout = ""
                stderr = ""
            ganj_vps.run = lambda *args, **kwargs: Result()
            ganj_vps.gateway_ping_ok = lambda: True
            ganj_vps.ping_latency_ms = lambda host: 9.0
            self.assertTrue(ganj_vps.switch_gateway({
                "id": "new", "name": "New", "endpoint": "new.example:51820",
            }))
            self.assertIn("Endpoint = new.example:51820", ganj_vps.WG_CONF.read_text())
            self.assertEqual(ganj_vps.load_json(ganj_vps.STATE_FILE, {})["active_gateway"]["id"], "new")

            ganj_vps.WG_CONF.write_text(config, encoding="utf-8")
            ganj_vps.gateway_ping_ok = lambda: False
            with self.assertRaisesRegex(RuntimeError, "gateway_switch_verification_failed"):
                ganj_vps.switch_gateway({
                    "id": "bad", "name": "Bad", "endpoint": "bad.example:51820",
                })
            self.assertEqual(ganj_vps.WG_CONF.read_text(), config)
        finally:
            ganj_vps.WG_CONF = old_conf
            ganj_vps.STATE_FILE = old_state
            ganj_vps.run = old_run
            ganj_vps.gateway_ping_ok = old_ping_ok
            ganj_vps.ping_latency_ms = old_latency

    def test_connection_counter_uses_local_endpoint_only(self):
        old_run = ganj_vps.run
        class Result:
            returncode = 0
            stdout = (
                "0 0 127.0.0.1:6000 198.51.100.1:50000\n"
                "0 0 127.0.0.1:5000 198.51.100.2:6000\n"
            )
            stderr = ""
        try:
            ganj_vps.run = lambda *args, **kwargs: Result()
            counts = ganj_vps.established_connections_by_port({6000})
            self.assertEqual(counts[6000], 1)
        finally:
            ganj_vps.run = old_run

    def test_location_signature_changes_when_placeholder_becomes_ready(self):
        desired_a = {"gateway": {"locations": []}}
        desired_b = {"gateway": {"locations": [
            {"country_code": "DE", "port": 1082, "enabled": True},
        ]}}
        sig_a = ganj_vps.locations_signature(ganj_vps.locations_from_desired(desired_a))
        sig_b = ganj_vps.locations_signature(ganj_vps.locations_from_desired(desired_b))
        self.assertNotEqual(sig_a, sig_b)

    def test_reconcile_installs_only_when_location_state_changes(self):
        old_panel_file = ganj_vps.PANEL_SECRET_FILE
        old_state = ganj_vps.STATE_FILE
        old_choose = ganj_vps.choose_best_gateway
        old_ping = ganj_vps.gateway_ping_ok
        old_panel_profile = ganj_vps.panel_profile
        old_adapter_factory = ganj_vps.adapter_from_profile
        tmpdir = Path(tempfile.mkdtemp(prefix="ganj-vps-reconcile-test-"))
        calls = []
        class FakeAdapter:
            def install_locations(self, rows):
                calls.append(ganj_vps.locations_signature(rows))
                return {"installed": rows}
            def status(self):
                return {"managed_inbounds": 40, "type": "sanaei"}
        try:
            ganj_vps.PANEL_SECRET_FILE = tmpdir / "panel.json"
            ganj_vps.PANEL_SECRET_FILE.write_text("{}", encoding="utf-8")
            ganj_vps.STATE_FILE = tmpdir / "state.json"
            ganj_vps.choose_best_gateway = lambda desired, force=False: {"id": "gw"}
            ganj_vps.gateway_ping_ok = lambda: True
            ganj_vps.panel_profile = lambda: {"type": "sanaei"}
            ganj_vps.adapter_from_profile = lambda profile: FakeAdapter()
            desired = {"revision": 1, "gateway": {"locations": []}}
            first = ganj_vps.reconcile_desired(desired)
            second = ganj_vps.reconcile_desired(desired)
            self.assertTrue(first["locations_changed"])
            self.assertFalse(second["locations_changed"])
            self.assertEqual(len(calls), 1)

            desired["revision"] = 2
            desired["gateway"]["locations"] = [{"country_code": "DE", "port": 1082, "enabled": True}]
            third = ganj_vps.reconcile_desired(desired)
            self.assertTrue(third["locations_changed"])
            self.assertEqual(len(calls), 2)
        finally:
            ganj_vps.PANEL_SECRET_FILE = old_panel_file
            ganj_vps.STATE_FILE = old_state
            ganj_vps.choose_best_gateway = old_choose
            ganj_vps.gateway_ping_ok = old_ping
            ganj_vps.panel_profile = old_panel_profile
            ganj_vps.adapter_from_profile = old_adapter_factory

    def test_semver_comparison(self):
        self.assertGreater(ganj_vps._version_tuple("0.4.0"), ganj_vps._version_tuple("0.3.9"))
        self.assertEqual(ganj_vps._version_tuple("v1.2.3"), (1, 2, 3))


class LocationProbeTests(unittest.TestCase):
    def test_socks_probe_uses_domain_atyp_for_hostname(self):
        old_create = ganj_vps.socket.create_connection
        old_time = ganj_vps.time.monotonic
        sent = []

        class FakeSocket:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, value):
                pass
            def sendall(self, data):
                sent.append(data)
            def recv(self, size):
                if len(sent) == 1:
                    return b"\x05\x00"
                return b"\x05\x00\x00\x01"

        ticks = iter([10.0, 10.123])
        try:
            ganj_vps.socket.create_connection = lambda *args, **kwargs: FakeSocket()
            ganj_vps.time.monotonic = lambda: next(ticks)
            latency = ganj_vps.socks5_latency_ms(
                "10.60.0.1", 1081, "www.cloudflare.com", 443, 1.0
            )
            self.assertEqual(latency, 123.0)
            request = sent[1]
            self.assertEqual(request[:4], b"\x05\x01\x00\x03")
            length = request[4]
            self.assertEqual(request[5:5+length], b"www.cloudflare.com")
        finally:
            ganj_vps.socket.create_connection = old_create
            ganj_vps.time.monotonic = old_time

    def test_socks_probe_keeps_ipv4_atyp_for_ipv4_target(self):
        old_create = ganj_vps.socket.create_connection
        sent = []

        class FakeSocket:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, value):
                pass
            def sendall(self, data):
                sent.append(data)
            def recv(self, size):
                if len(sent) == 1:
                    return b"\x05\x00"
                return b"\x05\x00\x00\x01"

        try:
            ganj_vps.socket.create_connection = lambda *args, **kwargs: FakeSocket()
            self.assertIsNotNone(
                ganj_vps.socks5_latency_ms("10.60.0.1", 1082, "1.1.1.1", 443, 1.0)
            )
            self.assertEqual(sent[1][:4], b"\x05\x01\x00\x01")
        finally:
            ganj_vps.socket.create_connection = old_create


class PasarGuardPublishingTests(unittest.TestCase):
    def test_template_host_must_belong_to_selected_inbound(self):
        panel_sync._validate_pasarguard_template_pair(
            {"tag": "template-a"},
            {"id": 9, "inbound_tag": "template-a"},
        )
        with self.assertRaisesRegex(
            RuntimeError, "pasarguard_template_host_inbound_mismatch"
        ):
            panel_sync._validate_pasarguard_template_pair(
                {"tag": "template-a"},
                {"id": 9, "inbound_tag": "template-b"},
            )

    def test_proxy_protocol_local_template_requires_frontend(self):
        self.assertTrue(panel_sync._template_requires_proxy_frontend({
            "listen": "127.0.0.1",
            "streamSettings": {"sockopt": {"acceptProxyProtocol": True}},
        }))
        self.assertFalse(panel_sync._template_requires_proxy_frontend({
            "listen": "0.0.0.0",
            "streamSettings": {"sockopt": {"acceptProxyProtocol": True}},
        }))

    def test_haproxy_block_publishes_ports_to_local_xray_with_proxy_protocol(self):
        block = panel_sync._ganj_haproxy_block(
            "198.51.100.10", [6001, 6000]
        )
        self.assertIn("bind 198.51.100.10:6000", block)
        self.assertIn("bind 198.51.100.10:6001", block)
        self.assertIn("server xray 127.0.0.1:6000 send-proxy", block)
        self.assertIn("server xray 127.0.0.1:6001 send-proxy", block)
        cleaned = panel_sync._haproxy_without_ganj_block(
            "global\n\n" + block + "\ndefaults\n"
        )
        self.assertNotIn("BEGIN GANJ VPS LOCATION PORTS", cleaned)
        self.assertIn("global", cleaned)
        self.assertIn("defaults", cleaned)


class CentralWebCredentialTests(unittest.TestCase):
    def test_central_web_credentials_store_only_argon_hash(self):
        old_save = ganj_vps.save_json
        old_run = ganj_vps.subprocess.run
        seen = {}
        try:
            ganj_vps.save_json = lambda path, payload, mode=0o600: seen.update({
                "path": path, "payload": payload, "mode": mode
            })
            class Result:
                returncode = 0
                stdout = ""
                stderr = ""
            ganj_vps.subprocess.run = lambda *args, **kwargs: Result()
            result = ganj_vps.execute_central_command(
                "web_credentials_set",
                {
                    "username": "representative",
                    "password_hash": "$argon2id$v=19$m=65536,t=3,p=2$abc$def",
                },
            )
            self.assertTrue(result["auth_configured"])
            self.assertEqual(seen["payload"]["username"], "representative")
            self.assertTrue(seen["payload"]["password_hash"].startswith("$argon2id$"))
            self.assertNotIn("password", result)
            self.assertEqual(seen["mode"], 0o600)
        finally:
            ganj_vps.save_json = old_save
            ganj_vps.subprocess.run = old_run

    def test_central_web_credentials_reject_plaintext(self):
        with self.assertRaisesRegex(RuntimeError, "invalid_web_password_hash"):
            ganj_vps.execute_central_command(
                "web_credentials_set",
                {"username": "representative", "password_hash": "plaintext-secret"},
            )


class InstallerUXTests(unittest.TestCase):
    def test_installer_hides_central_url_and_curl_progress(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("Central URL [", installer)
        self.assertIn("curl -fsSL", installer)
        self.assertIn("panel-configure --auto", installer)
        self.assertIn("Emerald / Gold Edition", installer)

    def test_pasarguard_auto_connection_hides_url_and_tls_questions(self):
        old_detect = ganj_vps._detect_pasarguard_local_url
        old_ask = ganj_vps._ask
        old_getpass = ganj_vps.getpass.getpass
        old_yes_no = ganj_vps._yes_no
        prompts = []
        try:
            ganj_vps._detect_pasarguard_local_url = lambda: "http://127.0.0.1:9876"
            ganj_vps._ask = lambda prompt, default="": prompts.append(prompt) or "pedram"
            ganj_vps.getpass.getpass = lambda prompt: "secret"
            ganj_vps._yes_no = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("TLS verification must not be prompted in installer auto mode")
            )
            profile = ganj_vps._panel_connection_profile("pasarguard", True, auto_mode=True)
            self.assertEqual(profile["url"], "http://127.0.0.1:9876")
            self.assertEqual(profile["username"], "pedram")
            self.assertEqual(profile["password"], "secret")
            self.assertFalse(profile["verify_tls"])
            self.assertFalse(any("URL" in str(x) for x in prompts))
        finally:
            ganj_vps._detect_pasarguard_local_url = old_detect
            ganj_vps._ask = old_ask
            ganj_vps.getpass.getpass = old_getpass
            ganj_vps._yes_no = old_yes_no

    def test_pasarguard_auto_mode_keeps_core_inbound_host_manual(self):
        old_detect_panels = ganj_vps.detect_panels
        old_connection = ganj_vps._panel_connection_profile
        old_factory = ganj_vps.adapter_from_profile
        old_choose = ganj_vps._choose_index
        old_input = __import__("builtins").input
        old_panel = ganj_vps.PANEL_SECRET_FILE
        old_config = ganj_vps.CONFIG_FILE
        old_secret = ganj_vps.SECRET_FILE
        tmp = Path(tempfile.mkdtemp(prefix="ganj-installer-ux-"))
        prompts = []
        inputs = iter(["1", "2"])

        class FakeAdapter:
            def __init__(self, profile):
                self.profile = profile

            def login(self):
                return None

            def list_cores(self):
                return [{"index": 1, "id": 7, "name": "Main Core", "type": "xray"}]

            def discover(self):
                return {
                    "inbounds": [{
                        "index": 1, "tag": "manual-template", "port": 443,
                        "protocol": "vless", "listen": "*",
                    }],
                    "hosts": [{
                        "index": 1, "id": 55, "remark": "Template Host",
                        "inbound_tag": "manual-template", "port": 443,
                    }],
                }

            def status(self):
                return {
                    "type": "pasarguard", "inbounds": 1, "hosts": 1,
                    "managed_inbounds": 0,
                }

        def choose(prompt, rows, *args, **kwargs):
            prompts.append(prompt)
            return rows[0]

        try:
            ganj_vps.PANEL_SECRET_FILE = tmp / "panel.json"
            ganj_vps.CONFIG_FILE = tmp / "missing-agent.json"
            ganj_vps.SECRET_FILE = tmp / "missing-secret"
            ganj_vps.detect_panels = lambda: [{
                "type": "pasarguard", "name": "PasarGuard", "version": None, "detected": True,
            }]
            ganj_vps._panel_connection_profile = lambda kind, detected, auto_mode=False: {
                "type": "pasarguard",
                "url": "http://127.0.0.1:8000",
                "username": "admin",
                "password": "secret",
                "core_id": 1,
                "verify_tls": False,
            }
            ganj_vps.adapter_from_profile = lambda profile: FakeAdapter(profile)
            ganj_vps._choose_index = choose
            __import__("builtins").input = lambda prompt="": next(inputs)

            self.assertEqual(ganj_vps.configure_panel(auto_mode=True), 0)
            saved = ganj_vps.load_json(ganj_vps.PANEL_SECRET_FILE, {})
            self.assertEqual(saved["core_id"], 7)
            self.assertEqual(saved["template_inbound_tag"], "manual-template")
            self.assertEqual(saved["template_host_id"], 55)
            self.assertEqual(saved["host_port_mode"], "inbound")
            self.assertIn("Core list number", prompts)
            self.assertIn("Inbound list number", prompts)
        finally:
            ganj_vps.detect_panels = old_detect_panels
            ganj_vps._panel_connection_profile = old_connection
            ganj_vps.adapter_from_profile = old_factory
            ganj_vps._choose_index = old_choose
            __import__("builtins").input = old_input
            ganj_vps.PANEL_SECRET_FILE = old_panel
            ganj_vps.CONFIG_FILE = old_config
            ganj_vps.SECRET_FILE = old_secret


class LocationTests(unittest.TestCase):
    def test_top_locations_are_unique_and_curated(self):
        self.assertEqual(len(ganj_vps.TOP_LOCATIONS), 40)
        self.assertEqual(len(set(ganj_vps.TOP_LOCATIONS)), 40)
        self.assertIn("DE", ganj_vps.TOP_LOCATIONS)
        self.assertIn("US", ganj_vps.TOP_LOCATIONS)

        self.assertIn("BR", ganj_vps.TOP_LOCATIONS)
        self.assertIn("UA", ganj_vps.TOP_LOCATIONS)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["BR"], 6030)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["UA"], 6039)

    def test_location_map_keeps_unavailable_catalog_rows(self):
        rows = _location_map([
            {"country_code": "de", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "nl", "name": "Netherlands", "port": 1081, "enabled": False},
            {"country_code": "", "name": "Broken", "port": 1, "enabled": True},
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {
            "country_code": "DE", "name": "Germany", "city": "Berlin",
            "flag": "🇩🇪", "port": 1082, "enabled": True, "available": True,
        })
        self.assertEqual(rows[1], {
            "country_code": "NL", "name": "Netherlands", "city": "Amsterdam",
            "flag": "🇳🇱", "port": 1081, "enabled": False, "available": False,
        })

    def test_location_map_honors_central_availability(self):
        rows = _location_map([
            {
                "country_code": "BR",
                "name": "Brazil",
                "port": 1101,
                "enabled": True,
                "available": False,
            },
        ])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["enabled"])
        self.assertFalse(rows[0]["available"])

    def test_port_allocator_does_not_collide(self):
        used = {20000, 20002}
        self.assertEqual(_alloc_ports(used, 3, 20000), [20001, 20003, 20004])


    def test_collision_aware_block_skips_busy_range(self):
        old = panel_sync.system_listening_ports
        panel_sync.system_listening_ports = lambda: {20000}
        try:
            self.assertEqual(choose_port_block(set(), 3, 20000), [21000, 21001, 21002])
        finally:
            panel_sync.system_listening_ports = old


class PasarGuardGroupSyncTests(unittest.TestCase):
    def test_group_sync_mirrors_template_membership(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-groups-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 0, "base_port": 6000,
        })
        groups = [
            {
                "id": 1, "name": "VIP",
                "inbound_tags": ["template", "other-vip"],
                "is_disabled": False, "total_users": 4,
            },
            {
                "id": 2, "name": "Other",
                "inbound_tags": ["other-only"],
                "is_disabled": False, "total_users": 2,
            },
            {
                "id": 3, "name": "CIP",
                "inbound_tags": ["template"],
                "is_disabled": False, "total_users": 3,
            },
        ]
        adapter.get_groups = lambda: copy.deepcopy(groups)

        def update_group(payload):
            idx = next(i for i, row in enumerate(groups) if int(row["id"]) == int(payload["id"]))
            current = copy.deepcopy(groups[idx])
            current["name"] = payload["name"]
            current["inbound_tags"] = list(payload["inbound_tags"])
            current["is_disabled"] = bool(payload["is_disabled"])
            groups[idx] = current

        adapter.update_group = update_group
        snapshot = adapter.template_groups()
        result = adapter.sync_template_groups(
            {"ganj-de 🇩🇪 Germany — Berlin", "ganj-fr 🇫🇷 France — Paris"},
            snapshot,
        )

        vip = next(x for x in groups if x["id"] == 1)
        other = next(x for x in groups if x["id"] == 2)
        cip = next(x for x in groups if x["id"] == 3)
        for row in (vip, cip):
            self.assertIn("ganj-de 🇩🇪 Germany — Berlin", row["inbound_tags"])
            self.assertIn("ganj-fr 🇫🇷 France — Paris", row["inbound_tags"])
        self.assertNotIn("ganj-de 🇩🇪 Germany — Berlin", other["inbound_tags"])
        self.assertEqual(result["updated_groups"], [1, 3])
        self.assertTrue(result["verified"])

    def test_group_sync_is_idempotent(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-groups-idem-"))
        tag = "ganj-de 🇩🇪 Germany — Berlin"
        groups = [{
            "id": 1, "name": "VIP",
            "inbound_tags": ["template", tag],
            "is_disabled": False,
        }]
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 0, "base_port": 6000,
        })
        adapter.get_groups = lambda: copy.deepcopy(groups)
        calls = []
        adapter.update_group = lambda payload: calls.append(copy.deepcopy(payload))
        result = adapter.sync_template_groups({tag}, adapter.template_groups())
        self.assertEqual(calls, [])
        self.assertEqual(result["updated_groups"], [])
        self.assertTrue(result["verified"])


class PasarGuardShared443Tests(unittest.TestCase):
    def test_reality_inbound_gets_unique_shared_sni_and_host_443(self):
        inbound = {
            "tag": "ganj-de",
            "port": 6000,
            "protocol": "vless",
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "target": "www.aparat.com:443",
                    "serverNames": ["link.aparat.com"],
                },
            },
        }
        sni = panel_sync._apply_pasarguard_shared_sni(inbound, 6000)
        self.assertEqual(sni, "hs-6000.aparat.com")
        self.assertIn(
            "hs-6000.aparat.com",
            inbound["streamSettings"]["realitySettings"]["serverNames"],
        )
        host = panel_sync._clone_pasarguard_host(
            {
                "id": 77,
                "inbound_tag": "template",
                "port": 2053,
                "remark": "Template",
                "address": ["ganjvps.pedramhs.ir"],
                "sni": ["link.aparat.com"],
                "security": "inbound_default",
            },
            "ganj-de",
            6000,
            "Germany",
            public_sni=sni,
        )
        self.assertEqual(host["port"], 443)
        self.assertEqual(host["sni"], ["hs-6000.aparat.com"])
        self.assertEqual(host["address"], ["ganjvps.pedramhs.ir"])
        self.assertNotIn("id", host)

    def test_non_reality_host_keeps_local_public_port(self):
        inbound = {
            "tag": "ganj-de",
            "port": 6000,
            "protocol": "vless",
            "streamSettings": {"security": "none"},
        }
        self.assertIsNone(
            panel_sync._apply_pasarguard_shared_sni(inbound, 6000)
        )
        host = panel_sync._clone_pasarguard_host(
            {
                "id": 1,
                "inbound_tag": "template",
                "port": 2053,
                "sni": ["example.test"],
            },
            "ganj-de",
            6000,
            "Germany",
        )
        self.assertEqual(host["port"], 6000)
        self.assertEqual(host["sni"], ["example.test"])

    def test_haproxy_shared_sni_block_precedes_web_and_is_idempotent(self):
        base = """global
    daemon

defaults
    mode tcp

frontend ft_single_443
    mode tcp
    bind 0.0.0.0:443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    # BEGIN GANJ WEB SNI
    acl sni_ganj_web req.ssl_sni -i status.example.test
    use_backend be_ganj_web_tls if sni_ganj_web
    # END GANJ WEB SNI
    default_backend be_panel

backend be_panel
    mode tcp
"""
        rendered = panel_sync._insert_ganj_shared_sni_block(
            base,
            [6000, 6001],
        )
        self.assertIn(
            "acl sni_ganj_6000 req.ssl_sni -i hs-6000.aparat.com",
            rendered,
        )
        self.assertIn(
            "use_backend be_ganj_6001 if sni_ganj_6001",
            rendered,
        )
        self.assertLess(
            rendered.index(panel_sync._HAPROXY_SNI_BEGIN),
            rendered.index("# BEGIN GANJ WEB SNI"),
        )
        rendered2 = panel_sync._insert_ganj_shared_sni_block(
            rendered,
            [6000, 6001],
        )
        self.assertEqual(rendered2.count(panel_sync._HAPROXY_SNI_BEGIN), 1)

    @without_live_ports
    def test_reality_install_publishes_hosts_on_shared_443(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-443-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test",
            "password": "test",
            "core_id": 1,
            "template_inbound_tag": "template",
            "template_host_id": 77,
            "base_port": 6000,
        })
        adapter.login = lambda: None
        core = {
            "name": "main",
            "type": "xray",
            "exclude_inbound_tags": [],
            "fallbacks_inbound_tags": [],
            "config": {
                "inbounds": [{
                    "tag": "template",
                    "port": 2053,
                    "protocol": "vless",
                    "listen": "",
                    "settings": {},
                    "streamSettings": {
                        "security": "reality",
                        "realitySettings": {
                            "target": "www.aparat.com:443",
                            "serverNames": ["link.aparat.com"],
                        },
                    },
                }],
                "outbounds": [],
                "routing": {"rules": []},
            },
        }
        hosts = [{
            "id": 77,
            "remark": "Template Host",
            "inbound_tag": "template",
            "port": 2053,
            "address": ["ganjvps.pedramhs.ir"],
            "sni": ["link.aparat.com"],
            "security": "inbound_default",
        }]
        adapter.get_core = lambda: copy.deepcopy(core)
        adapter.get_hosts = lambda: copy.deepcopy(hosts)
        adapter.template_groups = lambda: []
        adapter.update_core = lambda old, cfg: core.update({"config": copy.deepcopy(cfg)})
        adapter.restart_core = lambda old, cfg: None
        adapter.delete_host = lambda host_id: hosts.__setitem__(
            slice(None),
            [x for x in hosts if int(x.get("id") or 0) != int(host_id)],
        )
        next_id = [100]
        def create_host(host):
            row = copy.deepcopy(host)
            row["id"] = next_id[0]
            next_id[0] += 1
            hosts.append(row)
        adapter.create_host = create_host

        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "NL", "name": "Netherlands", "port": 1081, "enabled": True},
        ])

        managed_hosts = [
            x for x in hosts
            if str(x.get("inbound_tag") or "").startswith("ganj-")
        ]
        self.assertEqual([x["port"] for x in managed_hosts], [443, 443])
        self.assertEqual(
            [x["sni"] for x in managed_hosts],
            [["hs-6000.aparat.com"], ["hs-6001.aparat.com"]],
        )
        managed_inbounds = [
            x for x in core["config"]["inbounds"]
            if str(x.get("tag") or "").startswith("ganj-")
        ]
        self.assertIn(
            "hs-6000.aparat.com",
            managed_inbounds[0]["streamSettings"]["realitySettings"]["serverNames"],
        )
        self.assertIn(
            "hs-6001.aparat.com",
            managed_inbounds[1]["streamSettings"]["realitySettings"]["serverNames"],
        )
        self.assertEqual(
            [x["public_port"] for x in result["installed"]],
            [443, 443],
        )


class PasarGuardGenerationTests(unittest.TestCase):
    def test_unrelated_flag_prefixed_objects_are_not_ganj_owned(self):
        self.assertIsNone(panel_sync._country_from_ganj_remark("🇩🇪 Personal"))
        self.assertIsNone(panel_sync._country_from_pasarguard_tag("🇩🇪 Personal"))
        self.assertEqual(panel_sync._country_from_ganj_remark("🇩🇪 Germany — Berlin"), "DE")
        self.assertEqual(panel_sync._country_from_pasarguard_tag("ganj-de"), "DE")

    def test_pasarguard_tag_is_namespaced_and_comma_safe(self):
        tag = panel_sync._pasarguard_location_tag({
            "country_code": "US",
            "name": "United States",
            "city": "Washington, D.C.",
            "flag": "🇺🇸",
        })
        self.assertTrue(tag.startswith("ganj-us "))
        self.assertNotIn(",", tag)
        self.assertTrue(panel_sync._is_ganj_pasarguard_owned_tag(tag))
        self.assertFalse(
            panel_sync._is_ganj_pasarguard_owned_tag("🇺🇸 United States")
        )

    def test_pasarguard_restart_disconnect_is_recovered_by_readback(self):
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 0, "base_port": 6000,
        })
        class BrokenSession:
            def put(self, *args, **kwargs):
                raise panel_sync.requests.ConnectionError("restart closed socket")
        adapter.s = BrokenSession()
        seen = []
        adapter._wait_core_after_restart = lambda cfg, timeout=75: seen.append(copy.deepcopy(cfg))
        core = {
            "name": "main", "type": "xray",
            "exclude_inbound_tags": [], "fallbacks_inbound_tags": [],
        }
        cfg = {"inbounds": [{"tag": "ganj-de", "port": 6000}]}
        adapter._put_core(core, cfg, restart_nodes=True)
        self.assertEqual(seen, [cfg])

    @without_live_ports
    def test_install_generates_only_ganj_owned_objects(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test",
            "password": "test",
            "core_id": 1,
            "template_inbound_tag": "template",
            "template_host_id": 0,
            "base_port": 21000,
        })
        adapter.login = lambda: None
        core = {
            "name": "main",
            "type": "xray",
            "exclude_inbound_tags": [],
            "fallbacks_inbound_tags": [],
            "config": {
                "inbounds": [{"tag": "template", "port": 443, "protocol": "vless", "settings": {}}],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "outboundTag": "direct"}]},
            },
        }
        adapter.get_core = lambda: core
        adapter.get_hosts = lambda: []
        adapter.template_groups = lambda: []
        captured = {}
        def apply_core(c, config):
            core["config"] = config
            captured["config"] = config
        adapter.update_core = apply_core
        adapter.restart_core = lambda c, config: None
        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "NL", "name": "Netherlands", "port": 1081, "enabled": True},
        ])
        cfg = captured["config"]
        self.assertEqual(len(result["installed"]), 2)
        tags = {x["tag"] for x in cfg["inbounds"]}
        self.assertIn("template", tags)
        self.assertIn("ganj-de 🇩🇪 Germany — Berlin", tags)
        self.assertIn("ganj-nl 🇳🇱 Netherlands — Amsterdam", tags)
        outbound_tags = {x["tag"] for x in cfg["outbounds"]}
        self.assertIn("direct", outbound_tags)
        self.assertIn("ganj-egress-de", outbound_tags)
        self.assertIn("ganj-egress-nl", outbound_tags)
        socks = next(x for x in cfg["outbounds"] if x["tag"] == "ganj-egress-de")
        self.assertEqual(socks["settings"]["servers"][0], {"address": "10.60.0.1", "port": 1082})


    @without_live_ports
    def test_unavailable_location_creates_safe_placeholder(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-placeholder-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 0, "base_port": 6000,
        })
        adapter.login = lambda: None
        core = {
            "name": "main", "type": "xray",
            "exclude_inbound_tags": [], "fallbacks_inbound_tags": [],
            "config": {
                "inbounds": [{"tag": "template", "port": 443, "protocol": "vless", "settings": {}}],
                "outbounds": [], "routing": {"rules": []},
            },
        }
        adapter.get_core = lambda: core
        adapter.get_hosts = lambda: []
        adapter.template_groups = lambda: []
        adapter.update_core = lambda c, config: core.update({"config": config})
        adapter.restart_core = lambda c, config: None
        result = adapter.install_locations([
            {"country_code": "NL", "name": "Netherlands", "port": 0, "enabled": False},
        ])
        placeholder = next(x for x in core["config"]["inbounds"] if x.get("tag") == "ganj-nl 🇳🇱 Netherlands — Amsterdam")
        self.assertEqual(placeholder["port"], 6001)
        outbound = next(x for x in core["config"]["outbounds"] if x.get("tag") == "ganj-egress-nl")
        self.assertEqual(outbound["protocol"], "blackhole")
        self.assertFalse(result["installed"][0]["available"])
        self.assertIsNone(result["installed"][0]["gateway_port"])


    @without_live_ports
    def test_host_clone_can_follow_generated_inbound_port(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-host-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test",
            "password": "test",
            "core_id": 1,
            "template_inbound_tag": "template",
            "template_host_id": 77,
            "base_port": 23000,
            "host_port_mode": "inbound",
        })
        adapter.login = lambda: None
        core = {
            "name": "main", "type": "xray",
            "exclude_inbound_tags": [], "fallbacks_inbound_tags": [],
            "config": {
                "inbounds": [{"tag": "template", "port": 443, "protocol": "vless", "settings": {}}],
                "outbounds": [], "routing": {"rules": []},
            },
        }
        hosts = [{
            "id": 77,
            "remark": "template host",
            "inbound_tag": "template",
            "port": 443,
            "address": ["ganjvps.pedramhs.ir"],
            "sni": ["link.aparat.com"],
            "security": "inbound_default",
            "fingerprint": "chrome",
            "status": ["on_hold", "active"],
            "priority": 11,
            "transport_settings": {"xhttp_settings": {"mode": "auto"}},
        }]
        adapter.get_core = lambda: core
        adapter.get_hosts = lambda: list(hosts)
        adapter.template_groups = lambda: []
        adapter.update_core = lambda c, config: core.update({"config": config})
        adapter.restart_core = lambda c, config: None
        def delete_host(host_id):
            hosts[:] = [x for x in hosts if int(x.get("id") or 0) != int(host_id)]
        adapter.delete_host = delete_host
        created_hosts = []
        next_id = [100]
        def create_host(host):
            row = host.copy()
            row["id"] = next_id[0]
            next_id[0] += 1
            hosts.append(row)
            created_hosts.append(row.copy())
        adapter.create_host = create_host
        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "NL", "name": "Netherlands", "port": 1081, "enabled": True},
        ])
        self.assertEqual([x["port"] for x in created_hosts], [6000, 6001])
        self.assertEqual(
            [x["inbound_tag"] for x in created_hosts],
            ["ganj-de 🇩🇪 Germany — Berlin", "ganj-nl 🇳🇱 Netherlands — Amsterdam"],
        )
        self.assertEqual(
            [x["remark"] for x in created_hosts],
            ["🇩🇪 Germany — Berlin", "🇳🇱 Netherlands — Amsterdam"],
        )
        template = hosts[0]
        for clone in created_hosts:
            for key, value in template.items():
                if key in {"id", "inbound_tag", "port", "remark"}:
                    continue
                self.assertEqual(clone.get(key), value, key)
        self.assertEqual(
            created_hosts[0]["address"], ["ganjvps.pedramhs.ir"]
        )
        self.assertEqual(created_hosts[0]["sni"], ["link.aparat.com"])
        self.assertEqual(created_hosts[0]["security"], "inbound_default")
        self.assertEqual(
            created_hosts[0]["transport_settings"],
            {"xhttp_settings": {"mode": "auto"}},
        )
        self.assertEqual(len(result["installed"]), 2)


    def test_repeated_pasarguard_plan_migrates_to_catalog_ports(self):
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 0, "base_port": 20000,
        })
        adapter.login = lambda: None
        adapter.get_core = lambda: {
            "name": "main", "type": "xray",
            "config": {
                "inbounds": [
                    {"tag": "template", "port": 443, "protocol": "vless"},
                    {"tag": "ganj-de", "port": 22010, "protocol": "vless"},
                    {"tag": "ganj-nl", "port": 22011, "protocol": "vless"},
                ],
                "outbounds": [], "routing": {"rules": []},
            },
        }
        adapter.get_hosts = lambda: []
        old = panel_sync.system_listening_ports
        panel_sync.system_listening_ports = lambda: {22010, 22011}
        try:
            plan = adapter.plan_locations([
                {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
                {"country_code": "NL", "name": "Netherlands", "port": 1081, "enabled": True},
            ])
        finally:
            panel_sync.system_listening_ports = old
        self.assertEqual([x["local_port"] for x in plan["items"]], [6000, 6001])


    def test_pasarguard_host_failure_restores_previous_core_and_hosts(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-rollback-test-"))
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "template",
            "template_host_id": 1, "base_port": 25000,
            "host_port_mode": "inbound",
        })
        adapter.login = lambda: None
        old_config = {
            "inbounds": [
                {"tag": "template", "port": 443, "protocol": "vless", "settings": {}},
                {"tag": "ganj-de", "port": 25100, "protocol": "vless", "settings": {}},
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "ganj-egress-de", "protocol": "socks", "settings": {"servers": [{"address": "10.60.0.1", "port": 1082}]}},
            ],
            "routing": {"rules": [{"type": "field", "inboundTag": ["ganj-de"], "outboundTag": "ganj-egress-de"}]},
        }
        core = {"name": "main", "type": "xray", "exclude_inbound_tags": [], "fallbacks_inbound_tags": [], "config": copy.deepcopy(old_config)}
        hosts = [
            {"id": 1, "remark": "Template", "inbound_tag": "template", "port": 443, "address": ["edge.test"]},
            {"id": 2, "remark": "GANJ DE · Germany", "inbound_tag": "ganj-de", "port": 25100, "address": ["edge.test"]},
        ]
        adapter.get_core = lambda: copy.deepcopy(core)
        adapter.get_hosts = lambda: copy.deepcopy(hosts)
        adapter.template_groups = lambda: []
        adapter.update_core = lambda c, config: core.update({"config": copy.deepcopy(config)})
        def delete_host(host_id):
            hosts[:] = [x for x in hosts if int(x.get("id") or 0) != int(host_id)]
        adapter.delete_host = delete_host
        fail_once = [True]
        next_id = [100]
        def create_host(host):
            if fail_once[0] and panel_sync._country_from_pasarguard_tag(str(host.get("inbound_tag") or "")) == "DE":
                fail_once[0] = False
                raise RuntimeError("simulated_host_failure")
            row = copy.deepcopy(host); row["id"] = next_id[0]; next_id[0] += 1
            hosts.append(row)
        adapter.create_host = create_host

        with self.assertRaises(RuntimeError):
            adapter.install_locations([
                {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
                {"country_code": "FR", "name": "France", "port": 1080, "enabled": True},
            ])

        self.assertEqual(core["config"], old_config)
        managed = [x for x in hosts if str(x.get("inbound_tag") or "").startswith("ganj-")]
        self.assertEqual(len(managed), 1)
        self.assertEqual(managed[0]["inbound_tag"], "ganj-de")
        self.assertEqual(managed[0]["port"], 25100)


class SanaeiGenerationTests(unittest.TestCase):
    @without_live_ports
    def test_install_generates_country_inbounds_and_routing(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-xui-test-"))
        adapter = SanaeiAdapter({
            "url": "http://127.0.0.1:2053",
            "username": "test", "password": "test",
            "template_inbound_id": 9, "base_port": 24000,
        })
        adapter.login = lambda: None
        inbounds = [{
            "id": 9, "remark": "template", "port": 443, "protocol": "vless",
            "listen": "", "enable": True, "settings": {}, "streamSettings": {}, "sniffing": {},
        }]
        adapter.list_inbounds = lambda: list(inbounds)
        next_id = [30]
        def add(payload):
            row = payload.copy()
            row["id"] = next_id[0]
            next_id[0] += 1
            inbounds.append(row)
        adapter.add_inbound = add
        adapter.delete_inbound = lambda inbound_id: None
        xray = {"outbounds": [{"tag": "direct", "protocol": "freedom"}], "routing": {"rules": []}}
        adapter.get_xray = lambda: (xray, "https://example.test/204")
        adapter.update_xray = lambda cfg, test_url: xray.update(cfg)
        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "FR", "name": "France", "port": 1080, "enabled": True},
        ])
        managed = [x for x in inbounds if panel_sync._country_from_ganj_remark(str(x.get("remark", "")))]
        self.assertEqual([x["port"] for x in managed], [6000, 6002])
        self.assertEqual(
            [x["remark"] for x in managed],
            ["🇩🇪 Germany — Berlin", "🇫🇷 France — Paris"],
        )
        self.assertEqual(len(result["installed"]), 2)
        tags = {x.get("tag") for x in xray["outbounds"]}
        self.assertIn("ganj-egress-de", tags)
        self.assertIn("ganj-egress-fr", tags)


    def test_repeated_sanaei_plan_migrates_to_catalog_ports(self):
        adapter = SanaeiAdapter({
            "url": "http://127.0.0.1:2053",
            "username": "test", "password": "test",
            "template_inbound_id": 9, "base_port": 20000,
        })
        adapter.login = lambda: None
        rows = [
            {"id": 9, "remark": "template", "port": 443, "protocol": "vless"},
            {"id": 30, "remark": "GANJ DE · Germany", "port": 22100, "protocol": "vless"},
            {"id": 31, "remark": "GANJ FR · France", "port": 22101, "protocol": "vless"},
        ]
        adapter.list_inbounds = lambda: rows
        old = panel_sync.system_listening_ports
        panel_sync.system_listening_ports = lambda: {22100, 22101}
        try:
            plan = adapter.plan_locations([
                {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
                {"country_code": "FR", "name": "France", "port": 1080, "enabled": True},
            ])
        finally:
            panel_sync.system_listening_ports = old
        self.assertEqual([x["local_port"] for x in plan["items"]], [6000, 6002])


    @without_live_ports
    def test_sanaei_resync_updates_existing_country_in_place(self):
        panel_sync.BACKUP_DIR = Path(tempfile.mkdtemp(prefix="ganj-vps-xui-resync-"))
        adapter = SanaeiAdapter({
            "url": "http://127.0.0.1:2053",
            "username": "test", "password": "test",
            "template_inbound_id": 9, "base_port": 20000,
        })
        adapter.login = lambda: None
        rows = [
            {"id": 9, "remark": "template", "port": 443, "protocol": "vless", "listen": "", "enable": True, "settings": {}, "streamSettings": {}, "sniffing": {}},
            {"id": 30, "remark": "GANJ DE · Germany", "port": 22100, "protocol": "vless", "listen": "", "enable": True, "settings": {}, "streamSettings": {}, "sniffing": {}, "tag": "inbound-30"},
        ]
        adapter.list_inbounds = lambda: copy.deepcopy(rows)
        def update_inbound(iid, payload):
            row = next(x for x in rows if int(x["id"]) == int(iid))
            tag = row.get("tag")
            row.update(copy.deepcopy(payload))
            if tag: row["tag"] = tag
        adapter.update_inbound = update_inbound
        next_id = [31]
        def add_inbound(payload):
            row = copy.deepcopy(payload); row["id"] = next_id[0]; row["tag"] = f"inbound-{next_id[0]}"; next_id[0] += 1; rows.append(row)
        adapter.add_inbound = add_inbound
        adapter.delete_inbound = lambda iid: rows.__setitem__(slice(None), [x for x in rows if int(x.get("id") or 0) != int(iid)])
        xray = {"outbounds": [{"tag": "direct", "protocol": "freedom"}], "routing": {"rules": []}}
        adapter.get_xray = lambda: (copy.deepcopy(xray), "https://example.test/204")
        adapter.update_xray = lambda cfg, test_url: xray.clear() or xray.update(copy.deepcopy(cfg))

        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "FR", "name": "France", "port": 1080, "enabled": True},
        ])
        de = next(x for x in rows if panel_sync._country_from_ganj_remark(str(x.get("remark",""))) == "DE")
        fr = next(x for x in rows if panel_sync._country_from_ganj_remark(str(x.get("remark",""))) == "FR")
        self.assertEqual(de["id"], 30)
        self.assertEqual(de["port"], 6000)
        self.assertEqual(fr["port"], 6002)
        self.assertEqual(len(result["installed"]), 2)


    @without_live_ports
    def test_requested_public_names_and_ports(self):
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["DE"], 6000)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["NL"], 6001)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["FR"], 6002)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["GB"], 6003)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["US"], 6022)
        self.assertLessEqual(max(panel_sync.PREFERRED_LOCAL_PORTS.values()), 6039)
        self.assertEqual(panel_sync.DISPLAY_LABELS["FR"], "🇫🇷 France — Paris")
        self.assertEqual(panel_sync.DISPLAY_LABELS["NL"], "🇳🇱 Netherlands — Amsterdam")
        self.assertEqual(panel_sync.DISPLAY_LABELS["DE"], "🇩🇪 Germany — Berlin")
        self.assertEqual(panel_sync.DISPLAY_LABELS["US"], "🇺🇸 United States — Washington, D.C.")
        self.assertEqual(panel_sync.DISPLAY_LABELS["GB"], "🇬🇧 United Kingdom — London")

    def test_sanaei_does_not_claim_unrelated_flag_remark(self):
        adapter = SanaeiAdapter({
            "url": "http://127.0.0.1:2053",
            "username": "test", "password": "test",
            "template_inbound_id": 9, "base_port": 6000,
        })
        adapter.login = lambda: None
        adapter.list_inbounds = lambda: [
            {"id": 9, "remark": "template", "port": 443, "protocol": "vless"},
            {"id": 10, "remark": "🇩🇪 Personal", "port": 6500, "protocol": "vless"},
            {"id": 11, "remark": "🇩🇪 Germany — Berlin", "port": 6000, "protocol": "vless"},
        ]
        adapter.get_xray = lambda: ({"outbounds": [], "routing": {"rules": []}}, "https://example.test/204")
        status = adapter.managed_status()
        self.assertEqual(status["managed_inbounds"], 1)
        self.assertEqual(status["managed_ports"], [6000])

    def test_non_vless_template_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "template_protocol_must_be_vless"):
            panel_sync._require_vless({"protocol": "trojan"})


class DedicatedTemplateSafetyTests(unittest.TestCase):
    def test_pasarguard_refuses_ganj_managed_inbound_as_template(self):
        adapter = PasarGuardAdapter({
            "url": "http://127.0.0.1:8000",
            "username": "test", "password": "test",
            "core_id": 1, "template_inbound_tag": "ganj-de",
            "template_host_id": 0, "base_port": 20000,
        })
        adapter.login = lambda: None
        adapter.get_core = lambda: {
            "name": "main", "type": "xray",
            "config": {
                "inbounds": [{"tag": "ganj-de", "port": 22000, "protocol": "vless"}],
                "outbounds": [], "routing": {"rules": []},
            },
        }
        adapter.get_hosts = lambda: []
        with self.assertRaisesRegex(RuntimeError, "dedicated_non_ganj"):
            adapter.plan_locations([
                {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            ])

    def test_sanaei_refuses_ganj_managed_inbound_as_template(self):
        adapter = SanaeiAdapter({
            "url": "http://127.0.0.1:2053",
            "username": "test", "password": "test",
            "template_inbound_id": 30, "base_port": 20000,
        })
        adapter.login = lambda: None
        adapter.list_inbounds = lambda: [
            {"id": 30, "remark": "GANJ DE · Germany", "port": 22100, "protocol": "vless"},
        ]
        with self.assertRaisesRegex(RuntimeError, "dedicated_non_ganj"):
            adapter.plan_locations([
                {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            ])


if __name__ == "__main__":
    unittest.main()
