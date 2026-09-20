import tempfile
import unittest
from pathlib import Path

import ganj_vps
import panel_sync
from panel_sync import _alloc_ports, _location_map, choose_port_block, PasarGuardAdapter, SanaeiAdapter


class LocationTests(unittest.TestCase):
    def test_top_locations_are_unique_and_curated(self):
        self.assertEqual(len(ganj_vps.TOP_LOCATIONS), 30)
        self.assertEqual(len(set(ganj_vps.TOP_LOCATIONS)), 30)
        self.assertIn("DE", ganj_vps.TOP_LOCATIONS)
        self.assertIn("US", ganj_vps.TOP_LOCATIONS)

    def test_location_map_filters_disabled_and_bad_rows(self):
        rows = _location_map([
            {"country_code": "de", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "nl", "name": "Netherlands", "port": 1081, "enabled": False},
            {"country_code": "", "name": "Broken", "port": 1, "enabled": True},
        ])
        self.assertEqual(rows, [{"country_code": "DE", "name": "Germany", "flag": "", "port": 1082}])

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


class PasarGuardGenerationTests(unittest.TestCase):
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
        captured = {}
        def apply_core(c, config):
            core["config"] = config
            captured["config"] = config
        adapter.update_core = apply_core
        result = adapter.install_locations([
            {"country_code": "DE", "name": "Germany", "port": 1082, "enabled": True},
            {"country_code": "NL", "name": "Netherlands", "port": 1081, "enabled": True},
        ])
        cfg = captured["config"]
        self.assertEqual(len(result["installed"]), 2)
        tags = {x["tag"] for x in cfg["inbounds"]}
        self.assertIn("template", tags)
        self.assertIn("ganj-de", tags)
        self.assertIn("ganj-nl", tags)
        outbound_tags = {x["tag"] for x in cfg["outbounds"]}
        self.assertIn("direct", outbound_tags)
        self.assertIn("ganj-egress-de", outbound_tags)
        self.assertIn("ganj-egress-nl", outbound_tags)
        socks = next(x for x in cfg["outbounds"] if x["tag"] == "ganj-egress-de")
        self.assertEqual(socks["settings"]["servers"][0], {"address": "10.60.0.1", "port": 1082})


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
        hosts = [{"id": 77, "remark": "template host", "inbound_tag": "template", "port": 443, "address": ["edge.test"], "priority": 0}]
        adapter.get_core = lambda: core
        adapter.get_hosts = lambda: list(hosts)
        adapter.update_core = lambda c, config: core.update({"config": config})
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
        self.assertEqual([x["port"] for x in created_hosts], [23000, 23001])
        self.assertEqual([x["inbound_tag"] for x in created_hosts], ["ganj-de", "ganj-nl"])
        self.assertEqual(len(result["installed"]), 2)


    def test_repeated_pasarguard_plan_preserves_existing_country_ports(self):
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
        self.assertEqual([x["local_port"] for x in plan["items"]], [22010, 22011])


class SanaeiGenerationTests(unittest.TestCase):
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
        managed = [x for x in inbounds if str(x.get("remark", "")).startswith("GANJ ")]
        self.assertEqual([x["port"] for x in managed], [24000, 24001])
        self.assertEqual(len(result["installed"]), 2)
        tags = {x.get("tag") for x in xray["outbounds"]}
        self.assertIn("ganj-egress-de", tags)
        self.assertIn("ganj-egress-fr", tags)


    def test_repeated_sanaei_plan_preserves_existing_country_ports(self):
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
        self.assertEqual([x["local_port"] for x in plan["items"]], [22100, 22101])


if __name__ == "__main__":
    unittest.main()
