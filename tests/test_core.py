import unittest

import ganj_vps
from panel_sync import _alloc_ports, _location_map, PasarGuardAdapter


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


class PasarGuardGenerationTests(unittest.TestCase):
    def test_install_generates_only_ganj_owned_objects(self):
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
        adapter.update_core = lambda c, config: captured.update({"config": config})
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


if __name__ == "__main__":
    unittest.main()
