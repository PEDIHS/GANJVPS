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
        self.assertEqual([x["port"] for x in created_hosts], [4443, 2443])
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
        adapter.update_core = lambda c, config: core.update({"config": copy.deepcopy(config)})
        def delete_host(host_id):
            hosts[:] = [x for x in hosts if int(x.get("id") or 0) != int(host_id)]
        adapter.delete_host = delete_host
        fail_once = [True]
        next_id = [100]
        def create_host(host):
            if fail_once[0] and str(host.get("inbound_tag") or "") == "ganj-de":
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
        self.assertEqual([x["port"] for x in managed], [4443, 1443])
        self.assertEqual([x["remark"] for x in managed], ["🇩🇪 Germany", "🇫🇷 France dc"])
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
        self.assertEqual(de["port"], 22100)
        self.assertEqual(fr["port"], 20000)
        self.assertEqual(len(result["installed"]), 2)


    @without_live_ports
    def test_requested_public_names_and_ports(self):
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["FR"], 1443)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["NL"], 2443)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["GB"], 3443)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["DE"], 4443)
        self.assertEqual(panel_sync.PREFERRED_LOCAL_PORTS["US"], 9443)
        self.assertEqual(panel_sync.DISPLAY_LABELS["FR"], "🇫🇷 France dc")
        self.assertEqual(panel_sync.DISPLAY_LABELS["NL"], "🇳🇱 The Netherlands")
        self.assertEqual(panel_sync.DISPLAY_LABELS["DE"], "🇩🇪 Germany")
        self.assertEqual(panel_sync.DISPLAY_LABELS["US"], "🇺🇸 United States")
        self.assertEqual(panel_sync.DISPLAY_LABELS["GB"], "🇬🇧 United Kingdom")

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
