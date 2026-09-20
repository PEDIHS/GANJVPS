import unittest

import ganj_vps
from panel_sync import _alloc_ports, _location_map


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


if __name__ == "__main__":
    unittest.main()
