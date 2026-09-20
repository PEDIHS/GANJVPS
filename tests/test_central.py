import tempfile
import unittest
from pathlib import Path

import central.app as central


class CentralRepresentativeTests(unittest.TestCase):
    def setUp(self):
        self.old_db = central.DB_PATH
        central.DB_PATH = Path(tempfile.mkdtemp(prefix="ganj-central-test-")) / "central.db"
        central.init_db()

    def tearDown(self):
        central.DB_PATH = self.old_db

    def test_issue_token_keeps_only_hash_and_exposes_representative_status(self):
        rep_id, raw = central.issue_representative_token(
            "Representative A",
            50 * 1024**3,
            central.now_ts() + 86400,
            central.now_ts() + 3600,
        )
        self.assertTrue(raw.startswith("GANJ-"))
        with central.db() as conn:
            token = conn.execute(
                "SELECT * FROM enrollment_tokens WHERE representative_id=?",
                (rep_id,),
            ).fetchone()
            self.assertNotEqual(token["token_hash"], raw)
            self.assertEqual(token["token_hash"], central.hash_secret(raw))
            rows = central.representative_rows(conn)
        self.assertEqual(rows[0]["name"], "Representative A")
        self.assertEqual(rows[0]["token_status"], "pending")
        self.assertTrue(rows[0]["license_active"])
        self.assertEqual(rows[0]["traffic_limit_bytes"], 50 * 1024**3)

    def test_usage_is_delta_based_and_survives_counter_reset(self):
        rep_id, _ = central.issue_representative_token("Representative B", 10000, None, None)
        now = central.now_ts()
        with central.db() as conn:
            conn.execute(
                """INSERT INTO nodes
                   (id,representative_id,name,secret_hash,wg_public_key,wg_ip,status,last_seen_at,last_rx_bytes,last_tx_bytes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("node-1", rep_id, "panel", central.hash_secret("secret"), "pub", "10.60.0.10/32", "online", now, 0, 0, now, now),
            )
            node = conn.execute("SELECT * FROM nodes WHERE id='node-1'").fetchone()
            self.assertEqual(central.record_usage(conn, node, {"rx_bytes": 100, "tx_bytes": 50}), 150)
            node = conn.execute("SELECT * FROM nodes WHERE id='node-1'").fetchone()
            self.assertEqual(central.record_usage(conn, node, {"rx_bytes": 160, "tx_bytes": 90}), 100)
            node = conn.execute("SELECT * FROM nodes WHERE id='node-1'").fetchone()
            self.assertEqual(central.record_usage(conn, node, {"rx_bytes": 10, "tx_bytes": 5}), 15)
            rep = conn.execute("SELECT * FROM representatives WHERE id=?", (rep_id,)).fetchone()
            self.assertEqual(rep["traffic_used_bytes"], 265)

    def test_quota_and_expiry_are_independent_from_one_time_token(self):
        rep_id, _ = central.issue_representative_token("Representative C", 100, None, None)
        with central.db() as conn:
            conn.execute(
                "UPDATE representatives SET traffic_used_bytes=100 WHERE id=?",
                (rep_id,),
            )
            rep = conn.execute("SELECT * FROM representatives WHERE id=?", (rep_id,)).fetchone()
            active, reason = central.license_state(rep)
        self.assertFalse(active)
        self.assertEqual(reason, "quota_exceeded")

    def test_dashboard_uses_representative_language_and_usage_fields(self):
        rep_id, _ = central.issue_representative_token("نماینده تست", 1024**3, None, None)
        with central.db() as conn:
            rows = central.representative_rows(conn)
        rendered = central.representatives_table(rows)
        self.assertIn("نماینده", rendered)
        self.assertIn("مصرف", rendered)
        self.assertIn("محدودیت", rendered)
        self.assertNotIn(">Nodes<", rendered)


if __name__ == "__main__":
    unittest.main()
