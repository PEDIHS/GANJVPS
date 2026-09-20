import tempfile
import unittest
from pathlib import Path

from starlette.requests import Request

import central.app as central


def fake_request(ip: str) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-real-ip", ip.encode())],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "query_string": b"",
    })


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

    def test_node_auth_is_bound_to_enrollment_ip(self):
        rep_id, _ = central.issue_representative_token("Bound Rep", 5000, None, None)
        now = central.now_ts()
        secret = "s" * 40
        with central.db() as conn:
            conn.execute(
                """INSERT INTO nodes
                   (id,representative_id,name,bound_ip,fingerprint,secret_hash,wg_public_key,wg_ip,status,
                    last_seen_at,last_rx_bytes,last_tx_bytes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "bound-node", rep_id, "panel", "198.51.100.10", "a" * 64,
                    central.hash_secret(secret), "pub", "10.60.0.20/32", "online",
                    now, 0, 0, now, now,
                ),
            )
        row = central.authenticate_node(
            "bound-node", "Bearer " + secret, fake_request("198.51.100.10"), "a" * 64
        )
        self.assertEqual(row["id"], "bound-node")
        with self.assertRaises(central.HTTPException) as ctx:
            central.authenticate_node(
                "bound-node", "Bearer " + secret, fake_request("203.0.113.20"), "a" * 64
            )
        self.assertEqual(ctx.exception.status_code, 403)
        with central.db() as conn:
            node = conn.execute("SELECT * FROM nodes WHERE id='bound-node'").fetchone()
        self.assertEqual(node["status"], "ip_mismatch")

    def test_rotate_burns_old_token_and_preserves_representative_subscription(self):
        expiry = central.now_ts() + 86400
        rep_id, _ = central.issue_representative_token("Rotate Rep", 9999, expiry, None)
        now = central.now_ts()
        old_peer = central.wg_peer_apply
        central.wg_peer_apply = lambda *args, **kwargs: None
        try:
            with central.db() as conn:
                token = conn.execute(
                    "SELECT * FROM enrollment_tokens WHERE representative_id=?",
                    (rep_id,),
                ).fetchone()
                conn.execute(
                    """INSERT INTO nodes
                       (id,representative_id,name,bound_ip,fingerprint,secret_hash,wg_public_key,wg_ip,status,
                        last_seen_at,last_rx_bytes,last_tx_bytes,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        "old-node", rep_id, "panel", "198.51.100.10", "b" * 64,
                        central.hash_secret("z" * 40), "old-pub", "10.60.0.21/32", "online",
                        now, 0, 0, now, now,
                    ),
                )
                conn.execute(
                    "UPDATE enrollment_tokens SET status='used',used_at=?,node_id=? WHERE id=?",
                    (now, "old-node", token["id"]),
                )
                conn.execute(
                    "UPDATE representatives SET traffic_used_bytes=4321 WHERE id=?",
                    (rep_id,),
                )

            raw = central.rotate_representative_token(rep_id, 3600)
            self.assertTrue(raw.startswith("GANJ-"))
            with central.db() as conn:
                rep = conn.execute("SELECT * FROM representatives WHERE id=?", (rep_id,)).fetchone()
                node = conn.execute("SELECT * FROM nodes WHERE id='old-node'").fetchone()
                tokens = conn.execute(
                    "SELECT * FROM enrollment_tokens WHERE representative_id=? ORDER BY issued_at,id",
                    (rep_id,),
                ).fetchall()
            self.assertEqual(rep["traffic_limit_bytes"], 9999)
            self.assertEqual(rep["traffic_used_bytes"], 4321)
            self.assertEqual(rep["expires_at"], expiry)
            self.assertEqual(node["status"], "revoked")
            self.assertEqual(len(tokens), 2)
            self.assertEqual(tokens[0]["status"], "revoked")
            self.assertEqual(tokens[1]["status"], "pending")
            self.assertEqual(tokens[1]["token_hash"], central.hash_secret(raw))
        finally:
            central.wg_peer_apply = old_peer

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
