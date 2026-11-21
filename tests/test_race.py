import sqlite3
import threading
import unittest
from pathlib import Path

from app import app
from init_db import init_db


class CouponRaceTest(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).resolve().parent / "coupon_race.db"
        init_db(self.db_path)
        app.config.update(TESTING=True, DATABASE_PATH=str(self.db_path), SECRET_KEY="race-secret")

    def _checkout(self, results):
        client = app.test_client()
        client.get("/")
        with client.session_transaction() as state:
            token = state["csrf_token"]
        client.post("/login", data={"csrf_token": token, "username": "alice", "password": "alice-demo-pass"})
        with client.session_transaction() as state:
            token = state["csrf_token"]
        client.post("/cart/add", data={"csrf_token": token, "product_id": 1, "quantity": 1})
        response = client.post("/checkout", data={"csrf_token": token, "coupon": "WELCOME10"})
        results.append(response.status_code)

    def test_single_use_coupon_can_only_discount_one_concurrent_order(self):
        results = []
        threads = [threading.Thread(target=self._checkout, args=(results,)) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        with sqlite3.connect(self.db_path) as conn:
            usage, used = conn.execute("SELECT usage_count,is_used FROM coupons WHERE code='WELCOME10'").fetchone()
            discounted = conn.execute("SELECT COUNT(*) FROM orders WHERE coupon_used='WELCOME10'").fetchone()[0]
        self.assertEqual((usage, used, discounted), (1, 1, 1))
        # One request redirects to its confirmation; the other stays on checkout with feedback.
        self.assertEqual(sorted(results), [200, 302])


if __name__ == "__main__":
    unittest.main()
