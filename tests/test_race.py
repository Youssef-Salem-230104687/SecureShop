import http.cookiejar
import sqlite3
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from werkzeug.serving import make_server

from app import app
from init_db import init_db


class CouponRaceTest(unittest.TestCase):
    """Uses two simultaneous localhost HTTP requests, not a simulated sequential race."""
    def setUp(self):
        self.db_path = Path(__file__).resolve().parent / "coupon_race.db"
        init_db(self.db_path)
        app.config.update(TESTING=False, DATABASE_PATH=self.db_path)
        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()

    def test_single_use_coupon_redeemed_twice_concurrently(self):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        login = urllib.parse.urlencode({"username": "alice", "password": "alice-demo-pass", "role": "user"}).encode()
        opener.open(urllib.request.Request(self.base_url + "/login", login)).read()
        cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
        body = urllib.parse.urlencode({"product_id": 1, "quantity": 1, "unit_price": 89.99, "coupon": "WELCOME10", "discount": 10}).encode()
        statuses = []

        def redeem():
            request = urllib.request.Request(self.base_url + "/checkout", body, headers={"Cookie": cookie})
            try:
                statuses.append(urllib.request.urlopen(request).status)
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)

        first, second = threading.Thread(target=redeem), threading.Thread(target=redeem)
        first.start(); second.start(); first.join(); second.join()
        with sqlite3.connect(self.db_path) as conn:
            usage_count, is_used = conn.execute("SELECT usage_count,is_used FROM coupons WHERE code='WELCOME10'").fetchone()
            orders = conn.execute("SELECT COUNT(*) FROM orders WHERE coupon_used='WELCOME10'").fetchone()[0]
        self.assertEqual(statuses, [200, 200])
        self.assertEqual((usage_count, is_used, orders), (2, 1, 2))


if __name__ == "__main__":
    unittest.main()
