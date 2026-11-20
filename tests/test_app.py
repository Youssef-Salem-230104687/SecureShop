import sqlite3
import unittest
from pathlib import Path

from init_db import DB_PATH, init_db
from app import app


class SecureShopTest(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).resolve().parent / f"test_{self.id().rsplit('.', 1)[-1]}.db"
        init_db(self.db_path)
        app.config.update(TESTING=True, DATABASE_PATH=self.db_path)
        self.client = app.test_client()

    def login(self, username="alice", password="alice-demo-pass"):
        return self.client.post("/login", data={"username": username, "password": password, "role": "user"}, follow_redirects=True)

    def test_catalog_renders(self):
        response = self.client.get("/products")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Wireless Headphones", response.data)

    def test_sqli_login_bypasses_password(self):
        response = self.client.post("/login", data={"username": "alice' -- ", "password": "wrong", "role": "user"}, follow_redirects=True)
        self.assertIn(b"Welcome back", response.data)

    def test_idor_order_read(self):
        self.login()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status) VALUES (?,?,?,?)", (3, 10, "", "created"))
        response = self.client.get("/orders/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"bob", response.data)

    def test_client_price_is_stored(self):
        self.login()
        self.client.post("/checkout", data={"product_id": 1, "quantity": 1, "unit_price": -50, "discount": 0, "coupon": ""})
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT total_amount FROM orders ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual(total, -50)

    def test_path_traversal_reads_synthetic_parent_file(self):
        response = self.client.get("/download?name=../sample_private.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SYNTHETIC LOCAL TEST FILE", response.data)
        response.close()


if __name__ == "__main__":
    unittest.main()
