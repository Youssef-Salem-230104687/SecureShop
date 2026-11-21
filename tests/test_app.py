import sqlite3
import unittest
from pathlib import Path

from app import app
from init_db import init_db


class SecureShopTest(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).resolve().parent / f"test_{self.id().rsplit('.', 1)[-1]}.db"
        init_db(self.db_path)
        app.config.update(TESTING=True, DATABASE_PATH=str(self.db_path), SECRET_KEY="test-secret")
        self.client = app.test_client()

    def token(self):
        self.client.get("/")
        with self.client.session_transaction() as state:
            return state["csrf_token"]

    def post(self, url, data=None, **kwargs):
        payload = {"csrf_token": self.token()}
        payload.update(data or {})
        return self.client.post(url, data=payload, **kwargs)

    def login(self, username="alice", password="alice-demo-pass"):
        return self.post("/login", {"username": username, "password": password}, follow_redirects=True)

    def test_catalog_search_and_empty_state(self):
        self.assertIn(b"Wireless Headphones", self.client.get("/products").data)
        self.assertIn(b"No products found", self.client.get("/products?q=nothing-here").data)

    def test_registration_confirmation_and_login(self):
        response = self.post("/register", {"username": "new-user", "email": "new@example.test", "password": "longpassword1"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.db_path) as conn:
            code, stored = conn.execute("SELECT verification_code,password_hash FROM users WHERE username='new-user'").fetchone()
        self.assertNotEqual(stored, "longpassword1")
        self.assertIn(":", stored)
        response = self.post("/verify", {"email": "new@example.test", "code": code}, follow_redirects=True)
        self.assertIn(b"You can now sign in", response.data)
        self.assertIn(b"Welcome back, new-user", self.login("new-user", "longpassword1").data)

    def test_checkout_uses_server_prices_credit_stock_and_coupon(self):
        self.login()
        self.post("/cart/add", {"product_id": 1, "quantity": 2})
        # The submitted price field is ignored; only database pricing may be charged.
        response = self.post("/checkout", {"coupon": "WELCOME10", "total": "-9999", "unit_price": "-9999"}, follow_redirects=True)
        self.assertIn(b"Order #1", response.data)
        with sqlite3.connect(self.db_path) as conn:
            total, coupon = conn.execute("SELECT total_amount,coupon_used FROM orders").fetchone()
            stock = conn.execute("SELECT stock FROM products WHERE id=1").fetchone()[0]
            credit = conn.execute("SELECT store_credit FROM users WHERE username='alice'").fetchone()[0]
        self.assertEqual((round(total, 2), coupon, stock, round(credit, 2)), (161.98, "WELCOME10", 8, 338.02))

    def test_access_controls_csrf_and_private_orders(self):
        # CSRF rejection happens before credentials are inspected.
        self.assertEqual(self.client.post("/login", data={"username": "alice"}).status_code, 400)
        self.assertEqual(self.client.get("/admin/users").status_code, 302)
        self.login()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)", (3, 10, "", "paid", "2026-01-01T00:00:00+00:00"))
            conn.commit()
        self.assertEqual(self.client.get("/orders/1").status_code, 404)
        self.assertEqual(self.client.get("/download?name=../sample_private.txt").status_code, 404)

    def test_newsletter_issues_assigned_coupon_and_admin_can_manage(self):
        response = self.post("/newsletter", {"email": "person@example.test"}, follow_redirects=True)
        self.assertIn(b"10% welcome coupon", response.data)
        with sqlite3.connect(self.db_path) as conn:
            code, assigned = conn.execute("SELECT code,assigned_email FROM coupons WHERE assigned_email='person@example.test'").fetchone()
        self.assertTrue(code.startswith("NEWS"))
        self.assertEqual(assigned, "person@example.test")
        self.login("admin", "admin123secure")
        response = self.post("/admin/products", {"name": "Desk Lamp", "description": "Warm light", "price": "25", "stock": "4"}, follow_redirects=True)
        self.assertIn(b"Product created", response.data)
        self.assertIn(b"Desk Lamp", self.client.get("/admin/products").data)


if __name__ == "__main__":
    unittest.main()
