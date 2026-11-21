import hmac
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from werkzeug.security import generate_password_hash

from app import app, safe_redirect_url, check_ip_rate_limit, _login_ip_attempts
from init_db import init_db


class SecureShopSecurityTests(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).resolve().parent / f"test_sec_{self.id().rsplit('.', 1)[-1]}.db"
        init_db(self.db_path)
        app.config.update(
            TESTING=True,
            DATABASE_PATH=str(self.db_path),
            SECRET_KEY="test-security-secret-key-32byteslong!",
        )
        self.client = app.test_client()
        _login_ip_attempts.clear()

    def tearDown(self):
        if self.db_path.exists():
            try:
                self.db_path.unlink()
            except PermissionError:
                pass

    def get_csrf(self):
        self.client.get("/")
        with self.client.session_transaction() as sess:
            return sess.get("csrf_token", "")

    def post_with_csrf(self, url, data=None, **kwargs):
        payload = {"csrf_token": self.get_csrf()}
        if data:
            payload.update(data)
        return self.client.post(url, data=payload, **kwargs)

    def login(self, username="alice", password="alice-demo-pass"):
        return self.post_with_csrf("/login", {"username": username, "password": password}, follow_redirects=True)

    # ==========================================
    # A. SQL INJECTION (SQLi)
    # ==========================================
    def test_sqli_login_bypass_attempt(self):
        """Attacking login with SQL injection payloads must fail to authenticate."""
        payloads = [
            "alice' --",
            "' OR '1'='1",
            "admin' /*",
            "admin' or 1=1--",
            "' UNION SELECT 1, 'admin', 'admin@example.test', 'pbkdf2:dummy', 'admin', 1, NULL, 1000, 0, '', 0, NULL, NULL --",
        ]
        for payload in payloads:
            resp = self.post_with_csrf("/login", {"username": payload, "password": "wrongpassword"}, follow_redirects=True)
            self.assertIn(b"Invalid credentials", resp.data)
            with self.client.session_transaction() as sess:
                self.assertIsNone(sess.get("user_id"), f"Session user_id should be None for payload: {payload}")

    def test_sqli_product_search(self):
        """Attacking search query with SQL injection payloads must return safe parameterized results."""
        resp = self.client.get("/products?q=' OR 1=1 --")
        self.assertEqual(resp.status_code, 200)
        # Should not dump all products or crash with syntax error
        self.assertIn(b"No products found", resp.data)

        # UNION injection attempt
        resp_union = self.client.get("/products?q=' UNION SELECT id,username,email,password_hash,role,is_verified,store_credit,failed_attempts,device_id,0,NULL,NULL FROM users --")
        self.assertEqual(resp_union.status_code, 200)
        self.assertNotIn(b"admin@example.test", resp_union.data)

    # ==========================================
    # B. CROSS-SITE SCRIPTING (XSS)
    # ==========================================
    def test_stored_xss_product_review(self):
        """Stored XSS in product reviews must be HTML escaped."""
        self.login("alice", "alice-demo-pass")
        xss_payload = "<script>alert('XSS-STORED')</script><img src=x onerror=alert(1)>"
        resp = self.post_with_csrf("/product/1/review", {"body": xss_payload}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"<script>alert('XSS-STORED')</script>", resp.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;XSS-STORED&#39;)&lt;/script&gt;", resp.data)

    def test_reflected_xss_search_query(self):
        """Reflected XSS in search query parameter must be HTML escaped."""
        xss_query = '"><script>alert("XSS")</script>'
        resp = self.client.get(f"/products?q={xss_query}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b'"><script>alert("XSS")</script>', resp.data)
        self.assertNotIn(b'<script>', resp.data)
        self.assertIn(b"&lt;script&gt;alert(", resp.data)

    # ==========================================
    # C. CROSS-SITE REQUEST FORGERY (CSRF)
    # ==========================================
    def test_csrf_missing_token_rejected(self):
        """POST without CSRF token must be rejected with 400 Bad Request."""
        resp = self.client.post("/login", data={"username": "alice", "password": "alice-demo-pass"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Request could not be completed", resp.data)

    def test_csrf_invalid_token_rejected(self):
        """POST with forged CSRF token must be rejected with 400 Bad Request."""
        self.client.get("/")
        resp = self.client.post("/login", data={"username": "alice", "password": "alice-demo-pass", "csrf_token": "forged-token-abc"})
        self.assertEqual(resp.status_code, 400)

    def test_csrf_protects_all_state_changing_endpoints(self):
        """Every sensitive state-changing endpoint must reject requests without CSRF tokens."""
        endpoints = [
            ("/register", {"username": "attacker", "email": "att@evil.test", "password": "Password123"}),
            ("/verify", {"email": "alice@example.test", "code": "somecode"}),
            ("/cart/add", {"product_id": 1, "quantity": 1}),
            ("/cart/update", {"qty_1": 5}),
            ("/cart/remove", {"product_id": 1}),
            ("/checkout", {"coupon": ""}),
            ("/newsletter", {"email": "spam@evil.test"}),
            ("/logout", {}),
            ("/profile", {"username": "alice_mod", "email": "alice_mod@test.test"}),
            ("/admin/products", {"name": "Hacked", "description": "Hacked", "price": "10", "stock": "5"}),
        ]
        for url, data in endpoints:
            resp = self.client.post(url, data=data)
            self.assertEqual(resp.status_code, 400, f"Endpoint {url} failed to enforce CSRF")

    # ==========================================
    # D. BROKEN ACCESS CONTROL AND IDOR
    # ==========================================
    def test_idor_order_access_prevented(self):
        """User Alice cannot view Bob's order; returns 404."""
        # Create an order belonging to Bob (id=3)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
                         (3, 49.99, "", "paid", "2026-01-01T00:00:00+00:00"))
            order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()

        # Alice logs in
        self.login("alice", "alice-demo-pass")
        resp = self.client.get(f"/orders/{order_id}")
        self.assertEqual(resp.status_code, 404)

    def test_admin_can_view_any_order(self):
        """Admin user can view any user's order."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
                         (3, 49.99, "", "paid", "2026-01-01T00:00:00+00:00"))
            order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()

        self.login("admin", "admin123secure")
        resp = self.client.get(f"/orders/{order_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Order #", resp.data)

    def test_broken_access_control_admin_endpoints(self):
        """Unauthenticated or regular users cannot access administrative endpoints."""
        admin_routes = [
            "/admin",
            "/admin/users",
            "/admin/products",
            "/admin/coupons",
        ]
        # 1. Unauthenticated -> 302 redirect to login
        for route in admin_routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 302, f"Unauthenticated access to {route} did not redirect")

        # 2. Regular user (Alice) -> 403 Forbidden
        self.login("alice", "alice-demo-pass")
        for route in admin_routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 403, f"Regular user accessed {route} without 403")

    # ==========================================
    # E. AUTHENTICATION & ACCOUNT VERIFICATION BYPASS
    # ==========================================
    def test_unverified_user_cannot_login(self):
        """Unverified user cannot log in and is redirected to /verify."""
        self.post_with_csrf("/register", {
            "username": "unverified_user",
            "email": "unverified@example.test",
            "password": "Password12345",
        })
        resp = self.post_with_csrf("/login", {
            "username": "unverified_user",
            "password": "Password12345",
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/verify", resp.headers["Location"])
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("user_id"))

    def test_verification_code_reuse_prevented(self):
        """Once verified, the verification code is nullified and cannot be reused."""
        self.post_with_csrf("/register", {
            "username": "reuse_tester",
            "email": "reuse@example.test",
            "password": "Password12345",
        })
        with sqlite3.connect(self.db_path) as conn:
            code = conn.execute("SELECT verification_code FROM users WHERE username='reuse_tester'").fetchone()[0]

        # 1st verification succeeds
        resp1 = self.post_with_csrf("/verify", {"email": "reuse@example.test", "code": code}, follow_redirects=True)
        self.assertIn(b"Your account is confirmed", resp1.data)

        # 2nd verification with same code fails
        resp2 = self.post_with_csrf("/verify", {"email": "reuse@example.test", "code": code}, follow_redirects=True)
        self.assertIn(b"already confirmed", resp2.data)

    def test_verification_code_guessing_throttling(self):
        """Exceeding 5 failed verification attempts locks out further verification attempts."""
        self.post_with_csrf("/register", {
            "username": "guess_tester",
            "email": "guess@example.test",
            "password": "Password12345",
        })
        # Attempt 5 incorrect guesses
        for i in range(5):
            resp = self.post_with_csrf("/verify", {"email": "guess@example.test", "code": f"wrong-code-{i}"})
            self.assertIn(b"invalid or has already been used", resp.data)

        # 6th attempt (even if correct) is locked
        with sqlite3.connect(self.db_path) as conn:
            actual_code = conn.execute("SELECT verification_code FROM users WHERE username='guess_tester'").fetchone()[0]
        resp_blocked = self.post_with_csrf("/verify", {"email": "guess@example.test", "code": actual_code})
        self.assertIn(b"Too many failed confirmation attempts", resp_blocked.data)

    def test_expired_verification_code_rejected(self):
        """An expired verification code cannot be used to activate an account."""
        self.post_with_csrf("/register", {
            "username": "expired_tester",
            "email": "expired@example.test",
            "password": "Password12345",
        })
        # Manually expire the code
        expired_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET verification_code_expires_at=? WHERE username='expired_tester'", (expired_time,))
            conn.commit()
            code = conn.execute("SELECT verification_code FROM users WHERE username='expired_tester'").fetchone()[0]

        resp = self.post_with_csrf("/verify", {"email": "expired@example.test", "code": code})
        self.assertIn(b"has expired", resp.data)

    # ==========================================
    # F. PRIVILEGE ESCALATION
    # ==========================================
    def test_registration_privilege_escalation_prevented(self):
        """Submitting role=admin, is_verified=1, or store_credit=99999 at registration is strictly ignored."""
        self.post_with_csrf("/register", {
            "username": "sneaky_reg",
            "email": "sneaky@example.test",
            "password": "Password12345",
            "role": "admin",
            "is_verified": "1",
            "store_credit": "99999.00",
        })
        with sqlite3.connect(self.db_path) as conn:
            user = conn.execute("SELECT role, is_verified, store_credit FROM users WHERE username='sneaky_reg'").fetchone()
        self.assertEqual(user[0], "user")
        self.assertEqual(user[1], 0)
        self.assertEqual(user[2], 500.0)

    def test_profile_privilege_escalation_prevented(self):
        """Submitting role=admin or store_credit in /profile POST has zero effect."""
        self.login("alice", "alice-demo-pass")
        self.post_with_csrf("/profile", {
            "username": "alice_updated",
            "email": "alice_updated@example.test",
            "role": "admin",
            "store_credit": "1000000.00",
            "is_verified": "1",
        })
        with sqlite3.connect(self.db_path) as conn:
            user = conn.execute("SELECT role, store_credit FROM users WHERE id=1").fetchone()
        self.assertEqual(user[0], "user")
        self.assertEqual(user[1], 500.0)

    def test_admin_cannot_demote_self(self):
        """An administrator cannot remove their own admin privileges."""
        self.login("admin", "admin123secure")
        with sqlite3.connect(self.db_path) as conn:
            admin_id = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]

        resp = self.post_with_csrf(f"/admin/users/{admin_id}", {
            "role": "user",
            "store_credit": "1000.00",
            "is_verified": "on",
        }, follow_redirects=True)
        self.assertIn(b"You cannot remove your own administrator access", resp.data)
        with sqlite3.connect(self.db_path) as conn:
            role = conn.execute("SELECT role FROM users WHERE id=?", (admin_id,)).fetchone()[0]
        self.assertEqual(role, "admin")

    # ==========================================
    # G. SESSION SECURITY & SESSION HIJACKING
    # ==========================================
    def test_session_regeneration_on_login(self):
        """Session identifier and CSRF token are regenerated upon login."""
        self.client.get("/")
        with self.client.session_transaction() as sess:
            old_csrf = sess["csrf_token"]

        self.login("alice", "alice-demo-pass")
        with self.client.session_transaction() as sess:
            new_csrf = sess["csrf_token"]
            self.assertNotEqual(old_csrf, new_csrf)
            self.assertEqual(sess["user_id"], 1)

    def test_session_invalidation_on_logout(self):
        """Logging out clears all session state."""
        self.login("alice", "alice-demo-pass")
        resp = self.post_with_csrf("/logout", follow_redirects=True)
        self.assertIn(b"You have been signed out", resp.data)
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("user_id"))

    # ==========================================
    # H. BRUTE FORCE AND CREDENTIAL ATTACKS
    # ==========================================
    def test_brute_force_account_lockout(self):
        """Account locks after 5 consecutive failed login attempts."""
        for _ in range(5):
            self.post_with_csrf("/login", {"username": "bob", "password": "wrong-password"})

        with sqlite3.connect(self.db_path) as conn:
            user = conn.execute("SELECT failed_attempts, locked_until FROM users WHERE username='bob'").fetchone()
            self.assertGreaterEqual(user[0], 5)
            self.assertIsNotNone(user[1])

        # 6th attempt with correct password is still blocked by temporary lock
        resp = self.post_with_csrf("/login", {"username": "bob", "password": "bob123secure"})
        self.assertIn(b"temporarily locked", resp.data)

    def test_generic_credential_error_prevents_enumeration(self):
        """Login failure returns the exact same generic error whether username exists or not."""
        resp1 = self.post_with_csrf("/login", {"username": "nonexistent_user_999", "password": "anypassword"})
        resp2 = self.post_with_csrf("/login", {"username": "alice", "password": "wrongpassword"})
        self.assertIn(b"Invalid credentials", resp1.data)
        self.assertIn(b"Invalid credentials", resp2.data)

    # ==========================================
    # I. SECURITY MISCONFIGURATION
    # ==========================================
    def test_security_headers_present(self):
        """Responses must contain standard security headers."""
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_custom_error_handlers_do_not_leak_traces(self):
        """Error responses must be clean without stack traces."""
        resp404 = self.client.get("/nonexistent-page-xyz")
        self.assertEqual(resp404.status_code, 404)
        self.assertIn(b"Page not found", resp404.data)
        self.assertNotIn(b"Traceback", resp404.data)

    # ==========================================
    # J. OPEN REDIRECT
    # ==========================================
    def test_open_redirect_mitigations(self):
        """Redirect validation rejects external URLs, scheme-relative, and backslash bypasses."""
        malicious_targets = [
            "https://evil.com",
            "http://attacker.com/steal",
            "//evil.com",
            "///evil.com",
            "/\\evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        for target in malicious_targets:
            self.assertEqual(safe_redirect_url(target), "/")

        # Safe internal URLs are allowed
        self.assertEqual(safe_redirect_url("/products"), "/products")
        self.assertEqual(safe_redirect_url("/cart"), "/cart")
        self.assertEqual(safe_redirect_url("/orders/1"), "/orders/1")

    # ==========================================
    # K. SENSITIVE INFORMATION EXPOSURE
    # ==========================================
    def test_admin_users_view_does_not_expose_password_hashes(self):
        """The /admin/users view must never expose password hashes."""
        self.login("admin", "admin123secure")
        resp = self.client.get("/admin/users")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"pbkdf2:sha256", resp.data)
        self.assertNotIn(b"scrypt:", resp.data)

    # ==========================================
    # L. BUSINESS LOGIC VULNERABILITIES
    # ==========================================
    def test_negative_cart_quantity_rejected(self):
        """Submitting negative quantities to cart_add or cart_update must be rejected."""
        self.login("alice", "alice-demo-pass")
        # Negative quantity on add
        resp = self.post_with_csrf("/cart/add", {"product_id": 1, "quantity": -5}, follow_redirects=True)
        self.assertIn(b"Choose a valid quantity", resp.data)

        # Negative quantity on update
        self.post_with_csrf("/cart/add", {"product_id": 1, "quantity": 1})
        resp_up = self.post_with_csrf("/cart/update", {"qty_1": -10}, follow_redirects=True)
        self.assertIn(b"Cart quantities must be between zero", resp_up.data)

    def test_client_cannot_manipulate_price(self):
        """Client-provided prices in checkout POST are ignored; database price is enforced."""
        self.login("alice", "alice-demo-pass")
        self.post_with_csrf("/cart/add", {"product_id": 4, "quantity": 1})  # Office Coffee = $15.00
        # Attacker tries to submit a 1 cent or negative total
        resp = self.post_with_csrf("/checkout", {"total": "0.01", "unit_price": "0.01", "coupon": ""}, follow_redirects=True)
        self.assertIn(b"Order #", resp.data)
        with sqlite3.connect(self.db_path) as conn:
            order_total = conn.execute("SELECT total_amount FROM orders ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual(order_total, 15.00)

    def test_insufficient_store_credit_blocked(self):
        """Checkout fails if user's store credit is lower than the order total."""
        # Lower Alice's credit to $5
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET store_credit=5.00 WHERE username='alice'")
            conn.commit()

        self.login("alice", "alice-demo-pass")
        self.post_with_csrf("/cart/add", {"product_id": 1, "quantity": 1})  # $89.99
        resp = self.post_with_csrf("/checkout", {"coupon": ""}, follow_redirects=True)
        self.assertIn(b"Your store credit is insufficient", resp.data)

    def test_ineligible_coupon_rejected(self):
        """Coupons assigned to a different user, expired, or below min_purchase are rejected."""
        self.login("bob", "bob123secure")
        self.post_with_csrf("/cart/add", {"product_id": 4, "quantity": 1})  # $15.00

        # SINGLE50 is assigned only to alice@example.test
        resp_assigned = self.post_with_csrf("/checkout", {"coupon": "SINGLE50"}, follow_redirects=True)
        self.assertIn(b"not eligible for this order", resp_assigned.data)

        # WELCOME20 requires min_purchase of $100 (Coffee is $15)
        resp_min = self.post_with_csrf("/checkout", {"coupon": "WELCOME20"}, follow_redirects=True)
        self.assertIn(b"not eligible for this order", resp_min.data)

    # ==========================================
    # FILE SECURITY - PATH TRAVERSAL
    # ==========================================
    def test_path_traversal_downloads_prevented(self):
        """Directory traversal sequences in download and files routes return 404."""
        traversal_payloads = [
            "../sample_private.txt",
            "..\\sample_private.txt",
            "....//sample_private.txt",
            "../../etc/passwd",
        ]
        for payload in traversal_payloads:
            resp = self.client.get(f"/download?name={payload}")
            self.assertEqual(resp.status_code, 404)
            resp2 = self.client.get(f"/files?name={payload}")
            self.assertEqual(resp2.status_code, 404)


if __name__ == "__main__":
    unittest.main()
