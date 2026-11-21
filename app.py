import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import traceback

from flask import Flask, abort, flash, jsonify, redirect, render_template, render_template_string, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from security_middleware import request_observation

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secureshop.db"
UPLOAD_DIR, DEMO_DIR = BASE_DIR / "test_files", BASE_DIR / "demo_files"

# [SECURITY-DEFENSE: Security Misconfiguration Prevention]
# [SECURITY-DEFENSE: Secure Session Management]
# [VULNERABILITY: SECURITY MISCONFIGURATION] Debug mode enabled, exposing detailed errors and stack traces
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "supersecretkey-not-random"),  # [VULNERABILITY: SECURITY MISCONFIGURATION] Hardcoded weak secret key
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_PERMANENT=False,
    DEBUG=True,  # [VULNERABILITY: SECURITY MISCONFIGURATION] Debug mode enabled
)

# [VULNERABILITY: CSRF] Paths exempt from CSRF protection for vulnerable API endpoints
CSRF_EXEMPT_PATHS = [
    "/api/",
    "/login/debug",
    "/login/quick",
    "/redirect",
    "/verify-2fa",
    "/register/complete",
]

# In-memory IP tracking for brute force mitigation
# [SECURITY-DEFENSE: Brute Force Prevention]
_login_ip_attempts = {}

# [SECURITY-DEFENSE: SQL Injection Prevention]
def db():
    conn = sqlite3.connect(app.config.get("DATABASE_PATH", str(DB_PATH)), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now():
    return datetime.now(timezone.utc)

# [SECURITY-DEFENSE: Security Misconfiguration Prevention]
def migrate_database():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS newsletter_subscribers (
              id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
              coupon_code TEXT NOT NULL, subscribed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, user_id INTEGER,
              detail TEXT, ip TEXT, created_at TEXT NOT NULL);
        """)
        # Ensure coupon columns exist
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(coupons)")}
        for name, definition in {
            "expires_at": "TEXT",
            "max_uses": "INTEGER NOT NULL DEFAULT 1",
            "min_purchase": "REAL NOT NULL DEFAULT 0",
            "usage_count": "INTEGER DEFAULT 0",
        }.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE coupons ADD COLUMN {name} {definition}")
        
        # Ensure user security columns exist
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        for name, definition in {
            "verification_attempts": "INTEGER DEFAULT 0",
            "verification_code_expires_at": "TEXT",
            "locked_until": "TEXT",
        }.items():
            if name not in user_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")

        # [SECURITY-DEFENSE: Authentication Bypass Prevention] Upgrade any legacy plaintext passwords
        for user in conn.execute("SELECT id,password_hash FROM users"):
            if not user["password_hash"].startswith(("pbkdf2:", "scrypt:")):
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(user["password_hash"]), user["id"]))
        conn.commit()

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: Secure Session Management]
def current_user():
    if not session.get("user_id"):
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

# [SECURITY-DEFENSE: Sensitive Information Protection]
# [SECURITY-DEFENSE: Audit Accountability - Authenticated Actor Observation]
def audit(event, user_id=None, detail=""):
    obs = request_observation(user_id=user_id)
    with db() as conn:
        conn.execute("INSERT INTO audit_events(event,user_id,detail,ip,created_at) VALUES (?,?,?,?,?)",
                     (event, user_id, (detail or "")[:500], obs["ip"], now().isoformat()))
        conn.commit()

# [SECURITY-DEFENSE: Broken Access Control Prevention]
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: Privilege Escalation Prevention]
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped

# [SECURITY-DEFENSE: Business Logic Protection]
def money(raw):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError("Enter a valid amount.")
    if value < 0 or value > 1_000_000:
        raise ValueError("Enter an amount between 0 and 1,000,000.")
    return round(value, 2)

# [SECURITY-DEFENSE: Business Logic Protection]
def positive_int(raw, label="quantity", maximum=999):
    try:
        number = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"Enter a valid {label}.")
    if not 1 <= number <= maximum:
        raise ValueError(f"{label.capitalize()} must be between 1 and {maximum}.")
    return number

# [SECURITY-DEFENSE: XSS Prevention]
# [SECURITY-DEFENSE: Input Validation]
def validate_email(email):
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter a valid email address.")
    if len(email) > 120:
        raise ValueError("Email address is too long.")
    return email

# [SECURITY-DEFENSE: XSS Prevention]
# [SECURITY-DEFENSE: Input Validation]
def validate_username(username):
    username = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise ValueError("Username must be 3–32 letters, numbers, dots, dashes, or underscores.")
    return username

# [SECURITY-DEFENSE: Open Redirect Prevention]
def safe_redirect_url(target):
    if not target or not isinstance(target, str):
        return "/"
    target = target.strip()
    # Reject absolute URLs, scheme-relative URLs, Windows UNC paths, or backslashes
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return "/"
    if "\\" in target or ":" in target:
        return "/"
    try:
        parsed = urlparse(target)
        if parsed.scheme or parsed.netloc:
            return "/"
    except Exception:
        return "/"
    return target

# [SECURITY-DEFENSE: Brute Force Prevention]
def check_ip_rate_limit(ip, max_attempts=15, window_seconds=900):
    current_time = now().timestamp()
    attempts = _login_ip_attempts.get(ip, [])
    attempts = [t for t in attempts if current_time - t < window_seconds]
    _login_ip_attempts[ip] = attempts
    return len(attempts) < max_attempts

def record_ip_attempt(ip):
    current_time = now().timestamp()
    attempts = _login_ip_attempts.get(ip, [])
    attempts.append(current_time)
    _login_ip_attempts[ip] = attempts

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: SQL Injection Prevention]
def cart_items(conn=None):
    cart = session.get("cart", {})
    try:
        ids = [int(k) for k, v in cart.items() if int(v) > 0]
    except (ValueError, TypeError):
        session["cart"] = {}
        return []
    if not ids:
        return []
    close, conn = conn is None, conn or db()
    try:
        # [SECURITY-DEFENSE: SQL Injection Prevention - Parameterized query for integer IDs]
        placeholders = ",".join("?" for _ in ids)
        products = {p["id"]: p for p in conn.execute(
            f"SELECT * FROM products WHERE id IN ({placeholders})", ids)}
        return [(products[pid], int(cart[str(pid)])) for pid in ids if pid in products]
    finally:
        if close:
            conn.close()

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: SQL Injection Prevention]
def eligible_coupon(conn, raw_code, user, subtotal):
    code = (raw_code or "").strip().upper()
    if not code:
        return None, None
    coupon = conn.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
    if not coupon:
        return None, "Coupon code was not found."
    expiry = coupon["expires_at"]
    try:
        expired = bool(expiry) and datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc) <= now()
    except ValueError:
        expired = True
    assigned = bool(coupon["assigned_email"]) and coupon["assigned_email"].lower() != user["email"].lower()
    usage_count = coupon["usage_count"] if "usage_count" in coupon.keys() else 0
    if expired or assigned or coupon["is_used"] or usage_count >= coupon["max_uses"] or subtotal < coupon["min_purchase"]:
        return None, "This coupon is not eligible for this order."
    return coupon, None

# [SECURITY-DEFENSE: CSRF Protection]
# [VULNERABILITY: CSRF] API endpoints exempted from CSRF protection
@app.before_request
def csrf_protection():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # [VULNERABILITY: CSRF] Skip CSRF check for exempt API paths
        for exempt in CSRF_EXEMPT_PATHS:
            if request.path.startswith(exempt):
                return  # No CSRF validation
        token = request.form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf_token", "")
        if not token or not expected or not hmac.compare_digest(token, expected):
            abort(400)

# [SECURITY-DEFENSE: Security Misconfiguration Prevention]
# [SECURITY-DEFENSE: XSS Prevention]
# [VULNERABILITY: SECURITY MISCONFIGURATION] Security headers omitted for /api/* routes
@app.after_request
def set_security_headers(response):
    # [VULNERABILITY: SECURITY MISCONFIGURATION] No security headers on API endpoints
    if request.path.startswith("/api/"):
        return response
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# [SECURITY-DEFENSE: CSRF Protection]
# [SECURITY-DEFENSE: Secure Session Management]
@app.context_processor
def context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    cart = session.get("cart", {})
    return {"current_user": current_user(), "csrf_token": session["csrf_token"],
            "cart_count": sum(int(v) for v in cart.values() if str(v).isdigit())}

# [SECURITY-DEFENSE: SQL Injection Prevention]
@app.route("/")
def index():
    with db() as conn:
        products = conn.execute("SELECT * FROM products WHERE stock > 0 ORDER BY id LIMIT 4").fetchall()
    return render_template("index.html", products=products)

# [SECURITY-DEFENSE: SQL Injection Prevention]
# [SECURITY-DEFENSE: XSS Prevention]
@app.route("/products")
def products():
    query = request.args.get("q", "").strip()
    with db() as conn:
        if query:
            like = f"%{query}%"
            # [SECURITY-DEFENSE: SQL Injection Prevention - Parameterized LIKE queries]
            rows = conn.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY name", (like, like)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("products.html", products=rows, query=query)

# [SECURITY-DEFENSE: SQL Injection Prevention]
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    with db() as conn:
        product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        reviews = conn.execute("SELECT r.*,u.username FROM reviews r LEFT JOIN users u ON u.id=r.user_id WHERE r.product_id=? ORDER BY r.id DESC", (product_id,)).fetchall()
    if not product:
        abort(404)
    return render_template("product.html", product=product, reviews=reviews)

# [SECURITY-DEFENSE: XSS Prevention]
# [SECURITY-DEFENSE: SQL Injection Prevention]
# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/product/<int:product_id>/review", methods=["POST"])
@login_required
def review(product_id):
    body = request.form.get("body", "").strip()
    if not 1 <= len(body) <= 1000:
        flash("Reviews must be between 1 and 1,000 characters.", "danger")
    else:
        with db() as conn:
            if not conn.execute("SELECT 1 FROM products WHERE id=?", (product_id,)).fetchone():
                abort(404)
            # [SECURITY-DEFENSE: SQL Injection Prevention]
            # [SECURITY-DEFENSE: IDOR Prevention - Authenticated user ID bound server-side]
            conn.execute("INSERT INTO reviews(product_id,user_id,body,created_at) VALUES (?,?,?,?)",
                         (product_id, current_user()["id"], body, now().isoformat()))
            conn.commit()
        flash("Thanks for sharing your review.", "success")
    return redirect(url_for("product_detail", product_id=product_id))

# [SECURITY-DEFENSE: Authentication Bypass Prevention]
# [SECURITY-DEFENSE: Account Verification Bypass Prevention]
# [SECURITY-DEFENSE: Privilege Escalation Prevention]
# [SECURITY-DEFENSE: Sensitive Information Protection]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = validate_username(request.form.get("username"))
            email = validate_email(request.form.get("email"))
            password = request.form.get("password", "")
            if len(password) < 10 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
                raise ValueError("Use a password of at least 10 characters with letters and numbers.")
            
            # [SECURITY-DEFENSE: Account Verification Bypass Prevention - Cryptographically secure code and expiration]
            confirmation_code = secrets.token_urlsafe(18)
            code_expires = (now() + timedelta(minutes=30)).isoformat()
            
            # [SECURITY-DEFENSE: Privilege Escalation Prevention - Role hardcoded to 'user', credit to 500.0, is_verified to 0]
            with db() as conn:
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,role,is_verified,verification_code,store_credit,failed_attempts,device_id,verification_attempts,verification_code_expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (username, email, generate_password_hash(password), "user", 0, confirmation_code, 500.0, 0, "", 0, code_expires)
                )
                conn.commit()
            
            flash(f"Your account was created. Save this one-time confirmation code: {confirmation_code}", "success")
            return redirect(url_for("verify", email=email))
        except (ValueError, sqlite3.IntegrityError) as exc:
            # [SECURITY-DEFENSE: Sensitive Information Protection - Generic collision error]
            flash("That username or email is already unavailable." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    return render_template("register.html")

# [SECURITY-DEFENSE: Account Verification Bypass Prevention]
# [SECURITY-DEFENSE: Brute Force Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = request.args.get("email", "") or request.form.get("email", "")
    if request.method == "POST":
        submitted_code = request.form.get("code", "").strip()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", ((email or "").lower(),)).fetchone()
            if not user:
                flash("That confirmation code is invalid or has already been used.", "danger")
                return render_template("verify.html", email=email)
            
            if user["is_verified"]:
                flash("Your account is already confirmed. You can now sign in.", "info")
                return redirect(url_for("login"))
            
            # [SECURITY-DEFENSE: Account Verification Bypass Prevention - Limit verification attempts to 5]
            attempts = user["verification_attempts"] if "verification_attempts" in user.keys() and user["verification_attempts"] is not None else 0
            if attempts >= 5:
                flash("Too many failed confirmation attempts. Please contact support or register again.", "danger")
                return render_template("verify.html", email=email)
            
            # [SECURITY-DEFENSE: Account Verification Bypass Prevention - Enforce expiration]
            code_expiry = user["verification_code_expires_at"] if "verification_code_expires_at" in user.keys() else None
            if code_expiry:
                try:
                    if datetime.fromisoformat(code_expiry).replace(tzinfo=timezone.utc) <= now():
                        flash("That confirmation code has expired. Please register again.", "danger")
                        return render_template("verify.html", email=email)
                except ValueError:
                    pass

            # [SECURITY-DEFENSE: Account Verification Bypass Prevention - Constant-time comparison & single-use nullification]
            if user["verification_code"] and hmac.compare_digest(submitted_code, user["verification_code"]):
                conn.execute(
                    "UPDATE users SET is_verified=1, verification_code=NULL, verification_attempts=0, verification_code_expires_at=NULL WHERE id=?",
                    (user["id"],)
                )
                conn.commit()
                flash("Your account is confirmed. You can now sign in.", "success")
                return redirect(url_for("login"))
            else:
                # Increment failed verification attempts
                conn.execute("UPDATE users SET verification_attempts=verification_attempts+1 WHERE id=?", (user["id"],))
                conn.commit()
                flash("That confirmation code is invalid or has already been used.", "danger")
    return render_template("verify.html", email=email)

# [SECURITY-DEFENSE: Authentication Bypass Prevention]
# [SECURITY-DEFENSE: Brute Force Prevention]
# [SECURITY-DEFENSE: Secure Session Management]
# [SECURITY-DEFENSE: Open Redirect Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        if not check_ip_rate_limit(ip):
            flash("Too many failed requests. Please try again later.", "danger")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            
            # [SECURITY-DEFENSE: Brute Force Prevention - Account Lockout check]
            if user and "locked_until" in user.keys() and user["locked_until"]:
                try:
                    if datetime.fromisoformat(user["locked_until"]).replace(tzinfo=timezone.utc) > now():
                        audit("login_attempt_locked", user["id"], "Account temporarily locked")
                        flash("This account is temporarily locked due to failed attempts. Please try again later.", "danger")
                        return render_template("login.html")
                    else:
                        # Lockout has expired, reset counter
                        conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
                        conn.commit()
                except ValueError:
                    pass

            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                # [SECURITY-DEFENSE: Authentication Bypass Prevention - Prevent unverified sign in]
                if not user["is_verified"]:
                    flash("Confirm your account before signing in.", "warning")
                    return redirect(url_for("verify", email=user["email"]))
                
                # [SECURITY-DEFENSE: Secure Session Management - Regenerate session identifiers on login]
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                
                # Reset failed attempts and record IP
                conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_ip=? WHERE id=?", (ip, user["id"]))
                conn.commit()
                audit("login", user["id"], "successful login")
                flash(f"Welcome back, {user['username']}!", "success")
                
                # [SECURITY-DEFENSE: Open Redirect Prevention - Validate redirect target]
                # [VULNERABILITY: OPEN REDIRECT] Uses form-submitted redirect_url without validation when present
                form_redirect = request.form.get("redirect_url", "")
                if form_redirect:
                    target = form_redirect  # [VULNERABILITY: OPEN REDIRECT] Trusts unvalidated redirect destination
                else:
                    target = safe_redirect_url(request.args.get("next", ""))
                return redirect(target)
            
            # Authentication failed
            record_ip_attempt(ip)
            if user:
                new_attempts = (user["failed_attempts"] or 0) + 1
                if new_attempts >= 5:
                    lock_time = (now() + timedelta(minutes=15)).isoformat()
                    conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (new_attempts, lock_time, user["id"]))
                else:
                    conn.execute("UPDATE users SET failed_attempts=? WHERE id=?", (new_attempts, user["id"]))
                conn.commit()

        # [SECURITY-DEFENSE: Sensitive Information Protection - Generic credential error to prevent account enumeration]
        audit("failed_login", None, username)
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

# [SECURITY-DEFENSE: Secure Session Management]
# [SECURITY-DEFENSE: CSRF Protection]
# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [VULNERABILITY: INSECURE SESSION MANAGEMENT] Incomplete session invalidation on logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", current_user()["id"])
    # [VULNERABILITY: INSECURE SESSION MANAGEMENT] Only remove user_id; cart and csrf_token persist
    session.pop("user_id", None)
    session.pop("2fa_pending_user_id", None)
    # session.clear() is NOT called - session data like cart, csrf_token remain
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))

# [SECURITY-DEFENSE: IDOR Prevention]
# [SECURITY-DEFENSE: Privilege Escalation Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
# [SECURITY-DEFENSE: Broken Access Control Prevention]
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        try:
            # [SECURITY-DEFENSE: Privilege Escalation Prevention - Strictly update only username and email; ignore client role/credit/verified]
            username = validate_username(request.form.get("username"))
            email = validate_email(request.form.get("email"))
            # [VULNERABILITY: BROKEN ACCESS CONTROL / PRIVILEGE ESCALATION] Accepts role and store_credit from form data
            role = request.form.get("role")
            credit = request.form.get("store_credit")
            with db() as conn:
                if role and role in ("user", "admin"):
                    # [VULNERABILITY: BROKEN ACCESS CONTROL / PRIVILEGE ESCALATION] User can set own role to admin
                    conn.execute("UPDATE users SET username=?,email=?,role=? WHERE id=?", (username, email, role, user["id"]))
                elif credit:
                    # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Trusts client-submitted store credit
                    conn.execute("UPDATE users SET username=?,email=?,store_credit=? WHERE id=?", (username, email, float(credit), user["id"]))
                else:
                    # [SECURITY-DEFENSE: IDOR Prevention - Updates only authenticated user ID from session]
                    conn.execute("UPDATE users SET username=?,email=? WHERE id=?", (username, email, user["id"]))
                conn.commit()
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("That username or email is already unavailable." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    with db() as conn:
        orders = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 5", (user["id"],)).fetchall()
    return render_template("profile.html", user=current_user(), orders=orders)

# [SECURITY-DEFENSE: Business Logic Protection]
@app.route("/cart")
def cart():
    items = cart_items()
    return render_template("cart.html", items=items, total=sum(p["price"] * q for p, q in items))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/cart/add", methods=["POST"])
def cart_add():
    try:
        pid = int(request.form.get("product_id", ""))
        quantity = positive_int(request.form.get("quantity", 1))
        with db() as conn:
            product = conn.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
        if not product or product["stock"] < 1:
            raise ValueError
        cart = session.get("cart", {})
        if int(cart.get(str(pid), 0)) + quantity > product["stock"]:
            flash(f"Only {product['stock']} of this product are available.", "danger")
        else:
            cart[str(pid)] = int(cart.get(str(pid), 0)) + quantity
            session["cart"] = cart
            flash("Added to your cart.", "success")
    except (ValueError, TypeError):
        flash("Choose a valid quantity for an available product.", "danger")
    return redirect(safe_redirect_url(request.referrer) or url_for("products"))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart = session.get("cart", {})
    try:
        with db() as conn:
            for key, value in request.form.items():
                if key.startswith("qty_"):
                    pid, quantity = int(key[4:]), int(value)
                    product = conn.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
                    if not product or quantity < 0 or quantity > product["stock"]:
                        raise ValueError
                    if quantity:
                        cart[str(pid)] = quantity
                    else:
                        cart.pop(str(pid), None)
        session["cart"] = cart
        flash("Your cart has been updated.", "success")
    except (ValueError, TypeError):
        flash("Cart quantities must be between zero and the available stock.", "danger")
    return redirect(url_for("cart"))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/cart/remove", methods=["POST"])
def cart_remove():
    cart = session.get("cart", {})
    cart.pop(request.form.get("product_id", ""), None)
    session["cart"] = cart
    flash("Item removed from your cart.", "success")
    return redirect(url_for("cart"))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    user = current_user()
    if request.method == "POST":
        try:
            with db() as conn:
                # [SECURITY-DEFENSE: Business Logic Protection - Atomic transaction prevents race conditions and double spending]
                conn.execute("BEGIN IMMEDIATE")
                fresh_user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                items = cart_items(conn)
                if not items:
                    raise ValueError("Your cart is empty.")
                
                # [SECURITY-DEFENSE: Business Logic Protection - Server-side price calculation directly from database]
                subtotal = round(sum(p["price"] * q for p, q in items), 2)
                for product, quantity in items:
                    live = conn.execute("SELECT stock FROM products WHERE id=?", (product["id"],)).fetchone()
                    if not live or not 1 <= quantity <= live["stock"]:
                        raise ValueError(f"{product['name']} no longer has enough stock.")
                
                coupon, coupon_error = eligible_coupon(conn, request.form.get("coupon"), fresh_user, subtotal)
                if coupon_error:
                    raise ValueError(coupon_error)
                
                discount = round(subtotal * coupon["discount_percent"] / 100, 2) if coupon else 0
                total = round(subtotal - discount, 2)
                
                # [SECURITY-DEFENSE: Business Logic Protection - Verify store credit sufficiency]
                if fresh_user["store_credit"] + 1e-9 < total:
                    raise ValueError("Your store credit is insufficient for this order.")
                
                order_id = conn.execute(
                    "INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
                    (user["id"], total, coupon["code"] if coupon else "", "paid", now().isoformat())
                ).lastrowid
                
                for product, quantity in items:
                    conn.execute(
                        "INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)",
                        (order_id, product["id"], quantity, product["price"])
                    )
                    conn.execute("UPDATE products SET stock=stock-? WHERE id=?", (quantity, product["id"]))
                
                # [SECURITY-DEFENSE: Business Logic Protection - Atomic coupon redemption check]
                if coupon and conn.execute(
                    "UPDATE coupons SET usage_count=usage_count+1,is_used=CASE WHEN usage_count+1>=max_uses THEN 1 ELSE 0 END WHERE id=? AND usage_count<max_uses",
                    (coupon["id"],)
                ).rowcount != 1:
                    raise ValueError("That coupon was just redeemed. Please review your order.")
                
                conn.execute("UPDATE users SET store_credit=store_credit-? WHERE id=?", (total, user["id"]))
                conn.commit()
            
            session["cart"] = {}
            audit("order_created", user["id"], f"order={order_id}; total={total:.2f}")
            flash("Your order has been placed and paid with store credit.", "success")
            return redirect(url_for("order_detail", order_id=order_id))
        except (ValueError, sqlite3.Error) as exc:
            flash(str(exc) if isinstance(exc, ValueError) else "We could not complete your order. Please try again.", "danger")
    items = cart_items()
    return render_template("checkout.html", items=items, subtotal=round(sum(p["price"] * q for p, q in items), 2))

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: IDOR Prevention]
@app.route("/orders")
@login_required
def orders():
    with db() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (current_user()["id"],)).fetchall()
    return render_template("orders.html", orders=rows)

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: IDOR Prevention]
@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    user = current_user()
    with db() as conn:
        # [SECURITY-DEFENSE: IDOR Prevention - Ownership strictly verified against current session user]
        if user["role"] == "admin":
            order = conn.execute("SELECT orders.*,users.username FROM orders JOIN users ON users.id=orders.user_id WHERE orders.id=?", (order_id,)).fetchone()
        else:
            order = conn.execute("SELECT orders.*,users.username FROM orders JOIN users ON users.id=orders.user_id WHERE orders.id=? AND orders.user_id=?", (order_id, user["id"])).fetchone()
        items = conn.execute("SELECT oi.*,p.name FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?", (order_id,)).fetchall() if order else []
    if not order:
        abort(404)
    return render_template("order.html", order=order, items=items)

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/newsletter", methods=["GET", "POST"])
def newsletter():
    if request.method == "POST":
        try:
            email = validate_email(request.form.get("email"))
            with db() as conn:
                existing = conn.execute("SELECT coupon_code FROM newsletter_subscribers WHERE email=?", (email,)).fetchone()
                if existing:
                    flash(f"You are already subscribed. Your welcome coupon is {existing['coupon_code']}.", "info")
                else:
                    code = "NEWS" + secrets.token_hex(4).upper()
                    conn.execute("INSERT INTO coupons(code,discount_percent,is_used,usage_count,assigned_email,expires_at,max_uses,min_purchase) VALUES (?,?,0,0,?,?,?,?)",
                        (code, 10, email, (now() + timedelta(days=30)).isoformat(), 1, 0))
                    conn.execute("INSERT INTO newsletter_subscribers(email,coupon_code,subscribed_at) VALUES (?,?,?)", (email, code, now().isoformat()))
                    conn.commit()
                    flash(f"You are subscribed! Your 10% welcome coupon is {code}.", "success")
            return redirect(url_for("newsletter"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("newsletter.html")

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: Privilege Escalation Prevention]
# [SECURITY-DEFENSE: SQL Injection Prevention]
@app.route("/admin")
@admin_required
def admin():
    # [SECURITY-DEFENSE: SQL Injection Prevention - Hardcoded allowlist mapping without string formatting]
    ALLOWED_STAT_QUERIES = {
        "users": "SELECT COUNT(*) AS c FROM users",
        "orders": "SELECT COUNT(*) AS c FROM orders",
        "products": "SELECT COUNT(*) AS c FROM products",
    }
    with db() as conn:
        stats = {key: conn.execute(query).fetchone()["c"] for key, query in ALLOWED_STAT_QUERIES.items()}
    return render_template("admin.html", stats=stats)

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: Sensitive Information Protection]
@app.route("/admin/users")
@admin_required
def admin_users():
    with db() as conn:
        # [SECURITY-DEFENSE: Sensitive Information Protection - Omit password hashes from user management view]
        users = conn.execute("SELECT id,username,email,role,is_verified,store_credit FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users)

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: Privilege Escalation Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/users/<int:user_id>", methods=["POST"])
@admin_required
def admin_user_update(user_id):
    try:
        role = request.form.get("role")
        credit = money(request.form.get("store_credit"))
        if role not in {"user", "admin"}:
            raise ValueError("Choose a valid role.")
        # [SECURITY-DEFENSE: Privilege Escalation Prevention - Admin cannot demote self]
        if user_id == current_user()["id"] and role != "admin":
            raise ValueError("You cannot remove your own administrator access.")
        with db() as conn:
            conn.execute("UPDATE users SET role=?,store_credit=?,is_verified=? WHERE id=?",
                         (role, credit, 1 if request.form.get("is_verified") else 0, user_id))
            conn.commit()
        flash("User account updated.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("admin_users"))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: Input Validation]
def product_values():
    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not name or len(name) > 120 or len(description) > 2000:
        raise ValueError("Use a product name and a description within the allowed length.")
    try:
        stock = int(request.form.get("stock"))
    except (TypeError, ValueError):
        raise ValueError("Enter a valid stock quantity.")
    if not 0 <= stock <= 100000:
        raise ValueError("Stock must be between 0 and 100,000.")
    price = money(request.form.get("price"))
    if price <= 0:
        raise ValueError("Price must be greater than zero.")
    return name, description, price, stock, secure_filename(request.form.get("image_filename", ""))

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if request.method == "POST":
        try:
            with db() as conn:
                conn.execute("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)", product_values())
                conn.commit()
            flash("Product created.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
    with db() as conn:
        rows = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("admin_products.html", products=rows)

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/products/<int:product_id>", methods=["POST"])
@admin_required
def admin_product_update(product_id):
    try:
        with db() as conn:
            conn.execute("UPDATE products SET name=?,description=?,price=?,stock=?,image_filename=? WHERE id=?", (*product_values(), product_id))
            conn.commit()
        flash("Product updated.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("admin_products"))

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_product_delete(product_id):
    try:
        with db() as conn:
            conn.execute("DELETE FROM products WHERE id=?", (product_id,))
            conn.commit()
        flash("Product removed.", "success")
    except sqlite3.IntegrityError:
        flash("This product is retained because it appears in an order history.", "warning")
    return redirect(url_for("admin_products"))

# [SECURITY-DEFENSE: Business Logic Protection]
# [SECURITY-DEFENSE: Input Validation]
def coupon_values():
    code = (request.form.get("code") or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9_-]{4,32}", code):
        raise ValueError("Coupon codes use 4–32 uppercase letters, numbers, dashes, or underscores.")
    email = (request.form.get("email") or "").strip().lower()
    expiry = (request.form.get("expires_at") or "").strip()
    if email:
        email = validate_email(email)
    if expiry:
        expiry = datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc).isoformat()
    return code, positive_int(request.form.get("discount"), "discount", 100), email, expiry, positive_int(request.form.get("max_uses", 1), "maximum uses", 100000), money(request.form.get("min_purchase", 0))

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/coupons", methods=["GET", "POST"])
@admin_required
def admin_coupons():
    if request.method == "POST":
        try:
            code, discount, email, expiry, maximum, minimum = coupon_values()
            with db() as conn:
                conn.execute("INSERT INTO coupons(code,discount_percent,is_used,usage_count,assigned_email,expires_at,max_uses,min_purchase) VALUES (?,?,0,0,?,?,?,?)", (code, discount, email, expiry, maximum, minimum))
                conn.commit()
            flash("Coupon created.", "success")
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("Coupon code already exists." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    with db() as conn:
        rows = conn.execute("SELECT * FROM coupons ORDER BY id DESC").fetchall()
    return render_template("admin_coupons.html", coupons=rows)

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/coupons/<int:coupon_id>", methods=["POST"])
@admin_required
def admin_coupon_update(coupon_id):
    try:
        code, discount, email, expiry, maximum, minimum = coupon_values()
        with db() as conn:
            conn.execute("UPDATE coupons SET code=?,discount_percent=?,assigned_email=?,expires_at=?,max_uses=?,min_purchase=?,is_used=CASE WHEN usage_count>=? THEN 1 ELSE 0 END WHERE id=?", (code, discount, email, expiry, maximum, minimum, maximum, coupon_id))
            conn.commit()
        flash("Coupon updated.", "success")
    except (ValueError, sqlite3.IntegrityError) as exc:
        flash("Coupon code already exists." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    return redirect(url_for("admin_coupons"))

# [SECURITY-DEFENSE: Broken Access Control Prevention]
# [SECURITY-DEFENSE: CSRF Protection]
@app.route("/admin/coupons/<int:coupon_id>/delete", methods=["POST"])
@admin_required
def admin_coupon_delete(coupon_id):
    with db() as conn:
        conn.execute("DELETE FROM coupons WHERE id=?", (coupon_id,))
        conn.commit()
    flash("Coupon removed.", "success")
    return redirect(url_for("admin_coupons"))

# [SECURITY-DEFENSE: File Security - Path Traversal Prevention]
def safe_file(directory, name):
    candidate = (directory / secure_filename(name)).resolve()
    if candidate.parent != directory.resolve() or not candidate.is_file():
        abort(404)
    return candidate

@app.route("/files")
def files():
    return send_file(safe_file(UPLOAD_DIR, request.args.get("name", "")))

@app.route("/download")
def download():
    return send_file(safe_file(DEMO_DIR, request.args.get("name", "")))

# [SECURITY-DEFENSE: Sensitive Information Protection]
# [SECURITY-DEFENSE: Security Misconfiguration Prevention]
@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", title="Request could not be completed", message="Your request was invalid or your form expired. Please go back and try again."), 400

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", title="Access denied", message="You do not have permission to view this page."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", title="Page not found", message="The page or item you requested is unavailable."), 404

@app.errorhandler(500)
def internal_error(error):
    # [VULNERABILITY: SECURITY MISCONFIGURATION] Expose stack traces in API error responses
    if request.path.startswith("/api/"):
        return jsonify({"error": str(error), "traceback": traceback.format_exc()}), 500
    return render_template("error.html", title="Something went wrong", message="Please try again in a moment."), 500


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABLE ENDPOINTS — Intentionally insecure for security lab exercises
# ═══════════════════════════════════════════════════════════════════════════════

# ─── CATEGORY A: SQL INJECTION ────────────────────────────────────────────────

# [VULNERABILITY: SQL INJECTION] Login endpoint using string formatting in SQL
@app.route("/login/debug", methods=["GET", "POST"])
def login_debug():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # [VULNERABILITY: SQL INJECTION] Direct string interpolation in SQL query
        with db() as conn:
            query = f"SELECT * FROM users WHERE username='{username}'"
            try:
                user = conn.execute(query).fetchone()
            except Exception as e:
                # [VULNERABILITY: SECURITY MISCONFIGURATION] Leaking SQL errors
                flash(f"Database error: {e}", "danger")
                return render_template("login.html")
            if user and check_password_hash(user["password_hash"], password):
                # [VULNERABILITY: INSECURE SESSION MANAGEMENT] No session regeneration
                # [VULNERABILITY: BROKEN AUTHENTICATION] No verification check
                # [VULNERABILITY: BRUTE FORCE] No rate limiting
                session["user_id"] = user["id"]
                flash(f"Welcome back, {user['username']}!", "success")
                # [VULNERABILITY: OPEN REDIRECT] Trusts unvalidated redirect parameter
                redir = request.form.get("redirect_url", request.args.get("next", "/"))
                return redirect(redir)
            elif user:
                flash("Invalid credentials.", "danger")
            else:
                # [VULNERABILITY: SQL INJECTION] If injection returns a row, authenticate
                # Try re-executing to see if injection returned rows
                try:
                    result = conn.execute(query).fetchone()
                    if result:
                        session["user_id"] = result["id"]
                        flash(f"Welcome back, {result['username']}!", "success")
                        return redirect("/")
                except Exception:
                    pass
                flash("Invalid credentials.", "danger")
    return render_template("login.html")


# [VULNERABILITY: SQL INJECTION] Product search with string formatting
@app.route("/api/products/search")
def api_product_search():
    query = request.args.get("q", "")
    sort = request.args.get("sort", "name")
    # [VULNERABILITY: SQL INJECTION] Direct string interpolation in SQL
    with db() as conn:
        try:
            sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%' ORDER BY {sort}"
            rows = conn.execute(sql).fetchall()
            return jsonify([dict(r) for r in rows])
        except Exception as e:
            # [VULNERABILITY: SECURITY MISCONFIGURATION] SQL error leakage
            return jsonify({"error": str(e), "query": sql}), 500


# [VULNERABILITY: SQL INJECTION] Admin user search with string formatting
@app.route("/api/admin/users/search")
def api_admin_user_search():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] No admin authorization check
    query = request.args.get("q", "")
    with db() as conn:
        try:
            # [VULNERABILITY: SQL INJECTION] Direct string interpolation
            sql = f"SELECT id, username, email, role, is_verified, store_credit FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
            rows = conn.execute(sql).fetchall()
            return jsonify([dict(r) for r in rows])
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# [VULNERABILITY: SQL INJECTION] Product filter with injectable ORDER BY
@app.route("/api/products/filter")
def api_product_filter():
    category = request.args.get("category", "")
    min_price = request.args.get("min_price", "0")
    max_price = request.args.get("max_price", "999999")
    order_by = request.args.get("order_by", "name")
    with db() as conn:
        try:
            # [VULNERABILITY: SQL INJECTION] String formatting in WHERE and ORDER BY
            sql = f"SELECT * FROM products WHERE price >= {min_price} AND price <= {max_price} ORDER BY {order_by}"
            rows = conn.execute(sql).fetchall()
            return jsonify([dict(r) for r in rows])
        except Exception as e:
            return jsonify({"error": str(e), "sql": sql}), 500


# ─── CATEGORY B: XSS (handled via template changes + reflected endpoint) ─────

# [VULNERABILITY: REFLECTED XSS] Renders user input directly in response
@app.route("/api/search/preview")
def api_search_preview():
    q = request.args.get("q", "")
    # [VULNERABILITY: REFLECTED XSS] User input rendered as raw HTML
    html = f"""
    <html><body>
    <h2>Search Results for: {q}</h2>
    <p>No results found for your query.</p>
    <a href="/products?q={q}">Try the full catalogue</a>
    </body></html>
    """
    return html


# ─── CATEGORY C: CSRF (handled via CSRF_EXEMPT_PATHS above) ──────────────────

# [VULNERABILITY: CSRF] Profile update without CSRF protection
@app.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    # [VULNERABILITY: CSRF] No CSRF token validation (exempt path)
    # [VULNERABILITY: BROKEN AUTHENTICATION] Only checks session user_id
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    username = request.form.get("username", "")
    email = request.form.get("email", "")
    with db() as conn:
        conn.execute("UPDATE users SET username=?,email=? WHERE id=?", (username, email, user_id))
        conn.commit()
    return jsonify({"success": True})


# [VULNERABILITY: CSRF] Cart add without CSRF protection
@app.route("/api/cart/add", methods=["POST"])
def api_cart_add():
    # [VULNERABILITY: CSRF] No CSRF token validation
    try:
        pid = request.form.get("product_id", type=int) or int(request.json.get("product_id", 0) if request.is_json else 0)
        qty = request.form.get("quantity", type=int) or int(request.json.get("quantity", 1) if request.is_json else 1)
        cart = session.get("cart", {})
        cart[str(pid)] = int(cart.get(str(pid), 0)) + qty
        session["cart"] = cart
        return jsonify({"success": True, "cart": cart})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ─── CATEGORY D: IDOR ────────────────────────────────────────────────────────

# [VULNERABILITY: IDOR] Order details without ownership verification
@app.route("/api/orders/<int:order_id>")
def api_order_detail(order_id):
    # [VULNERABILITY: IDOR] No authentication or ownership check
    with db() as conn:
        order = conn.execute("SELECT orders.*,users.username,users.email FROM orders JOIN users ON users.id=orders.user_id WHERE orders.id=?", (order_id,)).fetchone()
        if not order:
            return jsonify({"error": "Order not found"}), 404
        items = conn.execute("SELECT oi.*,p.name FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?", (order_id,)).fetchall()
    return jsonify({
        "order": dict(order),
        "items": [dict(i) for i in items]
    })


# [VULNERABILITY: IDOR] User profile without authentication
@app.route("/api/users/<int:user_id>/profile")
def api_user_profile(user_id):
    # [VULNERABILITY: IDOR] No authentication check; direct object reference
    with db() as conn:
        user = conn.execute("SELECT id, username, email, role, is_verified, store_credit FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    # [VULNERABILITY: IDOR] Exposes sensitive user information
    return jsonify(dict(user))


# [VULNERABILITY: IDOR] Cancel order without ownership check
@app.route("/api/orders/<int:order_id>/cancel", methods=["POST"])
def api_order_cancel(order_id):
    # [VULNERABILITY: IDOR] No ownership verification
    # [VULNERABILITY: CSRF] No CSRF protection
    with db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            return jsonify({"error": "Order not found"}), 404
        conn.execute("UPDATE orders SET status='cancelled' WHERE id=?", (order_id,))
        # Refund store credit to the order owner
        conn.execute("UPDATE users SET store_credit=store_credit+? WHERE id=?", (order["total_amount"], order["user_id"]))
        conn.commit()
    return jsonify({"success": True, "message": "Order cancelled and credit refunded"})


# ─── CATEGORY E: BROKEN AUTHENTICATION ───────────────────────────────────────

# [VULNERABILITY: BROKEN AUTHENTICATION] Login without password verification
@app.route("/login/quick", methods=["POST"])
def login_quick():
    username = request.form.get("username", "")
    # [VULNERABILITY: BROKEN AUTHENTICATION] No password check at all
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user:
        # [VULNERABILITY: BROKEN AUTHENTICATION] No verification status check
        # [VULNERABILITY: INSECURE SESSION MANAGEMENT] No session regeneration
        session["user_id"] = user["id"]
        return jsonify({"success": True, "user": user["username"]})
    return jsonify({"error": "User not found"}), 404


# [VULNERABILITY: BROKEN AUTHENTICATION] JSON login with no rate limiting
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    # [VULNERABILITY: BRUTE FORCE] No rate limiting at all
    # [VULNERABILITY: BROKEN AUTHENTICATION] No account lockout check
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        # [VULNERABILITY: BROKEN AUTHENTICATION] No verification check
        session["user_id"] = user["id"]
        return jsonify({"success": True, "user_id": user["id"], "role": user["role"]})
    # [VULNERABILITY: BROKEN AUTHENTICATION] Different errors for user-not-found vs wrong-password
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"error": "Invalid password"}), 401


# ─── CATEGORY F: BROKEN ACCESS CONTROL / PRIVILEGE ESCALATION ────────────────

# [VULNERABILITY: BROKEN ACCESS CONTROL] Admin endpoint checking role from query param
@app.route("/api/admin/users")
def api_admin_users():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] Trusts client-supplied role parameter
    role_param = request.args.get("role", "")
    user = current_user()
    # [VULNERABILITY: BROKEN ACCESS CONTROL] If role=admin in query OR user is admin → allow
    if role_param == "admin":
        pass  # Bypass: anyone can add ?role=admin to gain access
    elif user and user["role"] == "admin":
        pass  # Legitimate admin
    else:
        return jsonify({"error": "Admin access required"}), 403
    with db() as conn:
        users = conn.execute("SELECT id, username, email, role, is_verified, store_credit FROM users ORDER BY id").fetchall()
    return jsonify([dict(u) for u in users])


# [VULNERABILITY: BROKEN ACCESS CONTROL] Admin orders without decorator
@app.route("/api/admin/orders")
def api_admin_orders():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] No @admin_required, no role check
    with db() as conn:
        orders = conn.execute("SELECT orders.*,users.username FROM orders JOIN users ON users.id=orders.user_id ORDER BY orders.id DESC").fetchall()
    return jsonify([dict(o) for o in orders])


# [VULNERABILITY: BROKEN ACCESS CONTROL / PRIVILEGE ESCALATION] Grant admin role
@app.route("/api/admin/grant-admin", methods=["POST"])
def api_grant_admin():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] No authentication required
    # [VULNERABILITY: CSRF] No CSRF protection
    data = request.get_json(silent=True) or request.form
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    with db() as conn:
        conn.execute("UPDATE users SET role='admin' WHERE id=?", (int(user_id),))
        conn.commit()
    return jsonify({"success": True, "message": f"User {user_id} is now admin"})


# ─── CATEGORY G: INSECURE SESSION MANAGEMENT ─────────────────────────────────

# [VULNERABILITY: INSECURE SESSION MANAGEMENT] Session data exposure
@app.route("/api/debug/session")
def api_debug_session():
    # [VULNERABILITY: INSECURE SESSION MANAGEMENT] Exposes all session data
    # [VULNERABILITY: SECURITY MISCONFIGURATION] Debug endpoint
    return jsonify({k: str(v) for k, v in session.items()})


# ─── CATEGORY H: BRUTE FORCE (handled via /login/debug and /api/login) ───────
# Both /login/debug and /api/login have no rate limiting (see above)
# /verify vulnerable path below also lacks attempt restrictions

# [VULNERABILITY: BRUTE FORCE] Verification endpoint without attempt limiting
@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email", "")).strip().lower()
    code = (data.get("code", "")).strip()
    # [VULNERABILITY: BRUTE FORCE] No verification attempt counter
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user["is_verified"]:
            return jsonify({"message": "Already verified"})
        # [VULNERABILITY: BROKEN 2FA LOGIC] No expiration check on code
        # [VULNERABILITY: BRUTE FORCE] No attempt limit
        if user["verification_code"] and code == user["verification_code"]:
            conn.execute("UPDATE users SET is_verified=1, verification_code=NULL WHERE id=?", (user["id"],))
            conn.commit()
            return jsonify({"success": True})
        return jsonify({"error": "Invalid code"}), 400


# ─── CATEGORY I: OPEN REDIRECT ───────────────────────────────────────────────

# [VULNERABILITY: OPEN REDIRECT] Arbitrary URL redirect
@app.route("/redirect")
def open_redirect():
    # [VULNERABILITY: OPEN REDIRECT] No validation of redirect target
    url = request.args.get("url", "/")
    return redirect(url)


# ─── CATEGORY J: BUSINESS LOGIC VULNERABILITIES ──────────────────────────────

# [VULNERABILITY: BUSINESS LOGIC] Checkout that doesn't enforce business rules
@app.route("/api/checkout", methods=["POST"])
def api_checkout():
    # [VULNERABILITY: BROKEN AUTHENTICATION] Only checks session user_id presence
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    coupon_code = data.get("coupon", (request.form.get("coupon") or "")).strip().upper()
    # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Accept client-submitted price
    client_total = data.get("total") or request.form.get("total")
    # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Accept client-submitted discount
    client_discount = data.get("discount") or request.form.get("discount")

    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        items = cart_items(conn)
        if not items:
            return jsonify({"error": "Cart is empty"}), 400

        # [VULNERABILITY: BUSINESS LOGIC] Server calculates subtotal but accepts client override
        subtotal = round(sum(p["price"] * q for p, q in items), 2)

        discount = 0
        if coupon_code:
            coupon = conn.execute("SELECT * FROM coupons WHERE code=?", (coupon_code,)).fetchone()
            if coupon:
                # [VULNERABILITY: BUSINESS LOGIC / FLAWED BUSINESS RULE ENFORCEMENT]
                # No check on is_used, usage_count, max_uses, expiry, assigned_email, or min_purchase
                discount = round(subtotal * coupon["discount_percent"] / 100, 2)
            # Coupon not found is silently ignored

        if client_discount:
            # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Accept client discount
            try:
                discount = float(client_discount)
            except (ValueError, TypeError):
                pass

        # [VULNERABILITY: BUSINESS LOGIC] Use client total if provided
        if client_total:
            # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS]
            try:
                total = float(client_total)
            except (ValueError, TypeError):
                total = round(subtotal - discount, 2)
        else:
            total = round(subtotal - discount, 2)

        # [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING] Negative totals accepted
        # [VULNERABILITY: BUSINESS LOGIC] No validation that total >= 0

        # [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] No stock validation
        order_id = conn.execute(
            "INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
            (user_id, total, coupon_code, "paid", now().isoformat())
        ).lastrowid

        for product, quantity in items:
            # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Accept client price
            client_price = data.get(f"price_{product['id']}")
            unit_price = float(client_price) if client_price else product["price"]
            conn.execute(
                "INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)",
                (order_id, product["id"], quantity, unit_price)
            )
            conn.execute("UPDATE products SET stock=stock-? WHERE id=?", (quantity, product["id"]))

        # [VULNERABILITY: BUSINESS LOGIC] Mark coupon used but don't check usage properly
        if coupon_code:
            conn.execute("UPDATE coupons SET usage_count=usage_count+1 WHERE code=?", (coupon_code,))

        # [VULNERABILITY: BUSINESS LOGIC] Deduct potentially negative total from credit
        conn.execute("UPDATE users SET store_credit=store_credit-? WHERE id=?", (total, user_id))
        conn.commit()

    session["cart"] = {}
    return jsonify({"success": True, "order_id": order_id, "total": total})


# [VULNERABILITY: BUSINESS LOGIC] Apply store credit with client-submitted amount
@app.route("/api/apply-store-credit", methods=["POST"])
def api_apply_store_credit():
    # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Trusts client credit amount
    data = request.get_json(silent=True) or request.form
    user_id = data.get("user_id") or session.get("user_id")
    amount = data.get("amount", 0)
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid amount"}), 400
    # [VULNERABILITY: IDOR] Uses client-submitted user_id
    # [VULNERABILITY: BUSINESS LOGIC] No validation on amount sign or magnitude
    with db() as conn:
        conn.execute("UPDATE users SET store_credit=store_credit+? WHERE id=?", (amount, int(user_id)))
        conn.commit()
    return jsonify({"success": True, "added": amount})


# [VULNERABILITY: BUSINESS LOGIC] Cart update accepting negative quantities
@app.route("/api/cart/update", methods=["POST"])
def api_cart_update():
    data = request.get_json(silent=True) or request.form
    cart = session.get("cart", {})
    # [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING] No validation on quantities
    # [VULNERABILITY: BUSINESS LOGIC] Negative quantities accepted
    for key, value in data.items():
        if key.startswith("qty_") or key.startswith("product_"):
            pid = key.split("_")[-1]
            try:
                qty = int(value)
                # [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING] Negative/zero values accepted
                cart[str(pid)] = qty
            except (ValueError, TypeError):
                pass
        elif key == "items" and isinstance(value, dict):
            for pid, qty in value.items():
                cart[str(pid)] = int(qty)
    session["cart"] = cart
    return jsonify({"success": True, "cart": cart})


# [VULNERABILITY: BUSINESS LOGIC] Apply coupon without proper validation
@app.route("/api/apply-coupon", methods=["POST"])
def api_apply_coupon():
    # [VULNERABILITY: CSRF] No CSRF protection
    data = request.get_json(silent=True) or request.form
    code = (data.get("code", "")).strip().upper()
    if not code:
        return jsonify({"error": "No coupon code provided"}), 400
    with db() as conn:
        coupon = conn.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
        if not coupon:
            return jsonify({"error": "Coupon not found"}), 404
        # [VULNERABILITY: BUSINESS LOGIC / FLAWED BUSINESS RULE ENFORCEMENT]
        # Returns full coupon details including discount without checking any restrictions
        return jsonify({
            "valid": True,
            "code": coupon["code"],
            "discount_percent": coupon["discount_percent"],
            "is_used": coupon["is_used"],
            "usage_count": coupon["usage_count"],
            "max_uses": coupon["max_uses"],
            "assigned_email": coupon["assigned_email"],
        })


# ─── CATEGORY K: SECURITY MISCONFIGURATION ───────────────────────────────────

# [VULNERABILITY: SECURITY MISCONFIGURATION] Debug config exposure
@app.route("/api/debug/config")
def api_debug_config():
    # [VULNERABILITY: SECURITY MISCONFIGURATION] Exposes application configuration
    config_data = {}
    for key in app.config:
        try:
            config_data[key] = str(app.config[key])
        except Exception:
            config_data[key] = "<unserializable>"
    return jsonify(config_data)


# [VULNERABILITY: SECURITY MISCONFIGURATION] Database info exposure
@app.route("/api/debug/db")
def api_debug_db():
    # [VULNERABILITY: SECURITY MISCONFIGURATION] Exposes database schema
    with db() as conn:
        tables = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
    return jsonify([{"name": t["name"], "sql": t["sql"]} for t in tables])


# [VULNERABILITY: SECURITY MISCONFIGURATION] Environment info exposure
@app.route("/api/debug/env")
def api_debug_env():
    # [VULNERABILITY: SECURITY MISCONFIGURATION] Exposes environment variables
    return jsonify({
        "debug": app.config.get("DEBUG", False),
        "secret_key_prefix": app.config.get("SECRET_KEY", "")[:10],
        "secret_key_length": len(app.config.get("SECRET_KEY", "")),
        "database_path": str(DB_PATH),
        "python_path": str(Path(__file__).resolve()),
        "base_dir": str(BASE_DIR),
    })


# ─── CATEGORY L: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS ─────────────────────
# (Handled in /api/checkout, /api/apply-store-credit, /profile above)


# ─── CATEGORY M: FLAWED BUSINESS RULE ENFORCEMENT ────────────────────────────
# (Handled in /api/checkout, /api/apply-coupon, /api/cart/update above)


# ─── CATEGORY N: INCONSISTENT EXCEPTIONAL INPUT HANDLING ─────────────────────

# [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING] Quantity endpoint
@app.route("/api/cart/set-quantity", methods=["POST"])
def api_cart_set_quantity():
    data = request.get_json(silent=True) or request.form
    product_id = data.get("product_id", "")
    quantity = data.get("quantity", "")
    # [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING]
    # Accepts negative, zero, decimal, extremely large values without validation
    try:
        qty = float(quantity)  # Accepts decimals
        cart = session.get("cart", {})
        cart[str(product_id)] = qty  # May be negative, zero, decimal, huge
        session["cart"] = cart
        return jsonify({"success": True, "product_id": product_id, "quantity": qty})
    except (ValueError, TypeError):
        # [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING] Missing param → default to 1
        cart = session.get("cart", {})
        cart[str(product_id)] = 1
        session["cart"] = cart
        return jsonify({"success": True, "product_id": product_id, "quantity": 1, "note": "defaulted to 1"})


# ─── CATEGORY O: INSUFFICIENT WORKFLOW VALIDATION ────────────────────────────

# [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] Direct order confirmation
@app.route("/api/order/confirm", methods=["POST"])
def api_order_confirm():
    # [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] Creates order without payment/cart validation
    data = request.get_json(silent=True) or request.form
    user_id = data.get("user_id") or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    total = data.get("total", 0)
    # [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] Skips checkout, payment, stock validation
    # [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS] Trusts client total
    with db() as conn:
        order_id = conn.execute(
            "INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
            (int(user_id), float(total), "", "paid", now().isoformat())
        ).lastrowid
        conn.commit()
    return jsonify({"success": True, "order_id": order_id, "total": total})


# [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] Direct order status view
@app.route("/api/orders/latest")
def api_orders_latest():
    # [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION] Can view orders without completing checkout
    # [VULNERABILITY: IDOR] No user ownership check
    with db() as conn:
        orders = conn.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 10").fetchall()
    return jsonify([dict(o) for o in orders])


# ─── CATEGORY P: BROKEN 2FA LOGIC ────────────────────────────────────────────

# [VULNERABILITY: BROKEN 2FA LOGIC] Two-factor authentication flow
@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "POST":
        data = request.form if request.form else (request.get_json(silent=True) or {})
        email = (data.get("email", "")).strip().lower()
        code = (data.get("code", "")).strip()
        target_email = data.get("target_email", "").strip().lower()  # For testing binding

        with db() as conn:
            # [VULNERABILITY: BROKEN 2FA LOGIC] Determine which user to verify
            if target_email:
                # [VULNERABILITY: BROKEN 2FA LOGIC] Code not bound to specific user
                user = conn.execute("SELECT * FROM users WHERE email=?", (target_email,)).fetchone()
            else:
                user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            if not user:
                flash("User not found.", "danger")
                return render_template("verify.html", email=email)

            # [VULNERABILITY: BROKEN 2FA LOGIC] Session set BEFORE 2FA verification
            session["user_id"] = user["id"]
            session["2fa_pending_user_id"] = user["id"]

            # [VULNERABILITY: BROKEN 2FA LOGIC] Empty code accepted as valid
            if not code:
                flash("Verification skipped — empty code accepted.", "success")
                return redirect(url_for("index"))

            # [VULNERABILITY: BROKEN 2FA LOGIC] No expiration check
            # [VULNERABILITY: BROKEN 2FA LOGIC] No attempt limiting
            # [VULNERABILITY: BROKEN 2FA LOGIC] Reused codes accepted (code not nullified)
            stored_code = user["verification_code"]
            if stored_code and code == stored_code:
                # [VULNERABILITY: BROKEN 2FA LOGIC] Code NOT invalidated after use
                flash("Two-factor verification successful.", "success")
                return redirect(url_for("index"))

            flash("Invalid verification code.", "danger")
            # [VULNERABILITY: BROKEN 2FA LOGIC] Session remains set even after failure

    email = request.args.get("email", "")
    return render_template("verify.html", email=email)


# ─── ADDITIONAL VULNERABLE ENDPOINTS ─────────────────────────────────────────

# [VULNERABILITY: OPEN REDIRECT] Registration redirect
@app.route("/register/complete")
def register_complete():
    # [VULNERABILITY: OPEN REDIRECT] Trusts return_to parameter
    return_to = request.args.get("return_to", url_for("login"))
    flash("Registration complete! Please sign in.", "success")
    return redirect(return_to)


# [VULNERABILITY: BROKEN ACCESS CONTROL] Admin product management without decorator
@app.route("/api/admin/products", methods=["GET", "POST"])
def api_admin_products():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] No @admin_required, no role verification
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        name = data.get("name", "")
        description = data.get("description", "")
        price = data.get("price", 0)
        stock = data.get("stock", 0)
        # [VULNERABILITY: BUSINESS LOGIC] No input validation
        # [VULNERABILITY: STORED XSS] Product name and description not sanitized
        with db() as conn:
            conn.execute("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)",
                         (name, description, float(price), int(stock), ""))
            conn.commit()
        return jsonify({"success": True})
    with db() as conn:
        products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return jsonify([dict(p) for p in products])


# [VULNERABILITY: BROKEN ACCESS CONTROL] Admin coupon management without decorator
@app.route("/api/admin/coupons", methods=["GET", "POST"])
def api_admin_coupons():
    # [VULNERABILITY: BROKEN ACCESS CONTROL] No authentication required
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        code = data.get("code", "").upper()
        discount = int(data.get("discount", 10))
        with db() as conn:
            conn.execute("INSERT INTO coupons(code,discount_percent,is_used,usage_count,max_uses,min_purchase) VALUES (?,?,0,0,?,?)",
                         (code, discount, int(data.get("max_uses", 999)), 0))
            conn.commit()
        return jsonify({"success": True, "code": code})
    with db() as conn:
        coupons = conn.execute("SELECT * FROM coupons ORDER BY id DESC").fetchall()
    return jsonify([dict(c) for c in coupons])

migrate_database()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
