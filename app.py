import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secureshop.db"
UPLOAD_DIR, DEMO_DIR = BASE_DIR / "test_files", BASE_DIR / "demo_files"
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production")

def db():
    conn = sqlite3.connect(app.config.get("DATABASE_PATH", str(DB_PATH)), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now():
    return datetime.now(timezone.utc)

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
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(coupons)")}
        for name, definition in {"expires_at": "TEXT", "max_uses": "INTEGER NOT NULL DEFAULT 1",
                                 "min_purchase": "REAL NOT NULL DEFAULT 0"}.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE coupons ADD COLUMN {name} {definition}")
        # One-time safe upgrade from this project's former plaintext demo data.
        for user in conn.execute("SELECT id,password_hash FROM users"):
            if not user["password_hash"].startswith(("pbkdf2:", "scrypt:")):
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(user["password_hash"]), user["id"]))
        conn.commit()

def current_user():
    if not session.get("user_id"):
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

def audit(event, user_id=None, detail=""):
    with db() as conn:
        conn.execute("INSERT INTO audit_events(event,user_id,detail,ip,created_at) VALUES (?,?,?,?,?)",
                     (event, user_id, detail[:500], request.remote_addr, now().isoformat()))
        conn.commit()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

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

def money(raw):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError("Enter a valid amount.")
    if value < 0 or value > 1_000_000:
        raise ValueError("Enter an amount between 0 and 1,000,000.")
    return round(value, 2)

def positive_int(raw, label="quantity", maximum=999):
    try:
        number = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"Enter a valid {label}.")
    if not 1 <= number <= maximum:
        raise ValueError(f"{label.capitalize()} must be between 1 and {maximum}.")
    return number

def validate_email(email):
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter a valid email address.")
    return email

def validate_username(username):
    username = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise ValueError("Username must be 3–32 letters, numbers, dots, dashes, or underscores.")
    return username

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
        products = {p["id"]: p for p in conn.execute(
            "SELECT * FROM products WHERE id IN (" + ",".join("?" for _ in ids) + ")", ids)}
        return [(products[pid], int(cart[str(pid)])) for pid in ids if pid in products]
    finally:
        if close:
            conn.close()

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
    if expired or assigned or coupon["is_used"] or coupon["usage_count"] >= coupon["max_uses"] or subtotal < coupon["min_purchase"]:
        return None, "This coupon is not eligible for this order."
    return coupon, None

@app.before_request
def csrf_protection():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
            abort(400)

@app.context_processor
def context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    cart = session.get("cart", {})
    return {"current_user": current_user(), "csrf_token": session["csrf_token"],
            "cart_count": sum(int(v) for v in cart.values() if str(v).isdigit())}

@app.route("/")
def index():
    with db() as conn:
        products = conn.execute("SELECT * FROM products WHERE stock > 0 ORDER BY id LIMIT 4").fetchall()
    return render_template("index.html", products=products)

@app.route("/products")
def products():
    query = request.args.get("q", "").strip()
    with db() as conn:
        if query:
            like = f"%{query}%"
            rows = conn.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY name", (like, like)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("products.html", products=rows, query=query)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    with db() as conn:
        product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        reviews = conn.execute("SELECT r.*,u.username FROM reviews r LEFT JOIN users u ON u.id=r.user_id WHERE r.product_id=? ORDER BY r.id DESC", (product_id,)).fetchall()
    if not product:
        abort(404)
    return render_template("product.html", product=product, reviews=reviews)

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
            conn.execute("INSERT INTO reviews(product_id,user_id,body,created_at) VALUES (?,?,?,?)",
                         (product_id, current_user()["id"], body, now().isoformat()))
            conn.commit()
        flash("Thanks for sharing your review.", "success")
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    form_data = {"username": "", "email": ""}
    if request.method == "POST":
        form_data = {"username": (request.form.get("username") or "").strip(),
                     "email": (request.form.get("email") or "").strip()}
        try:
            username, email = validate_username(request.form.get("username")), validate_email(request.form.get("email"))
            password = request.form.get("password", "")
            if len(password) < 10 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
                raise ValueError("Use a password of at least 10 characters with letters and numbers.")
            confirmation_code = secrets.token_urlsafe(18)
            with db() as conn:
                conn.execute("INSERT INTO users(username,email,password_hash,role,is_verified,verification_code,store_credit,failed_attempts,device_id) VALUES (?,?,?,?,?,?,?,?,?)",
                    (username, email, generate_password_hash(password), "user", 0, confirmation_code, 500.0, 0, ""))
                conn.commit()
            flash(f"Your account was created. Save this one-time confirmation code: {confirmation_code}", "success")
            return redirect(url_for("verify", email=email))
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("That username or email is already unavailable." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    return render_template("register.html", form_data=form_data)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = request.args.get("email", "") or request.form.get("email", "")
    if request.method == "POST":
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()
            if user and user["verification_code"] and hmac.compare_digest(request.form.get("code", ""), user["verification_code"]):
                conn.execute("UPDATE users SET is_verified=1,verification_code=NULL WHERE id=?", (user["id"],))
                conn.commit()
                flash("Your account is confirmed. You can now sign in.", "success")
                return redirect(url_for("login"))
        flash("That confirmation code is invalid or has already been used.", "danger")
    return render_template("verify.html", email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                if not user["is_verified"]:
                    flash("Confirm your account before signing in.", "warning")
                    return redirect(url_for("verify", email=user["email"]))
                session.clear()
                session["user_id"], session["csrf_token"] = user["id"], secrets.token_urlsafe(32)
                conn.execute("UPDATE users SET failed_attempts=0,last_login_ip=? WHERE id=?", (request.remote_addr, user["id"]))
                conn.commit()
                audit("login", user["id"], "successful login")
                flash(f"Welcome back, {user['username']}!", "success")
                target = request.args.get("next", "")
                return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("index"))
            if user:
                conn.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE id=?", (user["id"],))
                conn.commit()
        audit("failed_login", None, username)
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", current_user()["id"])
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        try:
            username, email = validate_username(request.form.get("username")), validate_email(request.form.get("email"))
            with db() as conn:
                conn.execute("UPDATE users SET username=?,email=? WHERE id=?", (username, email, user["id"]))
                conn.commit()
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("That username or email is already unavailable." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    with db() as conn:
        orders = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 5", (user["id"],)).fetchall()
    return render_template("profile.html", user=current_user(), orders=orders)

@app.route("/cart")
def cart():
    items = cart_items()
    return render_template("cart.html", items=items, total=sum(p["price"] * q for p, q in items))

@app.route("/cart/add", methods=["POST"])
def cart_add():
    try:
        pid, quantity = int(request.form.get("product_id", "")), positive_int(request.form.get("quantity", 1))
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
    return redirect(request.referrer or url_for("products"))

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
                    if quantity: cart[str(pid)] = quantity
                    else: cart.pop(str(pid), None)
        session["cart"] = cart
        flash("Your cart has been updated.", "success")
    except (ValueError, TypeError):
        flash("Cart quantities must be between zero and the available stock.", "danger")
    return redirect(url_for("cart"))

@app.route("/cart/remove", methods=["POST"])
def cart_remove():
    cart = session.get("cart", {})
    cart.pop(request.form.get("product_id", ""), None)
    session["cart"] = cart
    flash("Item removed from your cart.", "success")
    return redirect(url_for("cart"))

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    user = current_user()
    if request.method == "POST":
        try:
            with db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                fresh_user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                items = cart_items(conn)
                if not items: raise ValueError("Your cart is empty.")
                subtotal = round(sum(p["price"] * q for p, q in items), 2)
                for product, quantity in items:
                    live = conn.execute("SELECT stock FROM products WHERE id=?", (product["id"],)).fetchone()
                    if not live or not 1 <= quantity <= live["stock"]:
                        raise ValueError(f"{product['name']} no longer has enough stock.")
                coupon, coupon_error = eligible_coupon(conn, request.form.get("coupon"), fresh_user, subtotal)
                if coupon_error: raise ValueError(coupon_error)
                discount = round(subtotal * coupon["discount_percent"] / 100, 2) if coupon else 0
                total = round(subtotal - discount, 2)
                if fresh_user["store_credit"] + 1e-9 < total:
                    raise ValueError("Your store credit is insufficient for this order.")
                order_id = conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)",
                    (user["id"], total, coupon["code"] if coupon else "", "paid", now().isoformat())).lastrowid
                for product, quantity in items:
                    conn.execute("INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)",
                                 (order_id, product["id"], quantity, product["price"]))
                    conn.execute("UPDATE products SET stock=stock-? WHERE id=?", (quantity, product["id"]))
                if coupon and conn.execute("UPDATE coupons SET usage_count=usage_count+1,is_used=CASE WHEN usage_count+1>=max_uses THEN 1 ELSE 0 END WHERE id=? AND usage_count<max_uses", (coupon["id"],)).rowcount != 1:
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

@app.route("/orders")
@login_required
def orders():
    with db() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (current_user()["id"],)).fetchall()
    return render_template("orders.html", orders=rows)

@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    user = current_user()
    with db() as conn:
        if user["role"] == "admin":
            order = conn.execute("SELECT orders.*,users.username FROM orders JOIN users ON users.id=orders.user_id WHERE orders.id=?", (order_id,)).fetchone()
        else:
            order = conn.execute("SELECT orders.*,users.username FROM orders JOIN users ON users.id=orders.user_id WHERE orders.id=? AND orders.user_id=?", (order_id, user["id"])).fetchone()
        items = conn.execute("SELECT oi.*,p.name FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?", (order_id,)).fetchall() if order else []
    if not order: abort(404)
    return render_template("order.html", order=order, items=items)

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

@app.route("/admin")
@admin_required
def admin():
    with db() as conn:
        stats = {key: conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
                 for key, table in {"users": "users", "orders": "orders", "products": "products"}.items()}
    return render_template("admin.html", stats=stats)

@app.route("/admin/users")
@admin_required
def admin_users():
    with db() as conn:
        users = conn.execute("SELECT id,username,email,role,is_verified,store_credit FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/<int:user_id>", methods=["POST"])
@admin_required
def admin_user_update(user_id):
    try:
        role, credit = request.form.get("role"), money(request.form.get("store_credit"))
        if role not in {"user", "admin"}: raise ValueError("Choose a valid role.")
        if user_id == current_user()["id"] and role != "admin": raise ValueError("You cannot remove your own administrator access.")
        with db() as conn:
            conn.execute("UPDATE users SET role=?,store_credit=?,is_verified=? WHERE id=?",
                         (role, credit, 1 if request.form.get("is_verified") else 0, user_id))
            conn.commit()
        flash("User account updated.", "success")
    except ValueError as exc: flash(str(exc), "danger")
    return redirect(url_for("admin_users"))

def product_values():
    name, description = (request.form.get("name") or "").strip(), (request.form.get("description") or "").strip()
    if not name or len(name) > 120 or len(description) > 2000: raise ValueError("Use a product name and a description within the allowed length.")
    try:
        stock = int(request.form.get("stock"))
    except (TypeError, ValueError):
        raise ValueError("Enter a valid stock quantity.")
    if not 0 <= stock <= 100000:
        raise ValueError("Stock must be between 0 and 100,000.")
    return name, description, money(request.form.get("price")), stock, secure_filename(request.form.get("image_filename", ""))

@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if request.method == "POST":
        try:
            with db() as conn: conn.execute("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)", product_values()); conn.commit()
            flash("Product created.", "success")
        except ValueError as exc: flash(str(exc), "danger")
    with db() as conn: rows = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("admin_products.html", products=rows)

@app.route("/admin/products/<int:product_id>", methods=["POST"])
@admin_required
def admin_product_update(product_id):
    try:
        with db() as conn: conn.execute("UPDATE products SET name=?,description=?,price=?,stock=?,image_filename=? WHERE id=?", (*product_values(), product_id)); conn.commit()
        flash("Product updated.", "success")
    except ValueError as exc: flash(str(exc), "danger")
    return redirect(url_for("admin_products"))

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

def coupon_values():
    code = (request.form.get("code") or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9_-]{4,32}", code): raise ValueError("Coupon codes use 4–32 uppercase letters, numbers, dashes, or underscores.")
    email = (request.form.get("email") or "").strip().lower()
    expiry = (request.form.get("expires_at") or "").strip()
    if email: email = validate_email(email)
    if expiry: expiry = datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc).isoformat()
    return code, positive_int(request.form.get("discount"), "discount", 100), email, expiry, positive_int(request.form.get("max_uses", 1), "maximum uses", 100000), money(request.form.get("min_purchase", 0))

@app.route("/admin/coupons", methods=["GET", "POST"])
@admin_required
def admin_coupons():
    if request.method == "POST":
        try:
            code, discount, email, expiry, maximum, minimum = coupon_values()
            with db() as conn: conn.execute("INSERT INTO coupons(code,discount_percent,is_used,usage_count,assigned_email,expires_at,max_uses,min_purchase) VALUES (?,?,0,0,?,?,?,?)", (code, discount, email, expiry, maximum, minimum)); conn.commit()
            flash("Coupon created.", "success")
        except (ValueError, sqlite3.IntegrityError) as exc: flash("Coupon code already exists." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    with db() as conn: rows = conn.execute("SELECT * FROM coupons ORDER BY id DESC").fetchall()
    return render_template("admin_coupons.html", coupons=rows)

@app.route("/admin/coupons/<int:coupon_id>", methods=["POST"])
@admin_required
def admin_coupon_update(coupon_id):
    try:
        code, discount, email, expiry, maximum, minimum = coupon_values()
        with db() as conn: conn.execute("UPDATE coupons SET code=?,discount_percent=?,assigned_email=?,expires_at=?,max_uses=?,min_purchase=?,is_used=CASE WHEN usage_count>=? THEN 1 ELSE 0 END WHERE id=?", (code, discount, email, expiry, maximum, minimum, maximum, coupon_id)); conn.commit()
        flash("Coupon updated.", "success")
    except (ValueError, sqlite3.IntegrityError) as exc: flash("Coupon code already exists." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    return redirect(url_for("admin_coupons"))

@app.route("/admin/coupons/<int:coupon_id>/delete", methods=["POST"])
@admin_required
def admin_coupon_delete(coupon_id):
    with db() as conn: conn.execute("DELETE FROM coupons WHERE id=?", (coupon_id,)); conn.commit()
    flash("Coupon removed.", "success")
    return redirect(url_for("admin_coupons"))

def safe_file(directory, name):
    candidate = (directory / secure_filename(name)).resolve()
    if candidate.parent != directory.resolve() or not candidate.is_file(): abort(404)
    return candidate

@app.route("/files")
def files(): return send_file(safe_file(UPLOAD_DIR, request.args.get("name", "")))
@app.route("/download")
def download(): return send_file(safe_file(DEMO_DIR, request.args.get("name", "")))

@app.errorhandler(400)
def bad_request(error): return render_template("error.html", title="Request could not be completed", message="Your request was invalid or your form expired. Please go back and try again."), 400
@app.errorhandler(403)
def forbidden(error): return render_template("error.html", title="Access denied", message="You do not have permission to view this page."), 403
@app.errorhandler(404)
def not_found(error): return render_template("error.html", title="Page not found", message="The page or item you requested is unavailable."), 404
@app.errorhandler(500)
def internal_error(error): return render_template("error.html", title="Something went wrong", message="Please try again in a moment."), 500

migrate_database()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
