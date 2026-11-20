import os
import sqlite3
import secrets
import hashlib
import math
import statistics
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify, send_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secureshop.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "test_files")

app = Flask(__name__)
app.secret_key = "secureshop-naive-development-key"
app.config.update(SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_SAMESITE=None)

def db():
    conn = sqlite3.connect(app.config.get("DATABASE_PATH", DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def audit(event, user_id=None, detail=""):
    with db() as conn:
        conn.execute("INSERT INTO audit_events(event,user_id,detail,ip,created_at) VALUES (?,?,?,?,?)", (event, user_id, detail, request.remote_addr, datetime.utcnow().isoformat()))
        conn.commit()

def haversine_km(lat1, lon1, lat2, lon2):
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2-lat1), math.radians(lon2-lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

@app.context_processor
def inject_user():
    return {"current_user": current_user(), "cart_count": sum(session.get("cart", {}).values()) if session.get("cart") else 0}

@app.route("/")
def index():
    with db() as conn:
        products = conn.execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("index.html", products=products)

@app.route("/products")
def products():
    query = request.args.get("q", "")
    with db() as conn:
        # [INTENTIONAL-VULNERABILITY: SQL Injection - naive search concatenates untrusted input]
        if query:
            rows = conn.execute("SELECT * FROM products WHERE name LIKE '%" + query + "%' OR description LIKE '%" + query + "%'").fetchall()
        else:
            rows = conn.execute("SELECT * FROM products").fetchall()
    return render_template("products.html", products=rows, query=query)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    with db() as conn:
        product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        reviews = conn.execute("SELECT r.*,u.username FROM reviews r LEFT JOIN users u ON u.id=r.user_id WHERE product_id=? ORDER BY r.id DESC", (product_id,)).fetchall()
    if not product:
        return "Product not found", 404
    return render_template("product.html", product=product, reviews=reviews)

@app.route("/product/<int:product_id>/review", methods=["POST"])
def review(product_id):
    user = current_user()
    if not user:
        flash("Please log in to review products.", "warning"); return redirect(url_for("login"))
    with db() as conn:
        conn.execute("INSERT INTO reviews(product_id,user_id,body,created_at) VALUES (?,?,?,?)", (product_id, user["id"], request.form.get("body", ""), datetime.utcnow().isoformat()))
        conn.commit()
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username, email, password = request.form.get("username", ""), request.form.get("email", ""), request.form.get("password", "")
        # [INTENTIONAL-VULNERABILITY: Password Storage - plaintext credentials are stored]
        code = str((len(username) * 1000 + len(email)) % 10000).zfill(4)
        try:
            with db() as conn:
                conn.execute("INSERT INTO users(username,email,password_hash,role,is_verified,verification_code,store_credit,failed_attempts,device_id) VALUES (?,?,?,?,?,?,?,?,?)", (username,email,password,"user",0,code,500.0,0,request.form.get("device_id", "")))
                conn.commit()
            flash("Account created. Your verification code is " + code, "success")
            return redirect(url_for("verify", email=email))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
    return render_template("register.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = request.args.get("email", "") or request.form.get("email", "")
    if request.method == "POST":
        code = request.form.get("code", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            # [INTENTIONAL-VULNERABILITY: Account Verification - predictable code, no expiry or attempt limit]
            if user and code == user["verification_code"]:
                conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (user["id"],)); conn.commit(); flash("Account verified.", "success"); return redirect(url_for("login"))
        flash("Invalid verification code.", "danger")
    return render_template("verify.html", email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form.get("username", ""), request.form.get("password", "")
        with db() as conn:
            # [INTENTIONAL-VULNERABILITY: SQL Injection - login query is assembled from user input]
            sql = "SELECT * FROM users WHERE username='" + username + "' AND password_hash='" + password + "'"
            try:
                user = conn.execute(sql).fetchone()
            except sqlite3.Error as exc:
                return render_template("error.html", error=str(exc)), 500
            if user:
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["device_id"] = request.form.get("device_id", "")
                conn.execute("UPDATE users SET last_login_ip=? WHERE id=?", (request.remote_addr, user["id"])); conn.commit()
                audit("login", user["id"], "successful login")
                flash("Welcome back, " + user["username"] + "!", "success")
                return redirect(url_for("index"))
            audit("failed_login", None, username)
            flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    audit("logout", session.get("user_id")); session.clear(); return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user: return redirect(url_for("login"))
    if request.method == "POST":
        with db() as conn:
            conn.execute("UPDATE users SET username=?,email=? WHERE id=?", (request.form.get("username", user["username"]), request.form.get("email", user["email"]), user["id"])); conn.commit()
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

def cart_items():
    cart = session.get("cart", {})
    if not cart: return []
    ids = [int(x) for x in cart]
    placeholders = ",".join("?" for _ in ids)
    with db() as conn:
        rows = conn.execute("SELECT * FROM products WHERE id IN (" + placeholders + ")", ids).fetchall()
    return [(p, cart.get(str(p["id"]), 0)) for p in rows]

@app.route("/cart")
def cart():
    return render_template("cart.html", items=cart_items())

@app.route("/cart/add", methods=["POST"])
def cart_add():
    pid = request.form.get("product_id", "")
    cart = session.setdefault("cart", {})
    cart[pid] = cart.get(pid, 0) + int(request.form.get("quantity", 1)); session.modified=True
    return redirect(url_for("cart"))

@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart = session.setdefault("cart", {})
    for key, value in request.form.items():
        if key.startswith("qty_"):
            # [INTENTIONAL-VULNERABILITY: Quantity Manipulation - negative/zero/huge quantities accepted]
            cart[key[4:]] = int(value)
    session.modified=True; return redirect(url_for("cart"))

@app.route("/cart/remove", methods=["POST"])
def cart_remove():
    session.get("cart", {}).pop(request.form.get("product_id", ""), None); session.modified=True; return redirect(url_for("cart"))

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    user = current_user()
    if not user: return redirect(url_for("login"))
    items = cart_items()
    if request.method == "POST" and request.form.get("product_id"):
        with db() as conn:
            product = conn.execute("SELECT * FROM products WHERE id=?", (request.form.get("product_id"),)).fetchone()
        if product:
            items = [(product, int(request.form.get("quantity", 1)))]
    if request.method == "POST":
        if request.form.get("total") is not None:
            total = float(request.form.get("total", "0"))
        elif request.form.get("unit_price") is not None:
            total = float(request.form.get("unit_price")) * int(request.form.get("quantity", 1))
        else:
            total = 0.0
        coupon = request.form.get("coupon", "")
        with db() as conn:
            c = conn.execute("SELECT * FROM coupons WHERE code=?", (coupon,)).fetchone() if coupon else None
            if c: total = total * (100 - c["discount_percent"]) / 100
            # [INTENTIONAL-VULNERABILITY: Price Manipulation - client supplied total is trusted]
            cur = conn.execute("INSERT INTO orders(user_id,total_amount,coupon_used,status,created_at) VALUES (?,?,?,?,?)", (user["id"],total,coupon,"created",datetime.utcnow().isoformat()))
            oid = cur.lastrowid
            for p, qty in items:
                # [INTENTIONAL-VULNERABILITY: Business Logic - client-controlled negative quantities reach order items]
                conn.execute("INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)", (oid,p["id"],qty,request.form.get("price_"+str(p["id"]), p["price"])))
            if c:
                # [INTENTIONAL-VULNERABILITY: Coupon Race - read/update is not atomic]
                conn.execute("UPDATE coupons SET is_used=1, usage_count=usage_count+1 WHERE id=?", (c["id"],))
            conn.commit()
        audit("order_created", user["id"], str(oid)); session["cart"]={}
        if request.form.get("product_id"):
            return jsonify({"order_id": oid, "total": total}), 200
        return redirect(url_for("order_detail", order_id=oid))
    total = sum(p["price"] * qty for p, qty in items)
    return render_template("checkout.html", items=items, total=total)

@app.route("/orders")
def orders():
    user = current_user()
    if not user: return redirect(url_for("login"))
    with db() as conn: rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return render_template("orders.html", orders=rows)

@app.route("/orders/<int:order_id>")
def order_detail(order_id):
    user = current_user()
    if not user: return redirect(url_for("login"))
    with db() as conn:
        # [INTENTIONAL-VULNERABILITY: IDOR - ownership is not checked]
        order = conn.execute("SELECT orders.*, users.username FROM orders LEFT JOIN users ON users.id=orders.user_id WHERE orders.id=?", (order_id,)).fetchone()
        items = conn.execute("SELECT oi.*,p.name FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE order_id=?", (order_id,)).fetchall()
    if not order: return "Order not found",404
    return render_template("order.html", order=order, items=items)

@app.route("/newsletter", methods=["GET", "POST"])
def newsletter():
    if request.method == "POST": flash("Thanks for subscribing.", "success")
    return render_template("newsletter.html")

@app.route("/admin")
def admin():
    # [INTENTIONAL-VULNERABILITY: Broken Access Control - role from client session is trusted]
    if session.get("role") != "admin": return "Admin dashboard", 200
    with db() as conn: stats = {"users":conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],"orders":conn.execute("SELECT COUNT(*) c FROM orders").fetchone()["c"]}
    return render_template("admin.html", stats=stats)

@app.route("/admin/users")
def admin_users():
    # [INTENTIONAL-VULNERABILITY: Missing Authorization - sensitive route lacks an auth check]
    with db() as conn: users = conn.execute("SELECT id,username,email,role,is_verified,store_credit FROM users").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/products", methods=["GET", "POST"])
def admin_products():
    if request.method == "POST":
        with db() as conn: conn.execute("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)", (request.form.get("name"),request.form.get("description"),float(request.form.get("price",0)),int(request.form.get("stock",0)),request.form.get("image_filename",""))); conn.commit()
    with db() as conn: rows=conn.execute("SELECT * FROM products").fetchall()
    return render_template("admin_products.html", products=rows)

@app.route("/admin/coupons", methods=["GET", "POST"])
def admin_coupons():
    if request.method == "POST":
        with db() as conn: conn.execute("INSERT INTO coupons(code,discount_percent,is_used,assigned_email) VALUES (?,?,0,?)", (request.form.get("code"),int(request.form.get("discount",0)),request.form.get("email",""))); conn.commit()
    with db() as conn: rows=conn.execute("SELECT * FROM coupons").fetchall()
    return render_template("admin_coupons.html", coupons=rows)

@app.route("/files")
def files():
    name = request.args.get("name", "")
    # [INTENTIONAL-VULNERABILITY: Path Traversal - user path is joined without containment validation]
    path = os.path.join(UPLOAD_DIR, name)
    if not os.path.isfile(path): return "File not found", 404
    return send_file(path)

@app.route("/download")
def download():
    name = request.args.get("name", "")
    # [INTENTIONAL-VULNERABILITY: Path Traversal - no canonical containment validation]
    path = os.path.join(BASE_DIR, "demo_files", name)
    if not os.path.isfile(path): return "File not found", 404
    return send_file(path)

@app.route("/context-login", methods=["GET", "POST"])
def context_login():
    if request.method == "GET":
        return render_template("context_login.html", decision=None)
    passkey = request.form.get("passkey_verified", "false") == "true"
    hour = int(request.form.get("hour", 12))
    # [INTENTIONAL-VULNERABILITY: Context Authentication - client assertions are accepted as policy inputs]
    location_ok = request.form.get("location_allowed", "true") == "true"
    time_ok = request.form.get("time_allowed", "true") == "true" or 8 <= hour <= 22
    label = "ALLOW" if passkey and location_ok and time_ok else ("BLOCK (passkey)" if not passkey else "BLOCK (location)" if not location_ok else "BLOCK (time)")
    return render_template("context_login.html", decision={"label":label,"distance_km":0 if location_ok else 9999,"location_ok":location_ok,"time_ok":time_ok})

@app.route("/context-auth", methods=["POST"])
def context_auth():
    user = current_user()
    if not user: return jsonify({"decision":"BLOCK (authentication)"}), 401
    passkey = request.form.get("passkey_verified", "false") == "true"
    lat, lon = float(request.form.get("latitude", 0)), float(request.form.get("longitude", 0))
    # [INTENTIONAL-VULNERABILITY: Context Authentication - client controls passkey, coordinates, and time]
    with db() as conn:
        registered = conn.execute("SELECT latitude,longitude FROM registered_locations WHERE user_id=?", (user["id"],)).fetchone()
    distance = haversine_km(registered["latitude"], registered["longitude"], lat, lon) if registered else 9999
    # [INTENTIONAL-VULNERABILITY: Context Authentication - client boolean can override calculated location policy]
    location_allowed = request.form.get("location_allowed", "true") == "true"
    time_allowed = request.form.get("time_allowed", "true") == "true"
    decision = "ALLOW" if passkey and location_allowed and time_allowed else ("BLOCK (passkey)" if not passkey else "BLOCK (location)" if not location_allowed else "BLOCK (time)")
    audit("context_auth", user["id"], decision + " lat=" + str(lat) + " lon=" + str(lon))
    return jsonify({"decision":decision,"distance_km":round(distance, 2),"passkey_allowed":passkey,"location_allowed":location_allowed,"time_allowed":time_allowed})

@app.route("/behavior")
def behavior():
    user = current_user()
    if not user: return redirect(url_for("login"))
    with db() as conn: rows=conn.execute("SELECT typing_speed,request_ms,device_id,created_at FROM login_behavior WHERE user_id=?",(user["id"],)).fetchall()
    values=[r["typing_speed"] for r in rows]
    mean=statistics.mean(values) if values else 0; stdev=statistics.pstdev(values) if len(values)>1 else 0
    return render_template("behavior.html", rows=rows, mean=mean, stdev=stdev)

@app.errorhandler(Exception)
def verbose_error(error):
    # [INTENTIONAL-VULNERABILITY: Information Disclosure - verbose exception details are rendered]
    return render_template("error.html", error=repr(error)), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
