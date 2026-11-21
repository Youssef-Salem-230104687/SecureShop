import os
import sqlite3

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secureshop.db")

SCHEMA = '''
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', is_verified INTEGER DEFAULT 0, verification_code TEXT, store_credit REAL DEFAULT 500.0, failed_attempts INTEGER DEFAULT 0, last_login_ip TEXT, device_id TEXT);
CREATE TABLE products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, price REAL NOT NULL CHECK(price >= 0), stock INTEGER DEFAULT 0 CHECK(stock >= 0), image_filename TEXT);
CREATE TABLE coupons (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, discount_percent INTEGER NOT NULL CHECK(discount_percent BETWEEN 1 AND 100), is_used INTEGER DEFAULT 0, usage_count INTEGER DEFAULT 0, assigned_email TEXT, expires_at TEXT, max_uses INTEGER NOT NULL DEFAULT 1, min_purchase REAL NOT NULL DEFAULT 0);
CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, total_amount REAL NOT NULL CHECK(total_amount >= 0), coupon_used TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE order_items (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK(quantity > 0), unit_price REAL NOT NULL CHECK(unit_price >= 0), FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(product_id) REFERENCES products(id));
CREATE TABLE reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(product_id) REFERENCES products(id), FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, user_id INTEGER, detail TEXT, ip TEXT, created_at TEXT NOT NULL);
CREATE TABLE newsletter_subscribers (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, coupon_code TEXT NOT NULL, subscribed_at TEXT NOT NULL);
'''

def init_db(path=None):
    target = str(path or DB_PATH)
    if os.path.exists(target):
        os.remove(target)
    with sqlite3.connect(target) as conn:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO users(username,email,password_hash,role,is_verified,verification_code,store_credit) VALUES (?,?,?,?,?,?,?)", [
            ("alice", "alice@example.test", generate_password_hash("alice-demo-pass"), "user", 1, None, 500.0),
            ("admin", "admin@example.test", generate_password_hash("admin123secure"), "admin", 1, None, 1000.0),
            ("bob", "bob@example.test", generate_password_hash("bob123secure"), "user", 1, None, 500.0),
        ])
        conn.executemany("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)", [
            ("Wireless Headphones", "Noise-cancelling headphones for focused work.", 89.99, 10, ""),
            ("Development Laptop", "A fast laptop ready for your next build.", 999.00, 10, ""),
            ("Mechanical Keyboard", "Tactile mechanical keyboard with a compact footprint.", 89.00, 20, ""),
            ("Office Coffee", "Rich coffee beans for productive mornings.", 15.00, 100, ""),
        ])
        conn.executemany("INSERT INTO coupons(code,discount_percent,is_used,usage_count,assigned_email,max_uses,min_purchase) VALUES (?,?,?,?,?,?,?)", [
            ("WELCOME10", 10, 0, 0, "", 1, 0), ("WELCOME20", 20, 0, 0, "", 1, 100), ("SINGLE50", 50, 0, 0, "alice@example.test", 1, 0),
        ])
        conn.commit()
    return target

if __name__ == "__main__":
    print("Initialized", init_db())
