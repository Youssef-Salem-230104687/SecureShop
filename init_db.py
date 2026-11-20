import os, sqlite3
from datetime import datetime
BASE_DIR=os.path.dirname(os.path.abspath(__file__))
DB_PATH=os.path.join(BASE_DIR,"secureshop.db")
SCHEMA='''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', is_verified INTEGER DEFAULT 0, verification_code TEXT, store_credit REAL DEFAULT 500.0, failed_attempts INTEGER DEFAULT 0, last_login_ip TEXT, device_id TEXT);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, price REAL NOT NULL, stock INTEGER DEFAULT 0, image_filename TEXT);
CREATE TABLE IF NOT EXISTS coupons (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, discount_percent INTEGER NOT NULL, is_used INTEGER DEFAULT 0, usage_count INTEGER DEFAULT 0, assigned_email TEXT);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, total_amount REAL, coupon_used TEXT, status TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER, product_id INTEGER, quantity INTEGER, unit_price REAL);
CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER, user_id INTEGER, body TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, user_id INTEGER, detail TEXT, ip TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS login_behavior (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, typing_speed REAL, request_ms REAL, device_id TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS product_categories (product_id INTEGER, category_id INTEGER);
CREATE TABLE IF NOT EXISTS carts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS verification_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS registered_locations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, latitude REAL, longitude REAL);
CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, credential_id TEXT, registration_data TEXT, verified INTEGER DEFAULT 0);
'''
def init_db(path=None):
    target = str(path or DB_PATH)
    if os.path.exists(target): os.remove(target)
    with sqlite3.connect(target) as c:
        c.executescript(SCHEMA)
        c.executemany("INSERT INTO users(username,email,password_hash,role,is_verified,verification_code,device_id) VALUES (?,?,?,?,?,?,?)",[("alice","alice@example.test","alice-demo-pass","user",1,"1111","device-a"),("admin","admin@example.test","admin123","admin",1,"3333","device-admin"),("bob","bob@example.test","bob123","user",1,"2222","device-b")])
        c.executemany("INSERT INTO products(name,description,price,stock,image_filename) VALUES (?,?,?,?,?)",[("Wireless Headphones","Noise cancelling headphones",89.99,10,"headphones.txt"),("Laptop","A fast development laptop",999.0,10,"laptop.txt"),("Keyboard","Mechanical keyboard",89.0,20,"keyboard.txt"),("Coffee","Office coffee beans",15.0,100,"coffee.txt")])
        c.executemany("INSERT INTO categories(name) VALUES (?)", [("Electronics",), ("Office",)])
        c.executemany("INSERT INTO product_categories(product_id,category_id) VALUES (?,?)", [(1,1),(2,1),(3,2),(4,2)])
        c.executemany("INSERT INTO coupons(code,discount_percent,is_used,usage_count,assigned_email) VALUES (?,?,?,?,?)",[("WELCOME10",10,0,0,""),("WELCOME20",20,0,0,""),("SINGLE50",50,0,0,"alice@example.test")])
        c.execute("INSERT INTO login_behavior(user_id,typing_speed,request_ms,device_id,created_at) VALUES (?,?,?,?,?)",(1,250.0,120.0,"device-a",datetime.utcnow().isoformat()))
        c.execute("INSERT INTO registered_locations(user_id,latitude,longitude) VALUES (?,?,?)", (1,30.0444,31.2357))
        c.execute("INSERT INTO credentials(user_id,credential_id,registration_data,verified) VALUES (?,?,?,?)", (1,"cred-alice","synthetic-passkey-registration",1))
        c.commit()
    test_dir=os.path.join(BASE_DIR,"test_files"); os.makedirs(test_dir,exist_ok=True)
    with open(os.path.join(test_dir,"sample.txt"),"w") as f: f.write("synthetic test file")
    return target
def main():
    print("Initialized", init_db())
if __name__=="__main__": main()
