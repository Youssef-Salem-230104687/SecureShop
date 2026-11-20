# SecureShop Architecture & Rules
- **Tech Stack:** Python 3.11+, Flask, SQLite (via sqlite3 parameterized queries), Bootstrap 5 (Jinja2 templates).
- **Database Schema (`secureshop.db`):**
  1. `users`: id, username, email, password_hash, role ('user'|'admin'), is_verified (0|1), verification_code, store_credit (REAL DEFAULT 500.0), failed_attempts, last_login_ip, device_id
  2. `products`: id, name, description, price (REAL), stock (INT), image_filename
  3. `coupons`: id, code (UNIQUE), discount_percent (INT), is_used (0|1), assigned_email
  4. `orders`: id, user_id, total_amount (REAL), coupon_used, status, created_at
  5. `order_items`: id, order_id, product_id, quantity, unit_price
- **Routes Contract:**
  - Auth/Admin (Blue 1): `/register`, `/verify`, `/login`, `/logout`, `/profile`, `/admin`, `/admin/users`, `/admin/products`, `/admin/coupons`
  - Shop/Cart (Blue 2): `/`, `/products`, `/product/<id>`, `/cart`, `/cart/add`, `/cart/update`, `/cart/remove`
  - Checkout/Security (Blue 3): `/newsletter`, `/checkout`, `/orders`, `/orders/<id>`, `security_middleware.py`
- **Coding Rules:**
  1. Never trust client-side prices, user_ids, or roles. Fetch from DB/Server Session.
  2. Always use `?` placeholders in SQL queries. Never use f-strings in SQL.
  3. Keep code modular and clean; comment every security defense with `# [SECURITY-DEFENSE: <Topic>]`.
