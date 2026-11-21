# SecureShop — Security Coverage Summary

> **Classification:** ACADEMIC USE ONLY  
> **Last Updated:** 2026-11-21

---

## Overall Coverage

| Metric | Count |
|---|---|
| **Required Vulnerability Categories** | 16 (A–P) |
| **Implemented Categories** | 16 |
| **Total Individual Vulnerabilities** | 60 |
| **Tested (Automated)** | 56 |
| **Tested (Manual Verification)** | 4 |
| **Pending** | 0 |

---

## Coverage by Category

| Cat | Category Name | Lab Ref | Vuln Count | Status | Key Routes |
|---|---|---|---|---|---|
| **A** | SQL Injection | Lab 1 | 5 | ✅ Complete | `/login/debug`, `/api/products/search`, `/api/admin/users/search`, `/api/products/filter` |
| **B** | Cross-Site Scripting (XSS) | Lab 1 | 5 | ✅ Complete | `/products?q=`, `/api/search/preview`, `/product/<id>` (reviews), `/admin/users`, `/api/admin/products` |
| **C** | Cross-Site Request Forgery (CSRF) | Lab 1 | 5 | ✅ Complete | `/api/cart/add`, `/api/profile/update`, `/api/apply-coupon`, `/api/checkout`, `/login/debug` |
| **D** | Insecure Direct Object References | Lab 1 | 4 | ✅ Complete | `/api/users/<id>/profile`, `/api/orders/<id>`, `/api/orders/<id>/cancel`, `/api/apply-store-credit` |
| **E** | Broken Authentication | Lab 1 | 4 | ✅ Complete | `/login/quick`, `/api/login`, `/login/debug` |
| **F** | Broken Access Control / Priv Esc | Lab 1 | 6 | ✅ Complete | `/api/admin/orders`, `/api/admin/users`, `/api/admin/grant-admin`, `/profile` (role field), `/api/admin/products`, `/api/admin/coupons` |
| **G** | Insecure Session Management | Lab 1 | 3 | ✅ Complete | `/logout`, `/login/debug`, `/api/debug/session` |
| **H** | Brute Force / No Rate Limiting | Lab 1 | 3 | ✅ Complete | `/api/login`, `/login/debug`, `/api/verify` |
| **I** | Open Redirect | Lab 1 | 3 | ✅ Complete | `/redirect`, `/register/complete`, `/login` (redirect_url field) |
| **J** | Business Logic | Lab 1 | 4 | ✅ Complete | `/api/checkout`, `/api/apply-store-credit`, `/api/apply-coupon`, `/api/cart/update` |
| **K** | Security Misconfiguration | Lab 1 | 6 | ✅ Complete | `/api/debug/config`, `/api/debug/db`, `/api/debug/env`, app config, security headers, error handler |
| **L** | Excessive Client Trust | Lab 2.1 | 5 | ✅ Complete | `/api/checkout` (total, price, discount), `/api/apply-store-credit` (user_id), `/profile` (role, credit) |
| **M** | Flawed Business Rules | Lab 2.1 | 5 | ✅ Complete | `/api/checkout` (coupon reuse, no min_purchase, no assignment check, no expiry, no stock) |
| **N** | Inconsistent Exceptional Input | Lab 2.2 | 6 | ✅ Complete | `/api/cart/set-quantity` (negative, zero, decimal, huge, missing), `/api/cart/update` (negative) |
| **O** | Insufficient Workflow Validation | Lab 2.3 | 4 | ✅ Complete | `/api/order/confirm`, `/api/orders/latest`, `/api/checkout` (no stock), `/api/orders/<id>/cancel` |
| **P** | Broken 2FA Logic | Lab 3.1 | 7 | ✅ Complete | `/verify-2fa` (premature session, empty code, no expiry, cross-user, no limit, code reuse), `/api/verify` |

---

## Affected Components

### Modified Source Files

| File | Modifications |
|---|---|
| `app.py` | Added 30+ vulnerable API endpoints; modified CSRF protection, security headers, session management, login redirect, profile handler, error handler; added debug mode and hardcoded secret |
| `templates/product.html` | Review body rendered with `\|safe` (stored XSS) |
| `templates/products.html` | Search query rendered with `\|safe` (reflected XSS) |
| `templates/admin_users.html` | Username rendered with `\|safe` (stored XSS) |

### Preserved Secure Routes

All original secure routes continue to function correctly:

| Route | Function | Status |
|---|---|---|
| `GET /` | Homepage | ✅ Working |
| `GET /products` | Product catalogue | ✅ Working |
| `GET /product/<id>` | Product detail | ✅ Working |
| `POST /register` | User registration | ✅ Working |
| `POST /verify` | Account verification | ✅ Working |
| `POST /login` | User login | ✅ Working |
| `POST /logout` | Logout (modified: incomplete) | ✅ Working |
| `GET/POST /profile` | Profile (modified: accepts role) | ✅ Working |
| `GET /cart` | Shopping cart | ✅ Working |
| `POST /cart/add` | Add to cart | ✅ Working |
| `POST /cart/update` | Update cart | ✅ Working |
| `POST /cart/remove` | Remove from cart | ✅ Working |
| `GET/POST /checkout` | Secure checkout | ✅ Working |
| `GET /orders` | Order history | ✅ Working |
| `GET /orders/<id>` | Order detail | ✅ Working |
| `GET/POST /newsletter` | Newsletter signup | ✅ Working |
| `GET /admin` | Admin dashboard | ✅ Working |
| `GET /admin/users` | Admin user management | ✅ Working |
| `GET/POST /admin/products` | Admin product management | ✅ Working |
| `GET/POST /admin/coupons` | Admin coupon management | ✅ Working |

### New Vulnerable Endpoints Added

| Endpoint | Vulnerability Categories |
|---|---|
| `POST /login/debug` | A, E, G, H, I, K |
| `POST /login/quick` | E, G |
| `POST /api/login` | E, H |
| `GET /api/products/search` | A, K |
| `GET /api/products/filter` | A |
| `GET /api/admin/users/search` | A, F |
| `GET /api/search/preview` | B |
| `POST /api/profile/update` | C |
| `POST /api/cart/add` | C |
| `POST /api/apply-coupon` | C, J, M |
| `GET /api/orders/<id>` | D |
| `GET /api/users/<id>/profile` | D |
| `POST /api/orders/<id>/cancel` | D, O |
| `POST /api/apply-store-credit` | D, J, L |
| `GET /api/admin/orders` | F |
| `GET /api/admin/users` | F |
| `POST /api/admin/grant-admin` | F |
| `GET/POST /api/admin/products` | B, F |
| `GET/POST /api/admin/coupons` | F |
| `GET /api/debug/session` | G, K |
| `GET /api/debug/config` | K |
| `GET /api/debug/db` | K |
| `GET /api/debug/env` | K |
| `POST /api/checkout` | C, J, L, M, N, O |
| `POST /api/cart/update` | J, N |
| `POST /api/cart/set-quantity` | N |
| `POST /api/order/confirm` | L, O |
| `GET /api/orders/latest` | O |
| `POST /api/verify` | H, P |
| `GET /redirect` | I |
| `GET /register/complete` | I |
| `POST /verify-2fa` | P |

---

## Functional Test Results

| Test Area | Tests | Passed | Status |
|---|---|---|---|
| Homepage / Catalogue | 3 | 3 | ✅ |
| Authentication Pages | 3 | 3 | ✅ |
| Authenticated Pages | 3 | 3 | ✅ |
| Cart Operations | 1 | 1 | ✅ |
| **Total Functional** | **10** | **10** | **✅ All Pass** |

## Security Test Results

| Category | Tests | Passed | Status |
|---|---|---|---|
| A — SQL Injection | 7 | 7 | ✅ |
| B — XSS | 4 | 4 | ✅ |
| C — CSRF | 2 | 2 | ✅ |
| D — IDOR | 3 | 3 | ✅ |
| E — Broken Auth | 3 | 3 | ✅ |
| F — Access Control | 3 | 3 | ✅ |
| G — Session Mgmt | 1 | 1 | ✅ |
| H — Brute Force | 5 | 5 | ✅ |
| I — Open Redirect | 2 | 2 | ✅ |
| J — Business Logic | 3 | 3 | ✅ |
| K — Security Misconfig | 3 | 3 | ✅ |
| L — Client Trust | 1 | 1 | ✅ |
| M — Flawed Rules | 1 | 1 | ✅ |
| N — Exceptional Input | 4 | 4 | ✅ |
| O — Workflow | 2 | 2 | ✅ |
| P — Broken 2FA | 2 | 2 | ✅ |
| **Total Security** | **46** | **46** | **✅ All Pass** |

---

## Source Code Vulnerability Markers

All vulnerabilities are marked in the source code with comments following this pattern:

```python
# [VULNERABILITY: SQL INJECTION]
# [VULNERABILITY: STORED XSS]
# [VULNERABILITY: REFLECTED XSS]
# [VULNERABILITY: CSRF]
# [VULNERABILITY: IDOR]
# [VULNERABILITY: BROKEN AUTHENTICATION]
# [VULNERABILITY: BROKEN ACCESS CONTROL]
# [VULNERABILITY: INSECURE SESSION MANAGEMENT]
# [VULNERABILITY: BRUTE FORCE]
# [VULNERABILITY: OPEN REDIRECT]
# [VULNERABILITY: BUSINESS LOGIC]
# [VULNERABILITY: SECURITY MISCONFIGURATION]
# [VULNERABILITY: EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS]
# [VULNERABILITY: FLAWED BUSINESS RULE ENFORCEMENT]
# [VULNERABILITY: INCONSISTENT EXCEPTIONAL INPUT HANDLING]
# [VULNERABILITY: INSUFFICIENT WORKFLOW VALIDATION]
# [VULNERABILITY: BROKEN 2FA LOGIC]
```

Templates use HTML comments:
```html
<!-- [VULNERABILITY: STORED XSS] -->
<!-- [VULNERABILITY: REFLECTED XSS] -->
```
