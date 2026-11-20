# Naive Implementation

This is the intentionally vulnerable baseline. It is for localhost-only academic testing and uses synthetic data.

| Weakness | Affected code | Root cause |
|---|---|---|
| SQL injection | `login()` and `products()` in `app.py` | User input is concatenated into SQL. |
| XSS | `product.html` review body | Review text is rendered with `|safe`. |
| IDOR / access control | `order_detail()` and `/admin/users` | Ownership or administrator checks are missing. |
| Password/session | `register()`, `login()`, Flask config | Plaintext passwords and permissive cookie settings. |
| Business logic | `checkout()`, `cart_update()` | Client totals/prices and unrestricted quantities are accepted. |
| Coupon race | `checkout()` | Coupon read/update and order creation are not one atomic redemption. |
| Path traversal | `/download`, `/files` | Joined user paths are not constrained to a canonical directory. |
| Verification | `register()` / `verify()` | Code is predictable with no expiry or attempt limit. |
| Context auth | `/context-auth`, `/context-login` | Client-controlled passkey, location, and time assertions. |
| Information disclosure | `verbose_error()` | Exception representations are sent to clients. |

The local test suite exercises catalog rendering, SQLi login, IDOR, negative/client price handling, traversal, and a real threaded coupon race.
