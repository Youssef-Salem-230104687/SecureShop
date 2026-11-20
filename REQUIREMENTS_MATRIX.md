# Requirements Matrix

| ID | Requirement | Application Component | Test Case | Implementation Status | Evidence |
|---|---|---|---|---|---|
| R1 | Flask/SQLite e-commerce workflow | `app.py`, templates | `test_catalog_renders` | Verified | pytest |
| R2 | SQL injection | `login`, `products` | `test_sqli_login_bypasses_password` | Verified | pytest |
| R3 | IDOR | `order_detail` | `test_idor_order_read` | Verified | pytest |
| R4 | Client price/quantity trust | `checkout`, `cart_update` | `test_client_price_is_stored` | Verified | pytest |
| R5 | Path traversal | `/download` | `test_path_traversal_reads_synthetic_parent_file` | Verified | pytest |
| R6 | Coupon concurrency | `checkout` | `test_single_use_coupon_redeemed_twice_concurrently` | Verified | pytest |
| R7 | XSS review rendering | `product.html` | Manual browser procedure | Implemented, manual | ATTACK_DEMONSTRATION.md |
| R8 | Context authentication weakness | `/context-auth`, `/context-login` | Manual request matrix | Implemented, manual | ATTACK_DEMONSTRATION.md |
