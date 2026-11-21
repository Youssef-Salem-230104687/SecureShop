# Requirements Matrix

| Area | Implementation | Verification |
|---|---|---|
| Authentication and activation | Validated registration, hashed passwords, one-time confirmation token, verified-only login, server-side session identity | Registration/confirmation/login test |
| Catalogue | Search, detail pages, stock badges, empty search state | Catalogue test and smoke pass |
| Cart | Session cart, validated add/update/remove operations, calculated totals | Checkout workflow test |
| Coupons and newsletter | Eligibility/expiry/assignment/use rules; subscription issues an email-assigned coupon | Newsletter and coupon race tests |
| Checkout and orders | Atomic server-side total, inventory, coupon, and store-credit transaction; order history | Checkout workflow and authorization test |
| Account | Profile update, credit display, recent orders | Route and template smoke pass |
| Administration | Database-backed role gate and user/product/coupon management routes | Authorization and product management test |
| Security | CSRF, parameterized SQL, hashed passwords, ownership checks, safe downloads, non-verbose errors | CSRF/private-order/path tests |
| Responsive UI | Bootstrap 5 layouts, responsive navigation, cards, forms, empty states, tables, alerts | Source and response smoke pass |
