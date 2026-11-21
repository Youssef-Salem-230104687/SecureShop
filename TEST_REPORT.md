# Test Report

Verification command: `python -m py_compile app.py init_db.py; pytest -q`.

Result: **6 passed**.

The suite uses isolated SQLite databases and covers catalogue search and empty results, registration with password hashing and confirmation, CSRF enforcement, authenticated checkout, server-side prices and credit deductions, stock reduction, coupon eligibility, newsletter coupon issuance, administrator product management, private-order authorization, path containment, and concurrent single-use coupon redemption.

The public storefront pages also returned HTTP 200 during a Flask test-client smoke pass.
