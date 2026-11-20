# Test Report

Verification command: `pytest -q`.

The functional suite covers catalog rendering, SQL-injection login bypass, cross-user order access, client-controlled order price persistence, synthetic path traversal, and a concurrent coupon redemption: **6 passed**. `python -m py_compile app.py init_db.py` also passes. Tests use temporary SQLite databases created by `init_db(path)` and never contact external systems.

Manual smoke evidence: `python app.py` started successfully on `http://127.0.0.1:5000`; `GET /products` returned HTTP 200; login returned HTTP 302 followed by a 200 homepage; context-auth with client assertions returned `{"decision":"ALLOW","distance_km":0}`. A review containing `<script>window.XSS=1</script>` was returned literally in `GET /product/1`, confirming the unsafe render path.

Known limitations: this is intentionally insecure; the current test suite does not automate browser JavaScript execution, all context-authentication permutations, or every admin mutation route. Those procedures are documented in `ATTACK_DEMONSTRATION.md`.
