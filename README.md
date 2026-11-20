# SecureShop Naive

SecureShop is a local Flask/SQLite e-commerce application intentionally implemented with common security weaknesses for controlled academic testing. It must remain bound to localhost; it is not a production application.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python init_db.py
python app.py
```

Open http://127.0.0.1:5000. Seed accounts are `alice` / `alice-demo-pass`, `bob` / `bob123`, and `admin` / `admin123`. Reset with `python init_db.py`.

Run the reproducible local checks with `pytest -q`. All accounts and files are synthetic.

## Scope

The app demonstrates SQL injection (`/login`, `/products`), XSS in product reviews, IDOR on `/orders/<id>`, weak plaintext passwords and predictable verification codes, insecure session configuration, client-trusted checkout prices/quantities, a non-atomic coupon update, path traversal (`/download` and `/files`), verbose error details, behavioral statistics, and client-controlled context-authentication gates. The implementation deliberately does not provide a secure alternative.
