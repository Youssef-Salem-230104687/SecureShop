# SecureShop

SecureShop is a Flask and SQLite e-commerce application with a responsive Bootstrap 5 storefront. It supports account activation, a session cart, store-credit checkout, order history, newsletter welcome coupons, and an administrator console.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python init_db.py
python app.py
```

Open http://127.0.0.1:5000. The development seed accounts are:

- `alice` / `alice-demo-pass`
- `bob` / `bob123secure`
- `admin` / `admin123secure`

Reset the development database with `python init_db.py`, then run the checks with `pytest -q`.

## Security controls

State-changing forms include CSRF tokens. Passwords use Werkzeug password hashes, role checks come from the server-side database, all SQL receives parameterized values, and checkout recalculates prices, coupon eligibility, inventory, and credit inside a SQLite transaction. Private orders have ownership checks; download names are constrained to their intended directories. Set a persistent `SECRET_KEY` and enable HTTPS (`FLASK_ENV=production`) when deploying.
