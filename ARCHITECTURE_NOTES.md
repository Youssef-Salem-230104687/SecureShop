# Architecture Notes

`app.py` is the Flask entry point. `init_db.py` recreates `secureshop.db` and seeds synthetic accounts, products, coupons, behavior data, and a local `test_files` directory. Jinja templates in `templates/` extend `base.html` and use Bootstrap CDN styles.

Core workflow: catalog → session cart → checkout → order history/details. Authentication stores the user id and role in the signed Flask session. Admin and security demonstration endpoints are exposed from the same module for easy comparison with a future secure implementation.

Tables include the architecture-required users, products, coupons, orders, and order_items plus reviews, audit_events, and login_behavior. The application uses SQLite connections through the `db()` helper; intentionally vulnerable operations are marked directly in source comments.
