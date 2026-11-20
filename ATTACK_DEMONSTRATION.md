# Attack Demonstration

All demonstrations target `127.0.0.1` and use seeded synthetic records.

## SQL injection

POST `/login` with `username=alice' -- ` and any password. The SQL comment removes the password predicate and creates an authenticated session. Search injection can be tested with `/products?q=' OR 1=1 -- `.

## IDOR

Log in as Alice, then request `/orders/1` (or another user's known order id). `order_detail()` does not compare `order.user_id` with the session user.

## XSS

As Alice, submit `<script>document.body.dataset.xss='executed'</script>` to a product review. The review template uses `|safe`, so a browser executes it when the product page is opened.

## Price/quantity manipulation

POST `/checkout` with `product_id=1&quantity=-1&unit_price=-50`. The resulting order and order item persist the supplied values.

## Path traversal

Request `/download?name=../sample_private.txt`; the controlled synthetic parent file is returned.

## Coupon race

`tests/test_race.py` starts a threaded localhost server and submits two concurrent checkout requests using `WELCOME10`. It records both orders and the incremented usage count, demonstrating the non-atomic update.

## Context authentication

POST `/context-auth` or `/context-login` with client assertions such as `passkey_verified=true`, `location_allowed=true`, and `time_allowed=true`. The naive endpoint accepts those assertions rather than validating a credential, Haversine distance, or server time.
