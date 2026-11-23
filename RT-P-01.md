# RT-P-01 — 2FA session established before verification

| Field | Value |
|---|---|
| Category | Broken 2FA Logic |
| Severity | Critical |
| CVSS 3.1 | 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| Endpoint | `POST /verify-2fa` |
| Target commit | `0417f0a` |
| Tester | Youssef Salem |
| Date | 2026-11-23 |
| Status | Open |

## Summary

`POST /verify-2fa` creates an authenticated session for the target user
**before** validating the 2FA code. An unauthenticated attacker who knows a
victim's email address can submit any invalid code, receive a valid session
cookie, and access the victim's account without knowing the 2FA code.

## Affected component

`app.py` → `verify_2fa()` (around line 1523).

## Prerequisites

- Network access to `http://127.0.0.1:5000`.
- Victim email address (e.g., `alice@example.test`).
- No password and no valid 2FA code required.