"""Naive security observation hooks.

This module intentionally does not enforce authentication, CSRF, ownership,
or context policy. It exists so the vulnerable baseline has a clear seam for
comparison with a separately developed secure implementation.
"""
from flask import request

def request_observation():
    # [INTENTIONAL-VULNERABILITY: Audit Accountability - observation has no actor verification]
    return {"ip": request.remote_addr, "user_agent": request.headers.get("User-Agent", "")}
