"""Security observation and request auditing middleware.

Provides structured request observation with verified actor state, IP tracking,
and security telemetry for audit logging.
"""
from flask import request, session

# [SECURITY-DEFENSE: Audit Accountability - Authenticated Actor Observation]
def request_observation(user_id=None):
    """Capture verified request context for security audit events."""
    actor = user_id or session.get("user_id")
    return {
        "ip": request.remote_addr or "127.0.0.1",
        "user_agent": (request.headers.get("User-Agent") or "")[:250],
        "actor_id": actor,
        "path": request.path,
        "method": request.method,
    }
