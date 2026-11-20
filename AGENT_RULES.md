# AGENT_RULES.md — Strict Coding Guidelines for SecureShop

1. **Read First:** Before writing or modifying any file, read `ARCHITECTURE.md` to respect table names, column names, and route contracts.
2. **Scope Isolation (CRITICAL):**
   - Only create or edit files belonging to your assigned module.
   - Do NOT modify `init_db.py` schema or `templates/base.html` unless you are Blue 1 (Project Lead).
3. **Database Rules:**
   - Use Python's built-in `sqlite3` connecting to `secureshop.db`.
   - ALWAYS use parameterized queries (`?`). Never use string concatenation or f-strings in SQL queries.
   - Always close DB connections or use context managers (`with sqlite3.connect(...) as conn:`).
4. **Security Tagging:**
   - Every security check or defense you write MUST include a comment directly above it in this format:
     `# [SECURITY-DEFENSE: <Vulnerability Name> - <Brief Explanation>]`
   - This makes it easy to map code lines to the Security Coverage Matrix.
5. **Frontend Consistency:**
   - All HTML pages must extend `base.html` (`{% extends "base.html" %}`) and use Bootstrap 5 classes.
   - Display user feedback using Flask's `flash()` messages.
6. **No External Heavy Dependencies:**
   - Stick to standard Flask, Werkzeug, Requests, and standard Python libraries so the app runs cleanly on any machine via `pip install -r requirements.txt`.
