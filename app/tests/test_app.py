"""
Basic sanity tests for the vulnerable demo app.
Run with: pytest tests/test_app.py

NOTE: These just confirm the app boots and routes respond —
they intentionally do NOT "fix" the vulnerabilities. Testing
that the vulnerabilities exist (and later, that fixes work)
is part of your Level 1 / Level 6 documentation, not this file.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as flask_app  # noqa: E402


def test_home_loads():
    with flask_app.app.test_client() as c:
        r = c.get("/")
        assert r.status_code == 200


def test_health_check():
    with flask_app.app.test_client() as c:
        r = c.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"


def test_search_route_loads():
    with flask_app.app.test_client() as c:
        r = c.get("/search?query=hello")
        assert r.status_code == 200
        assert b"hello" in r.data
