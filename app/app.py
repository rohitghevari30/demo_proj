"""
SecureApp Pipeline — Vulnerable-by-Design Demo App
============================================================
INTENTIONALLY INSECURE. Built ONLY as a target for a DevSecOps
training pipeline (Bandit, Semgrep, ZAP, etc). Do not deploy
this as-is to a real production environment, and do not reuse
these patterns anywhere else.

Vulnerabilities planted (mapped to the pipeline's 8 levels):
  Level 1 (SAST):
    - Hardcoded secrets (see config.py)
    - Insecure eval() usage            -> /calculate
    - Insecure pickle deserialization  -> /load_profile
  Level 2 (SCA):
    - See requirements.txt (pin an old Flask/requests version
      on purpose so pip-audit has a real CVE to find)
  Level 6 (DAST — runtime, staging only):
    - SQL Injection                    -> /login
    - Reflected XSS                    -> /search
    - Missing security headers on all responses
  Level 8 (Monitoring / brute force):
    - No rate limiting / lockout on /login -> lets you demo
      the Prometheus "failed_logins > 200 in 60s" rule
============================================================
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import pickle
import base64
import os

from config import db_password, SECRET_KEY  # noqa: F401 (intentionally unused import trigger)

app = Flask(__name__)
app.secret_key = SECRET_KEY

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


# ------------------------------------------------------------------
# DB setup
# ------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    password TEXT)""")
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    c.execute("INSERT INTO users (username, password) VALUES ('canyon', 'password1')")
    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# Home
# ------------------------------------------------------------------
@app.route("/")
def home():
    return """
    <h1>SecureApp Pipeline — Vulnerable Demo</h1>
    <ul>
        <li><a href="/login">Login (SQLi target)</a></li>
        <li><a href="/search?query=test">Search (XSS target)</a></li>
        <li><a href="/calculate?expr=2%2B2">Calculate (eval target)</a></li>
        <li><a href="/load_profile">Load Profile (pickle target)</a></li>
        <li><a href="/health">Health check</a></li>
    </ul>
    """


# ------------------------------------------------------------------
# VULNERABLE: SQL Injection (Level 6 — DAST target)
# Attack payload:  username = admin' OR '1'='1
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # VULNERABLE: raw string concatenation, not parameterized
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
        except sqlite3.Error as e:
            conn.close()
            return f"DB error: {e}", 500
        conn.close()

        # No rate limiting / lockout here on purpose (Level 8 brute-force target)
        if user:
            return "Login successful!"
        return "Login failed.", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit">Login</button>
        </form>
    """


# ------------------------------------------------------------------
# VULNERABLE: Reflected XSS (Level 6 — DAST target)
# Attack payload: /search?query=<script>alert('XSS')</script>
# ------------------------------------------------------------------
@app.route("/search")
def search():
    query = request.args.get("query", "")

    # VULNERABLE: raw input reflected into HTML without escaping
    return render_template_string(f"""
        <h2>Search Results</h2>
        <p>You searched for: {query}</p>
    """)


# ------------------------------------------------------------------
# VULNERABLE: eval() on user input (Level 1 — SAST target, Bandit B307)
# Attack payload: /calculate?expr=__import__('os').system('id')
# ------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")
    try:
        result = eval(expr)  # noqa: S307  <-- Bandit should flag this
    except Exception as e:
        return f"Error: {e}", 400
    return jsonify({"expression": expr, "result": result})


# ------------------------------------------------------------------
# VULNERABLE: insecure deserialization via pickle (Level 1 — SAST target)
# Attack: craft a malicious base64 pickle payload and POST it
# ------------------------------------------------------------------
@app.route("/load_profile", methods=["GET", "POST"])
def load_profile():
    if request.method == "POST":
        encoded = request.form.get("profile_data", "")
        try:
            raw = base64.b64decode(encoded)
            profile = pickle.loads(raw)  # <-- Bandit B301: insecure pickle use
        except Exception as e:
            return f"Error loading profile: {e}", 400
        return jsonify({"loaded_profile": str(profile)})

    default_profile = {"name": "demo_user", "role": "guest"}
    encoded_default = base64.b64encode(pickle.dumps(default_profile)).decode()
    return f"""
        <p>Default encoded profile (paste into form below):</p>
        <textarea readonly style="width:100%">{encoded_default}</textarea>
        <form method="post">
            <textarea name="profile_data" style="width:100%"></textarea><br>
            <button type="submit">Load Profile</button>
        </form>
    """


# ------------------------------------------------------------------
# Health check — used later for Level 8 monitoring / uptime checks
# ------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ------------------------------------------------------------------
# NOTE: no security headers (CSP, X-Frame-Options, etc.) are set
# anywhere in this app on purpose — ZAP should flag "missing
# security headers" at Level 6. You'll add flask-talisman or
# manual headers when you FIX this level.
# ------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # debug=True is also intentionally insecure for a demo (Werkzeug debugger
    # exposure) — Bandit flags this too (B201)
    app.run(host="0.0.0.0", port=5000, debug=True)
