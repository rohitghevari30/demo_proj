"""
SecureApp Pipeline — Vulnerable-by-Design Demo App
============================================================
INTENTIONALLY INSECURE (partially remediated through Level 6).
Built ONLY as a target for a DevSecOps training pipeline
(Bandit, Semgrep, ZAP, etc). Do not deploy this as-is to a real
production environment, and do not reuse these patterns anywhere else.

Vulnerabilities planted (mapped to the pipeline's 8 levels):
  Level 1 (SAST):
    - Hardcoded secrets (see config.py)
    - Insecure eval() usage            -> /calculate
    - Insecure pickle deserialization  -> /load_profile
  Level 2 (SCA):
    - See requirements.txt (pin an old Flask/requests version
      on purpose so pip-audit has a real CVE to find)
  Level 6 (DAST — runtime, staging only):
    - [FIXED] SQL Injection            -> /login   (parameterized query)
    - [FIXED] Reflected XSS            -> /search  (escaped via markupsafe)
    - [FIXED] Missing security headers -> flask-talisman on all responses
    - [FIXED] debug=True               -> now False
  Level 8 (Monitoring / brute force):
    - [FIXED] No rate limiting / lockout on /login -> now increments a
      Prometheus counter on each failed attempt, with a
      "failed_logins > 200 in 60s" alert rule in Grafana/Prometheus

NOTE ON # nosec / # nosemgrep COMMENTS:
  The eval/pickle findings below (B403, B307, B301) are intentional
  Level 1 SAST targets — see docs/level_1_findings.md for the
  documented findings. The B104 finding is not a training target;
  it's required because this app is deployed on EC2 and needs to
  bind to all interfaces to be reachable externally.

  # nosec suppresses Bandit. # nosemgrep suppresses Semgrep — they're
  separate tools with separate suppression syntax, so intentional
  findings need both comments to avoid failing CI on purpose-built
  training targets while still gating on real issues.
============================================================
"""

from flask import Flask, request, jsonify, render_template
from flask_talisman import Talisman
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter
import sqlite3
import pickle  # nosec B403 -- intentional Level 1 SAST target, see docs/level_1_findings.md
import base64
import os

from config import db_password, SECRET_KEY  # noqa: F401 (intentionally unused import trigger)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ------------------------------------------------------------------
# Level 6 fix: security headers via flask-talisman
# force_https=False because this still runs on plain HTTP behind the
# EC2 demo setup (no TLS termination in front of it yet). If/when you
# put Cloudflare or an ALB with TLS in front of it, flip this to True.
# ------------------------------------------------------------------
Talisman(
    app,
    force_https=False,
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self' 'unsafe-inline'",
    },
    x_content_type_options=True,
    frame_options="DENY",
)

# ------------------------------------------------------------------
# Level 8: Prometheus instrumentation
# PrometheusMetrics(app) auto-exposes a /metrics endpoint with default
# Flask request metrics. failed_login_counter is a custom metric
# incremented on each failed /login attempt, scraped by Prometheus
# and used by the BruteForceLoginAttempt alert rule.
# ------------------------------------------------------------------
metrics = PrometheusMetrics(app)
failed_login_counter = Counter("failed_logins_total", "Total number of failed login attempts")

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
        <li><a href="/login">Login (SQLi target — FIXED)</a></li>
        <li><a href="/search?query=test">Search (XSS target — FIXED)</a></li>
        <li><a href="/calculate?expr=2%2B2">Calculate (eval target)</a></li>
        <li><a href="/load_profile">Load Profile (pickle target)</a></li>
        <li><a href="/health">Health check</a></li>
    </ul>
    """


# ------------------------------------------------------------------
# FIXED: SQL Injection (Level 6)
# Was: f-string concatenation into raw SQL.
# Now: parameterized query — sqlite3 driver handles escaping/binding,
# so a payload like  admin' OR '1'='1  is treated as a literal string,
# not SQL syntax.
#
# FIXED: No rate limiting / lockout (Level 8)
# Was: unlimited login attempts, no visibility into brute-force
# activity. Now: each failed attempt increments failed_login_counter,
# scraped by Prometheus and alerted on via BruteForceLoginAttempt
# (>200 failed logins in 60s). Deliberately still no hard lockout —
# the point of this level is detection/alerting, not blocking.
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        try:
            c.execute(query, (username, password))
            user = c.fetchone()
        except sqlite3.Error as e:
            conn.close()
            return f"DB error: {e}", 500
        conn.close()

        if user:
            return "Login successful!"
        failed_login_counter.inc()
        return "Login failed.", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit">Login</button>
        </form>
    """


# ------------------------------------------------------------------
# FIXED: Reflected XSS (Level 6)
# Attempt 1 was render_template_string() -- flagged as SSTI-risky by
# pattern regardless of safety.
# Attempt 2 was an f-string with markupsafe.escape() applied manually
# -- still flagged, because Semgrep flags any hand-built HTML string
# with an interpolated variable and can't verify escaping correctness
# just by reading the code.
# Now: render_template() against a real template file
# (templates/search.html). Jinja autoescapes .html templates by
# default, so {{ query }} is escaped automatically, and there's no
# manual string-building left for Semgrep to flag.
# ------------------------------------------------------------------
@app.route("/search")
def search():
    query = request.args.get("query", "")
    return render_template("search.html", query=query)


# ------------------------------------------------------------------
# VULNERABLE: eval() on user input (Level 1 — SAST target, Bandit B307)
# Out of scope for Level 6 — left as-is intentionally.
# Attack payload: /calculate?expr=__import__('os').system('id')
# ------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")  # nosemgrep
    try:
        result = eval(expr)  # nosec B307 -- intentional Level 1 SAST target, see docs/level_1_findings.md  # nosemgrep
    except Exception as e:
        return f"Error: {e}", 400
    return jsonify({"expression": expr, "result": result})


# ------------------------------------------------------------------
# VULNERABLE: insecure deserialization via pickle (Level 1 — SAST target)
# Out of scope for Level 6 — left as-is intentionally.
# Attack: craft a malicious base64 pickle payload and POST it
# ------------------------------------------------------------------
@app.route("/load_profile", methods=["GET", "POST"])
def load_profile():
    if request.method == "POST":
        encoded = request.form.get("profile_data", "")
        try:
            raw = base64.b64decode(encoded)
            profile = pickle.loads(raw)  # nosec B301 -- intentional Level 1 SAST target, see docs/level_1_findings.md  # nosemgrep
        except Exception as e:
            return f"Error loading profile: {e}", 400
        return jsonify({"loaded_profile": str(profile)})

    default_profile = {"name": "demo_user", "role": "guest"}
    encoded_default = base64.b64encode(pickle.dumps(default_profile)).decode()  # nosemgrep
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


if __name__ == "__main__":
    init_db()
    # FIXED (Level 6): debug=False — Werkzeug debugger is no longer
    # exposed on the running app (Bandit B201 should now pass too).
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec B104 -- required for EC2 deployment, not a Level 1/6 target  # nosemgrep