"""
SecureApp Pipeline — Vulnerable-by-Design Demo App
============================================================
PARTIALLY DEPRECATED AS A VULN TARGET: Level 1 eval() and pickle
findings have been remediated below (safe AST-based expression
evaluator + JSON instead of pickle). If this app is still being used
to teach the Level 1 SAST exercise, restore the previous eval/pickle
implementations from version control, or update
docs/level_1_findings.md to reflect that these two findings are now
fixed and no longer discoverable in this file.

Built ONLY as a target for a DevSecOps training pipeline
(Bandit, Semgrep, ZAP, etc). Do not deploy this as-is to a real
production environment, and do not reuse these patterns anywhere else.

Vulnerabilities planted (mapped to the pipeline's 8 levels):
  Level 1 (SAST):
    - Hardcoded secrets (see config.py)
    - [FIXED] Insecure eval() usage            -> /calculate (AST-based safe evaluator)
    - [FIXED] Insecure pickle deserialization  -> /load_profile (JSON instead of pickle)
  Level 2 (SCA):
    - See requirements.txt (pin an old Flask/requests version
      on purpose so pip-audit has a real CVE to find)
  Level 6 (DAST — runtime, staging only):
    - [FIXED] SQL Injection            -> /login   (parameterized query)
    - [FIXED] Reflected XSS            -> /search  (Jinja autoescaping)
    - [FIXED] Missing security headers -> flask-talisman on all responses
    - [FIXED] debug=True               -> now False
  Level 8 (Monitoring / brute force):
    - No rate limiting / lockout on /login -> lets you demo
      the Prometheus "failed_logins > 200 in 60s" rule

NOTE ON REMEDIATION:
  The eval/pickle findings that used to live here (B403, B307, B301)
  have been fixed. See the /calculate and /load_profile routes below
  for the safe replacements. The B104 finding (host="0.0.0.0") is
  still not a training target; it's required because this app is
  deployed on EC2 and needs to bind to all interfaces to be reachable
  externally.
============================================================
"""

import ast
import base64
import json
import operator
import os
import sqlite3

from flask import Flask, request, render_template_string, jsonify
from flask_talisman import Talisman

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
        <li><a href="/calculate?expr=2%2B2">Calculate (eval target — FIXED)</a></li>
        <li><a href="/load_profile">Load Profile (pickle target — FIXED)</a></li>
        <li><a href="/health">Health check</a></li>
    </ul>
    """


# ------------------------------------------------------------------
# FIXED: SQL Injection (Level 6)
# Was: f-string concatenation into raw SQL.
# Now: parameterized query — sqlite3 driver handles escaping/binding,
# so a payload like  admin' OR '1'='1  is treated as a literal string,
# not SQL syntax.
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
# FIXED: Reflected XSS (Level 6)
# Was: f-string interpolation of raw query into HTML.
# Now: query passed as a Jinja template variable ({{ query }}) instead
# of being baked into the template string. Jinja autoescapes variables
# by default, so <script> becomes &lt;script&gt; in the rendered output.
# ------------------------------------------------------------------
SEARCH_RESULTS_TEMPLATE = """
    <h2>Search Results</h2>
    <p>You searched for: {{ query }}</p>
"""


@app.route("/search")
def search():
    query = request.args.get("query", "")
    # Template string is a fixed constant, never built from request
    # data — only the *value* passed in for {{ query }} is
    # user-controlled, and Jinja autoescapes that by default.
    return render_template_string(SEARCH_RESULTS_TEMPLATE, query=query)


# ------------------------------------------------------------------
# FIXED: eval() on user input (was Level 1 — SAST target, Bandit B307)
# Was: raw eval(expr) on user-supplied input, allowing arbitrary code
#      execution, e.g. /calculate?expr=__import__('os').system('id')
# Now: expression is parsed into an AST and walked with a strict
#      whitelist of numeric operators only. No name lookups, no
#      attribute access, no function calls — so no code execution
#      path exists, regardless of payload.
# ------------------------------------------------------------------
_ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
}
_ALLOWED_UNARYOPS = {
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval_node(node):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("Only numeric constants are allowed")
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOPS:
        left = _safe_eval_node(node.left)
        right = _safe_eval_node(node.right)
        return _ALLOWED_BINOPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARYOPS:
        return _ALLOWED_UNARYOPS[type(node.op)](_safe_eval_node(node.operand))
    raise ValueError("Unsupported or disallowed expression")


def safe_eval(expr: str):
    """Evaluate a simple numeric expression without using eval()/exec().

    Only literal numbers combined with + - * / // % ** and unary +/-
    are permitted. Anything else (names, calls, attribute access,
    imports, comprehensions, etc.) raises ValueError.
    """
    parsed = ast.parse(expr, mode="eval")
    return _safe_eval_node(parsed.body)


@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")
    try:
        result = safe_eval(expr)
    except (ValueError, ZeroDivisionError, SyntaxError, TypeError) as e:
        return f"Error: {e}", 400
    return jsonify({"expression": expr, "result": result})


# ------------------------------------------------------------------
# FIXED: insecure deserialization (was Level 1 — SAST target)
# Was: pickle.loads() on a base64-decoded, attacker-controlled blob,
#      which allows arbitrary code execution via a crafted payload
#      (pickle can invoke arbitrary __reduce__ methods on unpickling).
# Now: profile data is JSON, not pickle. JSON has no mechanism to
#      execute code on load, so this class of attack is eliminated.
# ------------------------------------------------------------------
@app.route("/load_profile", methods=["GET", "POST"])
def load_profile():
    if request.method == "POST":
        encoded = request.form.get("profile_data", "")
        try:
            raw = base64.b64decode(encoded)
            profile = json.loads(raw)
        except Exception as e:
            return f"Error loading profile: {e}", 400
        return jsonify({"loaded_profile": profile})

    default_profile = {"name": "demo_user", "role": "guest"}
    encoded_default = base64.b64encode(json.dumps(default_profile).encode()).decode()
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
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec B104 -- required for EC2 deployment, not a Level 1/6 target
