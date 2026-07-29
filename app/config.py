# config.py
# ============================================================
# INTENTIONALLY INSECURE FILE — DO NOT USE IN PRODUCTION
# This hardcoded secret is planted on purpose so that:
#   - Level 1 (Bandit / Semgrep / pre-commit) catches it
#   - Level 3 (CI/CD secret scanning) catches it
# ============================================================

db_password = "admin123"          # <-- Bandit: hardcoded_password_string
SECRET_KEY = "supersecretkey123"  # <-- Bandit: hardcoded_bind_all_interfaces / weak secret
AWS_ACCESS_KEY = "AKIAFAKEEXAMPLE1234"   # <-- secret-scanner bait (Gitleaks/TruffleHog)
AWS_SECRET_KEY = "fakeSecretAccessKeyExample1234567890abcd"
