# Level 6 — Findings

## Before (vulnerable state)
Flask backend deployed to a live AWS EC2 staging instance (via systemd service), reachable
at `http://98.89.4.135:5000`. Tested with both automated DAST scanning and manual
verification.

## Tool(s) used
- OWASP ZAP Baseline Scan v0.12.0 (via `zaproxy/action-baseline` GitHub Action,
  `.github/workflows/dast-scan.yml`) — passive scanning only
- Manual verification via `curl`/`Invoke-WebRequest` for injection-class vulnerabilities
  (ZAP's baseline scan is passive-only and cannot detect SQLi/XSS; a full active scan
  was attempted but proved unreliable on GitHub-hosted runners — see notes below)

## Vulnerabilities found

### Automated (ZAP baseline scan): 8 WARN-NEW, 0 FAIL-NEW, 59 PASS
- Missing Anti-clickjacking Header (no `X-Frame-Options`)
- X-Content-Type-Options Header Missing
- Server Leaks Version Information via `Server` header (`Werkzeug/3.1.6 Python/3.14.4`)
- Content-Security-Policy Header Not Set
- Permissions-Policy Header Not Set
- Cross-Origin-Embedder-Policy Header Missing
- Non-Storable Content
- Authentication Request Identified (informational)

### Manual verification: SQL Injection (auth bypass) on `/login`
Payload: `username=admin' OR '1'='1&password=x`
Result: `200 OK — "Login successful!"` — authentication bypassed with no valid
credentials, confirming the login query is not parameterized.

### Manual verification: Reflected XSS on `/search`
Payload: `query=<script>alert(1)</script>`
Result: payload reflected unescaped in the HTML response body
(`<p>You searched for: <script>alert(1)</script></p>`) — confirms output is not
escaped/auto-sanitized before being rendered.

### Also present per code comments (Level 3 Bandit/CI gate)
- `debug=True` in `app.run()` — exposes the Werkzeug interactive debugger
  (arbitrary code execution risk if reachable)

## Fix applied
*(to be completed once code fixes are made)*
- Parameterize the `/login` query (use SQLAlchemy bound parameters / `?` placeholders
  instead of string formatting)
- Auto-escape or explicitly `markupsafe.escape()` user input rendered in `/search`
- Set `debug=False` for any non-local deployment
- Add security headers via `flask-talisman` (covers CSP, X-Frame-Options,
  X-Content-Type-Options, etc. in one pass) or set manually via `after_request`

## After (re-scan confirming fix)
*(to be completed after fixes are deployed and re-scanned)*

## Notes on tooling
ZAP's full active scan (`zaproxy/action-full-scan`) was attempted to catch SQLi/XSS
automatically, but repeatedly failed on GitHub-hosted runners — ZAP spent its full
10-minute startup window auto-updating 15+ bundled add-ons, then hit a port-binding
conflict and terminated before scanning began. This is a known reliability issue with
that action combination, not specific to this app. Given the scope of this project,
the baseline (passive) scan was kept as the CI-integrated pipeline step, with
injection-class vulnerabilities verified manually instead — a reasonable and common
supplement to automated DAST in real security workflows.