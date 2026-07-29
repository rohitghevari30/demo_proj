# Live Demo Script

Walk through each level in order: show the attack live, show the tool
catching it, show the fix, re-run the tool to confirm it's clean.

1. Level 1 — commit the hardcoded secret, watch pre-commit block it
2. Level 2 — run pip-audit, show the CVE, upgrade, re-run clean
3. Level 3 — open a PR with a planted SQLi bug, show CI blocking it
4. Level 4 — show Trivy findings on old Dockerfile, then the fixed one
5. Level 5 — show Checkov findings on insecure Terraform, then fixed
6. Level 6 — run ZAP against staging, show XSS/SQLi found, fix, re-scan
7. Level 7 — run Nmap, show closed ports, show Shodan clean
8. Level 8 — simulate brute-force, show Prometheus alert -> AI report -> dashboard
