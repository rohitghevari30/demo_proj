# SecureApp Pipeline

End-to-end DevSecOps demo: a vulnerable-by-design app secured
layer by layer across 8 levels, deployed for $0 on free-tier infra.

See `docs/` for level-by-level findings and the demo script.
See `app/README.md` (if present) for the vulnerable app's own docs.

## Structure
- `app/` — the vulnerable Flask app (Levels 1, 2, 4, 6, 8 target)
- `infra/` — Terraform IaC (Level 5)
- `frontend/` — React dashboard (Level 8 + overall reporting UI)
- `monitoring/` — Prometheus rules + AI incident reporting (Level 8)
- `scripts/` — Nmap/Shodan/SBOM utility scripts (Levels 2, 7)
- `.github/workflows/` — CI/CD pipeline gates (Levels 3-7)
- `docs/` — findings, OWASP mapping, demo script

## Getting started
```bash
cd app
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
