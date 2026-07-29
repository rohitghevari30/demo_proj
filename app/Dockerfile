# ============================================================
# INSECURE Dockerfile — "BEFORE" state for Level 4 demo
# Run Trivy / Hadolint / Docker Bench against this first,
# document the findings, THEN replace with the fixed version
# (python:3.12-slim + non-root USER) shown in your project doc.
# ============================================================
#FROM python:3.8
# ^ old base image, likely 200+ CVEs — Trivy should flag this

#WORKDIR /app

#COPY requirements.txt .
#RUN pip install -r requirements.txt

#COPY . .

# No USER instruction here — container runs as root by default
# Hadolint / Docker Bench should flag this (DKL-DI-0001-ish / CIS 4.1)

#EXPOSE 5000

# Running with debug=True baked into app.py is also a bad practice
# for a container image meant to run in any staging/prod context
#CMD ["python", "app.py"]


FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]