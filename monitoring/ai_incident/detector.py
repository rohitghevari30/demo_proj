"""
Level 8 — Rule-based incident detector.
Watches for patterns (e.g. brute-force) and flags incidents
for the AI (Groq) to explain.
"""

import os
import requests

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

THRESHOLD = 200


def failed_logins(ip: str = None, window: str = "3m") -> float:
    """
    Query Prometheus for the number of failed logins in the given window.
    NOTE: current failed_logins_total counter is not labeled per-IP,
    so this currently returns the aggregate count across all sources.
    If you add an `ip` label to the counter in app.py later, this can
    filter with: increase(failed_logins_total{ip="<ip>"}[<window>])
    """
    query = f'increase(failed_logins_total[{window}])'
    try:
        resp = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[ERROR] Could not reach Prometheus: {e}")
        return 0.0

    if data.get("status") != "success":
        print(f"[ERROR] Prometheus query failed: {data}")
        return 0.0

    result = data["data"]["result"]
    if not result:
        return 0.0

    return float(result[0]["value"][1])


def explain_incident(ip: str, incident_type: str, value: float) -> str:
    """Ask Groq to explain the incident in plain language."""
    if not GROQ_API_KEY:
        return "(GROQ_API_KEY not set — skipping AI summary.)"

    prompt = (
        f"A {incident_type.replace('_', ' ')} incident was detected from "
        f"source {ip}: {value:.0f} failed login attempts in the last 3 minutes, "
        f"exceeding the threshold of {THRESHOLD}. Write a concise 2-3 sentence "
        f"incident summary for a security analyst, including likely severity "
        f"and a recommended immediate action."
    )

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except requests.RequestException as e:
        return f"(Groq API call failed: {e})"


def flag_incident(ip: str, incident_type: str, value: float = None):
    print(f"[INCIDENT FLAGGED] type={incident_type} ip={ip}")
    if value is not None:
        summary = explain_incident(ip, incident_type, value)
        print("\n--- AI Incident Summary ---")
        print(summary)


if __name__ == "__main__":
    # Example usage / manual test hook
    test_ip = "45.33.32.156"
    count = failed_logins(test_ip)
    print(f"Current failed_logins (3m window): {count:.2f}")

    if count > THRESHOLD:
        flag_incident(test_ip, "brute_force", value=count)
    else:
        print("No incident: value is within normal range.")