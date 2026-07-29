"""
Level 8 — Sends flagged incident context to Groq (Llama 3.1 8B)
and returns a human-readable incident report.
"""
import os
import requests

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def explain_incident(incident_context: str) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": incident_context}],
    }
    resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


if __name__ == "__main__":
    example = "Brute force detected from 45.33.32.156. 847 failed logins in 60s."
    print(explain_incident(example))
