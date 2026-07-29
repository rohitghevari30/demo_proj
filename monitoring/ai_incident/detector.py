"""
Level 8 — Rule-based incident detector.
Watches for patterns (e.g. brute-force) and flags incidents
for the AI (Groq) to explain.
"""

def failed_logins(ip: str, window: str = "60s") -> int:
    # TODO: query Prometheus / your logs for real failed-login counts
    raise NotImplementedError


def flag_incident(ip: str, incident_type: str):
    # TODO: write incident to a queue/DB that groq_client.py reads from
    print(f"[INCIDENT FLAGGED] type={incident_type} ip={ip}")


if __name__ == "__main__":
    # Example usage / manual test hook
    test_ip = "45.33.32.156"
    if failed_logins(test_ip) > 200:
        flag_incident(test_ip, "brute_force")
