"""
Level 7 — Periodic passive Shodan lookup to confirm the deployed
IP hasn't leaked into Shodan's public index.
"""
import os
import shodan

API_KEY = os.environ.get("SHODAN_API_KEY", "")
DEPLOYED_IP = os.environ.get("BACKEND_IP", "")


def check_exposure():
    api = shodan.Shodan(API_KEY)
    try:
        result = api.host(DEPLOYED_IP)
        print("WARNING: IP found in Shodan index:", result)
    except shodan.APIError:
        print("Confirmed: nothing found in Shodan's index for this IP.")


if __name__ == "__main__":
    check_exposure()
