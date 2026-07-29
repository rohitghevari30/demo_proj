"""
Level 7 — Wrapper to run an Nmap scan against the deployed backend
and save/print results. Intended to be run manually or via the
network-check.yml GitHub Actions workflow.
"""
import subprocess
import os

BACKEND_IP = os.environ.get("BACKEND_IP", "127.0.0.1")


def run_scan():
    result = subprocess.run(
        ["nmap", "-sV", BACKEND_IP],
        capture_output=True, text=True
    )
    print(result.stdout)
    return result.stdout


if __name__ == "__main__":
    run_scan()
