#!/usr/bin/env bash
# Level 2 — Generate a Software Bill of Materials for the app's dependencies.
# Requires: pip install cyclonedx-bom

cd "$(dirname "$0")/../app" || exit 1
cyclonedx-py -r -i requirements.txt -o ../docs/sbom.json
echo "SBOM written to docs/sbom.json"
