#!/usr/bin/env bash
# Run every check in this repository. No installs; Python 3.9+, Node 20+, git and bash.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s formats/bundle/tests -p 'test_*.py'
python3 -m unittest discover -s tools/ci-local -p 'test_*.py'
node --test formats/bundle/tests/bundle-verify.test.mjs contracts/sites-security/sites-security.test.mjs
python3 -c "import json; json.load(open('formats/bundle/lighthouse-bundle-v1.schema.json')); json.load(open('STATUS.json'))"
echo "All checks passed."
