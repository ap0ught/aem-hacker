#!/usr/bin/env bash
# Run the aem-hacker test suite. No third-party dependencies required.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -m unittest discover -s tests -p 'test_*.py' -v "$@"
