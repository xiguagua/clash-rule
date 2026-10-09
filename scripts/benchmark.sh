#!/usr/bin/env bash
set -euo pipefail

# Find repository root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Check for python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required to run the benchmark comparison script." >&2
    exit 1
fi

exec python3 "${REPO_ROOT}/scripts/compare_benchmark.py" "$@"
