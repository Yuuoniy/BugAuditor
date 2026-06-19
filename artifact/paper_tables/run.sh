#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/artifact/results/paper_tables}"

python3 "${SCRIPT_DIR}/scripts/generate_paper_tables.py" --out "${OUT_DIR}"
