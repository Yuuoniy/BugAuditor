#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE_ARG=()
if [[ "${1:-}" == "--reference" ]]; then
  REFERENCE_ARG=(--reference)
fi

"${SCRIPT_DIR}/run_pattern_reasoning.sh" "${REFERENCE_ARG[@]}"
"${SCRIPT_DIR}/run_bug_auditing.sh" "${REFERENCE_ARG[@]}"
