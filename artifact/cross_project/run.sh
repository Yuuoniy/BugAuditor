#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "cross_project")"

ae_copy_reference "${SCRIPT_DIR}/reference/table16_expected.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/table16_openssl_ffmpeg_stats.tex" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/deepseek_rerun_summary.md" "${RESULT_DIR}"
ae_show_file "${RESULT_DIR}/table16_expected.csv" 80
