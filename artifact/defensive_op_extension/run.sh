#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "defensive_op_extension")"

ae_copy_reference "${SCRIPT_DIR}/reference/table11_paper_expected.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/extend_pattern_summary_frozen.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/extension_ops_summary.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/extended_defensive_ops_sample.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/extension_pattern_source_summary.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/extension_inferred_patterns_sample.csv" "${RESULT_DIR}"
ae_copy_reference "${SCRIPT_DIR}/reference/bug_auditing_pattern_sources.csv" "${RESULT_DIR}"

echo "[ae] extension experiment 1: function-call seed defensive operations"
ae_show_file "${RESULT_DIR}/table11_paper_expected.csv" 80
echo "[ae] extension op summary:"
ae_show_file "${RESULT_DIR}/extension_ops_summary.csv" 20
echo "[ae] pattern source summary:"
ae_show_file "${RESULT_DIR}/extension_pattern_source_summary.csv" 20
echo "[ae] bug auditing uses both initial seed patterns and extended patterns:"
ae_show_file "${RESULT_DIR}/bug_auditing_pattern_sources.csv" 20
