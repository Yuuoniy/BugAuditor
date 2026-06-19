#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"
START_MS="$(ae_now_ms)"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "r_bug_auditing")"
REFERENCE_DIR="${SCRIPT_DIR}/reference"
USE_REFERENCE=0
if [[ "${1:-}" == "--reference" ]]; then
  USE_REFERENCE=1
  shift
fi

PER_PATTERN_AUDIT_LIMIT="${1:-10}"
MIN_PER_PATTERN_AUDIT_LIMIT=10
WORKERS="${2:-8}"

if [[ "${PER_PATTERN_AUDIT_LIMIT}" -lt "${MIN_PER_PATTERN_AUDIT_LIMIT}" ]]; then
  echo "[ae] per-pattern audit limit must be at least ${MIN_PER_PATTERN_AUDIT_LIMIT}" >&2
  exit 1
fi

rm -f \
  "${RESULT_DIR}/bug_detection_cases.csv" \
  "${RESULT_DIR}/confirmed_bugs.csv" \
  "${RESULT_DIR}/defensive_patterns.csv" \
  "${RESULT_DIR}/bug_localization_probe.tsv" \
  "${RESULT_DIR}/bug_localization_probe_summary.json" \
  "${RESULT_DIR}/audited_candidates.jsonl" \
  "${RESULT_DIR}/violation_reports.json" \
  "${RESULT_DIR}/bug_detection_summary.json" \
  "${RESULT_DIR}/exact_audit_results.json" \
  "${RESULT_DIR}/llm_run_summary.csv" \
  "${RESULT_DIR}/llm_run_summary.md" \
  "${RESULT_DIR}/bug_auditing_results.json" \
  "${RESULT_DIR}/reduced_bug_auditing_cases.csv" \
  "${RESULT_DIR}/reduced_bug_auditing_summary.csv" \
  "${RESULT_DIR}/reduced_bug_auditing_summary.md" \
  "${RESULT_DIR}/reduced_bug_patterns.csv" \
  "${RESULT_DIR}/run_outputs.md" \
  "${RESULT_DIR}/audit_candidate_plan.csv" \
  "${RESULT_DIR}/selected_bug_auditing_cases.csv" \
  "${RESULT_DIR}/selected_bug_detection_cases.csv"
rm -rf "${RESULT_DIR}/patterns"

for name in \
  bug_auditing_results.csv \
  bug_reports.json \
  bug_auditing_summary.json \
  bug_auditing_summary.md \
  audit_candidate_plan.csv \
  expected_output.txt
do
  ae_copy_reference "${REFERENCE_DIR}/${name}" "${RESULT_DIR}"
done

echo "[ae] per-pattern audit limit: ${PER_PATTERN_AUDIT_LIMIT} comparable functions (confirmed bugs always included)"
echo "[ae] pattern input: ${REFERENCE_DIR}/defensive_patterns.csv"
echo "[ae] pattern files: ${REFERENCE_DIR}/patterns/"

if [[ "${USE_REFERENCE}" == "0" ]]; then
  ae_need_config "${REPO_ROOT}"
  ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
  ae_need_source_path "${REPO_ROOT}" "linux"
  ae_need_llm_config "${REPO_ROOT}"
  cd "${REPO_ROOT}"

  python artifact/r_bug_auditing/build_audit_candidates.py \
    --patterns "${REFERENCE_DIR}/defensive_patterns.csv" \
    --confirmed-bugs "${REFERENCE_DIR}/confirmed_bugs.csv" \
    --output-csv "${RESULT_DIR}/audit_candidate_plan.csv" \
    --per-pattern-limit "${PER_PATTERN_AUDIT_LIMIT}" \
    --repo linux

  python artifact/r_bug_auditing/audit_cases.py \
    --cases "${RESULT_DIR}/audit_candidate_plan.csv" \
    --output-json "${RESULT_DIR}/exact_audit_results.json" \
    --output-csv "${RESULT_DIR}/bug_auditing_results.csv" \
    --patterns "${REFERENCE_DIR}/defensive_patterns.csv" \
    --repo linux \
    --workers "${WORKERS}"
fi

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"
if [[ "${USE_REFERENCE}" == "1" ]]; then
  RUN_KIND="reference"
else
  RUN_KIND="run"
fi
ae_write_timing "${RESULT_DIR}/measured_runtime.csv" "r_bug_auditing" "${RUN_KIND}" "${ELAPSED}"

if [[ "${USE_REFERENCE}" == "0" ]]; then
  python3 - \
    "${RESULT_DIR}/exact_audit_results.json" \
    "${RESULT_DIR}/llm_run_summary.csv" \
    "${RESULT_DIR}/llm_run_summary.md" \
    "${ELAPSED}" \
    "${PER_PATTERN_AUDIT_LIMIT}" \
    "${WORKERS}" <<'PY'
import csv
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
csv_path = Path(sys.argv[2])
md_path = Path(sys.argv[3])
elapsed = sys.argv[4]
per_pattern_limit = sys.argv[5]
workers = sys.argv[6]

rows = json.loads(json_path.read_text(encoding="utf-8"))
positive_cases = sum(1 for r in rows if r["case"].get("expected") == "bug")
random_comparable = sum(1 for r in rows if r["case"].get("expected") == "unknown")
matched = sum(1 for r in rows if r["matches_expected"] is True)
labeled = sum(1 for r in rows if r["matches_expected"] is not None)
positive_detections = sum(
    1
    for r in rows
    if r["case"].get("expected") == "bug" and r["detected_bug"] == "yes"
)
random_detections = sum(
    1
    for r in rows
    if r["case"].get("expected") == "unknown" and r["detected_bug"] == "yes"
)
prompt_tokens = sum(
    (r["audit"].get("prompt_tokens") or 0)
    + (r["audit"].get("followup_prompt_tokens") or 0)
    for r in rows
)
completion_tokens = sum(
    (r["audit"].get("response_tokens") or 0)
    + (r["audit"].get("followup_response_tokens") or 0)
    for r in rows
)
total_tokens = sum(
    (r["audit"].get("total_tokens") or 0)
    + (r["audit"].get("followup_total_tokens") or 0)
    for r in rows
)
followup_calls = sum(1 for r in rows if r["audit"].get("used_followup"))

metrics = [
    ("per_pattern_audit_limit", per_pattern_limit),
    ("workers", workers),
    ("elapsed_seconds", elapsed),
    ("cases", len(rows)),
    ("labeled_cases", labeled),
    ("matched_expected", matched),
    ("known_bug_cases", positive_cases),
    ("random_comparable_candidates", random_comparable),
    ("known_bug_detections", positive_detections),
    ("random_comparable_detections", random_detections),
    ("known_bug_recall", f"{positive_detections}/{positive_cases}"),
    ("prompt_tokens", prompt_tokens),
    ("completion_tokens", completion_tokens),
    ("total_tokens", total_tokens),
    ("followup_calls", followup_calls),
]

with csv_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["metric", "value"])
    writer.writerows(metrics)

md_path.write_text(
    "\n".join(
        [
            "# Reproduced Bug Detection LLM Run",
            "",
            f"Command setting: per-pattern audit limit `{per_pattern_limit}`, workers `{workers}`.",
            "",
            (
                f"Known-bug recall: `{positive_detections}/{positive_cases}`. "
                f"Random comparable candidates flagged: `{random_detections}/{random_comparable}`."
            ),
            "",
            (
                f"Measured wall time: `{elapsed}` seconds. Token usage: "
                f"`{prompt_tokens}` prompt, `{completion_tokens}` completion, "
                f"`{total_tokens}` total tokens. Follow-up calls: `{followup_calls}`."
            ),
            "",
        ]
    ),
    encoding="utf-8",
)
print(f"[ae] wrote LLM run summary to {csv_path}")
PY

  python artifact/r_bug_auditing/scripts/build_reference.py \
    --cases "${RESULT_DIR}/audit_candidate_plan.csv" \
    --patterns "${REFERENCE_DIR}/defensive_patterns.csv" \
    --audit-json "${RESULT_DIR}/exact_audit_results.json" \
    --llm-summary "${RESULT_DIR}/llm_run_summary.csv" \
    --output-dir "${RESULT_DIR}" \
    --repo linux
fi

ae_show_file "${RESULT_DIR}/expected_output.txt" 20
echo "[ae] reproduced bug detection elapsed seconds: ${ELAPSED}"
