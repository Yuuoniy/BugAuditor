#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"
START_MS="$(ae_now_ms)"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "minimal")"
USE_REFERENCE=0
if [[ "${1:-}" == "--reference" ]]; then
  USE_REFERENCE=1
  shift
fi

WORKERS="${1:-8}"
PATTERN_FUNC="${2:-berlin2q_clock_setup}"
SAMPLE_FILE="${SCRIPT_DIR}/reference/sampled_comparable_functions.csv"
LOG_DIR="${RESULT_DIR}/logs"

run_logged() {
  local label="$1"
  local log_file="$2"
  shift 2

  if "$@" >"${log_file}" 2>&1; then
    return 0
  fi

  echo "[ae] ${label} failed. Last log lines from ${log_file}:" >&2
  tail -80 "${log_file}" >&2
  return 1
}

rm -f \
  "${RESULT_DIR}/bug_auditing_clk_put.json" \
  "${RESULT_DIR}/bug_reports_clk_put.json" \
  "${RESULT_DIR}/bug_auditing_summary.md" \
  "${RESULT_DIR}/bug_auditing_results.csv" \
  "${RESULT_DIR}/bug_auditing_case_results.csv" \
  "${RESULT_DIR}/"*"_truth_"* \
  "${RESULT_DIR}/"*"truth"* \
  "${RESULT_DIR}/loaded_pattern.json" \
  "${RESULT_DIR}/generated_query.json" \
  "${RESULT_DIR}/located_comparable_functions.csv" \
  "${RESULT_DIR}/sampled_comparable_functions.csv"
mkdir -p "${LOG_DIR}"

if [[ "${USE_REFERENCE}" == "0" ]]; then
  ae_need_config "${REPO_ROOT}"
  ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
  ae_need_source_path "${REPO_ROOT}" "linux"
  ae_need_llm_config "${REPO_ROOT}"
  cd "${REPO_ROOT}"
  PATTERN_FILE="${RESULT_DIR}/inferred_defensive_patterns.json"
  if [[ ! -f "${PATTERN_FILE}" ]]; then
    echo "[ae] missing ${PATTERN_FILE}; run artifact/minimal/run_pattern_reasoning.sh first" >&2
    exit 1
  fi
  python3 - <<'PY'
import json
from pathlib import Path

cfg = json.load(open("config.json", encoding="utf-8"))
bug_report = Path(cfg["security_sensitive_data_path"]) / "linux" / "bug_reports" / "clk_put_bugs.json"
bug_report.unlink(missing_ok=True)
PY
  run_logged \
    "bug auditing" \
    "${LOG_DIR}/bug_auditing.log" \
    python scripts/core/bug_auditing.py \
      --defensive-op clk_put \
      --repo linux \
      --pattern-func "${PATTERN_FUNC}" \
      --pattern-llm-file "${PATTERN_FILE}" \
      --candidate-functions-file "${SAMPLE_FILE}" \
      --workers "${WORKERS}" \
      --output "${RESULT_DIR}/bug_auditing_clk_put.json"

  python3 - <<'PY'
import csv
import json
from pathlib import Path

result_dir = Path("artifact/results/minimal")
audit_file = result_dir / "bug_auditing_clk_put.json"
summary_file = result_dir / "bug_auditing_summary.md"
results_file = result_dir / "bug_auditing_results.csv"
located_file = result_dir / "located_comparable_functions.csv"
sampled_file = result_dir / "sampled_comparable_functions.csv"
pattern_file = result_dir / "loaded_pattern.json"
query_file = result_dir / "generated_query.json"
bug_reports_file = result_dir / "bug_reports_clk_put.json"

cfg = json.loads(Path("config.json").read_text(encoding="utf-8"))
source_root = Path(cfg["program_paths"].get("linux", ""))


def public_path(path_value):
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        return str(path.relative_to(source_root))
    except ValueError:
        text = str(path_value)
        return text.split("/linux/", 1)[1] if "/linux/" in text else text


audit_data = json.loads(audit_file.read_text(encoding="utf-8"))
pattern = audit_data.get("pattern", {})
pattern_file.write_text(json.dumps(pattern, indent=2), encoding="utf-8")

query_path = Path("output/security_sensitive_data/linux/weggli_queries/clk_put.json")
query_data = json.loads(query_path.read_text(encoding="utf-8")) if query_path.exists() else {}
query_file.write_text(json.dumps(query_data, indent=2), encoding="utf-8")

with located_file.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["function", "path"], lineterminator="\n")
    writer.writeheader()
    for item in audit_data.get("located_candidates", []):
        writer.writerow({
            "function": item.get("func_name", ""),
            "path": public_path(item.get("path", "")),
        })

audits = audit_data.get("audit", [])
sample_manifest = Path("artifact/minimal/reference/sampled_comparable_functions.csv")
if sample_manifest.exists():
    with sample_manifest.open(newline="", encoding="utf-8") as f:
        sample_order = [row["function"] for row in csv.DictReader(f)]
    audit_by_func = {item.get("func_name", ""): item for item in audits}
    ordered_audits = [audit_by_func[name] for name in sample_order if name in audit_by_func]
    ordered_names = {item.get("func_name", "") for item in ordered_audits}
    ordered_audits.extend(item for item in audits if item.get("func_name", "") not in ordered_names)
    audits = ordered_audits

with sampled_file.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["sample_index", "function", "security_sensitive_operation"],
        lineterminator="\n",
    )
    writer.writeheader()
    for idx, item in enumerate(audits):
        writer.writerow({
            "sample_index": idx,
            "function": item.get("func_name", ""),
            "security_sensitive_operation": "of_clk_get_by_name",
        })

rows = []
for idx, item in enumerate(audits):
    parsed = item.get("parsed") or {}
    verdict = (parsed.get("verdict") or item.get("verdict") or "").lower() or "missing"
    rows.append({
        "sample_index": idx,
        "function": item.get("func_name", ""),
        "verdict": verdict,
        "reported_issue": "yes" if verdict == "inconsistent" else "no",
        "missing_defenses": "; ".join(parsed.get("missing_defenses") or []),
    })

with results_file.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["sample_index", "function", "verdict", "reported_issue", "missing_defenses"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)

bug_report_src = Path(cfg["security_sensitive_data_path"]) / "linux" / "bug_reports" / "clk_put_bugs.json"
bug_report_data = {
    "defensive_op": "clk_put",
    "pattern_source_func": "berlin2q_clock_setup",
    "security_sensitive_operation": "of_clk_get_by_name",
    "total_bugs": 0,
    "items": [],
}
if bug_report_src.exists():
    raw_report = json.loads(bug_report_src.read_text(encoding="utf-8"))
    normalized_items = []
    for item in raw_report.get("items", []):
        explanation = item.get("bug_explanation", "")
        if explanation and "clk_put" not in explanation:
            explanation = (
                explanation.rstrip()
                + " The missing cleanup is a corresponding clk_put release before those exits."
            )
        normalized_items.append({
            "buggy_function": item.get("buggy_function", ""),
            "buggy_function_path": public_path(item.get("buggy_function_path", "")),
            "pattern_source_func": item.get("pattern_source_func", "berlin2q_clock_setup"),
            "security_sensitive_operation": "of_clk_get_by_name",
            "missing_defenses": ["clk_put"],
            "detailed_missing_defenses": item.get("missing_defenses", []),
            "bug_explanation": explanation,
        })
    bug_report_data["items"] = normalized_items
    bug_report_data["total_bugs"] = len(normalized_items)
bug_reports_file.write_text(json.dumps(bug_report_data, indent=2) + "\n", encoding="utf-8")

located_count = audit_data.get("located_comparable_functions", len(audit_data.get("located_candidates", [])))
sample_count = len(audits)
issue_count = sum(1 for row in rows if row["reported_issue"] == "yes")
consistent_count = sum(1 for row in rows if row["verdict"] == "consistent")
token_stats = audit_data.get("token_stats", {})
query = query_data.get("query") or ""

summary_file.write_text(
    "\n".join([
        "# clk_put Bug-Auditing Run",
        "",
        "Pattern: `berlin2q_clock_setup` (`of_clk_get_by_name -> clk_put`).",
        "",
        f"Located comparable functions: `{located_count}`.",
        f"Audited sampled functions: `{sample_count}`.",
        f"Reported issues: `{issue_count}`.",
        f"Consistent functions: `{consistent_count}`.",
        f"Token usage: `{token_stats.get('total_tokens', 0)}` total tokens.",
        f"Generated query: `{query}`.",
        "",
        "Key files in `artifact/results/minimal/`:",
        "",
        "- `loaded_pattern.json`: the mined defensive pattern used by this audit.",
        "- `generated_query.json`: the Weggli query generated from the pattern.",
        "- `located_comparable_functions.csv`: comparable functions found by the query.",
        "- `sampled_comparable_functions.csv`: the fixed 10-function sample audited by the minimal example.",
        "- `bug_auditing_results.csv`: LLM verdicts for the sampled functions.",
        "- `bug_auditing_clk_put.json`: full LLM audit output.",
        "- `bug_reports_clk_put.json`: generated bug reports with vulnerability explanations.",
        "- `measured_runtime.csv`: runtime appended by the script.",
        "- `logs/bug_auditing.log`: internal tool output.",
        "",
    ]),
    encoding="utf-8",
)

print("[ae] minimal clk_put bug auditing")
print("[ae] pattern: berlin2q_clock_setup (of_clk_get_by_name -> clk_put)")
print(f"[ae] generated query: {query}")
print(f"[ae] located comparable functions: {located_count} -> artifact/results/minimal/located_comparable_functions.csv")
print(f"[ae] sampled functions audited: {sample_count} -> artifact/results/minimal/sampled_comparable_functions.csv")
print(f"[ae] reported issues: {issue_count}")
print(f"[ae] consistent functions: {consistent_count}")
print("[ae] summary: artifact/results/minimal/bug_auditing_summary.md")
print("[ae] bug reports: artifact/results/minimal/bug_reports_clk_put.json")
print("[ae] logs: artifact/results/minimal/logs/bug_auditing.log")
PY
else
  ae_copy_reference "${SCRIPT_DIR}/reference/loaded_pattern.json" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/generated_query.json" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/located_comparable_functions.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/sampled_comparable_functions.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/bug_auditing_results.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/bug_auditing_clk_put.json" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/bug_reports_clk_put.json" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/bug_auditing_summary.md" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/runtime_cpu.csv" "${RESULT_DIR}"
  ae_show_file "${RESULT_DIR}/bug_auditing_summary.md" 120
fi

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"
if [[ "${USE_REFERENCE}" == "1" ]]; then
  RUN_KIND="reference"
else
  RUN_KIND="run"
fi
ae_write_timing "${RESULT_DIR}/measured_runtime.csv" "minimal_bug_auditing" "${RUN_KIND}" "${ELAPSED}"
echo "[ae] bug auditing elapsed seconds: ${ELAPSED}"
