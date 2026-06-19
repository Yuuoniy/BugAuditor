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

DEFAULT_SAMPLE_SIZE=10
DEFAULT_WORKERS=8
SAMPLE_SIZE="${1:-${DEFAULT_SAMPLE_SIZE}}"
WORKERS="${2:-${DEFAULT_WORKERS}}"
SAMPLE_FILE="${SCRIPT_DIR}/reference/defensive_code_snippets_sample.csv"
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
  "${RESULT_DIR}/defensive_code_snippets.json" \
  "${RESULT_DIR}/defensive_code_snippet_sample.csv" \
  "${RESULT_DIR}/defensive_code_snippets_sample.csv" \
  "${RESULT_DIR}/input_for_defensive_pattern_reasoning.json" \
  "${RESULT_DIR}/inferred_defensive_patterns.json" \
  "${RESULT_DIR}/inferred_defensive_patterns_sample.csv" \
  "${RESULT_DIR}/defensive_pattern_templates.csv" \
  "${RESULT_DIR}/pattern_reasoning_summary.json" \
  "${RESULT_DIR}/pattern_reasoning_summary.md" \
  "${RESULT_DIR}/expected_pattern_reasoning_output.txt" \
  "${RESULT_DIR}/measured_runtime.csv"
mkdir -p "${LOG_DIR}"

if [[ "${USE_REFERENCE}" == "0" ]]; then
  ae_need_config "${REPO_ROOT}"
  ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
  ae_need_command "joern-parse" "Joern"
  ae_need_command "joern-export" "Joern"
  ae_need_tree_sitter "${REPO_ROOT}"
  ae_need_source_path "${REPO_ROOT}" "linux"
  ae_need_llm_config "${REPO_ROOT}"

  cd "${REPO_ROOT}"
  python3 - <<'PY'
import json
import shutil
from pathlib import Path

cfg = json.load(open("config.json", encoding="utf-8"))
data_root = Path(cfg["security_sensitive_data_path"])
repo_root = data_root / "linux"

for p in [
    data_root / "weggli_usage" / "clk_put.json",
    repo_root / "contexts" / "clk_put.json",
    repo_root / "contexts" / "clk_put_expanded.json",
    repo_root / "llm_inputs" / "clk_put.json",
    repo_root / "raw" / "clk_put.json",
    repo_root / "detail" / "clk_put.json",
    repo_root / "spec" / "clk_put.json",
]:
    p.unlink(missing_ok=True)

for pattern in [
    "contexts/clk_put_ts*.json",
    "llm_reports/clk_put*.json",
    "llm_reports/clk_put*.parsed.json",
    "llm_reports/clk_put*.dialog.json",
]:
    for p in repo_root.glob(pattern):
        p.unlink(missing_ok=True)

shutil.rmtree(repo_root / "minimal_internal", ignore_errors=True)
PY

  run_logged \
    "defensive code locating" \
    "${LOG_DIR}/defensive_code_locating.log" \
    python scripts/core/defensive_code_locating.py clk_put linux --single --workers "${WORKERS}"

  run_logged \
    "defensive pattern reasoning" \
    "${LOG_DIR}/defensive_pattern_reasoning.log" \
    python scripts/core/defensive_pattern_reasoning.py clk_put linux \
      --single \
      --step both \
      --sample-functions-file "${SAMPLE_FILE}" \
      --limit "${SAMPLE_SIZE}" \
      --workers "${WORKERS}" \
      --force-recompute \
      --llm-suffix "_minimal" \
      --output-subdir minimal_internal

  export AE_SAMPLE_SIZE="${SAMPLE_SIZE}"
  export AE_WORKERS="${WORKERS}"
  python3 - <<'PY'
import json
import os
import shutil
from pathlib import Path


def count_weggli_usages(path: Path) -> int:
    if not path.exists():
        return 0
    data = json.load(path.open(encoding="utf-8"))
    total = 0
    for file_set in data:
        for file_entry in file_set:
            total += len(file_entry.get("matches", []))
    return total


def load_json_len(path: Path) -> int:
    if not path.exists():
        return 0
    return len(json.load(path.open(encoding="utf-8")))


repo = Path.cwd()
cfg = json.load(open("config.json", encoding="utf-8"))
data_root = Path(cfg["security_sensitive_data_path"])
base = data_root / "linux"
internal = base / "minimal_internal"
result_dir = repo / "artifact" / "results" / "minimal"
result_dir.mkdir(parents=True, exist_ok=True)

usage_file = data_root / "weggli_usage" / "clk_put.json"
contexts = base / "contexts" / "clk_put.json"
inputs = internal / "llm_inputs" / "clk_put.json"
reports = internal / "llm_reports"
parsed_files = sorted(
    reports.glob("clk_put*.parsed.json"),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)
latest_parsed = parsed_files[0] if parsed_files else None

parsed_entries = []
if latest_parsed:
    parsed_entries = json.load(latest_parsed.open(encoding="utf-8"))
valid_inferred_patterns = sum(
    1
    for item in parsed_entries
    if (
        item.get("llm_output", {}).get("security_sensitive_behaviors")
        or item.get("llm_output", {}).get("defensive_behaviors")
        or item.get("llm_output", {}).get("analysis")
    )
)

published = {}
if contexts.exists():
    dst = result_dir / "defensive_code_snippets.json"
    shutil.copy2(contexts, dst)
    published["defensive_code_snippets"] = str(dst.relative_to(repo))
if inputs.exists():
    dst = result_dir / "input_for_defensive_pattern_reasoning.json"
    shutil.copy2(inputs, dst)
    published["input_for_defensive_pattern_reasoning"] = str(dst.relative_to(repo))
if latest_parsed:
    dst = result_dir / "inferred_defensive_patterns.json"
    shutil.copy2(latest_parsed, dst)
    published["inferred_defensive_patterns"] = str(dst.relative_to(repo))

raw_usages = count_weggli_usages(usage_file)
snippet_count = load_json_len(contexts)
reasoning_inputs = load_json_len(inputs)
inferred_patterns = valid_inferred_patterns

if reasoning_inputs and inferred_patterns < reasoning_inputs:
    raise SystemExit(
        "LLM reasoning did not produce valid inferred patterns for every input. "
        "Check artifact/results/minimal/logs/defensive_pattern_reasoning.log"
    )

summary = {
    "seed_defensive_op": "clk_put",
    "raw_usages_located": raw_usages,
    "valid_defensive_code_snippets": snippet_count,
    "reasoning_sample_size": int(os.environ["AE_SAMPLE_SIZE"]),
    "input_for_defensive_pattern_reasoning": reasoning_inputs,
    "inferred_defensive_patterns": inferred_patterns,
    "workers": int(os.environ["AE_WORKERS"]),
    "paper_table9_reference": {
        "raw_usages": 359,
        "collected_functions": 181,
        "inferred_defensive_patterns": 8,
    },
    "published_files": published,
    "internal_cache_note": (
        "The minimal AE script publishes reviewer-facing files under "
        "artifact/results/minimal and removes transient clk_put cache files."
    ),
}

(result_dir / "pattern_reasoning_summary.json").write_text(
    json.dumps(summary, indent=2),
    encoding="utf-8",
)
(result_dir / "pattern_reasoning_summary.md").write_text(
    "\n".join(
        [
            "# clk_put Locate-Code and Pattern-Reasoning Run",
            "",
            f"Raw usages located: `{raw_usages}`.",
            (
                "Valid defensive-code snippets: "
                f"`{snippet_count}` -> `artifact/results/minimal/defensive_code_snippets.json`."
            ),
            (
                "Reasoning inputs: "
                f"`{reasoning_inputs}` from requested sample size `{os.environ['AE_SAMPLE_SIZE']}` "
                "-> `artifact/results/minimal/input_for_defensive_pattern_reasoning.json`."
            ),
            (
                "Inferred defensive patterns: "
                f"`{inferred_patterns}` -> `artifact/results/minimal/inferred_defensive_patterns.json`."
            ),
            "",
            "Internal `raw`, `detail`, `spec`, and timestamped LLM files are transient cache files and are not kept by the minimal AE script.",
            "",
        ]
    ),
    encoding="utf-8",
)

print("[ae] minimal clk_put defensive pattern reasoning")
print(f"[ae] raw usages located: {raw_usages}")
print(
    "[ae] valid defensive-code snippets: "
    f"{snippet_count} -> artifact/results/minimal/defensive_code_snippets.json"
)
print(
    "[ae] reasoning inputs: "
    f"{reasoning_inputs} -> artifact/results/minimal/input_for_defensive_pattern_reasoning.json"
)
print(
    "[ae] inferred defensive patterns: "
    f"{inferred_patterns} -> artifact/results/minimal/inferred_defensive_patterns.json"
)
print("[ae] summary: artifact/results/minimal/pattern_reasoning_summary.json")
print("[ae] logs: artifact/results/minimal/logs/")

for p in [
    usage_file,
    contexts,
    base / "contexts" / "clk_put_expanded.json",
    base / "llm_inputs" / "clk_put.json",
    base / "raw" / "clk_put.json",
    base / "detail" / "clk_put.json",
    base / "spec" / "clk_put.json",
]:
    p.unlink(missing_ok=True)

for pattern in [
    "contexts/clk_put_ts*.json",
    "llm_reports/clk_put*.json",
    "llm_reports/clk_put*.parsed.json",
    "llm_reports/clk_put*.dialog.json",
]:
    for p in base.glob(pattern):
        p.unlink(missing_ok=True)

shutil.rmtree(internal, ignore_errors=True)
PY
else
  if [[ "${SAMPLE_SIZE}" != "10" ]]; then
    echo "[ae] reference sample contains 10 examples; showing the fixed sample"
  fi
  cp "${SCRIPT_DIR}/reference/pattern_reasoning_summary.md" "${RESULT_DIR}/pattern_reasoning_summary.md"
  cp "${SCRIPT_DIR}/reference/pattern_reasoning_summary.json" "${RESULT_DIR}/pattern_reasoning_summary.json"
  cp "${SCRIPT_DIR}/reference/expected_pattern_reasoning_output.txt" "${RESULT_DIR}/expected_pattern_reasoning_output.txt"
  cp "${SCRIPT_DIR}/reference/defensive_code_snippets.json" "${RESULT_DIR}/defensive_code_snippets.json"
  cp "${SCRIPT_DIR}/reference/input_for_defensive_pattern_reasoning.json" "${RESULT_DIR}/input_for_defensive_pattern_reasoning.json"
  cp "${SCRIPT_DIR}/reference/inferred_defensive_patterns.json" "${RESULT_DIR}/inferred_defensive_patterns.json"
  cp "${SCRIPT_DIR}/reference/defensive_code_snippets_sample.csv" "${RESULT_DIR}/defensive_code_snippets_sample.csv"
  cp "${SCRIPT_DIR}/reference/inferred_defensive_patterns_sample.csv" "${RESULT_DIR}/inferred_defensive_patterns_sample.csv"
  cp "${SCRIPT_DIR}/reference/defensive_pattern_templates.csv" "${RESULT_DIR}/defensive_pattern_templates.csv"
  cp "${SCRIPT_DIR}/reference/runtime_cpu.csv" "${RESULT_DIR}/runtime_cpu.csv"
  sed -n "1,80p" "${RESULT_DIR}/expected_pattern_reasoning_output.txt"
fi

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"
if [[ "${USE_REFERENCE}" == "1" ]]; then
  RUN_KIND="reference"
else
  RUN_KIND="run"
fi
ae_write_timing "${RESULT_DIR}/measured_runtime.csv" "minimal_pattern_reasoning" "${RUN_KIND}" "${ELAPSED}"
echo "[ae] pattern reasoning elapsed seconds: ${ELAPSED}"
