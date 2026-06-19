#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"
START_MS="$(ae_now_ms)"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "r_pattern_reasoning")"
USE_REFERENCE=0
if [[ "${1:-}" == "--reference" ]]; then
  USE_REFERENCE=1
  shift
fi

PER_SEED_SAMPLE_SIZE="${1:-200}"
MIN_SAMPLE_SIZE=50
WORKERS="${2:-8}"
MANIFEST="${SCRIPT_DIR}/reference/reasoning_sample_manifest.csv"
SEEDS=(kfree of_node_put clk_put null-ptr-check negative-check err-ptr-check)
LOG_DIR="${RESULT_DIR}/logs"
COVERAGE_SCRIPT="${SCRIPT_DIR}/check_table18_coverage.py"
TOP_OPS_DIR="${SCRIPT_DIR}/reference/table18_top30_security_sensitive_ops"
HEARTBEAT_SECONDS="${BUGAUDITOR_AE_HEARTBEAT_SECONDS:-30}"

rm -f \
  "${RESULT_DIR}/defensive_code_samples.csv" \
  "${RESULT_DIR}/inferred_patterns.csv" \
  "${RESULT_DIR}/inferred_pattern_files.csv" \
  "${RESULT_DIR}/pattern_reasoning_summary.csv" \
  "${RESULT_DIR}/pattern_reasoning_summary.md" \
  "${RESULT_DIR}/runtime_and_tokens.csv" \
  "${RESULT_DIR}/table18_top30_coverage.csv" \
  "${RESULT_DIR}/expected_output.txt" \
  "${RESULT_DIR}/run_outputs.md" \
  "${RESULT_DIR}/"*reduced* \
  "${RESULT_DIR}/"*extension*
rm -rf "${RESULT_DIR}/table18_top30_security_sensitive_ops"
if [[ "${USE_REFERENCE}" == "1" ]]; then
  rm -rf "${LOG_DIR}"
fi

if [[ "${PER_SEED_SAMPLE_SIZE}" -lt "${MIN_SAMPLE_SIZE}" ]]; then
  echo "[ae] per-seed sample size must be at least ${MIN_SAMPLE_SIZE}" >&2
  exit 1
fi

progress_bar() {
  local current="$1"
  local total="$2"
  local label="$3"
  local width=20
  local filled=$((current * width / total))
  local empty=$((width - filled))
  local bar
  bar="$(printf '%*s' "${filled}" '' | tr ' ' '#')$(printf '%*s' "${empty}" '' | tr ' ' '-')"
  echo "[ae] progress [${bar}] ${current}/${total}: ${label}"
}

run_logged() {
  local label="$1"
  local log_file="$2"
  shift 2

  echo "[ae] start: ${label}"
  echo "[ae] log: ${log_file}"
  "$@" >"${log_file}" 2>&1 &
  local pid="$!"
  local started_seconds="${SECONDS}"
  local next_heartbeat=$((started_seconds + HEARTBEAT_SECONDS))

  while kill -0 "${pid}" >/dev/null 2>&1; do
    sleep 1
    if [[ "${SECONDS}" -ge "${next_heartbeat}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      local elapsed
      local last_line
      elapsed="$((SECONDS - started_seconds))"
      last_line="$(tail -n 1 "${log_file}" 2>/dev/null | tr '\r' '\n' | tail -n 1 | cut -c1-180 || true)"
      if [[ -n "${last_line}" ]]; then
        echo "[ae] still running: ${label} (${elapsed}s). last log: ${last_line}"
      else
        echo "[ae] still running: ${label} (${elapsed}s)."
      fi
      next_heartbeat=$((SECONDS + HEARTBEAT_SECONDS))
    fi
  done

  if wait "${pid}"; then
    echo "[ae] done: ${label}"
    return 0
  fi

  echo "[ae] ${label} failed. Last log lines from ${log_file}:" >&2
  tail -80 "${log_file}" >&2
  return 1
}

publish_reference() {
  ae_copy_reference "${SCRIPT_DIR}/reference/defensive_code_samples.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/inferred_patterns.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/inferred_pattern_files.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/pattern_reasoning_summary.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/pattern_reasoning_summary.md" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/runtime_and_tokens.csv" "${RESULT_DIR}"
  ae_copy_reference "${SCRIPT_DIR}/reference/expected_output.txt" "${RESULT_DIR}"
  mkdir -p "${RESULT_DIR}/table18_top30_security_sensitive_ops"
  cp "${TOP_OPS_DIR}/"*.txt "${RESULT_DIR}/table18_top30_security_sensitive_ops/"
  echo "[ae] copied Table 18 top-operation txt files to ${RESULT_DIR}/table18_top30_security_sensitive_ops"
}

show_summary() {
  ae_show_file "${RESULT_DIR}/expected_output.txt" 80
}

run_coverage_check() {
  python3 "${COVERAGE_SCRIPT}" \
    --inferred-patterns "${RESULT_DIR}/inferred_patterns.csv" \
    --table18-dir "${RESULT_DIR}/table18_top30_security_sensitive_ops" \
    --output-csv "${RESULT_DIR}/table18_top30_coverage.csv"
}

print_seed_stats() {
  local seed="$1"
  local sample_file="$2"
  python3 - "${seed}" "${sample_file}" <<'PY'
import json
import sys
from pathlib import Path

import scripts.core.runtime_paths as rt

seed = sys.argv[1]
sample_file = Path(sys.argv[2])
cfg = rt.load_config()
data_root = Path(cfg["security_sensitive_data_path"])
usage_file = data_root / "weggli_usage" / f"{seed}.json"
contexts_file = data_root / "linux" / "contexts" / f"{seed}.json"

def count_usage(obj):
    if isinstance(obj, list):
        return sum(count_usage(item) for item in obj)
    if isinstance(obj, dict):
        if "matches" in obj and "path" in obj:
            return 1
        return sum(count_usage(item) for item in obj.values())
    return 0

def load_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

usage_count = count_usage(load_json(usage_file)) if usage_file.exists() else 0
contexts = load_json(contexts_file) or []
valid_count = len(contexts) if isinstance(contexts, list) else 0
sample_names = [line.strip().split(",", 1)[0] for line in sample_file.read_text(encoding="utf-8").splitlines() if line.strip()]
context_names = {ctx.get("func_name") for ctx in contexts if isinstance(ctx, dict)}
selected_count = sum(1 for name in sample_names if name in context_names)
print(f"[ae] {seed}: located usages={usage_count}, valid defensive code={valid_count}, selected for reasoning={selected_count}/{len(sample_names)}")
print(f"[ae] {seed}: defensive code file={contexts_file}")
PY
}

print_seed_outputs() {
  local seed="$1"
  python3 - "${seed}" <<'PY'
import csv
import json
import sys
from pathlib import Path

import scripts.core.runtime_paths as rt

seed = sys.argv[1]
cfg = rt.load_config()
base = Path(cfg["security_sensitive_data_path"]) / "linux" / "r_pattern_reasoning"
llm_inputs = base / "llm_inputs" / f"{seed}.json"
spec_file = base / "spec" / f"{seed}.json"
reports = sorted((base / "llm_reports").glob(f"{seed}_reproduced_reduced_*.parsed.json"), key=lambda p: p.stat().st_mtime)
latest = reports[-1] if reports else None

def json_len(path):
    if not path or not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    return len(data) if isinstance(data, list) else 0

print(f"[ae] {seed}: LLM reasoning inputs={json_len(llm_inputs)} -> {llm_inputs}")
print(f"[ae] {seed}: dominator/spec patterns={json_len(spec_file)} -> {spec_file}")
if latest:
    print(f"[ae] {seed}: inferred patterns={json_len(latest)} -> {latest}")
else:
    print(f"[ae] {seed}: inferred patterns file not found under {base / 'llm_reports'}")
PY
}

write_inferred_pattern_paths() {
  python3 - "${RESULT_DIR}/inferred_pattern_files.csv" <<'PY'
import csv
import json
import sys
from pathlib import Path

import scripts.core.runtime_paths as rt

out = Path(sys.argv[1])
cfg = rt.load_config()
base = Path(cfg["security_sensitive_data_path"]) / "linux" / "r_pattern_reasoning"
rows = []
for seed in ["kfree", "of_node_put", "clk_put", "null-ptr-check", "negative-check", "err-ptr-check"]:
    reports = sorted((base / "llm_reports").glob(f"{seed}_reproduced_reduced_*.parsed.json"), key=lambda p: p.stat().st_mtime)
    latest = reports[-1] if reports else None
    count = 0
    if latest:
        try:
            data = json.loads(latest.read_text(encoding="utf-8"))
            count = len(data) if isinstance(data, list) else 0
        except Exception:
            count = 0
    rows.append({
        "seed_defensive_op": seed,
        "inferred_patterns_file": str(latest) if latest else "",
        "inferred_patterns": count,
        "llm_inputs_file": str(base / "llm_inputs" / f"{seed}.json"),
        "spec_file": str(base / "spec" / f"{seed}.json"),
    })
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["seed_defensive_op", "inferred_patterns_file", "inferred_patterns", "llm_inputs_file", "spec_file"], lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
print(f"[ae] inferred pattern paths: {out}")
PY
}

echo "[ae] reproduced defensive pattern reasoning"
echo "[ae] seeds: ${SEEDS[*]}"
echo "[ae] per-seed sample target: ${PER_SEED_SAMPLE_SIZE} (minimum ${MIN_SAMPLE_SIZE}); workers=${WORKERS}"
echo "[ae] result directory: ${RESULT_DIR}"

if [[ "${USE_REFERENCE}" == "1" ]]; then
  publish_reference
  show_summary
  run_coverage_check
else
  ae_need_config "${REPO_ROOT}"
  ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
  ae_need_command "joern-parse" "Joern"
  ae_need_command "joern-export" "Joern"
  ae_need_tree_sitter "${REPO_ROOT}"
  ae_need_source_path "${REPO_ROOT}" "linux"
  ae_need_llm_config "${REPO_ROOT}"

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
  mkdir -p "${LOG_DIR}"
  python3 - "${PER_SEED_SAMPLE_SIZE}" "${MANIFEST}" "${TMP_DIR}" <<'PY'
import csv
import sys
from collections import defaultdict
from pathlib import Path

per_seed_sample_size = int(sys.argv[1])
manifest = Path(sys.argv[2])
tmp_dir = Path(sys.argv[3])
rows = list(csv.DictReader(manifest.open()))
by_seed = defaultdict(list)
for row in rows:
    by_seed[row["seed_defensive_op"]].append(row["func_name"])
for seed, funcs in sorted(by_seed.items()):
    funcs = funcs[:per_seed_sample_size]
    (tmp_dir / f"{seed}.txt").write_text("\n".join(funcs) + "\n")
PY

  cd "${REPO_ROOT}"
  seed_index=0
  for seed in "${SEEDS[@]}"; do
    seed_index=$((seed_index + 1))
    progress_bar "${seed_index}" "${#SEEDS[@]}" "${seed}"
    sample_file="${TMP_DIR}/${seed}.txt"
    if [[ ! -s "${sample_file}" ]]; then
      echo "[ae] skipping ${seed}: no functions selected"
      continue
    fi
    run_logged \
      "defensive code locating for ${seed}" \
      "${LOG_DIR}/${seed}_locating.log" \
      python scripts/core/defensive_code_locating.py "${seed}" linux --single --workers "${WORKERS}"
    print_seed_stats "${seed}" "${sample_file}"
    echo "[ae] ${seed}: reasoning progress is written to ${LOG_DIR}/${seed}_pattern_reasoning.log"
    run_logged \
      "defensive pattern reasoning for ${seed}" \
      "${LOG_DIR}/${seed}_pattern_reasoning.log" \
      python scripts/core/defensive_pattern_reasoning.py "${seed}" linux \
        --step both \
        --sample-functions-file "${sample_file}" \
        --workers "${WORKERS}" \
        --llm-suffix "_reproduced_reduced" \
        --output-subdir "r_pattern_reasoning"
    print_seed_outputs "${seed}"
  done

  publish_reference
  write_inferred_pattern_paths
  show_summary
  run_coverage_check
  echo "[ae] logs: artifact/results/r_pattern_reasoning/logs/"
fi

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"
if [[ "${USE_REFERENCE}" == "1" ]]; then
  RUN_KIND="reference"
else
  RUN_KIND="run"
fi
ae_write_timing "${RESULT_DIR}/measured_runtime.csv" "r_pattern_reasoning" "${RUN_KIND}" "${ELAPSED}"
echo "[ae] reproduced pattern reasoning elapsed seconds: ${ELAPSED}"
