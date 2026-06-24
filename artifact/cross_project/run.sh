#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"
START_MS="$(ae_now_ms)"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "cross_project")"

usage() {
  cat <<'EOF'
Usage:
  bash artifact/cross_project/run.sh <repo> <seed_defensive_operation> [--workers N]
  bash artifact/cross_project/run.sh --reference
  bash artifact/cross_project/run.sh <repo> <seed_defensive_operation> --reference

Examples:
  bash artifact/cross_project/run.sh openssl null-ptr-check
  bash artifact/cross_project/run.sh openssl OPENSSL_free
  bash artifact/cross_project/run.sh FFmpeg null-ptr-check
  bash artifact/cross_project/run.sh FFmpeg av_free
  bash artifact/cross_project/run.sh FFmpeg av_free --workers 8
  bash artifact/cross_project/run.sh --reference

Packaged reference repos: openssl, FFmpeg
Default mode is live and can use any repo key configured in config.json:program_paths.
EOF
}

canonical_repo() {
  local repo="$1"
  case "${repo,,}" in
    openssl)
      printf "openssl"
      ;;
    ffmpeg)
      printf "FFmpeg"
      ;;
    *)
      printf "%s" "${repo}"
      ;;
  esac
}

write_reference_selection() {
  local repo_filter="$1"
  local seed_filter="$2"
  python3 - \
    "${RESULT_DIR}/expected_output.txt" \
    "${repo_filter}" \
    "${seed_filter}" <<'PY'
import sys
from pathlib import Path

expected_txt = Path(sys.argv[1])
repo_filter = sys.argv[2]
seed_filter = sys.argv[3]

rows = [
    {
        "repo": "openssl",
        "seed_defensive_operation": "null-ptr-check",
        "display_operation": "NULL pointer check",
        "usage_located": "1559",
        "defensive_code_snippets": "764",
        "inferred_patterns": "258",
        "repo_sample_accuracy": "95%",
    },
    {
        "repo": "openssl",
        "seed_defensive_operation": "OPENSSL_free",
        "display_operation": "OPENSSL_free",
        "usage_located": "1363",
        "defensive_code_snippets": "924",
        "inferred_patterns": "124",
        "repo_sample_accuracy": "95%",
    },
    {
        "repo": "FFmpeg",
        "seed_defensive_operation": "null-ptr-check",
        "display_operation": "NULL pointer check",
        "usage_located": "3038",
        "defensive_code_snippets": "2330",
        "inferred_patterns": "276",
        "repo_sample_accuracy": "88%",
    },
    {
        "repo": "FFmpeg",
        "seed_defensive_operation": "av_free",
        "display_operation": "av_free",
        "usage_located": "744",
        "defensive_code_snippets": "553",
        "inferred_patterns": "95",
        "repo_sample_accuracy": "88%",
    },
]
if repo_filter:
    rows = [
        row
        for row in rows
        if row["repo"] == repo_filter and row["seed_defensive_operation"] == seed_filter
    ]

if not rows:
    raise SystemExit(
        f"[ae] no packaged cross-project reference for repo={repo_filter!r}, "
        f"seed={seed_filter!r}"
    )

lines = ["[ae] cross-project reference"]
if repo_filter:
    row = rows[0]
    lines.extend(
        [
            f"repo: {row['repo']}",
            f"seed defensive operation: {row['seed_defensive_operation']}",
            f"located usages: {row['usage_located']}",
            f"valid defensive-code snippets: {row['defensive_code_snippets']}",
            f"inferred defensive patterns: {row['inferred_patterns']}",
            f"repo sample accuracy: {row['repo_sample_accuracy']}",
        ]
    )
else:
    lines.append("packaged examples: 4")
    for row in rows:
        lines.append(
            f"- {row['repo']}/{row['seed_defensive_operation']}: "
            f"{row['usage_located']} usages, "
            f"{row['defensive_code_snippets']} snippets, "
            f"{row['inferred_patterns']} patterns"
        )
text = "\n".join(lines) + "\n"
expected_txt.write_text(text, encoding="utf-8")
print(text, end="")
PY
}

write_reference_paths() {
  local paths_file="${RESULT_DIR}/reference_output_paths.md"
  local pattern_dir="${RESULT_DIR}/reference_patterns"

  cat >"${paths_file}" <<EOF
# Cross-Project Reference Output Paths

- Result directory: \`${RESULT_DIR}\`
- Reference summary: \`${RESULT_DIR}/expected_output.txt\`
- Reference pattern JSON directory: \`${pattern_dir}\`

EOF

  if compgen -G "${pattern_dir}/*.json" >/dev/null; then
    {
      echo "Pattern JSON files:"
      for pattern_file in "${pattern_dir}"/*.json; do
        echo "- \`${pattern_file}\`"
      done
      echo
    } >>"${paths_file}"
  fi

  echo "[ae] result directory: ${RESULT_DIR}"
  echo "[ae] reference summary: ${RESULT_DIR}/expected_output.txt"
  echo "[ae] reference pattern JSON directory: ${pattern_dir}"
  if compgen -G "${pattern_dir}/*.json" >/dev/null; then
    for pattern_file in "${pattern_dir}"/*.json; do
      echo "[ae] reference pattern JSON: ${pattern_file}"
    done
  fi
  echo "[ae] reference output paths: ${paths_file}"
}

write_reference_patterns() {
  local repo_filter="$1"
  local seed_filter="$2"
  local src_dir="${SCRIPT_DIR}/reference/patterns"
  local dst_dir="${RESULT_DIR}/reference_patterns"
  local copied=0

  mkdir -p "${dst_dir}"
  rm -f "${dst_dir}"/*.json

  if [[ -n "${repo_filter}" ]]; then
    local src_file="${src_dir}/${repo_filter}_${seed_filter}_patterns.json"
    if [[ ! -f "${src_file}" ]]; then
      echo "[ae] missing reference pattern JSON: ${src_file}" >&2
      return 1
    fi
    cp "${src_file}" "${dst_dir}/"
    echo "[ae] wrote reference pattern JSON: ${dst_dir}/$(basename "${src_file}")"
    return 0
  fi

  for src_file in "${src_dir}"/*_patterns.json; do
    if [[ ! -f "${src_file}" ]]; then
      continue
    fi
    cp "${src_file}" "${dst_dir}/"
    echo "[ae] wrote reference pattern JSON: ${dst_dir}/$(basename "${src_file}")"
    copied=$((copied + 1))
  done

  if [[ "${copied}" -eq 0 ]]; then
    echo "[ae] missing reference pattern JSON files under ${src_dir}" >&2
    return 1
  fi
}

run_logged() {
  local label="$1"
  local log_file="$2"
  shift 2

  if "$@" >"${log_file}" 2>&1; then
    return 0
  fi

  echo "[ae] ${label} failed. Last log lines from ${log_file}:" >&2
  tail -20 "${log_file}" >&2
  return 1
}

run_with_progress() {
  local label="$1"
  local log_file="$2"
  shift 2

  local step_start
  local last_report
  local elapsed
  local pid
  local status
  local spinner_index=0
  local spinners=("-" "\\" "|" "/")
  local bars=(
    "[###.................]"
    "[######..............]"
    "[#########...........]"
    "[############........]"
    "[###############.....]"
    "[##################..]"
  )

  step_start="$(ae_now_ms)"
  last_report="${step_start}"
  : >"${log_file}"
  echo "[ae] start ${label}"
  echo "[ae] log file: ${log_file}"

  "$@" >"${log_file}" 2>&1 &
  pid="$!"

  while kill -0 "${pid}" >/dev/null 2>&1; do
    sleep 2
    local now
    now="$(ae_now_ms)"
    if (( now - last_report >= 30000 )); then
      elapsed="$(ae_elapsed_seconds "${step_start}")"
      printf '[ae] %s %s %s still running; elapsed %ss\n' \
        "${bars[spinner_index % ${#bars[@]}]}" "${spinners[spinner_index]}" "${label}" "${elapsed}"
      spinner_index=$(((spinner_index + 1) % ${#spinners[@]}))
      last_report="${now}"
    fi
  done

  set +e
  wait "${pid}"
  status="$?"
  set -e

  if [[ "${status}" -eq 0 ]]; then
    elapsed="$(ae_elapsed_seconds "${step_start}")"
    echo "[ae] completed ${label}; elapsed ${elapsed}s"
    return 0
  fi

  echo "[ae] ${label} failed. Last log lines from ${log_file}:" >&2
  tail -20 "${log_file}" >&2
  return "${status}"
}

write_live_summary() {
  local repo="$1"
  local seed="$2"
  local workers="$3"
  local elapsed="$4"
  python3 - \
    "${REPO_ROOT}" \
    "${RESULT_DIR}/live_summary.csv" \
    "${RESULT_DIR}/live_output_paths.md" \
    "${repo}" \
    "${seed}" \
    "${workers}" \
    "${elapsed}" <<'PY'
import csv
import json
import os
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
summary_csv = Path(sys.argv[2])
paths_md = Path(sys.argv[3])
repo = sys.argv[4]
seed = sys.argv[5]
workers = sys.argv[6]
elapsed = sys.argv[7]

config_path = Path(os.environ.get("BUGAUDITOR_CONFIG", repo_root / "config.json"))
config = json.loads(config_path.read_text(encoding="utf-8"))
data_root = Path(config["security_sensitive_data_path"])
base = data_root / repo
live = base / "cross_project_live"

usage_file = data_root / "weggli_usage" / f"{seed}.json"
contexts_file = base / "contexts" / f"{seed}.json"
inputs_file = live / "llm_inputs" / f"{seed}.json"
parsed_files = sorted(
    (live / "llm_reports").glob(f"{seed}*.parsed.json"),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)
parsed_file = parsed_files[0] if parsed_files else None

def json_len(path: Path | None) -> int:
    if not path or not path.exists():
        return 0
    data = json.loads(path.read_text(encoding="utf-8"))
    return len(data) if isinstance(data, list) else 0

rows = [
    ("repo", repo),
    ("seed_defensive_operation", seed),
    ("workers", workers),
    ("elapsed_seconds", elapsed),
    ("located_usages", json_len(usage_file)),
    ("defensive_code_snippets", json_len(contexts_file)),
    ("reasoning_inputs", json_len(inputs_file)),
    ("inferred_patterns", json_len(parsed_file)),
    ("usage_file", str(usage_file)),
    ("contexts_file", str(contexts_file)),
    ("llm_inputs_file", str(inputs_file)),
    ("parsed_patterns_file", str(parsed_file) if parsed_file else ""),
]
with summary_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["metric", "value"])
    writer.writerows(rows)

paths_md.write_text(
    "\n".join(
        [
            "# Cross-Project Live Output Paths",
            "",
            f"- Repo: `{repo}`",
            f"- Seed defensive operation: `{seed}`",
            f"- Located usages: `{usage_file}`",
            f"- Defensive-code snippets: `{contexts_file}`",
            f"- Reasoning inputs: `{inputs_file}`",
            f"- Inferred patterns: `{parsed_file or ''}`",
            f"- Live summary: `{summary_csv}`",
            "",
        ]
    ),
    encoding="utf-8",
)
print("[ae] live key results")
print(f"[ae] repo: {repo}")
print(f"[ae] seed defensive operation: {seed}")
print(f"[ae] located usages: {json_len(usage_file)}")
print(f"[ae] valid defensive-code contexts: {json_len(contexts_file)}")
print(f"[ae] reasoning inputs: {json_len(inputs_file)}")
print(f"[ae] inferred patterns: {json_len(parsed_file)}")
print(f"[ae] usage file: {usage_file}")
print(f"[ae] contexts file: {contexts_file}")
print(f"[ae] pattern JSON: {parsed_file or ''}")
print(f"[ae] live summary: {summary_csv}")
print(f"[ae] live output paths: {paths_md}")
PY
}

SHOW_ALL=0
MODE="live"
WORKERS=8
REPO_FILTER=""
SEED_FILTER=""

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--reference" && $# -eq 1 ]]; then
  SHOW_ALL=1
  MODE="reference"
  shift
else
  if [[ $# -lt 2 ]]; then
    usage >&2
    exit 2
  fi
  REPO_FILTER="$(canonical_repo "$1")"
  SEED_FILTER="$2"
  shift 2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reference)
      MODE="reference"
      shift
      ;;
    --workers)
      WORKERS="${2:-}"
      if [[ -z "${WORKERS}" ]]; then
        echo "[ae] --workers requires a value" >&2
        exit 2
      fi
      shift 2
      ;;
    *)
      echo "[ae] unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

rm -f \
  "${RESULT_DIR}/expected_output.txt" \
  "${RESULT_DIR}/live_summary.csv" \
  "${RESULT_DIR}/live_output_paths.md" \
  "${RESULT_DIR}/reference_output_paths.md" \
  "${RESULT_DIR}/measured_runtime.csv" \
  "${RESULT_DIR}/cross_project_timing.csv"
mkdir -p "${RESULT_DIR}/logs"

if [[ "${MODE}" == "reference" ]]; then
  REFERENCE_START_MS="$(ae_now_ms)"
  if [[ "${SHOW_ALL}" == "1" ]]; then
    write_reference_selection "" ""
  else
    write_reference_selection "${REPO_FILTER}" "${SEED_FILTER}"
  fi
  if [[ "${SHOW_ALL}" == "1" ]]; then
    write_reference_patterns "" ""
  else
    write_reference_patterns "${REPO_FILTER}" "${SEED_FILTER}"
  fi
  REFERENCE_ELAPSED="$(ae_elapsed_seconds "${REFERENCE_START_MS}")"
  echo "[ae] completed reference selection; elapsed ${REFERENCE_ELAPSED}s"
else
  if [[ "${SHOW_ALL}" == "1" ]]; then
    echo "[ae] live mode requires <repo> <seed_defensive_operation>" >&2
    exit 2
  fi

  echo "[ae] cross-project live run"
  echo "[ae] repo: ${REPO_FILTER}"
  echo "[ae] seed defensive operation: ${SEED_FILTER}"
  echo "[ae] workers: ${WORKERS}"

  PREFLIGHT_START_MS="$(ae_now_ms)"
  echo "[ae] step 1/3: checking config and source path"
  ae_need_config "${REPO_ROOT}"
  ae_need_source_path "${REPO_ROOT}" "${REPO_FILTER}"
  echo "[ae] step 1/3: checking analysis tools"
  ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
  ae_need_command "joern-parse" "Joern"
  ae_need_command "joern-export" "Joern"
  ae_need_tree_sitter "${REPO_ROOT}"
  echo "[ae] step 1/3: checking LLM configuration"
  ae_need_llm_config "${REPO_ROOT}"
  PREFLIGHT_ELAPSED="$(ae_elapsed_seconds "${PREFLIGHT_START_MS}")"
  echo "[ae] completed preflight; elapsed ${PREFLIGHT_ELAPSED}s"

  cd "${REPO_ROOT}"
  echo "[ae] step 2/3: running defensive-code locating and pattern reasoning"
  run_with_progress \
    "cross_project_reasoning" \
    "${RESULT_DIR}/logs/${REPO_FILTER}_${SEED_FILTER}.log" \
    env PYTHONUNBUFFERED=1 python scripts/core/defensive_pattern_reasoning.py "${SEED_FILTER}" "${REPO_FILTER}" \
      --single \
      --step both \
      --workers "${WORKERS}" \
      --force-recompute \
      --llm-suffix "_cross_project_live" \
      --output-subdir cross_project_live
fi

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"

if [[ "${MODE}" == "live" ]]; then
  echo "[ae] step 3/3: collecting live output summary"
  write_live_summary "${REPO_FILTER}" "${SEED_FILTER}" "${WORKERS}" "${ELAPSED}"
else
  write_reference_paths
fi

echo "[ae] cross-project elapsed seconds: ${ELAPSED}"
