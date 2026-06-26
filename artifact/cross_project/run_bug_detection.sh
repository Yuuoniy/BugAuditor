#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/ae_common.sh"
START_MS="$(ae_now_ms)"

REPO_ROOT="$(ae_repo_root)"
RESULT_DIR="$(ae_prepare_result_dir "${REPO_ROOT}" "cross_project")"
BUG_DIR="${RESULT_DIR}/bug_detection"
LOG_DIR="${BUG_DIR}/logs"

usage() {
  cat <<'EOF'
Usage:
  bash artifact/cross_project/run_bug_detection.sh [repo] [seed_defensive_operation] [options]

Options:
  --pattern-limit N       use the first N inferred patterns from the pattern JSON (default: 30)
  --candidate-limit N     audit up to N comparable functions per pattern (default: 10)
  --workers N             LLM audit workers (default: 8)
  --pattern-file PATH     use an explicit inferred-pattern JSON file

Example:
  bash artifact/cross_project/run_bug_detection.sh openssl OPENSSL_free --pattern-limit 30 --candidate-limit 10 --workers 8
  bash artifact/cross_project/run_bug_detection.sh openssl OPENSSL_free --pattern-file artifact/cross_project/reference/patterns/openssl_OPENSSL_free_patterns.json
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

MODE="live"
REPO_FILTER="openssl"
SEED_FILTER="OPENSSL_free"
PATTERN_LIMIT=30
CANDIDATE_LIMIT=10
WORKERS=8
PATTERN_FILE=""

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--reference" ]]; then
  MODE="reference"
  shift
elif [[ $# -gt 0 && "${1:-}" != --* ]]; then
  REPO_FILTER="$(canonical_repo "$1")"
  shift
  if [[ $# -gt 0 && "${1:-}" != --* ]]; then
    SEED_FILTER="$1"
    shift
  fi
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reference)
      MODE="reference"
      shift
      ;;
    --pattern-limit)
      PATTERN_LIMIT="${2:-}"
      shift 2
      ;;
    --candidate-limit)
      CANDIDATE_LIMIT="${2:-}"
      shift 2
      ;;
    --workers)
      WORKERS="${2:-}"
      shift 2
      ;;
    --pattern-file)
      PATTERN_FILE="${2:-}"
      shift 2
      ;;
    *)
      echo "[ae] unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "${BUG_DIR}" "${LOG_DIR}"
rm -f \
  "${BUG_DIR}/selected_patterns.json" \
  "${BUG_DIR}/full_audit_results.json" \
  "${BUG_DIR}/bug_reports.json" \
  "${BUG_DIR}/bug_detection_results.csv" \
  "${BUG_DIR}/bug_detection_summary.md" \
  "${BUG_DIR}/bug_detection_output_paths.md" \
  "${BUG_DIR}/bug_detection_actual_results.json"

if [[ "${MODE}" == "reference" ]]; then
  REF_DIR="${SCRIPT_DIR}/reference/bug_detection"
  if [[ ! -d "${REF_DIR}" ]]; then
    echo "[ae] missing packaged bug-detection reference directory: ${REF_DIR}" >&2
    exit 1
  fi
  cp "${REF_DIR}/bug_detection_actual_results.json" "${BUG_DIR}/"
  echo "[ae] cross-project bug detection reference"
  echo "[ae] actual-run results: ${BUG_DIR}/bug_detection_actual_results.json"
  ae_show_file "${BUG_DIR}/bug_detection_actual_results.json" 120
  exit 0
fi

if ! [[ "${PATTERN_LIMIT}" =~ ^[0-9]+$ ]] || [[ "${PATTERN_LIMIT}" -lt 1 ]]; then
  echo "[ae] --pattern-limit must be a positive integer" >&2
  exit 2
fi
if ! [[ "${CANDIDATE_LIMIT}" =~ ^[0-9]+$ ]] || [[ "${CANDIDATE_LIMIT}" -lt 1 ]]; then
  echo "[ae] --candidate-limit must be a positive integer" >&2
  exit 2
fi
if ! [[ "${WORKERS}" =~ ^[0-9]+$ ]] || [[ "${WORKERS}" -lt 1 ]]; then
  echo "[ae] --workers must be a positive integer" >&2
  exit 2
fi

echo "[ae] cross-project bug detection live run"
echo "[ae] repo: ${REPO_FILTER}"
echo "[ae] seed defensive operation: ${SEED_FILTER}"
echo "[ae] pattern limit: ${PATTERN_LIMIT}"
echo "[ae] candidate limit per pattern: ${CANDIDATE_LIMIT}"
echo "[ae] workers: ${WORKERS}"

ae_need_config "${REPO_ROOT}"
ae_need_source_path "${REPO_ROOT}" "${REPO_FILTER}"
ae_need_tool_path "${REPO_ROOT}" "weggli_path" "Weggli"
ae_need_llm_config "${REPO_ROOT}"

cd "${REPO_ROOT}"

python3 - \
  "${REPO_FILTER}" \
  "${SEED_FILTER}" \
  "${PATTERN_LIMIT}" \
  "${PATTERN_FILE}" \
  "${BUG_DIR}/selected_patterns.json" <<'PY'
import glob
import json
import os
import sys
from pathlib import Path

repo = sys.argv[1]
seed = sys.argv[2]
limit = int(sys.argv[3])
explicit = sys.argv[4]
selected_path = Path(sys.argv[5])

cfg = json.loads(Path("config.json").read_text(encoding="utf-8"))
data_root = Path(cfg["security_sensitive_data_path"])

if explicit:
    source = Path(explicit)
else:
    live_glob = data_root / repo / "cross_project_live" / "llm_reports" / f"{seed}*.parsed.json"
    live_candidates = sorted(
        (Path(p) for p in glob.glob(str(live_glob))),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if live_candidates:
        source = live_candidates[0]
    else:
        source = Path("artifact/cross_project/reference/patterns") / f"{repo}_{seed}_patterns.json"

if not source.exists():
    raise SystemExit(f"[ae] inferred pattern JSON not found: {source}")

patterns = json.loads(source.read_text(encoding="utf-8"))
selected = patterns[:limit]
if not selected:
    raise SystemExit(f"[ae] no patterns in {source}")

selected_path.parent.mkdir(parents=True, exist_ok=True)
selected_path.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")

print(f"[ae] pattern source: {source}")
print(f"[ae] selected patterns: {len(selected)}/{len(patterns)} -> {selected_path}")
PY

python3 - \
  "${REPO_FILTER}" \
  "${SEED_FILTER}" <<'PY'
import json
from pathlib import Path
import sys

repo = sys.argv[1]
seed = sys.argv[2]
cfg = json.loads(Path("config.json").read_text(encoding="utf-8"))
bug_dir = Path(cfg["security_sensitive_data_path"]) / repo / "bug_reports"
if bug_dir.exists():
    for path in bug_dir.glob(f"{seed}_all*_bugs.json"):
        path.unlink()
PY

run_with_progress \
  "cross_project_bug_detection" \
  "${LOG_DIR}/bug_detection.log" \
  env PYTHONUNBUFFERED=1 python scripts/core/bug_auditing.py \
    --defensive-op "${SEED_FILTER}" \
    --repo "${REPO_FILTER}" \
    --pattern-llm-file "${BUG_DIR}/selected_patterns.json" \
    --all-patterns \
    --limit-per-pattern "${CANDIDATE_LIMIT}" \
    --workers "${WORKERS}" \
    --output "${BUG_DIR}/full_audit_results.json" \
    --no-weggli-from-summary

python3 - \
  "${REPO_FILTER}" \
  "${SEED_FILTER}" \
  "${PATTERN_LIMIT}" \
  "${CANDIDATE_LIMIT}" \
  "${WORKERS}" \
  "${BUG_DIR}" \
  "${START_MS}" <<'PY'
import csv
import glob
import json
import subprocess
import sys
from pathlib import Path

repo = sys.argv[1]
seed = sys.argv[2]
pattern_limit = int(sys.argv[3])
candidate_limit = int(sys.argv[4])
workers = int(sys.argv[5])
bug_dir = Path(sys.argv[6])
start_ms = int(sys.argv[7])

cfg = json.loads(Path("config.json").read_text(encoding="utf-8"))
data_root = Path(cfg["security_sensitive_data_path"])
source_root = Path(cfg["program_paths"][repo])

def run_git(args):
    proc = subprocess.run(["git", "-C", str(source_root), *args], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else ""

commit = run_git(["rev-parse", "HEAD"])
describe = run_git(["describe", "--always", "--tags", "--dirty"])
commit_date = run_git(["log", "-1", "--format=%ci"])

selected_path = bug_dir / "selected_patterns.json"
audit_path = bug_dir / "full_audit_results.json"
reports_path = bug_dir / "bug_reports.json"
results_csv = bug_dir / "bug_detection_results.csv"
summary_md = bug_dir / "bug_detection_summary.md"
paths_md = bug_dir / "bug_detection_output_paths.md"

audit = json.loads(audit_path.read_text(encoding="utf-8"))
selected = json.loads(selected_path.read_text(encoding="utf-8"))

def public_source_path(value):
    if not value:
        return ""
    path = Path(str(value))
    try:
        return str(path.relative_to(source_root))
    except ValueError:
        text = str(value)
        marker = f"/{repo}/"
        if marker in text:
            return text.split(marker, 1)[1]
        return text

def normalize_paths(obj):
    if isinstance(obj, list):
        return [normalize_paths(item) for item in obj]
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in {"path", "source_path", "buggy_function_path"} and isinstance(value, str):
                out[key] = public_source_path(value)
            else:
                out[key] = normalize_paths(value)
        return out
    return obj

audit = normalize_paths(audit)
audit_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
summary_rows = audit.get("summary", [])

bug_candidates = sorted(
    (Path(p) for p in glob.glob(str(data_root / repo / "bug_reports" / f"{seed}_all*_bugs.json"))),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)
if bug_candidates:
    reports = json.loads(bug_candidates[0].read_text(encoding="utf-8"))
else:
    reports = {"defensive_op": seed, "total_bugs": 0, "items": []}
reports = normalize_paths(reports)
reports_path.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")

with results_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "pattern_index",
            "pattern_source_func",
            "candidates",
            "consistent",
            "reported_bugs",
            "uncertain",
            "needs_more_context",
            "total_tokens",
        ],
    )
    writer.writeheader()
    for row in summary_rows:
        writer.writerow({
            "pattern_index": row.get("pattern_index", ""),
            "pattern_source_func": row.get("pattern_source_func", ""),
            "candidates": row.get("candidates", 0),
            "consistent": row.get("consistent_true", 0),
            "reported_bugs": row.get("consistent_false", 0),
            "uncertain": row.get("consistent_none", 0),
            "needs_more_context": row.get("needs_more_context", 0),
            "total_tokens": row.get("total_tokens", 0),
        })

total_candidates = sum(int(row.get("candidates") or 0) for row in summary_rows)
total_reported = sum(int(row.get("consistent_false") or 0) for row in summary_rows)
total_consistent = sum(int(row.get("consistent_true") or 0) for row in summary_rows)
total_uncertain = sum(int(row.get("consistent_none") or 0) for row in summary_rows)
total_tokens = sum(int(row.get("total_tokens") or 0) for row in summary_rows)

paths_md.write_text(
    "\n".join([
        "# Cross-Project Bug Detection Output Paths",
        "",
        "- Selected patterns: `artifact/results/cross_project/bug_detection/selected_patterns.json`",
        "- Compact per-pattern results: `artifact/results/cross_project/bug_detection/bug_detection_results.csv`",
        "- Bug reports: `artifact/results/cross_project/bug_detection/bug_reports.json`",
        "- Summary: `artifact/results/cross_project/bug_detection/bug_detection_summary.md`",
        "- Log: `artifact/results/cross_project/bug_detection/logs/bug_detection.log`",
        "",
    ]),
    encoding="utf-8",
)

summary_md.write_text(
    "\n".join([
        "# Cross-Project Bug Detection",
        "",
        f"Repository: `{repo}`.",
        f"Source revision: `{describe}` (`{commit}`).",
        f"Source commit date: `{commit_date}`.",
        f"Seed defensive operation: `{seed}`.",
        "",
        "Settings:",
        "",
        f"- First generated patterns used: `{len(selected)}` (requested `{pattern_limit}`).",
        f"- Candidate limit per pattern: `{candidate_limit}`.",
        f"- Workers: `{workers}`.",
        f"- Query translation: LLM-generated Weggli queries from each selected pattern.",
        "",
        "Observed results:",
        "",
        f"- Audited comparable functions: `{total_candidates}`.",
        f"- Reported bug candidates: `{total_reported}`.",
        f"- Consistent candidates: `{total_consistent}`.",
        f"- Uncertain candidates: `{total_uncertain}`.",
        f"- Bug report items written: `{len(reports.get('items', []))}`.",
        f"- Total LLM tokens recorded by audit outputs: `{total_tokens}`.",
        "",
        "Key output files:",
        "",
        "- `selected_patterns.json`: first generated defensive patterns used as bug-detection rules.",
        "- `bug_detection_results.csv`: compact per-pattern audit counts.",
        "- `bug_reports.json`: reported bug candidates with explanations.",
        "- `bug_detection_output_paths.md`: paths to the generated files.",
        "",
    ]),
    encoding="utf-8",
)

print("[ae] cross-project bug detection results")
print(f"[ae] source revision: {describe} ({commit})")
print(f"[ae] selected patterns: {len(selected)} -> {selected_path}")
print(f"[ae] audited comparable functions: {total_candidates}")
print(f"[ae] reported bug candidates: {total_reported}")
print(f"[ae] bug reports: {reports_path}")
print(f"[ae] compact results: {results_csv}")
print(f"[ae] summary: {summary_md}")
print(f"[ae] output paths: {paths_md}")
PY

ELAPSED="$(ae_elapsed_seconds "${START_MS}")"
echo "[ae] cross-project bug detection elapsed seconds: ${ELAPSED}"
