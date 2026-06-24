#!/usr/bin/env bash

set -euo pipefail

ae_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
  cd "${script_dir}/../.." && pwd
}

ae_prepare_result_dir() {
  local repo_root="$1"
  local name="$2"
  local result_dir="${repo_root}/artifact/results/${name}"
  mkdir -p "${result_dir}"
  printf '%s\n' "${result_dir}"
}

ae_copy_reference() {
  local src="$1"
  local dst_dir="$2"
  cp "${src}" "${dst_dir}/"
  echo "[ae] copied reference $(basename "${src}")"
}

ae_show_file() {
  local file="$1"
  local lines="${2:-80}"
  echo "[ae] showing ${file}"
  sed -n "1,${lines}p" "${file}"
}

ae_now_ms() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

ae_elapsed_seconds() {
  local start_ms="$1"
  local end_ms
  local elapsed_ms
  end_ms="$(ae_now_ms)"
  elapsed_ms="$((end_ms - start_ms))"
  printf '%s.%03d\n' "$((elapsed_ms / 1000))" "$((elapsed_ms % 1000))"
}

ae_write_timing() {
  local file="$1"
  local workflow="$2"
  local mode="$3"
  local elapsed="$4"
  if [[ ! -f "${file}" ]]; then
    echo "workflow,mode,seconds,source" > "${file}"
  fi
  echo "${workflow},${mode},${elapsed},measured by artifact script" >> "${file}"
}

ae_need_config() {
  local repo_root="$1"
  if [[ ! -f "${repo_root}/config.json" ]]; then
    echo "[ae] missing config.json; restore the repository default config.json" >&2
    return 1
  fi
}

ae_config_value() {
  local repo_root="$1"
  local dotted_key="$2"
  local config_path="${BUGAUDITOR_CONFIG:-${repo_root}/config.json}"
  python3 -c '
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

cur = data
for part in sys.argv[2].split("."):
    if not isinstance(cur, dict) or part not in cur:
        sys.exit(2)
    cur = cur[part]

if cur is None:
    print("")
else:
    print(cur)
' "${config_path}" "${dotted_key}"
}

ae_need_source_path() {
  local repo_root="$1"
  local repo_key="$2"
  local path_value

  if ! path_value="$(ae_config_value "${repo_root}" "program_paths.${repo_key}")"; then
    echo "[ae] missing config.json:program_paths.${repo_key}" >&2
    return 1
  fi
  if [[ ! -d "${path_value}" ]]; then
    echo "[ae] missing ${repo_key} source at ${path_value}" >&2
    echo "[ae] Prepare the source directory via editing config.json:program_paths.${repo_key}." >&2
    return 1
  fi
}

ae_need_tool_path() {
  local repo_root="$1"
  local config_key="$2"
  local label="$3"
  local path_value

  if ! path_value="$(ae_config_value "${repo_root}" "${config_key}")"; then
    echo "[ae] missing config.json:${config_key}" >&2
    return 1
  fi
  if [[ ! -x "${path_value}" ]]; then
    echo "[ae] missing ${label} at ${path_value} (config.json:${config_key})" >&2
    echo "[ae] Use the Docker image from INSTALL.md, or edit config.json:${config_key}." >&2
    return 1
  fi
}

ae_need_command() {
  local command_name="$1"
  local label="$2"

  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "[ae] missing ${label} command: ${command_name}" >&2
    echo "[ae] Use the Docker image from INSTALL.md, or put ${label} on PATH." >&2
    return 1
  fi
}

ae_use_default_tree_sitter() {
  local repo_root="$1"

  export TREE_SITTER_C_DIR="${TREE_SITTER_C_DIR:-${repo_root}/scripts/tree-sitter-c}"
  export TREE_SITTER_BUILD_DIR="${TREE_SITTER_BUILD_DIR:-${repo_root}/scripts/build}"
}

ae_need_tree_sitter() {
  local repo_root="$1"
  local parser_c

  ae_use_default_tree_sitter "${repo_root}"
  parser_c="${TREE_SITTER_C_DIR}/src/parser.c"
  if [[ ! -f "${parser_c}" ]]; then
    echo "[ae] missing tree-sitter-c at ${TREE_SITTER_C_DIR}" >&2
    echo "[ae] Use the Docker image from INSTALL.md, or provide scripts/tree-sitter-c." >&2
    return 1
  fi
  mkdir -p "${TREE_SITTER_BUILD_DIR}"
}

ae_need_llm_config() {
  local repo_root="$1"
  local api_base
  local api_key
  local model

  if ! api_base="$(ae_config_value "${repo_root}" "openai_api_base")"; then
    echo "[ae] missing config.json:openai_api_base" >&2
    return 1
  fi
  if ! api_key="$(ae_config_value "${repo_root}" "openai_api_key")"; then
    echo "[ae] missing config.json:openai_api_key" >&2
    return 1
  fi
  if ! model="$(ae_config_value "${repo_root}" "openai_model")"; then
    echo "[ae] missing config.json:openai_model" >&2
    return 1
  fi

  if [[ -z "${api_base}" ]]; then
    api_base="${OPENAI_API_BASE:-https://api.openai.com}"
  fi
  if [[ -z "${api_key}" || "${api_key}" == "YOUR_KEY" ]]; then
    api_key="${OPENAI_API_KEY:-}"
  fi
  if [[ -z "${model}" ]]; then
    model="${OPENAI_MODEL:-}"
  fi

  if [[ -z "${api_base}" || -z "${api_key}" || -z "${model}" ]]; then
    echo "[ae] config.json needs a valid LLM endpoint: openai_api_base, openai_api_key, and openai_model" >&2
    return 1
  fi
}
