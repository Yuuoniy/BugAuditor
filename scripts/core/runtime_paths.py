"""Shared runtime path helpers for BugAuditor command-line scripts."""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent
INTERNAL_DIR = CORE_DIR / "internal"
WRAPPERS_DIR = CORE_DIR / "wrappers"
SCRIPTS_DIR = CORE_DIR.parent
REPO_ROOT = SCRIPTS_DIR.parent
SRC_UTILS_DIR = REPO_ROOT / "src" / "utils"
PROMPT_DIR = REPO_ROOT / "prompts"


def ensure_runtime_paths() -> None:
    paths = (CORE_DIR, INTERNAL_DIR, WRAPPERS_DIR, REPO_ROOT, SRC_UTILS_DIR)
    for path in paths:
        text = str(path)
        while text in sys.path:
            sys.path.remove(text)
    for path in reversed(paths):
        sys.path.insert(0, str(path))


def config_path() -> str:
    override = os.environ.get("BUGAUDITOR_CONFIG")
    if override:
        return override
    return str(REPO_ROOT / "config.json")


def load_config() -> dict:
    with open(config_path(), "r") as f:
        config = json.load(f)

    if "security_sensitive_data_path" not in config and "vuln_data_path" in config:
        config["security_sensitive_data_path"] = config["vuln_data_path"]
    if "vuln_data_path" not in config and "security_sensitive_data_path" in config:
        config["vuln_data_path"] = config["security_sensitive_data_path"]
    if "defensive_op_data_path" not in config and "secop_data_path" in config:
        config["defensive_op_data_path"] = config["secop_data_path"]
    if "secop_data_path" not in config and "defensive_op_data_path" in config:
        config["secop_data_path"] = config["defensive_op_data_path"]

    return config


def repo_path(*parts: str) -> Path:
    return REPO_ROOT.joinpath(*parts)


ensure_runtime_paths()
