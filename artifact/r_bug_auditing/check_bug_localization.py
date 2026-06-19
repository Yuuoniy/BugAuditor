#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_DIR = REPO_ROOT / "scripts" / "core"
INTERNAL_DIR = CORE_DIR / "internal"
SCRIPT_DIR = Path(__file__).resolve().parent
for path in (REPO_ROOT, SCRIPT_DIR, CORE_DIR, INTERNAL_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from bug_auditing import load_config  # noqa: E402
from audit_cases import find_function_source  # noqa: E402


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_tsv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def linux_commit(source_dir: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return "unknown"
    if proc.returncode == 0:
        return proc.stdout.strip()
    return "unknown"


def display_path(source_dir: Path, path: str) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).relative_to(source_dir))
    except ValueError:
        return path


def query_for_call(call_name: str) -> str:
    return f"_ $func(_){{{call_name}(_);}}"


def _extract_definition_name(signature: str) -> str:
    signature = re.sub(r"/\*.*?\*/", " ", signature, flags=re.S)
    signature = re.sub(r"//.*", " ", signature)
    before_brace = signature.split("{", 1)[0]
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*$", before_brace, re.S)
    if not match:
        return ""
    name = match.group(1)
    if name in {"if", "for", "while", "switch", "return", "sizeof"}:
        return ""
    return name


def _functions_containing_call(path: Path, call_name: str) -> list[dict[str, str]]:
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return []

    call_re = re.compile(r"\b" + re.escape(call_name) + r"\s*\(")
    rows: dict[str, dict[str, str]] = {}
    pending: list[str] = []
    current_func = ""
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        if brace_depth == 0:
            if stripped and not stripped.startswith("#"):
                pending.append(line)
                pending = pending[-8:]
            if "{" in line:
                current_func = _extract_definition_name("\n".join(pending))
                brace_depth += line.count("{") - line.count("}")
                pending = []
                if brace_depth <= 0:
                    current_func = ""
                    brace_depth = 0
                continue
            if stripped.endswith(";"):
                pending = []
            continue

        if current_func and call_re.search(line):
            rows[current_func] = {"func_name": current_func, "path": str(path)}
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            current_func = ""
            brace_depth = 0

    return list(rows.values())


def find_calling_functions(source_dir: Path, call_name: str) -> list[dict[str, str]]:
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", call_name or ""):
        return []

    query = r"\b" + re.escape(call_name) + r"\s*\("
    proc = subprocess.run(
        [
            "rg",
            "-l",
            query,
            str(source_dir),
            "-g",
            "*.c",
            "-g",
            "*.h",
            "-g",
            "!tools/verification/**",
            "-g",
            "!tools/testing/**",
            "-g",
            "!.git/**",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        return []

    found: dict[str, dict[str, str]] = {}
    for raw_path in proc.stdout.splitlines():
        path = Path(raw_path)
        for row in _functions_containing_call(path, call_name):
            found.setdefault(row["func_name"], row)

    return sorted(found.values(), key=lambda row: (row["path"], row["func_name"]))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether selected bug-auditing functions are present in pattern-located comparable functions."
    )
    parser.add_argument("--cases", required=True, help="CSV produced by the reproduced bug-detection setup")
    parser.add_argument("--patterns", required=True, help="defensive_patterns.csv")
    parser.add_argument("--output-tsv", required=True, help="path for per-case localization probe TSV")
    parser.add_argument("--output-summary", required=True, help="path for localization summary JSON")
    parser.add_argument("--repo", default="linux", help="repo key from config.json")
    parser.add_argument("--source-dir", help="override source tree path")
    args = parser.parse_args()

    cfg = load_config()
    source_dir = Path(args.source_dir or cfg["program_paths"][args.repo])
    cases = read_csv(Path(args.cases))
    patterns = {row["pattern_id"]: row for row in read_csv(Path(args.patterns))}

    cache: dict[str, list[dict[str, str]]] = {}
    probe_rows: list[dict[str, object]] = []
    for case in cases:
        pattern = patterns[case["pattern_id"]]
        call_name = pattern["security_sensitive_operation"]
        if call_name not in cache:
            cache[call_name] = find_calling_functions(source_dir, call_name)
        candidates = cache[call_name]
        candidate_names = {row["func_name"] for row in candidates}
        candidate_code, candidate_path = find_function_source(source_dir, case["candidate_function"])
        candidate_present = case["candidate_function"] in candidate_names
        if not candidate_present and candidate_code and re.search(r"\b" + re.escape(call_name) + r"\s*\(", candidate_code):
            candidate_present = True
            candidates = candidates + [{"func_name": case["candidate_function"], "path": candidate_path}]
            cache[call_name] = candidates

        probe_rows.append(
            {
                "case_id": case["case_id"],
                "pattern_id": case["pattern_id"],
                "query": query_for_call(call_name),
                "candidate_function": case["candidate_function"],
                "expected": case["expected"],
                "candidate_present": "yes" if candidate_present else "no",
                "located_comparable_functions": len({row["func_name"] for row in candidates}),
                "sampled_for_audit": "yes",
                "candidate_path": display_path(source_dir, candidate_path),
            }
        )

    fieldnames = [
        "case_id",
        "pattern_id",
        "query",
        "candidate_function",
        "expected",
        "candidate_present",
        "located_comparable_functions",
        "sampled_for_audit",
        "candidate_path",
    ]
    write_tsv(Path(args.output_tsv), probe_rows, fieldnames)

    positives = [row for row in cases if row["expected"] == "bug"]
    summary = {
        "cases": len(cases),
        "known_bug_cases": len(positives),
        "candidate_present_cases": sum(1 for row in probe_rows if row["candidate_present"] == "yes"),
        "unique_patterns": len({row["pattern_id"] for row in cases}),
        "unique_security_sensitive_operations": len({patterns[row["pattern_id"]]["security_sensitive_operation"] for row in cases}),
        "linux_source": str(source_dir),
        "linux_commit": linux_commit(source_dir),
    }
    Path(args.output_summary).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(
        "[ae] localization probe: "
        f"{summary['candidate_present_cases']}/{summary['cases']} selected functions found in comparable candidates"
    )


if __name__ == "__main__":
    main()
