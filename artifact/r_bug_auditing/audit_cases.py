#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_DIR = REPO_ROOT / "scripts" / "core"
INTERNAL_DIR = CORE_DIR / "internal"
for path in (CORE_DIR, INTERNAL_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from bug_auditing import DefensivePattern, DefensivePatternAuditor, load_config  # noqa: E402


def read_patterns(path):
    if not path:
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return {row["pattern_id"]: row for row in rows}


def build_pattern(sec_op, defensive_op, reference_func, pattern_row=None):
    pattern_row = pattern_row or {}
    return DefensivePattern(
        security_sensitive_behaviors=[
            pattern_row.get("security_sensitive_behavior")
            or (
                f"When {sec_op} is called, the returned object, acquired resource, "
                "or error state requires consistent defensive handling."
            )
        ],
        defensive_behaviors=[
            pattern_row.get("defensive_behavior")
            or (
                f"{defensive_op} is expected on the relevant cleanup/error path "
                "or before unsafe use."
            )
        ],
        name=pattern_row.get("pattern_id") or f"{sec_op}->{defensive_op}",
        source_func=pattern_row.get("reference_function") or reference_func,
        source_defensive_op=defensive_op,
    )


def normalize_detected_bug(output):
    consistent = output.get("consistent")
    if consistent is False:
        return "yes"
    if consistent is True:
        return "no"
    return "unknown"


def extract_function_from_text(text, func_name):
    pattern = re.compile(r"\b" + re.escape(func_name) + r"\s*\(", re.M)
    for match in pattern.finditer(text):
        i = match.start() - 1
        while i >= 0 and text[i].isspace():
            i -= 1
        if i >= 1 and text[i - 1 : i + 1] == "->":
            continue
        if i >= 0 and text[i] == ".":
            continue

        brace_pos = text.find("{", match.end())
        if brace_pos == -1:
            continue
        if ";" in text[match.end() : brace_pos]:
            continue

        start = text.rfind("\n", 0, match.start()) + 1
        for _ in range(3):
            prev_end = start - 1
            prev_start = text.rfind("\n", 0, prev_end) + 1
            prev_line = text[prev_start:prev_end].strip()
            if not prev_line:
                break
            if prev_line.endswith((";", "{", "}")) or prev_line.startswith("#"):
                break
            start = prev_start

        depth = 0
        end = None
        for pos in range(brace_pos, len(text)):
            ch = text[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        if end is not None:
            return text[start:end]
    return ""


def find_function_source(source_dir, func_name):
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", func_name or ""):
        return "", ""

    query = r"\b" + re.escape(func_name) + r"\s*\("
    cmd = [
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
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        return "", ""
    paths = [Path(p) for p in proc.stdout.splitlines() if p.strip()]
    paths.sort(key=lambda p: ("/tools/" in str(p), p.suffix != ".c", len(str(p))))
    for path in paths:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        code = extract_function_from_text(text, func_name)
        if code:
            return code, str(path)
    return "", ""


def main():
    parser = argparse.ArgumentParser(description="Run exact-case reduced bug auditing.")
    parser.add_argument("--cases", required=True, help="CSV containing reduced bug-auditing cases")
    parser.add_argument("--output-json", required=True, help="path to write detailed JSON results")
    parser.add_argument("--output-csv", required=True, help="path to write compact CSV results")
    parser.add_argument("--repo", default="linux", help="repo key from config.json")
    parser.add_argument("--patterns", help="reference defensive_patterns.csv used as pattern input")
    parser.add_argument("--workers", type=int, default=8, help="parallel workers within each pattern group")
    parser.add_argument("--llm-model", help="override LLM model")
    parser.add_argument("--llm-timeout", type=float, default=300.0, help="LLM timeout in seconds")
    args = parser.parse_args()

    with open(args.cases, newline="") as f:
        rows = list(csv.DictReader(f))
    patterns_by_id = read_patterns(args.patterns)

    cfg = load_config()
    source_dir = Path(cfg["program_paths"][args.repo])

    groups = defaultdict(list)
    for row in rows:
        key = (row["security_sensitive_operation"], row["defensive_operation"])
        groups[key].append(row)

    auditor = DefensivePatternAuditor(args.repo)
    detailed = []
    compact = []

    for (sec_op, defensive_op), case_rows in groups.items():
        reference_func = next((r["reference_function"] for r in case_rows if r.get("reference_function")), "")
        pattern_row = patterns_by_id.get(case_rows[0].get("pattern_id", ""))
        pattern = build_pattern(sec_op, defensive_op, reference_func, pattern_row)
        candidates = []
        for row in case_rows:
            code, path = find_function_source(source_dir, row["candidate_function"])
            if not code:
                print(f"[warn] source not found for {row['candidate_function']}")
            candidates.append(
                {
                    "func_name": row["candidate_function"],
                    "path": path,
                    "function": code,
                }
            )
        outputs = auditor.audit(
            pattern,
            candidates,
            llm_model=args.llm_model,
            timeout=args.llm_timeout,
            workers=args.workers,
        )
        for row, output in zip(case_rows, outputs):
            detected_bug = normalize_detected_bug(output)
            expected = row.get("expected", "")
            expected_bug = expected == "bug"
            expected_no_bug = expected == "no_bug"
            if expected_bug or expected_no_bug:
                matched = (
                    (expected_bug and detected_bug == "yes")
                    or (expected_no_bug and detected_bug == "no")
                )
                matched_value = "yes" if matched else "no"
            else:
                matched = None
                matched_value = "n/a"
            record = {
                "case": row,
                "audit": output,
                "detected_bug": detected_bug,
                "matches_expected": matched,
            }
            detailed.append(record)
            compact.append(
                {
                    "case_id": row["case_id"],
                    "expected": row["expected"],
                    "candidate_function": row["candidate_function"],
                    "security_sensitive_operation": sec_op,
                    "defensive_operation": defensive_op,
                    "verdict": output.get("verdict"),
                    "consistent": output.get("consistent"),
                    "detected_bug": detected_bug,
                    "matches_expected": matched_value,
                }
            )

    out_json = Path(args.output_json)
    out_csv = Path(args.output_csv)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(detailed, indent=2), encoding="utf-8")
    with out_csv.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "case_id",
                "expected",
                "candidate_function",
                "security_sensitive_operation",
                "defensive_operation",
                "verdict",
                "consistent",
                "detected_bug",
                "matches_expected",
            ],
        )
        writer.writeheader()
        writer.writerows(compact)

    labeled = [row for row in compact if row["matches_expected"] != "n/a"]
    matched = sum(1 for row in labeled if row["matches_expected"] == "yes")
    print(
        "[ae] audit completed: "
        f"{matched}/{len(labeled)} labeled candidates matched expected labels; "
        f"{len(compact) - len(labeled)} random comparable candidates audited without expected labels"
    )


if __name__ == "__main__":
    main()
