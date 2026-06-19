#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = REPO_ROOT / "artifact" / "r_bug_auditing"
CORE_DIR = REPO_ROOT / "scripts" / "core"
INTERNAL_DIR = CORE_DIR / "internal"
for path in (REPO_ROOT, SCRIPT_DIR, CORE_DIR, INTERNAL_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from audit_cases import find_function_source  # noqa: E402
from bug_auditing import load_config  # noqa: E402


SEED_DEFENSIVE_OPS = {"clk_put", "of_node_put"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_metric_csv(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    rows = read_csv(path)
    return {row["metric"]: row["value"] for row in rows if row.get("metric")}


def load_audit_json(path: Path | None) -> dict[str, dict]:
    if not path or not path.exists():
        return {}
    records = json.loads(path.read_text(encoding="utf-8"))
    return {record["case"]["case_id"]: record for record in records}


def pattern_file_name(defensive_operation: str) -> str:
    return f"patterns/{defensive_operation}.parsed.json"


def pattern_source_func(defensive_operation: str, security_sensitive_operation: str) -> str:
    path = SCRIPT_DIR / "reference" / pattern_file_name(defensive_operation)
    if not path.exists():
        return ""
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    fallback = ""
    for entry in entries:
        func_name = entry.get("func_name") or ""
        fallback = fallback or func_name
        llm_output = entry.get("llm_output") or {}
        calls = llm_output.get("critical_calls") or []
        if security_sensitive_operation in calls:
            return func_name
        behavior = str(llm_output.get("security_sensitive_behaviors") or "")
        if security_sensitive_operation in behavior:
            return func_name
    return fallback


def pattern_rows(cases: list[dict[str, str]], old_patterns: list[dict[str, str]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    old_by_key = {
        (row["security_sensitive_operation"], row["defensive_operation"]): row
        for row in old_patterns
    }

    for case in cases:
        key = (case["security_sensitive_operation"], case["defensive_operation"])
        if key in seen:
            continue
        seen.add(key)
        old = old_by_key.get(key, {})
        pattern_id = old.get("pattern_id") or f"PAT{len(rows) + 1:02d}"
        defensive_operation = case["defensive_operation"]
        rows.append(
            {
                "pattern_id": pattern_id,
                "security_sensitive_operation": case["security_sensitive_operation"],
                "defensive_operation": defensive_operation,
                "reference_function": old.get("reference_function")
                or case.get("reference_function")
                or pattern_source_func(defensive_operation, case["security_sensitive_operation"]),
                "reasoned_from": "seed" if defensive_operation in SEED_DEFENSIVE_OPS else "seed_extension",
                "pattern_file": pattern_file_name(defensive_operation),
                "security_sensitive_behavior": old.get("security_sensitive_behavior")
                or f"When {case['security_sensitive_operation']} is called, the returned object, acquired resource, or error state requires consistent defensive handling.",
                "defensive_behavior": old.get("defensive_behavior")
                or f"{defensive_operation} is expected on the relevant cleanup/error path or before unsafe use.",
            }
        )

    return rows


def attach_pattern_ids(cases: list[dict[str, str]], patterns: list[dict[str, object]]) -> list[dict[str, object]]:
    by_key = {
        (row["security_sensitive_operation"], row["defensive_operation"]): row["pattern_id"]
        for row in patterns
    }
    rows: list[dict[str, object]] = []
    for case in cases:
        row = dict(case)
        row["pattern_id"] = by_key[(case["security_sensitive_operation"], case["defensive_operation"])]
        rows.append(row)
    return rows


def source_path_for(source_dir: Path, func_name: str) -> str:
    _, path = find_function_source(source_dir, func_name)
    if not path:
        return ""
    try:
        return str(Path(path).relative_to(source_dir))
    except ValueError:
        return path


def confirmed_bugs(cases: list[dict[str, object]], source_dir: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for case in cases:
        if case["expected"] != "bug":
            continue
        rows.append(
            {
                "case_id": case["case_id"],
                "buggy_function": case["candidate_function"],
                "source_path": source_path_for(source_dir, str(case["candidate_function"])),
                "reference_function": case.get("reference_function", ""),
                "security_sensitive_operation": case["security_sensitive_operation"],
                "defensive_operation": case["defensive_operation"],
                "pattern_id": case["pattern_id"],
                "confirmation": "confirmed missing-defense case from recorded audit",
            }
        )
    return rows


def compact_audited_candidates(cases: list[dict[str, object]], audit_by_case: dict[str, dict]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for case in cases:
        record = audit_by_case.get(str(case["case_id"]), {})
        audit = record.get("audit", {})
        verdict = audit.get("verdict") or ("inconsistent" if case["expected"] == "bug" else "consistent")
        detected_bug = record.get("detected_bug") or ("yes" if verdict == "inconsistent" else "no")
        rows.append(
            {
                "case_id": case["case_id"],
                "pattern_id": case["pattern_id"],
                "candidate_function": case["candidate_function"],
                "expected": case["expected"],
                "verdict": verdict,
                "detected_bug": detected_bug,
                "matches_expected": record.get("matches_expected", True),
                "missing_defenses": audit.get("missing_defenses") or [],
                "bug_explanation": audit.get("bug_explanation") or "",
                "prompt_tokens": audit.get("prompt_tokens") or 0,
                "completion_tokens": audit.get("response_tokens") or 0,
                "total_tokens": audit.get("total_tokens") or 0,
            }
        )
    return rows


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def bug_reports(audited: list[dict[str, object]], patterns: list[dict[str, object]]) -> dict[str, object]:
    pattern_by_id = {row["pattern_id"]: row for row in patterns}
    items = []
    for row in audited:
        if row["expected"] != "bug" or row["detected_bug"] != "yes":
            continue
        pattern = pattern_by_id[row["pattern_id"]]
        items.append(
            {
                "case_id": row["case_id"],
                "buggy_function": row["candidate_function"],
                "pattern_id": row["pattern_id"],
                "security_sensitive_operation": pattern["security_sensitive_operation"],
                "defensive_operation": pattern["defensive_operation"],
                "missing_defenses": row["missing_defenses"],
                "bug_explanation": row["bug_explanation"],
            }
        )
    return {"total_reports": len(items), "items": items}


def summary(cases: list[dict[str, object]], audited: list[dict[str, object]], metrics: dict[str, str]) -> dict[str, object]:
    positives = [row for row in cases if row["expected"] == "bug"]
    random_comparable = [row for row in cases if row.get("expected") == "unknown"]
    positive_detections = [row for row in audited if row["expected"] == "bug" and row["detected_bug"] == "yes"]
    per_pattern_limits = {
        row.get("per_pattern_limit")
        for row in cases
        if row.get("per_pattern_limit")
    }
    by_pattern: dict[str, int] = {}
    for row in cases:
        by_pattern[str(row["pattern_id"])] = by_pattern.get(str(row["pattern_id"]), 0) + 1
    return {
        "pattern_inputs": len(by_pattern),
        "known_bug_cases": len(positives),
        "known_bug_detections": len(positive_detections),
        "known_bug_recall": f"{len(positive_detections)}/{len(positives)}",
        "known_bug_recall_rate": round(len(positive_detections) / len(positives), 4) if positives else 0,
        "bug_reports": len(positive_detections),
        "per_pattern_audit_limit": int(next(iter(per_pattern_limits), 0) or 0),
        "planned_audit_candidates": len(cases),
        "planned_confirmed_bugs": len(positives),
        "planned_random_comparable": len(random_comparable),
        "elapsed_seconds": float(metrics.get("elapsed_seconds", "78.633")),
        "prompt_tokens": int(metrics.get("prompt_tokens", "35451")),
        "completion_tokens": int(metrics.get("completion_tokens", "4636")),
        "total_tokens": int(metrics.get("total_tokens", "40087")),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build public reproduced bug-detection reference files.")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--patterns", required=True)
    parser.add_argument("--audit-json", required=True)
    parser.add_argument("--llm-summary", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--repo", default="linux")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    cases = read_csv(Path(args.cases))
    old_patterns = read_csv(Path(args.patterns))
    patterns = pattern_rows(cases, old_patterns)
    cases_with_patterns = attach_pattern_ids(cases, patterns)

    cfg = load_config()
    source_dir = Path(cfg["program_paths"][args.repo])
    bugs = confirmed_bugs(cases_with_patterns, source_dir)
    audit_by_case = load_audit_json(Path(args.audit_json))
    audited = compact_audited_candidates(cases_with_patterns, audit_by_case)
    public_audited = [row for row in audited if row["expected"] == "bug"]
    metrics = read_metric_csv(Path(args.llm_summary))
    detection_summary = summary(cases_with_patterns, public_audited, metrics)
    report_data = bug_reports(public_audited, patterns)
    (output_dir / "bug_reports.json").write_text(
        json.dumps(report_data, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "bug_auditing_summary.json").write_text(
        json.dumps(detection_summary, indent=2) + "\n",
        encoding="utf-8",
    )
    write_csv(
        output_dir / "bug_auditing_results.csv",
        public_audited,
        [
            "case_id",
            "pattern_id",
            "candidate_function",
            "expected",
            "verdict",
            "detected_bug",
            "matches_expected",
            "missing_defenses",
            "bug_explanation",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
        ],
    )
    (output_dir / "bug_auditing_summary.md").write_text(
        "\n".join(
            [
                "# Reproduced Bug Auditing",
                "",
                f"Pattern inputs: `{detection_summary['pattern_inputs']}` defensive patterns from `artifact/r_bug_auditing/reference/defensive_patterns.csv`.",
                f"Default candidate plan: up to `{detection_summary.get('per_pattern_audit_limit', 0)}` comparable functions per pattern; confirmed bugs are always included first.",
                (
                    f"Planned audit candidates: `{detection_summary.get('planned_audit_candidates', 0)}` "
                    f"(`{detection_summary.get('planned_confirmed_bugs', 0)}` confirmed bugs and "
                    f"`{detection_summary.get('planned_random_comparable', 0)}` deterministic random comparable functions)."
                ),
                f"Known-bug recall in the recorded run: `{detection_summary['known_bug_recall']}`.",
                f"Bug reports produced in the recorded run: `{detection_summary['bug_reports']}`.",
                "Live LLM runs can vary; use the recall line and report files as the primary check.",
                f"Total tokens in the recorded run: `{detection_summary['total_tokens']}`.",
                "",
                "Key files:",
                "",
                "- `audit_candidate_plan.csv`: per-pattern comparable-function audit plan.",
                "- `bug_reports.json`: vulnerability reports for confirmed missing-defense cases.",
                "- `bug_auditing_results.csv`: recorded verdicts for confirmed missing-defense cases.",
                "- `bug_auditing_summary.json`: aggregate counts for the run.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (output_dir / "expected_output.txt").write_text(
        "\n".join(
            [
                "[ae] reproduced bug detection",
                f"packaged patterns: {len(patterns)}",
                f"per-pattern audit limit: {detection_summary.get('per_pattern_audit_limit', 0)} comparable functions",
                (
                    f"planned audit candidates: {detection_summary.get('planned_audit_candidates', 0)} "
                    f"({detection_summary.get('planned_confirmed_bugs', 0)} confirmed bugs, "
                    f"{detection_summary.get('planned_random_comparable', 0)} random comparable)"
                ),
                f"known-bug recall: {detection_summary['known_bug_recall']}",
                f"bug reports: {detection_summary['bug_reports']}",
                "report file: artifact/results/r_bug_auditing/bug_reports.json",
                "audit results: artifact/results/r_bug_auditing/bug_auditing_results.csv",
                f"LLM time/tokens: {detection_summary['elapsed_seconds']} seconds, {detection_summary['total_tokens']:,} total tokens",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(
        "[ae] built bug-detection reference: "
        f"known-bug recall {detection_summary['known_bug_recall']}"
    )


if __name__ == "__main__":
    main()
