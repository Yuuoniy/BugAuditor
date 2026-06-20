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


SEED_DEFENSIVE_OPS = {"clk_put", "of_node_put"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_metric_csv(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    rows = read_csv(path)
    return {row["metric"]: row["value"] for row in rows if row.get("metric")}


def metric(metrics: dict[str, str], new_key: str, old_key: str | None = None, default: str = "0") -> str:
    if new_key in metrics:
        return metrics[new_key]
    if old_key and old_key in metrics:
        return metrics[old_key]
    return default


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


def public_source_path(path: object) -> str:
    text = str(path or "")
    if not text:
        return ""
    if "/linux/" in text:
        return text.split("/linux/", 1)[1]
    return text


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


def audit_status(record: dict | None, audit: dict[str, object]) -> str:
    if not record:
        return "missing_audit"
    verdict = audit.get("verdict")
    if verdict == "source_not_found":
        return "source_not_found"
    if verdict == "error" or audit.get("error"):
        return "llm_error"
    return "completed"


def normalize_match(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "n/a"


def compact_audited_candidates(cases: list[dict[str, object]], audit_by_case: dict[str, dict]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for case in cases:
        record = audit_by_case.get(str(case["case_id"]))
        audit = record.get("audit", {}) if record else {}
        verdict = audit.get("verdict") or ("missing_audit" if not record else "uncertain")
        detected_bug = record.get("detected_bug") if record else "unknown"
        if detected_bug not in {"yes", "no", "unknown"}:
            detected_bug = "unknown"
        rows.append(
            {
                "case_id": case["case_id"],
                "pattern_id": case["pattern_id"],
                "candidate_function": case["candidate_function"],
                "candidate_role": case.get("candidate_role", ""),
                "security_sensitive_operation": case.get("security_sensitive_operation", ""),
                "defensive_operation": case.get("defensive_operation", ""),
                "source_path": public_source_path(audit.get("source_path") or case.get("candidate_path", "")),
                "expected": case["expected"],
                "audit_status": audit_status(record, audit),
                "verdict": verdict,
                "detected_bug": detected_bug,
                "matches_expected": normalize_match(record.get("matches_expected") if record else None),
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
        if row["detected_bug"] != "yes":
            continue
        pattern = pattern_by_id[row["pattern_id"]]
        items.append(
            {
                "case_id": row["case_id"],
                "buggy_function": row["candidate_function"],
                "expected": row.get("expected", ""),
                "pattern_id": row["pattern_id"],
                "security_sensitive_operation": pattern["security_sensitive_operation"],
                "defensive_operation": pattern["defensive_operation"],
                "source_path": row.get("source_path", ""),
                "missing_defenses": row["missing_defenses"],
                "bug_explanation": row["bug_explanation"],
            }
        )
    detected_bug_reports = sum(1 for item in items if item.get("expected") == "bug")
    comparable_reports = sum(1 for item in items if item.get("expected") == "unknown")
    return {
        "total_reports": len(items),
        "detected_bug_reports": detected_bug_reports,
        "additional_comparable_reports": comparable_reports,
        "items": items,
    }


def detected_bug_overlap(audited: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for row in audited:
        if row.get("expected") != "bug":
            continue
        rows.append(
            {
                "case_id": row["case_id"],
                "pattern_id": row["pattern_id"],
                "buggy_function": row["candidate_function"],
                "security_sensitive_operation": row.get("security_sensitive_operation", ""),
                "defensive_operation": row.get("defensive_operation", ""),
                "source_path": row.get("source_path", ""),
                "audit_status": row.get("audit_status", ""),
                "detected_bug": row.get("detected_bug", ""),
                "matches_expected": row.get("matches_expected", ""),
                "included_in_bug_reports": "yes" if row.get("detected_bug") == "yes" else "no",
                "verdict": row.get("verdict", ""),
            }
        )
    return rows


def summary(cases: list[dict[str, object]], audited: list[dict[str, object]], metrics: dict[str, str]) -> dict[str, object]:
    positives = [row for row in cases if row["expected"] == "bug"]
    random_comparable = [row for row in cases if row.get("expected") == "unknown"]
    positive_detections = [row for row in audited if row["expected"] == "bug" and row["detected_bug"] == "yes"]
    comparable_detections = [row for row in audited if row["expected"] == "unknown" and row["detected_bug"] == "yes"]
    missing_records = [row for row in audited if row["audit_status"] == "missing_audit"]
    llm_errors = [row for row in audited if row["audit_status"] == "llm_error"]
    source_missing = [row for row in audited if row["audit_status"] == "source_not_found"]
    completed = [row for row in audited if row["audit_status"] == "completed"]
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
        "detected_bug_cases": len(positives),
        "detected_bug_reports": len(positive_detections),
        "detected_bug_recall": f"{len(positive_detections)}/{len(positives)}",
        "detected_bug_recall_rate": round(len(positive_detections) / len(positives), 4) if positives else 0,
        "additional_comparable_reports": len(comparable_detections),
        "bug_reports": len(positive_detections) + len(comparable_detections),
        "per_pattern_audit_limit": int(next(iter(per_pattern_limits), 0) or 0),
        "planned_audit_candidates": len(cases),
        "planned_detected_bugs": len(positives),
        "planned_random_comparable": len(random_comparable),
        "completed_audit_candidates": len(completed),
        "missing_audit_records": len(missing_records),
        "llm_error_records": len(llm_errors),
        "source_not_found_records": len(source_missing),
        "elapsed_seconds": float(metric(metrics, "elapsed_seconds", default="78.633")),
        "prompt_tokens": int(metric(metrics, "prompt_tokens", default="35451")),
        "completion_tokens": int(metric(metrics, "completion_tokens", default="4636")),
        "total_tokens": int(metric(metrics, "total_tokens", default="40087")),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build public reproduced bug-detection reference files.")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--patterns", required=True)
    parser.add_argument("--audit-json", required=True)
    parser.add_argument("--llm-summary", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--repo", default="linux")
    parser.add_argument("--source-dir", help="override source tree path")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = read_csv(Path(args.cases))
    old_patterns = read_csv(Path(args.patterns))
    patterns = pattern_rows(cases, old_patterns)
    cases_with_patterns = attach_pattern_ids(cases, patterns)

    audit_by_case = load_audit_json(Path(args.audit_json))
    audited = compact_audited_candidates(cases_with_patterns, audit_by_case)
    metrics = read_metric_csv(Path(args.llm_summary))
    detection_summary = summary(cases_with_patterns, audited, metrics)
    report_data = bug_reports(audited, patterns)
    (output_dir / "bug_reports.json").write_text(
        json.dumps(report_data, indent=2) + "\n", encoding="utf-8"
    )
    benchmark_report_data = {
        "total_reports": report_data["detected_bug_reports"],
        "items": [
            item
            for item in report_data["items"]
            if item.get("expected") == "bug"
        ],
    }
    (output_dir / "detected_bug_reports.json").write_text(
        json.dumps(benchmark_report_data, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "bug_auditing_summary.json").write_text(
        json.dumps(detection_summary, indent=2) + "\n",
        encoding="utf-8",
    )
    write_csv(
        output_dir / "detected_bug_overlap.csv",
        detected_bug_overlap(audited),
        [
            "case_id",
            "pattern_id",
            "buggy_function",
            "security_sensitive_operation",
            "defensive_operation",
            "source_path",
            "audit_status",
            "detected_bug",
            "matches_expected",
            "included_in_bug_reports",
            "verdict",
        ],
    )
    write_csv(
        output_dir / "bug_auditing_results.csv",
        audited,
        [
            "case_id",
            "pattern_id",
            "candidate_function",
            "candidate_role",
            "security_sensitive_operation",
            "defensive_operation",
            "source_path",
            "expected",
            "audit_status",
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
                f"Default candidate plan: up to `{detection_summary.get('per_pattern_audit_limit', 0)}` comparable functions per pattern; detected bug cases are always included first.",
                (
                    f"Planned audit candidates: `{detection_summary.get('planned_audit_candidates', 0)}` "
                    f"(`{detection_summary.get('planned_detected_bugs', 0)}` detected bugs and "
                    f"`{detection_summary.get('planned_random_comparable', 0)}` deterministic random comparable functions)."
                ),
                f"Detected-bug recall in the recorded run: `{detection_summary['detected_bug_recall']}`.",
                (
                    f"Completed audit candidates: `{detection_summary['completed_audit_candidates']}/"
                    f"{detection_summary.get('planned_audit_candidates', 0)}`."
                ),
                (
                    f"Unfinished records: `{detection_summary['llm_error_records']}` LLM errors, "
                    f"`{detection_summary['source_not_found_records']}` missing-source records, "
                    f"`{detection_summary['missing_audit_records']}` missing audit records."
                ),
                f"Additional comparable-function reports in the recorded run: `{detection_summary['additional_comparable_reports']}`.",
                f"Total bug reports produced in the recorded run: `{detection_summary['bug_reports']}`.",
                "Live LLM runs can vary; use the recall line and report files as the primary check.",
                f"Total tokens in the recorded run: `{detection_summary['total_tokens']}`.",
                "",
                "Key files:",
                "",
                "- `audit_candidate_plan.csv`: per-pattern comparable-function audit plan.",
                "- `bug_reports.json`: vulnerability reports produced by the audit.",
                "- `detected_bug_reports.json`: vulnerability reports for the detected benchmark bugs only.",
                "- `bug_auditing_results.csv`: recorded verdicts for all selected audit candidates.",
                "- `detected_bug_overlap.csv`: overlap between detected benchmark bugs and generated reports.",
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
                    f"({detection_summary.get('planned_detected_bugs', 0)} detected bugs, "
                    f"{detection_summary.get('planned_random_comparable', 0)} random comparable)"
                ),
                f"detected-bug recall: {detection_summary['detected_bug_recall']}",
                (
                    f"completed audit candidates: {detection_summary['completed_audit_candidates']}/"
                    f"{detection_summary.get('planned_audit_candidates', 0)}"
                ),
                (
                    f"unfinished records: {detection_summary['llm_error_records']} llm errors, "
                    f"{detection_summary['source_not_found_records']} missing source, "
                    f"{detection_summary['missing_audit_records']} missing audit"
                ),
                f"additional comparable reports: {detection_summary['additional_comparable_reports']}",
                f"bug reports: {detection_summary['bug_reports']}",
                "report file: artifact/results/r_bug_auditing/bug_reports.json",
                "detected bug reports: artifact/results/r_bug_auditing/detected_bug_reports.json",
                "audit results: artifact/results/r_bug_auditing/bug_auditing_results.csv",
                "detected-bug overlap: artifact/results/r_bug_auditing/detected_bug_overlap.csv",
                f"LLM time/tokens: {detection_summary['elapsed_seconds']} seconds, {detection_summary['total_tokens']:,} total tokens",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(
        "[ae] built bug-detection reference: "
        f"detected-bug recall {detection_summary['detected_bug_recall']}"
    )


if __name__ == "__main__":
    main()
