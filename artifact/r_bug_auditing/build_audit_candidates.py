#!/usr/bin/env python3
import argparse
import csv
import random
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_DIR = REPO_ROOT / "scripts" / "core"
INTERNAL_DIR = CORE_DIR / "internal"
SCRIPT_DIR = Path(__file__).resolve().parent
for path in (REPO_ROOT, SCRIPT_DIR, CORE_DIR, INTERNAL_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from audit_cases import find_function_source  # noqa: E402
from bug_auditing import load_config  # noqa: E402
from check_bug_localization import find_calling_functions  # noqa: E402


SEED = "BugAuditor:r_bug_auditing:candidate-plan"
MIN_PER_PATTERN_LIMIT = 10


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def source_path(source_dir: Path, func_name: str) -> str:
    _, path = find_function_source(source_dir, func_name)
    if not path:
        return ""
    return public_source_path(source_dir, path)


def public_source_path(source_dir: Path, path: str) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).relative_to(source_dir))
    except ValueError:
        return str(path).split("/linux/", 1)[1] if "/linux/" in str(path) else str(path)


def function_calls(code: str, call_name: str) -> bool:
    return bool(re.search(r"\b" + re.escape(call_name) + r"\s*\(", code or ""))


def confirmed_bug_rows(confirmed_path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for row in read_csv(confirmed_path):
        key = (row["buggy_function"], row["pattern_id"])
        seen.add(key)
        rows.append({
            "case_id": row["case_id"],
            "pattern_id": row["pattern_id"],
            "candidate_function": row["buggy_function"],
            "reference_function": row.get("reference_function", ""),
            "security_sensitive_operation": row["security_sensitive_operation"],
            "defensive_operation": row["defensive_operation"],
            "source": "confirmed_bugs.csv",
            "note": row.get("confirmation", ""),
        })

    return rows


def located_candidates(source_dir: Path, call_name: str) -> list[dict[str, str]]:
    rows = find_calling_functions(source_dir, call_name)
    unique: dict[str, dict[str, str]] = {}
    for row in rows:
        unique.setdefault(row["func_name"], row)
    return sorted(unique.values(), key=lambda row: (row.get("path", ""), row["func_name"]))


def build_plan(
    source_dir: Path,
    patterns: list[dict[str, str]],
    confirmed_rows: list[dict[str, str]],
    per_pattern_limit: int,
) -> list[dict[str, object]]:
    confirmed_by_pattern: dict[str, list[dict[str, str]]] = {}
    for row in confirmed_rows:
        confirmed_by_pattern.setdefault(row["pattern_id"], []).append(row)

    plan_rows: list[dict[str, object]] = []
    for pattern in patterns:
        pattern_id = pattern["pattern_id"]
        call_name = pattern["security_sensitive_operation"]
        defensive_op = pattern["defensive_operation"]
        candidates = located_candidates(source_dir, call_name)
        candidate_by_name = {row["func_name"]: row for row in candidates}
        candidate_names = set(candidate_by_name)

        confirmed = confirmed_by_pattern.get(pattern_id, [])
        target_count = max(per_pattern_limit, len(confirmed))
        selected_names: set[str] = set()

        for bug in confirmed:
            code, path = find_function_source(source_dir, bug["candidate_function"])
            present = bug["candidate_function"] in candidate_names
            if not present and function_calls(code, call_name):
                present = True
            selected_names.add(bug["candidate_function"])
            plan_rows.append({
                "case_id": bug["case_id"],
                "pattern_id": pattern_id,
                "expected": "bug",
                "candidate_function": bug["candidate_function"],
                "reference_function": bug.get("reference_function") or pattern.get("reference_function", ""),
                "security_sensitive_operation": call_name,
                "defensive_operation": defensive_op,
                "source": bug["source"],
                "note": bug.get("note", ""),
                "candidate_role": "confirmed_bug",
                "candidate_present": "yes" if present else "no",
                "candidate_path": source_path(source_dir, bug["candidate_function"]) or path,
                "located_comparable_functions": len(candidates),
                "per_pattern_limit": per_pattern_limit,
            })

        fill = [row for row in candidates if row["func_name"] not in selected_names]
        rng = random.Random(f"{SEED}:{pattern_id}:{call_name}:{defensive_op}")
        rng.shuffle(fill)
        for idx, candidate in enumerate(fill[: max(0, target_count - len(selected_names))], 1):
            name = candidate["func_name"]
            selected_names.add(name)
            plan_rows.append({
                "case_id": f"{pattern_id}-R{idx:02d}",
                "pattern_id": pattern_id,
                "expected": "unknown",
                "candidate_function": name,
                "reference_function": pattern.get("reference_function", ""),
                "security_sensitive_operation": call_name,
                "defensive_operation": defensive_op,
                "source": "deterministic_random_comparable",
                "note": "deterministic random comparable function; no expected label",
                "candidate_role": "random_comparable",
                "candidate_present": "yes",
                "candidate_path": public_source_path(source_dir, candidate.get("path", "")),
                "located_comparable_functions": len(candidates),
                "per_pattern_limit": per_pattern_limit,
            })

        print(
            "[ae] pattern {pid}: confirmed={confirmed}, selected={selected}, "
            "located_comparable={located}, cap={cap}".format(
                pid=pattern_id,
                confirmed=len(confirmed),
                selected=len(selected_names),
                located=len(candidates),
                cap=target_count,
            )
        )

    return plan_rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build per-pattern comparable-function audit candidates for reproduced bug auditing."
    )
    parser.add_argument("--patterns", required=True, help="defensive_patterns.csv")
    parser.add_argument("--confirmed-bugs", required=True, help="confirmed_bugs.csv")
    parser.add_argument("--output-csv", required=True, help="candidate plan CSV")
    parser.add_argument("--repo", default="linux", help="repo key from config.json")
    parser.add_argument("--source-dir", help="override source tree path")
    parser.add_argument("--per-pattern-limit", type=int, default=MIN_PER_PATTERN_LIMIT)
    args = parser.parse_args()

    if args.per_pattern_limit < MIN_PER_PATTERN_LIMIT:
        raise SystemExit(f"per-pattern audit limit must be at least {MIN_PER_PATTERN_LIMIT}")

    cfg = load_config()
    source_dir = Path(args.source_dir or cfg["program_paths"][args.repo])
    patterns = read_csv(Path(args.patterns))
    confirmed = confirmed_bug_rows(Path(args.confirmed_bugs))
    rows = build_plan(source_dir, patterns, confirmed, args.per_pattern_limit)

    fieldnames = [
        "case_id",
        "pattern_id",
        "expected",
        "candidate_function",
        "reference_function",
        "security_sensitive_operation",
        "defensive_operation",
        "source",
        "note",
        "candidate_role",
        "candidate_present",
        "candidate_path",
        "located_comparable_functions",
        "per_pattern_limit",
    ]
    write_csv(Path(args.output_csv), rows, fieldnames)
    confirmed_count = sum(1 for row in rows if row["candidate_role"] == "confirmed_bug")
    random_count = sum(1 for row in rows if row["candidate_role"] == "random_comparable")
    print(
        "[ae] wrote audit candidate plan: "
        f"{len(rows)} candidates ({confirmed_count} confirmed bugs, {random_count} random comparable)"
    )
    print(f"[ae] candidate plan: {args.output_csv}")


if __name__ == "__main__":
    main()
