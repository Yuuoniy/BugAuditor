#!/usr/bin/env python3
"""Check Table 18 top security-sensitive-operation coverage."""

import argparse
import csv
from pathlib import Path


SEEDS = [
    "kfree",
    "of_node_put",
    "clk_put",
    "null-ptr-check",
    "negative-check",
    "err-ptr-check",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_inferred_patterns(root: Path) -> Path:
    result_path = root / "artifact" / "results" / "r_pattern_reasoning" / "inferred_patterns.csv"
    if result_path.exists():
        return result_path
    return root / "artifact" / "r_pattern_reasoning" / "reference" / "inferred_patterns.csv"


def read_top_ops(table_dir: Path, seed: str) -> list[str]:
    path = table_dir / f"{seed}.txt"
    ops = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ops.append(line)
    return ops


def read_inferred_ops(path: Path) -> dict[str, set[str]]:
    by_seed = {seed: set() for seed in SEEDS}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            seed = row.get("seed_defensive_op", "")
            op = row.get("security_sensitive_operation", "")
            if seed in by_seed and op:
                by_seed[seed].add(op)
    return by_seed


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "seed_defensive_op",
                "covered_top_operations",
                "top_operations",
                "coverage",
                "missing_operations",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    root = repo_root()
    reference_dir = root / "artifact" / "r_pattern_reasoning" / "reference"
    parser = argparse.ArgumentParser(
        description="Check whether inferred patterns cover Table 18 top security-sensitive operations."
    )
    parser.add_argument(
        "--inferred-patterns",
        default=str(default_inferred_patterns(root)),
        help="inferred_patterns.csv to check; defaults to results first, then packaged reference",
    )
    parser.add_argument(
        "--table18-dir",
        default=str(reference_dir / "table18_top30_security_sensitive_ops"),
        help="directory containing one Table 18 top-operation txt file per seed",
    )
    parser.add_argument(
        "--output-csv",
        default=str(root / "artifact" / "results" / "r_pattern_reasoning" / "table18_top30_coverage.csv"),
        help="path to write the coverage summary CSV",
    )
    args = parser.parse_args()

    inferred_path = Path(args.inferred_patterns)
    table_dir = Path(args.table18_dir)
    inferred_ops = read_inferred_ops(inferred_path)

    rows: list[dict[str, object]] = []
    total_covered = 0
    total_ops = 0

    print("[ae] Table 18 top security-sensitive operation coverage")
    print(f"[ae] inferred patterns: {inferred_path}")
    print(f"[ae] table operation files: {table_dir}")
    for seed in SEEDS:
        top_ops = read_top_ops(table_dir, seed)
        covered = [op for op in top_ops if op in inferred_ops[seed]]
        missing = [op for op in top_ops if op not in inferred_ops[seed]]
        total_covered += len(covered)
        total_ops += len(top_ops)
        suffix = ""
        if missing:
            suffix = f" (missing: {', '.join(missing[:6])}"
            if len(missing) > 6:
                suffix += ", ..."
            suffix += ")"
        print(f"[ae] {seed}: {len(covered)}/{len(top_ops)} covered{suffix}")
        rows.append(
            {
                "seed_defensive_op": seed,
                "covered_top_operations": len(covered),
                "top_operations": len(top_ops),
                "coverage": f"{len(covered)}/{len(top_ops)}",
                "missing_operations": ";".join(missing),
            }
        )

    rows.append(
        {
            "seed_defensive_op": "TOTAL",
            "covered_top_operations": total_covered,
            "top_operations": total_ops,
            "coverage": f"{total_covered}/{total_ops}",
            "missing_operations": "",
        }
    )
    write_csv(Path(args.output_csv), rows)
    print(f"[ae] TOTAL: {total_covered}/{total_ops} covered")
    print(f"[ae] wrote coverage CSV: {args.output_csv}")


if __name__ == "__main__":
    main()
