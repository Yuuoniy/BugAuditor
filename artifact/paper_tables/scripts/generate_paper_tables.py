#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import html
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def format_int(value: str) -> str:
    try:
        return f"{int(value):,}"
    except ValueError:
        return value


def format_accuracy(value: str) -> str:
    return f"{float(value) * 100:.1f}%"


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def latex_escape(value: str) -> str:
    return (
        value.replace("\\", "\\textbackslash{}")
        .replace("_", "\\_")
        .replace("%", "\\%")
        .replace("&", "\\&")
        .replace("#", "\\#")
    )


def latex_table(headers: list[str], rows: list[list[str]]) -> str:
    spec = "l" + "r" * (len(headers) - 1)
    lines = [
        f"\\begin{{tabular}}{{{spec}}}",
        "\\toprule",
        " & ".join(latex_escape(h) for h in headers) + r" \\",
        "\\midrule",
    ]
    lines.extend(" & ".join(latex_escape(cell) for cell in row) + r" \\" for row in rows)
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    return "\n".join(lines)


def write_table(out_dir: Path, stem: str, title: str, headers: list[str], rows: list[list[str]]) -> None:
    md = f"# {title}\n\n" + markdown_table(headers, rows)
    tex = latex_table(headers, rows)
    write_text(out_dir / f"{stem}.md", md)
    write_text(out_dir / f"{stem}.tex", tex)
    print(title)
    print(markdown_table(headers, rows))


def table9(out_dir: Path) -> None:
    rows = []
    for row in read_csv(DATA_DIR / "table9_paper_expected.csv"):
        rows.append(
            [
                row["defensive_op"],
                format_int(row["usage_located"]),
                format_int(row["collected_functions"]),
                format_int(row["spec_patterns"]),
            ]
        )
    write_table(
        out_dir,
        "table9_statistics",
        "Table 9: Statistics of Defensive Patterns for Six Seed Operations",
        ["Defensive operation", "# usages", "# defensive-code snippets", "# inferred patterns"],
        rows,
    )


def table11(out_dir: Path) -> None:
    rows = []
    for row in read_csv(DATA_DIR / "table11_paper_expected.csv"):
        rows.append(
            [
                row["seed_defensive_op"],
                format_int(row["wrapper_defensive_ops"]),
                format_int(row["inferred_patterns"]),
            ]
        )
    write_table(
        out_dir,
        "table11_wrapper_patterns",
        "Table 11: Statistics of Wrappers and Patterns from Seeds",
        ["Seed defensive operation", "# wrapper defensive operations", "# inferred patterns"],
        rows,
    )


def nice_ticks(max_value: int) -> list[int]:
    ticks = [1]
    value = 10
    while value <= max_value:
        ticks.append(value)
        value *= 10
    return ticks


def figure8(out_dir: Path) -> None:
    rows = read_csv(DATA_DIR / "figure8_pattern_occurrences.csv")
    points = [(int(row["rank"]), int(row["count"])) for row in rows]
    width, height = 980, 560
    left, right, top, bottom = 88, 28, 36, 78
    plot_w = width - left - right
    plot_h = height - top - bottom
    max_rank = max(rank for rank, _ in points)
    max_count = max(count for _, count in points)
    log_max = math.log10(max_count)

    def x_pos(rank: int) -> float:
        return left + (rank - 1) / max(1, max_rank - 1) * plot_w

    def y_pos(count: int) -> float:
        return top + (log_max - math.log10(max(1, count))) / log_max * plot_h

    sampled = []
    step = max(1, len(points) // 1800)
    for idx, point in enumerate(points):
        if idx % step == 0 or idx == len(points) - 1:
            sampled.append(point)
    polyline = " ".join(f"{x_pos(rank):.2f},{y_pos(count):.2f}" for rank, count in sampled)

    x_ticks = [1, 2500, 5000, 7500, 10000, 12500, 15000, max_rank]
    y_ticks = nice_ticks(max_count)
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>text{font-family:Arial,sans-serif;font-size:14px;fill:#1f2933}.axis{stroke:#1f2933;stroke-width:1.4}.grid{stroke:#d9dee7;stroke-width:1}.line{fill:none;stroke:#1f77b4;stroke-width:2.2}</style>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="white"/>',
        f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}"/>',
        f'<line class="axis" x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}"/>',
    ]
    for tick in x_ticks:
        x = x_pos(tick)
        svg.append(f'<line class="grid" x1="{x:.2f}" y1="{top}" x2="{x:.2f}" y2="{top + plot_h}"/>')
        svg.append(f'<text x="{x:.2f}" y="{top + plot_h + 24}" text-anchor="middle">{tick:,}</text>')
    for tick in y_ticks:
        y = y_pos(tick)
        svg.append(f'<line class="grid" x1="{left}" y1="{y:.2f}" x2="{left + plot_w}" y2="{y:.2f}"/>')
        svg.append(f'<text x="{left - 12}" y="{y + 5:.2f}" text-anchor="end">{tick:,}</text>')
    svg.append(f'<polyline class="line" points="{polyline}"/>')
    svg.append(f'<text x="{left + plot_w / 2:.2f}" y="{height - 24}" text-anchor="middle">Defensive pattern index (sorted by occurrence)</text>')
    svg.append(f'<text transform="translate(26 {top + plot_h / 2:.2f}) rotate(-90)" text-anchor="middle">Occurrences (log scale)</text>')
    svg.append(f'<text x="{left}" y="22">Figure 8: Long-tail occurrences of inferred defensive patterns</text>')
    svg.append(f'<text x="{left + plot_w}" y="22" text-anchor="end">n={max_rank:,}, max={max_count:,}</text>')
    svg.append("</svg>")
    write_text(out_dir / "figure8_long_tail.svg", "\n".join(svg) + "\n")
    print(f"Figure 8 written to {out_dir / 'figure8_long_tail.svg'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate BugAuditor paper tables and Figure 8 from packaged source data.")
    parser.add_argument("--out", type=Path, default=ROOT.parent / "results" / "paper_tables")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    table9(args.out)
    table11(args.out)
    figure8(args.out)


if __name__ == "__main__":
    main()
