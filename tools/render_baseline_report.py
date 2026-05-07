#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_summary(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_series(records: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    accepted = []
    evaluated = []
    failures = []
    for record in records:
        event = record.get("event")
        if event == "baseline_coverage":
            accepted.append(
                {
                    "iteration": record["iteration"],
                    "line": record["line_coverage"],
                    "branch": record["branch_coverage"],
                    "functions": record.get("functions_coverage"),
                    "label": "baseline",
                }
            )
        elif event == "candidate_accepted":
            accepted.append(
                {
                    "iteration": record["iteration"],
                    "line": record["line_coverage"],
                    "branch": record["branch_coverage"],
                    "functions": record.get("functions_coverage"),
                    "label": record.get("target_name", "accepted"),
                }
            )
        elif event == "candidate_evaluated":
            evaluated.append(record)
        elif event == "target_generation_failed":
            failures.append(record)
    accepted.sort(key=lambda item: item["iteration"])
    evaluated.sort(key=lambda item: item["iteration"])
    failures.sort(key=lambda item: item["iteration"])
    return accepted, evaluated, failures


def svg_line_chart(points: list[dict], width: int = 860, height: int = 360) -> str:
    margin_left = 70
    margin_right = 20
    margin_top = 25
    margin_bottom = 45
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    max_x = max(point["iteration"] for point in points)
    max_x = max(max_x, 1)

    def scale_x(value: float) -> float:
        return margin_left + (value / max_x) * plot_w

    def scale_y(value: float) -> float:
        return margin_top + (100.0 - value) / 100.0 * plot_h

    line_path = " ".join(f"{scale_x(p['iteration']):.2f},{scale_y(p['line']):.2f}" for p in points)
    branch_path = " ".join(f"{scale_x(p['iteration']):.2f},{scale_y(p['branch']):.2f}" for p in points)
    function_path = " ".join(f"{scale_x(p['iteration']):.2f},{scale_y(p['functions']):.2f}" for p in points if p["functions"] is not None)

    y_ticks = []
    for tick in range(0, 101, 20):
        y = scale_y(tick)
        y_ticks.append(f'<line x1="{margin_left}" y1="{y:.2f}" x2="{width - margin_right}" y2="{y:.2f}" stroke="#e5e7eb" />')
        y_ticks.append(
            f'<text x="{margin_left - 10}" y="{y + 4:.2f}" font-size="12" text-anchor="end" fill="#374151">{tick}</text>'
        )

    x_ticks = []
    for tick in range(0, max_x + 1):
        x = scale_x(tick)
        x_ticks.append(f'<line x1="{x:.2f}" y1="{margin_top}" x2="{x:.2f}" y2="{height - margin_bottom}" stroke="#f3f4f6" />')
        x_ticks.append(
            f'<text x="{x:.2f}" y="{height - margin_bottom + 20}" font-size="12" text-anchor="middle" fill="#374151">{tick}</text>'
        )

    point_marks = []
    for point in points:
        x = scale_x(point["iteration"])
        y = scale_y(point["line"])
        point_marks.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4" fill="#2563eb" />')
        point_marks.append(
            f'<text x="{x:.2f}" y="{y - 10:.2f}" font-size="11" text-anchor="middle" fill="#1f2937">{point["line"]:.1f}</text>'
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{margin_left}" y="18" font-size="18" font-weight="bold" fill="#111827">tinyxml2 baseline coverage growth</text>
  <text x="{width - margin_right}" y="18" font-size="12" text-anchor="end" fill="#6b7280">accepted iterations only</text>
  {''.join(y_ticks)}
  {''.join(x_ticks)}
  <line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#111827" />
  <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#111827" />
  <polyline fill="none" stroke="#2563eb" stroke-width="3" points="{line_path}" />
  <polyline fill="none" stroke="#dc2626" stroke-width="3" points="{branch_path}" />
  <polyline fill="none" stroke="#059669" stroke-width="3" points="{function_path}" />
  {''.join(point_marks)}
  <text x="{width / 2:.2f}" y="{height - 8}" font-size="13" text-anchor="middle" fill="#111827">Iteration</text>
  <text x="18" y="{height / 2:.2f}" font-size="13" text-anchor="middle" fill="#111827" transform="rotate(-90 18 {height / 2:.2f})">Coverage %</text>
  <rect x="{width - 235}" y="40" width="12" height="12" fill="#2563eb"/><text x="{width - 217}" y="50" font-size="12" fill="#111827">Line coverage</text>
  <rect x="{width - 235}" y="60" width="12" height="12" fill="#dc2626"/><text x="{width - 217}" y="70" font-size="12" fill="#111827">Branch coverage</text>
  <rect x="{width - 235}" y="80" width="12" height="12" fill="#059669"/><text x="{width - 217}" y="90" font-size="12" fill="#111827">Function coverage</text>
</svg>
"""


def svg_bar_chart(evaluated: list[dict], width: int = 860, height: int = 320) -> str:
    margin_left = 70
    margin_right = 20
    margin_top = 25
    margin_bottom = 45
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    count = max(len(evaluated), 1)
    slot = plot_w / count
    bar_w = slot * 0.35
    max_growth = max(max(item["line_growth"], item["branch_growth"]) for item in evaluated)
    max_growth = max(max_growth, 1.0)

    def scale_y(value: float) -> float:
        return margin_top + plot_h - (value / max_growth) * plot_h

    bars = []
    labels = []
    for idx, item in enumerate(evaluated):
        center = margin_left + slot * idx + slot / 2
        line_h = plot_h - (scale_y(item["line_growth"]) - margin_top)
        branch_h = plot_h - (scale_y(item["branch_growth"]) - margin_top)
        line_x = center - bar_w - 4
        branch_x = center + 4
        line_y = scale_y(item["line_growth"])
        branch_y = scale_y(item["branch_growth"])
        bars.append(f'<rect x="{line_x:.2f}" y="{line_y:.2f}" width="{bar_w:.2f}" height="{line_h:.2f}" fill="#2563eb" />')
        bars.append(f'<rect x="{branch_x:.2f}" y="{branch_y:.2f}" width="{bar_w:.2f}" height="{branch_h:.2f}" fill="#dc2626" />')
        labels.append(
            f'<text x="{center:.2f}" y="{height - margin_bottom + 20}" font-size="12" text-anchor="middle" fill="#374151">{item["iteration"]}</text>'
        )

    y_ticks = []
    for tick_idx in range(0, 6):
        tick = max_growth * tick_idx / 5
        y = scale_y(tick)
        y_ticks.append(f'<line x1="{margin_left}" y1="{y:.2f}" x2="{width - margin_right}" y2="{y:.2f}" stroke="#e5e7eb" />')
        y_ticks.append(
            f'<text x="{margin_left - 10}" y="{y + 4:.2f}" font-size="12" text-anchor="end" fill="#374151">{tick:.1f}</text>'
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{margin_left}" y="18" font-size="18" font-weight="bold" fill="#111827">Per-candidate coverage gain</text>
  {''.join(y_ticks)}
  <line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#111827" />
  <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#111827" />
  {''.join(bars)}
  {''.join(labels)}
  <text x="{width / 2:.2f}" y="{height - 8}" font-size="13" text-anchor="middle" fill="#111827">Evaluated iteration</text>
  <text x="18" y="{height / 2:.2f}" font-size="13" text-anchor="middle" fill="#111827" transform="rotate(-90 18 {height / 2:.2f})">Growth %</text>
  <rect x="{width - 210}" y="40" width="12" height="12" fill="#2563eb"/><text x="{width - 192}" y="50" font-size="12" fill="#111827">Line growth</text>
  <rect x="{width - 210}" y="60" width="12" height="12" fill="#dc2626"/><text x="{width - 192}" y="70" font-size="12" fill="#111827">Branch growth</text>
</svg>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", required=True, help="Path to the baseline metrics jsonl.")
    parser.add_argument("--summary", help="Optional coverage summary json.")
    parser.add_argument("--output-dir", required=True, help="Directory to write the report into.")
    args = parser.parse_args()

    metrics_path = Path(args.metrics)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = load_jsonl(metrics_path)
    accepted, evaluated, failures = build_series(records)
    summary = load_summary(Path(args.summary)) if args.summary else None

    coverage_svg = svg_line_chart(accepted)
    growth_svg = svg_bar_chart(evaluated)
    (output_dir / "coverage_growth.svg").write_text(coverage_svg, encoding="utf-8")
    (output_dir / "candidate_growth.svg").write_text(growth_svg, encoding="utf-8")

    initial = accepted[0]
    final = accepted[-1]
    line_gain = final["line"] - initial["line"]
    branch_gain = final["branch"] - initial["branch"]
    function_gain = (final["functions"] or 0.0) - (initial["functions"] or 0.0)
    accepted_candidates = max(len(accepted) - 1, 0)
    failed_generations = len(failures)
    best_eval = max(evaluated, key=lambda item: item["line_growth"]) if evaluated else None

    summary_section = "No summary file provided."
    if summary:
        totals = summary["data"][0]["totals"]
        summary_section = (
            f"- Current line coverage summary: {totals['lines']['percent']:.2f}% ({totals['lines']['covered']}/{totals['lines']['count']})\n"
            f"- Current branch coverage summary: {totals['branches']['percent']:.2f}% ({totals['branches']['covered']}/{totals['branches']['count']})\n"
            f"- Current function coverage summary: {totals['functions']['percent']:.2f}% ({totals['functions']['covered']}/{totals['functions']['count']})"
        )

    report = f"""# tinyxml2 Baseline Report

## Overview
- Metrics file: `{metrics_path}`
- Accepted candidates: {accepted_candidates}
- Failed target generations: {failed_generations}
- Initial line coverage: {initial['line']:.2f}%
- Final line coverage: {final['line']:.2f}%
- Line coverage gain: {line_gain:.2f} points
- Initial branch coverage: {initial['branch']:.2f}%
- Final branch coverage: {final['branch']:.2f}%
- Branch coverage gain: {branch_gain:.2f} points
- Initial function coverage: {initial['functions']:.2f}%
- Final function coverage: {final['functions']:.2f}%
- Function coverage gain: {function_gain:.2f} points

## Best Candidate
"""
    if best_eval:
        report += (
            f"- Iteration: {best_eval['iteration']}\n"
            f"- Action: {best_eval['action_type']}\n"
            f"- Target: `{best_eval['target_name']}`\n"
            f"- Line growth: {best_eval['line_growth']:.2f} points\n"
            f"- Branch growth: {best_eval['branch_growth']:.2f} points\n"
        )
    else:
        report += "- No evaluated candidates.\n"

    report += f"""
## Current Summary
{summary_section}

## Charts
- Coverage growth: `coverage_growth.svg`
- Candidate growth: `candidate_growth.svg`

## Notes
- This report is based on the `process` stage metrics.
- If `run_all_fuzzer` did not emit a new coverage summary after the long fuzzing run, the summary values above may still reflect the last `process` coverage snapshot.
"""

    (output_dir / "report.md").write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
