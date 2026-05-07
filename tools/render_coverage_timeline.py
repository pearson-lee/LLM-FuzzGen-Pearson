#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def build_points(records: list[dict]) -> list[dict]:
    points = []
    for record in records:
        lines = record.get("lines") or {}
        branches = record.get("branches") or {}
        functions = record.get("functions") or {}
        elapsed_seconds = record.get("elapsed_seconds")
        if elapsed_seconds is None or lines.get("percent") is None:
            continue
        points.append(
            {
                "elapsed_seconds": int(elapsed_seconds),
                "elapsed_minutes": int(elapsed_seconds) / 60.0,
                "line_percent": float(lines.get("percent", 0.0)),
                "line_covered": int(lines.get("covered", 0)),
                "line_total": int(lines.get("count", 0)),
                "branch_percent": float(branches.get("percent", 0.0)) if branches.get("percent") is not None else None,
                "branch_covered": int(branches.get("covered", 0)) if branches else None,
                "branch_total": int(branches.get("count", 0)) if branches else None,
                "function_percent": float(functions.get("percent", 0.0)) if functions.get("percent") is not None else None,
                "function_covered": int(functions.get("covered", 0)) if functions else None,
                "function_total": int(functions.get("count", 0)) if functions else None,
                "timestamp": record.get("timestamp", ""),
            }
        )
    points.sort(key=lambda item: item["elapsed_seconds"])
    return points


def find_stagnation(points: list[dict], window: int, threshold: float) -> list[dict]:
    if window < 1:
        return []
    stagnant = []
    for idx in range(window, len(points)):
        prev = points[idx - window]
        current = points[idx]
        growth = current["line_percent"] - prev["line_percent"]
        if growth <= threshold:
            stagnant.append(
                {
                    "start_seconds": prev["elapsed_seconds"],
                    "end_seconds": current["elapsed_seconds"],
                    "growth": growth,
                }
            )
    return stagnant


def svg_coverage_chart(points: list[dict], width: int = 900, height: int = 380) -> str:
    margin_left = 72
    margin_right = 24
    margin_top = 28
    margin_bottom = 52
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    max_minutes = max(point["elapsed_minutes"] for point in points)
    max_minutes = max(max_minutes, 1.0)

    def scale_x(minutes: float) -> float:
        return margin_left + (minutes / max_minutes) * plot_w

    def scale_y(percent: float) -> float:
        return margin_top + (100.0 - percent) / 100.0 * plot_h

    y_ticks = []
    for tick in range(0, 101, 20):
        y = scale_y(tick)
        y_ticks.append(f'<line x1="{margin_left}" y1="{y:.2f}" x2="{width - margin_right}" y2="{y:.2f}" stroke="#e5e7eb" />')
        y_ticks.append(
            f'<text x="{margin_left - 10}" y="{y + 4:.2f}" font-size="12" text-anchor="end" fill="#374151">{tick}</text>'
        )

    x_ticks = []
    tick_count = min(max(len(points), 2), 8)
    for idx in range(tick_count + 1):
        tick_minutes = max_minutes * idx / tick_count
        x = scale_x(tick_minutes)
        label = f"{tick_minutes:.0f}m" if max_minutes >= 10 else f"{tick_minutes:.1f}m"
        x_ticks.append(f'<line x1="{x:.2f}" y1="{margin_top}" x2="{x:.2f}" y2="{height - margin_bottom}" stroke="#f3f4f6" />')
        x_ticks.append(
            f'<text x="{x:.2f}" y="{height - margin_bottom + 20}" font-size="12" text-anchor="middle" fill="#374151">{label}</text>'
        )

    def polyline(metric_name: str) -> str:
        pairs = []
        for point in points:
            value = point.get(metric_name)
            if value is None:
                continue
            pairs.append(f"{scale_x(point['elapsed_minutes']):.2f},{scale_y(value):.2f}")
        return " ".join(pairs)

    point_marks = []
    for point in points:
        x = scale_x(point["elapsed_minutes"])
        y = scale_y(point["line_percent"])
        point_marks.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4" fill="#2563eb" />')
        point_marks.append(
            f'<text x="{x:.2f}" y="{y - 10:.2f}" font-size="11" text-anchor="middle" fill="#1f2937">{point["line_percent"]:.1f}</text>'
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{margin_left}" y="18" font-size="18" font-weight="bold" fill="#111827">Coverage timeline during fuzzing</text>
  <text x="{width - margin_right}" y="18" font-size="12" text-anchor="end" fill="#6b7280">periodic OSS-Fuzz coverage snapshots</text>
  {''.join(y_ticks)}
  {''.join(x_ticks)}
  <line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#111827" />
  <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#111827" />
  <polyline fill="none" stroke="#2563eb" stroke-width="3" points="{polyline('line_percent')}" />
  <polyline fill="none" stroke="#dc2626" stroke-width="3" points="{polyline('branch_percent')}" />
  <polyline fill="none" stroke="#059669" stroke-width="3" points="{polyline('function_percent')}" />
  {''.join(point_marks)}
  <text x="{width / 2:.2f}" y="{height - 8}" font-size="13" text-anchor="middle" fill="#111827">Elapsed fuzzing time</text>
  <text x="18" y="{height / 2:.2f}" font-size="13" text-anchor="middle" fill="#111827" transform="rotate(-90 18 {height / 2:.2f})">Coverage %</text>
  <rect x="{width - 220}" y="40" width="12" height="12" fill="#2563eb"/><text x="{width - 202}" y="50" font-size="12" fill="#111827">Line coverage</text>
  <rect x="{width - 220}" y="60" width="12" height="12" fill="#dc2626"/><text x="{width - 202}" y="70" font-size="12" fill="#111827">Branch coverage</text>
  <rect x="{width - 220}" y="80" width="12" height="12" fill="#059669"/><text x="{width - 202}" y="90" font-size="12" fill="#111827">Function coverage</text>
</svg>
"""


def svg_line_count_chart(points: list[dict], width: int = 900, height: int = 380) -> str:
    margin_left = 72
    margin_right = 24
    margin_top = 28
    margin_bottom = 52
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    max_minutes = max(point["elapsed_minutes"] for point in points)
    max_minutes = max(max_minutes, 1.0)
    max_lines = max(max(point["line_total"] for point in points), max(point["line_covered"] for point in points))
    max_lines = max(max_lines, 1)

    def scale_x(minutes: float) -> float:
        return margin_left + (minutes / max_minutes) * plot_w

    def scale_y(count: float) -> float:
        return margin_top + (1.0 - (count / max_lines)) * plot_h

    y_ticks = []
    for idx in range(0, 6):
        tick = max_lines * idx / 5
        y = scale_y(tick)
        y_ticks.append(f'<line x1="{margin_left}" y1="{y:.2f}" x2="{width - margin_right}" y2="{y:.2f}" stroke="#e5e7eb" />')
        y_ticks.append(
            f'<text x="{margin_left - 10}" y="{y + 4:.2f}" font-size="12" text-anchor="end" fill="#374151">{int(tick)}</text>'
        )

    x_ticks = []
    tick_count = min(max(len(points), 2), 8)
    for idx in range(tick_count + 1):
        tick_minutes = max_minutes * idx / tick_count
        x = scale_x(tick_minutes)
        label = f"{tick_minutes:.0f}m" if max_minutes >= 10 else f"{tick_minutes:.1f}m"
        x_ticks.append(f'<line x1="{x:.2f}" y1="{margin_top}" x2="{x:.2f}" y2="{height - margin_bottom}" stroke="#f3f4f6" />')
        x_ticks.append(
            f'<text x="{x:.2f}" y="{height - margin_bottom + 20}" font-size="12" text-anchor="middle" fill="#374151">{label}</text>'
        )

    def polyline(metric_name: str) -> str:
        return " ".join(
            f"{scale_x(point['elapsed_minutes']):.2f},{scale_y(point[metric_name]):.2f}"
            for point in points
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{margin_left}" y="18" font-size="18" font-weight="bold" fill="#111827">Covered lines vs total lines</text>
  <text x="{width - margin_right}" y="18" font-size="12" text-anchor="end" fill="#6b7280">same snapshots, absolute counts</text>
  {''.join(y_ticks)}
  {''.join(x_ticks)}
  <line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#111827" />
  <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#111827" />
  <polyline fill="none" stroke="#f59e0b" stroke-width="3" points="{polyline('line_covered')}" />
  <polyline fill="none" stroke="#10b981" stroke-width="3" points="{polyline('line_total')}" />
  <text x="{width / 2:.2f}" y="{height - 8}" font-size="13" text-anchor="middle" fill="#111827">Elapsed fuzzing time</text>
  <text x="18" y="{height / 2:.2f}" font-size="13" text-anchor="middle" fill="#111827" transform="rotate(-90 18 {height / 2:.2f})">Line count</text>
  <rect x="{width - 215}" y="40" width="12" height="12" fill="#f59e0b"/><text x="{width - 197}" y="50" font-size="12" fill="#111827">Covered lines</text>
  <rect x="{width - 215}" y="60" width="12" height="12" fill="#10b981"/><text x="{width - 197}" y="70" font-size="12" fill="#111827">Total lines</text>
</svg>
"""


def build_report(points: list[dict], stagnant: list[dict], input_path: Path) -> str:
    first = points[0]
    last = points[-1]
    line_gain = last["line_percent"] - first["line_percent"]
    branch_gain = (
        last["branch_percent"] - first["branch_percent"]
        if last["branch_percent"] is not None and first["branch_percent"] is not None
        else None
    )
    function_gain = (
        last["function_percent"] - first["function_percent"]
        if last["function_percent"] is not None and first["function_percent"] is not None
        else None
    )

    report = [
        "# Coverage Timeline Report",
        "",
        "## Overview",
        f"- Source log: `{input_path}`",
        f"- Snapshot count: {len(points)}",
        f"- First snapshot: {first['elapsed_minutes']:.1f} min, line coverage {first['line_percent']:.2f}%",
        f"- Last snapshot: {last['elapsed_minutes']:.1f} min, line coverage {last['line_percent']:.2f}%",
        f"- Line coverage gain: {line_gain:.2f} points",
    ]
    if branch_gain is not None:
        report.append(f"- Branch coverage gain: {branch_gain:.2f} points")
    if function_gain is not None:
        report.append(f"- Function coverage gain: {function_gain:.2f} points")

    report.extend(
        [
            "",
            "## Final Snapshot",
            f"- Lines: {last['line_percent']:.2f}% ({last['line_covered']}/{last['line_total']})",
        ]
    )
    if last["branch_percent"] is not None:
        report.append(
            f"- Branches: {last['branch_percent']:.2f}% ({last['branch_covered']}/{last['branch_total']})"
        )
    if last["function_percent"] is not None:
        report.append(
            f"- Functions: {last['function_percent']:.2f}% ({last['function_covered']}/{last['function_total']})"
        )

    report.extend(["", "## Stagnation Windows"])
    if stagnant:
        for item in stagnant:
            report.append(
                f"- {item['start_seconds'] // 60}m -> {item['end_seconds'] // 60}m: line growth {item['growth']:.4f} points"
            )
    else:
        report.append("- No stagnation windows matched the configured threshold.")

    report.extend(
        [
            "",
            "## Charts",
            "- `coverage_timeline.svg`",
            "- `line_count_timeline.svg`",
        ]
    )
    return "\n".join(report) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to coverage JSONL generated by --coverage-interval.")
    parser.add_argument("--output-dir", required=True, help="Directory for report artifacts.")
    parser.add_argument("--stagnation-window", type=int, default=3, help="Window size for stagnation detection.")
    parser.add_argument("--stagnation-threshold", type=float, default=0.01, help="Max line coverage growth within the window.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    points = build_points(load_jsonl(input_path))
    if not points:
        raise SystemExit(f"No valid coverage snapshots found in {input_path}")

    stagnant = find_stagnation(points, args.stagnation_window, args.stagnation_threshold)
    (output_dir / "coverage_timeline.svg").write_text(svg_coverage_chart(points), encoding="utf-8")
    (output_dir / "line_count_timeline.svg").write_text(svg_line_count_chart(points), encoding="utf-8")
    (output_dir / "report.md").write_text(build_report(points, stagnant, input_path), encoding="utf-8")


if __name__ == "__main__":
    main()
