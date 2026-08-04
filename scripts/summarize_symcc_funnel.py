#!/usr/bin/env python3
"""Summarise where the LLM->SymCC blocker pipeline loses cases, per archived campaign.

Reading the solve rate alone ("0 of 66") says nothing about what to fix. This tool splits
the pipeline into the two SymCC attempts each blocker actually gets and reports where each
case died, so a failure caused by a missing include path is never mistaken for a failure
of symbolic execution.

    Stage A  symcc_probe_original_target   -- SymCC on the project's own fuzz target
    Stage B  symcc_generated_harness       -- SymCC on a harness the LLM wrote for the blocker

Stage B only runs when Stage A fails, so the two stages are reported separately rather
than summed: a blocker appearing in both is one blocker given two chances, not two cases.

Usage:
    summarize_symcc_funnel.py
    summarize_symcc_funnel.py --experiments experiments/20260714_035206_zlib ...
    summarize_symcc_funnel.py --cases
    summarize_symcc_funnel.py --csv out.csv
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Failure kinds that occur before SymCC ever explores. Keeping this explicit -- rather than
# inferring "anything that isn't coverage_no_blocked_side" -- means a new failure kind shows
# up as unclassified instead of being silently counted as a solver limitation.
PRE_SYMCC_FAILURES = {
    "harness_seed_incompatible": "LLM harness did not reproduce the branch with the one seed tried",
    "harness_fidelity_unknown": "branch line could not be located in the coverage report",
    "build_context_missing_header": "SymCC harness failed to compile",
    "missing_link_library": "link failed",
    "missing_link_symbol": "link failed",
    "build_failure": "compile or link failed",
    "native_archive_prepare_failed": "archive preparation failed",
}


def experiment_dirs(explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(p) for p in explicit]
    root = REPO_ROOT / "experiments"
    return sorted(p for p in root.glob("*") if p.is_dir() and (p / "blockers").is_dir())


def _exploration(node: dict | None) -> dict:
    """Normalise an exploration record; absent means SymCC never explored."""
    exploration = (node or {}).get("exploration") or {}
    counts = exploration.get("outcome_counts") or {}
    budgets = exploration.get("budgets") or {}
    deadline = budgets.get("deadline_seconds") or 0
    elapsed = exploration.get("elapsed_seconds") or 0
    return {
        "explored": bool(exploration),
        "stop_reason": exploration.get("stop_reason") or "NO_EXPLORATION",
        "outputs": exploration.get("outputs_discovered") or 0,
        "evaluations": exploration.get("candidate_evaluations") or 0,
        "branch": counts.get("branch") or 0,
        "blocked_side": counts.get("blocked_side") or 0,
        "wall_pct": (elapsed / deadline * 100) if deadline else 0.0,
    }


def collect_stage_a(experiment: Path) -> list[dict]:
    """Stage A: one symcc_probe_summary.json per blocker that reached the probe."""
    rows = []
    for path in sorted(experiment.glob("blockers/*/symbolic_run/*/symcc_probe_summary.json")):
        try:
            summary = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        symcc = summary.get("symcc") or {}
        rows.append(
            {
                "project": experiment.name.split("_")[-1],
                "blocker": path.parts[path.parts.index("blockers") + 1],
                "failure_kind": summary.get("failure_kind") or symcc.get("failure_kind") or "",
                "linked": summary.get("linked_archive_kind"),
                **_exploration(symcc),
            }
        )
    return rows


def collect_stage_b(experiment: Path) -> list[dict]:
    """Stage B: one metadata.json per LLM-generated SymCC harness attempt."""
    rows = []
    for path in sorted(experiment.glob("symcc/*/metadata.json")):
        try:
            meta = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        stage = meta.get("symcc_harness_stage") or {}
        fidelity = stage.get("harness_fidelity") or {}
        rows.append(
            {
                "project": experiment.name.split("_")[-1],
                "blocker": f"{meta.get('function_name')}_{meta.get('branch_line_number')}",
                "reason": meta.get("reason") or "",
                "used_symcc": bool(stage.get("used_symcc")),
                "linked": stage.get("linked_archive_kind"),
                "fidelity_status": fidelity.get("status"),
                "fidelity_attempts": fidelity.get("attempt_count"),
                **_exploration(stage.get("symcc")),
            }
        )
    return rows


def _print_counter(title: str, counter: collections.Counter, total: int) -> None:
    print(f"\n{title}")
    for key, count in counter.most_common():
        share = f"{count / total * 100:5.1f}%" if total else "    -"
        print(f"  {count:4d}  {share}  {key}")


def report_stage(title: str, rows: list[dict], reason_key: str) -> None:
    if not rows:
        print(f"\n=== {title}: no records found")
        return
    total = len(rows)
    print(f"\n\n=== {title} ({total} attempts)")

    _print_counter(f"-- {reason_key}", collections.Counter(r.get(reason_key, "") for r in rows), total)
    _print_counter("-- stop_reason", collections.Counter(r["stop_reason"] for r in rows), total)

    explored = [r for r in rows if r["explored"]]
    outputs = sum(r["outputs"] for r in rows)
    evaluated = sum(r["evaluations"] for r in rows)
    discarded = outputs - evaluated
    print("\n-- exploration totals")
    print(f"  attempts that explored at all : {len(explored)} / {total}")
    print(f"  attempts with zero outputs    : {sum(1 for r in rows if r['outputs'] == 0)}")
    print(f"  candidates discovered         : {outputs}")
    print(f"  candidates evaluated          : {evaluated}")
    if outputs:
        print(f"  candidates never evaluated    : {discarded} ({discarded / outputs * 100:.1f}%)")
    print(f"  attempts reaching the branch  : {sum(1 for r in rows if r['branch'] > 0)}")
    print(f"  attempts reaching blocked side: {sum(1 for r in rows if r['blocked_side'] > 0)}")

    pre = sum(1 for r in rows if r.get(reason_key) in PRE_SYMCC_FAILURES)
    if pre:
        print(f"\n-- failures occurring before symbolic execution: {pre} / {total} "
              f"({pre / total * 100:.1f}%)")
        for kind, description in PRE_SYMCC_FAILURES.items():
            count = sum(1 for r in rows if r.get(reason_key) == kind)
            if count:
                print(f"  {count:4d}  {kind} -- {description}")


def print_cases(stage_a: list[dict], stage_b: list[dict]) -> None:
    for title, rows in (("Stage A (original target)", stage_a), ("Stage B (generated harness)", stage_b)):
        print(f"\n\n=== {title}: per case")
        header = (
            f"{'project':8} {'blocker':42} {'stop':30} {'out':>6} {'eval':>5} "
            f"{'br':>5} {'BS':>3} {'%wall':>6}"
        )
        print(header)
        print("-" * len(header))
        for row in sorted(rows, key=lambda r: (r["project"], r["blocker"])):
            print(
                f"{row['project']:8} {row['blocker'][:42]:42} {row['stop_reason'][:30]:30} "
                f"{row['outputs']:>6} {row['evaluations']:>5} {row['branch']:>5} "
                f"{row['blocked_side']:>3} {row['wall_pct']:>5.1f}%"
            )


def write_csv(path: Path, stage_a: list[dict], stage_b: list[dict]) -> None:
    fields = [
        "stage", "project", "blocker", "outcome", "linked", "stop_reason",
        "outputs", "evaluations", "branch", "blocked_side", "wall_pct",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for stage, rows, key in (("A", stage_a, "failure_kind"), ("B", stage_b, "reason")):
            for row in rows:
                writer.writerow(
                    {
                        "stage": stage,
                        "project": row["project"],
                        "blocker": row["blocker"],
                        "outcome": row.get(key, ""),
                        "linked": row.get("linked"),
                        "stop_reason": row["stop_reason"],
                        "outputs": row["outputs"],
                        "evaluations": row["evaluations"],
                        "branch": row["branch"],
                        "blocked_side": row["blocked_side"],
                        "wall_pct": round(row["wall_pct"], 1),
                    }
                )
    print(f"\nwrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--experiments", nargs="*", default=[], help="Experiment dirs. Default: all.")
    parser.add_argument("--cases", action="store_true", help="Also print the per-case table.")
    parser.add_argument("--csv", default=None, help="Write a machine-readable row per attempt.")
    args = parser.parse_args()

    stage_a: list[dict] = []
    stage_b: list[dict] = []
    experiments = experiment_dirs(args.experiments)
    for experiment in experiments:
        stage_a.extend(collect_stage_a(experiment))
        stage_b.extend(collect_stage_b(experiment))

    print(f"experiments: {len(experiments)}")
    for experiment in experiments:
        print(f"  {experiment}")

    report_stage("Stage A -- SymCC on the project's own fuzz target", stage_a, "failure_kind")
    report_stage("Stage B -- SymCC on the LLM-generated harness", stage_b, "reason")

    solved = sum(1 for r in stage_a + stage_b if r["blocked_side"] > 0)
    print(f"\n\n=== blockers solved across both stages: {solved}")

    if args.cases:
        print_cases(stage_a, stage_b)
    if args.csv:
        write_csv(Path(args.csv), stage_a, stage_b)


if __name__ == "__main__":
    main()
