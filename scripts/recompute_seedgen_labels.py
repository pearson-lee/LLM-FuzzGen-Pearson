#!/usr/bin/env python3
"""Re-derive archived seed-generator iteration labels with the corrected branch attribution.

``classify_iteration_status`` used to read "did we reach the branch?" off the post-merge
corpus. That corpus is the triggering seed plus the generated seeds, so once the trigger
reached the branch -- the normal case for an input-dependent blocker -- the answer was yes
regardless of how bad the generated seeds were. ``stalled_at_branch`` became unfalsifiable,
``no_branch_signal`` became unreachable, and the repair prompt kept telling the LLM to tune
predicate fields for a function its seeds never entered.

Every archived iteration already stores the correct per-family measurement, so the corrected
labels can be recomputed from the archive alone -- no seed regeneration, no coverage replay,
no LLM quota. That matters because quota exhaustion is itself one of the failure modes under
study, so any conclusion that required re-running would be unobtainable.

Usage:
    recompute_seedgen_labels.py
    recompute_seedgen_labels.py --experiments experiments/20260714_035206_zlib
    recompute_seedgen_labels.py --changed-only
    recompute_seedgen_labels.py --csv relabelled.csv
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.dependent.input_dependent_seed_generator import (  # noqa: E402
    classify_iteration_status,
    compute_family_signal_score,
    diagnose_iteration,
)

_FIELD = {
    "status": re.compile(r"^Iteration status:\s*(.+)$", re.M),
    "diagnosis": re.compile(r"^Diagnosis:\s*(.+)$", re.M),
    "symcc_candidate": re.compile(r"^SymCC candidate:\s*(\w+)$", re.M),
    "family_progress": re.compile(r"^Family progress this iteration:\s*(\w+)$", re.M),
    "validation": re.compile(r"^Generator validation:\s*(\w+)$", re.M),
    "seed_count": re.compile(r"^Materialized seed count:\s*(\d+)$", re.M),
    "added": re.compile(r"^Added seed count this iteration:\s*(\d+)$", re.M),
    "skipped": re.compile(r"^Skipped duplicate seed count:\s*(\d+)$", re.M),
    "baseline_branch": re.compile(r"^Baseline branch_line hit count:\s*(\d+)$", re.M),
    "baseline_blocked": re.compile(r"^Baseline blocked_side_line hit count:\s*(\d+)$", re.M),
    "post_branch": re.compile(r"^Post-merge branch_line hit count:\s*(\d+)$", re.M),
    "post_blocked": re.compile(r"^Post-merge blocked_side_line hit count:\s*(\d+)$", re.M),
    "branch_delta": re.compile(r"^branch_line hit count delta:\s*(-?\d+)$", re.M),
    "blocked_delta": re.compile(r"^blocked_side_line hit count delta:\s*(-?\d+)$", re.M),
    "branch_after": re.compile(r"^branch_line reached after merge:\s*(\w+)$", re.M),
    "blocked_after": re.compile(r"^blocked_side_line reached after merge:\s*(\w+)$", re.M),
    "newly_blocked": re.compile(r"^Newly reached blocked_side_line this iteration:\s*(\w+)$", re.M),
}


def _get(text: str, key: str, default: str = "") -> str:
    match = _FIELD[key].search(text)
    return match.group(1).strip() if match else default


def _int(text: str, key: str) -> int:
    raw = _get(text, key, "0")
    try:
        return int(raw)
    except ValueError:
        return 0


def _bool(text: str, key: str) -> bool:
    return _get(text, key, "False").lower() == "true"


def replay_iteration(iteration_dir: Path) -> dict | None:
    """Rebuild one iteration's classifier inputs from its archived artifacts."""
    evaluation = iteration_dir / "evaluation.txt"
    family_summary_path = iteration_dir / "family_summary.json"
    if not evaluation.is_file() or not family_summary_path.is_file():
        return None

    text = evaluation.read_text(encoding="utf-8", errors="replace")
    try:
        family_summary = json.loads(family_summary_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None

    representative_results: list[dict] = []
    rep_path = iteration_dir / "representative_results.json"
    if rep_path.is_file():
        try:
            representative_results = json.loads(rep_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            representative_results = []

    baseline_evaluation = {
        "success": True,
        "branch_hit_count": _int(text, "baseline_branch"),
        "branch_line_reached": _int(text, "baseline_branch") > 0,
        "blocked_side_hit_count": _int(text, "baseline_blocked"),
        "blocked_side_line_reached": _int(text, "baseline_blocked") > 0,
    }
    post_merge_evaluation = {
        "success": True,
        "branch_hit_count": _int(text, "post_branch"),
        "branch_line_reached": _bool(text, "branch_after"),
        "blocked_side_hit_count": _int(text, "post_blocked"),
        "blocked_side_line_reached": _bool(text, "blocked_after"),
    }
    coverage_delta = {
        "branch_hit_count_delta": _int(text, "branch_delta"),
        "blocked_side_hit_count_delta": _int(text, "blocked_delta"),
        "newly_reached_blocked_side_line": _bool(text, "newly_blocked"),
    }

    # family_progress is a comparison against the previous iteration's score, which the
    # archive records as a verdict rather than a number. Reconstruct the score that
    # reproduces the recorded verdict so the replay follows the same branch.
    score = compute_family_signal_score(family_summary)
    previous_score = score - 1 if _bool(text, "family_progress") else score

    status, reason = classify_iteration_status(
        validation_ok=_get(text, "validation") == "success",
        generated_seed_count=_int(text, "seed_count"),
        baseline_evaluation=baseline_evaluation,
        post_merge_evaluation=post_merge_evaluation,
        coverage_delta=coverage_delta,
        representative_results=representative_results,
        family_summary=family_summary,
        previous_family_signal_score=previous_score,
    )
    diagnosis = diagnose_iteration(
        iteration_status=status,
        validation_ok=_get(text, "validation") == "success",
        generated_seed_count=_int(text, "seed_count"),
        staging_metadata={
            "added_seed_count": _int(text, "added"),
            "skipped_duplicate_seed_count": _int(text, "skipped"),
        },
        baseline_evaluation=baseline_evaluation,
        post_merge_evaluation=post_merge_evaluation,
        coverage_delta=coverage_delta,
        family_summary=family_summary,
    )

    parts = iteration_dir.parts
    blocker = parts[parts.index("blockers") + 1]
    experiment = parts[parts.index("experiments") + 1]
    return {
        "experiment": experiment,
        "project": experiment.split("_")[-1],
        "blocker": blocker,
        "iteration": iteration_dir.name,
        "old_status": _get(text, "status"),
        "new_status": status,
        "new_reason": reason,
        "old_diagnosis": _get(text, "diagnosis"),
        "new_diagnosis": diagnosis["diagnosis_code"],
        "old_symcc_candidate": _bool(text, "symcc_candidate"),
        "new_symcc_candidate": bool(diagnosis["symcc_candidate"]),
        "generated_reached_branch": bool(family_summary.get("generated_family_reached_branch")),
        "baseline_branch": _int(text, "baseline_branch"),
        "post_branch": _int(text, "post_branch"),
    }


def collect(experiments: list[Path]) -> list[dict]:
    rows = []
    for experiment in experiments:
        for iteration_dir in sorted(experiment.glob("blockers/*/generator/*/iter_*")):
            row = replay_iteration(iteration_dir)
            if row is not None:
                rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--experiments", nargs="*", default=[], help="Experiment dirs. Default: all.")
    parser.add_argument("--changed-only", action="store_true", help="Only print relabelled iterations.")
    parser.add_argument("--csv", default=None, help="Write every row to CSV.")
    args = parser.parse_args()

    experiments = (
        [Path(p) for p in args.experiments]
        if args.experiments
        else sorted(p for p in (REPO_ROOT / "experiments").glob("*") if (p / "blockers").is_dir())
    )
    rows = collect(experiments)
    if not rows:
        print("no archived iterations found")
        return

    changed = [r for r in rows if r["old_status"] != r["new_status"] or r["old_diagnosis"] != r["new_diagnosis"]]

    header = f"{'project':8} {'blocker':40} {'iter':8} {'old status':22} -> {'new status':20} {'symcc':>12}"
    print(header)
    print("-" * len(header))
    for row in changed if args.changed_only else rows:
        symcc = f"{row['old_symcc_candidate']}->{row['new_symcc_candidate']}"
        print(
            f"{row['project']:8} {row['blocker'][:40]:40} {row['iteration']:8} "
            f"{row['old_status'][:22]:22} -> {row['new_status'][:20]:20} {symcc:>12}"
        )

    print(f"\niterations replayed : {len(rows)}")
    print(f"iterations relabelled: {len(changed)}")
    print(f"blockers affected    : {len({(r['project'], r['blocker']) for r in changed})}")

    print("\n-- status transitions --")
    for (old, new), count in collections.Counter(
        (r["old_status"], r["new_status"]) for r in changed
    ).most_common():
        print(f"  {count:4d}  {old} -> {new}")

    print("\n-- diagnosis transitions --")
    for (old, new), count in collections.Counter(
        (r["old_diagnosis"], r["new_diagnosis"]) for r in changed
    ).most_common():
        print(f"  {count:4d}  {old} -> {new}")

    flipped = [r for r in rows if r["old_symcc_candidate"] and not r["new_symcc_candidate"]]
    print(f"\nsymcc_candidate True -> False: {len(flipped)} iteration(s)")

    if args.csv:
        with Path(args.csv).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote {args.csv}")


if __name__ == "__main__":
    main()
