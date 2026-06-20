#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.global_blocker_selector import (
    _extract_range,
    _fetch_file_lines,
    _safe_int,
    rescore_existing_blockers,
)


def _key(blocker: dict[str, Any]) -> str:
    return ":".join(
        (
            str(blocker.get("function_name", "")),
            str(blocker.get("branch_line_number", "")),
            str(blocker.get("blocked_side", "")),
        )
    )


def _rank_map(blockers: list[dict[str, Any]]) -> dict[str, int]:
    return {_key(blocker): rank for rank, blocker in enumerate(blockers, 1)}


def _discover_source_root(project_name: str) -> Path | None:
    direct = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out" / project_name / "source_code"
    if direct.is_dir():
        return direct

    cache_root = (
        REPO_ROOT
        / "external"
        / "oss-fuzz"
        / "build"
        / "artifact_cache"
        / project_name
    )
    candidates = sorted(cache_root.glob("**/source_code"), key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _context(
    project_name: str,
    blocker: dict[str, Any],
    source_root: Path | None,
) -> tuple[str, str]:
    lines = _fetch_file_lines(
        project_name,
        str(blocker.get("source_file", "")),
        source_root=str(source_root) if source_root else None,
    )
    if not lines:
        return "SOURCE_UNAVAILABLE", "SOURCE_UNAVAILABLE"
    branch_line = _safe_int(blocker.get("branch_line_number", 0), 0)
    blocked_line = _safe_int(blocker.get("blocked_side_line_number", 0), 0)
    return (
        _extract_range(lines, branch_line, radius=4),
        _extract_range(lines, blocked_line, radius=4),
    )


def _write_audit_csv(
    path: Path,
    project_name: str,
    old_blockers: list[dict[str, Any]],
    new_blockers: list[dict[str, Any]],
    source_root: Path | None,
    top_k: int,
) -> None:
    old_ranks = _rank_map(old_blockers)
    new_ranks = _rank_map(new_blockers)
    by_key = {_key(blocker): blocker for blocker in old_blockers + new_blockers}
    union_keys = set(list(old_ranks)[:top_k]) | set(list(new_ranks)[:top_k])
    ordered_keys = sorted(
        union_keys,
        key=lambda key: (min(old_ranks.get(key, 10**9), new_ranks.get(key, 10**9)), key),
    )

    fieldnames = [
        "blocker_key",
        "function_name",
        "branch_line_number",
        "blocked_side_line_number",
        "source_file",
        "old_rank",
        "new_rank",
        "old_score",
        "new_score",
        "reach_confidence",
        "coverage_benefit",
        "unlock_ratio",
        "solvability_score",
        "solvability_reason",
        "evidence_grade",
        "evidence_pattern",
        "evidence_callee",
        "evidence_variable",
        "resource_terms",
        "project_branch_hit_count",
        "blocked_unique_not_covered_complexity",
        "blocked_unique_reachable_complexity",
        "blocked_unique_functions",
        "branch_context",
        "blocked_side_context",
        "manual_label",
        "manual_reason",
        "reviewer",
    ]
    old_by_key = {_key(blocker): blocker for blocker in old_blockers}

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for key in ordered_keys:
            blocker = by_key[key]
            old = old_by_key.get(key, {})
            evidence = blocker.get("solvability_evidence") or {}
            branch_context, blocked_context = _context(
                project_name,
                blocker,
                source_root,
            )
            writer.writerow(
                {
                    "blocker_key": key,
                    "function_name": blocker.get("function_name", ""),
                    "branch_line_number": blocker.get("branch_line_number", ""),
                    "blocked_side_line_number": blocker.get("blocked_side_line_number", ""),
                    "source_file": blocker.get("source_file", ""),
                    "old_rank": old_ranks.get(key, ""),
                    "new_rank": new_ranks.get(key, ""),
                    "old_score": old.get("score", ""),
                    "new_score": blocker.get("score", ""),
                    "reach_confidence": blocker.get("reach_confidence", ""),
                    "coverage_benefit": blocker.get("coverage_benefit", ""),
                    "unlock_ratio": blocker.get("unlock_ratio", ""),
                    "solvability_score": blocker.get("solvability_score", ""),
                    "solvability_reason": blocker.get("solvability_reason", ""),
                    "evidence_grade": evidence.get("grade", "not_evaluated"),
                    "evidence_pattern": evidence.get("pattern", ""),
                    "evidence_callee": evidence.get("callee", ""),
                    "evidence_variable": evidence.get("checked_variable", ""),
                    "resource_terms": " | ".join(evidence.get("resource_terms", [])),
                    "project_branch_hit_count": blocker.get("project_branch_hit_count", 0),
                    "blocked_unique_not_covered_complexity": blocker.get(
                        "blocked_unique_not_covered_complexity", 0
                    ),
                    "blocked_unique_reachable_complexity": blocker.get(
                        "blocked_unique_reachable_complexity", 0
                    ),
                    "blocked_unique_functions": " | ".join(
                        blocker.get("blocked_unique_functions", [])
                    ),
                    "branch_context": branch_context,
                    "blocked_side_context": blocked_context,
                    "manual_label": "",
                    "manual_reason": "",
                    "reviewer": "",
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay an archived blocker-selector snapshot with the new deterministic score."
    )
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--source-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--top-k", type=int, default=20)
    parser.add_argument("--thresholds", type=int, nargs="+", default=[10_000, 100_000])
    parser.add_argument("--production-threshold", type=int, default=100_000)
    parser.add_argument("--known-success", action="append", default=[])
    args = parser.parse_args()

    payload = json.loads(args.snapshot.read_text(encoding="utf-8"))
    old_blockers = payload.get("blockers") if isinstance(payload, dict) else payload
    if not isinstance(old_blockers, list):
        raise SystemExit("snapshot must contain a blocker list or a top-level 'blockers' list")

    source_root = args.source_root or _discover_source_root(args.project_name)
    output_dir = args.output_dir or (
        REPO_ROOT / "TODO_MD" / "blocker_selector_replay" / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    reports: dict[str, Any] = {
        "snapshot": str(args.snapshot),
        "project_name": args.project_name,
        "source_root": str(source_root) if source_root else None,
        "top_k": args.top_k,
        "thresholds": {},
    }
    production_ranking: list[dict[str, Any]] | None = None
    old_ranks = _rank_map(old_blockers)

    thresholds = list(dict.fromkeys(args.thresholds + [args.production_threshold]))
    for threshold in thresholds:
        rescored = rescore_existing_blockers(
            old_blockers,
            project_name=args.project_name,
            source_root=str(source_root) if source_root else None,
            hit_saturation_threshold=threshold,
        )
        ranks = _rank_map(rescored)
        strong_count = sum(
            1
            for blocker in rescored[: args.top_k]
            if (blocker.get("solvability_evidence") or {}).get("grade") == "strong"
        )
        reports["thresholds"][str(threshold)] = {
            "top_k_strong_evidence_count": strong_count,
            "known_success_ranks": {
                key: {"old_rank": old_ranks.get(key), "new_rank": ranks.get(key)}
                for key in args.known_success
            },
            "top_k": [
                {
                    "rank": rank,
                    "blocker_key": _key(blocker),
                    "score": blocker.get("score"),
                    "reach_confidence": blocker.get("reach_confidence"),
                    "coverage_benefit": blocker.get("coverage_benefit"),
                    "solvability_score": blocker.get("solvability_score"),
                    "evidence_grade": (blocker.get("solvability_evidence") or {}).get("grade"),
                }
                for rank, blocker in enumerate(rescored[: args.top_k], 1)
            ],
        }
        if threshold == args.production_threshold:
            production_ranking = rescored

    assert production_ranking is not None
    (output_dir / "replay_report.json").write_text(
        json.dumps(reports, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (output_dir / "new_ranking.json").write_text(
        json.dumps(production_ranking, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_audit_csv(
        output_dir / "manual_audit.csv",
        args.project_name,
        old_blockers,
        production_ranking,
        source_root,
        args.top_k,
    )

    print(f"Replay report: {output_dir / 'replay_report.json'}")
    print(f"New ranking: {output_dir / 'new_ranking.json'}")
    print(f"Manual audit: {output_dir / 'manual_audit.csv'}")


if __name__ == "__main__":
    main()
