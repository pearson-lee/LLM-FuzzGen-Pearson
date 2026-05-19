#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def _load_snapshot(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"Failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def _blocker_key(blocker: dict) -> tuple[str, str, str, str, str]:
    return (
        str(blocker.get("blocked_side", "")),
        str(blocker.get("source_file", "")),
        str(blocker.get("branch_line_number", "")),
        str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", ""))),
        str(blocker.get("function_name", "")),
    )


def _index_blockers(blockers: list[dict]) -> dict[tuple[str, str, str, str, str], dict]:
    return {_blocker_key(blocker): blocker for blocker in blockers}


def _format_blocker(blocker: dict) -> dict:
    return {
        "source_file": blocker.get("source_file"),
        "function_name": blocker.get("function_name"),
        "branch_line_number": blocker.get("branch_line_number"),
        "blocked_side_line_number": blocker.get(
            "blocked_side_line_number", blocker.get("blocked_side_line_numder")
        ),
        "best_target": blocker.get("best_target"),
        "project_branch_hit_count": blocker.get("project_branch_hit_count"),
        "project_blocked_hit_count": blocker.get("project_blocked_hit_count"),
        "project_branch_reached_target_count": blocker.get("project_branch_reached_target_count"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two real blocker snapshot JSON files.")
    parser.add_argument("before", type=Path, help="Earlier snapshot JSON path.")
    parser.add_argument("after", type=Path, help="Later snapshot JSON path.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path for the comparison result.",
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=20,
        help="How many example blockers to include per category in the JSON summary. Default 20.",
    )
    args = parser.parse_args()

    before_snapshot = _load_snapshot(args.before)
    after_snapshot = _load_snapshot(args.after)

    before_blockers = before_snapshot.get("blockers", [])
    after_blockers = after_snapshot.get("blockers", [])
    if not isinstance(before_blockers, list) or not isinstance(after_blockers, list):
        raise SystemExit("Both input files must contain a top-level 'blockers' list.")

    before_index = _index_blockers(before_blockers)
    after_index = _index_blockers(after_blockers)

    before_keys = set(before_index.keys())
    after_keys = set(after_index.keys())

    removed_keys = sorted(before_keys - after_keys)
    added_keys = sorted(after_keys - before_keys)
    persisted_keys = sorted(before_keys & after_keys)

    max_examples = max(0, args.max_examples)
    result = {
        "before_file": str(args.before),
        "after_file": str(args.after),
        "before_project": before_snapshot.get("project"),
        "after_project": after_snapshot.get("project"),
        "before_selection_stage": before_snapshot.get("selection_stage"),
        "after_selection_stage": after_snapshot.get("selection_stage"),
        "before_aggregated_count": before_snapshot.get("aggregated_count"),
        "after_aggregated_count": after_snapshot.get("aggregated_count"),
        "before_filtered_count": len(before_blockers),
        "after_filtered_count": len(after_blockers),
        "aggregated_count_delta": (
            None
            if before_snapshot.get("aggregated_count") is None or after_snapshot.get("aggregated_count") is None
            else int(after_snapshot.get("aggregated_count")) - int(before_snapshot.get("aggregated_count"))
        ),
        "filtered_count_delta": len(after_blockers) - len(before_blockers),
        "removed_count": len(removed_keys),
        "added_count": len(added_keys),
        "persisted_count": len(persisted_keys),
        "solved_count": len(removed_keys),
        "solved_rate": (len(removed_keys) / len(before_blockers)) if before_blockers else 0.0,
        "removed_blockers": [_format_blocker(before_index[key]) for key in removed_keys[:max_examples]],
        "added_blockers": [_format_blocker(after_index[key]) for key in added_keys[:max_examples]],
        "persisted_blockers": [_format_blocker(after_index[key]) for key in persisted_keys[:max_examples]],
    }

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Before filtered blockers: {len(before_blockers)}")
    print(f"After filtered blockers: {len(after_blockers)}")
    print(f"Filtered delta: {len(after_blockers) - len(before_blockers)}")
    print(f"Removed blockers: {len(removed_keys)}")
    print(f"Added blockers: {len(added_keys)}")
    print(f"Persisted blockers: {len(persisted_keys)}")
    print(f"Solved blockers: {len(removed_keys)}")
    print(f"Solved rate: {result['solved_rate']:.4f}")
    if args.output is not None:
        print(f"Comparison result written to {args.output}")
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        print()


if __name__ == "__main__":
    main()
