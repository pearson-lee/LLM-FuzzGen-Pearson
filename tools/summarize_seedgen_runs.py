#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = REPO_ROOT / "blocker_process" / "dependent" / "generated_generators"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def parse_key_value_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def summarize_iteration(iter_dir: Path) -> dict[str, Any]:
    evaluation = parse_key_value_file(iter_dir / "evaluation.txt")
    staging = load_json(iter_dir / "staging_metadata.json")
    parsed = load_json(iter_dir / "parsed.json")
    materialized_dir = iter_dir / "materialized_by_generator"
    materialized_seed_count = len([p for p in materialized_dir.rglob("*") if p.is_file()]) if materialized_dir.exists() else 0

    return {
        "iteration": iter_dir.name,
        "status": evaluation.get("Iteration status", "unknown"),
        "diagnosis": evaluation.get("Diagnosis", "unknown"),
        "symcc_candidate": evaluation.get("SymCC candidate", "False") == "True",
        "generated_seed_count": materialized_seed_count,
        "added_seed_count": int(staging.get("added_seed_count", 0) or 0),
        "skipped_duplicate_seed_count": int(staging.get("skipped_duplicate_seed_count", 0) or 0),
        "branch_delta": evaluation.get("branch_line hit count delta", "N/A"),
        "blocked_side_delta": evaluation.get("blocked_side_line hit count delta", "N/A"),
        "generator_filename": parsed.get("generator_filename", ""),
    }


def infer_final_status(iterations: list[dict[str, Any]]) -> str:
    statuses = [item.get("status") for item in iterations]
    if "solved" in statuses:
        return "solved"
    if "progress" in statuses:
        return "progress"
    if "stalled_at_branch" in statuses:
        return "stalled_at_branch"
    if any(status in {"invalid_generator", "evaluation_failed"} for status in statuses):
        return "failed"
    return "no_progress" if statuses else "empty"


def summarize_run(run_dir: Path) -> dict[str, Any]:
    iterations = [summarize_iteration(path) for path in sorted(run_dir.glob("iter_*")) if path.is_dir()]
    status_counts = Counter(str(item.get("status", "unknown")) for item in iterations)
    diagnosis_counts = Counter(str(item.get("diagnosis", "unknown")) for item in iterations)
    symcc_candidates = [item for item in iterations if item.get("symcc_candidate")]
    format_info = {}
    for parsed_path in sorted(run_dir.glob("iter_*/prompt.txt")):
        text = parsed_path.read_text(encoding="utf-8", errors="replace")
        marker = "- Family: `"
        if marker in text:
            family = text.split(marker, 1)[1].split("`", 1)[0]
            format_info["format_family"] = family
            break

    return {
        "run_dir": str(run_dir),
        "run_name": run_dir.name,
        "final_status": infer_final_status(iterations),
        "iterations_run": len(iterations),
        "status_counts": dict(status_counts),
        "diagnosis_counts": dict(diagnosis_counts),
        "symcc_candidate_iteration_count": len(symcc_candidates),
        "format_info": format_info,
        "best_iteration": next((item for item in iterations if item.get("status") == "solved"), None)
        or next((item for item in iterations if item.get("status") == "progress"), None)
        or (iterations[-1] if iterations else None),
        "iterations": iterations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize LLM blocker seed generator run artifacts.")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help=f"Generated generator root. Default: {DEFAULT_ROOT}")
    parser.add_argument("--run-dir", type=Path, default=None, help="Summarize one run directory instead of all runs.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a compact text table.")
    args = parser.parse_args()

    run_dirs = [args.run_dir] if args.run_dir else [path for path in sorted(args.root.iterdir()) if path.is_dir()]
    summaries = [summarize_run(path) for path in run_dirs]

    if args.json:
        print(json.dumps({"runs": summaries}, ensure_ascii=False, indent=2))
        return

    print("run_name\tfinal_status\titerations\tsymcc_candidates\tstatus_counts\tdiagnosis_counts\tformat")
    for summary in summaries:
        print(
            "\t".join(
                [
                    summary["run_name"],
                    summary["final_status"],
                    str(summary["iterations_run"]),
                    str(summary["symcc_candidate_iteration_count"]),
                    json.dumps(summary["status_counts"], sort_keys=True),
                    json.dumps(summary["diagnosis_counts"], sort_keys=True),
                    summary.get("format_info", {}).get("format_family", "unknown"),
                ]
            )
        )


if __name__ == "__main__":
    main()
