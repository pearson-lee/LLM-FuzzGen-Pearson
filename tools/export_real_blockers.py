#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.coverage_utils import get_line_execution_count
from blocker_process.global_blocker_selector import aggregate_blockers
from external.oss_fuzz import OSSFuzz


oss_fuzz = OSSFuzz()


def _default_blocker_json_candidates(project_name: str) -> list[Path]:
    build_out = oss_fuzz.build_out_dir / project_name
    return [
        build_out / "report" / "linux" / "branch-blockers.json",
        build_out / "inspector" / "branch-blockers.json",
        Path("process_blocker") / "branch-blockers.json",
        Path("branch-blockers.json"),
    ]


def _resolve_blocker_json_path(project_name: str, explicit_path: Path | None) -> Path | None:
    candidates = [explicit_path] if explicit_path else _default_blocker_json_candidates(project_name)
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    return None


def _normalize_hitcount(raw: str) -> int:
    text = str(raw or "").strip()
    if not text or text == "0":
        return 0

    suffix = text[-1]
    multiplier = {"k": 1_000, "M": 1_000_000, "G": 1_000_000_000}.get(suffix, 1)
    numeric = text[:-1] if multiplier != 1 else text
    try:
        return int(float(numeric) * multiplier)
    except ValueError:
        return 0


def _read_branch_blocker_targets(blocker_json_path: Path) -> list[str]:
    try:
        data = json.loads(blocker_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, dict):
        return []
    return sorted(str(target_name) for target_name in data.keys())


def _expected_blocker_coverage_files(project_name: str, blocker_targets: list[str]) -> list[Path]:
    reports_dir = oss_fuzz.build_out_dir / project_name / "textcov_reports"
    expected = [
        reports_dir / "project.linecovreport",
        reports_dir / "summary_exclude_target.json",
    ]
    expected.extend(reports_dir / f"{target_name}.linecovreport" for target_name in blocker_targets)
    return expected


def _read_existing_project_linecov_report(project_name: str) -> str:
    report_path = oss_fuzz.build_out_dir / project_name / "textcov_reports" / "project.linecovreport"
    if report_path.exists():
        return report_path.read_text(encoding="utf-8")
    return ""


def _load_project_target_reports(project_name: str) -> dict[str, str]:
    reports_dir = oss_fuzz.build_out_dir / project_name / "textcov_reports"
    if not reports_dir.is_dir():
        return {}

    reports: dict[str, str] = {}
    for report_path in sorted(reports_dir.glob("*.linecovreport")):
        if report_path.stem == "project":
            continue
        reports[report_path.stem] = report_path.read_text(encoding="utf-8")
    return reports


def _load_blocker_coverage_context(
    project_name: str,
    blocker_json_path: Path,
    repair_missing: bool,
) -> tuple[str, dict[str, str]] | None:
    blocker_targets = _read_branch_blocker_targets(blocker_json_path)
    expected_files = _expected_blocker_coverage_files(project_name, blocker_targets)
    missing_files = [path for path in expected_files if not path.exists()]

    if missing_files and repair_missing:
        oss_fuzz.coverage(project_name)
        missing_files = [path for path in expected_files if not path.exists()]

    if missing_files:
        return None

    project_report = _read_existing_project_linecov_report(project_name)
    target_reports = _load_project_target_reports(project_name)
    if not project_report:
        return None

    available_targets = {target_name for target_name in blocker_targets if target_name in target_reports}
    if len(available_targets) != len(blocker_targets):
        return None

    return project_report, target_reports


def _filter_real_blockers(
    blockers: list[dict],
    project_report: str,
    target_reports: dict[str, str],
) -> list[dict]:
    filtered: list[dict] = []
    for blocker in blockers:
        branch_line = int(str(blocker.get("branch_line_number", "0")) or 0)
        blocked_side_line = int(
            str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "0"))) or 0
        )
        function_name = blocker.get("function_name")
        project_branch_hit_count = _normalize_hitcount(
            get_line_execution_count(project_report, branch_line, function_name=function_name)
        )
        project_blocked_hit_count = _normalize_hitcount(
            get_line_execution_count(project_report, blocked_side_line, function_name=function_name)
        )

        if project_branch_hit_count <= 0 or project_blocked_hit_count > 0:
            continue

        refined = dict(blocker)
        refined["project_branch_hit_count"] = project_branch_hit_count
        refined["project_blocked_hit_count"] = project_blocked_hit_count
        refined["project_branch_reached"] = True
        refined["project_blocked_side_reached"] = False
        refined["project_blocker_state"] = "stalled_at_branch"
        refined["project_relevant"] = True

        contributing_targets = [
            str(target_name)
            for target_name in blocker.get("contributing_targets", [])
            if str(target_name) in target_reports
        ]
        branch_reached_targets: list[str] = []
        blocked_side_reached_targets: list[str] = []
        target_hit_details: list[dict[str, int | str]] = []
        refined_best_target = refined.get("best_target")
        refined_best_score = (-1, -1)

        for target_name in contributing_targets:
            report = target_reports[target_name]
            branch_hit_count = _normalize_hitcount(
                get_line_execution_count(report, branch_line, function_name=function_name)
            )
            blocked_hit_count = _normalize_hitcount(
                get_line_execution_count(report, blocked_side_line, function_name=function_name)
            )
            if branch_hit_count > 0:
                branch_reached_targets.append(target_name)
            if blocked_hit_count > 0:
                blocked_side_reached_targets.append(target_name)
            if branch_hit_count > 0 or blocked_hit_count > 0:
                target_hit_details.append(
                    {
                        "target_name": target_name,
                        "branch_hit_count": branch_hit_count,
                        "blocked_hit_count": blocked_hit_count,
                    }
                )
            if branch_hit_count > 0 and blocked_hit_count == 0:
                score = (branch_hit_count, 1 if target_name == blocker.get("best_target") else 0)
                if score > refined_best_score:
                    refined_best_score = score
                    refined_best_target = target_name

        refined["project_branch_reached_targets"] = sorted(branch_reached_targets)
        refined["project_blocked_side_reached_targets"] = sorted(blocked_side_reached_targets)
        refined["project_branch_reached_target_count"] = len(branch_reached_targets)
        refined["project_blocked_side_reached_target_count"] = len(blocked_side_reached_targets)
        refined["project_target_hit_details"] = sorted(
            target_hit_details,
            key=lambda item: (int(item["branch_hit_count"]), -int(item["blocked_hit_count"])),
            reverse=True,
        )
        if refined_best_target:
            refined["best_target"] = refined_best_target
        filtered.append(refined)

    return filtered


def _default_output_path(project_name: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("artifacts") / "branch_blocker_json" / f"{timestamp}_{project_name}.json"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aggregate and export project-real blockers from existing introspector and coverage artifacts."
    )
    parser.add_argument("project_name", help="OSS-Fuzz project name.")
    parser.add_argument(
        "--blocker-json-path",
        type=Path,
        default=None,
        help="Optional path to branch-blockers.json. If omitted, common project artifact locations are checked.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=0,
        help="Limit exported blockers after real-blocker filtering. Default 0 means export all.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Explicit output JSON path. Defaults to artifacts/branch_blocker_json/<timestamp>_<project>.json.",
    )
    parser.add_argument(
        "--no-repair-missing-coverage",
        action="store_true",
        default=False,
        help="Do not auto-run coverage() when required textcov artifacts are missing.",
    )
    args = parser.parse_args()

    blocker_json_path = _resolve_blocker_json_path(args.project_name, args.blocker_json_path)
    if blocker_json_path is None:
        raise SystemExit(f"Could not find branch-blockers.json for project {args.project_name}.")

    coverage_context = _load_blocker_coverage_context(
        args.project_name,
        blocker_json_path,
        repair_missing=not args.no_repair_missing_coverage,
    )
    if coverage_context is None:
        raise SystemExit(
            f"Coverage artifacts for project {args.project_name} are incomplete. "
            "Prepare textcov_reports first or rerun without --no-repair-missing-coverage."
        )

    project_report, target_reports = coverage_context
    aggregated_blockers = aggregate_blockers(json_path=str(blocker_json_path), top_k=None)
    filtered_blockers = _filter_real_blockers(aggregated_blockers, project_report, target_reports)
    if args.top_k > 0:
        filtered_blockers = filtered_blockers[: args.top_k]

    output_path = args.output or _default_output_path(args.project_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "project": args.project_name,
        "source_blocker_json_path": str(blocker_json_path),
        "aggregated_count": len(aggregated_blockers),
        "filtered_count": len(filtered_blockers),
        "blocker_top_k": args.top_k,
        "blockers": filtered_blockers,
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Wrote real blocker snapshot to {output_path}")
    print(f"Aggregated blockers: {len(aggregated_blockers)}")
    print(f"Real blockers: {len(filtered_blockers)}")


if __name__ == "__main__":
    main()
