import argparse
import json
import math
import os
import re
from glob import glob
from typing import Any, Dict, Iterable, List, Optional
from blocker_process.coverage_utils import get_line_execution_count


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().rstrip("%"))
        except ValueError:
            return default
    return default


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _normalize_count(raw: Any) -> int:
    text = str(raw or "").strip()
    if not text or text == "0":
        return 0

    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kMGT]?)", text)
    if not match:
        return 0

    value = float(match.group(1))
    suffix = match.group(2)
    multipliers = {
        "": 1,
        "k": 1_000,
        "M": 1_000_000,
        "G": 1_000_000_000,
        "T": 1_000_000_000_000,
    }
    return int(value * multipliers[suffix])


def _normalize_source_path(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""

    normalized = os.path.normpath(text).replace("\\", "/")

    # Keep source-rooted paths stable across reports that may use `/src/...`,
    # `src/...`, or contain redundant `./` segments.
    if normalized == ".":
        return ""
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _infer_project_artifact_paths(json_path: str) -> tuple[Optional[str], Optional[str]]:
    base_dir = os.path.dirname(os.path.abspath(json_path))
    all_functions_path = os.path.join(base_dir, "all_functions.js")
    summary_path = os.path.join(base_dir, "summary_exclude_target.json")

    if not os.path.isfile(summary_path):
        fallback_summary = os.path.join(base_dir, "summary.json")
        summary_path = fallback_summary if os.path.isfile(fallback_summary) else None

    return (
        all_functions_path if os.path.isfile(all_functions_path) else None,
        summary_path,
    )

def _infer_project_linecov_report_dir(json_path: str) -> Optional[str]:
    inspector_dir = os.path.dirname(os.path.abspath(json_path))
    project_dir = os.path.dirname(inspector_dir)
    candidate = os.path.join(project_dir, "textcov_reports")
    return candidate if os.path.isdir(candidate) else None

def _extract_js_array_payload(raw_js: str) -> str:
    marker = "var all_functions_table_data ="
    if marker not in raw_js:
        raise ValueError("Unsupported all_functions.js format")
    payload = raw_js.split(marker, 1)[1].strip()
    if payload.endswith(";"):
        payload = payload[:-1]
    return payload


def load_project_function_coverage(all_functions_js_path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if not all_functions_js_path or not os.path.isfile(all_functions_js_path):
        return {}

    with open(all_functions_js_path, "r", encoding="utf-8") as f:
        raw_js = f.read()

    table_data = json.loads(_extract_js_array_payload(raw_js))
    function_coverage: Dict[str, Dict[str, Any]] = {}
    name_pattern = re.compile(r">\s*([^\n<][^<]*?)\s*<")

    for row in table_data:
        func_name_html = row.get("Func name", "")
        match = name_pattern.search(func_name_html)
        if not match:
            continue

        func_name = match.group(1).strip()
        function_coverage[func_name] = {
            "function_name": func_name,
            "filename": _normalize_source_path(row.get("Functions filename", "")),
            "runtime_hit": str(row.get("Fuzzers runtime hit", "")).strip().lower() == "yes",
            "line_coverage_percent": _safe_float(row.get("Func lines hit %", "0%")),
            "cyclomatic_complexity": _safe_int(row.get("Cyclomatic complexity", 0)),
            "accumulated_complexity": _safe_int(row.get("Accumulated cyclomatic complexity", 0)),
            "undiscovered_complexity": _safe_int(row.get("Undiscovered complexity", 0)),
        }

    return function_coverage


def load_project_file_coverage(summary_json_path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if not summary_json_path or not os.path.isfile(summary_json_path):
        return {}

    summary = _read_json(summary_json_path)
    file_coverage: Dict[str, Dict[str, Any]] = {}

    for entry in summary.get("data", []):
        for file_entry in entry.get("files", []):
            filename = _normalize_source_path(file_entry.get("filename", ""))
            stats = file_entry.get("summary", {})
            file_coverage[filename] = {
                "filename": filename,
                "lines_percent": _safe_float(stats.get("lines", {}).get("percent", 0)),
                "lines_notcovered": _safe_int(stats.get("lines", {}).get("count", 0))
                - _safe_int(stats.get("lines", {}).get("covered", 0)),
                "branches_percent": _safe_float(stats.get("branches", {}).get("percent", 0)),
                "branches_notcovered": _safe_int(stats.get("branches", {}).get("notcovered", 0)),
                "functions_percent": _safe_float(stats.get("functions", {}).get("percent", 0)),
                "functions_notcovered": _safe_int(stats.get("functions", {}).get("count", 0))
                - _safe_int(stats.get("functions", {}).get("covered", 0)),
            }

    return file_coverage


def _summarize_blocked_functions(
    blocked_unique_functions: Iterable[str],
    function_coverage_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    matched = []
    for func_name in blocked_unique_functions:
        func_cov = function_coverage_map.get(func_name)
        if func_cov:
            matched.append(func_cov)

    if not matched:
        return {
            "matched_function_count": 0,
            "globally_unhit_function_count": 0,
            "low_coverage_function_count": 0,
            "avg_blocked_function_line_coverage": None,
            "max_blocked_function_undiscovered_complexity": 0,
            "sum_blocked_function_undiscovered_complexity": 0,
            "project_function_coverage_signal": 0.0,
        }

    globally_unhit = [f for f in matched if not f["runtime_hit"]]
    low_coverage = [f for f in matched if f["line_coverage_percent"] < 30.0]
    avg_line_cov = sum(f["line_coverage_percent"] for f in matched) / len(matched)
    max_undiscovered = max(f["undiscovered_complexity"] for f in matched)
    sum_undiscovered = sum(f["undiscovered_complexity"] for f in matched)

    # Higher means the blocker guards functions that are still poorly covered project-wide.
    signal = (
        len(globally_unhit) * 5.0
        + len(low_coverage) * 2.0
        + math.log1p(sum_undiscovered)
        + max(0.0, (100.0 - avg_line_cov) / 20.0)
    )

    return {
        "matched_function_count": len(matched),
        "globally_unhit_function_count": len(globally_unhit),
        "low_coverage_function_count": len(low_coverage),
        "avg_blocked_function_line_coverage": round(avg_line_cov, 2),
        "max_blocked_function_undiscovered_complexity": max_undiscovered,
        "sum_blocked_function_undiscovered_complexity": sum_undiscovered,
        "project_function_coverage_signal": signal,
    }


def _summarize_blocker_file(
    source_file: str,
    file_coverage_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    info = file_coverage_map.get(_normalize_source_path(source_file))
    if not info:
        return {
            "project_file_lines_percent": None,
            "project_file_branches_percent": None,
            "project_file_lines_notcovered": 0,
            "project_file_branches_notcovered": 0,
            "project_file_coverage_signal": 0.0,
        }

    signal = (
        max(0.0, (100.0 - info["lines_percent"]) / 20.0)
        + max(0.0, (100.0 - info["branches_percent"]) / 20.0)
        + math.log1p(info["lines_notcovered"])
        + math.log1p(info["branches_notcovered"])
    )

    return {
        "project_file_lines_percent": round(info["lines_percent"], 2),
        "project_file_branches_percent": round(info["branches_percent"], 2),
        "project_file_lines_notcovered": info["lines_notcovered"],
        "project_file_branches_notcovered": info["branches_notcovered"],
        "project_file_coverage_signal": signal,
    }


def aggregate_and_score_blockers(
    json_path: str,
    top_k: Optional[int] = None,
    all_functions_js_path: Optional[str] = None,
    summary_json_path: Optional[str] = None,
    preloaded_data: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    if preloaded_data is not None:
        data = preloaded_data
    else:
        try:
            data = _read_json(json_path)
        except FileNotFoundError:
            print(f"[Error] File not found: {json_path}")
            return []

    if all_functions_js_path is None or summary_json_path is None:
        inferred_all_functions, inferred_summary = _infer_project_artifact_paths(json_path)
        all_functions_js_path = all_functions_js_path or inferred_all_functions
        summary_json_path = summary_json_path or inferred_summary

    function_coverage_map = load_project_function_coverage(all_functions_js_path)
    file_coverage_map = load_project_file_coverage(summary_json_path)

    global_blockers: Dict[tuple[str, str, str], Dict[str, Any]] = {}

    for target_name, blockers in data.items():
        for blocker in blockers:
            source_file = _normalize_source_path(blocker.get("source_file", ""))
            branch_line = str(blocker.get("branch_line_number", ""))
            blocked_side = str(blocker.get("blocked_side", ""))
            key = (source_file, branch_line, blocked_side)

            if key not in global_blockers:
                global_blockers[key] = {
                    "source_file": source_file,
                    "branch_line_number": branch_line,
                    "blocked_side": blocked_side,
                    "function_name": blocker.get("function_name", ""),
                    "blocked_side_line_numder": blocker.get("blocked_side_line_numder", ""),
                    "occurrence_count": 0,
                    "blocked_unique_not_covered_complexity": 0,
                    "blocked_unique_reachable_complexity": 0,
                    "blocked_not_covered_complexity": 0,
                    "blocked_reachable_complexity": 0,
                    "sides_hitcount_diff": 0,
                    "blocked_unique_functions": set(),
                    "contributing_targets": set(),
                    "best_target": target_name,
                    "best_target_score": (-1, -1),
                }

            gb = global_blockers[key]
            gb["occurrence_count"] += 1
            gb["contributing_targets"].add(target_name)

            gb["blocked_unique_not_covered_complexity"] = max(
                gb["blocked_unique_not_covered_complexity"],
                blocker.get("blocked_unique_not_covered_complexity", 0),
            )
            gb["blocked_unique_reachable_complexity"] = max(
                gb["blocked_unique_reachable_complexity"],
                blocker.get("blocked_unique_reachable_complexity", 0),
            )
            gb["blocked_not_covered_complexity"] = max(
                gb["blocked_not_covered_complexity"],
                blocker.get("blocked_not_covered_complexity", 0),
            )
            gb["blocked_reachable_complexity"] = max(
                gb["blocked_reachable_complexity"],
                blocker.get("blocked_reachable_complexity", 0),
            )

            hitcount_diff = blocker.get("sides_hitcount_diff", 0)
            gb["sides_hitcount_diff"] += hitcount_diff

            current_complexity = blocker.get("blocked_unique_not_covered_complexity", 0)
            current_hitcount = blocker.get("sides_hitcount_diff", 0)
            if (current_complexity, current_hitcount) > gb["best_target_score"]:
                gb["best_target_score"] = (current_complexity, current_hitcount)
                gb["best_target"] = target_name

            funcs = blocker.get("blocked_unique_functions", [])
            if funcs:
                gb["blocked_unique_functions"].update(funcs)

    result = []
    for gb in global_blockers.values():
        gb["blocked_unique_functions"] = sorted(gb["blocked_unique_functions"])
        gb["contributing_targets"] = sorted(gb["contributing_targets"])

        function_signal = _summarize_blocked_functions(
            gb["blocked_unique_functions"], function_coverage_map
        )
        file_signal = _summarize_blocker_file(gb["source_file"], file_coverage_map)
        gb.update(function_signal)
        gb.update(file_signal)

        structural_score = (
            gb["blocked_unique_not_covered_complexity"]
            * math.log1p(gb["occurrence_count"])
            * math.log1p(max(1, gb["sides_hitcount_diff"]))
        )
        project_coverage_bonus = (
            gb["project_function_coverage_signal"] + gb["project_file_coverage_signal"]
        )

        gb["score_components"] = {
            "structural_score": round(structural_score, 4),
            "project_coverage_bonus": round(project_coverage_bonus, 4),
        }
        gb["score"] = structural_score + project_coverage_bonus
        result.append(gb)

    result.sort(
        key=lambda x: (
            x["score"],
            x["globally_unhit_function_count"],
            x["sum_blocked_function_undiscovered_complexity"],
            x["blocked_unique_not_covered_complexity"],
            x["blocked_unique_reachable_complexity"],
            x["blocked_not_covered_complexity"],
            x["blocked_reachable_complexity"],
        ),
        reverse=True,
    )
    if top_k is not None and top_k > 0:
        return result[:top_k]
    return result


def aggregate_blockers(
    json_path: str,
    top_k: Optional[int] = None,
) -> List[Dict[str, Any]]:
    try:
        data = _read_json(json_path)
    except FileNotFoundError:
        print(f"[Error] File not found: {json_path}")
        return []

    global_blockers: Dict[tuple[str, str, str], Dict[str, Any]] = {}

    for target_name, blockers in data.items():
        for blocker in blockers:
            source_file = blocker.get("source_file", "")
            branch_line = str(blocker.get("branch_line_number", ""))
            blocked_side = str(blocker.get("blocked_side", ""))
            key = (source_file, branch_line, blocked_side)

            if key not in global_blockers:
                global_blockers[key] = {
                    "source_file": source_file,
                    "branch_line_number": branch_line,
                    "blocked_side": blocked_side,
                    "function_name": blocker.get("function_name", ""),
                    "blocked_side_line_numder": blocker.get("blocked_side_line_numder", ""),
                    "occurrence_count": 0,
                    "blocked_unique_not_covered_complexity": 0,
                    "blocked_unique_reachable_complexity": 0,
                    "blocked_not_covered_complexity": 0,
                    "blocked_reachable_complexity": 0,
                    "sides_hitcount_diff": 0,
                    "blocked_unique_functions": set(),
                    "contributing_targets": set(),
                    "best_target": target_name,
                    "best_target_score": (-1, -1),
                }

            gb = global_blockers[key]
            gb["occurrence_count"] += 1
            gb["contributing_targets"].add(target_name)

            gb["blocked_unique_not_covered_complexity"] = max(
                gb["blocked_unique_not_covered_complexity"],
                blocker.get("blocked_unique_not_covered_complexity", 0),
            )
            gb["blocked_unique_reachable_complexity"] = max(
                gb["blocked_unique_reachable_complexity"],
                blocker.get("blocked_unique_reachable_complexity", 0),
            )
            gb["blocked_not_covered_complexity"] = max(
                gb["blocked_not_covered_complexity"],
                blocker.get("blocked_not_covered_complexity", 0),
            )
            gb["blocked_reachable_complexity"] = max(
                gb["blocked_reachable_complexity"],
                blocker.get("blocked_reachable_complexity", 0),
            )

            hitcount_diff = blocker.get("sides_hitcount_diff", 0)
            gb["sides_hitcount_diff"] += hitcount_diff

            current_complexity = blocker.get("blocked_unique_not_covered_complexity", 0)
            current_hitcount = blocker.get("sides_hitcount_diff", 0)
            if (current_complexity, current_hitcount) > gb["best_target_score"]:
                gb["best_target_score"] = (current_complexity, current_hitcount)
                gb["best_target"] = target_name

            funcs = blocker.get("blocked_unique_functions", [])
            if funcs:
                gb["blocked_unique_functions"].update(funcs)

    result = []
    for gb in global_blockers.values():
        gb["blocked_unique_functions"] = sorted(gb["blocked_unique_functions"])
        gb["contributing_targets"] = sorted(gb["contributing_targets"])
        result.append(gb)

    if top_k is not None and top_k > 0:
        return result[:top_k]
    return result


def _load_project_target_reports(linecov_dir: Optional[str]) -> Dict[str, str]:
    if not linecov_dir or not os.path.isdir(linecov_dir):
        return {}

    reports: Dict[str, str] = {}
    for path in sorted(glob(os.path.join(linecov_dir, "*.linecovreport"))):
        basename = os.path.basename(path)
        target_name, _ = os.path.splitext(basename)
        if target_name == "project":
            continue
        with open(path, "r", encoding="utf-8") as f:
            reports[target_name] = f.read()
    return reports


def annotate_blockers_with_project_target_coverage(
    blockers: List[Dict[str, Any]],
    project_target_reports: Dict[str, str],
) -> List[Dict[str, Any]]:
    annotated: List[Dict[str, Any]] = []
    for blocker in blockers:
        branch_line = _safe_int(blocker.get("branch_line_number", 0))
        blocked_side_line = _safe_int(
            blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", 0)),
            0,
        )
        function_name = blocker.get("function_name")

        branch_hits_sum = 0
        blocked_hits_sum = 0
        branch_reached_targets: List[str] = []
        blocked_side_reached_targets: List[str] = []
        per_target_hits: List[Dict[str, Any]] = []

        for target_name, report_text in project_target_reports.items():
            branch_raw = get_line_execution_count(
                report_text,
                branch_line,
                function_name=function_name,
            )
            blocked_raw = get_line_execution_count(
                report_text,
                blocked_side_line,
                function_name=function_name,
            )
            branch_hits = _normalize_count(branch_raw)
            blocked_hits = _normalize_count(blocked_raw)

            branch_hits_sum += branch_hits
            blocked_hits_sum += blocked_hits

            if branch_hits > 0:
                branch_reached_targets.append(target_name)
            if blocked_hits > 0:
                blocked_side_reached_targets.append(target_name)

            if branch_hits > 0 or blocked_hits > 0:
                per_target_hits.append(
                    {
                        "target_name": target_name,
                        "branch_hit_count": branch_hits,
                        "blocked_hit_count": blocked_hits,
                    }
                )

        annotated_blocker = dict(blocker)
        annotated_blocker.update(
            {
                "project_branch_hit_count": branch_hits_sum,
                "project_blocked_hit_count": blocked_hits_sum,
                "project_branch_reached": branch_hits_sum > 0,
                "project_blocked_side_reached": blocked_hits_sum > 0,
                "project_branch_reached_targets": sorted(branch_reached_targets),
                "project_blocked_side_reached_targets": sorted(blocked_side_reached_targets),
                "project_branch_reached_target_count": len(branch_reached_targets),
                "project_blocked_side_reached_target_count": len(blocked_side_reached_targets),
                "project_target_hit_details": sorted(
                    per_target_hits,
                    key=lambda item: (item["blocked_hit_count"], item["branch_hit_count"]),
                    reverse=True,
                ),
            }
        )

        if blocked_hits_sum > 0:
            annotated_blocker["project_blocker_state"] = "resolved"
            annotated_blocker["project_relevant"] = False
        elif branch_hits_sum > 0:
            annotated_blocker["project_blocker_state"] = "stalled_at_branch"
            annotated_blocker["project_relevant"] = True
        else:
            annotated_blocker["project_blocker_state"] = "unreached_branch"
            annotated_blocker["project_relevant"] = True

        annotated.append(annotated_blocker)

    return annotated


def aggregate_score_and_revalidate_blockers(
    json_path: str,
    project_target_reports: Dict[str, str],
    top_k: Optional[int] = 12,
    all_functions_js_path: Optional[str] = None,
    summary_json_path: Optional[str] = None,
    include_resolved: bool = False,
) -> List[Dict[str, Any]]:
    blockers = aggregate_blockers(json_path=json_path, top_k=None)
    annotated = annotate_blockers_with_project_target_coverage(blockers, project_target_reports)

    if not include_resolved:
        annotated = [blocker for blocker in annotated if blocker.get("project_relevant")]

    if not annotated:
        return []

    scored = aggregate_and_score_blockers(
        json_path=json_path,
        top_k=None,
        all_functions_js_path=all_functions_js_path,
        summary_json_path=summary_json_path,
        preloaded_data={"revalidated": annotated},
    )

    # `aggregate_and_score_blockers` expects a target->blockers mapping. For revalidated
    # blockers we already have global entries, so score them inline instead.
    if "revalidated" in {"revalidated": annotated}:
        function_coverage_map = load_project_function_coverage(all_functions_js_path)
        file_coverage_map = load_project_file_coverage(summary_json_path)
        scored = []
        for blocker in annotated:
            enriched = dict(blocker)
            function_signal = _summarize_blocked_functions(
                enriched["blocked_unique_functions"], function_coverage_map
            )
            file_signal = _summarize_blocker_file(enriched["source_file"], file_coverage_map)
            enriched.update(function_signal)
            enriched.update(file_signal)

            structural_score = (
                enriched["blocked_unique_not_covered_complexity"]
                * math.log1p(enriched["occurrence_count"])
                * math.log1p(max(1, enriched["sides_hitcount_diff"]))
            )
            project_coverage_bonus = (
                enriched["project_function_coverage_signal"] + enriched["project_file_coverage_signal"]
            )
            enriched["score_components"] = {
                "structural_score": round(structural_score, 4),
                "project_coverage_bonus": round(project_coverage_bonus, 4),
            }
            enriched["score"] = structural_score + project_coverage_bonus
            scored.append(enriched)

    state_priority = {
        "stalled_at_branch": 2,
        "unreached_branch": 1,
        "resolved": 0,
    }
    scored.sort(
        key=lambda blocker: (
            state_priority.get(str(blocker.get("project_blocker_state")), -1),
            blocker.get("project_branch_hit_count", 0),
            blocker.get("score", 0.0),
            blocker.get("globally_unhit_function_count", 0),
            blocker.get("sum_blocked_function_undiscovered_complexity", 0),
        ),
        reverse=True,
    )
    if top_k is not None and top_k > 0:
        return scored[:top_k]
    return scored


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("json_path", nargs="?", default="branch-blockers.json")
    parser.add_argument("--top-k", type=int, default=12)
    parser.add_argument("--all-functions-js", default=None)
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--project-linecov-dir", default=None)
    parser.add_argument("--include-resolved", action="store_true")
    args = parser.parse_args()

    print("[Info] Aggregate and evaluate global blockers...")
    project_linecov_dir = args.project_linecov_dir or _infer_project_linecov_report_dir(
        args.json_path
    )
    project_target_reports = _load_project_target_reports(project_linecov_dir)

    if not project_target_reports:
        print(
            "[Warn] No per-target .linecovreport files found in textcov_reports/. "
            "Project-level blocker revalidation requires aggregated target coverage."
        )
        return

    global_blockers = aggregate_score_and_revalidate_blockers(
        json_path=args.json_path,
        project_target_reports=project_target_reports,
        top_k=args.top_k,
        all_functions_js_path=args.all_functions_js,
        summary_json_path=args.summary_json,
        include_resolved=args.include_resolved,
    )

    if not global_blockers:
        print("[Warn] No blockers found or file missing.")
        return

    print(f"[Info] Total unique global blockers aggregated: {len(global_blockers)}")
    print(json.dumps(global_blockers, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
