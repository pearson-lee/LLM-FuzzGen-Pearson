import argparse
import json
import math
import os
import re
import time
from glob import glob
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from blocker_process.coverage_utils import get_line_execution_count


# ── Phase 1: Terminal function signal ─────────────────────────────────────────
# Functions that, when uniquely reachable only through a blocked branch, indicate
# the blocked side is a defensive/terminal path (abort-on-impossible-state).
# Only standard C/C++/GLib/Rust names are included; project-specific wrappers
# like xmalloc are excluded because their abort() is internal and won't appear
# in blocked_unique_functions.
_TERMINAL_FUNCTIONS: frozenset = frozenset({
    "abort", "_abort", "exit", "_exit", "_Exit", "quick_exit",
    "__assert_fail", "__assert_rtn",
    "__builtin_trap", "__builtin_unreachable",
    "std::terminate", "std::abort",
    "g_assertion_message_expr", "g_assertion_message",
    "rust_begin_unwind",
})


def _compute_static_solvability(blocker: Dict[str, Any]) -> tuple:
    blocked_funcs = blocker.get("blocked_unique_functions", [])
    if any(f in _TERMINAL_FUNCTIONS for f in blocked_funcs):
        return 0.15, "terminal_function"
    return 1.0, "normal"


# ── Phase 2: Conservative source-level penalty ────────────────────────────────
# Hard rule: fetch entire file once (range fetch), not line-by-line.
# Generated-parser variables (yyerrstatus, yy_fill_buffer, etc.) are
# self-certifying — they only appear in bison/flex generated code.

_PAT_GENERATED_SKELETON = re.compile(
    r"\b(yyerrstatus|yyerrlab1?"
    r"|yy_fill_buffer"
    r"|YY_CURRENT_BUFFER(?:_LVALUE)?"
    r")\b"
)
_PAT_OOM_ALLOC = re.compile(
    r"\b(\w{3,})\s*=\s*(?:malloc|calloc|realloc|g_try_malloc|zmalloc)\s*\("
)
_PAT_OOM_NULL_CHECK = re.compile(
    r"\bif\s*\(\s*(?:!\s*(\w+)|(\w+)\s*==\s*NULL)\s*\)"
)
_AUDIT_HINTS: List = [
    (re.compile(r"\b(yychar|yytable|yyreduce)\b"), "possible_parser_var"),
    (re.compile(r"\b(NOTREACHED|UNREACHABLE|ASSERT\s*\(\s*(?:false|0)\s*\))"), "possible_assertion_macro"),
    (re.compile(r'"(?:out of memory|not enough memory|ENOMEM)"', re.I), "possible_oom_string"),
]


def _fetch_file_lines(project_name: str, source_file: str) -> List[str]:
    def _read(p: Path) -> List[str]:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()

    # Strategy 1: direct local path (works when running inside container)
    path = Path(source_file)
    if path.is_file():
        try:
            return _read(path)
        except OSError:
            pass

    # Strategy 1.5: inspector source-code mirror (host path for container-relative paths)
    # FuzzIntrospector copies source files preserving the full container path structure,
    # so /src/foo/bar.c maps to .../inspector/source-code/src/foo/bar.c on the host.
    if project_name:
        mirrored = (
            Path(f"external/oss-fuzz/build/out/{project_name}/inspector/source-code")
            / source_file.lstrip("/")
        )
        if mirrored.is_file():
            try:
                return _read(mirrored)
            except OSError:
                pass

    # Strategy 2: Introspector API (network, fallback)
    try:
        from blocker_process.blocker_classifier import get_introspector
        content = get_introspector().get_project_source_code(
            project_name=project_name,
            filepath=source_file,
            begin_line=1,
            end_line=999999,
        )
        return content.splitlines() if content else []
    except Exception:
        return []


def _extract_range(lines: List[str], center: int, radius: int) -> str:
    lo = max(0, center - 1 - radius)
    hi = min(len(lines), center + radius)
    return "\n".join(lines[lo:hi])


def _apply_snippet_solvability(
    branch_line_text: str,
    branch_snippet: str,
) -> tuple:
    hints: List[str] = []
    for pat, hint in _AUDIT_HINTS:
        if pat.search(branch_snippet):
            hints.append(hint)

    # P1: generated-parser/lexer skeleton variable in the branch condition itself.
    # yyerrstatus/yyerrlab (bison) and yy_fill_buffer/YY_CURRENT_BUFFER (flex) are
    # self-certifying — they only exist in bison/flex generated code.
    if _PAT_GENERATED_SKELETON.search(branch_line_text):
        return 0.20, "generated_skeleton_state", hints

    # P2: OOM null check requires same variable name in alloc call and null check
    alloc_vars = {m.group(1) for m in _PAT_OOM_ALLOC.finditer(branch_snippet)}
    if alloc_vars:
        for m in _PAT_OOM_NULL_CHECK.finditer(branch_snippet):
            checked = m.group(1) or m.group(2)
            if checked in alloc_vars:
                return 0.25, "oom_null_check", hints

    return 1.0, "normal", hints


def _enrich_with_snippet_solvability(
    scored: List[Dict[str, Any]],
    project_name: str,
    top_k: Optional[int],
) -> List[Dict[str, Any]]:
    cap = min(len(scored), (top_k or 10) * 2, 30)
    file_cache: Dict[str, List[str]] = {}

    for blocker in scored[:cap]:
        source_file = blocker.get("source_file", "")
        branch_line = _safe_int(blocker.get("branch_line_number", 0), 0)
        if not source_file or branch_line <= 0:
            continue

        if source_file not in file_cache:
            file_cache[source_file] = _fetch_file_lines(project_name, source_file)
        file_lines = file_cache[source_file]
        if not file_lines:
            continue

        branch_line_text = file_lines[branch_line - 1] if 0 < branch_line <= len(file_lines) else ""
        branch_snippet = _extract_range(file_lines, branch_line, radius=3)

        solv, reason, hints = _apply_snippet_solvability(branch_line_text, branch_snippet)
        if solv < blocker.get("solvability_score", 1.0):
            blocker["solvability_score"] = round(solv, 4)
            blocker["solvability_reason"] = reason
            blocker["score_components"]["solvability_score"] = round(solv, 4)
            blocker["score"] = (
                blocker.get("actionability_score", 0.0) + blocker.get("impact_score", 0.0)
            ) * solv
        if hints:
            blocker["solvability_hints"] = hints

    return scored


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


def _blocked_side_line_number(blocker: Dict[str, Any]) -> str:
    return str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "")))


def _canonicalize_blocker(blocker: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(blocker)
    blocked_side_line_number = _blocked_side_line_number(blocker)
    normalized["blocked_side_line_number"] = blocked_side_line_number
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


def _compute_actionability_score(blocker: Dict[str, Any]) -> float:
    branch_hit_count = _safe_int(blocker.get("project_branch_hit_count", 0), 0)
    branch_target_count = _safe_int(blocker.get("project_branch_reached_target_count", 0), 0)
    side_gap = _safe_int(blocker.get("sides_hitcount_diff", 0), 0)

    return (
        math.log1p(branch_hit_count)
        + 0.75 * math.log1p(branch_target_count)
        + 0.3 * math.log1p(max(0, side_gap))
    )


def _compute_impact_score(blocker: Dict[str, Any]) -> float:
    return (
        1.2 * math.log1p(_safe_int(blocker.get("blocked_unique_not_covered_complexity", 0), 0))
        + 0.8 * math.log1p(_safe_int(blocker.get("blocked_not_covered_complexity", 0), 0))
        + 0.8 * math.log1p(_safe_int(blocker.get("blocked_unique_reachable_complexity", 0), 0))
        + 0.5 * math.log1p(_safe_int(blocker.get("blocked_reachable_complexity", 0), 0))
        + _safe_float(blocker.get("project_function_coverage_signal", 0.0), 0.0)
        + _safe_float(blocker.get("project_file_coverage_signal", 0.0), 0.0)
        + 0.5 * math.log1p(_safe_int(blocker.get("occurrence_count", 0), 0))
    )


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
            blocker = _canonicalize_blocker(blocker)
            source_file = _normalize_source_path(blocker.get("source_file", ""))
            branch_line = str(blocker.get("branch_line_number", ""))
            blocked_side = str(blocker.get("blocked_side", ""))
            blocked_side_line_number = blocker["blocked_side_line_number"]
            key = (source_file, branch_line, blocked_side)

            if key not in global_blockers:
                global_blockers[key] = {
                    "source_file": source_file,
                    "branch_line_number": branch_line,
                    "blocked_side": blocked_side,
                    "function_name": blocker.get("function_name", ""),
                    "blocked_side_line_number": blocked_side_line_number,
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

        actionability_score = _compute_actionability_score(gb)
        impact_score = _compute_impact_score(gb)
        static_solv, static_reason = _compute_static_solvability(gb)

        gb["score_components"] = {
            "actionability_score": round(actionability_score, 4),
            "impact_score": round(impact_score, 4),
            "solvability_score": round(static_solv, 4),
        }
        gb["actionability_score"] = actionability_score
        gb["impact_score"] = impact_score
        gb["solvability_score"] = round(static_solv, 4)
        gb["solvability_reason"] = static_reason
        gb["score"] = (actionability_score + impact_score) * static_solv
        result.append(gb)

    result.sort(
        key=lambda x: (
            x["score"],
            x["actionability_score"],
            x["impact_score"],
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
            blocker = _canonicalize_blocker(blocker)
            source_file = blocker.get("source_file", "")
            branch_line = str(blocker.get("branch_line_number", ""))
            blocked_side = str(blocker.get("blocked_side", ""))
            blocked_side_line_number = blocker["blocked_side_line_number"]
            key = (source_file, branch_line, blocked_side)

            if key not in global_blockers:
                global_blockers[key] = {
                    "source_file": source_file,
                    "branch_line_number": branch_line,
                    "blocked_side": blocked_side,
                    "function_name": blocker.get("function_name", ""),
                    "blocked_side_line_number": blocked_side_line_number,
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
    started_at = time.perf_counter()
    annotated: List[Dict[str, Any]] = []
    total_target_scans = 0
    slowest_blocker: tuple[str, float, int] | None = None
    for blocker in blockers:
        blocker_started_at = time.perf_counter()
        branch_line = _safe_int(blocker.get("branch_line_number", 0))
        blocked_side_line = _safe_int(
            blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", 0)),
            0,
        )
        function_name = blocker.get("function_name")
        source_file = blocker.get("source_file") or ""

        branch_hits_sum = 0
        blocked_hits_sum = 0
        branch_reached_targets: List[str] = []
        blocked_side_reached_targets: List[str] = []
        per_target_hits: List[Dict[str, Any]] = []

        for target_name, report_text in project_target_reports.items():
            total_target_scans += 1
            branch_raw = get_line_execution_count(
                report_text,
                branch_line,
                function_name=function_name,
                source_file=source_file,
            )
            blocked_raw = get_line_execution_count(
                report_text,
                blocked_side_line,
                function_name=function_name,
                source_file=source_file,
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
        blocker_elapsed = time.perf_counter() - blocker_started_at
        blocker_label = (
            f"{annotated_blocker.get('function_name', 'unknown')}:{annotated_blocker.get('branch_line_number', 'unknown')}"
        )
        if slowest_blocker is None or blocker_elapsed > slowest_blocker[1]:
            slowest_blocker = (blocker_label, blocker_elapsed, len(project_target_reports))

    total_elapsed = time.perf_counter() - started_at
    avg_targets_per_blocker = (total_target_scans / len(blockers)) if blockers else 0.0
    slowest_label = slowest_blocker[0] if slowest_blocker else "n/a"
    slowest_elapsed = slowest_blocker[1] if slowest_blocker else 0.0
    print(
        "[Timing] annotate_blockers_with_project_target_coverage: "
        f"blockers={len(blockers)} targets={len(project_target_reports)} "
        f"target_scans={total_target_scans} avg_targets_per_blocker={avg_targets_per_blocker:.2f} "
        f"slowest_blocker={slowest_label} slowest_elapsed={slowest_elapsed:.2f}s total={total_elapsed:.2f}s"
    )

    return annotated


def aggregate_score_and_revalidate_blockers(
    json_path: str,
    project_target_reports: Dict[str, str],
    top_k: Optional[int] = 12,
    all_functions_js_path: Optional[str] = None,
    summary_json_path: Optional[str] = None,
    include_resolved: bool = False,
    project_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    started_at = time.perf_counter()
    aggregate_started_at = time.perf_counter()
    blockers = aggregate_blockers(json_path=json_path, top_k=None)
    aggregate_elapsed = time.perf_counter() - aggregate_started_at
    print(
        "[Info] aggregate_score_and_revalidate_blockers: "
        f"deduplicated_global_blockers={len(blockers)}"
    )
    annotate_started_at = time.perf_counter()
    annotated = annotate_blockers_with_project_target_coverage(blockers, project_target_reports)
    annotate_elapsed = time.perf_counter() - annotate_started_at

    filter_started_at = time.perf_counter()
    if not include_resolved:
        annotated = [blocker for blocker in annotated if blocker.get("project_relevant")]
    filter_elapsed = time.perf_counter() - filter_started_at

    if not annotated:
        total_elapsed = time.perf_counter() - started_at
        print(
            "[Timing] aggregate_score_and_revalidate_blockers: "
            f"aggregate={aggregate_elapsed:.2f}s annotate={annotate_elapsed:.2f}s "
            f"filter={filter_elapsed:.2f}s total={total_elapsed:.2f}s blockers_in={len(blockers)} annotated=0"
        )
        return []

    pre_score_started_at = time.perf_counter()
    scored = aggregate_and_score_blockers(
        json_path=json_path,
        top_k=None,
        all_functions_js_path=all_functions_js_path,
        summary_json_path=summary_json_path,
        preloaded_data={"revalidated": annotated},
    )
    pre_score_elapsed = time.perf_counter() - pre_score_started_at

    # `aggregate_and_score_blockers` expects a target->blockers mapping. For revalidated
    # blockers we already have global entries, so score them inline instead.
    if "revalidated" in {"revalidated": annotated}:
        inline_score_started_at = time.perf_counter()
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

            actionability_score = _compute_actionability_score(enriched)
            impact_score = _compute_impact_score(enriched)
            static_solv, static_reason = _compute_static_solvability(enriched)
            enriched["score_components"] = {
                "actionability_score": round(actionability_score, 4),
                "impact_score": round(impact_score, 4),
                "solvability_score": round(static_solv, 4),
            }
            enriched["actionability_score"] = actionability_score
            enriched["impact_score"] = impact_score
            enriched["solvability_score"] = round(static_solv, 4)
            enriched["solvability_reason"] = static_reason
            enriched["score"] = (actionability_score + impact_score) * static_solv
            scored.append(enriched)
        inline_score_elapsed = time.perf_counter() - inline_score_started_at
    else:
        inline_score_elapsed = 0.0

    state_priority = {
        "stalled_at_branch": 2,
        "unreached_branch": 1,
        "resolved": 0,
    }
    sort_started_at = time.perf_counter()
    scored.sort(
        key=lambda blocker: (
            state_priority.get(str(blocker.get("project_blocker_state")), -1),
            blocker.get("score", 0.0),
            blocker.get("actionability_score", 0.0),
            blocker.get("impact_score", 0.0),
            blocker.get("project_branch_hit_count", 0),
            blocker.get("globally_unhit_function_count", 0),
            blocker.get("sum_blocked_function_undiscovered_complexity", 0),
        ),
        reverse=True,
    )

    snippet_started_at = time.perf_counter()
    if project_name is not None:
        scored = _enrich_with_snippet_solvability(scored, project_name, top_k)
        scored.sort(
            key=lambda blocker: (
                state_priority.get(str(blocker.get("project_blocker_state")), -1),
                blocker.get("score", 0.0),
                blocker.get("actionability_score", 0.0),
                blocker.get("impact_score", 0.0),
                blocker.get("project_branch_hit_count", 0),
                blocker.get("globally_unhit_function_count", 0),
                blocker.get("sum_blocked_function_undiscovered_complexity", 0),
            ),
            reverse=True,
        )
    snippet_elapsed = time.perf_counter() - snippet_started_at
    sort_elapsed = snippet_started_at - sort_started_at
    total_elapsed = time.perf_counter() - started_at
    print(
        "[Timing] aggregate_score_and_revalidate_blockers: "
        f"aggregate={aggregate_elapsed:.2f}s annotate={annotate_elapsed:.2f}s "
        f"filter={filter_elapsed:.2f}s pre_score={pre_score_elapsed:.2f}s "
        f"inline_score={inline_score_elapsed:.2f}s sort={sort_elapsed:.2f}s "
        f"snippet={snippet_elapsed:.2f}s total={total_elapsed:.2f}s "
        f"blockers_in={len(blockers)} annotated={len(annotated)} scored={len(scored)}"
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
    parser.add_argument("--project-name", default=None,
                        help="Enable Phase 2 snippet inspection (requires Introspector API or local source files)")
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
        project_name=args.project_name,
    )

    if not global_blockers:
        print("[Warn] No blockers found or file missing.")
        return

    print(f"[Info] Total unique global blockers aggregated: {len(global_blockers)}")
    print(json.dumps(global_blockers, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
