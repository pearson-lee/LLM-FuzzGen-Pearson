import argparse
import copy
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
_PAT_CALL_ASSIGNMENT = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"(?:\([^;=()]*\)\s*)?"
    r"(?P<callee>[A-Za-z_]\w*)\s*\("
)
_PAT_NULL_CHECKS = (
    re.compile(r"\bif\s*\(\s*!\s*(?P<var>[A-Za-z_]\w*)\s*\)"),
    re.compile(
        r"\bif\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*==\s*(?:NULL|nullptr)\s*\)"
    ),
    re.compile(
        r"\bif\s*\(\s*(?:NULL|nullptr)\s*==\s*(?P<var>[A-Za-z_]\w*)\s*\)"
    ),
)
_PAT_RESOURCE_FAILURE = re.compile(
    r"\bENOMEM\b"
    r"|out\s+of\s+memory"
    r"|not\s+enough\s+memory"
    r"|cannot\s+allocate\s+memory"
    r"|allocation(?:\s+|_)(?:failed|failure)",
    re.I,
)
_STANDARD_ALLOCATORS: frozenset[str] = frozenset({
    "malloc",
    "calloc",
    "realloc",
    "aligned_alloc",
    "posix_memalign",
    "g_try_malloc",
    "zmalloc",
})
_HIT_SATURATION_THRESHOLD = 100_000
_SOURCE_SCORE_POOL_SIZE = 20
_SOURCE_BENEFIT_POOL_SIZE = 10
_SOURCE_EVIDENCE_POOL_CAP = 30
_SOURCE_EVIDENCE_MAX_PASSES = 3
_STATE_PRIORITY = {
    "stalled_at_branch": 2,
    "unreached_branch": 1,
    "resolved": 0,
}
_AUDIT_HINTS: List = [
    (re.compile(r"\b(yychar|yytable|yyreduce)\b"), "possible_parser_var"),
    (re.compile(r"\b(NOTREACHED|UNREACHABLE|ASSERT\s*\(\s*(?:false|0)\s*\))"), "possible_assertion_macro"),
    (_PAT_RESOURCE_FAILURE, "possible_resource_failure"),
]


def _source_root_candidates(
    source_root: Path,
    project_name: str,
    source_file: str,
) -> List[Path]:
    relative = Path(source_file.lstrip("/"))
    candidates = [source_root / relative]

    parts = relative.parts
    project_prefix = ("src", project_name)
    if project_name and parts[:2] == project_prefix:
        project_relative = Path(*parts[2:])
        candidates.extend((source_root / project_relative, source_root / "src" / project_relative))

    candidates.append(source_root / relative.name)
    return candidates


def _fetch_file_lines(
    project_name: str,
    source_file: str,
    source_root: Optional[str] = None,
) -> List[str]:
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
        project_roots = (
            Path(f"external/oss-fuzz/build/out/{project_name}/inspector/source-code"),
            Path(f"external/oss-fuzz/build/out/{project_name}/source_code"),
            Path(f"external/oss-fuzz/build/out/{project_name}/src"),
        )
        for root in project_roots:
            for mirrored in _source_root_candidates(root, project_name, source_file):
                if mirrored.is_file():
                    try:
                        return _read(mirrored)
                    except OSError:
                        continue

    # Strategy 1.75: explicit source root, used by offline replay of archived builds.
    if source_root:
        for candidate in _source_root_candidates(Path(source_root), project_name, source_file):
            if candidate.is_file():
                try:
                    return _read(candidate)
                except OSError:
                    continue

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


def _strip_comments_preserve_strings(source: str) -> str:
    """Remove C/C++ comments while preserving strings and line numbers."""
    output: List[str] = []
    index = 0
    state = "code"
    quote = ""

    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == "/" and nxt == "/":
                output.extend((" ", " "))
                index += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                output.extend((" ", " "))
                index += 2
                state = "block_comment"
                continue
            if char in {'"', "'"}:
                quote = char
                state = "string"
            output.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        output.append(char)
        if char == "\\" and index + 1 < len(source):
            output.append(source[index + 1])
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1

    return "".join(output)


def _find_null_checked_variables(snippet: str) -> set[str]:
    checked: set[str] = set()
    for pattern in _PAT_NULL_CHECKS:
        checked.update(match.group("var") for match in pattern.finditer(snippet))
    return checked


def _extract_if_statement(lines: List[str], branch_line: int, max_lines: int = 8) -> str:
    """Extract the current if predicate, including conservative multiline conditions."""
    if branch_line <= 0 or branch_line > len(lines):
        return ""
    candidate = "\n".join(lines[branch_line - 1 : branch_line - 1 + max_lines])
    match = re.search(r"\bif\s*\(", candidate)
    if not match:
        return lines[branch_line - 1]

    open_paren = candidate.find("(", match.start())
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_paren, len(candidate)):
        char = candidate[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return candidate[match.start() : index + 1]
    return lines[branch_line - 1]


def _analyze_snippet_solvability(
    branch_line_text: str,
    branch_snippet: str,
    blocked_side_snippet: str = "",
    assignment_snippet: Optional[str] = None,
) -> tuple:
    combined_snippet = "\n".join((branch_snippet, blocked_side_snippet))
    hints = [hint for pattern, hint in _AUDIT_HINTS if pattern.search(combined_snippet)]

    if _PAT_GENERATED_SKELETON.search(branch_line_text):
        return 0.20, "generated_skeleton_state", hints, {
            "grade": "strong",
            "pattern": "generated_skeleton_variable",
        }

    assignment_source = assignment_snippet if assignment_snippet is not None else branch_snippet
    assignments = [
        {
            "variable": match.group("var"),
            "callee": match.group("callee"),
        }
        for match in _PAT_CALL_ASSIGNMENT.finditer(assignment_source)
    ]
    # Attribution rule: the NULL check must be the current blocker's predicate.
    # Nearby branches are context only and cannot supply the checked variable.
    checked_variables = _find_null_checked_variables(branch_line_text)
    same_variable = [
        item for item in assignments if item["variable"] in checked_variables
    ]
    resource_terms = sorted({
        match.group(0) for match in _PAT_RESOURCE_FAILURE.finditer(blocked_side_snippet)
    })

    for item in same_variable:
        direct_allocator = item["callee"] in _STANDARD_ALLOCATORS
        if resource_terms or direct_allocator:
            pattern = (
                "same_variable_call_null_check_resource_failure"
                if resource_terms
                else "same_variable_standard_allocator_null_check"
            )
            return 0.25, "resource_guard_strong", hints, {
                "grade": "strong",
                "pattern": pattern,
                "assigned_variable": item["variable"],
                "checked_variable": item["variable"],
                "callee": item["callee"],
                "resource_terms": resource_terms,
            }

    if same_variable:
        item = same_variable[0]
        return 1.0, "normal", hints, {
            "grade": "unknown",
            "pattern": "same_variable_call_null_check_without_resource_evidence",
            "assigned_variable": item["variable"],
            "checked_variable": item["variable"],
            "callee": item["callee"],
            "resource_terms": resource_terms,
        }

    allocator_like = sorted({
        item["callee"] for item in assignments if "alloc" in item["callee"].lower()
    })
    if resource_terms or allocator_like:
        return 1.0, "normal", hints, {
            "grade": "weak",
            "pattern": "unlinked_resource_hint",
            "allocator_like_callees": allocator_like,
            "resource_terms": resource_terms,
        }

    return 1.0, "normal", hints, {
        "grade": "none",
        "pattern": "none",
    }


def _apply_snippet_solvability(
    branch_line_text: str,
    branch_snippet: str,
    blocked_side_snippet: str = "",
) -> tuple:
    solvability, reason, hints, _ = _analyze_snippet_solvability(
        branch_line_text,
        branch_snippet,
        blocked_side_snippet,
    )
    return solvability, reason, hints


def _enrich_with_snippet_solvability(
    scored: List[Dict[str, Any]],
    project_name: str,
    top_k: Optional[int],
    source_root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    file_cache: Dict[str, List[str]] = {}
    code_cache: Dict[str, List[str]] = {}
    evaluated: set[tuple[str, str, str]] = set()

    for _pass in range(_SOURCE_EVIDENCE_MAX_PASSES):
        candidates = [
            blocker
            for blocker in _select_source_evidence_candidates(scored)
            if _blocker_key(blocker) not in evaluated
        ]
        if not candidates:
            break

        for blocker in candidates:
            evaluated.add(_blocker_key(blocker))
            source_file = blocker.get("source_file", "")
            branch_line = _safe_int(blocker.get("branch_line_number", 0), 0)
            blocked_side_line = _safe_int(
                blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", 0)),
                0,
            )
            if not source_file or branch_line <= 0 or blocked_side_line <= 0:
                blocker["solvability_evidence"] = {
                    "grade": "not_evaluated",
                    "pattern": "missing_source_location",
                }
                continue

            if source_file not in file_cache:
                file_cache[source_file] = _fetch_file_lines(
                    project_name,
                    source_file,
                    source_root=source_root,
                )
            file_lines = file_cache[source_file]
            if not file_lines:
                blocker["solvability_evidence"] = {
                    "grade": "not_evaluated",
                    "pattern": "source_unavailable",
                }
                continue

            if source_file not in code_cache:
                stripped = _strip_comments_preserve_strings("\n".join(file_lines))
                code_cache[source_file] = stripped.splitlines()
            code_lines = code_cache[source_file]

            branch_line_text = _extract_if_statement(code_lines, branch_line)
            branch_snippet = _extract_range(code_lines, branch_line, radius=4)
            blocked_side_snippet = _extract_range(code_lines, blocked_side_line, radius=4)
            assignment_start = max(0, branch_line - 1 - 4)
            assignment_snippet = "\n".join(
                code_lines[assignment_start : branch_line - 1]
            )
            assignment_snippet = "\n".join((assignment_snippet, branch_line_text))

            solv, reason, hints, evidence = _analyze_snippet_solvability(
                branch_line_text,
                branch_snippet,
                blocked_side_snippet,
                assignment_snippet=assignment_snippet,
            )
            blocker["solvability_evidence"] = evidence
            blocker["source_evidence_locations"] = {
                "source_file": source_file,
                "branch_line_number": branch_line,
                "blocked_side_line_number": blocked_side_line,
            }
            if solv < blocker.get("solvability_score", 1.0):
                blocker["solvability_score"] = round(solv, 4)
                blocker["solvability_reason"] = reason
                blocker["score_components"]["solvability_score"] = round(solv, 4)
                blocker["score"] = (
                    blocker.get("reach_confidence", blocker.get("actionability_score", 0.0))
                    * blocker.get("coverage_benefit", blocker.get("impact_score", 0.0))
                    * solv
                )
            if hints:
                blocker["solvability_hints"] = hints

        scored.sort(key=_selector_state_sort_key, reverse=True)

    return scored


def _blocker_key(blocker: Dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(blocker.get("source_file", "")),
        str(blocker.get("branch_line_number", "")),
        str(blocker.get("blocked_side", "")),
    )


def _select_source_evidence_candidates(
    scored: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Union hot/utility candidates with high-benefit candidates before source checks."""
    primary = scored[:_SOURCE_SCORE_POOL_SIZE]
    by_benefit = sorted(
        scored,
        key=lambda blocker: (
            blocker.get("coverage_benefit", blocker.get("impact_score", 0.0)),
            blocker.get("score", 0.0),
        ),
        reverse=True,
    )[:_SOURCE_BENEFIT_POOL_SIZE]

    selected: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for blocker in primary + by_benefit:
        key = _blocker_key(blocker)
        if key in seen:
            continue
        selected.append(blocker)
        seen.add(key)
        if len(selected) >= _SOURCE_EVIDENCE_POOL_CAP:
            break
    return selected


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


def _compute_actionability_score(
    blocker: Dict[str, Any],
    hit_saturation_threshold: int = _HIT_SATURATION_THRESHOLD,
) -> float:
    branch_hit_count = _safe_int(blocker.get("project_branch_hit_count", 0), 0)
    threshold = max(1, hit_saturation_threshold)
    saturated_hotness = min(
        1.0,
        math.log1p(max(0, branch_hit_count)) / math.log1p(threshold),
    )
    return 0.5 + 0.5 * saturated_hotness


def _compute_impact_score(blocker: Dict[str, Any]) -> float:
    not_covered = max(
        0,
        _safe_int(blocker.get("blocked_unique_not_covered_complexity", 0), 0),
    )
    reachable = max(
        0,
        _safe_int(blocker.get("blocked_unique_reachable_complexity", 0), 0),
    )
    unlock_ratio = min(1.0, not_covered / max(reachable, 1))
    base_benefit = math.log1p(not_covered) * (0.5 + 0.5 * unlock_ratio)

    # Keep this secondary and bounded because all_functions.js may be stale between
    # Introspector refreshes. It only preserves small semantic unlocks.
    globally_unhit = max(
        0,
        _safe_int(blocker.get("globally_unhit_function_count", 0), 0),
    )
    globally_unhit_bonus = 0.25 * min(globally_unhit, 4)
    return base_benefit + globally_unhit_bonus


def _compute_unlock_ratio(blocker: Dict[str, Any]) -> float:
    not_covered = max(
        0,
        _safe_int(blocker.get("blocked_unique_not_covered_complexity", 0), 0),
    )
    reachable = max(
        0,
        _safe_int(blocker.get("blocked_unique_reachable_complexity", 0), 0),
    )
    return min(1.0, not_covered / max(reachable, 1))


def _apply_expected_utility_score(
    blocker: Dict[str, Any],
    hit_saturation_threshold: int = _HIT_SATURATION_THRESHOLD,
) -> Dict[str, Any]:
    reach_confidence = _compute_actionability_score(
        blocker,
        hit_saturation_threshold=hit_saturation_threshold,
    )
    coverage_benefit = _compute_impact_score(blocker)
    unlock_ratio = _compute_unlock_ratio(blocker)
    static_solvability, static_reason = _compute_static_solvability(blocker)
    globally_unhit_bonus = 0.25 * min(
        max(0, _safe_int(blocker.get("globally_unhit_function_count", 0), 0)),
        4,
    )

    blocker["score_model"] = "reach_x_solvability_x_coverage_benefit_v1"
    blocker["score_components"] = {
        "reach_confidence": round(reach_confidence, 4),
        "coverage_benefit": round(coverage_benefit, 4),
        "unlock_ratio": round(unlock_ratio, 4),
        "globally_unhit_function_bonus": round(globally_unhit_bonus, 4),
        "solvability_score": round(static_solvability, 4),
        "hit_saturation_threshold": hit_saturation_threshold,
    }
    # Keep the old field names for downstream compatibility, but their semantics
    # are now bounded reach and marginal coverage benefit.
    blocker["actionability_score"] = reach_confidence
    blocker["impact_score"] = coverage_benefit
    blocker["reach_confidence"] = reach_confidence
    blocker["coverage_benefit"] = coverage_benefit
    blocker["unlock_ratio"] = unlock_ratio
    blocker["solvability_score"] = round(static_solvability, 4)
    blocker["solvability_reason"] = static_reason
    blocker["score"] = reach_confidence * coverage_benefit * static_solvability
    blocker["function_coverage_evidence_freshness"] = "introspector_snapshot_may_be_stale"
    blocker["sides_hitcount_diff_role"] = "audit_only"
    return blocker


def _selector_sort_key(blocker: Dict[str, Any]) -> tuple:
    return (
        blocker.get("score", 0.0),
        blocker.get("coverage_benefit", blocker.get("impact_score", 0.0)),
        blocker.get("reach_confidence", blocker.get("actionability_score", 0.0)),
        blocker.get("globally_unhit_function_count", 0),
        blocker.get("blocked_unique_not_covered_complexity", 0),
    )


def _selector_state_sort_key(blocker: Dict[str, Any]) -> tuple:
    return (
        _STATE_PRIORITY.get(str(blocker.get("project_blocker_state")), -1),
        *_selector_sort_key(blocker),
    )


def rescore_existing_blockers(
    blockers: List[Dict[str, Any]],
    project_name: str,
    source_root: Optional[str] = None,
    hit_saturation_threshold: int = _HIT_SATURATION_THRESHOLD,
    top_k: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Re-score an archived selector snapshot without rerunning coverage."""
    rescored = []
    for original in blockers:
        blocker = copy.deepcopy(original)
        blocker.pop("solvability_evidence", None)
        blocker.pop("source_evidence_locations", None)
        _apply_expected_utility_score(
            blocker,
            hit_saturation_threshold=hit_saturation_threshold,
        )
        rescored.append(blocker)

    rescored.sort(key=_selector_state_sort_key, reverse=True)
    rescored = _enrich_with_snippet_solvability(
        rescored,
        project_name=project_name,
        top_k=top_k,
        source_root=source_root,
    )
    rescored.sort(key=_selector_state_sort_key, reverse=True)
    if top_k is not None and top_k > 0:
        return rescored[:top_k]
    return rescored


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

        _apply_expected_utility_score(gb)
        result.append(gb)

    result.sort(key=_selector_sort_key, reverse=True)
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

            _apply_expected_utility_score(enriched)
            scored.append(enriched)
        inline_score_elapsed = time.perf_counter() - inline_score_started_at
    else:
        inline_score_elapsed = 0.0

    sort_started_at = time.perf_counter()
    scored.sort(key=_selector_state_sort_key, reverse=True)

    snippet_started_at = time.perf_counter()
    if project_name is not None:
        scored = _enrich_with_snippet_solvability(scored, project_name, top_k)
        scored.sort(key=_selector_state_sort_key, reverse=True)
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
