import logging
import os
import re
from functools import lru_cache


logger = logging.getLogger(__name__)
ENABLE_CACHED_LOOKUP_VALIDATION = os.environ.get("BLOCKER_VALIDATE_CACHED_LOOKUP", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

_LINE_ENTRY_RE = re.compile(r"^\s*(?P<line>\d+)\|(?P<count>[^|]*)\|(?P<code>.*)$")


def _count_is_positive(count: str) -> bool:
    stripped = count.strip()
    return bool(stripped) and stripped != "0" and bool(re.search(r"[1-9]", stripped))


def _normalize_name(value: str | None) -> str:
    return re.sub(r"\s+", "", (value or "").strip())


def _is_section_header(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and stripped.endswith(":") and "|" not in stripped


def _iter_function_sections(report: str) -> list[tuple[str, list[str]]]:
    lines = report.splitlines()
    sections: list[tuple[str, list[str]]] = []
    current_header = ""
    current_body: list[str] = []

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        next_line = lines[idx + 1] if idx + 1 < len(lines) else ""
        if _is_section_header(line) and _LINE_ENTRY_RE.match(next_line):
            if current_body:
                sections.append((current_header, current_body))
            current_header = line.strip().rstrip(":")
            current_body = []
            idx += 1
            continue
        current_body.append(line)
        idx += 1

    if current_body:
        sections.append((current_header, current_body))

    return sections


def _header_matches(header: str, function_name: str | None, raw_function_name: str | None) -> bool:
    normalized_header = _normalize_name(header)
    if not normalized_header:
        return False

    candidates = [_normalize_name(function_name), _normalize_name(raw_function_name)]
    candidates = [candidate for candidate in candidates if candidate]
    if not candidates:
        return False

    return any(candidate in normalized_header for candidate in candidates)


def _extract_count_from_lines(lines: list[str], line_no: int) -> list[str]:
    matches: list[str] = []
    for line in lines:
        match = _LINE_ENTRY_RE.match(line)
        if not match:
            continue
        if int(match.group("line")) == line_no:
            matches.append(match.group("count").strip())
    return matches


def _legacy_get_line_execution_count(
    report: str,
    line_no: int,
    *,
    function_name: str | None = None,
    raw_function_name: str | None = None,
    source_file: str | None = None,
) -> str:
    if not report or line_no <= 0:
        return ""

    sections = _iter_function_sections(report)
    matching_sections = [
        section_lines
        for header, section_lines in sections
        if _header_matches(header, function_name=function_name, raw_function_name=raw_function_name)
    ]

    for section_lines in matching_sections:
        matches = _extract_count_from_lines(section_lines, line_no)
        if matches:
            return matches[0]

    if source_file:
        sf_suffix = source_file if source_file.startswith("/") else "/" + source_file
        for header, section_lines in sections:
            normalized_header = _normalize_name(header)
            if not (normalized_header.endswith(sf_suffix) or normalized_header == source_file):
                continue
            matches = _extract_count_from_lines(section_lines, line_no)
            if not matches:
                continue
            non_zero = [m for m in matches if _count_is_positive(m)]
            return non_zero[0] if non_zero else matches[0]

    global_matches = _extract_count_from_lines(report.splitlines(), line_no)
    if len(global_matches) == 1:
        return global_matches[0]
    if global_matches:
        return global_matches[0]
    return ""


@lru_cache(maxsize=64)
def _build_report_index(report: str) -> tuple[dict[str, dict[int, list[str]]], dict[int, list[str]]]:
    sections = _iter_function_sections(report)
    section_indexes: dict[str, dict[int, list[str]]] = {}
    global_index: dict[int, list[str]] = {}

    for header, section_lines in sections:
        header_key = _normalize_name(header)
        line_index: dict[int, list[str]] = {}
        for line in section_lines:
            match = _LINE_ENTRY_RE.match(line)
            if not match:
                continue
            line_no = int(match.group("line"))
            count = match.group("count").strip()
            line_index.setdefault(line_no, []).append(count)
            global_index.setdefault(line_no, []).append(count)
        if header_key:
            existing = section_indexes.setdefault(header_key, {})
            for line_no, counts in line_index.items():
                existing.setdefault(line_no, []).extend(counts)

    if not global_index:
        for line in report.splitlines():
            match = _LINE_ENTRY_RE.match(line)
            if not match:
                continue
            line_no = int(match.group("line"))
            count = match.group("count").strip()
            global_index.setdefault(line_no, []).append(count)

    return section_indexes, global_index


def _cached_get_line_execution_count(
    report: str,
    line_no: int,
    *,
    function_name: str | None = None,
    raw_function_name: str | None = None,
    source_file: str | None = None,
) -> str:
    if not report or line_no <= 0:
        return ""

    section_indexes, global_index = _build_report_index(report)
    candidates = [_normalize_name(function_name), _normalize_name(raw_function_name)]
    candidates = [candidate for candidate in candidates if candidate]

    for header_key, line_index in section_indexes.items():
        if not any(candidate in header_key for candidate in candidates):
            continue
        matches = line_index.get(line_no, [])
        if matches:
            return matches[0]

    if source_file:
        sf_suffix = source_file if source_file.startswith("/") else "/" + source_file
        for header_key, line_index in section_indexes.items():
            if not (header_key.endswith(sf_suffix) or header_key == source_file):
                continue
            matches = line_index.get(line_no, [])
            if not matches:
                continue
            non_zero = [m for m in matches if _count_is_positive(m)]
            return non_zero[0] if non_zero else matches[0]

    global_matches = global_index.get(line_no, [])
    if len(global_matches) == 1:
        return global_matches[0]
    if global_matches:
        return global_matches[0]
    return ""


def get_line_execution_count(
    report: str,
    line_no: int,
    *,
    function_name: str | None = None,
    raw_function_name: str | None = None,
    source_file: str | None = None,
) -> str:
    """Extract the execution count for a source line from llvm-cov output.

    Prefer the target function's section when llvm-cov emits function-level blocks.
    When the report is project-wide (file-path sections), use source_file to narrow
    the lookup to the correct file section and avoid collisions with same-numbered
    lines in other source files.
    Falls back to global scan when neither function nor source_file narrows the result.
    """
    cached_result = _cached_get_line_execution_count(
        report,
        line_no,
        function_name=function_name,
        raw_function_name=raw_function_name,
        source_file=source_file,
    )
    if not ENABLE_CACHED_LOOKUP_VALIDATION:
        return cached_result

    legacy_result = _legacy_get_line_execution_count(
        report,
        line_no,
        function_name=function_name,
        raw_function_name=raw_function_name,
        source_file=source_file,
    )

    if legacy_result != cached_result:
        logger.warning(
            "Coverage lookup mismatch at line=%s function=%s raw_function=%s source_file=%s legacy=%r cached=%r",
            line_no,
            function_name,
            raw_function_name,
            source_file,
            legacy_result,
            cached_result,
        )
        return legacy_result
    return cached_result
