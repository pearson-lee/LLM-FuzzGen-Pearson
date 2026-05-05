import re


_LINE_ENTRY_RE = re.compile(r"^\s*(?P<line>\d+)\|(?P<count>[^|]*)\|(?P<code>.*)$")


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


def get_line_execution_count(
    report: str,
    line_no: int,
    *,
    function_name: str | None = None,
    raw_function_name: str | None = None,
) -> str:
    """Extract the execution count for a source line from llvm-cov output.

    Prefer the target function's section when llvm-cov emits multiple function blocks.
    Fall back to scanning the full report when the report is a single-file listing.
    """
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

    global_matches = _extract_count_from_lines(report.splitlines(), line_no)
    if len(global_matches) == 1:
        return global_matches[0]
    if global_matches:
        return global_matches[0]
    return ""
