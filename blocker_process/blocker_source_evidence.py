from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from blocker_process.blocker_callpath_extractor import (
    build_evidence_for_conditions,
    collect_project_source_files,
    display_project_source_path,
    load_build_macro_facts,
    preprocessor_context_by_line,
    render_source_window,
    resolve_project_source_file,
)
from blocker_process.blocker_triage import extract_source_identifiers


MAX_SYMBOL_SEEDS = 24
MAX_DIRECT_ENTRIES = 20
MAX_TYPE_API_ENTRIES = 24
MAX_RENDERED_ENTRIES = 44
SOURCE_WINDOW_BEFORE = 2
SOURCE_WINDOW_AFTER = 3

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++"}
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx"}
_NON_CALL_WORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined"}
_TYPE_NOISE = {
    "const", "static", "extern", "volatile", "register", "signed", "unsigned",
    "long", "short", "void", "char", "int", "float", "double", "struct",
    "union", "enum", "class", "typename", "auto", "return",
}
_MACRO_NOISE = {"NULL", "TRUE", "FALSE", "CMSAPI", "CMSEXPORT"}
_CONSTRUCTORISH_PREFIXES = (
    "create", "alloc", "open", "init", "new", "make", "build", "set", "write", "insert", "link",
)


def _ordered_unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _strip_non_code(text: str) -> str:
    return re.sub(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        " ",
        text or "",
        flags=re.DOTALL,
    )


def _call_names(text: str) -> list[str]:
    code = _strip_non_code(text)
    return _ordered_unique(
        name
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code)
        if name not in _NON_CALL_WORDS
    )


def _macro_names(text: str) -> list[str]:
    return _ordered_unique(
        token
        for token in re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b", _strip_non_code(text))
        if not token.isdigit()
    )


def _find_function_body(lines: list[str], function_name: str) -> tuple[int, int] | None:
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for start, line in enumerate(lines):
        if not pattern.search(line):
            continue
        before = line.split(function_name, 1)[0]
        if not before.strip() or any(token in before for token in ("=", "(", "->", ".")):
            continue
        signature_end = start
        signature = line
        while signature_end + 1 < len(lines) and "{" not in signature and ";" not in signature:
            signature_end += 1
            signature += " " + lines[signature_end]
        if ";" in signature and ("{" not in signature or signature.index(";") < signature.index("{")):
            continue
        if "{" not in signature:
            continue
        depth = 0
        opened = False
        for end in range(start, min(len(lines), start + 500)):
            code = _strip_non_code(lines[end])
            depth += code.count("{")
            if code.count("{"):
                opened = True
            depth -= code.count("}")
            if opened and depth <= 0:
                return start, end
        return start, min(len(lines) - 1, start + 120)
    return None


def _type_names_near_identifiers(text: str, identifiers: Iterable[str]) -> list[str]:
    types: list[str] = []
    code = _strip_non_code(text)
    for identifier in identifiers:
        pattern = re.compile(
            rf"\b((?:(?:const|struct|union|enum|class)\s+)*[A-Za-z_][A-Za-z0-9_:<>]*)"
            rf"(?:[ \t]*[*&]+)?[ \t]+{re.escape(identifier)}\b"
        )
        for match in pattern.finditer(code):
            candidate = match.group(1).split()[-1]
            if (
                candidate not in _TYPE_NOISE
                and len(candidate) > 2
                and not candidate.replace(":", "").isupper()
            ):
                types.append(candidate)
    return _ordered_unique(types)


def _declared_type_names(text: str) -> list[str]:
    result: list[str] = []
    pattern = re.compile(
        r"^[ \t]*(?:const[ \t]+|static[ \t]+|volatile[ \t]+)*"
        r"((?:struct[ \t]+|union[ \t]+|enum[ \t]+|class[ \t]+)?[A-Za-z_][A-Za-z0-9_:<>]*)"
        r"(?:[ \t]*[*&]+)?[ \t]+[A-Za-z_][A-Za-z0-9_]*",
        re.MULTILINE,
    )
    for line in _strip_non_code(text).splitlines():
        if "(" in line or line.lstrip().startswith(("case ", "return ")):
            continue
        match = pattern.match(line)
        if match:
            candidate = match.group(1).split()[-1]
            if candidate not in _TYPE_NOISE and len(candidate) > 2:
                result.append(candidate)
    return _ordered_unique(result)


def _declared_function_name(line: str) -> str:
    before = line.split("(", 1)[0]
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", before)
    return names[-1] if names else ""


def _referenced_constant_names(text: str) -> list[str]:
    code = _strip_non_code(text)
    return _ordered_unique(
        re.findall(r"=\s*([A-Za-z_][A-Za-z0-9_]*)\b", code)
        + re.findall(r"(?:==|!=|\bcase)\s*([A-Za-z_][A-Za-z0-9_]*)\b", code)
    )


def _looks_like_public_header(path: str, explicit_header: str | None) -> bool:
    normalized = path.replace("\\", "/").lower()
    base = os.path.basename(normalized)
    if any(marker in base for marker in ("internal", "private", "detail")):
        return False
    if explicit_header and os.path.basename(explicit_header) == os.path.basename(path):
        return True
    return "/include/" in normalized


def _visibility(path: str, line: str, symbol: str, explicit_header: str | None) -> str:
    if re.search(r"\bstatic\b", line) or symbol.startswith("_"):
        return "internal"
    if Path(path).suffix.lower() in _HEADER_SUFFIXES and _looks_like_public_header(path, explicit_header):
        return "public"
    return "unknown"


def _looks_like_function_definition(lines: list[str], line_index: int, symbol: str) -> bool:
    line = lines[line_index]
    before = line.split(symbol, 1)[0]
    if not before.strip() or any(token in before for token in ("=", "(", "->", ".")):
        return False
    signature = line
    for next_index in range(line_index + 1, min(len(lines), line_index + 5)):
        if "{" in signature or ";" in signature:
            break
        signature += " " + lines[next_index]
    if "{" not in signature:
        return False
    if ";" in signature and signature.index(";") < signature.index("{"):
        return False
    return bool(re.search(rf"\b{re.escape(symbol)}\s*\(", signature))


def _classify_occurrence(path: str, lines: list[str], line_index: int, symbol: str) -> str:
    line = lines[line_index]
    stripped = line.strip()
    if re.match(rf"^#\s*define\s+{re.escape(symbol)}\b", stripped):
        return "macro_definition"
    if re.search(rf"\btypedef\b.*\b{re.escape(symbol)}\b", line):
        return "type_definition"
    if re.search(rf"\b{re.escape(symbol)}\s*\(", line):
        suffix = Path(path).suffix.lower()
        if suffix in _HEADER_SUFFIXES and ";" in line:
            return "declaration"
        if suffix in _SOURCE_SUFFIXES and _looks_like_function_definition(lines, line_index, symbol):
            return "definition"
        return "callsite"
    if re.search(
        rf"(?:->|\.)\s*{re.escape(symbol)}\s*=|"
        rf"\b{re.escape(symbol)}\s*(?:\[[^\]]*\])?\s*=",
        line,
    ):
        return "assignment"
    if re.search(rf"\b(?:enum|struct|union|class)\b.*\b{re.escape(symbol)}\b", line):
        return "type_definition"
    return "occurrence"


def _target_presence(
    *,
    path: str,
    kind: str,
    symbol: str,
    blocker_function: str,
    blocker_source: str | None,
) -> str:
    if kind == "definition" and symbol == blocker_function and blocker_source:
        resolved = os.path.realpath(path)
        if resolved == os.path.realpath(blocker_source):
            return "confirmed"
    return "unknown"


def _entry(
    *,
    project_name: str,
    path: str,
    lines: list[str],
    line_index: int,
    symbol: str,
    relation: str,
    preprocessor: dict,
    macro_facts: dict,
    explicit_header: str | None,
    blocker_function: str,
    blocker_source: str | None,
    local_context: str | None = None,
) -> dict:
    line = lines[line_index]
    kind = _classify_occurrence(path, lines, line_index, symbol)
    conditions = preprocessor.get("conditions", [])
    return {
        "symbol": symbol,
        "kind": kind,
        "file": display_project_source_path(path, project_name),
        "line": line_index + 1,
        "relation": relation,
        "visibility": _visibility(path, line, symbol, explicit_header),
        "preprocessor_status": preprocessor.get("status", "unknown"),
        "preprocessor_conditions": conditions,
        "build_evidence": build_evidence_for_conditions(conditions, macro_facts),
        "target_presence": _target_presence(
            path=path,
            kind=kind,
            symbol=symbol,
            blocker_function=blocker_function,
            blocker_source=blocker_source,
        ),
        "local_context": local_context or render_source_window(
            lines,
            line_index,
            before=SOURCE_WINDOW_BEFORE,
            after=SOURCE_WINDOW_AFTER,
        ),
    }


def _entry_priority(item: dict) -> tuple:
    kind_order = {
        "definition": 0,
        "declaration": 1,
        "macro_definition": 2,
        "type_definition": 3,
        "assignment": 4,
        "callsite": 5,
        "occurrence": 6,
    }
    visibility_order = {"public": 0, "unknown": 1, "internal": 2}
    preprocessor_order = {"active": 0, "unknown": 1, "inactive": 2}
    return (
        kind_order.get(item.get("kind"), 9),
        visibility_order.get(item.get("visibility"), 9),
        preprocessor_order.get(item.get("preprocessor_status"), 9),
        item.get("file", ""),
        int(item.get("line", 0)),
    )


def _type_api_priority(item: dict) -> tuple:
    name = item.get("symbol", "").lower()
    constructor_rank = next(
        (index for index, part in enumerate(_CONSTRUCTORISH_PREFIXES) if part in name),
        len(_CONSTRUCTORISH_PREFIXES),
    )
    relation = item.get("relation", "")
    specific_type_rank = 0 if any(
        marker in relation for marker in ("*", "PROFILE", "Profile", "Context", "HANDLE", "Handle")
    ) else 1
    return (specific_type_rank, constructor_rank, *_entry_priority(item))


def _operation_rank(symbol: str) -> int:
    name = symbol.lower()
    return next(
        (index for index, part in enumerate(_CONSTRUCTORISH_PREFIXES) if part in name),
        len(_CONSTRUCTORISH_PREFIXES),
    )


def _structural_name_fragment(symbol: str) -> str:
    name = symbol.split("::")[-1].lstrip("_")
    for prefix in ("cmsGet", "cmsSet", "cmsIs", "cmsCreate", "cmsRead", "cmsWrite", "get", "set", "is"):
        if name.startswith(prefix) and len(name) > len(prefix) + 3:
            return name[len(prefix) :]
    return name if len(name) >= 5 else ""


def _select_type_entries(entries: list[dict], type_seeds: list[str]) -> list[dict]:
    selected: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    per_type_limit = max(6, MAX_TYPE_API_ENTRIES // max(1, min(len(type_seeds), 3)))
    operation_quotas = {
        _CONSTRUCTORISH_PREFIXES.index("create"): 5,
        _CONSTRUCTORISH_PREFIXES.index("alloc"): 5,
        _CONSTRUCTORISH_PREFIXES.index("open"): 2,
        _CONSTRUCTORISH_PREFIXES.index("set"): 5,
        _CONSTRUCTORISH_PREFIXES.index("write"): 2,
    }
    for type_name in type_seeds[:3]:
        type_candidates = [
            entry
            for entry in entries
            if type_name in entry.get("relation", "") and entry.get("visibility") != "internal"
        ]
        candidates = sorted(
            type_candidates,
            key=lambda item: (
                0 if item.get("visibility") == "public" else 1,
                -len(item.get("matched_symbol_fragments", [])),
                -len(item.get("matched_predicate_identifiers", [])),
                _operation_rank(item.get("symbol", "")),
                _entry_priority(item),
            ),
        )
        added = 0
        used_operations: dict[int, int] = {}
        deferred: list[dict] = []
        high_signal_candidates = [
            candidate
            for candidate in candidates
            if candidate.get("matched_symbol_fragments")
            or len(candidate.get("matched_predicate_identifiers", [])) >= 2
        ]
        for candidate in high_signal_candidates[:4]:
            key = (candidate.get("file", ""), int(candidate.get("line", 0)), candidate.get("symbol", ""))
            if key in seen:
                continue
            operation = _operation_rank(candidate.get("symbol", ""))
            selected.append(candidate)
            seen.add(key)
            used_operations[operation] = used_operations.get(operation, 0) + 1
            added += 1
            if added >= per_type_limit or len(selected) >= MAX_TYPE_API_ENTRIES:
                break
        foundation_candidates = sorted(
            type_candidates,
            key=lambda item: (
                0 if item.get("visibility") == "public" else 1,
                _operation_rank(item.get("symbol", "")),
                item.get("file", ""),
                int(item.get("line", 0)),
            ),
        )
        foundation_operations: set[int] = set()
        for candidate in foundation_candidates:
            operation = _operation_rank(candidate.get("symbol", ""))
            if operation >= len(_CONSTRUCTORISH_PREFIXES) or operation in foundation_operations:
                continue
            key = (candidate.get("file", ""), int(candidate.get("line", 0)), candidate.get("symbol", ""))
            if key in seen:
                continue
            selected.append(candidate)
            seen.add(key)
            foundation_operations.add(operation)
            used_operations[operation] = used_operations.get(operation, 0) + 1
            added += 1
            if added >= per_type_limit or len(selected) >= MAX_TYPE_API_ENTRIES:
                break
        for candidate in candidates:
            key = (candidate.get("file", ""), int(candidate.get("line", 0)), candidate.get("symbol", ""))
            if key in seen:
                continue
            operation = _operation_rank(candidate.get("symbol", ""))
            quota = operation_quotas.get(operation, 1)
            if used_operations.get(operation, 0) >= quota:
                deferred.append(candidate)
                continue
            selected.append(candidate)
            seen.add(key)
            used_operations[operation] = used_operations.get(operation, 0) + 1
            added += 1
            if added >= per_type_limit or len(selected) >= MAX_TYPE_API_ENTRIES:
                break
        if added < per_type_limit and len(selected) < MAX_TYPE_API_ENTRIES:
            for candidate in deferred:
                key = (candidate.get("file", ""), int(candidate.get("line", 0)), candidate.get("symbol", ""))
                if key in seen:
                    continue
                selected.append(candidate)
                seen.add(key)
                added += 1
                if added >= per_type_limit or len(selected) >= MAX_TYPE_API_ENTRIES:
                    break
        if len(selected) >= MAX_TYPE_API_ENTRIES:
            break
    if len(selected) < MAX_TYPE_API_ENTRIES:
        for candidate in sorted(entries, key=_type_api_priority):
            key = (candidate.get("file", ""), int(candidate.get("line", 0)), candidate.get("symbol", ""))
            if key in seen:
                continue
            selected.append(candidate)
            seen.add(key)
            if len(selected) >= MAX_TYPE_API_ENTRIES:
                break
    return selected


def _function_bodies_for_names(files: list[str], names: Iterable[str]) -> dict[str, str]:
    remaining = set(names)
    bodies: dict[str, str] = {}
    if not remaining:
        return bodies
    for path in files:
        if Path(path).suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for name in list(remaining):
            extent = _find_function_body(lines, name)
            if not extent:
                continue
            bodies[name] = "\n".join(lines[extent[0] : extent[1] + 1])
            remaining.remove(name)
        if not remaining:
            break
    return bodies


def _select_direct_entries(entries: list[dict], symbol_seeds: list[str]) -> list[dict]:
    selected: list[dict] = []
    selected_keys: set[tuple[str, int, str]] = set()
    kind_quota = {
        "definition": 1,
        "declaration": 1,
        "macro_definition": 1,
        "type_definition": 1,
        "assignment": 1,
        "callsite": 1,
        "occurrence": 1,
    }
    by_symbol = {
        symbol: sorted((entry for entry in entries if entry.get("symbol") == symbol), key=_entry_priority)
        for symbol in symbol_seeds
    }
    for symbol in symbol_seeds:
        candidates = by_symbol[symbol]
        if not candidates:
            continue
        candidate = candidates[0]
        selected.append(candidate)
        selected_keys.add((candidate.get("file", ""), int(candidate.get("line", 0)), symbol))
        if len(selected) >= MAX_DIRECT_ENTRIES:
            return selected

    for symbol in symbol_seeds:
        candidates = by_symbol[symbol]
        used: dict[str, int] = {}
        for candidate in candidates:
            key = (candidate.get("file", ""), int(candidate.get("line", 0)), symbol)
            if key in selected_keys:
                used[candidate.get("kind", "occurrence")] = 1
                continue
            kind = candidate.get("kind", "occurrence")
            if used.get(kind, 0) >= kind_quota.get(kind, 1):
                continue
            selected.append(candidate)
            selected_keys.add(key)
            used[kind] = used.get(kind, 0) + 1
            if len(selected) >= MAX_DIRECT_ENTRIES:
                return selected
    return selected


def collect_symbol_evidence(
    *,
    project_name: str,
    function_name: str,
    source_file: str | None,
    header_file: str | None,
    blocker_line_code: str,
    blocked_side_line_code: str,
    branch_window: str,
    blocked_window: str,
) -> dict:
    result = {
        "version": 1,
        "project_name": project_name,
        "blocker_function": function_name,
        "symbol_seeds": [],
        "type_seeds": [],
        "entries": [],
        "total_entries": 0,
        "included_entries": 0,
        "truncated": False,
        "collection_errors": [],
        "limitations": [
            "Best-effort textual C/C++ evidence; overloads, templates, virtual dispatch, function pointers, and macro-expanded calls may remain unknown.",
            "Missing evidence means unknown, not proof that a symbol or API route does not exist.",
        ],
    }

    files, errors = collect_project_source_files(project_name)
    result["collection_errors"].extend(errors)
    if not files:
        result["collection_errors"].append("No project source mirror files were available.")
        return result

    resolved_source = resolve_project_source_file(project_name, source_file)
    basic_identifiers = extract_source_identifiers(
        blocker_line_code,
        blocked_side_line_code,
        branch_window,
        blocked_window,
    )
    predicate_calls = _call_names("\n".join((blocker_line_code, blocked_side_line_code)))
    predicate_macros = _macro_names("\n".join((blocker_line_code, blocked_side_line_code)))
    direct_identifiers = extract_source_identifiers(blocker_line_code, blocked_side_line_code)

    function_body = ""
    if resolved_source:
        try:
            source_lines = Path(resolved_source).read_text(encoding="utf-8", errors="ignore").splitlines()
            extent = _find_function_body(source_lines, function_name)
            if extent:
                function_body = "\n".join(source_lines[extent[0] : extent[1] + 1])
        except OSError as exc:
            result["collection_errors"].append(f"Failed to read blocker source: {exc}")

    direct_predicate_variables = [
        identifier
        for identifier in direct_identifiers
        if identifier not in predicate_calls and identifier not in predicate_macros and identifier != function_name
    ]
    predicate_variables = [
        identifier
        for identifier in basic_identifiers
        if identifier not in predicate_calls and identifier not in predicate_macros and identifier != function_name
    ]
    direct_type_seeds = _type_names_near_identifiers(function_body, direct_predicate_variables)
    supplementary_type_seeds = _type_names_near_identifiers(function_body, predicate_variables)
    predicate_bodies = _function_bodies_for_names(files, predicate_calls)
    predicate_dependency_text = "\n".join(predicate_bodies.values())
    blocker_dependency_calls = _call_names(function_body)
    blocker_dependency_macros = _macro_names(function_body)
    predicate_dependency_calls = _call_names(predicate_dependency_text)
    predicate_dependency_macros = _macro_names(predicate_dependency_text)
    predicate_references = _referenced_constant_names(predicate_dependency_text)
    dependency_calls = _ordered_unique(blocker_dependency_calls + predicate_dependency_calls)
    dependency_macros = _ordered_unique(blocker_dependency_macros + predicate_dependency_macros)
    type_seeds = _ordered_unique(
        direct_type_seeds
        + _declared_type_names(predicate_dependency_text)
        + supplementary_type_seeds
        + _type_names_near_identifiers(
            predicate_dependency_text,
            extract_source_identifiers(predicate_dependency_text),
        )
    )

    seed_relations: dict[str, str] = {function_name: "blocker_function"}
    for name in predicate_calls:
        seed_relations.setdefault(name, "predicate_function")
    for name in predicate_macros:
        seed_relations.setdefault(name, "predicate_macro")
    for name in predicate_dependency_calls:
        seed_relations.setdefault(name, "called_by_predicate_function")
    for name in predicate_references:
        seed_relations.setdefault(name, "referenced_by_predicate_function")
    for name in predicate_dependency_macros:
        if name in _MACRO_NOISE:
            continue
        seed_relations.setdefault(name, "referenced_by_predicate_function")
    for name in blocker_dependency_calls:
        seed_relations.setdefault(name, "called_by_blocker_function")
    for name in blocker_dependency_macros:
        if name in _MACRO_NOISE:
            continue
        seed_relations.setdefault(name, "referenced_by_blocker_function")

    symbol_seeds = list(seed_relations)[:MAX_SYMBOL_SEEDS]
    structural_fragments = _ordered_unique(
        fragment
        for fragment in (_structural_name_fragment(symbol) for symbol in dependency_calls)
        if fragment
    )
    result["symbol_seeds"] = [
        {"symbol": symbol, "relation": seed_relations[symbol]}
        for symbol in symbol_seeds
    ]
    result["type_seeds"] = type_seeds

    macro_facts = load_build_macro_facts(project_name)
    direct_entries: list[dict] = []
    type_entries: list[dict] = []
    seen_entries: set[tuple[str, int, str]] = set()

    for path in files:
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            result["collection_errors"].append(f"Failed to read {os.path.basename(path)}: {exc}")
            continue
        contexts = preprocessor_context_by_line(lines, macro_facts)
        suffix = Path(path).suffix.lower()

        for line_index, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith(("//", "/*", "*")):
                continue
            for symbol in symbol_seeds:
                if not re.search(rf"\b{re.escape(symbol)}\b", line):
                    continue
                key = (path, line_index, symbol)
                if key in seen_entries:
                    continue
                seen_entries.add(key)
                local_context = None
                if symbol == function_name or symbol in predicate_calls:
                    extent = _find_function_body(lines, symbol)
                    if extent and extent[0] == line_index:
                        body = "\n".join(
                            f"{current + 1}: {lines[current]}"
                            for current in range(extent[0], extent[1] + 1)
                        )
                        local_context = body[:5000] + ("\n... [function body truncated] ..." if len(body) > 5000 else "")
                direct_entries.append(
                    _entry(
                        project_name=project_name,
                        path=path,
                        lines=lines,
                        line_index=line_index,
                        symbol=symbol,
                        relation=seed_relations[symbol],
                        preprocessor=contexts[line_index],
                        macro_facts=macro_facts,
                        explicit_header=header_file,
                        blocker_function=function_name,
                        blocker_source=resolved_source,
                        local_context=local_context,
                    )
                )

            if suffix not in _HEADER_SUFFIXES or "(" not in line or ";" not in line:
                continue
            matched_types = [type_name for type_name in type_seeds if re.search(rf"\b{re.escape(type_name)}\b", line)]
            if not matched_types:
                continue
            function_symbol = _declared_function_name(line)
            if not function_symbol or function_symbol in _NON_CALL_WORDS:
                continue
            key = (path, line_index, function_symbol)
            if key in seen_entries:
                continue
            seen_entries.add(key)
            candidate = _entry(
                    project_name=project_name,
                    path=path,
                    lines=lines,
                    line_index=line_index,
                    symbol=function_symbol,
                    relation="declaration_uses_predicate_type:" + ",".join(matched_types),
                    preprocessor=contexts[line_index],
                    macro_facts=macro_facts,
                    explicit_header=header_file,
                    blocker_function=function_name,
                    blocker_source=resolved_source,
                    local_context=f">> {line_index + 1:6d}: {line}",
                )
            candidate["matched_predicate_identifiers"] = [
                identifier
                for identifier in direct_predicate_variables
                if re.search(rf"\b{re.escape(identifier)}\b", line)
                or identifier.lower() in function_symbol.lower()
            ]
            candidate["matched_symbol_fragments"] = [
                fragment
                for fragment in structural_fragments
                if fragment.lower() in function_symbol.lower()
            ]
            type_entries.append(candidate)

    total_direct_entries = len(direct_entries)
    direct_entries = _select_direct_entries(direct_entries, symbol_seeds)
    selected = direct_entries + _select_type_entries(type_entries, type_seeds)
    result["total_entries"] = total_direct_entries + len(type_entries)
    result["entries"] = selected[:MAX_RENDERED_ENTRIES]
    result["included_entries"] = len(result["entries"])
    result["truncated"] = result["included_entries"] < result["total_entries"]
    if not result["entries"]:
        result["collection_errors"].append("No source evidence matched the collected symbol/type seeds.")
    return result


def render_symbol_evidence_for_prompt(evidence: dict) -> str:
    entries = evidence.get("entries", []) if evidence else []
    if not entries:
        errors = "; ".join(evidence.get("collection_errors", [])) if evidence else "not collected"
        return f"N/A: no symbol evidence collected ({errors})."

    lines = [
        f"Collected {evidence.get('included_entries', 0)} of {evidence.get('total_entries', 0)} source evidence entries"
        + (" (list truncated)." if evidence.get("truncated") else "."),
        "These are structural source facts, not pre-selected solutions. Missing evidence means unknown.",
        "Use only positively supported declarations/definitions as facts. Internal, inactive, or unknown entries require corresponding caution.",
        "",
        "Symbol seeds: " + ", ".join(
            f"{item['symbol']}[{item['relation']}]" for item in evidence.get("symbol_seeds", [])
        ),
        "Predicate-related type seeds: " + (", ".join(evidence.get("type_seeds", [])) or "N/A"),
        "",
    ]
    for index, item in enumerate(entries, 1):
        lines.append(
            f"### Evidence {index}: {item['symbol']} [{item['kind']}] "
            f"relation={item['relation']} visibility={item['visibility']} "
            f"preprocessor={item['preprocessor_status']} target_presence={item['target_presence']}"
        )
        lines.append(f"Location: {item['file']}:{item['line']}")
        if item.get("preprocessor_conditions"):
            lines.append("Preprocessor conditions: " + " -> ".join(item["preprocessor_conditions"]))
        lines.append("```text")
        lines.append(item.get("local_context", "N/A"))
        lines.append("```")
        lines.append("")
    if evidence.get("collection_errors"):
        lines.append("Collection notes: " + "; ".join(evidence["collection_errors"]))
    return "\n".join(lines).strip()
