from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


_STRATEGY_CONTRACT_COMMENT_RE = re.compile(
    r"/\*\s*BLOCKER_STRATEGY_CONTRACT\b(.*?)\*/",
    re.DOTALL,
)
_STRATEGY_CONTRACT_END_RE = re.compile(
    r"^\s*END_[A-Z_]*STRATEGY_CONTRACT\s*$",
    re.MULTILINE,
)
_STRATEGY_CONTRACT_FIELDS = (
    "required_state",
    "state_constructor",
    "trigger_api",
    "preserved_invariants",
)
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_NON_CALL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "defined",
    "catch",
    "new",
    "delete",
}
_INTERNAL_CALL_ALLOWLIST = {
    "_Static_assert",
    "__attribute__",
    "__builtin_expect",
    "__builtin_unreachable",
}
_CONTRACT_WORD_NOISE = {
    "a",
    "an",
    "and",
    "api",
    "as",
    "be",
    "before",
    "by",
    "call",
    "constructor",
    "do",
    "does",
    "field",
    "for",
    "from",
    "function",
    "in",
    "is",
    "it",
    "must",
    "not",
    "of",
    "or",
    "profile",
    "required",
    "set",
    "state",
    "the",
    "to",
    "trigger",
    "use",
    "with",
}
_RESOURCE_RE = re.compile(
    r"\b(?:oom|out[- ]of[- ]memory|allocation failure|resource exhaustion|malloc failure|calloc failure|realloc failure)\b",
    re.IGNORECASE,
)
_HARNESS_STATE_RE = re.compile(
    r"\b(?:NULL|nullptr|0x[0-9A-Fa-f]+|INTENT_|TYPE_|CLASS_|TAG_|cmsSig|DLT_|PCAP_|LCMS_)\b"
)
_DIRECT_STRUCT_CLAIM_RE = re.compile(
    r"(?:->|direct(?:ly)?\s+(?:write|modify|manipulat)|(?:struct|member|field)\s+(?:write|modify|manipulat))",
    re.IGNORECASE,
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


def strip_strategy_contracts(text: str) -> str:
    return _STRATEGY_CONTRACT_COMMENT_RE.sub(" ", text or "")


def strip_c_comments_and_strings(text: str) -> str:
    return re.sub(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        " ",
        text or "",
        flags=re.DOTALL,
    )


def code_without_comments_strings_or_contracts(code: str) -> str:
    return strip_c_comments_and_strings(strip_strategy_contracts(code or ""))


def _extract_call_names(text: str) -> list[str]:
    return _ordered_unique(
        name
        for name in _CALL_RE.findall(text or "")
        if name not in _NON_CALL_WORDS
    )


def _extract_public_symbols(symbol_evidence: dict | None) -> set[str]:
    public_symbols: set[str] = set()
    for item in (symbol_evidence or {}).get("entries", []):
        if item.get("visibility") != "public":
            continue
        if item.get("preprocessor_status") == "inactive":
            continue
        if item.get("kind") not in {
            "declaration",
            "definition",
            "macro_definition",
            "type_definition",
        }:
            continue
        symbol = item.get("symbol")
        if symbol:
            public_symbols.add(symbol)
    return public_symbols


def _parse_strategy_contract_fields(strategy_contract: str) -> dict[str, str]:
    text = strategy_contract or ""
    match = _STRATEGY_CONTRACT_COMMENT_RE.search(text)
    if match:
        text = match.group(1)
    text = _STRATEGY_CONTRACT_END_RE.sub("", text).strip()
    field_names = "|".join(re.escape(field) for field in _STRATEGY_CONTRACT_FIELDS)
    field_re = re.compile(
        rf"^\s*({field_names})\s*:\s*(.*?)(?=^\s*(?:{field_names})\s*:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    fields: dict[str, str] = {}
    for field_match in field_re.finditer(text):
        fields[field_match.group(1)] = " ".join(field_match.group(2).split())
    return fields


def _contract_expected_symbols(
    strategy_contract: str,
    code_calls: Iterable[str],
    public_symbols: set[str],
) -> list[str]:
    fields = _parse_strategy_contract_fields(strategy_contract)
    relevant_text = " ".join(
        fields.get(field, "") for field in ("state_constructor", "trigger_api")
    )
    call_like = _extract_call_names(relevant_text)
    code_call_set = set(code_calls)
    tokens = [
        token
        for token in _IDENT_RE.findall(relevant_text)
        if token not in _CONTRACT_WORD_NOISE and not token.isupper()
    ]
    token_candidates = [
        token for token in tokens if token in code_call_set or token in public_symbols
    ]
    return _ordered_unique(call_like + token_candidates)


def _include_paths(code: str) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", code or "", re.MULTILINE):
        paths.append(match.group(1))
    return paths


def _internal_header_paths(code: str) -> list[str]:
    result: list[str] = []
    for path in _include_paths(code):
        normalized = path.replace("\\", "/").lower()
        basename = Path(normalized).name
        if "internal" in basename or "private" in basename or "detail" in basename:
            result.append(path)
    return result


def _internal_api_calls(code_calls: Iterable[str]) -> list[str]:
    return [
        name
        for name in code_calls
        if name.startswith("_")
        and name not in _INTERNAL_CALL_ALLOWLIST
        and not name.startswith("__builtin_")
    ]


def _direct_struct_writes(code_text: str) -> list[str]:
    pattern = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?:[+\-*/%&|^]?=|\+\+|--)"
    )
    return _ordered_unique(
        f"{match.group(1)}.{match.group(2)}" for match in pattern.finditer(code_text or "")
    )


def _contract_code_alignment(
    *,
    strategy_contract: str,
    code_calls: list[str],
    direct_struct_writes: list[str],
    public_symbols: set[str],
) -> tuple[str, list[str]]:
    notes: list[str] = []
    expected = _contract_expected_symbols(strategy_contract, code_calls, public_symbols)
    code_call_set = set(code_calls)
    contract_claims_direct_struct = bool(_DIRECT_STRUCT_CLAIM_RE.search(strategy_contract or ""))

    if contract_claims_direct_struct and not direct_struct_writes:
        notes.append(
            "Strategy Contract describes direct struct/member manipulation, but the generated code did not perform a direct struct-field write."
        )
        return "mismatch", notes

    if not expected:
        notes.append("No concrete constructor/trigger function identifiers were recoverable from the Strategy Contract.")
        return "unknown", notes

    missing = [name for name in expected if name not in code_call_set]
    present = [name for name in expected if name in code_call_set]
    if not missing:
        return "aligned", notes
    if present:
        notes.append(
            "Only part of the Strategy Contract function identifiers appear in the generated code: "
            f"present={present}, missing={missing}."
        )
        return "partial", notes
    notes.append(
        "None of the Strategy Contract constructor/trigger function identifiers appear in the generated code: "
        f"expected={expected}."
    )
    return "mismatch", notes


def _runtime_confirmed(evaluation: dict | None) -> bool:
    evaluation = evaluation or {}
    return bool(evaluation.get("blocked_side_line_reached")) or int(
        evaluation.get("blocked_side_hit_count", 0) or 0
    ) > 0


def analyze_target_quality(
    *,
    code: str,
    evaluation: dict | None,
    strategy_contract: str,
    symbol_evidence: dict | None = None,
) -> dict:
    """Classify a generated target after runtime coverage has already judged success.

    This is intentionally a conservative, deterministic post-analysis. It does
    not decide solver success; runtime coverage remains the oracle.
    """
    non_code_free = code_without_comments_strings_or_contracts(code)
    code_calls = _extract_call_names(non_code_free)
    public_symbols = _extract_public_symbols(symbol_evidence)
    public_api_calls = sorted(set(code_calls) & public_symbols)
    internal_calls = _internal_api_calls(code_calls)
    struct_writes = _direct_struct_writes(non_code_free)
    internal_headers = _internal_header_paths(code)
    runtime_confirmed = _runtime_confirmed(evaluation)
    contract_expected_symbols = _contract_expected_symbols(
        strategy_contract,
        code_calls,
        public_symbols,
    )
    alignment, alignment_notes = _contract_code_alignment(
        strategy_contract=strategy_contract,
        code_calls=code_calls,
        direct_struct_writes=struct_writes,
        public_symbols=public_symbols,
    )

    labels: list[str] = []
    flags: list[str] = []
    notes: list[str] = list(alignment_notes)
    needs_manual_review = False

    if internal_headers:
        flags.append("includes_internal_header")
        notes.append(
            "Generated target includes internal/private headers; this is a weak signal and is not treated as direct internal API use by itself."
        )
    if internal_calls:
        labels.append("internal_api_direct")
        notes.append(
            "Generated target directly calls internal-looking APIs: "
            + ", ".join(internal_calls)
            + "."
        )
    if struct_writes:
        labels.append("direct_struct_field_write")
        needs_manual_review = True
        notes.append(
            "Generated target writes through struct fields or members: "
            + ", ".join(struct_writes)
            + ". This may be valid for public structs, so it is flagged for review instead of rejected."
        )
    if _RESOURCE_RE.search(strategy_contract or ""):
        labels.append("resource_or_failure_path")
        needs_manual_review = True
        notes.append("Strategy Contract references resource/failure-path behavior.")

    if runtime_confirmed and not internal_calls and not struct_writes and "resource_or_failure_path" not in labels:
        if public_api_calls:
            if alignment == "mismatch" or _HARNESS_STATE_RE.search(non_code_free):
                labels.append("public_api_with_harness_state")
            else:
                labels.append("public_api_clean")
        else:
            labels.append("unknown")
            needs_manual_review = True
            notes.append("Runtime success used no project public API call supported by collected symbol evidence.")

    if not labels:
        labels.append("unknown")
        if runtime_confirmed:
            needs_manual_review = True

    priority = [
        "internal_api_direct",
        "direct_struct_field_write",
        "resource_or_failure_path",
        "public_api_with_harness_state",
        "public_api_clean",
        "unknown",
    ]
    primary = next(label for label in priority if label in labels)

    unsupported_contract_symbols = [
        name for name in contract_expected_symbols if name not in public_symbols
    ]
    if unsupported_contract_symbols:
        flags.append("contract_symbols_missing_public_evidence")
        notes.append(
            "Some Strategy Contract identifiers were not found as public symbols in collected evidence: "
            + ", ".join(unsupported_contract_symbols)
            + "."
        )

    return {
        "runtime_confirmed": runtime_confirmed,
        "primary_success_quality": primary,
        "success_quality_labels": _ordered_unique(labels),
        "contract_code_alignment": alignment,
        "quality_flags": _ordered_unique(flags),
        "needs_manual_review": bool(needs_manual_review),
        "quality_notes": notes,
        "evidence": {
            "code_call_count": len(code_calls),
            "public_api_calls": public_api_calls,
            "internal_api_calls": internal_calls,
            "direct_struct_writes": struct_writes,
            "internal_headers": internal_headers,
            "contract_expected_symbols": contract_expected_symbols,
            "public_symbol_count": len(public_symbols),
        },
        "limitations": [
            "Heuristic quality labels do not replace runtime coverage success.",
            "C/C++ macro expansion, templates, overloaded calls, function pointers, and public struct policies may require manual review.",
        ],
    }
