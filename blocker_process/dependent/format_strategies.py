from __future__ import annotations

from blocker_process.dependent.format_inference import FormatInfo


def build_format_strategy_notes(format_info: FormatInfo) -> str:
    family = format_info.format_family
    notes: dict[str, list[str]] = {
        "xml": [
            "Preserve well-formed XML scaffolds unless malformed structure is specifically useful.",
            "Vary element text, attributes, whitespace, numeric text, and repeated sibling structure near the blocker field.",
            "Include both valid and strategically malformed tag or attribute variants when they may affect the blocker.",
        ],
        "json": [
            "Vary object vs array shape, missing fields, duplicate-like structures, numeric boundaries, and escaping.",
            "Keep seeds small and deterministic; blocker-specific fields should be easy to locate and mutate.",
            "Include type-mismatch cases when the blocker depends on conversion or validation logic.",
        ],
        "yaml": [
            "Vary indentation, scalar style, sequence vs mapping shape, and numeric/string boundary cases.",
            "Include compact and multiline representations when parser behavior may differ.",
        ],
        "toml": [
            "Vary table nesting, quoted vs bare keys, numbers, arrays, and duplicate-like key patterns.",
            "Keep the blocker-related field explicit and easy to extend.",
        ],
        "ini": [
            "Vary section presence, repeated keys, whitespace, comments, and numeric/string boundary cases.",
            "Prefer concise config files with a clear blocker-related field.",
        ],
        "csv": [
            "Vary delimiter-sensitive rows, column counts, quoting, escapes, empty cells, and numeric boundary values.",
            "Keep blocker-sensitive columns stable while mutating nearby fields.",
        ],
        "png": [
            "Start from valid PNG magic and minimal required chunk structure whenever parser depth matters.",
            "Mutate chunk lengths, chunk ordering, and blocker-relevant payload bytes near the branch condition.",
            "Include a few malformed chunk cases only when they may still reach the blocker path.",
        ],
        "jpeg": [
            "Start from valid marker structure and mutate blocker-relevant segment payloads and lengths.",
            "Use short deterministic segment families rather than random binary noise.",
        ],
        "tiff": [
            "Preserve TIFF header, endianness, and basic IFD structure when deeper parser reachability matters.",
            "Mutate tag values, counts, offsets, and blocker-sensitive numeric fields systematically.",
        ],
        "plain_text": [
            "Treat the input as line-oriented or free-form text with explicit blocker-focused tokens.",
            "Vary whitespace, delimiters, boundary numbers, casing, and malformed fragments.",
        ],
        "raw_binary": [
            "Use structured byte families when any field layout is visible from code or triggering input.",
            "Prefer small deterministic binary variants over opaque random blobs.",
        ],
    }
    selected = notes.get(family, notes["raw_binary"])
    return "\n".join(f"- {item}" for item in selected)
