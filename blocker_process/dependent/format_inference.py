from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class FormatInfo:
    format_family: str = "raw_binary"
    mime_hint: str = "application/octet-stream"
    is_text: bool = False
    extensions: list[str] = field(default_factory=lambda: [".bin"])
    encoding: str = "binary"
    container_style: str = "single-blob"
    features: list[str] = field(default_factory=list)
    confidence: float = 0.2
    reasoning: list[str] = field(default_factory=list)

    def to_prompt_mapping(self) -> dict[str, str]:
        return {
            "format_family": self.format_family,
            "format_mime_hint": self.mime_hint,
            "format_is_text": "true" if self.is_text else "false",
            "format_extensions": ", ".join(self.extensions) if self.extensions else ".bin",
            "format_encoding": self.encoding,
            "format_container_style": self.container_style,
            "format_features": ", ".join(self.features) if self.features else "N/A",
            "format_confidence": f"{self.confidence:.2f}",
            "format_reasoning": "\n".join(f"- {item}" for item in self.reasoning) if self.reasoning else "- No strong signal.",
            "format_info_json": json.dumps(asdict(self), ensure_ascii=False, indent=2),
        }


def _add_score(scores: dict[str, float], reasons: dict[str, list[str]], family: str, score: float, reason: str) -> None:
    scores[family] = scores.get(family, 0.0) + score
    reasons.setdefault(family, []).append(reason)


def _detect_by_extension(path_str: str | None, scores: dict[str, float], reasons: dict[str, list[str]]) -> None:
    if not path_str:
        return
    suffix = Path(path_str).suffix.lower()
    mapping = {
        ".xml": ("xml", 5.0, "Triggering input extension suggests XML."),
        ".json": ("json", 5.0, "Triggering input extension suggests JSON."),
        ".yaml": ("yaml", 5.0, "Triggering input extension suggests YAML."),
        ".yml": ("yaml", 5.0, "Triggering input extension suggests YAML."),
        ".toml": ("toml", 5.0, "Triggering input extension suggests TOML."),
        ".ini": ("ini", 5.0, "Triggering input extension suggests INI."),
        ".cfg": ("ini", 4.0, "Triggering input extension suggests config text."),
        ".csv": ("csv", 5.0, "Triggering input extension suggests CSV."),
        ".png": ("png", 5.0, "Triggering input extension suggests PNG."),
        ".jpg": ("jpeg", 5.0, "Triggering input extension suggests JPEG."),
        ".jpeg": ("jpeg", 5.0, "Triggering input extension suggests JPEG."),
        ".tif": ("tiff", 5.0, "Triggering input extension suggests TIFF."),
        ".tiff": ("tiff", 5.0, "Triggering input extension suggests TIFF."),
        ".txt": ("plain_text", 3.0, "Triggering input extension suggests plain text."),
    }
    if suffix in mapping:
        family, score, reason = mapping[suffix]
        _add_score(scores, reasons, family, score, reason)


def _detect_by_text(text: str, scores: dict[str, float], reasons: dict[str, list[str]]) -> None:
    trimmed = text.lstrip()
    if not trimmed:
        return
    if trimmed.startswith("<?xml") or trimmed.startswith("<"):
        _add_score(scores, reasons, "xml", 6.0, "Input preview looks like XML markup.")
    if trimmed.startswith("{") or trimmed.startswith("["):
        _add_score(scores, reasons, "json", 4.0, "Input preview looks like JSON.")
    if "\n" in trimmed and ":" in trimmed and "{" not in trimmed[:80]:
        _add_score(scores, reasons, "yaml", 2.0, "Input preview resembles YAML key/value text.")
    if "=" in trimmed and "\n" in trimmed:
        _add_score(scores, reasons, "ini", 1.5, "Input preview resembles INI or config text.")
    if "," in trimmed and "\n" in trimmed:
        _add_score(scores, reasons, "csv", 1.5, "Input preview resembles CSV rows.")


def _detect_by_code(code: str, project_name: str, function_name: str, scores: dict[str, float], reasons: dict[str, list[str]]) -> None:
    haystack = f"{project_name}\n{function_name}\n{code}".lower()
    api_patterns = {
        "xml": [
            r"\bxml",
            r"xmlelement",
            r"xmlutil",
            r"parse\s*\(",
        ],
        "json": [
            r"\bjson",
            r"cjson",
            r"parsewithopts",
            r"json_parse",
        ],
        "yaml": [r"\byaml"],
        "toml": [r"\btoml"],
        "ini": [r"\bini\b", r"config"],
        "csv": [r"\bcsv\b"],
        "png": [r"\bpng\b", r"png_sig_cmp", r"png_read"],
        "jpeg": [r"\bjpeg\b", r"\bjpg\b", r"jpeg_"],
        "tiff": [r"\btiff\b", r"tif_", r"tiffread"],
    }
    for family, patterns in api_patterns.items():
        for pattern in patterns:
            if re.search(pattern, haystack):
                _add_score(scores, reasons, family, 2.0, f"Code or symbol names mention {family}-specific APIs.")
                break

    text_cues = [
        r"consumestring",
        r"stringview",
        r"std::string",
        r"char\s*\*",
        r"fuzzeddataprovider",
    ]
    if any(re.search(pattern, haystack) for pattern in text_cues):
        _add_score(scores, reasons, "plain_text", 1.0, "Fuzz target appears to consume string-like data.")


def infer_input_format(
    project_name: str,
    function_name: str,
    fuzz_target_code: str,
    source_code: str,
    triggering_input_path: str | None,
    triggering_input_preview: str,
) -> FormatInfo:
    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    _detect_by_extension(triggering_input_path, scores, reasons)
    _detect_by_text(triggering_input_preview or "", scores, reasons)
    _detect_by_code(f"{fuzz_target_code}\n{source_code}", project_name, function_name, scores, reasons)

    if not scores:
        return FormatInfo(reasoning=["No strong format signal found; defaulting to raw binary seeds."])

    family = max(scores, key=scores.get)
    confidence = min(0.99, 0.25 + (scores[family] / max(8.0, scores[family] + 2.0)))
    presets = {
        "xml": dict(mime_hint="application/xml", is_text=True, extensions=[".xml"], encoding="utf-8", container_style="single-document", features=["nested-elements", "attributes", "text-nodes"]),
        "json": dict(mime_hint="application/json", is_text=True, extensions=[".json"], encoding="utf-8", container_style="single-document", features=["objects", "arrays", "numbers", "strings"]),
        "yaml": dict(mime_hint="application/yaml", is_text=True, extensions=[".yaml", ".yml"], encoding="utf-8", container_style="single-document", features=["mappings", "sequences", "scalars"]),
        "toml": dict(mime_hint="application/toml", is_text=True, extensions=[".toml"], encoding="utf-8", container_style="single-document", features=["tables", "key-value", "numbers"]),
        "ini": dict(mime_hint="text/plain", is_text=True, extensions=[".ini", ".cfg"], encoding="utf-8", container_style="single-document", features=["sections", "key-value"]),
        "csv": dict(mime_hint="text/csv", is_text=True, extensions=[".csv"], encoding="utf-8", container_style="row-based", features=["rows", "columns", "delimiters"]),
        "plain_text": dict(mime_hint="text/plain", is_text=True, extensions=[".txt"], encoding="utf-8", container_style="single-document", features=["free-form-text"]),
        "png": dict(mime_hint="image/png", is_text=False, extensions=[".png"], encoding="binary", container_style="chunked-binary", features=["magic-bytes", "chunks", "crc"]),
        "jpeg": dict(mime_hint="image/jpeg", is_text=False, extensions=[".jpg", ".jpeg"], encoding="binary", container_style="marker-stream", features=["magic-bytes", "segments"]),
        "tiff": dict(mime_hint="image/tiff", is_text=False, extensions=[".tiff", ".tif"], encoding="binary", container_style="tagged-binary", features=["magic-bytes", "endianness", "ifd-entries"]),
        "raw_binary": dict(mime_hint="application/octet-stream", is_text=False, extensions=[".bin"], encoding="binary", container_style="single-blob", features=["opaque-bytes"]),
    }
    preset = presets.get(family, presets["raw_binary"])
    return FormatInfo(
        format_family=family,
        mime_hint=preset["mime_hint"],
        is_text=preset["is_text"],
        extensions=list(preset["extensions"]),
        encoding=preset["encoding"],
        container_style=preset["container_style"],
        features=list(preset["features"]),
        confidence=confidence,
        reasoning=reasons.get(family, []),
    )
