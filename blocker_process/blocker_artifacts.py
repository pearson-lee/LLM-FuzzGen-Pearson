from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_SAFE_FRAGMENT_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def sanitize_artifact_fragment(value: object, *, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    safe = _SAFE_FRAGMENT_RE.sub("_", text).strip("._-")
    return safe or fallback


def short_sha256(value: object, *, length: int = 12) -> str:
    return hashlib.sha256(str(value or "unknown").encode("utf-8")).hexdigest()[:length]


def blocker_artifact_id(function_name: object, branch_line_number: object, *, prefix: str = "blocker") -> str:
    line = sanitize_artifact_fragment(branch_line_number, fallback="0")
    return f"{prefix}_{line}_{short_sha256(function_name)}"


def blocker_stage_artifact_name(
    project_name: object,
    function_name: object,
    branch_line_number: object,
    timestamp: str | None,
    *extra_parts: object,
) -> str:
    parts = [
        sanitize_artifact_fragment(project_name),
        blocker_artifact_id(function_name, branch_line_number),
    ]
    parts.extend(sanitize_artifact_fragment(part) for part in extra_parts if part not in (None, ""))
    if timestamp:
        parts.append(sanitize_artifact_fragment(timestamp))
    return "_".join(parts)


def blocker_log_filename(
    function_name: object,
    branch_line_number: object,
    timestamp: str,
    *extra_parts: object,
) -> str:
    parts = [timestamp, blocker_artifact_id(function_name, branch_line_number)]
    parts.extend(sanitize_artifact_fragment(part) for part in extra_parts if part not in (None, ""))
    return "_".join(parts) + ".log"


def write_blocker_metadata(
    artifact_dir: Path,
    *,
    blocker_id: str,
    project_name: object,
    function_name: object,
    branch_line_number: object,
    blocked_side_line_number: object | None = None,
    source_file: object | None = None,
    target_name: object | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "blocker_id": blocker_id,
        "project_name": project_name,
        "function_name": function_name,
        "branch_line_number": branch_line_number,
        "blocked_side_line_number": blocked_side_line_number,
        "source_file": source_file,
        "target_name": target_name,
    }
    if extra:
        payload.update(extra)
    metadata_path = artifact_dir / "blocker_metadata.json"
    metadata_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return metadata_path
