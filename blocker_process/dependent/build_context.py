from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OSS_FUZZ_OUT = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out"

C_EXTENSIONS = {".c"}
CXX_EXTENSIONS = {
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
    ".cp",
    ".hpp",
    ".hh",
    ".hxx",
    ".h++",
}
HEADER_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".h++"}
NOISE_PATH_MARKERS = (
    "/test/",
    "/tests/",
    "/testprogs/",
    "/example/",
    "/examples/",
    "/benchmark/",
    "/rpcapd/",
)
MAX_FILES_PER_GUIDED_DIR = 10
MAX_OPTIONAL_SOURCES = 24


def path_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in C_EXTENSIONS:
        return "c"
    if suffix in CXX_EXTENSIONS:
        return "c++"
    raise ValueError(f"Unsupported source extension for {path}")


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _resolve_source_path(project_name: str | None, raw_path: str | Path | None) -> Path | None:
    if not raw_path:
        return None

    direct = _safe_resolve(Path(str(raw_path)))
    if direct.is_file():
        return direct

    normalized = str(raw_path).replace("\\", "/").strip()
    if not normalized:
        return None

    candidates: list[Path] = []
    if project_name:
        if normalized.startswith("/src/"):
            relative = normalized.lstrip("/")
            candidates.extend(
                [
                    OSS_FUZZ_OUT / project_name / relative,
                    OSS_FUZZ_OUT / project_name / "inspector" / "source-code" / relative,
                ]
            )
        elif "/inspector/source-code/" in normalized:
            inner = normalized.split("/inspector/source-code/", 1)[1].lstrip("/")
            candidates.extend(
                [
                    OSS_FUZZ_OUT / project_name / "inspector" / "source-code" / inner,
                    OSS_FUZZ_OUT / project_name / "src" / inner,
                ]
            )
        elif "/src/" in normalized:
            inner = normalized.split("/src/", 1)[1].lstrip("/")
            candidates.extend(
                [
                    OSS_FUZZ_OUT / project_name / "src" / inner,
                    OSS_FUZZ_OUT / project_name / "inspector" / "source-code" / inner,
                ]
            )

    for candidate in candidates:
        resolved = _safe_resolve(candidate)
        if resolved.is_file():
            return resolved
    return None


def _resolve_project_source_root(project_name: str | None, seed_paths: list[Path]) -> Path | None:
    if project_name:
        candidates = [
            OSS_FUZZ_OUT / project_name / "src" / project_name,
            OSS_FUZZ_OUT / project_name / "source_code",
            OSS_FUZZ_OUT / project_name / project_name / "source_code",
            OSS_FUZZ_OUT / project_name / "src",
        ]
        for candidate in candidates:
            resolved = _safe_resolve(candidate)
            if resolved.is_dir():
                return resolved

    for seed_path in seed_paths:
        for parent in [seed_path.parent, *seed_path.parents]:
            resolved = _safe_resolve(parent)
            if not resolved.is_dir():
                continue
            if resolved.name == "src":
                return resolved
            if (resolved / "include").is_dir():
                return resolved
    return None


def _looks_like_noise_source(path: Path) -> bool:
    lowered = path.as_posix().lower()
    if any(marker in lowered for marker in NOISE_PATH_MARKERS):
        return True
    if path.name.startswith("fuzz_") or path.name.startswith("fuzz-"):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if re.search(r"\bint\s+main\s*\(", text):
        return True
    if "LLVMFuzzerTestOneInput" in text:
        return True
    return False


def _derive_module_token(path: Path) -> str:
    stem = path.stem.lower()
    for separator in ("_", "-", "."):
        if separator in stem:
            return stem.split(separator, 1)[0]
    return stem


def _collect_guided_sources(
    *,
    source_root: Path | None,
    involved_sources: list[Path],
    excluded: set[Path],
) -> list[Path]:
    guided_dirs: list[Path] = []
    for source in involved_sources:
        for directory in (source.parent, source.parent.parent):
            resolved = _safe_resolve(directory)
            if resolved.is_dir() and resolved not in guided_dirs:
                guided_dirs.append(resolved)

    optional: list[Path] = []
    seen: set[Path] = set()
    module_tokens = {_derive_module_token(path) for path in involved_sources}

    for directory in guided_dirs:
        if len(optional) >= MAX_OPTIONAL_SOURCES:
            break
        try:
            children = sorted(directory.iterdir())
        except OSError:
            continue
        local_count = 0
        for child in children:
            resolved = _safe_resolve(child)
            if not resolved.is_file():
                continue
            if resolved in excluded or resolved in seen:
                continue
            if resolved.suffix.lower() not in C_EXTENSIONS | CXX_EXTENSIONS:
                continue
            if _looks_like_noise_source(resolved):
                continue
            if _derive_module_token(resolved) not in module_tokens and directory not in {path.parent for path in involved_sources}:
                continue
            seen.add(resolved)
            optional.append(resolved)
            local_count += 1
            if local_count >= MAX_FILES_PER_GUIDED_DIR or len(optional) >= MAX_OPTIONAL_SOURCES:
                break

    if source_root and len(optional) < MAX_OPTIONAL_SOURCES:
        for include_dir in sorted(source_root.rglob("include")):
            parent = _safe_resolve(include_dir.parent)
            if not parent.is_dir() or parent in guided_dirs:
                continue
            for candidate in sorted(parent.iterdir()):
                resolved = _safe_resolve(candidate)
                if not resolved.is_file():
                    continue
                if resolved in excluded or resolved in seen:
                    continue
                if resolved.suffix.lower() not in C_EXTENSIONS | CXX_EXTENSIONS:
                    continue
                if _looks_like_noise_source(resolved):
                    continue
                seen.add(resolved)
                optional.append(resolved)
                if len(optional) >= MAX_OPTIONAL_SOURCES:
                    break
            if len(optional) >= MAX_OPTIONAL_SOURCES:
                break

    return optional


def _discover_include_dirs(
    *,
    source_root: Path | None,
    explicit_include_dirs: list[Path],
    related_paths: list[Path],
) -> list[Path]:
    include_dirs: list[Path] = []

    def add(path: Path | None) -> None:
        if not path:
            return
        resolved = _safe_resolve(path)
        if not resolved.exists() or not resolved.is_dir():
            return
        if resolved not in include_dirs:
            include_dirs.append(resolved)

    for include_dir in explicit_include_dirs:
        add(include_dir)

    if source_root:
        add(source_root)
        if source_root.parent.name == "src":
            add(source_root.parent)
        for path in sorted(source_root.rglob("include")):
            add(path)

    for related in related_paths:
        add(related.parent)
        add(related.parent.parent if related.parent.parent != related.parent else None)

    return include_dirs


@dataclass(slots=True)
class BuildContext:
    project_name: str | None
    mode: str
    target_source: str | None
    branch_source: str
    harness_source: str | None
    source_root: str | None
    language: str
    sources: list[str] = field(default_factory=list)
    required_sources: list[str] = field(default_factory=list)
    optional_sources: list[str] = field(default_factory=list)
    include_dirs: list[str] = field(default_factory=list)
    defines: list[str] = field(default_factory=list)
    cflags: str = ""
    cxxflags: str = ""
    ldflags: str = ""
    selection_reason: str = ""
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def write_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, payload: dict) -> "BuildContext":
        return cls(
            project_name=payload.get("project_name"),
            mode=str(payload.get("mode") or "original_target"),
            target_source=payload.get("target_source"),
            branch_source=str(payload.get("branch_source") or ""),
            harness_source=payload.get("harness_source"),
            source_root=payload.get("source_root"),
            language=str(payload.get("language") or "c++"),
            sources=[str(item) for item in payload.get("sources", [])],
            required_sources=[str(item) for item in payload.get("required_sources", [])],
            optional_sources=[str(item) for item in payload.get("optional_sources", [])],
            include_dirs=[str(item) for item in payload.get("include_dirs", [])],
            defines=[str(item) for item in payload.get("defines", [])],
            cflags=str(payload.get("cflags") or ""),
            cxxflags=str(payload.get("cxxflags") or ""),
            ldflags=str(payload.get("ldflags") or ""),
            selection_reason=str(payload.get("selection_reason") or ""),
            diagnostics=[str(item) for item in payload.get("diagnostics", [])],
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "BuildContext":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @property
    def compilation_sources(self) -> list[Path]:
        seen: set[Path] = set()
        ordered: list[Path] = []
        for raw in [*self.required_sources, *self.optional_sources]:
            resolved = _safe_resolve(Path(raw))
            if resolved in seen:
                continue
            seen.add(resolved)
            ordered.append(resolved)
        return ordered


def reconstruct_build_context(
    *,
    project_name: str | None,
    mode: str,
    target_source: str | Path | None,
    branch_source: str | Path,
    harness_source: str | Path | None = None,
    explicit_sources: list[str] | None = None,
    explicit_include_dirs: list[str] | None = None,
    defines: list[str] | None = None,
    cflags: str = "",
    cxxflags: str = "",
    ldflags: str = "",
    header_file: str | Path | None = None,
) -> BuildContext:
    target_path = _resolve_source_path(project_name, target_source)
    branch_path = _resolve_source_path(project_name, branch_source)
    harness_path = _resolve_source_path(project_name, harness_source) if harness_source else None
    header_path = _resolve_source_path(project_name, header_file) if header_file else None
    if branch_path is None:
        raise FileNotFoundError(f"Branch source file not found: {branch_source}")

    explicit_source_paths = [
        path
        for path in (_resolve_source_path(project_name, raw) for raw in (explicit_sources or []))
        if path is not None
    ]
    explicit_include_paths = [
        _safe_resolve(Path(raw))
        for raw in (explicit_include_dirs or [])
        if raw and _safe_resolve(Path(raw)).is_dir()
    ]

    related_for_roots = [path for path in [target_path, branch_path, harness_path, header_path, *explicit_source_paths] if path]
    source_root = _resolve_project_source_root(project_name, related_for_roots)

    required: list[Path] = []
    diagnostics: list[str] = []
    if mode == "generated_harness" and harness_path is not None:
        required.append(harness_path)
        diagnostics.append("Using generated harness as the primary compilation unit.")
    elif target_path is not None:
        required.append(target_path)
        diagnostics.append("Using original fuzz target as the primary compilation unit.")

    if branch_path not in required:
        required.append(branch_path)
        diagnostics.append("Keeping blocker branch source as a required compilation unit.")

    for source in explicit_source_paths:
        if source not in required:
            required.append(source)

    excluded = set(required)
    optional = _collect_guided_sources(
        source_root=source_root,
        involved_sources=required if required else [branch_path],
        excluded=excluded,
    )
    if explicit_source_paths:
        optional = [path for path in explicit_source_paths if path not in excluded]
        diagnostics.append("Using caller-provided source list instead of guided source discovery.")
    else:
        diagnostics.append(
            f"Guided source discovery selected {len(optional)} optional source(s) near blocker-relevant directories."
        )

    include_dirs = _discover_include_dirs(
        source_root=source_root,
        explicit_include_dirs=explicit_include_paths,
        related_paths=[path for path in [branch_path, target_path, harness_path, header_path, *required, *optional] if path],
    )
    diagnostics.append(f"Resolved {len(include_dirs)} include directorie(s).")

    language_inputs = [path for path in [harness_path, target_path, branch_path, *required, *optional] if path]
    use_cxx = any(path.suffix.lower() in CXX_EXTENSIONS for path in language_inputs)
    language = "c++" if use_cxx else "c"

    all_sources = [*required, *optional]
    seen_sources: set[Path] = set()
    deduped_sources: list[str] = []
    for source in all_sources:
        resolved = _safe_resolve(source)
        if resolved in seen_sources:
            continue
        seen_sources.add(resolved)
        deduped_sources.append(str(resolved))

    return BuildContext(
        project_name=project_name,
        mode=mode,
        target_source=str(target_path) if target_path else None,
        branch_source=str(branch_path),
        harness_source=str(harness_path) if harness_path else None,
        source_root=str(source_root) if source_root else None,
        language=language,
        sources=deduped_sources,
        required_sources=[str(_safe_resolve(path)) for path in required],
        optional_sources=[str(_safe_resolve(path)) for path in optional if path not in required],
        include_dirs=[str(path) for path in include_dirs],
        defines=list(defines or []),
        cflags=cflags,
        cxxflags=cxxflags,
        ldflags=ldflags,
        selection_reason=(
            "Shared build context reconstructed from blocker branch source, primary target/harness, "
            "and a low-cost guided neighborhood source selection."
        ),
        diagnostics=diagnostics,
    )
