#!/usr/bin/env python3
"""Build and run a SymCC-assisted blocker solver for libFuzzer-style targets.

This utility accepts C/C++ fuzz target code plus dependent source files,
replays seed inputs through a generated driver, lets SymCC derive alternative
inputs, and uses llvm-cov to check whether any discovered input reaches the
blocked side of a branch.

The target side is identified by `--blocked-side-line`, which should point to
the first executable line inside the side you want to unlock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, TypeVar


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SYMCC = REPO_ROOT / "symcc" / "build" / "symcc"
DEFAULT_SYMPP = REPO_ROOT / "symcc" / "build" / "sym++"
DEFAULT_LLVM18_ROOT = Path.home() / "tools" / "llvm-18.1.8" / "bin"
DEFAULT_LLVM_PROFDATA = str(DEFAULT_LLVM18_ROOT / "llvm-profdata")
DEFAULT_LLVM_COV = str(DEFAULT_LLVM18_ROOT / "llvm-cov")

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.dependent.build_context import BuildContext

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


@dataclass(slots=True)
class CoverageResult:
    seed: Path
    branch_hit_count_raw: str
    blocked_side_hit_count_raw: str
    branch_hit_count: int
    blocked_side_hit_count: int
    blocked_side_line_reached: bool


class CoverageOracleError(RuntimeError):
    """Coverage measurement failed before it could classify a candidate seed."""

    def __init__(self, kind: str, message: str, *, systemic: bool = False) -> None:
        super().__init__(message)
        self.kind = kind
        self.systemic = systemic


@dataclass(slots=True)
class CandidateEvaluation:
    seed: Path
    coverage: CoverageResult | None
    status: str
    error_kind: str | None = None
    error: str | None = None


@dataclass(slots=True)
class SymCCExplorationResult:
    corpus: list[Path]
    evaluations: list[CandidateEvaluation]
    solved: CoverageResult | None
    stop_reason: str
    generations_completed: int
    symcc_executions: int
    outputs_discovered: int
    candidate_evaluations: int
    retained_seed_count: int
    oracle_errors: dict[str, int]
    elapsed_seconds: float
    candidate_eval_budget: int
    retention_limit: int
    initial_frontier_cap: int
    deadline_seconds: float

    def to_json_dict(self) -> dict[str, object]:
        outcome_counts = {
            "blocked_side": 0,
            "branch": 0,
            "coverage_unknown": 0,
            "non_branch": 0,
        }
        for candidate in self.evaluations:
            if candidate.coverage and candidate.coverage.blocked_side_line_reached:
                outcome_counts["blocked_side"] += 1
            elif candidate.coverage and candidate.coverage.branch_hit_count > 0:
                outcome_counts["branch"] += 1
            elif candidate.status == "coverage_unknown":
                outcome_counts["coverage_unknown"] += 1
            else:
                outcome_counts["non_branch"] += 1
        return {
            "stop_reason": self.stop_reason,
            "generations_completed": self.generations_completed,
            "symcc_executions": self.symcc_executions,
            "outputs_discovered": self.outputs_discovered,
            "candidate_evaluations": self.candidate_evaluations,
            "retained_seed_count": self.retained_seed_count,
            "oracle_errors": self.oracle_errors,
            "outcome_counts": outcome_counts,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "budgets": {
                "candidate_evaluations": self.candidate_eval_budget,
                "next_generation_retention": self.retention_limit,
                "initial_frontier": self.initial_frontier_cap,
                "deadline_seconds": self.deadline_seconds,
            },
            "solved_seed": str(self.solved.seed) if self.solved else None,
        }


T = TypeVar("T")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a libFuzzer-style target with SymCC, explore from given seeds, "
            "and find an input that crosses a blocked branch side."
        )
    )
    parser.add_argument("--fuzz-target", required=True, help="Path to the fuzz target source containing LLVMFuzzerTestOneInput.")
    parser.add_argument(
        "--build-context-file",
        default=None,
        help="Optional shared build-context manifest. When present, SymCC build inputs are loaded from this file.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Additional source file. Repeat this option for multiple files.",
    )
    parser.add_argument(
        "--include-dir",
        action="append",
        default=[],
        help="Additional include directory. Repeat this option for multiple paths.",
    )
    parser.add_argument(
        "--define",
        action="append",
        default=[],
        help="Preprocessor define, for example NAME=value. Repeat this option as needed.",
    )
    parser.add_argument("--branch-source", required=True, help="Source file used for the blocker branch.")
    parser.add_argument(
        "--coverage-source",
        default=None,
        help="Source path identity embedded in the coverage binary; defaults to --branch-source.",
    )
    parser.add_argument("--branch-line", required=True, type=int, help="Line number of the blocker condition.")
    parser.add_argument(
        "--blocked-side-line",
        required=True,
        type=int,
        help="First executable line inside the branch side that should become reachable.",
    )
    parser.add_argument(
        "--seed",
        action="append",
        default=[],
        help="Initial seed file. Repeat this option for multiple files.",
    )
    parser.add_argument(
        "--fidelity-seed",
        default=None,
        help="Previously branch-reaching seed used to verify a generated harness preserves the blocker path.",
    )
    parser.add_argument(
        "--fidelity-only",
        action="store_true",
        help="Exit after generated-harness fidelity validation without running SymCC.",
    )
    parser.add_argument("--seed-dir", default=None, help="Directory containing initial seed files.")
    parser.add_argument(
        "--target-args",
        default="@@",
        help='Arguments passed to the replay binary. Use "@@" where the seed path should be substituted. Default: "@@".',
    )
    parser.add_argument(
        "--input-mode",
        choices=("file", "stdin"),
        default="file",
        help="How the replay driver should feed input into the fuzz target. Default: file.",
    )
    parser.add_argument("--work-dir", default=None, help="Directory to store build outputs and generated seeds.")
    parser.add_argument("--max-generations", type=int, default=3, help="Maximum SymCC exploration generations.")
    parser.add_argument(
        "--max-total-seeds",
        type=int,
        default=60,
        help="Deprecated compatibility alias for --max-retained-seeds.",
    )
    parser.add_argument(
        "--max-candidate-evaluations",
        type=int,
        default=200,
        help="Cumulative number of generated candidates that the coverage oracle may replay.",
    )
    parser.add_argument(
        "--max-retained-seeds",
        type=int,
        default=None,
        help="Maximum number of candidates retained as the next SymCC frontier. Defaults to --max-total-seeds.",
    )
    parser.add_argument(
        "--initial-frontier-cap",
        type=int,
        default=30,
        help="Maximum number of initial seeds used as the first SymCC frontier.",
    )
    parser.add_argument("--timeout-sec", type=int, default=30, help="Timeout for each target execution.")
    parser.add_argument("--wall-clock-budget-sec", type=int, default=300, help="Total wall-clock budget for SymCC exploration and online coverage replay. 0 means no limit.")
    parser.add_argument("--ossfuzz-supplement-corpus-dir", default=None, help="OSS-Fuzz corpus dir to scan for branch-reaching binary seeds when initial corpus is sparse (<4 seeds).")
    parser.add_argument("--export-solved-seed-dir", default=None, help="Directory to receive the best blocked-side-reaching seed after a successful original-target solve.")
    parser.add_argument("--symcc", default=str(DEFAULT_SYMCC), help=f"Path to symcc. Default: {DEFAULT_SYMCC}")
    parser.add_argument("--sympp", default=str(DEFAULT_SYMPP), help=f"Path to sym++. Default: {DEFAULT_SYMPP}")
    parser.add_argument("--clang", default="clang", help="Path to clang for the coverage build.")
    parser.add_argument("--clangxx", default="clang++", help="Path to clang++ for the coverage build.")
    parser.add_argument(
        "--llvm-profdata",
        default=os.environ.get("LLVM_PROFDATA", DEFAULT_LLVM_PROFDATA),
        help="Path to llvm-profdata used to merge coverage profiles.",
    )
    parser.add_argument(
        "--llvm-cov",
        default=os.environ.get("LLVM_COV", DEFAULT_LLVM_COV),
        help="Path to llvm-cov used to inspect line coverage.",
    )
    parser.add_argument(
        "--coverage-binary",
        default=None,
        help="Optional prebuilt coverage-instrumented target binary to reuse for seed validation.",
    )
    parser.add_argument(
        "--prebuilt-archive",
        action="append",
        default=[],
        help="Optional prebuilt static archive to link against instead of reconstructing project source closure.",
    )
    parser.add_argument(
        "--native-include-dir",
        action="append",
        default=[],
        help="Additional include directory for native-archive build mode.",
    )
    parser.add_argument("--cflags", default="", help="Extra C compiler flags, passed to both builds.")
    parser.add_argument("--cxxflags", default="", help="Extra C++ compiler flags, passed to both builds.")
    parser.add_argument("--ldflags", default="", help="Extra linker flags, passed to both builds.")
    parser.add_argument("--keep-coverage-reports", action="store_true", help="Keep llvm-cov reports for all evaluated seeds.")
    return parser.parse_args()


def log(message: str) -> None:
    print(message, flush=True)


def ensure_tool(path_or_name: str) -> str:
    resolved = shutil.which(path_or_name)
    if resolved:
        return resolved

    candidate = Path(path_or_name)
    if candidate.exists():
        return str(candidate.resolve())

    raise FileNotFoundError(f"Required tool not found: {path_or_name}")


def normalize_count(raw: str) -> int:
    raw = raw.strip()
    if not raw or raw == "0":
        return 0

    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kMGT]?)", raw)
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


def get_line_execution_count(report: str, line_no: int) -> str:
    target_prefix = f"{line_no}|"
    for line in report.splitlines():
        if line.lstrip().startswith(target_prefix):
            parts = line.split("|", 2)
            if len(parts) >= 2:
                return parts[1].strip()
    return ""


def _normalized_source_line(path: Path, line_no: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if line_no < 1 or line_no > len(lines):
        return ""
    return " ".join(lines[line_no - 1].strip().split())


def _path_matches_source_identity(path_text: str, source_names: set[str], source_suffixes: set[str]) -> bool:
    normalized = path_text.strip().rstrip(":").replace("\\", "/")
    if not normalized:
        return False
    path_name = Path(normalized).name
    if path_name in source_names:
        return True
    if any(path_name.endswith(f"_{name}") for name in source_names):
        return True
    return any(normalized.endswith(suffix) for suffix in source_suffixes if suffix)


def get_line_execution_count_for_source(
    report: str,
    line_no: int,
    *,
    branch_source: Path,
    coverage_source: str | None,
) -> str:
    """Find a line count in an unfiltered llvm-cov report without trusting order."""
    source_names = {branch_source.name}
    source_suffixes = {str(branch_source).replace("\\", "/")}
    if coverage_source:
        coverage_path = Path(coverage_source)
        source_names.add(coverage_path.name)
        source_suffixes.add(str(coverage_path).replace("\\", "/"))

    expected_line = _normalized_source_line(branch_source, line_no)
    target_prefix = f"{line_no}|"
    current_source = ""
    matches: list[str] = []

    for raw_line in report.splitlines():
        stripped = raw_line.strip()
        if stripped.endswith(":") and "|" not in raw_line:
            current_source = stripped[:-1]
            continue
        if not raw_line.lstrip().startswith(target_prefix):
            continue

        parts = raw_line.split("|", 2)
        if len(parts) < 2:
            continue
        count = parts[1].strip()
        rendered_source = " ".join(parts[2].strip().split()) if len(parts) >= 3 else ""
        source_matches = _path_matches_source_identity(current_source, source_names, source_suffixes)
        line_matches = bool(expected_line and rendered_source and expected_line == rendered_source)
        if source_matches or line_matches:
            matches.append(count)

    return matches[0] if len(matches) == 1 else ""


def coverage_source_args(branch_source: Path, coverage_source: str | None) -> list[str]:
    """Map the binary's source identity to the local source mirror for llvm-cov."""
    local_source = branch_source.resolve()
    if not coverage_source:
        return [str(local_source)]

    embedded_source = Path(coverage_source)
    if embedded_source == local_source:
        return [str(local_source)]

    embedded_parts = embedded_source.parts
    local_parts = local_source.parts
    common_suffix = 0
    for embedded_part, local_part in zip(reversed(embedded_parts), reversed(local_parts)):
        if embedded_part != local_part:
            break
        common_suffix += 1

    # Even filename-only matches are useful for generated harness sessions: the
    # coverage binary can embed /src/project/file.c while the local mirror is a
    # flat source_root/file.c.
    if common_suffix >= 1:
        embedded_root = Path(*embedded_parts[:-common_suffix])
        local_root = Path(*local_parts[:-common_suffix])
        if str(embedded_root) and str(local_root):
            return [
                f"-path-equivalence={embedded_root},{local_root}",
                str(local_source),
            ]

    return [str(local_source)]


def path_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in C_EXTENSIONS:
        return "c"
    if suffix in CXX_EXTENSIONS:
        return "c++"
    raise ValueError(f"Unsupported source extension for {path}")


def replay_driver_source(language: str) -> str:
    extern_decl = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);' if language == "c++" else "int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);"
    return f"""#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

{extern_decl}

static int read_all_bytes(FILE* input, uint8_t** data, size_t* size) {{
    size_t capacity = 4096;
    size_t used = 0;
    uint8_t* buffer = NULL;

    if (!data || !size) {{
        return 0;
    }}

    buffer = (uint8_t*)malloc(capacity);
    if (!buffer) {{
        return 0;
    }}

    for (;;) {{
        if (used == capacity) {{
            size_t next_capacity = capacity * 2;
            uint8_t* next = (uint8_t*)realloc(buffer, next_capacity);
            if (!next) {{
                free(buffer);
                return 0;
            }}
            buffer = next;
            capacity = next_capacity;
        }}

        size_t count = fread(buffer + used, 1, capacity - used, input);
        used += count;

        if (count == 0) {{
            if (feof(input)) {{
                break;
            }}
            free(buffer);
            return 0;
        }}
    }}

    *data = buffer;
    *size = used;
    return 1;
}}

int main(int argc, char** argv) {{
    FILE* input = stdin;
    uint8_t* data = NULL;
    size_t size = 0;
    int result = 0;

    if (argc > 2) {{
        fprintf(stderr, "usage: %s [seed-file]\\n", argv[0]);
        return 1;
    }}

    if (argc == 2) {{
        input = fopen(argv[1], "rb");
        if (!input) {{
            perror("fopen");
            return 1;
        }}
    }}

    if (!read_all_bytes(input, &data, &size)) {{
        fprintf(stderr, "failed to read input\\n");
        if (argc == 2) {{
            fclose(input);
        }}
        return 1;
    }}

    if (argc == 2) {{
        fclose(input);
    }}

    result = LLVMFuzzerTestOneInput(data, size);
    free(data);
    return result;
}}
"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seed_name(seed_hash: str, source_path: Path) -> str:
    suffix = source_path.suffix if source_path.suffix else ".bin"
    return f"{seed_hash}{suffix}"


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    stdin_path: Path | None = None,
    timeout_sec: int | None = None,
) -> subprocess.CompletedProcess[str]:
    stdin_handle = None
    try:
        if stdin_path is not None:
            stdin_handle = stdin_path.open("rb")
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=stdin_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
    finally:
        if stdin_handle is not None:
            stdin_handle.close()


_SIMPLE_BACKEND_ASSIGNMENT_RE = re.compile(
    r"^stdin(?P<offset>\d+)\s*->\s*(?P<value>#x[0-9a-fA-F]+|#b[01]+|\d+)\s*$"
)


def _parse_simple_backend_byte(value: str) -> int | None:
    if value.startswith("#x"):
        parsed = int(value[2:], 16)
    elif value.startswith("#b"):
        parsed = int(value[2:], 2)
    else:
        parsed = int(value, 10)
    if parsed < 0 or parsed > 0xFF:
        return None
    return parsed


def parse_symcc_simple_backend_models(output: str) -> list[dict[int, int]]:
    """Parse simple-backend solver models printed as stdin byte assignments."""
    models: list[dict[int, int]] = []
    current: dict[int, int] | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Found diverging input:":
            if current:
                models.append(current)
            current = {}
            continue
        if current is None:
            continue
        if not stripped:
            if current:
                models.append(current)
            current = None
            continue

        match = _SIMPLE_BACKEND_ASSIGNMENT_RE.match(stripped)
        if not match:
            continue
        byte_value = _parse_simple_backend_byte(match.group("value"))
        if byte_value is None:
            continue
        current[int(match.group("offset"))] = byte_value

    if current:
        models.append(current)
    return models


def materialize_symcc_simple_backend_outputs(
    *,
    seed_path: Path,
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
) -> int:
    """Convert simple-backend stderr models into seed files.

    QSYM writes candidate inputs into SYMCC_OUTPUT_DIR. The simple backend only
    prints the solved byte assignments, so we patch those assignments onto the
    current seed and let the normal output collector consume the materialized
    files.
    """
    solver_output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    models = parse_symcc_simple_backend_models(solver_output)
    if not models:
        return 0

    original = seed_path.read_bytes()
    written_payloads: set[bytes] = set()
    written = 0
    for index, model in enumerate(models):
        if not model:
            continue
        candidate = bytearray(original)
        max_offset = max(model)
        if max_offset >= len(candidate):
            candidate.extend(b"\0" * (max_offset + 1 - len(candidate)))
        for offset, byte_value in model.items():
            candidate[offset] = byte_value

        payload = bytes(candidate)
        if payload in written_payloads:
            continue
        written_payloads.add(payload)
        digest = hashlib.sha256(payload).hexdigest()
        (output_dir / f"simple-{index:06d}-{digest[:12]}.seed").write_bytes(payload)
        written += 1
    return written


def collect_seed_paths(seed_files: list[str], seed_dir: str | None) -> list[Path]:
    paths = [Path(seed).resolve() for seed in seed_files]
    if seed_dir:
        seed_dir_path = Path(seed_dir).resolve()
        if not seed_dir_path.is_dir():
            raise FileNotFoundError(f"Seed directory not found: {seed_dir_path}")
        paths.extend(sorted(path for path in seed_dir_path.iterdir() if path.is_file()))

    unique_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"Seed file not found: {path}")
        if path in seen:
            continue
        seen.add(path)
        unique_paths.append(path)
    return unique_paths


def add_seed_to_corpus(seed_path: Path, corpus_dir: Path, known_hashes: set[str]) -> Path | None:
    seed_hash = sha256_file(seed_path)
    if seed_hash in known_hashes:
        return None

    known_hashes.add(seed_hash)
    dest = corpus_dir / seed_name(seed_hash, seed_path)
    shutil.copy2(seed_path, dest)
    return dest


def export_solved_seed(seed_path: Path, export_dir: Path) -> dict:
    export_dir.mkdir(parents=True, exist_ok=True)
    existing_by_hash = {sha256_file(path): path for path in sorted(export_dir.iterdir()) if path.is_file()}
    seed_hash = sha256_file(seed_path)
    dest = export_dir / seed_name(seed_hash, seed_path)
    if seed_hash in existing_by_hash:
        return {
            "exported": False,
            "duplicate": True,
            "seed_path": str(seed_path),
            "export_dir": str(export_dir),
            "dest_path": str(existing_by_hash[seed_hash]),
            "sha256": seed_hash,
        }
    shutil.copy2(seed_path, dest)
    return {
        "exported": True,
        "duplicate": False,
        "seed_path": str(seed_path),
        "export_dir": str(export_dir),
        "dest_path": str(dest),
        "sha256": seed_hash,
    }


def write_replay_driver(work_dir: Path, driver_language: str) -> Path:
    extension = ".cpp" if driver_language == "c++" else ".c"
    driver_path = work_dir / f"symcc_replay_driver{extension}"
    driver_path.write_text(replay_driver_source(driver_language), encoding="utf-8")
    return driver_path


def normalize_include_for_symcc(path: str, include_dirs: list[Path]) -> str:
    """Find the correct include form for local SymCC compilation.

    Strips leading directory components of `path` one at a time and checks whether
    the resulting suffix exists under any of the include_dirs (-I search paths).
    Returns the shortest working form in angle brackets, or the bare filename as a
    double-quoted fallback when nothing is found.
    """
    parts = path.lstrip("/").split("/")
    for i in range(len(parts)):
        candidate = "/".join(parts[i:])
        for inc_dir in include_dirs:
            if (inc_dir / candidate).exists():
                return f"<{candidate}>"
    return f'"{parts[-1]}"'


def normalize_source_includes(source_text: str, include_dirs: list[Path] | None = None) -> str:
    if include_dirs:
        # Broader pattern: any double-quoted include that contains a "/" (multi-level path).
        # Excludes parent-relative "../" paths which should stay as-is.
        include_re = re.compile(
            r'^(?P<prefix>\s*#\s*include\s+")(?P<path>[^"]*[/][^"]+)(?P<suffix>")',
            re.MULTILINE,
        )

        def repl(match: re.Match[str]) -> str:
            raw_path = match.group("path").replace("\\", "/")
            if raw_path.startswith("../"):
                return match.group(0)
            normalized = normalize_include_for_symcc(raw_path, include_dirs)
            return match.group("prefix")[:-1] + normalized

    else:
        # Original narrow pattern: only Docker-absolute /src/ and /repo/ paths.
        include_re = re.compile(r'^(?P<prefix>\s*#\s*include\s+")(?P<path>/(?:src|repo)/[^"]+)(?P<suffix>")', re.MULTILINE)

        def repl(match: re.Match[str]) -> str:
            raw_path = match.group("path").replace("\\", "/")
            rewritten = raw_path.split("/")[-1]
            if raw_path.startswith("/src/"):
                rewritten = raw_path[len("/src/"):]
            elif raw_path.startswith("/repo/"):
                repo_relative = raw_path[len("/repo/"):]
                src_marker = "/src/"
                if src_marker in repo_relative:
                    rewritten = repo_relative.split(src_marker, 1)[1]
                else:
                    rewritten = repo_relative.split("/")[-1]
            return f'{match.group("prefix")}{rewritten}{match.group("suffix")}'

    return include_re.sub(repl, source_text)


def materialize_normalized_source(
    source: Path,
    normalized_source_dir: Path,
    include_dirs: list[Path] | None = None,
) -> Path:
    normalized_source_dir.mkdir(parents=True, exist_ok=True)
    path_digest = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:10]
    target = normalized_source_dir / f"{path_digest}_{source.name}"
    source_text = source.read_text(encoding="utf-8", errors="replace")
    target.write_text(normalize_source_includes(source_text, include_dirs), encoding="utf-8")
    return target


def compile_objects(
    *,
    sources: list[Path],
    object_dir: Path,
    required_sources: set[Path],
    include_dirs: list[Path],
    defines: list[str],
    common_flags: list[str],
    cflags: list[str],
    cxxflags: list[str],
    compiler_c: str,
    compiler_cxx: str,
    compiler_env: dict[str, str] | None,
) -> list[Path]:
    object_dir.mkdir(parents=True, exist_ok=True)
    objects: list[Path] = []
    include_flags = [flag for inc in include_dirs for flag in ("-I", str(inc))]
    define_flags = [f"-D{value}" for value in defines]

    for index, source in enumerate(sources):
        language = path_language(source)
        compiler = compiler_cxx if language == "c++" else compiler_c
        per_language_flags = cxxflags if language == "c++" else cflags
        object_path = object_dir / f"{index:03d}_{source.stem}.o"
        cmd = [
            compiler,
            "-c",
            str(source),
            "-o",
            str(object_path),
            *common_flags,
            *per_language_flags,
            *include_flags,
            *define_flags,
        ]
        result = run_cmd(cmd, env=compiler_env)
        if result.returncode != 0:
            if source.resolve() not in required_sources:
                log(
                    "[warn] skipping optional source due to compilation failure:\n"
                    f"  source: {source}\n"
                    f"  stderr: {result.stderr.strip() or result.stdout.strip()}"
                )
                continue
            raise RuntimeError(
                f"Compilation failed for {source}\n"
                f"command: {' '.join(shlex.quote(part) for part in cmd)}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
        objects.append(object_path)

    return objects


def link_binary(
    *,
    output_path: Path,
    objects: list[Path],
    link_flags: list[str],
    linker: str,
    env: dict[str, str] | None,
) -> None:
    cmd = [linker, *map(str, objects), "-o", str(output_path), *link_flags]
    result = run_cmd(cmd, env=env)
    if result.returncode != 0:
        raise RuntimeError(
            f"Link failed for {output_path}\n"
            f"command: {' '.join(shlex.quote(part) for part in cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def build_binaries(args: argparse.Namespace, work_dir: Path) -> tuple[Path, Path]:
    build_context = BuildContext.from_json_file(Path(args.build_context_file).resolve()) if args.build_context_file else None

    fuzz_target = Path(args.fuzz_target).resolve()
    branch_source = Path(args.branch_source).resolve()
    prebuilt_archives = [Path(path).resolve() for path in args.prebuilt_archive]
    native_include_dirs = [Path(path).resolve() for path in args.native_include_dir]
    if build_context is not None:
        source_list = build_context.compilation_sources
        include_dirs = [Path(path).resolve() for path in build_context.include_dirs]
        defines = list(build_context.defines)
        extra_cflags = shlex.split(build_context.cflags)
        extra_cxxflags = shlex.split(build_context.cxxflags)
        extra_ldflags = shlex.split(build_context.ldflags)
        log(
            "[info] loaded shared build context: "
            f"required={len(build_context.required_sources)} optional={len(build_context.optional_sources)} "
            f"include_dirs={len(build_context.include_dirs)}"
        )
    else:
        additional_sources = [Path(path).resolve() for path in args.source]
        source_list = [fuzz_target, *additional_sources]
        include_dirs = [Path(path).resolve() for path in args.include_dir]
        defines = list(args.define)
        extra_cflags = shlex.split(args.cflags)
        extra_cxxflags = shlex.split(args.cxxflags)
        extra_ldflags = shlex.split(args.ldflags)

    if prebuilt_archives:
        source_list = [fuzz_target]
        include_dirs = [*include_dirs, *native_include_dirs]
        log(
            "[info] using prebuilt native archives: "
            + ", ".join(str(path) for path in prebuilt_archives)
        )

    seen_sources: set[Path] = set()
    deduped_sources: list[Path] = []
    for source in source_list:
        if not source.is_file():
            raise FileNotFoundError(f"Source file not found: {source}")
        if source in seen_sources:
            continue
        seen_sources.add(source)
        deduped_sources.append(source)

    normalized_source_dir = work_dir / "normalized_sources"
    normalized_sources = [
        materialize_normalized_source(source, normalized_source_dir, include_dirs)
        for source in deduped_sources
    ]

    use_cxx = any(path_language(source) == "c++" for source in normalized_sources)
    driver_language = "c++" if use_cxx else "c"
    driver_path = write_replay_driver(work_dir, driver_language)
    build_sources = [driver_path, *normalized_sources]
    if build_context is not None:
        required_sources = {
            driver_path.resolve(),
            *{
                materialize_normalized_source(
                    Path(path).resolve(), normalized_source_dir, include_dirs
                ).resolve()
                for path in build_context.required_sources
            },
        }
    else:
        required_sources = {driver_path.resolve(), normalized_sources[0].resolve()}
    if prebuilt_archives:
        required_sources = {driver_path.resolve(), normalized_sources[0].resolve()}

    common_cflags = ["-g", "-O0", "-fno-omit-frame-pointer"]

    symcc = ensure_tool(args.symcc) if not args.fidelity_only else args.symcc
    sympp = ensure_tool(args.sympp) if not args.fidelity_only else args.sympp
    clang = ensure_tool(args.clang)
    clangxx = ensure_tool(args.clangxx)
    llvm_profdata = ensure_tool(args.llvm_profdata)
    llvm_cov = ensure_tool(args.llvm_cov)
    log(f"[info] coverage toolchain: llvm-profdata={llvm_profdata} llvm-cov={llvm_cov}")

    symcc_env = os.environ.copy()
    symcc_env["SYMCC_ENABLE_LINEARIZATION"] = "1"
    symcc_env["SYMCC_CLANG"] = clang
    symcc_env["SYMCC_CLANGPP"] = clangxx
    symcc_dir = Path(symcc).resolve().parent
    symcc_env["SYMCC_PASS_DIR"] = str(symcc_dir)
    symcc_runtime_dir = symcc_dir / "SymCCRuntime-prefix" / "src" / "SymCCRuntime-build"
    if symcc_runtime_dir.is_dir():
        symcc_env["SYMCC_RUNTIME_DIR"] = str(symcc_runtime_dir)
    if use_cxx:
        libcxx_install = REPO_ROOT / "libcxx_symcc_install"
        if libcxx_install.is_dir():
            symcc_env["SYMCC_LIBCXX_PATH"] = str(libcxx_install)
        else:
            symcc_env.setdefault("SYMCC_REGULAR_LIBCXX", "yes")

    symcc_obj_dir = work_dir / "build" / "symcc" / "obj"
    symcc_bin = work_dir / "build" / "symcc" / "replay_symcc"
    provided_coverage_bin = Path(args.coverage_binary).resolve() if args.coverage_binary else None
    if provided_coverage_bin is not None and not provided_coverage_bin.is_file():
        raise FileNotFoundError(f"Provided coverage binary not found: {provided_coverage_bin}")

    if not args.fidelity_only:
        symcc_objects = compile_objects(
            sources=build_sources,
            object_dir=symcc_obj_dir,
            required_sources=required_sources,
            include_dirs=include_dirs,
            defines=defines,
            common_flags=common_cflags,
            cflags=extra_cflags,
            cxxflags=extra_cxxflags,
            compiler_c=symcc,
            compiler_cxx=sympp,
            compiler_env=symcc_env,
        )
        link_binary(
            output_path=symcc_bin,
            objects=symcc_objects,
            link_flags=[*map(str, prebuilt_archives), *extra_ldflags],
            linker=sympp if use_cxx else symcc,
            env=symcc_env,
        )

    if provided_coverage_bin is not None:
        coverage_bin = provided_coverage_bin
        log(f"[info] reusing prebuilt coverage binary: {coverage_bin}")
    else:
        coverage_obj_dir = work_dir / "build" / "coverage" / "obj"
        coverage_bin = work_dir / "build" / "coverage" / "replay_cov"
        coverage_common_flags = [*common_cflags, "-fprofile-instr-generate", "-fcoverage-mapping"]
        coverage_objects = compile_objects(
            sources=build_sources,
            object_dir=coverage_obj_dir,
            required_sources=required_sources,
            include_dirs=include_dirs,
            defines=defines,
            common_flags=coverage_common_flags,
            cflags=extra_cflags,
            cxxflags=extra_cxxflags,
            compiler_c=clang,
            compiler_cxx=clangxx,
            compiler_env=None,
        )
        link_binary(
            output_path=coverage_bin,
            objects=coverage_objects,
            link_flags=["-fprofile-instr-generate", *extra_ldflags],
            linker=clangxx if use_cxx else clang,
            env=None,
        )

    if not branch_source.is_file():
        raise FileNotFoundError(f"Branch source file not found: {branch_source}")

    return symcc_bin, coverage_bin


def render_target_command(binary: Path, target_args: str, seed_path: Path) -> list[str]:
    args = shlex.split(target_args)
    if not args:
        return [str(binary)]
    return [str(binary), *[str(seed_path) if arg == "@@" else arg for arg in args]]


def run_single_seed(
    *,
    binary: Path,
    seed_path: Path,
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    env: dict[str, str] | None,
) -> subprocess.CompletedProcess[str]:
    command = render_target_command(binary, target_args, seed_path)
    seed_env = dict(env or {})
    stdin_path = seed_path if input_mode == "stdin" else None
    if input_mode == "file":
        seed_env["SYMCC_INPUT_FILE"] = str(seed_path)
    return run_cmd(command, env=seed_env, stdin_path=stdin_path, timeout_sec=timeout_sec)


def deterministic_stratified_sample(items: list[T], limit: int) -> list[T]:
    """Select deterministic positions across the full ordered input, including its tail."""
    if limit <= 0 or not items:
        return []
    if len(items) <= limit:
        return list(items)
    if limit == 1:
        return [items[(len(items) - 1) // 2]]

    indices = [round(index * (len(items) - 1) / (limit - 1)) for index in range(limit)]
    return [items[index] for index in indices]


def classify_coverage_oracle_error(exc: Exception) -> tuple[str, bool]:
    if isinstance(exc, CoverageOracleError):
        return exc.kind, exc.systemic

    message = str(exc).lower()
    if "llvm-profdata" in message:
        return "llvm_profdata_failed", True
    if "llvm-cov" in message:
        return "llvm_cov_failed", True
    if "did not contain blocker branch line" in message:
        return "branch_line_missing", False
    if "timed out" in message:
        return "target_timeout", False
    return "coverage_unknown", False


def _candidate_rank(candidate: CandidateEvaluation) -> int:
    if candidate.coverage and candidate.coverage.blocked_side_line_reached:
        return 0
    if candidate.coverage and candidate.coverage.branch_hit_count > 0:
        return 1
    if candidate.status == "coverage_unknown":
        return 2
    return 3


def explore_with_symcc(
    args: argparse.Namespace,
    symcc_bin: Path,
    corpus_dir: Path,
    generated_dir: Path,
    evaluate_candidate: Callable[[Path, float], CoverageResult],
) -> SymCCExplorationResult:
    """Explore SymCC outputs and classify them online before deciding retention."""
    generated_dir.mkdir(parents=True, exist_ok=True)
    symcc_out = generated_dir / "symcc_out"
    evaluated_dir = generated_dir / "evaluated_candidates"
    symcc_out.mkdir(parents=True, exist_ok=True)
    evaluated_dir.mkdir(parents=True, exist_ok=True)

    known_hashes = {sha256_file(path) for path in sorted(corpus_dir.iterdir()) if path.is_file()}
    seen_hashes = set(known_hashes)
    all_corpus = sorted(path for path in corpus_dir.iterdir() if path.is_file())
    initial_frontier_cap = max(1, int(getattr(args, "initial_frontier_cap", 30) or 30))
    frontier = deterministic_stratified_sample(all_corpus, initial_frontier_cap)
    fuzz_target_path = Path(args.fuzz_target).resolve()
    use_cxx = path_language(fuzz_target_path) == "c++"
    wall_clock_budget = float(getattr(args, "wall_clock_budget_sec", 0) or 0)
    max_candidate_evaluations = max(1, int(getattr(args, "max_candidate_evaluations", 200) or 200))
    retained_arg = getattr(args, "max_retained_seeds", None)
    if retained_arg is None:
        retained_arg = getattr(args, "max_total_seeds", 60)
    max_retained_seeds = max(1, int(retained_arg or 60))
    budget_start = time.monotonic()

    evaluations: list[CandidateEvaluation] = []
    oracle_errors: dict[str, int] = {}
    solved: CoverageResult | None = None
    stop_reason = "frontier_exhausted"
    generations_completed = 0
    symcc_executions = 0
    outputs_discovered = 0
    retained_seed_count = 0

    def remaining_seconds() -> float | None:
        if wall_clock_budget <= 0:
            return None
        return max(0.0, wall_clock_budget - (time.monotonic() - budget_start))

    def bounded_timeout(configured_timeout: float) -> float | None:
        remaining = remaining_seconds()
        if remaining is None:
            return max(0.1, configured_timeout)
        if remaining <= 0:
            return None
        return max(0.1, min(configured_timeout, remaining))

    for generation in range(1, int(args.max_generations) + 1):
        if not frontier:
            stop_reason = "frontier_exhausted"
            break
        remaining_eval_budget = max_candidate_evaluations - len(evaluations)
        if remaining_eval_budget <= 0:
            stop_reason = "candidate_eval_budget_exhausted"
            break
        if bounded_timeout(float(args.timeout_sec)) is None:
            stop_reason = "deadline_exhausted"
            break

        # When fewer evaluations than frontier seeds remain, sample the frontier
        # itself so the remaining work is not biased toward its filename prefix.
        active_frontier = deterministic_stratified_sample(
            frontier,
            min(len(frontier), remaining_eval_budget),
        )
        log(
            f"[info] SymCC generation {generation}: {len(active_frontier)} active seed(s), "
            f"{remaining_eval_budget} cumulative evaluation slot(s) remaining"
        )
        generation_candidates: list[CandidateEvaluation] = []

        for frontier_index, seed_path in enumerate(active_frontier):
            remaining_eval_budget = max_candidate_evaluations - len(evaluations)
            if remaining_eval_budget <= 0:
                stop_reason = "candidate_eval_budget_exhausted"
                break
            symcc_timeout = bounded_timeout(float(args.timeout_sec))
            if symcc_timeout is None:
                stop_reason = "deadline_exhausted"
                break

            shutil.rmtree(symcc_out)
            symcc_out.mkdir(parents=True, exist_ok=True)
            symcc_env = os.environ.copy()
            symcc_env["SYMCC_OUTPUT_DIR"] = str(symcc_out)
            symcc_env["SYMCC_ENABLE_LINEARIZATION"] = "1"
            if use_cxx:
                libcxx_install = REPO_ROOT / "libcxx_symcc_install"
                if libcxx_install.is_dir():
                    symcc_env["SYMCC_LIBCXX_PATH"] = str(libcxx_install)
                else:
                    symcc_env.setdefault("SYMCC_REGULAR_LIBCXX", "yes")

            try:
                result = run_single_seed(
                    binary=symcc_bin,
                    seed_path=seed_path,
                    target_args=args.target_args,
                    input_mode=args.input_mode,
                    timeout_sec=symcc_timeout,
                    env=symcc_env,
                )
            except subprocess.TimeoutExpired:
                log(f"[warn] SymCC timeout on {seed_path.name}")
                symcc_executions += 1
                continue

            symcc_executions += 1
            if result.returncode not in (0, 1):
                log(f"[info] seed {seed_path.name} exited with code {result.returncode}")

            materialized_simple_outputs = materialize_symcc_simple_backend_outputs(
                seed_path=seed_path,
                result=result,
                output_dir=symcc_out,
            )
            if materialized_simple_outputs:
                log(
                    f"[info] materialized {materialized_simple_outputs} "
                    "simple-backend output seed(s)"
                )

            unique_outputs: list[tuple[Path, str]] = []
            for output_seed in sorted(path for path in symcc_out.iterdir() if path.is_file()):
                output_hash = sha256_file(output_seed)
                if output_hash in seen_hashes:
                    continue
                seen_hashes.add(output_hash)
                unique_outputs.append((output_seed, output_hash))
            outputs_discovered += len(unique_outputs)

            remaining_frontier_count = len(active_frontier) - frontier_index
            fair_quota = max(1, remaining_eval_budget // max(remaining_frontier_count, 1))
            sampled_outputs = deterministic_stratified_sample(
                unique_outputs,
                min(len(unique_outputs), fair_quota),
            )
            log(
                f"[info] frontier seed {seed_path.name}: {len(unique_outputs)} unique output(s), "
                f"replaying {len(sampled_outputs)} with fair quota {fair_quota}"
            )

            for output_seed, output_hash in sampled_outputs:
                candidate_path = evaluated_dir / seed_name(output_hash, output_seed)
                if not candidate_path.exists():
                    shutil.copy2(output_seed, candidate_path)

                coverage_timeout = bounded_timeout(float(args.timeout_sec))
                if coverage_timeout is None:
                    stop_reason = "deadline_exhausted"
                    break

                try:
                    coverage = evaluate_candidate(candidate_path, coverage_timeout)
                    candidate = CandidateEvaluation(
                        seed=candidate_path,
                        coverage=coverage,
                        status=("blocked_side" if coverage.blocked_side_line_reached else "evaluated"),
                    )
                except Exception as exc:
                    error_kind, systemic = classify_coverage_oracle_error(exc)
                    oracle_errors[error_kind] = oracle_errors.get(error_kind, 0) + 1
                    candidate = CandidateEvaluation(
                        seed=candidate_path,
                        coverage=None,
                        status="coverage_unknown",
                        error_kind=error_kind,
                        error=str(exc),
                    )

                    branch_identity_failed = (
                        error_kind == "branch_line_missing" and oracle_errors[error_kind] >= 2
                    )
                    if systemic or branch_identity_failed:
                        stop_reason = "oracle_unavailable"

                evaluations.append(candidate)
                generation_candidates.append(candidate)
                if candidate.coverage and candidate.coverage.blocked_side_line_reached:
                    solved = candidate.coverage
                    stop_reason = "blocked_side_reached"
                    break
                if stop_reason == "oracle_unavailable":
                    break

            if solved or stop_reason in {"oracle_unavailable", "deadline_exhausted"}:
                break

        generations_completed = generation
        if solved or stop_reason in {"oracle_unavailable", "deadline_exhausted"}:
            break

        ranked_candidates = sorted(
            generation_candidates,
            key=lambda candidate: (_candidate_rank(candidate), candidate.seed.name),
        )
        retained = ranked_candidates[:max_retained_seeds]
        next_frontier: list[Path] = []
        for candidate in retained:
            added = add_seed_to_corpus(candidate.seed, corpus_dir, known_hashes)
            if added is not None:
                next_frontier.append(added)
        retained_seed_count += len(next_frontier)
        frontier = next_frontier

        if len(evaluations) >= max_candidate_evaluations:
            stop_reason = "candidate_eval_budget_exhausted"
            break
        if not frontier:
            stop_reason = "frontier_exhausted"
            break

    elapsed_seconds = time.monotonic() - budget_start
    if (
        stop_reason == "frontier_exhausted"
        and frontier
        and generations_completed >= int(args.max_generations)
    ):
        stop_reason = "generation_limit_reached"
    return SymCCExplorationResult(
        corpus=sorted(path for path in corpus_dir.iterdir() if path.is_file()),
        evaluations=evaluations,
        solved=solved,
        stop_reason=stop_reason,
        generations_completed=generations_completed,
        symcc_executions=symcc_executions,
        outputs_discovered=outputs_discovered,
        candidate_evaluations=len(evaluations),
        retained_seed_count=retained_seed_count,
        oracle_errors=oracle_errors,
        elapsed_seconds=elapsed_seconds,
        candidate_eval_budget=max_candidate_evaluations,
        retention_limit=max_retained_seeds,
        initial_frontier_cap=initial_frontier_cap,
        deadline_seconds=wall_clock_budget,
    )


def evaluate_seed_with_coverage(
    *,
    coverage_bin: Path,
    branch_source: Path,
    coverage_source: str | None,
    branch_line: int,
    blocked_side_line: int,
    seed_path: Path,
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    keep_report: bool,
    llvm_profdata: str,
    llvm_cov: str,
) -> CoverageResult:
    raw_profile = coverage_dir / f"{seed_path.name}.profraw"
    profdata = coverage_dir / f"{seed_path.name}.profdata"
    report_path = coverage_dir / f"{seed_path.name}.linecov.txt"

    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = str(raw_profile)

    try:
        run_result = run_single_seed(
            binary=coverage_bin,
            seed_path=seed_path,
            target_args=target_args,
            input_mode=input_mode,
            timeout_sec=timeout_sec,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise CoverageOracleError(
            "target_timeout",
            f"Coverage run timed out for {seed_path}: {exc}",
        ) from exc

    if run_result.returncode not in (0, 1):
        log(f"[info] coverage run for {seed_path.name} exited with code {run_result.returncode}")

    merge_cmd = [llvm_profdata, "merge", "-sparse", str(raw_profile), "-o", str(profdata)]
    merge_result = run_cmd(merge_cmd)
    if merge_result.returncode != 0:
        raise CoverageOracleError(
            "llvm_profdata_failed",
            f"llvm-profdata failed for {seed_path}\nstdout:\n{merge_result.stdout}\nstderr:\n{merge_result.stderr}",
            systemic=True,
        )

    cov_cmd = [
        llvm_cov,
        "show",
        str(coverage_bin),
        f"-instr-profile={profdata}",
        "-show-branches=count",
        "-show-instantiations=false",
        *coverage_source_args(branch_source, coverage_source),
    ]
    cov_result = run_cmd(cov_cmd)
    if cov_result.returncode != 0:
        raise CoverageOracleError(
            "llvm_cov_failed",
            f"llvm-cov failed for {seed_path}\nstdout:\n{cov_result.stdout}\nstderr:\n{cov_result.stderr}",
            systemic=True,
        )

    report = cov_result.stdout
    if keep_report:
        report_path.write_text(report, encoding="utf-8")

    branch_raw = get_line_execution_count(report, branch_line)
    blocked_raw = get_line_execution_count(report, blocked_side_line)
    if not branch_raw:
        unfiltered_cmd = [
            llvm_cov,
            "show",
            str(coverage_bin),
            f"-instr-profile={profdata}",
            "-show-branches=count",
            "-show-instantiations=false",
        ]
        unfiltered_result = run_cmd(unfiltered_cmd)
        if unfiltered_result.returncode == 0:
            unfiltered_report = unfiltered_result.stdout
            if keep_report:
                report_path.with_suffix(".unfiltered.linecov.txt").write_text(
                    unfiltered_report,
                    encoding="utf-8",
                )
            branch_raw = get_line_execution_count_for_source(
                unfiltered_report,
                branch_line,
                branch_source=branch_source,
                coverage_source=coverage_source,
            )
            blocked_raw = get_line_execution_count_for_source(
                unfiltered_report,
                blocked_side_line,
                branch_source=branch_source,
                coverage_source=coverage_source,
            )
    if not branch_raw:
        raise CoverageOracleError(
            "branch_line_missing",
            "llvm-cov report did not contain blocker branch line "
            f"{branch_line} (local_source={branch_source}, coverage_source={coverage_source or branch_source})",
        )
    branch_count = normalize_count(branch_raw)
    blocked_count = normalize_count(blocked_raw)
    return CoverageResult(
        seed=seed_path,
        branch_hit_count_raw=branch_raw or "0",
        blocked_side_hit_count_raw=blocked_raw or "0",
        branch_hit_count=branch_count,
        blocked_side_hit_count=blocked_count,
        blocked_side_line_reached=blocked_count > 0,
    )


def evaluate_corpus(
    *,
    coverage_bin: Path,
    branch_source: Path,
    coverage_source: str | None,
    branch_line: int,
    blocked_side_line: int,
    corpus: Iterable[Path],
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    keep_report: bool,
    llvm_profdata: str,
    llvm_cov: str,
) -> list[CoverageResult]:
    coverage_dir.mkdir(parents=True, exist_ok=True)
    results: list[CoverageResult] = []
    for seed_path in corpus:
        results.append(
            evaluate_seed_with_coverage(
                coverage_bin=coverage_bin,
                branch_source=branch_source,
                coverage_source=coverage_source,
                branch_line=branch_line,
                blocked_side_line=blocked_side_line,
                seed_path=seed_path,
                target_args=target_args,
                input_mode=input_mode,
                timeout_sec=timeout_sec,
                coverage_dir=coverage_dir,
                keep_report=keep_report,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
            )
        )
    return results


def evaluate_generated_harness_fidelity(
    *,
    coverage_bin: Path,
    branch_source: Path,
    coverage_source: str | None,
    branch_line: int,
    blocked_side_line: int,
    fidelity_seed: Path,
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    keep_report: bool,
    llvm_profdata: str,
    llvm_cov: str,
    max_attempts: int = 2,
) -> dict:
    errors: list[str] = []
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        try:
            result = evaluate_seed_with_coverage(
                coverage_bin=coverage_bin,
                branch_source=branch_source,
                coverage_source=coverage_source,
                branch_line=branch_line,
                blocked_side_line=blocked_side_line,
                seed_path=fidelity_seed,
                target_args=target_args,
                input_mode=input_mode,
                timeout_sec=timeout_sec,
                coverage_dir=coverage_dir / f"attempt_{attempt:02d}",
                keep_report=keep_report,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
            )
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc))
            log(f"[warn] generated-harness fidelity coverage attempt {attempt} failed: {exc}")
            continue

        return {
            "status": "compatible" if result.branch_hit_count > 0 else "incompatible",
            "coverage_success": True,
            "attempt_count": attempt,
            "seed_path": str(fidelity_seed),
            "branch_hit_count": result.branch_hit_count,
            "branch_hit_count_raw": result.branch_hit_count_raw,
            "blocked_side_hit_count": result.blocked_side_hit_count,
            "blocked_side_hit_count_raw": result.blocked_side_hit_count_raw,
            "errors": errors,
        }

    return {
        "status": "unknown",
        "coverage_success": False,
        "attempt_count": max(1, int(max_attempts)),
        "seed_path": str(fidelity_seed),
        "branch_hit_count": None,
        "blocked_side_hit_count": None,
        "errors": errors,
    }


def supplement_corpus_from_ossfuzz(
    *,
    corpus_dir: Path,
    known_hashes: set[str],
    ossfuzz_corpus_dir: Path,
    coverage_bin: Path,
    branch_source: Path,
    coverage_source: str | None,
    branch_line: int,
    blocked_side_line: int,
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    llvm_profdata: str,
    llvm_cov: str,
    max_supplement: int = 4,
    max_candidates: int = 32,
) -> tuple[int, CoverageResult | None]:
    """Supplement SymCC corpus with branch-reaching seeds from the OSS-Fuzz corpus.

    Scans for SHA1-named (40-char hex, fuzzer-discovered) seeds, evaluates each with the
    coverage binary, and adds only those where branch_line_hit_count > 0. Stops after
    max_supplement seeds are added or max_candidates seeds are evaluated.
    Only hex-named seeds are considered because they are in the native binary format the
    fuzz target expects; .txt/.bpf LLM seeds may have format mismatches.
    """
    if max_supplement <= 0 or not ossfuzz_corpus_dir.is_dir():
        return 0, None

    candidates: list[tuple[int, Path]] = []
    for seed_path in ossfuzz_corpus_dir.iterdir():
        if not seed_path.is_file():
            continue
        name = seed_path.name
        if not (len(name) == 40 and all(c in "0123456789abcdef" for c in name)):
            continue
        if sha256_file(seed_path) in known_hashes:
            continue
        try:
            candidates.append((seed_path.stat().st_size, seed_path))
        except OSError:
            pass
    candidates.sort()
    if len(candidates) <= max_candidates:
        selected = candidates
    else:
        step = len(candidates) / max_candidates
        selected = [candidates[int(i * step)] for i in range(max_candidates)]

    coverage_dir.mkdir(parents=True, exist_ok=True)
    added = 0
    blocked_side_result: CoverageResult | None = None
    for _, seed_path in selected:
        result = evaluate_seed_with_coverage(
            coverage_bin=coverage_bin,
            branch_source=branch_source,
            coverage_source=coverage_source,
            branch_line=branch_line,
            blocked_side_line=blocked_side_line,
            seed_path=seed_path,
            target_args=target_args,
            input_mode=input_mode,
            timeout_sec=timeout_sec,
            coverage_dir=coverage_dir,
            keep_report=False,
            llvm_profdata=llvm_profdata,
            llvm_cov=llvm_cov,
        )
        if result.branch_hit_count > 0:
            dest = add_seed_to_corpus(seed_path, corpus_dir, known_hashes)
            if dest is not None:
                result.seed = dest
                log(f"[info] corpus supplement: {seed_path.name} (branch_hits={result.branch_hit_count})")
                added += 1
                if result.blocked_side_line_reached:
                    blocked_side_result = result
                    break
        if added >= max_supplement:
            break

    return added, blocked_side_result


def main() -> int:
    args = parse_args()
    if args.fidelity_only and not args.fidelity_seed:
        raise SystemExit("--fidelity-only requires --fidelity-seed.")
    coverage_source = str(args.coverage_source or args.branch_source)
    loaded_context = None
    if args.build_context_file:
        loaded_context = BuildContext.from_json_file(Path(args.build_context_file).resolve())
        args.branch_source = loaded_context.branch_source
        if loaded_context.mode == "generated_harness" and loaded_context.harness_source:
            args.fuzz_target = loaded_context.harness_source
        elif loaded_context.target_source:
            args.fuzz_target = loaded_context.target_source
    initial_seeds = collect_seed_paths(args.seed, args.seed_dir)
    if not initial_seeds:
        raise SystemExit("At least one seed is required via --seed or --seed-dir.")
    max_retained_seeds = max(
        1,
        int(args.max_retained_seeds if args.max_retained_seeds is not None else args.max_total_seeds),
    )
    args.max_retained_seeds = max_retained_seeds
    initial_frontier_cap = max(1, int(args.initial_frontier_cap))
    if len(initial_seeds) > initial_frontier_cap:
        log(
            f"[info] truncating initial SymCC seeds from {len(initial_seeds)} "
            f"to initial frontier cap {initial_frontier_cap}"
        )
        initial_seeds = deterministic_stratified_sample(initial_seeds, initial_frontier_cap)

    branch_source = Path(args.branch_source).resolve()
    if not branch_source.is_file():
        raise SystemExit(f"Branch source file not found: {branch_source}")

    work_dir = Path(args.work_dir).resolve() if args.work_dir else Path(
        tempfile.mkdtemp(prefix="symcc-blocker-", dir=str(REPO_ROOT / "blocker_process"))
    )
    work_dir.mkdir(parents=True, exist_ok=True)

    corpus_dir = work_dir / "corpus"
    baseline_dir = work_dir / "baseline"
    generated_dir = work_dir / "generated"
    baseline_cov_dir = work_dir / "coverage" / "baseline"
    final_cov_dir = work_dir / "coverage" / "final"
    for directory in (corpus_dir, baseline_dir, generated_dir, baseline_cov_dir, final_cov_dir):
        directory.mkdir(parents=True, exist_ok=True)

    known_hashes: set[str] = set()
    for seed_path in initial_seeds:
        copied = add_seed_to_corpus(seed_path, corpus_dir, known_hashes)
        if copied is None:
            continue
        shutil.copy2(copied, baseline_dir / copied.name)

    log(f"[info] work dir: {work_dir}")
    log("[info] building replay binaries")
    symcc_bin, coverage_bin = build_binaries(args, work_dir)
    llvm_profdata = ensure_tool(args.llvm_profdata)
    llvm_cov = ensure_tool(args.llvm_cov)

    generated_harness_mode = bool(loaded_context and loaded_context.mode == "generated_harness")
    if generated_harness_mode and args.fidelity_seed:
        fidelity_seed = Path(args.fidelity_seed).resolve()
        if not fidelity_seed.is_file():
            fidelity_result = {
                "status": "unknown",
                "coverage_success": False,
                "attempt_count": 0,
                "seed_path": str(fidelity_seed),
                "branch_hit_count": None,
                "blocked_side_hit_count": None,
                "errors": ["Fidelity seed file does not exist."],
            }
        else:
            fidelity_result = evaluate_generated_harness_fidelity(
                coverage_bin=coverage_bin,
                branch_source=branch_source,
                coverage_source=coverage_source,
                branch_line=args.branch_line,
                blocked_side_line=args.blocked_side_line,
                fidelity_seed=fidelity_seed,
                target_args=args.target_args,
                input_mode=args.input_mode,
                timeout_sec=args.timeout_sec,
                coverage_dir=work_dir / "coverage" / "harness_fidelity",
                keep_report=args.keep_coverage_reports,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
            )

        log("HARNESS_FIDELITY_JSON=" + json.dumps(fidelity_result, ensure_ascii=False))
        if fidelity_result["status"] == "unknown":
            log("Status: Generated harness fidelity is unknown because coverage measurement failed.")
            return 3
        if fidelity_result["status"] == "incompatible":
            log("Status: Generated harness is incompatible with the branch-reaching fidelity seed.")
            return 4
        if args.fidelity_only:
            log("Status: Generated harness fidelity preflight passed.")
            return 0

    log("[info] evaluating baseline seeds")
    try:
        baseline_results = evaluate_corpus(
            coverage_bin=coverage_bin,
            branch_source=branch_source,
            coverage_source=coverage_source,
            branch_line=args.branch_line,
            blocked_side_line=args.blocked_side_line,
            corpus=sorted(path for path in baseline_dir.iterdir() if path.is_file()),
            target_args=args.target_args,
            input_mode=args.input_mode,
            timeout_sec=args.timeout_sec,
            coverage_dir=baseline_cov_dir,
            keep_report=args.keep_coverage_reports,
            llvm_profdata=llvm_profdata,
            llvm_cov=llvm_cov,
        )
    except (OSError, RuntimeError) as exc:
        error_kind, _ = classify_coverage_oracle_error(exc)
        failure = {
            "stop_reason": "oracle_unavailable",
            "phase": "baseline",
            "oracle_errors": {error_kind: 1},
            "error": str(exc),
        }
        log("SYMCC_EXPLORATION_JSON=" + json.dumps(failure, ensure_ascii=False))
        print("Status: Coverage oracle unavailable; SymCC result is inconclusive and retryable.")
        return 5

    baseline_reached = any(result.blocked_side_line_reached for result in baseline_results)
    log(f"[info] baseline reached blocked-side line: {'yes' if baseline_reached else 'no'}")

    # Supplement corpus with branch-reaching seeds from OSS-Fuzz when initial seeds are sparse.
    supplement_reached: CoverageResult | None = None
    if getattr(args, "ossfuzz_supplement_corpus_dir", None) and len(initial_seeds) < 4:
        supplement_cov_dir = work_dir / "coverage" / "supplement"
        try:
            n_supplemented, supplement_reached = supplement_corpus_from_ossfuzz(
                corpus_dir=corpus_dir,
                known_hashes=known_hashes,
                ossfuzz_corpus_dir=Path(args.ossfuzz_supplement_corpus_dir),
                coverage_bin=coverage_bin,
                branch_source=branch_source,
                coverage_source=coverage_source,
                branch_line=args.branch_line,
                blocked_side_line=args.blocked_side_line,
                target_args=args.target_args,
                input_mode=args.input_mode,
                timeout_sec=args.timeout_sec,
                coverage_dir=supplement_cov_dir,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
                max_supplement=min(4 - len(initial_seeds), initial_frontier_cap - len(initial_seeds)),
                max_candidates=32,
            )
        except (OSError, RuntimeError) as exc:
            error_kind, _ = classify_coverage_oracle_error(exc)
            failure = {
                "stop_reason": "oracle_unavailable",
                "phase": "supplement",
                "oracle_errors": {error_kind: 1},
                "error": str(exc),
            }
            log("SYMCC_EXPLORATION_JSON=" + json.dumps(failure, ensure_ascii=False))
            print("Status: Coverage oracle unavailable; SymCC result is inconclusive and retryable.")
            return 5
        if n_supplemented > 0:
            log(f"[info] supplemented corpus with {n_supplemented} branch-reaching seeds from OSS-Fuzz corpus")

    log("[info] starting oracle-driven SymCC exploration")

    def evaluate_online_candidate(seed_path: Path, timeout_sec: float) -> CoverageResult:
        return evaluate_seed_with_coverage(
            coverage_bin=coverage_bin,
            branch_source=branch_source,
            coverage_source=coverage_source,
            branch_line=args.branch_line,
            blocked_side_line=args.blocked_side_line,
            seed_path=seed_path,
            target_args=args.target_args,
            input_mode=args.input_mode,
            timeout_sec=timeout_sec,
            coverage_dir=final_cov_dir,
            keep_report=args.keep_coverage_reports,
            llvm_profdata=llvm_profdata,
            llvm_cov=llvm_cov,
        )

    if baseline_reached or supplement_reached is not None:
        exploration = SymCCExplorationResult(
            corpus=sorted(path for path in corpus_dir.iterdir() if path.is_file()),
            evaluations=[],
            solved=None,
            stop_reason=("baseline_already_reached" if baseline_reached else "supplement_already_reached"),
            generations_completed=0,
            symcc_executions=0,
            outputs_discovered=0,
            candidate_evaluations=0,
            retained_seed_count=0,
            oracle_errors={},
            elapsed_seconds=0.0,
            candidate_eval_budget=int(args.max_candidate_evaluations),
            retention_limit=max_retained_seeds,
            initial_frontier_cap=initial_frontier_cap,
            deadline_seconds=float(args.wall_clock_budget_sec),
        )
    else:
        exploration = explore_with_symcc(
            args,
            symcc_bin,
            corpus_dir,
            generated_dir,
            evaluate_online_candidate,
        )
    final_corpus = exploration.corpus
    log(f"[info] total retained corpus after SymCC: {len(final_corpus)}")
    log("SYMCC_EXPLORATION_JSON=" + json.dumps(exploration.to_json_dict(), ensure_ascii=False))

    reached_results = [result for result in baseline_results if result.blocked_side_line_reached]
    if supplement_reached is not None:
        reached_results.append(supplement_reached)
    if exploration.solved is not None:
        reached_results.append(exploration.solved)
    newly_reached = [exploration.solved] if exploration.solved is not None else []

    print("\n=== Summary ===")
    print(f"Work dir: {work_dir}")
    print(f"Baseline seed count: {len(baseline_results)}")
    print(f"Final retained corpus size: {len(final_corpus)}")
    print(f"Generated candidates evaluated online: {exploration.candidate_evaluations}")
    print(f"SymCC exploration stop reason: {exploration.stop_reason}")
    print(f"Baseline reached blocked-side line: {'yes' if baseline_reached else 'no'}")
    print(f"Final reached blocked-side line: {'yes' if reached_results else 'no'}")

    if reached_results:
        best = max(reached_results, key=lambda item: (item.blocked_side_hit_count, item.branch_hit_count))
        print(f"Best blocked-side-reaching seed: {best.seed}")
        print(
            "Branch coverage: "
            f"{best.branch_hit_count_raw} at line {args.branch_line}, "
            f"blocked side coverage: {best.blocked_side_hit_count_raw} at line {args.blocked_side_line}"
        )
        if args.export_solved_seed_dir:
            export_info = export_solved_seed(best.seed, Path(args.export_solved_seed_dir).resolve())
            if export_info["exported"]:
                print(f"Exported solved seed to OSS-Fuzz corpus: {export_info['dest_path']}")
            elif export_info["duplicate"]:
                print(f"Solved seed already exists in OSS-Fuzz corpus: {export_info['dest_path']}")
        if newly_reached:
            print("Status: SymCC discovered at least one new seed that reaches the blocked-side line.")
        else:
            print("Status: The blocked-side line was already reachable from the initial seeds.")
        return 0

    if exploration.stop_reason == "oracle_unavailable":
        print("Status: Coverage oracle unavailable; SymCC result is inconclusive and retryable.")
        return 5

    print("Status: No seed reached the blocked-side line.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
