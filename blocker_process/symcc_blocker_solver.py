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
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SYMCC = REPO_ROOT / "symcc" / "build" / "symcc"
DEFAULT_SYMPP = REPO_ROOT / "symcc" / "build" / "sym++"

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a libFuzzer-style target with SymCC, explore from given seeds, "
            "and find an input that crosses a blocked branch side."
        )
    )
    parser.add_argument("--fuzz-target", required=True, help="Path to the fuzz target source containing LLVMFuzzerTestOneInput.")
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
    parser.add_argument("--max-generations", type=int, default=5, help="Maximum SymCC exploration generations.")
    parser.add_argument("--max-total-seeds", type=int, default=200, help="Maximum total corpus size including generated seeds.")
    parser.add_argument("--timeout-sec", type=int, default=20, help="Timeout for each target execution.")
    parser.add_argument("--symcc", default=str(DEFAULT_SYMCC), help=f"Path to symcc. Default: {DEFAULT_SYMCC}")
    parser.add_argument("--sympp", default=str(DEFAULT_SYMPP), help=f"Path to sym++. Default: {DEFAULT_SYMPP}")
    parser.add_argument("--clang", default="clang", help="Path to clang for the coverage build.")
    parser.add_argument("--clangxx", default="clang++", help="Path to clang++ for the coverage build.")
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


def write_replay_driver(work_dir: Path, driver_language: str) -> Path:
    extension = ".cpp" if driver_language == "c++" else ".c"
    driver_path = work_dir / f"symcc_replay_driver{extension}"
    driver_path.write_text(replay_driver_source(driver_language), encoding="utf-8")
    return driver_path


def compile_objects(
    *,
    sources: list[Path],
    object_dir: Path,
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
    fuzz_target = Path(args.fuzz_target).resolve()
    additional_sources = [Path(path).resolve() for path in args.source]
    branch_source = Path(args.branch_source).resolve()
    source_list = [fuzz_target, *additional_sources]
    seen_sources: set[Path] = set()
    deduped_sources: list[Path] = []
    for source in source_list:
        if not source.is_file():
            raise FileNotFoundError(f"Source file not found: {source}")
        if source in seen_sources:
            continue
        seen_sources.add(source)
        deduped_sources.append(source)

    use_cxx = any(path_language(source) == "c++" for source in deduped_sources)
    driver_language = "c++" if use_cxx else "c"
    driver_path = write_replay_driver(work_dir, driver_language)
    build_sources = [driver_path, *deduped_sources]

    include_dirs = [Path(path).resolve() for path in args.include_dir]
    common_cflags = ["-g", "-O0", "-fno-omit-frame-pointer"]
    extra_cflags = shlex.split(args.cflags)
    extra_cxxflags = shlex.split(args.cxxflags)
    extra_ldflags = shlex.split(args.ldflags)

    symcc = ensure_tool(args.symcc)
    sympp = ensure_tool(args.sympp)
    clang = ensure_tool(args.clang)
    clangxx = ensure_tool(args.clangxx)
    ensure_tool("llvm-profdata")
    ensure_tool("llvm-cov")

    symcc_env = os.environ.copy()
    if use_cxx:
        symcc_env.setdefault("SYMCC_REGULAR_LIBCXX", "yes")

    symcc_obj_dir = work_dir / "build" / "symcc" / "obj"
    coverage_obj_dir = work_dir / "build" / "coverage" / "obj"
    symcc_bin = work_dir / "build" / "symcc" / "replay_symcc"
    coverage_bin = work_dir / "build" / "coverage" / "replay_cov"

    symcc_objects = compile_objects(
        sources=build_sources,
        object_dir=symcc_obj_dir,
        include_dirs=include_dirs,
        defines=args.define,
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
        link_flags=extra_ldflags,
        linker=sympp if use_cxx else symcc,
        env=symcc_env,
    )

    coverage_common_flags = [*common_cflags, "-fprofile-instr-generate", "-fcoverage-mapping"]
    coverage_objects = compile_objects(
        sources=build_sources,
        object_dir=coverage_obj_dir,
        include_dirs=include_dirs,
        defines=args.define,
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


def explore_with_symcc(args: argparse.Namespace, symcc_bin: Path, corpus_dir: Path, generated_dir: Path) -> list[Path]:
    generated_dir.mkdir(parents=True, exist_ok=True)
    symcc_out = generated_dir / "symcc_out"
    symcc_out.mkdir(parents=True, exist_ok=True)

    known_hashes = {sha256_file(path) for path in sorted(corpus_dir.iterdir()) if path.is_file()}
    all_corpus = sorted(path for path in corpus_dir.iterdir() if path.is_file())
    frontier = list(all_corpus)
    processed_count = 0
    fuzz_target_path = Path(args.fuzz_target).resolve()
    use_cxx = path_language(fuzz_target_path) == "c++"

    for generation in range(1, args.max_generations + 1):
        if not frontier or processed_count >= args.max_total_seeds:
            break

        log(f"[info] SymCC generation {generation}: {len(frontier)} seed(s)")
        next_frontier: list[Path] = []

        for seed_path in frontier:
            if processed_count >= args.max_total_seeds:
                break

            shutil.rmtree(symcc_out)
            symcc_out.mkdir(parents=True, exist_ok=True)

            symcc_env = os.environ.copy()
            symcc_env["SYMCC_OUTPUT_DIR"] = str(symcc_out)
            if use_cxx:
                symcc_env.setdefault("SYMCC_REGULAR_LIBCXX", "yes")

            try:
                result = run_single_seed(
                    binary=symcc_bin,
                    seed_path=seed_path,
                    target_args=args.target_args,
                    input_mode=args.input_mode,
                    timeout_sec=args.timeout_sec,
                    env=symcc_env,
                )
            except subprocess.TimeoutExpired:
                log(f"[warn] timeout on {seed_path.name}")
                processed_count += 1
                continue

            if result.returncode not in (0, 1):
                log(f"[info] seed {seed_path.name} exited with code {result.returncode}")

            new_outputs = sorted(path for path in symcc_out.iterdir() if path.is_file())
            for output_seed in new_outputs:
                added = add_seed_to_corpus(output_seed, corpus_dir, known_hashes)
                if added is not None:
                    next_frontier.append(added)

            processed_count += 1

        frontier = next_frontier
        if not frontier:
            break
        if len(known_hashes) >= args.max_total_seeds:
            break

    return sorted(path for path in corpus_dir.iterdir() if path.is_file())


def evaluate_seed_with_coverage(
    *,
    coverage_bin: Path,
    branch_source: Path,
    branch_line: int,
    blocked_side_line: int,
    seed_path: Path,
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    keep_report: bool,
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
        raise RuntimeError(f"Coverage run timed out for {seed_path}: {exc}") from exc

    if run_result.returncode not in (0, 1):
        log(f"[info] coverage run for {seed_path.name} exited with code {run_result.returncode}")

    merge_cmd = ["llvm-profdata", "merge", "-sparse", str(raw_profile), "-o", str(profdata)]
    merge_result = run_cmd(merge_cmd)
    if merge_result.returncode != 0:
        raise RuntimeError(
            f"llvm-profdata failed for {seed_path}\nstdout:\n{merge_result.stdout}\nstderr:\n{merge_result.stderr}"
        )

    cov_cmd = [
        "llvm-cov",
        "show",
        str(coverage_bin),
        f"-instr-profile={profdata}",
        "-show-branches=count",
        "-show-instantiations=false",
        str(branch_source),
    ]
    cov_result = run_cmd(cov_cmd)
    if cov_result.returncode != 0:
        raise RuntimeError(
            f"llvm-cov failed for {seed_path}\nstdout:\n{cov_result.stdout}\nstderr:\n{cov_result.stderr}"
        )

    report = cov_result.stdout
    if keep_report:
        report_path.write_text(report, encoding="utf-8")

    branch_raw = get_line_execution_count(report, branch_line)
    blocked_raw = get_line_execution_count(report, blocked_side_line)
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
    branch_line: int,
    blocked_side_line: int,
    corpus: Iterable[Path],
    target_args: str,
    input_mode: str,
    timeout_sec: int,
    coverage_dir: Path,
    keep_report: bool,
) -> list[CoverageResult]:
    coverage_dir.mkdir(parents=True, exist_ok=True)
    results: list[CoverageResult] = []
    for seed_path in corpus:
        results.append(
            evaluate_seed_with_coverage(
                coverage_bin=coverage_bin,
                branch_source=branch_source,
                branch_line=branch_line,
                blocked_side_line=blocked_side_line,
                seed_path=seed_path,
                target_args=target_args,
                input_mode=input_mode,
                timeout_sec=timeout_sec,
                coverage_dir=coverage_dir,
                keep_report=keep_report,
            )
        )
    return results


def main() -> int:
    args = parse_args()
    initial_seeds = collect_seed_paths(args.seed, args.seed_dir)
    if not initial_seeds:
        raise SystemExit("At least one seed is required via --seed or --seed-dir.")

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

    log("[info] evaluating baseline seeds")
    baseline_results = evaluate_corpus(
        coverage_bin=coverage_bin,
        branch_source=branch_source,
        branch_line=args.branch_line,
        blocked_side_line=args.blocked_side_line,
        corpus=sorted(path for path in baseline_dir.iterdir() if path.is_file()),
        target_args=args.target_args,
        input_mode=args.input_mode,
        timeout_sec=args.timeout_sec,
        coverage_dir=baseline_cov_dir,
        keep_report=args.keep_coverage_reports,
    )

    baseline_reached = any(result.blocked_side_line_reached for result in baseline_results)
    log(f"[info] baseline reached blocked-side line: {'yes' if baseline_reached else 'no'}")

    log("[info] starting SymCC exploration")
    final_corpus = explore_with_symcc(args, symcc_bin, corpus_dir, generated_dir)
    log(f"[info] total corpus after SymCC: {len(final_corpus)}")

    log("[info] evaluating final corpus")
    final_results = evaluate_corpus(
        coverage_bin=coverage_bin,
        branch_source=branch_source,
        branch_line=args.branch_line,
        blocked_side_line=args.blocked_side_line,
        corpus=final_corpus,
        target_args=args.target_args,
        input_mode=args.input_mode,
        timeout_sec=args.timeout_sec,
        coverage_dir=final_cov_dir,
        keep_report=args.keep_coverage_reports,
    )

    reached_results = [result for result in final_results if result.blocked_side_line_reached]
    newly_reached = [
        result for result in reached_results if not (baseline_dir / result.seed.name).exists()
    ]

    print("\n=== Summary ===")
    print(f"Work dir: {work_dir}")
    print(f"Baseline seed count: {len(baseline_results)}")
    print(f"Final corpus size: {len(final_results)}")
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
        if newly_reached:
            print("Status: SymCC discovered at least one new seed that reaches the blocked-side line.")
        else:
            print("Status: The blocked-side line was already reachable from the initial seeds.")
        return 0

    print("Status: No seed reached the blocked-side line.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
