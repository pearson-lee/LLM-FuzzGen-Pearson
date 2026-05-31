#!/usr/bin/env python3
"""Run the SymCC blocker solver."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
SYMCC_SOLVER = MODULE_ROOT / "symcc_blocker_solver.py"
DEFAULT_LLVM18_ROOT = Path.home() / "tools" / "llvm-18.1.8" / "bin"
DEFAULT_LLVM_PROFDATA = str(DEFAULT_LLVM18_ROOT / "llvm-profdata")
DEFAULT_LLVM_COV = str(DEFAULT_LLVM18_ROOT / "llvm-cov")

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.dependent.build_context import reconstruct_build_context
from external.oss_fuzz import OSSFuzz

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


def path_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in C_EXTENSIONS:
        return "c"
    if suffix in CXX_EXTENSIONS:
        return "c++"
    raise ValueError(f"Unsupported source extension for {path}")


def repo_path(path_str: str) -> Path:
    path = Path(path_str).resolve()
    path.relative_to(REPO_ROOT)
    return path


def run_cmd(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the SymCC blocker solver."
    )
    parser.add_argument("--blocker-json-file", default=None, help="Path to blocker/classifier JSON from the upstream pipeline.")
    parser.add_argument("--blocker-json", default=None, help="Inline blocker/classifier JSON.")
    parser.add_argument("--project-name", default=None, help="OSS-Fuzz project name for automatic source resolution.")
    parser.add_argument("--target-name", default=None, help="Optional fuzz target executable name used for auto-resolving the fuzz target source.")
    parser.add_argument("--fuzz-target", default=None)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--include-dir", action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--branch-source", default=None)
    parser.add_argument("--branch-line", default=None, type=int)
    parser.add_argument("--blocked-side-line", default=None, type=int)
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--seed-dir", default=None)
    parser.add_argument("--target-args", default="@@")
    parser.add_argument("--input-mode", choices=("file", "stdin"), default="file")
    parser.add_argument("--work-dir", default=None)
    parser.add_argument("--json-output", action="store_true", help="Print a final JSON summary to stdout.")
    parser.add_argument("--json-output-file", default=None, help="Optional path to write the final JSON summary.")
    parser.add_argument("--max-generations", type=int, default=5)
    parser.add_argument("--max-total-seeds", type=int, default=200)
    parser.add_argument("--timeout-sec", type=int, default=30)
    parser.add_argument("--wall-clock-budget-sec", type=int, default=0, help="Total wall-clock budget for SymCC exploration in seconds. 0 means no limit.")
    parser.add_argument("--symcc", default=str(REPO_ROOT / "symcc" / "build" / "symcc"))
    parser.add_argument("--sympp", default=str(REPO_ROOT / "symcc" / "build" / "sym++"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--llvm-profdata", default=DEFAULT_LLVM_PROFDATA)
    parser.add_argument("--llvm-cov", default=DEFAULT_LLVM_COV)
    parser.add_argument("--cflags", default="")
    parser.add_argument("--cxxflags", default="")
    parser.add_argument("--ldflags", default="")
    parser.add_argument("--keep-coverage-reports", action="store_true")
    return parser.parse_args()


def emit_summary(args: argparse.Namespace, summary: dict[str, object]) -> None:
    rendered = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.json_output_file:
        output_path = Path(args.json_output_file).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    if args.json_output:
        print(rendered)


def first_present(mapping: dict, keys: list[str], default=None):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


def resolve_coverage_binary(oss_fuzz: OSSFuzz, project_name: str, target_name: str) -> Path | None:
    replay_name = f"{target_name}_replay"
    return (
        oss_fuzz.built_target_binary(project_name, replay_name, subdir="symcc_replay")
        or oss_fuzz.built_target_binary(project_name, target_name)
    )


def resolve_native_archive_inputs(oss_fuzz: OSSFuzz, project_name: str) -> tuple[list[Path], list[Path]]:
    if project_name != "libpcap":
        return [], []
    archive_path = oss_fuzz.build_out_dir / project_name / "symcc_native" / "libpcap.a"
    source_root = oss_fuzz.build_out_dir / project_name / "source_code"
    include_dirs = [source_root, source_root / "pcap"]
    if not archive_path.is_file():
        return [], []
    usable_include_dirs = [path for path in include_dirs if path.is_dir()]
    return [archive_path], usable_include_dirs


def load_blocker_payload(args: argparse.Namespace) -> dict | None:
    if args.blocker_json_file:
        return json.loads(Path(args.blocker_json_file).read_text(encoding="utf-8"))
    if args.blocker_json:
        return json.loads(args.blocker_json)
    return None


def apply_blocker_payload(args: argparse.Namespace) -> argparse.Namespace:
    payload = load_blocker_payload(args)
    if not isinstance(payload, dict):
        return args

    if not getattr(args, "project_name", None):
        args.project_name = first_present(payload, ["project_name"], None)
    if not getattr(args, "target_name", None):
        args.target_name = first_present(payload, ["target_name", "best_target"], None)
    if not getattr(args, "branch_line", None):
        branch_line = first_present(payload, ["branch_line", "branch_line_number"], None)
        if branch_line not in (None, ""):
            args.branch_line = int(branch_line)
    if not getattr(args, "blocked_side_line", None):
        blocked_line = first_present(
            payload,
            ["blocked_side_line", "blocked_side_line_number", "blocked_side_line_numder"],
            None,
        )
        if blocked_line not in (None, ""):
            args.blocked_side_line = int(blocked_line)
    if not getattr(args, "branch_source", None):
        args.branch_source = first_present(payload, ["branch_source", "source_api_file", "source_file"], None)
    if not getattr(args, "seed", None):
        seeds = first_present(payload, ["seeds", "seed_paths"], None)
        if isinstance(seeds, list):
            args.seed = [str(item) for item in seeds if item]
        elif isinstance(seeds, str) and seeds:
            args.seed = [seeds]
    return args


def maybe_auto_resolve_fuzz_target(args: argparse.Namespace) -> argparse.Namespace:
    if getattr(args, "fuzz_target", None):
        return args
    if not getattr(args, "project_name", None):
        return args
    if getattr(args, "target_name", None):
        project_dir = REPO_ROOT / "external" / "oss-fuzz" / "projects" / args.project_name
        for suffix in (".cpp", ".cc", ".cxx", ".c"):
            candidate = project_dir / f"{args.target_name}{suffix}"
            if candidate.is_file():
                args.fuzz_target = str(candidate.resolve())
                return args

    try:
        from blocker_process.blocker_classifier import resolve_fuzz_target_path
    except Exception as exc:  # pragma: no cover - defensive import path
        raise RuntimeError(f"Failed to import blocker_classifier for fuzz target resolution: {exc}") from exc

    resolved = resolve_fuzz_target_path(args.project_name, getattr(args, "target_name", None))
    if not resolved:
        raise RuntimeError(
            "Could not auto-resolve fuzz target source from blocker metadata. "
            "Pass --fuzz-target explicitly or ensure target_name exists in the blocker payload."
        )
    args.fuzz_target = resolved
    return args


def symcc_cmd(
    args: argparse.Namespace,
    work_dir: Path,
    build_context_path: Path,
    coverage_binary: Path | None,
    prebuilt_archives: list[Path],
    native_include_dirs: list[Path],
) -> list[str]:
    cmd = [
        sys.executable,
        str(SYMCC_SOLVER),
        "--build-context-file",
        str(build_context_path),
        "--fuzz-target",
        str(repo_path(args.fuzz_target)),
        "--branch-source",
        str(args.branch_source),
        "--branch-line",
        str(args.branch_line),
        "--blocked-side-line",
        str(args.blocked_side_line),
        "--target-args",
        args.target_args,
        "--input-mode",
        args.input_mode,
        "--work-dir",
        str(work_dir),
        "--max-generations",
        str(args.max_generations),
        "--max-total-seeds",
        str(args.max_total_seeds),
        "--timeout-sec",
        str(args.timeout_sec),
        "--wall-clock-budget-sec",
        str(getattr(args, "wall_clock_budget_sec", 0) or 0),
        "--symcc",
        args.symcc,
        "--sympp",
        args.sympp,
        "--clang",
        args.clang,
        "--clangxx",
        args.clangxx,
        "--llvm-profdata",
        args.llvm_profdata or "llvm-profdata",
        "--llvm-cov",
        args.llvm_cov or "llvm-cov",
        "--cflags",
        args.cflags,
        "--cxxflags",
        args.cxxflags,
        "--ldflags",
        args.ldflags,
    ]
    if coverage_binary is not None:
        cmd.extend(["--coverage-binary", str(coverage_binary)])
    for archive in prebuilt_archives:
        cmd.extend(["--prebuilt-archive", str(archive)])
    for include_dir in native_include_dirs:
        cmd.extend(["--native-include-dir", str(include_dir)])
    for define in args.define:
        cmd.extend(["--define", define])
    for seed in args.seed:
        cmd.extend(["--seed", str(repo_path(seed))])
    if args.seed_dir:
        cmd.extend(["--seed-dir", str(repo_path(args.seed_dir))])
    if args.keep_coverage_reports:
        cmd.append("--keep-coverage-reports")
    # Auto-derive OSS-Fuzz corpus dir for branch-reaching seed supplementation.
    # symcc_blocker_solver.py only activates this when initial seed count < 4.
    if getattr(args, "project_name", None) and getattr(args, "target_name", None):
        oss_fuzz = OSSFuzz()
        supplement_dir = oss_fuzz.build_corpus_dir / args.project_name / args.target_name
        if supplement_dir.is_dir():
            cmd.extend(["--ossfuzz-supplement-corpus-dir", str(supplement_dir)])
    return cmd


def main() -> int:
    args = apply_blocker_payload(parse_args())
    args = maybe_auto_resolve_fuzz_target(args)

    missing = []
    if not getattr(args, "fuzz_target", None):
        missing.append("--fuzz-target")
    if not getattr(args, "branch_source", None):
        missing.append("--branch-source")
    if getattr(args, "branch_line", None) is None:
        missing.append("--branch-line")
    if getattr(args, "blocked_side_line", None) is None:
        missing.append("--blocked-side-line")
    if missing:
        raise SystemExit(f"Missing required inputs after blocker metadata resolution: {', '.join(missing)}")

    base_work_dir = Path(args.work_dir).resolve() if args.work_dir else Path(
        tempfile.mkdtemp(prefix="run-symcc-blocker-", dir=str(REPO_ROOT / "blocker_process"))
    )
    base_work_dir.mkdir(parents=True, exist_ok=True)

    symcc_build_context = reconstruct_build_context(
        project_name=args.project_name,
        mode="original_target",
        target_source=args.fuzz_target,
        branch_source=args.branch_source,
        explicit_sources=args.source,
        explicit_include_dirs=args.include_dir,
        defines=args.define,
        cflags=args.cflags,
        cxxflags=args.cxxflags,
        ldflags=args.ldflags,
    )
    build_context_path = base_work_dir / "build_context.json"
    symcc_build_context.write_json(build_context_path)
    if symcc_build_context.source_root:
        print(f"[info] reconstructed source root: {symcc_build_context.source_root}", flush=True)
    print(
        f"[info] reconstructed build context: required={len(symcc_build_context.required_sources)} "
        f"optional={len(symcc_build_context.optional_sources)} include_dirs={len(symcc_build_context.include_dirs)}",
        flush=True,
    )

    coverage_binary: Path | None = None
    prebuilt_archives: list[Path] = []
    native_include_dirs: list[Path] = []
    native_prepare_info: dict[str, object] = {
        "attempted": False,
        "success": False,
        "error": None,
        "discovered_archives": [],
        "copied_archives": [],
        "include_dirs": [],
    }
    coverage_prepare_info: dict[str, object] = {
        "attempted": False,
        "success": False,
        "error": None,
        "resolved_binary": None,
        "resolved_binary_kind": None,
    }
    if args.project_name and args.target_name:
        oss_fuzz = OSSFuzz()
        if args.project_name == "libpcap":
            native_prepare_info["attempted"] = True
            native_build = oss_fuzz.build_fuzzers(
                args.project_name,
                sanitizer="none",
                extra_env={
                    "LLM_FUZZGEN_BUILD_FLAVOR": "symcc_native",
                    "LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS": "1",
                },
                variant="symcc_native",
            )
            if native_build.success:
                discovered_archives, native_include_dirs = resolve_native_archive_inputs(oss_fuzz, args.project_name)
                native_prepare_info["discovered_archives"] = [str(path) for path in discovered_archives]
                native_prepare_info["include_dirs"] = [str(path) for path in native_include_dirs]
                if discovered_archives:
                    archive_copy_dir = base_work_dir / "native_archives"
                    archive_copy_dir.mkdir(parents=True, exist_ok=True)
                    prebuilt_archives = []
                    for archive_path in discovered_archives:
                        copied_archive = archive_copy_dir / archive_path.name
                        shutil.copy2(archive_path, copied_archive)
                        prebuilt_archives.append(copied_archive)
                native_prepare_info["copied_archives"] = [str(path) for path in prebuilt_archives]
                if prebuilt_archives:
                    native_prepare_info["success"] = True
                    print(
                        "[info] reusing OSS-Fuzz native archive(s): "
                        + ", ".join(str(path) for path in prebuilt_archives),
                        flush=True,
                    )
                else:
                    native_prepare_info["error"] = (
                        "native build succeeded but no usable archive was discovered at the expected path"
                    )
                    print(
                        f"[warn] native archive build for {args.project_name}/{args.target_name} succeeded "
                        "but no usable archive was discovered",
                        flush=True,
                    )
            else:
                native_prepare_info["error"] = native_build.error
                print(
                    f"[warn] failed to prepare OSS-Fuzz native archive for {args.project_name}/{args.target_name}: "
                    f"{native_build.error}",
                    flush=True,
                )
        coverage_prepare_info["attempted"] = True
        coverage_build = oss_fuzz.ensure_target_binary(
            args.project_name,
            args.target_name,
            sanitizer="coverage",
            extra_env={
                "LLM_FUZZGEN_BUILD_FLAVOR": "symcc_replay",
                "LLM_FUZZGEN_BUILD_SYMCC_REPLAY": "1",
            },
            variant="symcc_replay",
        )
        if coverage_build.success:
            coverage_binary = resolve_coverage_binary(oss_fuzz, args.project_name, args.target_name)
            if coverage_binary is not None:
                coverage_prepare_info["success"] = True
                coverage_prepare_info["resolved_binary"] = str(coverage_binary)
                coverage_prepare_info["resolved_binary_kind"] = (
                    "replay" if coverage_binary.name.endswith("_replay") else "libfuzzer_target"
                )
                print(f"[info] reusing OSS-Fuzz coverage binary: {coverage_binary}", flush=True)
            else:
                coverage_prepare_info["error"] = (
                    "coverage build succeeded but no usable target binary was resolved"
                )
                print(
                    f"[warn] coverage build for {args.project_name}/{args.target_name} succeeded "
                    "but no usable target binary was resolved",
                    flush=True,
                )
        else:
            coverage_prepare_info["error"] = coverage_build.error
            print(
                f"[warn] failed to prepare OSS-Fuzz coverage binary for {args.project_name}/{args.target_name}: "
                f"{coverage_build.error}",
                flush=True,
            )

    summary: dict[str, object] = {
        "success": False,
        "used_symcc": False,
        "pipeline_methods": [],
        "symcc": None,
        "coverage_binary": str(coverage_binary) if coverage_binary is not None else None,
        "coverage_binary_kind": (
            "replay"
            if coverage_binary is not None and coverage_binary.name.endswith("_replay")
            else ("libfuzzer_target" if coverage_binary is not None else None)
        ),
        "native_archives": [str(path) for path in prebuilt_archives],
        "native_prepare": native_prepare_info,
        "coverage_prepare": coverage_prepare_info,
    }

    symcc_work_dir = base_work_dir / "symcc"
    print(f"[info] running SymCC; work dir: {symcc_work_dir}", flush=True)
    symcc_result = run_cmd(
        symcc_cmd(args, symcc_work_dir, build_context_path, coverage_binary, prebuilt_archives, native_include_dirs),
        cwd=REPO_ROOT,
    )
    print(symcc_result.stdout, end="")
    summary["used_symcc"] = True
    summary["pipeline_methods"] = ["symcc"]
    summary["symcc"] = {
        "returncode": symcc_result.returncode,
        "work_dir": str(symcc_work_dir),
        "solved": symcc_result.returncode == 0,
        "output": symcc_result.stdout,
    }
    summary["success"] = symcc_result.returncode == 0
    emit_summary(args, summary)
    return symcc_result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
