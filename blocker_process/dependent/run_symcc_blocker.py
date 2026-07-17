#!/usr/bin/env python3
"""Run the SymCC blocker solver."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
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

from blocker_process.dependent.build_context import BuildContext, reconstruct_build_context
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
    parser.add_argument(
        "--coverage-source",
        default=None,
        help="Source path identity embedded in the coverage binary; defaults to --branch-source.",
    )
    parser.add_argument("--branch-line", default=None, type=int)
    parser.add_argument("--blocked-side-line", default=None, type=int)
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--fidelity-seed", default=None)
    parser.add_argument(
        "--fidelity-only",
        action="store_true",
        help="Validate generated-harness fidelity and exit before SymCC exploration.",
    )
    parser.add_argument("--seed-dir", default=None)
    parser.add_argument("--target-args", default="@@")
    parser.add_argument("--input-mode", choices=("file", "stdin"), default="file")
    parser.add_argument("--work-dir", default=None)
    parser.add_argument("--json-output", action="store_true", help="Print a final JSON summary to stdout.")
    parser.add_argument("--json-output-file", default=None, help="Optional path to write the final JSON summary.")
    parser.add_argument("--max-generations", type=int, default=3)
    parser.add_argument("--max-total-seeds", type=int, default=60)
    parser.add_argument("--max-candidate-evaluations", type=int, default=200)
    parser.add_argument("--max-retained-seeds", type=int, default=None)
    parser.add_argument("--initial-frontier-cap", type=int, default=30)
    parser.add_argument("--timeout-sec", type=int, default=30)
    parser.add_argument("--wall-clock-budget-sec", type=int, default=300, help="Total wall-clock budget for SymCC exploration and online coverage replay. 0 means no limit.")
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


def load_project_config(project_name: str) -> dict:
    config_path = REPO_ROOT / "external" / "oss-fuzz" / "projects" / project_name / "symcc_config.json"
    if config_path.is_file():
        return json.loads(config_path.read_text(encoding="utf-8"))
    return {}


def _config_list(value: object) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [str(value)]


def _resolve_config_path(raw_path: str, project_name: str | None) -> Path:
    build_out = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out"
    expanded = (
        raw_path
        .replace("{repo_root}", str(REPO_ROOT))
        .replace("{build_out}", str(build_out))
    )
    if project_name:
        expanded = expanded.replace("{project}", project_name)

    path = Path(expanded)
    if path.is_absolute():
        return path
    return REPO_ROOT / path


def apply_project_config_overrides(args: argparse.Namespace, project_config: dict) -> argparse.Namespace:
    if not project_config:
        return args

    project_name = getattr(args, "project_name", None)
    for include_dir in _config_list(project_config.get("extra_include_dirs")):
        resolved = str(_resolve_config_path(include_dir, project_name))
        if resolved not in args.include_dir:
            args.include_dir.append(resolved)

    for key, attr in (
        ("extra_cflags", "cflags"),
        ("extra_cxxflags", "cxxflags"),
        ("extra_ldflags", "ldflags"),
    ):
        extras = _config_list(project_config.get(key))
        if extras:
            current = getattr(args, attr) or ""
            setattr(args, attr, " ".join(part for part in [current, *extras] if part).strip())

    return args


def _merge_shell_flags(existing: str, additional: str) -> str:
    merged = shlex.split(existing or "")
    for flag in shlex.split(additional or ""):
        if flag not in merged:
            merged.append(flag)
    return " ".join(shlex.quote(flag) for flag in merged)


def merge_build_context_overrides(build_context: BuildContext, args: argparse.Namespace) -> BuildContext:
    for include_dir in getattr(args, "include_dir", []) or []:
        resolved = str(Path(include_dir).resolve())
        if resolved not in build_context.include_dirs:
            build_context.include_dirs.append(resolved)
    for define in getattr(args, "define", []) or []:
        if define not in build_context.defines:
            build_context.defines.append(define)

    build_context.cflags = _merge_shell_flags(build_context.cflags, getattr(args, "cflags", ""))
    build_context.cxxflags = _merge_shell_flags(build_context.cxxflags, getattr(args, "cxxflags", ""))
    build_context.ldflags = _merge_shell_flags(build_context.ldflags, getattr(args, "ldflags", ""))
    build_context.diagnostics.append(
        "Merged project SymCC config and CLI build flags into the effective generated-harness context."
    )
    return build_context


# Phase 1 allowlist: only projects where symcc_library has been validated.
_SYMCC_LIBRARY_PROJECTS = {"libpcap", "tinyxml2", "lcms", "zlib", "libtiff"}


def _symcc_variant_name(symcc_bin_host: Path, length: int = 8) -> str:
    """Compute a variant name that embeds a hash of all SymCC binary files.

    This binds the artifact-cache key to the SymCC version, so updating
    symcc/build/ automatically invalidates the cached symcc_library archive.
    """
    h = hashlib.sha256()
    for fname in (
        "symcc",
        "sym++",
        "libsymcc.so",
        "SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a",
        "SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so",
    ):
        fpath = symcc_bin_host / fname
        try:
            h.update(fpath.read_bytes())
        except OSError:
            h.update(fname.encode())
    return f"symcc_library_{h.hexdigest()[:length]}"


def _should_use_symcc_library(
    project_name: str, project_config: dict, seeds: list
) -> bool:
    """Return True if symcc_library instrumentation should be attempted."""
    if project_name not in _SYMCC_LIBRARY_PROJECTS:
        return False
    if not project_config.get("symcc_library", False):
        return False
    if not seeds:
        print("[info] symcc_library skip: no branch-reaching seeds available", flush=True)
        return False
    return True


def resolve_coverage_binary(oss_fuzz: OSSFuzz, project_name: str, target_name: str) -> Path | None:
    replay_name = f"{target_name}_replay"
    return (
        oss_fuzz.built_target_binary(project_name, replay_name, subdir="symcc_replay")
        or oss_fuzz.built_target_binary(project_name, target_name)
    )


def resolve_native_archive_inputs(
    oss_fuzz: OSSFuzz, project_name: str, project_config: dict
) -> tuple[list[Path], list[Path]]:
    archive_subdir = project_config.get("native_archive_subdir", "symcc_native")
    archive_filename = project_config.get("native_archive_filename", f"{project_name}.a")
    include_rel_dirs = project_config.get("native_archive_include_dirs", ["source_code"])
    archive_path = oss_fuzz.build_out_dir / project_name / archive_subdir / archive_filename
    base_dir = oss_fuzz.build_out_dir / project_name
    include_dirs = [base_dir / rel_dir for rel_dir in include_rel_dirs]
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
    if not getattr(args, "coverage_source", None):
        args.coverage_source = first_present(
            payload,
            ["source_api_file", "branch_source", "source_file"],
            None,
        )
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
        "--coverage-source",
        str(args.coverage_source or args.branch_source),
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
        "--max-candidate-evaluations",
        str(args.max_candidate_evaluations),
        "--max-retained-seeds",
        str(args.max_retained_seeds if args.max_retained_seeds is not None else args.max_total_seeds),
        "--initial-frontier-cap",
        str(args.initial_frontier_cap),
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
        f"--cflags={args.cflags}",
        f"--cxxflags={args.cxxflags}",
        f"--ldflags={args.ldflags}",
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
    if args.fidelity_seed:
        cmd.extend(["--fidelity-seed", str(repo_path(args.fidelity_seed))])
    if args.fidelity_only:
        cmd.append("--fidelity-only")
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
        try:
            build_context = BuildContext.from_json_file(build_context_path)
        except Exception:
            build_context = None
        if build_context is not None and build_context.mode == "original_target":
            export_dir = oss_fuzz.build_corpus_dir / args.project_name / args.target_name
            cmd.extend(["--export-solved-seed-dir", str(export_dir)])
    return cmd


def main() -> int:
    args = apply_blocker_payload(parse_args())
    args = maybe_auto_resolve_fuzz_target(args)
    project_config = load_project_config(args.project_name) if args.project_name else {}
    args = apply_project_config_overrides(args, project_config)

    missing = []
    if not getattr(args, "fuzz_target", None):
        missing.append("--fuzz-target")
    if not getattr(args, "branch_source", None):
        missing.append("--branch-source")
    if getattr(args, "branch_line", None) is None:
        missing.append("--branch-line")
    if getattr(args, "blocked_side_line", None) is None:
        missing.append("--blocked-side-line")
    if args.fidelity_only and not args.fidelity_seed:
        missing.append("--fidelity-seed (required with --fidelity-only)")
    if missing:
        raise SystemExit(f"Missing required inputs after blocker metadata resolution: {', '.join(missing)}")

    base_work_dir = Path(args.work_dir).resolve() if args.work_dir else Path(
        tempfile.mkdtemp(prefix="run-symcc-blocker-", dir=str(REPO_ROOT / "blocker_process"))
    )
    base_work_dir.mkdir(parents=True, exist_ok=True)

    # T8: if fuzz_target lives inside a generated harness dir that has a pre-built
    # build_context.json (created by input_dependent_harness_generator.py), reuse it
    # directly instead of re-running reconstruct_build_context(), which would produce
    # wrong include paths for harness sources located outside the original source tree.
    harness_build_ctx_path = Path(args.fuzz_target).parent / "build_context.json"
    if harness_build_ctx_path.is_file():
        symcc_build_context = BuildContext.from_json_file(harness_build_ctx_path)
        symcc_build_context = merge_build_context_overrides(symcc_build_context, args)
        print(f"[info] using pre-built harness build context: {harness_build_ctx_path}", flush=True)
    else:
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
        if symcc_build_context.source_root:
            print(f"[info] reconstructed source root: {symcc_build_context.source_root}", flush=True)
    build_context_path = base_work_dir / "build_context.json"
    symcc_build_context.write_json(build_context_path)
    print(
        f"[info] build context: required={len(symcc_build_context.required_sources)} "
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
    symcc_library_archives: list[Path] = []
    symcc_lib_archive: Path | None = None
    symcc_lib_build_result = None
    symcc_variant: str | None = None
    symcc_fail_marker: Path | None = None

    if args.project_name and args.target_name:
        oss_fuzz = OSSFuzz()
        # T9: native archive mode is config-driven via external/oss-fuzz/projects/{project}/symcc_config.json
        if project_config.get("native_archive", False) and not args.fidelity_only:
            native_prepare_info["attempted"] = True
            native_archive_flavor = project_config.get("native_archive_build_flavor", "symcc_native")
            native_build = oss_fuzz.build_fuzzers(
                args.project_name,
                sanitizer="none",
                extra_env={
                    "LLM_FUZZGEN_BUILD_FLAVOR": native_archive_flavor,
                    "LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS": "1",
                },
                variant=native_archive_flavor,
            )
            if native_build.success:
                discovered_archives, native_include_dirs = resolve_native_archive_inputs(
                    oss_fuzz, args.project_name, project_config
                )
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
        # symcc_library: re-build the project library with SymCC instrumentation so symbolic tracking
        # can follow execution into library internals (not just the harness).
        seeds_for_check = getattr(args, "seed", []) or []
        if not args.fidelity_only and _should_use_symcc_library(args.project_name, project_config, seeds_for_check):
            symcc_bin_host = REPO_ROOT / "symcc" / "build_llvm18"
            symcc_variant = _symcc_variant_name(symcc_bin_host)
            symcc_fail_marker = (
                oss_fuzz.build_cache_dir
                / args.project_name
                / "none"
                / symcc_variant
                / ".build_failed"
            )

            if symcc_fail_marker.exists():
                print(
                    f"[warn] symcc_library build previously failed this session "
                    f"(marker: {symcc_fail_marker}), skipping; using native archive",
                    flush=True,
                )
            else:
                symcc_lib_flavor = project_config.get("symcc_library_build_flavor", "symcc_library")
                # libsymcc-rt.so depends on libz3.so.4 at link time; if apt-get
                # inside the container can't install it, mount symcc/lib/ as
                # /symcc-libs (a separate mountpoint, not inside the read-only
                # /symcc-bin) so LD_LIBRARY_PATH=/symcc-libs resolves it.
                libz3_dir = REPO_ROOT / "symcc" / "lib"
                extra_vols = [f"{symcc_bin_host}:/symcc-bin:ro"]
                if (libz3_dir / "libz3.so.4").is_file():
                    extra_vols.append(f"{libz3_dir}:/symcc-libs:ro")
                symcc_lib_build_result = oss_fuzz.build_fuzzers(
                    args.project_name,
                    sanitizer="none",
                    extra_env={
                        "LLM_FUZZGEN_BUILD_FLAVOR": symcc_lib_flavor,
                        "LLM_FUZZGEN_BUILD_SYMCC_LIBRARY": "1",
                    },
                    extra_volumes=extra_vols,
                    variant=symcc_variant,
                )
                if symcc_lib_build_result.success:
                    lib_subdir = project_config.get("symcc_library_subdir", "symcc_library")
                    lib_fname = project_config.get("symcc_library_filename", "libpcap.a")
                    symcc_lib_archive = oss_fuzz.build_out_dir / args.project_name / lib_subdir / lib_fname
                    if symcc_lib_archive.is_file():
                        # Copy to work dir alongside native archives for consistent linking.
                        symcc_archive_copy_dir = base_work_dir / "symcc_library_archives"
                        symcc_archive_copy_dir.mkdir(parents=True, exist_ok=True)
                        copied = symcc_archive_copy_dir / symcc_lib_archive.name
                        shutil.copy2(symcc_lib_archive, copied)
                        symcc_library_archives = [copied]
                        prebuilt_archives = symcc_library_archives
                        print(f"[info] symcc_library archive ready, replacing native archive: {copied}", flush=True)
                    else:
                        print(
                            f"[warn] symcc_library build succeeded but archive not found at {symcc_lib_archive}; "
                            "falling back to native archive",
                            flush=True,
                        )
                else:
                    symcc_fail_marker.parent.mkdir(parents=True, exist_ok=True)
                    symcc_fail_marker.touch()
                    print(
                        f"[warn] symcc_library build failed; failure marker written; "
                        "falling back to native archive",
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
        # symcc_library instrumentation fields — key for post-run diagnosis
        "linked_archive_kind": "symcc_library" if symcc_library_archives else "native_archive",
        "symcc_library_archive": str(symcc_library_archives[0]) if symcc_library_archives else None,
        "native_archive_path": str(prebuilt_archives[0]) if (prebuilt_archives and not symcc_library_archives) else None,
        "symcc_library_prepare": {
            "attempted": symcc_variant is not None,
            "build_success": symcc_lib_build_result.success if symcc_lib_build_result is not None else None,
            "variant": symcc_variant,
            "archive_found": bool(symcc_library_archives),
            "fail_marker_existed": symcc_fail_marker.exists() if symcc_fail_marker is not None else None,
            "runtime_note": (
                "library: LLVM-18 pass (Docker build_llvm18), "
                "harness+link: LLVM-14 runtime (host symcc/build/); "
                "same source → _sym_* API compatible"
            ),
        },
    }

    if args.fidelity_seed and coverage_binary is None:
        failure_summary = {
            "returncode": 3,
            "work_dir": None,
            "failure_kind": "harness_fidelity_unknown",
            "output": "Coverage replay binary preparation failed before harness fidelity validation.",
        }
        if args.fidelity_only:
            summary["fidelity_preflight"] = failure_summary
            summary["failure_kind"] = "harness_fidelity_unknown"
        else:
            summary["symcc"] = {**failure_summary, "solved": False}
        summary["harness_fidelity"] = {
            "status": "unknown",
            "coverage_success": False,
            "seed_path": args.fidelity_seed,
            "errors": [coverage_prepare_info.get("error") or "Coverage replay binary is unavailable."],
        }
        emit_summary(args, summary)
        return 3

    symcc_work_dir = base_work_dir / "symcc"
    print(f"[info] running SymCC; work dir: {symcc_work_dir}", flush=True)
    symcc_result = run_cmd(
        symcc_cmd(args, symcc_work_dir, build_context_path, coverage_binary, prebuilt_archives, native_include_dirs),
        cwd=REPO_ROOT,
    )
    print(symcc_result.stdout, end="")
    summary["used_symcc"] = not args.fidelity_only
    summary["pipeline_methods"] = ["harness_fidelity_preflight" if args.fidelity_only else "symcc"]

    failure_kind: str | None = None
    fidelity_result: dict | None = None
    exploration_result: dict | None = None
    fidelity_match = re.search(r"HARNESS_FIDELITY_JSON=(\{.*\})", symcc_result.stdout)
    if fidelity_match:
        try:
            parsed_fidelity = json.loads(fidelity_match.group(1))
            if isinstance(parsed_fidelity, dict):
                fidelity_result = parsed_fidelity
        except json.JSONDecodeError:
            fidelity_result = None
    exploration_match = re.search(r"SYMCC_EXPLORATION_JSON=(\{.*\})", symcc_result.stdout)
    if exploration_match:
        try:
            parsed_exploration = json.loads(exploration_match.group(1))
            if isinstance(parsed_exploration, dict):
                exploration_result = parsed_exploration
        except json.JSONDecodeError:
            exploration_result = None
    if symcc_result.returncode != 0:
        stdout_lower = symcc_result.stdout.lower()
        if symcc_result.returncode == 3 or "generated harness fidelity is unknown" in stdout_lower:
            failure_kind = "harness_fidelity_unknown"
        elif symcc_result.returncode == 4 or "generated harness is incompatible" in stdout_lower:
            failure_kind = "harness_seed_incompatible"
        elif symcc_result.returncode == 5 or "coverage oracle unavailable" in stdout_lower:
            failure_kind = "oracle_unavailable"
        elif "cannot find -l" in stdout_lower:
            failure_kind = "missing_link_library"
        elif "undefined reference to" in stdout_lower:
            failure_kind = "missing_link_symbol"
        elif "link failed" in stdout_lower:
            failure_kind = "build_failure"
        elif "file not found" in stdout_lower:
            failure_kind = "build_context_missing_header"
        elif "no such file or directory" in stdout_lower and "fatal error:" in stdout_lower:
            failure_kind = "build_context_missing_header"
        elif "compile failed" in stdout_lower:
            failure_kind = "build_failure"
        elif "no seed reached the blocked-side line" in stdout_lower:
            failure_kind = "coverage_no_blocked_side"
        elif native_prepare_info.get("attempted") and not native_prepare_info.get("success"):
            failure_kind = "native_archive_prepare_failed"
        else:
            failure_kind = "symcc_no_new_outputs"

    execution_summary = {
        "returncode": symcc_result.returncode,
        "work_dir": str(symcc_work_dir),
        "failure_kind": failure_kind,
        "attempt_result": "pipeline_error" if failure_kind == "oracle_unavailable" else None,
        "exploration": exploration_result,
        "output": symcc_result.stdout,
    }
    if args.fidelity_only:
        summary["fidelity_preflight"] = execution_summary
        summary["failure_kind"] = failure_kind
    else:
        summary["symcc"] = {
            **execution_summary,
            "solved": symcc_result.returncode == 0,
        }
    summary["harness_fidelity"] = fidelity_result
    summary["success"] = symcc_result.returncode == 0
    summary["attempt_result"] = "pipeline_error" if failure_kind == "oracle_unavailable" else (
        "success" if symcc_result.returncode == 0 else "failed"
    )
    emit_summary(args, summary)
    return symcc_result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
