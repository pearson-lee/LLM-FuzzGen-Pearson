#!/usr/bin/env python3
"""Run SymCC first, then fall back to KLEE if needed."""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
SYMCC_SOLVER = MODULE_ROOT / "symcc_blocker_solver.py"
KLEE_IMAGE = "klee/klee:3.0"
OSS_FUZZ_OUT = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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


def container_path(path: Path) -> str:
    relative = path.resolve().relative_to(REPO_ROOT)
    return f"/repo/{relative.as_posix()}"


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
        description="Try SymCC first; if it fails to solve the blocker, run a KLEE fallback."
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
    parser.add_argument("--skip-symcc", action="store_true", help="Skip the SymCC stage and run only the KLEE fallback.")
    parser.add_argument("--json-output", action="store_true", help="Print a final JSON summary to stdout.")
    parser.add_argument("--json-output-file", default=None, help="Optional path to write the final JSON summary.")
    parser.add_argument("--max-generations", type=int, default=5)
    parser.add_argument("--max-total-seeds", type=int, default=200)
    parser.add_argument("--timeout-sec", type=int, default=20)
    parser.add_argument("--symcc", default=str(REPO_ROOT / "symcc" / "build" / "symcc"))
    parser.add_argument("--sympp", default=str(REPO_ROOT / "symcc" / "build" / "sym++"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--cflags", default="")
    parser.add_argument("--cxxflags", default="")
    parser.add_argument("--ldflags", default="")
    parser.add_argument("--keep-coverage-reports", action="store_true")
    parser.add_argument("--klee-harness", default=None, help="Path to a local KLEE fallback harness.")
    parser.add_argument("--klee-source", action="append", default=[], help="Additional sources for the KLEE harness.")
    parser.add_argument("--klee-include-dir", action="append", default=[], help="Include dirs for the KLEE harness.")
    parser.add_argument("--klee-define", action="append", default=[], help="Defines for the KLEE harness.")
    parser.add_argument("--klee-max-time", type=int, default=60)
    parser.add_argument("--klee-max-tests", type=int, default=10)
    parser.add_argument("--klee-output-seed", default=None, help="Where to write the first extracted KLEE seed.")
    parser.add_argument("--klee-extract-object", default="input", help="Name of the KLEE object to extract.")
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
        args.branch_source = first_present(payload, ["branch_source", "source_file", "source_api_file"], None)
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


def resolve_project_source_root(project_name: str) -> Path:
    candidates = [
        OSS_FUZZ_OUT / project_name / "source_code",
        OSS_FUZZ_OUT / project_name / project_name / "source_code",
        OSS_FUZZ_OUT / project_name / "src" / project_name,
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise FileNotFoundError(
        f"Could not resolve source root for project '{project_name}'. "
        f"Tried: {', '.join(str(path) for path in candidates)}"
    )


def collect_project_sources(source_root: Path, excluded: list[Path]) -> list[Path]:
    excluded_set = {path.resolve() for path in excluded}
    sources: list[Path] = []
    for path in sorted(source_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in C_EXTENSIONS | CXX_EXTENSIONS:
            continue
        if path.resolve() in excluded_set:
            continue
        lowered = path.as_posix().lower()
        if any(part in lowered for part in ("/test/", "/tests/", "/example/", "/examples/", "/benchmark/")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r"\bint\s+main\s*\(", text):
            continue
        sources.append(path.resolve())
    return sources


def collect_include_dirs(source_root: Path) -> list[Path]:
    include_dirs = [source_root.resolve()]
    if source_root.parent.name == "src":
        include_dirs.append(source_root.parent.resolve())
    for path in sorted(source_root.rglob("include")):
        if path.is_dir():
            include_dirs.append(path.resolve())

    unique: list[Path] = []
    seen: set[Path] = set()
    for path in include_dirs:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def resolve_build_inputs(
    project_name: str | None,
    sources: list[str],
    include_dirs: list[str],
    excluded: list[Path],
) -> tuple[list[Path], list[Path], Path | None]:
    if sources or include_dirs:
        resolved_sources = [repo_path(path) for path in sources]
        resolved_includes = [repo_path(path) for path in include_dirs]
        return resolved_sources, resolved_includes, None

    if not project_name:
        return [], [], None

    source_root = resolve_project_source_root(project_name)
    resolved_sources = collect_project_sources(source_root, excluded)
    resolved_includes = collect_include_dirs(source_root)
    return resolved_sources, resolved_includes, source_root


def symcc_cmd(
    args: argparse.Namespace,
    work_dir: Path,
    resolved_sources: list[Path],
    resolved_include_dirs: list[Path],
) -> list[str]:
    cmd = [
        sys.executable,
        str(SYMCC_SOLVER),
        "--fuzz-target",
        str(repo_path(args.fuzz_target)),
        "--branch-source",
        str(repo_path(args.branch_source)),
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
        "--symcc",
        args.symcc,
        "--sympp",
        args.sympp,
        "--clang",
        args.clang,
        "--clangxx",
        args.clangxx,
        "--cflags",
        args.cflags,
        "--cxxflags",
        args.cxxflags,
        "--ldflags",
        args.ldflags,
    ]
    for source in resolved_sources:
        cmd.extend(["--source", str(source)])
    for include_dir in resolved_include_dirs:
        cmd.extend(["--include-dir", str(include_dir)])
    for define in args.define:
        cmd.extend(["--define", define])
    for seed in args.seed:
        cmd.extend(["--seed", str(repo_path(seed))])
    if args.seed_dir:
        cmd.extend(["--seed-dir", str(repo_path(args.seed_dir))])
    if args.keep_coverage_reports:
        cmd.append("--keep-coverage-reports")
    return cmd


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def build_klee_bitcode(
    harness: Path,
    sources: list[Path],
    include_dirs: list[Path],
    defines: list[str],
    cflags: str,
    cxxflags: str,
    out_dir: Path,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    object_dir = out_dir / "obj"
    object_dir.mkdir(parents=True, exist_ok=True)

    all_sources: list[Path] = []
    seen: set[Path] = set()
    for path in [harness, *sources]:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        all_sources.append(resolved)

    compile_commands: list[str] = []
    include_flags = []
    for include_dir in include_dirs:
        include_flags.extend(["-I", container_path(include_dir)])
    define_flags = [f"-D{item}" for item in defines]
    common_flags = ["-emit-llvm", "-c", "-g", "-O0", "-Xclang", "-disable-O0-optnone"]
    extra_cflags = shlex.split(cflags)
    extra_cxxflags = shlex.split(cxxflags)

    for index, source in enumerate(all_sources):
        compiler = "clang" if path_language(source) == "c" else "clang++"
        per_language_flags = extra_cflags if compiler == "clang" else extra_cxxflags
        output = f"/out/obj/{index:03d}_{source.stem}.bc"
        compile_commands.append(
            shell_join(
                [
                    compiler,
                    *common_flags,
                    *per_language_flags,
                    *include_flags,
                    *define_flags,
                    container_path(source),
                    "-o",
                    output,
                ]
            )
        )

    link_inputs = [f"/out/obj/{index:03d}_{source.stem}.bc" for index, source in enumerate(all_sources)]
    linked_bc = out_dir / "linked.bc"
    script = "\n".join(
        [
            "set -e",
            *compile_commands,
            shell_join(["llvm-link", *link_inputs, "-o", "/out/linked.bc"]),
        ]
    )

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{REPO_ROOT}:/repo",
        "-v",
        f"{out_dir}:/out",
        KLEE_IMAGE,
        "bash",
        "-lc",
        script,
    ]
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"KLEE bitcode build failed:\n{result.stdout}")
    if not linked_bc.exists():
        raise RuntimeError("KLEE linked bitcode was not produced.")
    return linked_bc


def run_klee(linked_bc: Path, out_dir: Path, max_time: int, max_tests: int) -> Path:
    klee_out = out_dir / "klee-out"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--ulimit=stack=-1:-1",
        "-v",
        f"{out_dir}:/out",
        KLEE_IMAGE,
        "bash",
        "-lc",
        shell_join(
            [
                "klee",
                f"--output-dir=/out/{klee_out.name}",
                f"--max-time={max_time}",
                f"--max-tests={max_tests}",
                "--search=dfs",
                "--optimize",
                "/out/linked.bc",
            ]
        ),
    ]
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"KLEE execution failed:\n{result.stdout}")
    return klee_out


def extract_ktest_object(klee_out: Path, object_name: str, output_seed: Path | None) -> bytes | None:
    tests = sorted(klee_out.glob("*.ktest"))
    if not tests:
        return None

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{klee_out}:/input",
        KLEE_IMAGE,
        "ktest-tool",
        f"/input/{tests[0].name}",
    ]
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"ktest-tool failed:\n{result.stdout}")

    pattern = re.compile(
        rf"name: '{re.escape(object_name)}'.*?data: b'(.*?)'",
        re.DOTALL,
    )
    match = pattern.search(result.stdout)
    if not match:
        return None

    payload = ast.literal_eval("b'" + match.group(1) + "'")
    if output_seed is not None:
        output_seed.parent.mkdir(parents=True, exist_ok=True)
        output_seed.write_bytes(payload)
    return payload


def main() -> int:
    args = apply_blocker_payload(parse_args())
    args = maybe_auto_resolve_fuzz_target(args)

    missing = []
    if not args.skip_symcc and not getattr(args, "fuzz_target", None):
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
        tempfile.mkdtemp(prefix="symcc-then-klee-", dir=str(REPO_ROOT / "blocker_process"))
    )
    base_work_dir.mkdir(parents=True, exist_ok=True)

    excluded: list[Path] = []
    if getattr(args, "fuzz_target", None):
        excluded.append(repo_path(args.fuzz_target))
    if args.klee_harness:
        excluded.append(repo_path(args.klee_harness))
    resolved_sources, resolved_include_dirs, source_root = resolve_build_inputs(
        args.project_name,
        args.source,
        args.include_dir,
        excluded,
    )
    if source_root is not None:
        print(f"[info] auto-resolved source root: {source_root}", flush=True)
        print(f"[info] auto-resolved {len(resolved_sources)} source files", flush=True)
        print(f"[info] auto-resolved {len(resolved_include_dirs)} include dirs", flush=True)

    summary: dict[str, object] = {
        "success": False,
        "used_symcc": False,
        "used_klee": False,
        "pipeline_methods": [],
        "symcc": None,
        "klee": None,
    }

    symcc_result: subprocess.CompletedProcess[str] | None = None
    if not args.skip_symcc:
        symcc_work_dir = base_work_dir / "symcc"
        print(f"[info] running SymCC first; work dir: {symcc_work_dir}", flush=True)
        symcc_result = run_cmd(
            symcc_cmd(args, symcc_work_dir, resolved_sources, resolved_include_dirs),
            cwd=REPO_ROOT,
        )
        print(symcc_result.stdout, end="")
        summary["used_symcc"] = True
        summary["pipeline_methods"] = ["symcc"]
        summary["symcc"] = {
            "returncode": symcc_result.returncode,
            "work_dir": str(symcc_work_dir),
            "solved": symcc_result.returncode == 0,
        }
        if symcc_result.returncode == 0:
            print("[info] SymCC solved the blocker; KLEE fallback not needed.", flush=True)
            summary["success"] = True
            emit_summary(args, summary)
            return 0

    if not args.klee_harness:
        if args.skip_symcc:
            print("[info] SymCC stage was skipped and no KLEE harness was provided.", flush=True)
            emit_summary(args, summary)
            return 1
        print("[info] SymCC did not solve the blocker and no KLEE harness was provided.", flush=True)
        emit_summary(args, summary)
        return symcc_result.returncode if symcc_result is not None else 1

    if not args.skip_symcc:
        print("[info] SymCC did not solve the blocker; switching to KLEE fallback.", flush=True)
    else:
        print("[info] SymCC stage skipped; running KLEE fallback only.", flush=True)
    klee_work_dir = base_work_dir / "klee"
    harness = repo_path(args.klee_harness)
    if args.klee_source:
        klee_sources = [repo_path(path) for path in args.klee_source]
    else:
        klee_sources = resolved_sources
    if args.klee_include_dir:
        klee_include_dirs = [repo_path(path) for path in args.klee_include_dir]
    else:
        klee_include_dirs = resolved_include_dirs
    klee_defines = args.klee_define or args.define

    linked_bc = build_klee_bitcode(
        harness=harness,
        sources=klee_sources,
        include_dirs=klee_include_dirs,
        defines=klee_defines,
        cflags=args.cflags,
        cxxflags=args.cxxflags,
        out_dir=klee_work_dir,
    )
    print(f"[info] built KLEE bitcode: {linked_bc}", flush=True)
    klee_out = run_klee(linked_bc, klee_work_dir, args.klee_max_time, args.klee_max_tests)
    print(f"[info] KLEE output dir: {klee_out}", flush=True)
    summary["used_klee"] = True
    summary["pipeline_methods"] = list(dict.fromkeys([*summary["pipeline_methods"], "klee"]))

    output_seed = Path(args.klee_output_seed).resolve() if args.klee_output_seed else None
    payload = extract_ktest_object(klee_out, args.klee_extract_object, output_seed)
    if payload is None:
        print("[warn] KLEE ran, but no extractable object was found in the first ktest.", flush=True)
        summary["klee"] = {
            "work_dir": str(klee_work_dir),
            "output_dir": str(klee_out),
            "solved": False,
            "extractable_object_found": False,
        }
        emit_summary(args, summary)
        return 1

    print(f"[info] extracted {len(payload)} bytes from KLEE object '{args.klee_extract_object}'.", flush=True)
    if output_seed is not None:
        print(f"[info] wrote KLEE seed to {output_seed}", flush=True)
    summary["success"] = True
    summary["klee"] = {
        "work_dir": str(klee_work_dir),
        "output_dir": str(klee_out),
        "solved": True,
        "extractable_object_found": True,
        "output_seed": str(output_seed) if output_seed is not None else None,
        "extracted_size": len(payload),
    }
    emit_summary(args, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
