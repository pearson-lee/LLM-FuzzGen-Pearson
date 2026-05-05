#!/usr/bin/env python3
"""Find corpus seeds that reach a branch blocker using OSS-Fuzz coverage tools."""

import argparse
import os
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from blocker_process.coverage_utils import get_line_execution_count

OSS_FUZZ_IMAGE_PREFIX = "gcr.io/oss-fuzz"


def normalize_count(raw: str) -> int:
    """Convert llvm-cov counts such as 109k into integers."""
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


def get_raw_function_name(project_name: str, function_name: str) -> str:
    """Resolve a demangled function name to the raw/mangled name used by Introspector."""
    introspector = Introspector()
    query = function_name.replace(" ", "")
    for func in introspector.get_all_functions(project_name):
        candidate = func.get("function_name", "").replace(" ", "")
        if candidate == query:
            return func.get("raw_function_name", "")
    return ""


def build_coverage_target(project_name: str) -> OSSFuzz:
    """Build the project with coverage instrumentation."""
    oss_fuzz = OSSFuzz()
    result = oss_fuzz.build_fuzzers(project_name, "coverage")
    if not result.success:
        raise RuntimeError(f"Coverage build failed: {result.error}")
    return oss_fuzz


def run_cmd(cmd: list[str], env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
    """Run a subprocess and capture stdout/stderr."""
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


def run_in_ossfuzz(project_name: str, out_dir: Path, corpus_root: Path, command: str) -> subprocess.CompletedProcess:
    """Run a shell command inside the OSS-Fuzz project image."""
    image = f"{OSS_FUZZ_IMAGE_PREFIX}/{project_name}"
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{out_dir}:/out",
        "-v",
        f"{corpus_root}:/corpus",
        image,
        "bash",
        "-lc",
        command,
    ]
    return run_cmd(docker_cmd)


def start_ossfuzz_container(project_name: str, out_dir: Path, corpus_root: Path) -> str:
    """Start one reusable OSS-Fuzz container for multiple seed replays."""
    image = f"{OSS_FUZZ_IMAGE_PREFIX}/{project_name}"
    container_name = f"blocker-coverage-{project_name}-{uuid.uuid4().hex[:12]}"
    docker_cmd = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        container_name,
        "-v",
        f"{out_dir}:/out",
        "-v",
        f"{corpus_root}:/corpus",
        image,
        "sleep",
        "infinity",
    ]
    result = run_cmd(docker_cmd)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return container_name


def run_in_existing_ossfuzz_container(container_name: str, command: str) -> subprocess.CompletedProcess:
    """Run a shell command inside an already running OSS-Fuzz container."""
    docker_cmd = [
        "docker",
        "exec",
        container_name,
        "bash",
        "-lc",
        command,
    ]
    return run_cmd(docker_cmd)


def stop_ossfuzz_container(container_name: str) -> None:
    """Stop the reusable OSS-Fuzz container and ignore cleanup errors."""
    run_cmd(["docker", "rm", "-f", container_name])


def render_linecov_report_in_ossfuzz(
    container_name: str,
    fuzz_target_name: str,
    seed_path: Path,
    source_file: str,
    raw_function_name: Optional[str],
) -> str:
    """Replay one seed in the OSS-Fuzz image and return llvm-cov line coverage output."""
    seed_name = seed_path.name
    corpus_subdir = seed_path.parent.name
    container_seed_path = f"/corpus/{corpus_subdir}/{seed_name}"
    command = (
        'work_dir="$(mktemp -d /tmp/blocker-cov-XXXXXX)" && '
        'trap \'rm -rf "$work_dir"\' EXIT && '
        'LLVM_PROFILE_FILE="$work_dir/current_seed.profraw" '
        f"/out/{shlex.quote(fuzz_target_name)} {shlex.quote(container_seed_path)} "
        "-runs=0 -rss_limit_mb=0 -timeout=0 && "
        'llvm-profdata merge -sparse "$work_dir/current_seed.profraw" '
        '-o "$work_dir/current_seed.profdata" && '
        f"llvm-cov show /out/{shlex.quote(fuzz_target_name)} "
        '-instr-profile="$work_dir/current_seed.profdata" '
        "-show-branches=count "
        "-show-instantiations=false "
        "-Xdemangler c++filt "
        "-path-equivalence=/,/out "
    )
    if raw_function_name:
        command += f"--name-regex={shlex.quote(raw_function_name)} "
    command += shlex.quote(source_file)

    result = run_in_existing_ossfuzz_container(container_name, command)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def iter_seed_files(corpus_dir: Path) -> list[Path]:
    """Return all seed files in a corpus directory in stable order."""
    return sorted([p for p in corpus_dir.iterdir() if p.is_file()])


def guess_container_source_file(project_name: str, local_source_file: str) -> str:
    """Map a local source filename/path to the corresponding /out path inside the OSS-Fuzz container."""
    source_path = Path(local_source_file)
    if source_path.is_absolute():
        parts = source_path.parts
        if "src" in parts:
            src_index = parts.index("src")
            return "/out/" + "/".join(parts[src_index:])
        return f"/out/{source_path.name}"

    return f"/out/src/{project_name}/{source_path.name}"


def run_callchain_for_seed(
    target_bin: Path,
    seed_path: Path,
    breakpoint: str,
) -> None:
    """Invoke get_callchain.sh for a matched seed."""
    script_path = PROJECT_ROOT / "process_blocker" / "get_callchain.sh"
    result = run_cmd(["bash", str(script_path), str(target_bin), str(seed_path), breakpoint])
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if stdout:
        print(stdout)
    if stderr:
        print(stderr, file=sys.stderr)
    if result.returncode != 0:
        print(f"[warn] get_callchain.sh exited with code {result.returncode}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay seeds on a coverage-instrumented fuzz target and find inputs that hit a blocker line."
    )
    parser.add_argument("--project", required=True, help="OSS-Fuzz project name, e.g. tinyxml2")
    parser.add_argument("--target", required=True, help="Fuzz target name, e.g. xmltest")
    parser.add_argument(
        "--function-name",
        required=True,
        help="Demangled function name, e.g. tinyxml2::StrPair::GetStr()",
    )
    parser.add_argument("--branch-line", required=True, type=int, help="Blocker branch line number")
    parser.add_argument("--blocked-side-line", type=int, default=None, help="Blocked side line number")
    parser.add_argument("--corpus-dir", default=None, help="Override corpus directory")
    parser.add_argument("--limit", type=int, default=None, help="Only scan the first N seeds")
    parser.add_argument("--stop-after-first", action="store_true", help="Stop after the first matching seed")
    parser.add_argument("--keep-reports-dir", default=None, help="Optional directory to store per-seed linecov reports")
    parser.add_argument("--skip-build", action="store_true", help="Reuse an existing coverage build instead of rebuilding")
    parser.add_argument(
        "--source-file",
        default=None,
        help="Source file path used by llvm-cov. Default maps to /out/src/<project>/<basename> inside the OSS-Fuzz container.",
    )
    parser.add_argument(
        "--run-callchain",
        action="store_true",
        help="After finding a matching seed, invoke process_blocker/get_callchain.sh with that seed.",
    )
    parser.add_argument(
        "--breakpoint",
        default=None,
        help="Breakpoint passed to get_callchain.sh, e.g. tinyxml2.cpp:1972 or tinyxml2::XMLElement::ParseAttributes(char*, int*).",
    )
    args = parser.parse_args()

    if args.run_callchain and not args.breakpoint:
        print("--run-callchain requires --breakpoint", file=sys.stderr)
        return 2

    raw_function_name = get_raw_function_name(args.project, args.function_name)
    if not raw_function_name:
        print(f"Could not resolve raw function name for: {args.function_name}", file=sys.stderr)
        return 2

    print(f"[info] raw function name: {raw_function_name}")
    if args.skip_build:
        print(f"[info] reusing existing coverage target for project={args.project}")
        oss_fuzz = OSSFuzz()
    else:
        print(f"[info] building coverage target for project={args.project}")
        oss_fuzz = build_coverage_target(args.project)

    fuzz_target_bin = oss_fuzz.build_out_dir / args.project / args.target
    if not fuzz_target_bin.exists():
        print(f"Coverage fuzz target not found: {fuzz_target_bin}", file=sys.stderr)
        return 2

    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else (oss_fuzz.build_corpus_dir / args.project / args.target)
    if not corpus_dir.is_dir():
        print(f"Corpus directory not found: {corpus_dir}", file=sys.stderr)
        return 2

    source_file = guess_container_source_file(
        args.project,
        args.source_file or f"{args.project}.cpp",
    )
    print(f"[info] llvm-cov source file: {source_file}")

    seed_files = iter_seed_files(corpus_dir)
    if args.limit is not None:
        seed_files = seed_files[: args.limit]

    if not seed_files:
        print(f"No seed files found in: {corpus_dir}", file=sys.stderr)
        return 2

    reports_dir = Path(args.keep_reports_dir) if args.keep_reports_dir else None
    if reports_dir:
        reports_dir.mkdir(parents=True, exist_ok=True)

    matches = []
    container_name: Optional[str] = None
    try:
        container_name = start_ossfuzz_container(
            args.project,
            oss_fuzz.build_out_dir / args.project,
            oss_fuzz.build_corpus_dir / args.project,
        )
        print(f"[info] reusing container: {container_name}")

        for idx, seed_path in enumerate(seed_files, start=1):
            try:
                report = render_linecov_report_in_ossfuzz(
                    container_name,
                    args.target,
                    seed_path,
                    source_file,
                    raw_function_name,
                )
            except Exception as exc:
                print(f"[warn] {idx}/{len(seed_files)} {seed_path.name}: failed to collect coverage: {exc}")
                continue

            branch_count_raw = get_line_execution_count(
                report,
                args.branch_line,
                function_name=args.function_name,
                raw_function_name=raw_function_name,
            )
            branch_count = normalize_count(branch_count_raw)

            blocked_side_count_raw = ""
            blocked_side_count = 0
            if args.blocked_side_line:
                blocked_side_count_raw = get_line_execution_count(
                    report,
                    args.blocked_side_line,
                    function_name=args.function_name,
                    raw_function_name=raw_function_name,
                )
                blocked_side_count = normalize_count(blocked_side_count_raw)

            if reports_dir:
                report_path = reports_dir / f"{seed_path.name}.linecovreport"
                report_path.write_text(report, encoding="utf-8")

            print(
                f"[scan] {idx}/{len(seed_files)} {seed_path.name} "
                f"branch_line={args.branch_line}:{branch_count_raw or 'NA'} "
                f"blocked_side_line={args.blocked_side_line}:{blocked_side_count_raw or 'NA'}"
            )

            if branch_count > 0:
                match = {
                    "seed": str(seed_path),
                    "branch_line": args.branch_line,
                    "branch_hit_count": branch_count_raw,
                    "blocked_side_line": args.blocked_side_line,
                    "blocked_side_hit_count": blocked_side_count_raw,
                }
                matches.append(match)
                print(f"[match] seed reaches blocker: {seed_path}")
                if args.run_callchain:
                    print(f"[info] invoking get_callchain.sh with breakpoint: {args.breakpoint}")
                    run_callchain_for_seed(fuzz_target_bin, seed_path, args.breakpoint)
                if args.stop_after_first:
                    break
    finally:
        if container_name:
            stop_ossfuzz_container(container_name)

    print("")
    print("=== Matching seeds ===")
    if not matches:
        print("No seed reached the target blocker line.")
        return 1

    for match in matches:
        print(
            f"{match['seed']} | branch {match['branch_line']} -> {match['branch_hit_count']} | "
            f"blocked side {match['blocked_side_line']} -> {match['blocked_side_hit_count'] or 'NA'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
