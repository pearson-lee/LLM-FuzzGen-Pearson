import codecs
import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
import os
from concurrent.futures import ALL_COMPLETED, FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    success: bool
    error: str = ""


@dataclass
class CoverageMetricSummary:
    count: int
    covered: int
    percent: float


@dataclass
class TotalCoverageSummary:
    branches: CoverageMetricSummary | None = None
    functions: CoverageMetricSummary | None = None
    lines: CoverageMetricSummary | None = None


@dataclass
class BuildState:
    sanitizer: str
    target_fingerprint: str


@dataclass
class FuzzerTimeSliceResult:
    fuzzer_name: str
    requested_seconds: int
    actual_seconds: float
    success: bool
    error: str = ""


@dataclass
class HelperCommandResult:
    success: bool
    stdout: str
    stderr: str
    timed_out: bool = False


class OSSFuzz:
    LANG_EXT: dict[str, str] = {"c": ".c", "c++": ".cc", "cpp": ".cc"}
    DEFAULT_FUZZ_QUANTUM_SECONDS = 30

    def __init__(self, oss_fuzz_dir: Path | None = None):
        self.oss_fuzz_dir: Path = oss_fuzz_dir or Path(__file__).parent / "oss-fuzz"
        self.helper_script: Path = self.oss_fuzz_dir / "infra" / "helper.py"
        self.build_out_dir: Path = self.oss_fuzz_dir / "build" / "out"
        self.build_corpus_dir: Path = self.oss_fuzz_dir / "build" / "corpus"
        self.empty_fuzz_target_c: Path = Path(__file__).parent / "llm_fuzzgen_empty.c"
        self.empty_fuzz_target_cc: Path = Path(__file__).parent / "llm_fuzzgen_empty.cc"
        self.fuzz_introspector_cli: Path = (
            Path(__file__).parent / "fuzz-introspector" / "src" / "fuzz_introspector" / "cli.py"
        )
        self.build_cache_dir: Path = self.oss_fuzz_dir / "build" / "artifact_cache"
        self._project_build_state: dict[str, BuildState] = {}
        self._fuzzer_served_seconds: dict[str, dict[str, float]] = {}

    def _get_project_yaml(self, proj_name: str) -> dict:
        """Read and parse project.yaml file."""
        proj_yaml_path = self.oss_fuzz_dir / "projects" / proj_name / "project.yaml"
        with open(proj_yaml_path) as f:
            return yaml.safe_load(f)

    def _run_helper_command(self, args: list[str], timeout: float | None = None) -> HelperCommandResult:
        """Run helper.py command and return success status, stdout, stderr, and timeout state."""
        try:
            process = subprocess.run(
                ["python", str(self.helper_script)] + args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                errors="ignore",
                timeout=timeout,
            )
            return HelperCommandResult(process.returncode == 0, process.stdout, process.stderr)
        except subprocess.TimeoutExpired as e:
            logger.warning(f"Helper command '{args}' timed out after {timeout:.2f}s")
            stdout = e.stdout.decode(errors="ignore") if isinstance(e.stdout, bytes) else e.stdout
            stderr = e.stderr.decode(errors="ignore") if isinstance(e.stderr, bytes) else e.stderr
            return HelperCommandResult(False, stdout or "", stderr or "timed out", timed_out=True)
        except BaseException as e:
            logger.warning(f"Helper command '{args}' failed with exception: {e}")
            return HelperCommandResult(False, "", str(e))

    def _remaining_timeout(self, deadline: float | None) -> float | None:
        if deadline is None:
            return None
        remaining = deadline - time.monotonic()
        return remaining if remaining > 0 else 0

    def _extract_build_error_message(self, output: str) -> str:
        """Extract relevant error message from compiler output."""
        # Define the core error pattern.
        error_pattern = r"(error:.*?generated\.|error:.*)"

        # If llm_fuzzgen is present, anchor the search to it.
        prefix = r"llm_fuzzgen[\s\S]*?" if "llm_fuzzgen" in output else ""

        # Combine the pattern and perform the search once.
        pattern = prefix + error_pattern
        match = re.search(pattern, output, re.DOTALL | re.IGNORECASE)

        # The error message is always in group(1).
        return match.group(1).strip() if match else output

    def _iter_project_target_artifacts(self, proj_name: str) -> list[Path]:
        project_dir = self.oss_fuzz_dir / "projects" / proj_name
        if not project_dir.exists():
            return []

        patterns = (
            "llm_fuzzgen*.c",
            "llm_fuzzgen*.cc",
            "llm_fuzzgen*.cpp",
            "llm_fuzzgen*.options",
            "llm_fuzzgen*_seed_corpus.zip",
            "llm_fuzzgen.dict",
        )
        artifacts: list[Path] = []
        for pattern in patterns:
            artifacts.extend(project_dir.glob(pattern))
        return sorted({path for path in artifacts})

    def _get_project_target_fingerprint(self, proj_name: str) -> str:
        digest = hashlib.sha256()
        for path in self._iter_project_target_artifacts(proj_name):
            digest.update(path.name.encode("utf-8"))
            digest.update(b"\0")
            try:
                digest.update(path.read_bytes())
            except OSError:
                logger.warning("Failed to read target artifact for fingerprinting: %s", path)
                digest.update(b"<unreadable>")
            digest.update(b"\0")
        return digest.hexdigest()

    def _has_built_llm_targets(self, proj_name: str) -> bool:
        build_dir = self.build_out_dir / proj_name
        if not build_dir.exists():
            return False
        return any(path.is_file() and path.name.startswith("llm_fuzzgen") and not path.suffix for path in build_dir.iterdir())

    def _artifact_cache_path(self, proj_name: str, sanitizer: str, fingerprint: str) -> Path:
        return self.build_cache_dir / proj_name / sanitizer / fingerprint

    def _clear_build_out_dir(self, proj_name: str) -> bool:
        build_dir = self.build_out_dir / proj_name
        if not build_dir.exists():
            return True

        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{build_dir}:/out",
            "-t",
            f"gcr.io/oss-fuzz/{proj_name}",
            "/bin/bash",
            "-c",
            "find /out -mindepth 1 ! -path '/out/inspector' ! -path '/out/inspector/*' -delete",
        ]
        process = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            errors="ignore",
        )
        if process.returncode == 0:
            return True

        logger.error(
            "Failed to clear build output directory for %s before cache restore: %s%s",
            proj_name,
            process.stdout,
            process.stderr,
        )
        return False

    def _copy_directory_contents(self, source_dir: Path, destination_dir: Path) -> None:
        destination_dir.mkdir(parents=True, exist_ok=True)
        for source_path in source_dir.iterdir():
            if source_path.name == "inspector":
                logger.info("Skipping cached inspector artifacts from %s during copy.", source_dir)
                continue
            destination_path = destination_dir / source_path.name
            if source_path.is_dir():
                shutil.copytree(source_path, destination_path, dirs_exist_ok=True)
            else:
                shutil.copy2(source_path, destination_path)

    def _restore_build_artifacts_from_cache(self, proj_name: str, sanitizer: str, fingerprint: str) -> bool:
        cache_dir = self._artifact_cache_path(proj_name, sanitizer, fingerprint)
        if not cache_dir.exists():
            logger.info(
                "No cached %s build artifacts for %s with fingerprint %s.",
                sanitizer,
                proj_name,
                fingerprint[:12],
            )
            return False

        build_dir = self.build_out_dir / proj_name
        build_dir.mkdir(parents=True, exist_ok=True)
        if not self._clear_build_out_dir(proj_name):
            return False
        self._copy_directory_contents(cache_dir, build_dir)
        self._record_build_state(proj_name, sanitizer, fingerprint)
        logger.info(
            "Restored %s build artifacts for %s from cache fingerprint %s.",
            sanitizer,
            proj_name,
            fingerprint[:12],
        )
        return self._has_built_llm_targets(proj_name)

    def _store_build_artifacts_in_cache(self, proj_name: str, sanitizer: str, fingerprint: str) -> None:
        build_dir = self.build_out_dir / proj_name
        if not build_dir.exists():
            logger.warning(
                "Skipping cache store for %s/%s because build output directory does not exist: %s",
                proj_name,
                sanitizer,
                build_dir,
            )
            return

        sanitizer_cache_root = self.build_cache_dir / proj_name / sanitizer
        sanitizer_cache_root.mkdir(parents=True, exist_ok=True)
        for existing in sanitizer_cache_root.iterdir():
            if existing.name != fingerprint:
                shutil.rmtree(existing, ignore_errors=True)

        cache_dir = sanitizer_cache_root / fingerprint
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._copy_directory_contents(build_dir, cache_dir)
        logger.info(
            "Stored %s build artifacts for %s into cache fingerprint %s at %s",
            sanitizer,
            proj_name,
            fingerprint[:12],
            cache_dir,
        )

    def _should_rebuild(self, proj_name: str, sanitizer: str) -> bool:
        fingerprint = self._get_project_target_fingerprint(proj_name)
        build_state = self._project_build_state.get(proj_name)
        logger.info(
            "Build decision for %s/%s: fingerprint=%s, cached_state=%s, build_out_has_targets=%s",
            proj_name,
            sanitizer,
            fingerprint[:12],
            (
                f"{build_state.sanitizer}:{build_state.target_fingerprint[:12]}"
                if build_state is not None
                else "none"
            ),
            self._has_built_llm_targets(proj_name),
        )
        if (
            build_state is not None
            and build_state.sanitizer == sanitizer
            and build_state.target_fingerprint == fingerprint
            and self._has_built_llm_targets(proj_name)
        ):
            logger.info(
                "Skipping %s rebuild for %s; target fingerprint unchanged and build artifacts are present.",
                sanitizer,
                proj_name,
            )
            return False

        if self._restore_build_artifacts_from_cache(proj_name, sanitizer, fingerprint):
            return False

        logger.info(
            "Rebuild required for %s/%s: no reusable in-memory build state or artifact cache matched fingerprint %s.",
            proj_name,
            sanitizer,
            fingerprint[:12],
        )
        return True

    def _record_build_state(self, proj_name: str, sanitizer: str, fingerprint: str | None = None) -> None:
        self._project_build_state[proj_name] = BuildState(
            sanitizer=sanitizer,
            target_fingerprint=fingerprint or self._get_project_target_fingerprint(proj_name),
        )

    def _convert_str_to_seed_bytes(self, seed_str: str) -> bytes:
        # 第一層：處理來自 LLM 的、包含 "\\x" 字面文字的字串
        if r"\x" in seed_str:
            try:
                result = codecs.decode(seed_str.encode("utf-8"), "unicode_escape")
                # 確保結果是 bytes
                return result if isinstance(result, bytes) else result.encode("latin-1")
            except Exception:
                pass  # 失敗則退回到下面的通用處理

        # 第二層：處理不含 "\\x" 字面文字的、已經被 Python 解譯過的字串
        else:
            try:
                # 優先嘗試 'latin-1'，這能正確處理 '\xDE' 這種單一位元組字元
                # 和 'AAAAAAAAAAAAAAAA' 這種純 ASCII 字元。
                return seed_str.encode("latin-1")
            except UnicodeEncodeError:
                # 如果 'latin-1' 失敗，代表字串中有 '😂' 或 '你' 這種高位元字元，
                # 我們就退回到萬能的 'utf-8'。
                return seed_str.encode("utf-8")

    def build_fuzzers(
        self,
        proj_name: str,
        sanitizer: str = "address",
        deadline: float | None = None,
    ) -> CompilationResult:
        """Builds fuzzers for the given project."""
        if not self._should_rebuild(proj_name, sanitizer):
            return CompilationResult(success=True)

        logger.info("Starting %s rebuild for %s.", sanitizer, proj_name)
        timeout = self._remaining_timeout(deadline)
        if timeout == 0:
            return CompilationResult(success=False, error="deadline reached")
        helper_result = self._run_helper_command(
            ["build_fuzzers", proj_name, "--clean", f"--sanitizer={sanitizer}"],
            timeout=timeout,
        )

        if helper_result.success:
            fingerprint = self._get_project_target_fingerprint(proj_name)
            self._record_build_state(proj_name, sanitizer, fingerprint)
            self._store_build_artifacts_in_cache(proj_name, sanitizer, fingerprint)
            logger.info(
                "Completed %s rebuild for %s with fingerprint %s.",
                sanitizer,
                proj_name,
                fingerprint[:12],
            )
            return CompilationResult(success=True)

        error_message = self._extract_build_error_message(helper_result.stdout + helper_result.stderr)
        logger.error(f"Compilation failed: {error_message}")
        return CompilationResult(success=False, error=error_message)

    def run_fuzzer(
        self,
        proj_name: str,
        fuzzer_name: str,
        seconds: int = 30,
        build_fuzzer: bool = True,
        deadline: float | None = None,
    ) -> CompilationResult:
        """Runs the fuzzer for the given project and fuzzer name."""
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.info(f"Skipping fuzzer {fuzzer_name}; deadline already reached.")
                return CompilationResult(success=False, error="deadline reached")
            seconds = min(seconds, max(1, int(remaining)))

        logger.info(f"Running fuzzer {fuzzer_name} for {seconds} seconds for project {proj_name}")

        if build_fuzzer and not (build_result := self.build_fuzzers(proj_name, deadline=deadline)).success:
            logger.error(f"Fuzzer {fuzzer_name} for project {proj_name} failed to build.")
            return CompilationResult(success=False, error=build_result.error)

        corpus_dir = self.build_corpus_dir / proj_name / fuzzer_name
        corpus_dir.mkdir(parents=True, exist_ok=True)

        timeout = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.info(f"Skipping fuzzer {fuzzer_name}; deadline reached before execution.")
                return CompilationResult(success=False, error="deadline reached")
            seconds = min(seconds, max(1, int(remaining)))
            timeout = remaining

        helper_result = self._run_helper_command(
            [
                "run_fuzzer",
                f"--corpus-dir={corpus_dir.absolute()}",
                proj_name,
                fuzzer_name,
                f" -max_total_time={seconds} ",  # Add space to avoid issues with command parsing
            ],
            timeout=timeout,
        )

        if not helper_result.success:
            full_output = helper_result.stdout + helper_result.stderr
            error_pattern = r"==\d+==\s*ERROR:.*"
            match = re.search(error_pattern, full_output, re.DOTALL)
            if helper_result.timed_out and match is None:
                logger.info(
                    "Fuzzer %s stopped at the wall-clock deadline after %.2fs.",
                    fuzzer_name,
                    timeout if timeout is not None else 0.0,
                )
                return CompilationResult(success=False, error="deadline reached")
            error_message = match.group(0) if match else full_output
            logger.error(f"Failed to run fuzzer {fuzzer_name}: \n{error_message}")
            return CompilationResult(success=False, error=error_message)

        logger.info(f"Fuzzer {fuzzer_name} ran successfully")
        return CompilationResult(success=True, error="")

    def _list_project_fuzzers(self, project_name: str) -> list[str]:
        fuzzer_dir = self.build_out_dir / project_name
        if not fuzzer_dir.exists():
            return []
        return sorted(
            f.name for f in fuzzer_dir.iterdir() if f.is_file() and f.name.startswith("llm_fuzzgen") and not f.suffix
        )

    def _sync_project_fuzzer_stats(self, project_name: str, fuzzers_to_run: list[str]) -> dict[str, float]:
        served = self._fuzzer_served_seconds.setdefault(project_name, {})
        active = set(fuzzers_to_run)
        for stale in list(served):
            if stale not in active:
                del served[stale]
        for fuzzer_name in fuzzers_to_run:
            served.setdefault(fuzzer_name, 0.0)
        return served

    def _run_fuzzer_time_slice(
        self,
        project_name: str,
        fuzzer_name: str,
        seconds: int,
        deadline: float | None = None,
    ) -> FuzzerTimeSliceResult:
        started_at = time.monotonic()
        result = self.run_fuzzer(
            project_name,
            fuzzer_name,
            seconds,
            build_fuzzer=False,
            deadline=deadline,
        )
        actual_seconds = max(0.0, time.monotonic() - started_at)
        return FuzzerTimeSliceResult(
            fuzzer_name=fuzzer_name,
            requested_seconds=seconds,
            actual_seconds=actual_seconds,
            success=result.success,
            error=result.error,
        )

    def run_all_fuzzers(
        self,
        project_name: str,
        seconds: int = 30,
        max_workers: int | None = None,
        deadline: float | None = None,
    ):
        """Build and run all fuzzers using the original per-target execution model."""
        logger.info(f"Building all fuzzers for project {project_name}")
        build_result = self.build_fuzzers(project_name, deadline=deadline)
        if not build_result.success:
            logger.error(f"Failed to build fuzzers for project {project_name}.")
            return
        if deadline is not None and deadline - time.monotonic() <= 0:
            logger.info(f"Skipping fuzzers for {project_name}; deadline reached after build.")
            return

        fuzzers_to_run = self._list_project_fuzzers(project_name)
        if not fuzzers_to_run:
            logger.warning("No llm_fuzzgen fuzzers found for %s.", project_name)
            return

        try:
            with ThreadPoolExecutor(max_workers) as executor:
                futures = {
                    executor.submit(
                        self.run_fuzzer,
                        project_name,
                        fuzzer_name,
                        seconds,
                        build_fuzzer=False,
                        deadline=deadline,
                    )
                    for fuzzer_name in fuzzers_to_run
                    if deadline is None or deadline - time.monotonic() > 0
                }
                for future in as_completed(futures):
                    try:
                        future.result()
                    except BaseException as exc:
                        logger.error(f"Fuzzer execution generated an exception: {exc}")
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user. Shutting down...")

    def run_all_fuzzers_scheduled(
        self,
        project_name: str,
        seconds: int = 30,
        max_workers: int | None = None,
        deadline: float | None = None,
    ):
        """Run fuzzers within a wall-clock budget using least-served-first scheduling."""
        logger.info(f"Building all fuzzers for project {project_name}")
        build_result = self.build_fuzzers(project_name, deadline=deadline)
        if not build_result.success:
            logger.error(f"Failed to build fuzzers for project {project_name}.")
            return
        if deadline is not None and deadline - time.monotonic() <= 0:
            logger.info(f"Skipping fuzzers for {project_name}; deadline reached after build.")
            return

        fuzzers_to_run = self._list_project_fuzzers(project_name)
        if not fuzzers_to_run:
            logger.warning("No llm_fuzzgen fuzzers found for %s.", project_name)
            return

        served_seconds = self._sync_project_fuzzer_stats(project_name, fuzzers_to_run)
        chunk_deadline = time.monotonic() + max(1, seconds)
        effective_deadline = min(deadline, chunk_deadline) if deadline is not None else chunk_deadline
        max_workers = max_workers or min(6, len(fuzzers_to_run)) or 1
        quantum_seconds = max(1, min(self.DEFAULT_FUZZ_QUANTUM_SECONDS, seconds))
        logger.info(
            "Scheduling %d fuzzers for %s with wall-clock budget=%ds, workers=%d, quantum=%ds using least-served-first.",
            len(fuzzers_to_run),
            project_name,
            seconds,
            max_workers,
            quantum_seconds,
        )

        try:
            with ThreadPoolExecutor(max_workers) as executor:
                in_flight: dict = {}

                def schedule_one() -> bool:
                    remaining = effective_deadline - time.monotonic()
                    if remaining <= 1:
                        return False
                    available = [name for name in fuzzers_to_run if name not in in_flight.values()]
                    if not available:
                        return False
                    next_fuzzer = min(available, key=lambda name: (served_seconds.get(name, 0.0), name))
                    slice_seconds = max(1, min(quantum_seconds, int(remaining)))
                    logger.info(
                        "Dispatching %s for %ds (served_so_far=%.2fs, remaining_chunk_budget=%.2fs)",
                        next_fuzzer,
                        slice_seconds,
                        served_seconds.get(next_fuzzer, 0.0),
                        remaining,
                    )
                    future = executor.submit(
                        self._run_fuzzer_time_slice,
                        project_name,
                        next_fuzzer,
                        slice_seconds,
                        effective_deadline,
                    )
                    in_flight[future] = next_fuzzer
                    return True

                while len(in_flight) < max_workers and schedule_one():
                    pass

                while in_flight:
                    timeout = max(0.1, effective_deadline - time.monotonic())
                    done, _ = wait(in_flight.keys(), timeout=timeout, return_when=FIRST_COMPLETED)
                    if not done:
                        logger.info(
                            "Reached wall-clock barrier for %s with %d fuzzer task(s) still draining.",
                            project_name,
                            len(in_flight),
                        )
                        done, _ = wait(in_flight.keys(), return_when=ALL_COMPLETED)
                    for future in done:
                        fuzzer_name = in_flight.pop(future)
                        try:
                            slice_result = future.result()
                            served_seconds[fuzzer_name] = served_seconds.get(fuzzer_name, 0.0) + slice_result.actual_seconds
                            logger.info(
                                "Completed slice for %s: requested=%ds actual=%.2fs cumulative=%.2fs success=%s",
                                fuzzer_name,
                                slice_result.requested_seconds,
                                slice_result.actual_seconds,
                                served_seconds[fuzzer_name],
                                slice_result.success,
                            )
                            if not slice_result.success and slice_result.error != "deadline reached":
                                logger.error("Fuzzer %s slice failed: %s", fuzzer_name, slice_result.error)
                        except BaseException as exc:
                            logger.error(f"Fuzzer execution generated an exception: {exc}")
                    while len(in_flight) < max_workers and schedule_one():
                        pass

                logger.info(
                    "Finished wall-clock fuzzing chunk for %s. Top least-served targets: %s",
                    project_name,
                    ", ".join(
                        f"{name}={served_seconds[name]:.2f}s"
                        for name in sorted(served_seconds, key=lambda item: (served_seconds[item], item))[:5]
                    ),
                )
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user. Shutting down...")

    def coverage(
        self,
        proj_name: str,
        fuzzer_name: str = None,
        seconds: int = 60,
        fun_name_regex: str = None,
        deadline: float | None = None,
    ) -> TotalCoverageSummary | None:
        """
        Run fuzzer and return the coverage percentage of the given fuzzer.
        `seconds` only applies if `fuzzer_name` is provided.
        `fun_name_regex` is the regex to filter function names for coverage.
        """
        if fuzzer_name:
            logger.info(f"Computing coverage for {proj_name} with fuzzer {fuzzer_name}")
        else:
            logger.info(f"Computing coverage for {proj_name} with existing corpus")

        # If fuzzer_name is provided, run the fuzzer to build the corpus
        if fuzzer_name:
            self.run_fuzzer(proj_name, fuzzer_name, seconds, deadline=deadline)

        if deadline is not None and deadline - time.monotonic() <= 0:
            logger.info(f"Skipping coverage for {proj_name}; deadline reached.")
            return None

        # Build with coverage instrumentation
        if not self.build_fuzzers(proj_name, "coverage", deadline=deadline).success:
            logger.error(f"Failed to build coverage for {proj_name}")
            return None

        # Generate coverage report
        cmd = ["coverage", "--no-corpus-download", "--no-serve", proj_name]
        if fun_name_regex:
            cmd.extend(["--", f"--name-regex={fun_name_regex}"])
        timeout = self._remaining_timeout(deadline)
        if timeout == 0:
            logger.info(f"Skipping coverage report for {proj_name}; deadline reached.")
            return None
        helper_result = self._run_helper_command(cmd, timeout=timeout)

        if not helper_result.success:
            logger.error(f"Coverage computation failed: \n {helper_result.stdout}{helper_result.stderr}")
            return None

        # Read coverage data
        source_info = f"with fuzzer {fuzzer_name}" if fuzzer_name else "with existing corpus"
        if total_cov := self.get_coverage_summary(proj_name, exclude_target=True):
            line_percent = total_cov.lines.percent if total_cov.lines else "N/A"
            branch_percent = total_cov.branches.percent if total_cov.branches else "N/A"
            logger.info(f"Coverage for {proj_name} {source_info}: Lines={line_percent}%, Branches={branch_percent}%")
            return total_cov

        logger.error(f"Could not retrieve coverage for {proj_name} {source_info}")
        return None

    def generate_report(
        self,
        proj_name: str,
        seconds: int = 10,
        clean: bool = False,
        deadline: float | None = None,
    ) -> bool:
        """Generates an introspector report for the given project."""
        logger.info(f"Creating introspector reports for {proj_name}")
        started_at = time.perf_counter()

        cmd = ["introspector", "--seconds", str(seconds)]
        if clean:
            cmd.append("--clean")
        cmd.append(proj_name)

        timeout = self._remaining_timeout(deadline)
        if timeout == 0:
            logger.info(f"Skipping introspector report for {proj_name}; deadline reached.")
            return False
        helper_result = self._run_helper_command(cmd, timeout=timeout)
        elapsed = time.perf_counter() - started_at

        if not helper_result.success:
            logger.error(
                "Failed to generate report for %s after %.2fs: \n %s%s",
                proj_name,
                elapsed,
                helper_result.stdout,
                helper_result.stderr,
            )
            return False

        # Clear the internal build state so that subsequent calls know the current out dir 
        # is dominated by introspector artifacts and forced to rebuild or restore from cache.
        self._project_build_state.pop(proj_name, None)

        logger.info(
            "Introspector reports created for %s in %.2fs (requested_seconds=%s, clean=%s)",
            proj_name,
            elapsed,
            seconds,
            clean,
        )
        return True

    def _introspector_output_dir(self, proj_name: str) -> Path:
        return self.build_out_dir / proj_name / "inspector"

    def _introspector_correlation_file(self, proj_name: str) -> Path:
        return self._introspector_output_dir(proj_name) / "exe_to_fuzz_introspector_logs.yaml"

    def _textcov_reports_dir(self, proj_name: str) -> Path:
        return self.build_out_dir / proj_name / "textcov_reports"

    def _sync_covreports_into_introspector(self, proj_name: str) -> bool:
        introspector_dir = self._introspector_output_dir(proj_name)
        textcov_dir = self._textcov_reports_dir(proj_name)
        if not introspector_dir.is_dir():
            logger.error("Introspector directory does not exist for %s: %s", proj_name, introspector_dir)
            return False
        if not textcov_dir.is_dir():
            logger.error("Textcov directory does not exist for %s: %s", proj_name, textcov_dir)
            return False
        if not os.access(introspector_dir, os.W_OK):
            logger.error("Introspector directory is not writable for %s: %s", proj_name, introspector_dir)
            return False

        synced = 0
        for covreport in textcov_dir.glob("*.covreport"):
            destination = introspector_dir / covreport.name
            try:
                shutil.copy2(covreport, destination)
            except PermissionError:
                logger.error(
                    "Permission denied while syncing %s into %s for %s.",
                    covreport,
                    destination,
                    proj_name,
                )
                return False
            synced += 1

        if synced == 0:
            logger.error("No .covreport files were found for %s under %s", proj_name, textcov_dir)
            return False

        logger.info("Synced %d covreport files into %s", synced, introspector_dir)
        return True

    def refresh_blocker_report_from_existing_introspector(
        self,
        proj_name: str,
        deadline: float | None = None,
    ) -> bool:
        """Re-run introspector report generation using existing static data."""
        timeout = self._remaining_timeout(deadline)
        if timeout == 0:
            logger.info("Skipping light blocker report refresh for %s; deadline reached.", proj_name)
            return False

        introspector_dir = self._introspector_output_dir(proj_name)
        if not introspector_dir.is_dir():
            logger.error("Cannot light-refresh blocker report for %s: missing %s", proj_name, introspector_dir)
            return False
        if not os.access(introspector_dir, os.W_OK):
            logger.error("Cannot light-refresh blocker report for %s: %s is not writable", proj_name, introspector_dir)
            return False
        if not self.fuzz_introspector_cli.is_file():
            logger.error("Cannot locate fuzz-introspector CLI at %s", self.fuzz_introspector_cli)
            return False
        if not self._sync_covreports_into_introspector(proj_name):
            return False

        correlation_file = self._introspector_correlation_file(proj_name)
        cmd = [
            "python3",
            str(self.fuzz_introspector_cli),
            "report",
            "--target-dir",
            str(introspector_dir),
            "--out-dir",
            str(introspector_dir),
            "--name",
            proj_name,
            "--language",
            self.proj_lang(proj_name),
        ]
        if correlation_file.is_file():
            cmd.extend(["--correlation-file", str(correlation_file)])

        env = {**os.environ, "PYTHONPATH": str(self.fuzz_introspector_cli.parent.parent)}
        logger.info("Refreshing blocker report from existing introspector data for %s", proj_name)
        try:
            process = subprocess.run(
                cmd,
                cwd=str(self.fuzz_introspector_cli.parent.parent),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                errors="ignore",
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("Light blocker report refresh timed out for %s", proj_name)
            return False
        except BaseException as exc:
            logger.error("Failed to execute light blocker report refresh for %s: %s", proj_name, exc)
            return False

        if process.returncode != 0:
            logger.error(
                "Light blocker report refresh failed for %s:\n%s%s",
                proj_name,
                process.stdout,
                process.stderr,
            )
            return False

        logger.info("Light blocker report refresh completed for %s", proj_name)
        return True

    def get_project_info(self, proj_name: str, key: str, default: str = "") -> str:
        """Get project information from project.yaml."""
        data = self._get_project_yaml(proj_name)
        return data.get(key, default)

    def main_git_repo(self, proj_name: str) -> str:
        """Returns the main repository URL for the given project"""
        return self.get_project_info(proj_name, "main_repo")

    def commit_hash(self, proj_name: str) -> str:
        """Returns the commit hash of the given project"""
        return self.get_project_info(proj_name, "commit_hash")

    def proj_lang(self, proj_name: str) -> str:
        """Returns the language of the given project"""
        return self.get_project_info(proj_name, "language")

    def save_target(self, proj_name: str, code: str) -> Path:
        """Saves the given code as a fuzzer target for the project"""
        lang = self.proj_lang(proj_name)
        target_dir = self.oss_fuzz_dir / "projects" / proj_name
        timestamp = datetime.now().strftime("%m%d%H%M%S")
        extension = self.LANG_EXT.get(lang.lower(), ".c")
        target_file = target_dir / f"llm_fuzzgen{timestamp}{extension}"

        target_file.write_text(code)
        logger.info(f"Saved fuzz target to {target_file}")
        return target_file

    def remove_target(self, proj_name: str, target_name: str) -> None:
        """Removes the fuzzer target for the given project"""
        target_dir = self.oss_fuzz_dir / "projects" / proj_name
        for item in target_dir.iterdir():
            if item.is_file() and item.name.startswith(target_name):
                item.unlink(True)
                logger.info(f"Removed target file {item}")

        binary_path = self.build_out_dir / proj_name / target_name
        if binary_path.exists():
            binary_path.unlink(True)
            logger.info(f"Removed binary target at {binary_path}")

        self.remove_corpus(proj_name, target_name)

    def _format_funcov_report(self, report_content: str) -> str:
        """
        Reads the content of an llvm-cov report, filters and formats it,
        and returns the result as a string.

        Processing logic:
        1. Removes all columns related to 'Regions'.
        2. Filters out functions where both Lines Miss and Branches Miss are 0.
        3. Removes the 'TOTAL' summary line.
        4. The width of the function name column is dynamically adjusted to ensure alignment.

        :param report_content: The content string of the llvm-cov report.
        :return: The formatted report string.
        """
        lines = report_content.splitlines()
        NUM_WIDTH, MISS_WIDTH, COVER_WIDTH = 10, 7, 10

        # Regex for parsing data lines (functions or TOTAL)
        data_line_re = re.compile(
            r"^(?P<name>.+?)\s+"
            r"(?P<r_c>\d+)\s+(?P<r_m>\d+)\s+(?P<r_p>[\d.]+%)\s+"  # regions
            r"(?P<l_c>\d+)\s+(?P<l_m>\d+)\s+(?P<l_p>[\d.]+%)\s+"  # lines
            r"(?P<b_c>\d+)\s+(?P<b_m>\d+)\s+(?P<b_p>[\d.]+%)\s*$"  # branches
        )

        # Pass 1: Parse, filter, and find the maximum function name width
        processed_items = []
        max_name_width = len("Name")

        for line in lines:
            line = line.rstrip()

            if "Regions" in line and "Lines" in line and "Branches" in line:
                processed_items.append({"type": "header"})
            elif line.startswith("---"):
                processed_items.append({"type": "separator"})
            elif match := data_line_re.match(line):
                data = match.groupdict()
                name = data["name"].strip()

                # Skip TOTAL line and fully covered functions
                if name == "TOTAL" or (int(data["l_m"]) == 0 and int(data["b_m"]) == 0):
                    continue

                processed_items.append({"type": "data", "data": data})
                max_name_width = max(max_name_width, len(data["name"]))
            else:
                # Other info lines (e.g., file paths, blank lines)
                processed_items.append({"type": "info", "data": line})

        # Pass 2: Format the output
        name_width = max_name_width + 2  # Add some padding
        header = (
            f"{'Name':<{name_width}} "
            f"{'Lines':>{NUM_WIDTH}} {'Miss':>{MISS_WIDTH}} {'Cover':>{COVER_WIDTH}} "
            f"{'Branches':>{NUM_WIDTH}} {'Miss':>{MISS_WIDTH}} {'Cover':>{COVER_WIDTH}}"
        )
        separator = "-" * len(header)

        output_lines: list[str] = []
        for item in processed_items:
            item_type = item["type"]
            if item_type == "header":
                output_lines.append(header)
            elif item_type == "separator":
                output_lines.append(separator)
            elif item_type == "info":
                output_lines.append(item["data"])
            elif item_type == "data":
                data = item["data"]
                line = (
                    f"{data['name']:<{name_width}} "
                    f"{data['l_c']:>{NUM_WIDTH}} {data['l_m']:>{MISS_WIDTH}} {data['l_p']:>{COVER_WIDTH}} "
                    f"{data['b_c']:>{NUM_WIDTH}} {data['b_m']:>{MISS_WIDTH}} {data['b_p']:>{COVER_WIDTH}}"
                )
                output_lines.append(line)

        return "\n".join(output_lines)

    def funcov_reports(self, proj_name: str, fuzzer_name: str = None) -> str:
        """Returns the formatted funcov report for the given fuzzer."""
        logger.info(f"Generating funcov report for {proj_name} with {fuzzer_name if fuzzer_name else 'project'}")
        self.coverage(proj_name)
        if fuzzer_name:
            report_file = self.build_out_dir / proj_name / "textcov_reports" / f"{fuzzer_name}.funcovreport"
        else:
            report_file = self.build_out_dir / proj_name / "textcov_reports" / "project.funcovreport"
        if not report_file.exists():
            logger.error(f"Report file {report_file} does not exist.")
            return ""

        raw_report = report_file.read_text()
        return self._format_funcov_report(raw_report)

    def linecov_reports(self, proj_name: str, fuzzer_name: str, fun_name_regex: str = "LLVMFuzzerTestOneInput") -> str:
        """
        Returns the linecov report for the given fuzzer.
        `fun_name_regex` is the regex to filter function names for coverage. (default: "LLVMFuzzerTestOneInput")
        """
        logger.info(f"Generating linecov report for {proj_name} with fuzzer {fuzzer_name} and function regex {fun_name_regex}")
        self.coverage(proj_name, fun_name_regex=fun_name_regex)
        report_file = self.build_out_dir / proj_name / "textcov_reports" / f"{fuzzer_name}.linecovreport"
        if not report_file.exists():
            logger.error(f"Report file {report_file} does not exist.")
            return ""

        return report_file.read_text()

    def proj_linecov_reports(self, proj_name: str, fun_name_regex: str = None) -> str:
        """
        Returns the project linecov report.
        `fun_name_regex` is the regex to filter function names for coverage.
        """
        logger.info(f"Generating project linecov report for {proj_name} with function regex {fun_name_regex}")
        self.coverage(proj_name, fun_name_regex=fun_name_regex)
        report_file = self.build_out_dir / proj_name / "textcov_reports" / "project.linecovreport"
        if not report_file.exists():
            logger.error(f"Report file {report_file} does not exist.")
            return ""

        return report_file.read_text()

    def add_seeds(self, proj_name: str, fuzzer_name: str, seeds: list[str]) -> None:
        """Adds seeds to the project's seed corpus.

        If the corpus zip file already exists, adds new seeds to it.
        Otherwise, creates a new zip file.
        """
        project_dir = self.oss_fuzz_dir / "projects" / proj_name
        if not project_dir.is_dir():
            logger.error(f"Project directory {project_dir} does not exist.")
            return

        zip_filename = f"{fuzzer_name}_seed_corpus.zip"
        zip_filepath = project_dir / zip_filename

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                new_seed_files = []
                for seed_content in seeds:
                    # Generate a unique filename for each seed to avoid collisions
                    seed_filename = str(uuid.uuid4())
                    seed_filepath = tmp_path / seed_filename
                    try:
                        seed_bytes = self._convert_str_to_seed_bytes(seed_content)

                        seed_filepath.write_bytes(seed_bytes)
                        new_seed_files.append(seed_filepath)
                    except Exception as e:
                        logger.error(
                            f"Failed to write temporary seed file {seed_filename} for content '{seed_content[:50]}...': {e}"
                        )
                        # Continue trying to write other seeds

                if not new_seed_files:
                    logger.warning("No valid new seed files were generated to add.")
                    return

                # Determine zip mode: 'w' (write) if file doesn't exist, 'a' (append) if it does
                zip_mode = "a" if zip_filepath.exists() else "w"

                try:
                    with zipfile.ZipFile(zip_filepath, zip_mode, zipfile.ZIP_DEFLATED) as seed_zip:
                        # Keep track of existing filenames in the zip to avoid duplicates if appending
                        existing_files = set(seed_zip.namelist()) if zip_mode == "a" else set()

                        for file_path in new_seed_files:
                            # Ensure the generated filename isn't already in the zip
                            arcname = file_path.name
                            while arcname in existing_files:
                                arcname = str(uuid.uuid4())  # Generate a new unique name if collision

                            seed_zip.write(file_path, arcname=arcname)
                            if zip_mode == "a":  # Add to existing set if appending
                                existing_files.add(arcname)

                    action = "Appended to" if zip_mode == "a" else "Successfully created"
                    logger.info(f"{len(new_seed_files)} seeds {action.lower()} seed corpus zip: {zip_filepath}")

                except Exception as e:
                    logger.error(f"Failed to {'append to' if zip_mode == 'a' else 'create'} seed corpus zip {zip_filepath}: {e}")

        except Exception as e:
            logger.error(f"An error occurred during seed processing: {e}")

    def add_dict(self, proj_name: str, dict_content: str) -> None:
        if dict_content is None or not dict_content.strip():
            logger.warning("No dictionary content provided to add.")
            return

        project_dir = self.oss_fuzz_dir / "projects" / proj_name
        dict_filepath = project_dir / f"llm_fuzzgen.dict"
        try:
            dict_filepath = project_dir / f"llm_fuzzgen.dict"
            with open(dict_filepath, "a") as f:
                f.write("\n" + dict_content.strip())

            logger.info(f"Added dictionary content to: {dict_filepath}")

        except Exception as e:
            logger.error(f"Failed to write dictionary file {dict_filepath.name}: {e}")

    def get_coverage_summary(
        self, proj_name: str, fuzz_target_name: str = None, exclude_target: bool = False
    ) -> TotalCoverageSummary | None:
        """Reads and parses the coverage summary.json for a given project."""
        base_path = self.build_out_dir / proj_name
        if exclude_target:
            summary_json_path = base_path / "textcov_reports" / "summary_exclude_target.json"
        else:
            summary_json_path = (
                base_path / "report_target" / fuzz_target_name / "linux" / "summary.json"
                if fuzz_target_name
                else base_path / "report" / "linux" / "summary.json"
            )

        if not summary_json_path.exists():
            logger.error(f"Coverage summary file not found: {summary_json_path}")
            return None

        try:
            with open(summary_json_path) as f:
                data = json.load(f)

            totals = data.get("data", [{}])[0].get("totals")
            if not totals:
                logger.error("Could not find 'totals' in coverage JSON data.")
                return None

            summary_data = {
                metric: CoverageMetricSummary(
                    count=metric_data.get("count", 0),
                    covered=metric_data.get("covered", 0),
                    percent=metric_data.get("percent", 0.0),
                )
                for metric in ["branches", "functions", "lines"]
                if (metric_data := totals.get(metric))
            }

            if not summary_data:
                logger.error("Could not extract any summary data from totals.")
                return None

            if exclude_target:
                logger.info(f"Successfully extracted total coverage summary for {proj_name} (excluding target).")
            else:
                logger.info(f"Successfully extracted total coverage summary for {proj_name}.")

            return TotalCoverageSummary(**summary_data)

        except Exception as e:
            logger.error(f"Error processing coverage summary for {proj_name}: {e}")
            return None

    def copy_empty_fuzz_target(self, proj_name: str) -> bool:
        """Copies the empty fuzz target template to the specified project directory."""
        proj_path = self.oss_fuzz_dir / "projects" / proj_name
        if not proj_path.is_dir():
            logger.error(f"Project directory {proj_path} does not exist.")
            return False
        empty_target_path = self.empty_fuzz_target_c if self.proj_lang(proj_name).lower() == "c" else self.empty_fuzz_target_cc
        destination_path = proj_path / empty_target_path.name

        try:
            shutil.copy(empty_target_path, destination_path)
            logger.info(f"Copied empty fuzz target from {empty_target_path} to {destination_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to copy empty fuzz target from {empty_target_path} to {destination_path}: {e}")
            return False

    def remove_corpus(self, proj_name: str, fuzzer_name: str) -> None:
        """Removes the corpus directory for the specified project and fuzzer."""
        corpus_dir = self.build_corpus_dir / proj_name / fuzzer_name
        if corpus_dir.exists():
            try:
                shutil.rmtree(corpus_dir)
                logger.info(f"Removed corpus directory {corpus_dir}")
            except Exception as e:
                logger.error(f"Failed to remove corpus directory {corpus_dir}: {e}", exc_info=True)

    @staticmethod
    def _minimize_corpus_worker(args):
        """
        Worker function to minimize a single fuzzer's corpus by executing a script inside a fresh Docker container.
        """
        fuzzer_name, proj_name, oss_fuzz_dir_str = args

        # Define paths as they exist inside the Docker container
        container_base_path = "/src/oss-fuzz"
        fuzzer_path = f"{container_base_path}/build/out/{proj_name}/{fuzzer_name}"
        corpus_path = f"{container_base_path}/build/corpus/{proj_name}/{fuzzer_name}"
        tmp_corpus_path = f"{corpus_path}_tmp"

        # This script runs entirely inside the container, ensuring correct permissions.
        script = f"""
        set -e
        if [ ! -d "{corpus_path}" ] || [ -z "$(ls -A {corpus_path} 2>/dev/null)" ]; then
            echo "Corpus for {fuzzer_name} is empty or does not exist. Skipping."
            exit 0
        fi
        echo "Minimizing corpus for {fuzzer_name}..."
        mkdir -p {tmp_corpus_path}
        {fuzzer_path} -use_value_profile=1 -set_cover_merge=1 {tmp_corpus_path} {corpus_path}
        rm -rf {corpus_path}
        mv {tmp_corpus_path} {corpus_path}
        echo "Corpus for {fuzzer_name} minimized successfully."
        """

        image_name = f"gcr.io/oss-fuzz/{proj_name}"
        volume_mount = f"{oss_fuzz_dir_str}:{container_base_path}"

        cmd = ["docker", "run", "--rm", "-v", volume_mount, image_name, "bash", "-c", script]

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, errors="ignore")
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, f"Docker command failed: {e.stderr or e.stdout}"
        except Exception as e:
            return False, f"An unexpected error occurred: {e}"

    def minimize_corpus(self, proj_name: str) -> None:
        """Minimizes the corpus for all fuzz targets of a given project in parallel."""
        logger.info(f"Minimizing corpus for project {proj_name}")

        build_result = self.build_fuzzers(proj_name)
        if not build_result.success:
            logger.error(f"Failed to build fuzzers for {proj_name}. Aborting corpus minimization.")
            return

        project_out_dir = self.build_out_dir / proj_name
        fuzz_targets = [
            f
            for f in project_out_dir.iterdir()
            if f.is_file() and f.stat().st_mode & 0o111 and "." not in f.name and f.name != "llvm-symbolizer"
        ]

        if not fuzz_targets:
            logger.warning(f"No fuzz targets found for project {proj_name}.")
            return

        tasks = [(target.name, proj_name, str(self.oss_fuzz_dir)) for target in fuzz_targets]

        with ThreadPoolExecutor() as executor:
            future_to_fuzzer = {executor.submit(OSSFuzz._minimize_corpus_worker, task): task[0] for task in tasks}
            for future in as_completed(future_to_fuzzer):
                fuzzer_name = future_to_fuzzer[future]
                try:
                    success, message = future.result()
                    if success:
                        logger.info(f"Successfully minimized corpus for {proj_name} - {fuzzer_name}")
                    else:
                        logger.error(f"Failed to minimize corpus for {proj_name} - {fuzzer_name}: {message}")
                except Exception as exc:
                    logger.error(f"{proj_name} - {fuzzer_name} generated an exception: {exc}")

    def reproduce_crash(self, proj_name: str, fuzzer_name: str, crash_input_path: Path) -> str:
        """
        Reproduces a crash and returns the formatted stack trace from the fuzzer's output.
        """
        logger.info(f"Reproducing crash for {proj_name} with fuzzer {fuzzer_name} and input {crash_input_path.name}")
        helper_result = self._run_helper_command(["reproduce", proj_name, fuzzer_name, str(crash_input_path.resolve())])
        stdout = helper_result.stdout

        # Dynamically create a regex to find the start of the fuzzer's execution log.
        # e.g., /out/llm_fuzzgen0719004011 -rss_limit_mb=2560 ...
        # We escape the fuzzer_name to handle any special regex characters it might contain.
        crash_log_pattern = re.compile(rf"/out/{re.escape(fuzzer_name)}:.*", re.DOTALL)
        match = crash_log_pattern.search(stdout)

        if match:
            extracted_log = match.group(0)
            logger.info(f"Successfully extracted crash log for {fuzzer_name}.")
            return extracted_log

        logger.error(f"Could not extract crash log starting with '/out/{fuzzer_name}' from the stdout.")
        return stdout  # Return the full output as a fallback
