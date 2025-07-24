import codecs
import json
import logging
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class OSSFuzz:
    LANG_EXT: dict[str, str] = {"c": ".c", "c++": ".cc", "cpp": ".cc"}

    def __init__(self, oss_fuzz_dir: Path | None = None):
        self.oss_fuzz_dir: Path = oss_fuzz_dir or Path(__file__).parent / "oss-fuzz"
        self.helper_script: Path = self.oss_fuzz_dir / "infra" / "helper.py"
        self.build_out_dir: Path = self.oss_fuzz_dir / "build" / "out"
        self.build_corpus_dir: Path = self.oss_fuzz_dir / "build" / "corpus"
        self.empty_fuzz_target_c: Path = Path(__file__).parent / "llm_fuzzgen_empty.c"
        self.empty_fuzz_target_cc: Path = Path(__file__).parent / "llm_fuzzgen_empty.cc"

    def _get_project_yaml(self, proj_name: str) -> dict:
        """Read and parse project.yaml file."""
        proj_yaml_path = self.oss_fuzz_dir / "projects" / proj_name / "project.yaml"
        with open(proj_yaml_path) as f:
            return yaml.safe_load(f)

    def _run_helper_command(self, args: list[str]) -> tuple[bool, str, str]:
        """Run helper.py command and return success status, stdout, and stderr."""
        try:
            process = subprocess.run(
                ["python", str(self.helper_script)] + args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                errors="ignore",
            )
            return process.returncode == 0, process.stdout, process.stderr
        except BaseException as e:
            logger.warning(f"Helper command '{args}' failed with exception: {e}")
            return False, "", str(e)

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

    def build_fuzzers(self, proj_name: str, sanitizer: str = "address") -> CompilationResult:
        """Builds fuzzers for the given project."""
        success, stdout, stderr = self._run_helper_command(["build_fuzzers", proj_name, "--clean", f"--sanitizer={sanitizer}"])

        if success:
            return CompilationResult(success=True)

        error_message = self._extract_build_error_message(stdout + stderr)
        logger.error(f"Compilation failed: {error_message}")
        return CompilationResult(success=False, error=error_message)

    def run_fuzzer(self, proj_name: str, fuzzer_name: str, seconds: int = 30, build_fuzzer: bool = True) -> CompilationResult:
        """Runs the fuzzer for the given project and fuzzer name."""
        logger.info(f"Running fuzzer {fuzzer_name} for {seconds} seconds for project {proj_name}")

        if build_fuzzer and not (build_result := self.build_fuzzers(proj_name)).success:
            logger.error(f"Fuzzer {fuzzer_name} for project {proj_name} failed to build.")
            return CompilationResult(success=False, error=build_result.error)

        corpus_dir = self.build_corpus_dir / proj_name / fuzzer_name
        corpus_dir.mkdir(parents=True, exist_ok=True)

        success, stdout, stderr = self._run_helper_command(
            [
                "run_fuzzer",
                f"--corpus-dir={corpus_dir.absolute()}",
                proj_name,
                fuzzer_name,
                f" -max_total_time={seconds} ",  # Add space to avoid issues with command parsing
            ]
        )

        if not success:
            full_output = stdout + stderr
            error_pattern = r"ERROR:.*?SUMMARY:[^\n]*"
            match = re.search(error_pattern, full_output, re.DOTALL)
            error_message = match.group(0) if match else full_output
            logger.error(f"Failed to run fuzzer {fuzzer_name}: \n{error_message}")
            return CompilationResult(success=False, error=error_message)

        logger.info(f"Fuzzer {fuzzer_name} ran successfully")
        return CompilationResult(success=True, error="")

    def run_all_fuzzers(self, project_name: str, seconds: int = 30):
        """Builds and runs all fuzzers for a given project."""
        logger.info(f"Building all fuzzers for project {project_name}")
        build_result = self.build_fuzzers(project_name)
        if not build_result.success:
            logger.error(f"Failed to build fuzzers for project {project_name}.")
            return

        fuzzer_dir = self.build_out_dir / project_name
        fuzzers_to_run = [
            f.name for f in fuzzer_dir.iterdir() if f.is_file() and f.name.startswith("llm_fuzzgen") and not f.suffix
        ]

        try:
            with ThreadPoolExecutor() as executor:
                futures = {
                    executor.submit(self.run_fuzzer, project_name, fuzzer_name, seconds, build_fuzzer=False)
                    for fuzzer_name in fuzzers_to_run
                }
                for future in as_completed(futures):
                    try:
                        future.result()
                    except BaseException as exc:
                        logger.error(f"Fuzzer execution generated an exception: {exc}")
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user. Shutting down...")

    def coverage(
        self, proj_name: str, fuzzer_name: str = None, seconds: int = 60, fun_name_regex: str = None
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
            self.run_fuzzer(proj_name, fuzzer_name, seconds)

        # Build with coverage instrumentation
        if not self.build_fuzzers(proj_name, "coverage").success:
            logger.error(f"Failed to build coverage for {proj_name}")
            return None

        # Generate coverage report
        cmd = ["coverage", "--no-corpus-download", "--no-serve", proj_name]
        if fun_name_regex:
            cmd.extend(["--", f"--name-regex={fun_name_regex}"])
        success, stdout, stderr = self._run_helper_command(cmd)

        if not success:
            logger.error(f"Coverage computation failed: \n {stdout}{stderr}")
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

    def generate_report(self, proj_name: str, seconds: int = 10, clean: bool = False) -> bool:
        """Generates an introspector report for the given project."""
        logger.info(f"Creating introspector reports for {proj_name}")

        cmd = ["introspector", "--seconds", str(seconds)]
        if clean:
            cmd.append("--clean")
        cmd.append(proj_name)

        success, stdout, stderr = self._run_helper_command(cmd)

        if not success:
            logger.error(f"Failed to generate report for {proj_name}: \n {stdout}{stderr}")
            return False

        logger.info(f"Introspector reports created for {proj_name}")
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
        _, stdout, _ = self._run_helper_command(["reproduce", proj_name, fuzzer_name, str(crash_input_path.resolve())])

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
