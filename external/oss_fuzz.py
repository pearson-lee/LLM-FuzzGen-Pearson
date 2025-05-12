import json
import logging
import re
import subprocess
import tempfile
import uuid
import zipfile
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
                capture_output=True,
                check=False,
                text=True,
                errors="ignore",
            )
            return process.returncode == 0, process.stdout, process.stderr
        except Exception as e:
            logger.warning(f"Helper command '{args}' failed with exception: {e}")
            return False, "", str(e)

    def _extract_error_message(self, output: str) -> str:
        """Extract relevant error message from compiler output."""
        pattern = r"error:.*?generated\."
        match = re.search(pattern, output, re.DOTALL)
        if match:
            return match.group(0)
        return output

    def build_fuzzers(self, proj_name: str, sanitizer: str = "address") -> CompilationResult:
        """Builds fuzzers for the given project."""
        success, stdout, stderr = self._run_helper_command(
            ["build_fuzzers", f"--sanitizer={sanitizer}", proj_name]
        )

        if success:
            return CompilationResult(success=True)

        error_message = self._extract_error_message(stdout + stderr)
        logger.error(f"Compilation failed: {error_message}")
        return CompilationResult(success=False, error=error_message)

    def run_fuzzer(self, proj_name: str, fuzzer_name: str, seconds: int = 10) -> bool:
        """Runs the fuzzer for the given project and fuzzer name."""
        logger.info(f"Running fuzzer {fuzzer_name} for project {proj_name}")

        # Build the fuzzer
        binary_path = self.build_out_dir / proj_name / fuzzer_name
        if not self.build_fuzzers(proj_name).success:
            logger.error(f"Fuzzer {fuzzer_name} for project {proj_name} failed to build.")
            return False

        corpus_dir = self.build_corpus_dir / proj_name / fuzzer_name
        corpus_dir.mkdir(parents=True, exist_ok=True)

        success, stdout, stderr = self._run_helper_command(
            [
                "run_fuzzer",
                f"--corpus-dir={corpus_dir.absolute()}",
                proj_name,
                fuzzer_name,
                f"-max_total_time={seconds} -detect_leaks=0 -use_value_profile=1",
            ]
        )

        if not success:
            logger.error(f"Failed to run fuzzer {fuzzer_name}: \n {stdout}{stderr}")
            binary_path.unlink(True)
            return False

        logger.info(f"Fuzzer {fuzzer_name} ran successfully")
        return True

    def coverage(self, proj_name: str, fuzzer_name: str = None) -> float:
        """Returns the coverage percentage of the given fuzzer."""
        if fuzzer_name:
            logger.info(f"Computing coverage for {proj_name} with fuzzer {fuzzer_name}")
        else:
            logger.info(f"Computing coverage for {proj_name}")
        summary_json = self.build_out_dir / proj_name / "report" / "linux" / "summary.json"

        # If fuzzer_name is provided, run the fuzzer to build the corpus
        if fuzzer_name and not self.run_fuzzer(proj_name, fuzzer_name):
            logger.error(f"Failed to run fuzzer for coverage computation")
            return 0.0

        # Build with coverage instrumentation
        if not self.build_fuzzers(proj_name, "coverage").success:
            logger.error(f"Failed to build coverage for {proj_name}")
            return 0.0

        # Generate coverage report
        success, stdout, stderr = self._run_helper_command(
            ["coverage", "--no-corpus-download", "--no-serve", proj_name]
        )

        if not success:
            logger.error(f"Coverage computation failed: \n {stdout}{stderr}")
            return 0.0

        # Read coverage data
        if summary_json.exists():
            try:
                with open(summary_json) as f:
                    data = json.load(f)
                    percent = round(data["data"][0]["totals"]["lines"]["percent"], 2)
                    logger.info(f"Coverage for {proj_name} with {fuzzer_name}: {percent}%")
                    return percent
            except Exception as e:
                logger.error(f"Error parsing coverage data: {e}")

        logger.error(f"Summary JSON file {summary_json} does not exist.")
        return 0.0

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

    def textcov_reports(self, proj_name: str, fuzzer_name: str) -> str:
        """Returns the textcov report for the given fuzzer."""
        report_file = self.build_out_dir / proj_name / "textcov_reports" / f"{fuzzer_name}.covreport"

        if not report_file.exists():
            logger.error(f"Report file {report_file} does not exist.")
            return ""

        return report_file.read_text()

    def funcov_reports(self, proj_name: str, fuzzer_name: str) -> str:
        """Returns the funcov report for the given fuzzer."""
        report_file = self.build_out_dir / proj_name / "textcov_reports" / f"{fuzzer_name}.funcovreport"
        if not report_file.exists():
            logger.error(f"Report file {report_file} does not exist.")
            return ""

        return report_file.read_text()

    def reachable_functions_covered(self, proj_name: str, fuzzer_name: str) -> float:
        """Returns the percentage of reachable functions covered by the fuzzer."""
        summary_json = self.build_out_dir / proj_name / "inspector" / "summary.json"

        if not summary_json.exists():
            logger.error(f"Summary JSON file {summary_json} does not exist.")
            return 0.0

        try:
            with open(summary_json) as f:
                data = json.load(f)
                cov = data[fuzzer_name]["coverage-blocker-stats"]["cov-reach-proportion"]
                cov = round(cov, 2)
                logger.info(f"Reachable functions covered by {proj_name}-{fuzzer_name}: {cov}")
                return cov
        except Exception as e:
            logger.error(f"Error parsing coverage data: {e}")
            return 0.0

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
                        # Encode the string to bytes (using UTF-8 as assumed encoding, ignoring errors)
                        # and write raw bytes to the file.
                        seed_bytes = seed_content.encode("utf-8", errors="ignore")
                        seed_filepath.write_bytes(seed_bytes)
                        new_seed_files.append(seed_filepath)
                    except Exception as e:
                        logger.error(f"Failed to write temporary seed file {seed_filename}: {e}")
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
                    logger.info(f"{action} seed corpus zip: {zip_filepath}")

                except Exception as e:
                    logger.error(
                        f"Failed to {'append to' if zip_mode == 'a' else 'create'} seed corpus zip {zip_filepath}: {e}"
                    )

        except Exception as e:
            logger.error(f"An error occurred during seed processing: {e}")

    def add_dict(self, proj_name: str, dict_content: str) -> None:
        project_dir = self.oss_fuzz_dir / "projects" / proj_name
        dict_filepath = project_dir / f"llm_fuzzgen.dict"
        try:
            dict_filepath = project_dir / f"llm_fuzzgen.dict"
            with open(dict_filepath, "a") as f:
                f.write("\n" + dict_content.strip())

            logger.info(f"Added dictionary content to: {dict_filepath}")

        except Exception as e:
            logger.error(f"Failed to write dictionary file {dict_filepath.name}: {e}")

    def get_total_coverage_summary(self, proj_name: str) -> TotalCoverageSummary | None:
        """Reads and parses the coverage summary.json for a given project."""
        summary_json_path = self.build_out_dir / proj_name / "report" / "linux" / "summary.json"

        if not summary_json_path.exists():
            logger.error(f"Coverage summary file not found: {summary_json_path}")
            return None

        try:
            with open(summary_json_path, 'r') as f:
                data = json.load(f)

            totals = data.get("data", [{}])[0].get("totals")
            if not totals:
                logger.error("Could not find 'totals' in coverage JSON data.")
                return None

            summary_data = {}
            for metric_name in ["branches", "functions", "lines"]:
                metric_data = totals.get(metric_name)
                if metric_data:
                    summary_data[metric_name] = CoverageMetricSummary(
                        count=metric_data.get("count", 0),
                        covered=metric_data.get("covered", 0),
                        percent=metric_data.get("percent", 0.0)
                    )

            if not summary_data:
                 logger.error("Could not extract any summary data from totals.")
                 return None

            total_summary = TotalCoverageSummary(**summary_data)

            logger.info(f"Successfully extracted total coverage summary for {proj_name}.")
            return total_summary

        except Exception as e:
            logger.error(f"An error occurred while processing coverage summary for {proj_name} from {summary_json_path}: {e}")
            return None
