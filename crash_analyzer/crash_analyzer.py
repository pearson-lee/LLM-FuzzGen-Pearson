import logging
import re
import shutil
from pathlib import Path

import prompts.prompt_generator as prompt_generator
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient

logger = logging.getLogger(__name__)


class CrashAnalyzer:
    """
    Analyzes crashes found by OSS-Fuzz, uses an LLM to determine their
    validity, and generates reports and reduced test cases.
    """

    def __init__(self, llm_client: "LLMClient", oss_fuzz: OSSFuzz):
        """
        Initializes the CrashAnalyzer.
        """
        self.llm_client = llm_client
        self.oss_fuzz = oss_fuzz
        self.crashes_dir = Path(__file__).parent / "crashes"
        self.crashes_dir.mkdir(exist_ok=True)
        self.crash_file_pattern = re.compile(r"llm_fuzzgen\d{10}_.*")
        self.fuzzer_base_name_pattern = re.compile(r"^(llm_fuzzgen\d{10})")

    def analyze_project(self, project_name: str):
        """
        Finds and analyzes all crashes for a given project.
        """
        logger.info(f"Starting crash analysis for project: {project_name}")
        project_out_dir = self.oss_fuzz.build_out_dir / project_name
        if not project_out_dir.is_dir():
            logger.warning(f"Project output directory not found for '{project_name}', skipping.")
            return

        crash_files = [f for f in project_out_dir.iterdir() if f.is_file() and self.crash_file_pattern.match(f.name)]

        if not crash_files:
            logger.info(f"No new crash files found for project '{project_name}'.")
            return

        logger.info(f"Found {len(crash_files)} new crash file(s) for '{project_name}'.")
        for crash_path in crash_files:
            self._process_crash(project_name, crash_path)

    def _process_crash(self, project_name: str, crash_path: Path):
        """
        Processes a single crash: finds source, gets LLM analysis, and saves artifacts.
        """
        logger.info(f"Processing crash: {crash_path.name}")
        match = self.fuzzer_base_name_pattern.match(crash_path.stem)
        if not match:
            logger.error(f"Could not extract fuzzer base name from '{crash_path.name}'.")
            return

        fuzzer_binary_name = match.group(1)
        source_file = self._find_source_file(project_name, fuzzer_binary_name)

        if not source_file:
            logger.error(f"Could not find source file for fuzzer '{fuzzer_binary_name}'.")
            return

        try:
            crash_input_bytes = crash_path.read_bytes()
            fuzzer_source_code = source_file.read_text()
        except IOError as e:
            logger.error(f"Error reading crash files: {e}")
            return

        # Reproduce the crash to get a clean stack trace
        stack_trace = self.oss_fuzz.reproduce_crash(project_name, fuzzer_binary_name, crash_path)

        # Get analysis from LLM
        report_content = self._get_llm_analysis(project_name, fuzzer_source_code, crash_input_bytes, stack_trace)

        if not report_content:
            logger.error(f"LLM analysis failed for '{crash_path.name}'.")
            return

        # Save the artifacts
        self._save_artifacts(
            project_name=project_name,
            fuzzer_binary_name=fuzzer_binary_name,
            original_source_path=source_file,
            crash_input_path=crash_path,
            report_content=report_content,
        )

    def _find_source_file(self, project_name: str, fuzzer_binary_name: str) -> Path | None:
        """
        Finds the source code file for a given fuzzer binary name.
        """
        project_src_dir = self.oss_fuzz.oss_fuzz_dir / "projects" / project_name
        for ext in [".cc", ".cpp", ".c"]:
            source_file = project_src_dir / (fuzzer_binary_name + ext)
            if source_file.exists():
                return source_file
        return None

    def _get_llm_analysis(self, project_name: str, source_code: str, crash_input_bytes: bytes, stack_trace: str) -> str | None:
        """
        Sends the crash data to an LLM for analysis and returns the report.
        """
        logger.info("Getting analysis from LLM...")
        try:
            crash_input_hex = crash_input_bytes.hex()
            lang = self.oss_fuzz.proj_lang(project_name)

            prompt = prompt_generator.crash_analysis_prompt(
                project_name=project_name,
                lang=lang,
                fuzzer_source_code=source_code,
                crash_input_hex=crash_input_hex,
                stack_trace=stack_trace,
            )

            return self.llm_client.generate(prompt)
        except Exception as e:
            logger.error(f"An error occurred during LLM analysis: {e}", exc_info=True)
            return None

    def _save_artifacts(
        self, project_name: str, fuzzer_binary_name: str, original_source_path: Path, crash_input_path: Path, report_content: str
    ):
        """
        Saves the analysis report and copies the original source and crash input.
        """
        logger.info(f"Saving artifacts for {fuzzer_binary_name}")
        artifact_dir = self.crashes_dir / project_name / fuzzer_binary_name
        artifact_dir.mkdir(parents=True, exist_ok=True)

        # Save the report from the LLM
        (artifact_dir / "report.md").write_text(report_content)

        # Copy the original source and crash input for reference
        shutil.copy(original_source_path, artifact_dir / original_source_path.name)
        shutil.copy(crash_input_path, artifact_dir / crash_input_path.name)

        logger.info(f"Artifacts saved to: {artifact_dir}")
