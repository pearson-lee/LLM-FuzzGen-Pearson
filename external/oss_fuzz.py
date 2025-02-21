import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    success: bool
    error: str = ""


class OSSFuzz:
    LANG_EXT = {"c": ".c", "c++": ".cc", "cpp": ".cc"}

    def __init__(self, oss_fuzz_dir: Path = None):
        self.oss_fuzz_dir = oss_fuzz_dir or Path(__file__).parent / "oss-fuzz"
        self.helper_script = self.oss_fuzz_dir / "infra" / "helper.py"
        self.build_out_dir = self.oss_fuzz_dir / "build" / "out"

    def _get_project_yaml(self, proj_name: str):
        """Read and parse project.yaml file."""
        proj_yaml_path = self.oss_fuzz_dir / "projects" / proj_name / "project.yaml"
        with open(proj_yaml_path) as f:
            return yaml.safe_load(f)

    def _remove_build_dir(self, proj_name: str) -> bool:
        """Remove the build directory for the given project."""
        try:
            build_dir = self.build_out_dir / proj_name
            if build_dir.exists():
                subprocess.run(["rm", "-rf", str(build_dir)], check=True)
            return True
        except Exception as e:
            logger.error(f"Failed to remove build directory for {proj_name}: {e}")
            return False

    def _run_helper_command(self, args: list[str]) -> tuple[bool, str, str]:
        """Run helper.py command and return result."""
        try:
            process = subprocess.run(
                ["python3", str(self.helper_script)] + args, capture_output=True, text=True, check=False
            )
            return (process.returncode == 0, process.stdout, process.stderr)
        except Exception as e:
            return (False, "", str(e))

    def build_fuzzers(self, proj_name: str) -> CompilationResult:
        """Builds fuzzers for the given project."""
        success, stdout, stderr = self._run_helper_command(["build_fuzzers", proj_name])
        if success:
            return CompilationResult(success=True)
        logger.error(f"Compilation failed: {stdout}{stderr}")
        return CompilationResult(success=False, error=f"{stdout}{stderr}")

    def generate_report(self, proj_name: str, seconds: int = 10) -> bool:
        """Generates an introspector report for the given project."""
        logger.info(f"Creating introspector reports for {proj_name}")
        if not self._remove_build_dir(proj_name):
            return False

        success, stdout, stderr = self._run_helper_command(
            ["introspector", "--seconds", str(seconds), proj_name]
        )
        if not success:
            logger.error(f"Failed to generate report for {proj_name}: \n {stdout}{stderr}")
            return False

        logger.info(f"Introspector reports created for {proj_name}")
        return True

    def generate_reports(self, projects: list[str], seconds: int = 10) -> bool:
        """Generates introspector reports for the given list of projects."""
        return all(self.generate_report(proj, seconds) for proj in projects)

    def main_git_repo(self, proj_name: str) -> str:
        """Returns the main repository URL for the given project"""
        data = self._get_project_yaml(proj_name)
        return data.get("main_repo", "")

    def commit_hash(self, proj_name: str) -> str:
        """Returns the commit hash of the given project"""
        data = self._get_project_yaml(proj_name)
        return data.get("commit_hash", "")

    def proj_lang(self, proj_name: str) -> str:
        """Returns the language of the given project"""
        data = self._get_project_yaml(proj_name)
        return data.get("language", "")

    def save_target(self, proj_name: str, code: str) -> Path:
        """Saves the given code as a fuzzer target for the project"""
        lang = self.proj_lang(proj_name)
        target_dir = self.oss_fuzz_dir / "projects" / proj_name
        timestamp = datetime.now().strftime("%H%M%S")
        extension = self.LANG_EXT.get(lang.lower(), ".c")
        target_file = target_dir / f"fuzz_{timestamp}_fuzzer{extension}"

        target_file.write_text(code)
        return target_file
