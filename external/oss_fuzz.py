import asyncio
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    success: bool
    error: str = ""


class OSSFuzz:
    def __init__(self, oss_fuzz_dir: Optional[Path] = None):
        self.oss_fuzz_dir = oss_fuzz_dir or Path(__file__).parent / "oss-fuzz"
        self.helper_script = self.oss_fuzz_dir / "infra" / "helper.py"

    def _get_project_yaml(self, proj_name: str) -> dict:
        """Read and parse project.yaml file."""
        proj_yaml_path = self.oss_fuzz_dir / "projects" / proj_name / "project.yaml"
        with open(proj_yaml_path, "r") as f:
            return yaml.safe_load(f)

    async def _run_helper_command(self, command: list[str]) -> tuple[bool, str, str]:
        """Run helper.py command and return result."""
        try:
            process = await asyncio.create_subprocess_exec(
                "python3",
                str(self.helper_script),
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            return (process.returncode == 0, stdout.decode(), stderr.decode())

        except Exception as e:
            return False, "", str(e)

    async def build_fuzzers(self, proj_name: str) -> CompilationResult:
        """Builds fuzzers for the given project."""
        success, stdout, stderr = await self._run_helper_command(["build_fuzzers", proj_name])

        if success:
            return CompilationResult(success=True)

        error_msg = stdout + stderr
        logger.error(f"Compilation failed: {error_msg}")
        return CompilationResult(success=False, error=error_msg)

    async def generate_report(self, proj_name: str, seconds: int = 10) -> bool:
        """Generates an introspector report for the given project."""
        logger.info(f"Creating introspector reports for {proj_name}")
        success, stdout, stderr = await self._run_helper_command(
            ["introspector", "--seconds", str(seconds), proj_name]
        )

        if not success:
            logger.error(f"Failed to generate report for {proj_name}")

        logger.info(f"Introspector reports created for {proj_name}")
        return success

    async def generator_reports(self, list_of_projects: list[str], seconds: int = 10) -> bool:
        """Generates introspector reports for the given list of projects concurrently."""
        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(self.generate_report(proj_name, seconds), name=f"report-{proj_name}")
                for proj_name in list_of_projects
            ]

        return all(task.result() for task in tasks)

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
        LANGUAGE_EXTENSIONS = {"c": ".c", "c++": ".cc", "cpp": ".cc"}

        lang = self.proj_lang(proj_name)
        target_dir = self.oss_fuzz_dir / "projects" / proj_name
        timestamp = datetime.now().strftime("%H%M%S")
        extension = LANGUAGE_EXTENSIONS.get(lang.lower(), ".c")
        target_file = target_dir / f"fuzz_{timestamp}_fuzzer{extension}"

        target_file.write_text(code)
        return target_file
