import logging
import subprocess
from pathlib import Path
from typing import Optional

from external.oss_fuzz import OSSFuzz

logger = logging.getLogger(__name__)


class SUT:
    def __init__(self, base_dir: Optional[Path] = None, oss_fuzz: Optional[OSSFuzz] = None):
        self._base_dir = base_dir or Path(__file__).resolve().parent / "sut"
        self._oss_fuzz = oss_fuzz or OSSFuzz()
        logger.info(f"Initialized SUT with base directory: {self._base_dir}")

    def _get_project_paths(self, project_name: str) -> tuple[Path, Path]:
        """Returns tuple of (project_dir, info_file) paths."""
        return (self._base_dir / project_name, self._base_dir / f"{project_name}.info")

    def _run_git_command(self, cmd: list[str]) -> None:
        """Runs git command and handles errors."""
        cmd_str = " ".join(cmd)
        logger.debug(f"Running git command: {cmd_str}")
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logger.debug(f"Git command completed successfully: {cmd_str}")
        except subprocess.CalledProcessError as e:
            error_msg = f"Git command failed: {e.stderr or e.stdout}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _clone_repository(self, git_url: str, proj_dir: Path) -> None:
        """Clones the repository to the specified directory."""
        logger.info(f"Cloning repository from {git_url} to {proj_dir}")
        clone_cmd = ["git", "clone", "--depth", "1", git_url, str(proj_dir)]
        self._run_git_command(clone_cmd)
        logger.info("Repository cloned successfully")

    def _checkout_commit(self, proj_dir: Path, commit_hash: str) -> None:
        """Fetches and checkouts specific commit."""
        if not commit_hash:
            logger.debug("No commit hash specified, skipping checkout")
            return

        logger.info(f"Checking out commit: {commit_hash}")
        fetch_cmd = ["git", "-C", str(proj_dir), "fetch", "--depth", "1", "origin", commit_hash]
        checkout_cmd = ["git", "-C", str(proj_dir), "checkout", commit_hash]

        self._run_git_command(fetch_cmd)
        self._run_git_command(checkout_cmd)
        logger.info(f"Successfully checked out commit: {commit_hash}")

    def _generate_project_info(self, proj_dir: Path, info_file: Path) -> None:
        """Generates project info using code2prompt tool."""
        logger.info(f"Generating project info: {proj_dir} -> {info_file}")
        try:
            exclude_patterns = [
                "Makefile",
                "LICENSE",
                "CONTRIBUTING",
                "test_suite/*",
                "test_cmd/*",
                "*.jsonnet",
                "benchmarks/*",
                "*.txt",
                "*.md",
                "*.yml",
                "*.yaml",
                "*.json",
                "*.gitignore",
                "*.gitattributes",
                ".git/*",
                ".github/*",
                "*.html",
                "*.xml",
                "*.css",
                "*.js",
                "*.otf",
                "*.eot",
                "*.woff",
                "*.golden",
                "*.png",
                "*.jpg",
                "*.jpeg",
                "*.gif",
                "*.svg",
                "docs/*",
                "doc/*",
                "*.sh",
                "third_party/*",
                "dox",
            ]
            exclude_arg = "--exclude=" + ",".join(exclude_patterns)
            cmd = [
                "code2prompt",
                f"{proj_dir}/",
                f"--output={info_file}",
                exclude_arg,
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("Project info generated successfully")
        except subprocess.CalledProcessError as e:
            error_msg = f"code2prompt failed: {e.stderr or e.stdout}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def get_project_info(self, project_name: str) -> str:
        """
        Retrieves project information by either reading from a local file or cloning the project's repository
        and generating a prompt using the `code2prompt` tool.
        """
        logger.info(f"Retrieving project info for {project_name}")
        proj_dir, info_file = self._get_project_paths(project_name)

        if info_file.exists():
            return info_file.read_text().strip()

        try:
            git_url = self._oss_fuzz.main_git_repo(project_name)
            commit_hash = self._oss_fuzz.commit_hash(project_name)

            self._clone_repository(git_url, proj_dir)
            self._checkout_commit(proj_dir, commit_hash)
            self._generate_project_info(proj_dir, info_file)

            logger.info(f"Successfully retrieved project info for {project_name}")
            return info_file.read_text().strip()

        except Exception as e:
            logger.error(f"Error retrieving project info for {project_name}: {str(e)}")
            return f"Error: {str(e)}"
