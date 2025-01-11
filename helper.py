from dataclasses import dataclass
import subprocess
from pathlib import Path
import logging
import config

logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    success: bool
    error: str = ""


def test_compilation(project_name: str) -> CompilationResult:
    try:
        helper_script = Path(config.OSS_FUZZ_PATH) / "infra" / "helper.py"
        result = subprocess.run(
            ["python3", str(helper_script), "build_fuzzers", project_name],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
        return CompilationResult(success=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Compilation failed: {e}")
        error_msg = ""
        if e.stdout:
            logger.error(f"stdout: {e.stdout}")
            error_msg += e.stdout
        if e.stderr:
            logger.error(f"stderr: {e.stderr}")
            error_msg += e.stderr
        return CompilationResult(success=False, error=error_msg)
