import json
import logging
import os
import subprocess
import time
from pathlib import Path

import requests

import config.config as config

logger = logging.getLogger(__name__)


class Introspector:
    API_REQUEST_TIMEOUT = 3
    MAX_RETRIES = 3
    RETRY_WAIT_TIME = 1

    def __init__(self, base_url: str = None):
        self.base_url = base_url or config.INTROSPECTOR_API_BASE_URL
        self.session = requests.Session()
        self.base_dir = Path(__file__).parent
        self.oss_fuzz_dir = self.base_dir / "oss-fuzz"
        self.fi_dir = self.base_dir / "fuzz-introspector"

    def _query_api(self, endpoint: str, params: dict, enable_retry: bool = True) -> dict:
        max_attempts = self.MAX_RETRIES + 1 if enable_retry else 1

        for attempt in range(max_attempts):
            try:
                response = self.session.get(
                    f"{self.base_url}/{endpoint}", params=params, timeout=self.API_REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return response.json()
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                if attempt == max_attempts - 1:
                    if endpoint == "shutdown":
                        return {}
                    logger.error(f"API request failed: {e}")
                    return {}

                logger.warning(f"API request failed (attempt {attempt + 1}/{max_attempts}): {e}")
                time.sleep(self.RETRY_WAIT_TIME)

    def _webapp_db_update(self) -> bool:
        db_script_path = (
            self.fi_dir
            / "tools/web-fuzzing-introspection/app/static/assets/db"
            / "web_db_creator_from_summary.py"
        )
        try:
            subprocess.run(
                ["python3", str(db_script_path), "--local-oss-fuzz", str(self.oss_fuzz_dir)],
                cwd=db_script_path.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update webapp database: {e}")
            return False

    def target_functions(self, project_name: str) -> list[str]:
        response = self._query_api("far-reach-but-low-coverage", {"project": project_name})
        return [func["function_signature"] for func in response.get("functions", [])]

    def function_source_code(self, project_name: str, function_signature: str) -> str:
        response = self._query_api(
            "function-source-code", {"project": project_name, "function_signature": function_signature}
        )
        return response.get("source", "")

    def function_required_headers(self, project_name: str, function_signature: str) -> str:
        response = self._query_api(
            "get-header-files-needed-for-function",
            {"project": project_name, "function_signature": function_signature},
        )
        return "\n".join(response.get("headers-to-include", []))

    def line_coverage(self, project_name: str) -> float:
        response = self._query_api("project-summary", {"project": project_name})
        try:
            coverage_data = (
                response.get("project", {}).get("runtime_coverage_data", {}).get("line_coverage", {})
            )
            return round(float(coverage_data.get("percent", 0)), 2)
        except (KeyError, ValueError, TypeError):
            logger.warning(f"Failed to get line coverage for {project_name}")
            return 0.0

    def update_start_webapp(self) -> bool:
        if not self._webapp_db_update():
            return False

        self.shutdown_webapp()
        try:
            webapp_path = self.fi_dir / "tools/web-fuzzing-introspection/app"
            env = {**os.environ, "FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ": str(self.oss_fuzz_dir)}

            subprocess.Popen(
                ["python3", "./main.py"],
                cwd=str(webapp_path),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(1)  # Give the webapp a moment to start
            if self.webapp_tester():
                logger.info("Web application started successfully")
                return True

            logger.error("Failed to start web application")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize webapp: {e}")
            return False

    def webapp_tester(self) -> bool:
        response = self._query_api("tester", {})
        return response.get("result") == "success"

    def shutdown_webapp(self):
        self._query_api("shutdown", {}, enable_retry=False)

    def fuzz_target_source_code(self, project_name: str) -> str:
        """Get fuzz target source code for the project."""
        logger.info(f"Getting fuzz target source code for project: {project_name}")
        pairs = self._query_api("harness-source-and-executable", {"project": project_name}).get("pairs", [])

        codes = []
        for i, pair in enumerate(pairs, 1):
            params = {"project": project_name, "filepath": pair["source"], "begin_line": 0, "end_line": 999}
            if code := self._query_api("project-source-code", params).get("source_code"):
                codes.append(f"```fuzz_target_{i}\n{code}\n```")

        return "\n".join(codes)
