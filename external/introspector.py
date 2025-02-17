import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

import config.config as config

logger = logging.getLogger(__name__)


class Introspector:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or config.INTROSPECTOR_API_BASE_URL
        self.session = requests.Session()
        self.base_dir = Path(__file__).parent
        self.oss_fuzz_dir = self.base_dir / "oss-fuzz"
        self.fi_dir = self.base_dir / "fuzz-introspector"

    def _query_api(self, endpoint: str, params: Dict) -> Optional[dict]:
        try:
            response = self.session.get(f"{self.base_url}/{endpoint}", params=params, timeout=3)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response: {e}")
            return None

    def _webapp_db_update(self) -> bool:
        """Update the database of the web application."""
        try:
            db_path = self.fi_dir / "tools/web-fuzzing-introspection/app/static/assets/db"
            subprocess.run(
                ["python3", "./web_db_creator_from_summary.py", "--local-oss-fuzz", str(self.oss_fuzz_dir)],
                cwd=str(db_path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            logger.info("Web application database updated successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to update webapp database: {e}")
            return False

    def target_functions(self, project_name: str) -> List[str]:
        response = self._query_api("far-reach-but-low-coverage", {"project": project_name})
        return (
            [func["function_signature"] for func in response.get("functions", [])]
            if isinstance(response, dict)
            else []
        )

    def function_source_code(self, project_name: str, function_signature: str) -> str:
        source_code = self._query_api(
            "function-source-code",
            {"project": project_name, "function_signature": function_signature},
        )
        return source_code.get("source") if source_code else ""

    def function_required_headers(self, project_name: str, function_signature: str) -> str:
        response = self._query_api(
            "get-header-files-needed-for-function",
            {"project": project_name, "function_signature": function_signature},
        )
        headers = response.get("headers-to-include", [])
        return "\n".join(headers) if headers else ""

    def line_coverage(self, project_name: str) -> float:
        """Get the line coverage percentage for the given project."""
        response = self._query_api("project-summary", {"project": project_name})
        percent = response["project"]["runtime_coverage_data"]["line_coverage"]["percent"]
        return round(float(percent), 2)

    def update_start_webapp(self) -> bool:
        """Initialize and start the web application"""
        try:
            logger.info("Initializing web application")
            self._webapp_db_update()
            self.shutdown_webapp()
            # Start web server
            webapp_path = self.fi_dir / "tools/web-fuzzing-introspection/app"
            env = os.environ.copy()
            env["FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ"] = str(self.oss_fuzz_dir)

            subprocess.Popen(
                ["python3", "./main.py"],
                cwd=str(webapp_path),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for the web application to start
            for attempt in range(1, 6):
                time.sleep(attempt)
                if self.webapp_tester():
                    break
            else:
                logger.error("Failed to start web application")
                return False

            logger.info("Web application started successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize webapp: {e}")
            return False

    def webapp_tester(self) -> bool:
        response = self._query_api("tester", {})
        return response and response.get("result") == "success"

    def shutdown_webapp(self) -> bool:
        """Shutdown the web application."""
        return self._query_api("shutdown", {})

    def fuzz_target_source_code(self, project_name: str) -> str:
        """Get all fuzz target source code for a given project."""
        # First get the harness source file paths
        logger.info(f"Getting fuzz target source code for project: {project_name}")
        pairs_response = self._query_api("harness-source-and-executable", {"project": project_name})

        if not pairs_response or "pairs" not in pairs_response:
            logger.error("Failed to get harness source file paths")
            return ""

        result = []
        for i, pair in enumerate(pairs_response["pairs"], 1):
            source_path = pair["source"]
            # Get source code for each harness file
            code_response = self._query_api(
                "project-source-code",
                {"project": project_name, "filepath": source_path, "begin_line": 0, "end_line": 999},
            )

            if code_response and "source_code" in code_response:
                result.append(f"```fuzz_target_{i}\n{code_response['source_code']}\n```")

        return "\n".join(result)
