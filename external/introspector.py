import json
import logging
import os
import subprocess
import time
import fcntl
import functools
from pathlib import Path
from typing import TypedDict, List
from contextlib import contextmanager

import requests
from requests.adapters import HTTPAdapter, Retry

import config.config as config

logger = logging.getLogger(__name__)


class FunctionInfo(TypedDict):
    """Type hints for function information returned by get_all_functions."""

    function_name: str
    function_signature: str
    possible_header_files: List[str]
    function_filename: str
    source_line_begin: int
    source_line_end: int


class CrossReference(TypedDict):
    """Type hints for cross-reference information returned by get_function_cross_references."""

    src_func: str
    possible_header_files: List[str]
    src_func_signature: str


class TargetFunctionInfo(TypedDict):
    """Type for target functions returned by target_functions."""

    function_signature: str
    possible_header_files: List[str]


class Introspector:
    LOCKFILE_PATH = Path("/tmp/llm_fuzzgen.lock")
    API_REQUEST_TIMEOUT = 3
    MAX_RETRIES = 10
    RETRY_BACKOFF = 1  # seconds

    def __init__(self, base_url: str = None):
        self._specific_cache = {}
        self.base_url = base_url or config.INTROSPECTOR_API_BASE_URL
        self.retry_strategy = Retry(
            total=self.MAX_RETRIES,
            backoff_factor=self.RETRY_BACKOFF,
        )

        self.session = requests.Session()
        retry_adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=self.retry_strategy)
        self.session.mount("http://", retry_adapter)
        self.session.mount("https://", retry_adapter)

        # Session without retries for shutdown endpoint
        self.session_no_retry = requests.Session()
        no_retry_adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
        self.session_no_retry.mount("http://", no_retry_adapter)
        self.session_no_retry.mount("https://", no_retry_adapter)

        self.base_dir = Path(__file__).parent
        self.oss_fuzz_dir = self.base_dir / "oss-fuzz"
        self.fi_dir = self.base_dir / "fuzz-introspector"
        self.webapp_path = self.fi_dir / "tools" / "web-fuzzing-introspection" / "app"

    def _query_api(self, endpoint: str, params: dict, enable_retry: bool = True) -> dict:
        logger.info(f"Querying API: {endpoint} with params: {params}")
        session = self.session if enable_retry else self.session_no_retry
        try:
            response = session.get(f"{self.base_url}/{endpoint}", params=params, timeout=self.API_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            if endpoint == "shutdown":
                return {}
            logger.error(f"API request failed: {e} for endpoint: {endpoint}")
            return {}

    def _cacheable(func):
        """
        A decorator to cache the results of instance methods of Introspector.
        It creates a cache key based on the function name and its arguments.
        """

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Create a cache key from the function name and arguments
            # We skip 'self' which is the first argument
            key_dict = {"func_name": func.__name__, "args": args, "kwargs": kwargs}
            cache_key = json.dumps(key_dict, sort_keys=True)

            if cache_key in self._specific_cache:
                logger.info(f"Returning cached data for {func.__name__}")
                return self._specific_cache[cache_key]

            result = func(self, *args, **kwargs)
            self._specific_cache[cache_key] = result
            return result

        return wrapper

    def _webapp_db_update(self) -> bool:
        db_script_path = (
            self.fi_dir
            / "tools"
            / "web-fuzzing-introspection"
            / "app"
            / "static"
            / "assets"
            / "db"
            / "web_db_creator_from_summary.py"
        )
        try:
            subprocess.run(
                ["python", str(db_script_path), "--local-oss-fuzz", str(self.oss_fuzz_dir)],
                cwd=db_script_path.parent,
                check=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update webapp database: {e}")
            return False

    @contextmanager
    def file_lock(self):
        """A context manager for file locking using fcntl.flock."""
        lock_file_handle = None
        try:
            lock_file_handle = open(self.LOCKFILE_PATH, "a")
            fcntl.flock(lock_file_handle, fcntl.LOCK_EX)
            logger.info(f"Acquired lock: {self.LOCKFILE_PATH}")
            yield lock_file_handle
        finally:
            if lock_file_handle:
                fcntl.flock(lock_file_handle, fcntl.LOCK_UN)
                lock_file_handle.close()
                logger.info(f"Released lock: {self.LOCKFILE_PATH}")

    def update_start_webapp(self) -> bool:
        try:
            with self.file_lock():
                if not self._webapp_db_update():
                    return False

                self.shutdown_webapp()
                env = {**os.environ, "FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ": str(self.oss_fuzz_dir)}

                subprocess.Popen(
                    ["python", "./main.py"],
                    cwd=str(self.webapp_path),
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                time.sleep(10)
                if self.webapp_tester():
                    logger.info("Web application started successfully.")
                    return True

                logger.error("Failed to start web application after maximum attempts")
                return False
        except Exception as e:
            logger.error(f"Failed to initialize webapp: {e}")
            return False

    def webapp_tester(self) -> bool:
        response = self._query_api("tester", {})
        return response.get("result") == "success"

    def shutdown_webapp(self):
        self._query_api("shutdown", {}, enable_retry=False)

    def target_functions(self, project_name: str) -> List[TargetFunctionInfo]:
        """
        Get target functions (low coverage) for the project.

        Args:
            project_name: str - Name of the project to query.

        Returns:
            List[TargetFunctionInfo]: A list of target function info dictionaries, each containing:
                - function_signature (str): The signature of the function.
                - possible_header_files (List[str]): Header files that may be required.
        """
        response = self._query_api("far-reach-but-low-coverage", {"project": project_name})
        targets: List[TargetFunctionInfo] = []
        for func in response.get("functions", []):
            sig = func.get("function_signature", "")
            headers = func.get("debug_summary", {}).get("possible-header-files", [])
            targets.append(
                {
                    "function_signature": sig,
                    "possible_header_files": headers,
                }
            )
        return targets

    def check_far_reach_low_coverage(self, project_name: str) -> dict:
        response = self._query_api("far-reach-but-low-coverage", {"project": project_name})
        return response

    def get_function_signature_and_headers(self, project_name: str, func_name: str) -> tuple[str, list[str]]:
        """Get function signature and possible header files by function name.

        Args:
            project_name: str - The name of the project
            func_name: str - The name of the function to look up

        Returns:
            tuple: (function_signature: str, possible_header_files: list[str])
        """
        response = self._query_api("function-signature", {"project": project_name, "function": func_name})
        signature = response.get("signature", "")
        headers = response.get("raw_data", {}).get("possible-header-files", [])
        return signature, headers

    @_cacheable
    def function_source_code(self, project_name: str, function_signature: str) -> str:
        """Get function source code by function signature."""
        response = self._query_api(
            "function-source-code",
            {"project": project_name, "function_signature": function_signature},
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
            coverage_data = response.get("project", {}).get("runtime_coverage_data", {}).get("line_coverage", {})
            coverage = round(float(coverage_data.get("percent", 0)), 2)
            logger.info(f"Line coverage data for {project_name}: {coverage}")
            return coverage
        except (KeyError, ValueError, TypeError):
            logger.warning(f"Failed to get line coverage for {project_name}")
            return 0.0

    def fuzz_target_source_code(self, project_name: str, end_line: int = 999) -> list[dict[str, str]]:
        """Get fuzz target names and source code for the project.

        Args:
            project_name (str): The name of the project.

        Returns:
            list[dict[str, str]]: A list of dictionaries, each containing:
                - 'name' (str): The name of the fuzz target.
                - 'code' (str): The source code of the fuzz target.
        """
        logger.info(f"Getting fuzz target source code for project: {project_name}")
        pairs = self._query_api("harness-source-and-executable", {"project": project_name}).get("pairs", [])

        results = []
        for pair in pairs:
            executable = pair.get("executable")
            source_path = pair.get("source")

            if not executable or not source_path:
                logger.warning(f"Skipping pair due to missing executable or source path: {pair}")
                continue

            fuzzer_name = os.path.splitext(executable)[0]

            params = {
                "project": project_name,
                "filepath": source_path,
                "begin_line": 0,
                "end_line": end_line,
            }
            if code := self._query_api("project-source-code", params).get("source_code"):
                results.append({"name": fuzzer_name, "code": code})
            else:
                logger.warning(f"Could not retrieve source code for fuzzer: {fuzzer_name} in project: {project_name}")

        if not results:
            logger.warning(f"No fuzz target source code found for project: {project_name}")
            return []

        return results

    def get_fuzz_target_names(self, project_name: str) -> List[str]:
        """Get all fuzz target names for the project."""
        logger.info(f"Getting fuzz target names for project: {project_name}")
        response = self._query_api("harness-source-and-executable", {"project": project_name})

        if response.get("result") != "success":
            logger.warning(f"API request failed for project: {project_name}")
            return []

        pairs = response.get("pairs", [])
        target_names = []

        for pair in pairs:
            executable = pair.get("executable")
            if executable:
                # Remove file extension to get the target name
                target_name = os.path.splitext(executable)[0]
                target_names.append(target_name)
            else:
                logger.warning(f"Skipping pair due to missing executable: {pair}")

        logger.info(f"Found {len(target_names)} fuzz targets for project {project_name}: {target_names}")
        return target_names

    @_cacheable
    def get_project_source_code(self, project_name: str, filepath: str, begin_line: int, end_line: int) -> str:
        """Get source code for a specific file and line range within a project.

        Args:
            project_name (str): The name of the project.
            filepath (str): The path to the file within the project.
            begin_line (int): The starting line number.
            end_line (int): The ending line number.

        Returns:
            str: The source code as a string, or an empty string if not found.
        """
        logger.info(f"Getting source code for project: {project_name}, file: {filepath}, lines: {begin_line}-{end_line}")
        params = {
            "project": project_name,
            "filepath": filepath,
            "begin_line": begin_line,
            "end_line": end_line,
        }
        response = self._query_api("project-source-code", params)
        source_code = response.get("source_code", "")
        if not source_code:
            logger.warning(f"Could not retrieve source code for project: {project_name}, file: {filepath}")
        return source_code

    @_cacheable
    def get_function_cross_references(self, project_name: str, function_signature: str) -> List[CrossReference]:
        """Get detailed cross-reference information for the given function.

        Args:
            project_name: str - The name of the project
            function_signature: str - The signature of the function to look up

        Returns:
            List[CrossReference]: List of cross-reference information dictionaries, each containing:
                - src_func (str): The source function name that calls the target function
                - possible_header_files (List[str]): List of possible header files for the source function
                - src_func_signature (str): The signature of the source function
        """
        response = self._query_api(
            "all-cross-references",
            {"project": project_name, "function_signature": function_signature},
        )
        callsites = response.get("callsites", [])

        # Get all functions to map function names to their possible header files
        all_functions = self.get_all_functions(project_name)
        func_to_headers = {func["function_name"]: func["possible_header_files"] for func in all_functions}
        func_to_signature = {func["function_name"]: func["function_signature"] for func in all_functions}

        cross_references = [
            {
                "src_func": callsite.get("src_func", ""),
                "possible_header_files": func_to_headers.get(callsite.get("src_func", ""), []),
                "src_func_signature": func_to_signature.get(callsite.get("src_func", ""), ""),
            }
            for callsite in callsites
        ]
        return cross_references

    @_cacheable
    def get_all_header_files(self, project_name: str) -> list[str]:
        """Get all header files for the project.

        Args:
            project_name: str - The name of the project

        Returns:
            list[str]: List of header file paths
        """
        response = self._query_api("all-header-files", {"project": project_name})
        return response.get("all-header-files", [])

    @_cacheable
    def get_all_functions(self, project_name: str) -> List[FunctionInfo]:
        """Retrieve all functions associated with the specified project.

        Args:
            project_name (str): The name of the project.

        Returns:
            List[FunctionInfo]: A list of dictionaries, each containing:
                - function_name (str): The name of the function.
                - function_signature (str): The demangled function signature.
                - possible_header_files (List[str]): A list of potential header files.
                - function_filename (str): The source file containing the function.
                - source_line_begin (int): The starting line number of the function in the source file.
                - source_line_end (int): The ending line number of the function in the source file.
        """
        response = self._query_api("all-functions", {"project": project_name})
        return [
            {
                "function_name": func.get("function_name", ""),
                "function_signature": func.get("function_signature", ""),
                "possible_header_files": func.get("debug_summary", {}).get("possible-header-files", []),
                "function_filename": func.get("debug_summary", {}).get("source", {}).get("source_file", ""),
                "source_line_begin": func.get("source_line_begin", 0),
                "source_line_end": func.get("source_line_end", 0),
            }
            for func in response.get("functions", [])
        ]
