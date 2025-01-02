import requests
from typing import Dict, Optional, List
import json
import logging

logger = logging.getLogger(__name__)


class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def query_api(self, endpoint: str, params: Dict) -> Optional[dict]:
        try:
            response = requests.get(
                f"{self.base_url}/{endpoint}", params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response: {e}")
            return None

    def get_target_functions(self, project_name: str) -> List[str]:
        response = self.query_api(
            "far-reach-but-low-coverage", {"project": project_name})
        return [func["function_signature"] for func in response.get("functions", [])] if isinstance(response, dict) else []

    def get_function_source_code(self, project_name: str, function_signature: str) -> str:
        source_code = self.query_api("function-source-code", {
            "project": project_name,
            "function_signature": function_signature
        })
        return source_code.get("source") if source_code else ""

    def get_function_required_headers(self, project_name: str, function_signature: str) -> str:
        response = self.query_api("get-header-files-needed-for-function", {
            "project": project_name,
            "function_signature": function_signature
        })
        headers = response.get("headers-to-include", [])
        return "\n".join(headers) if headers else ""

    def get_project_language(self, project_name: str) -> str:
        response = self.query_api("get-project-language-from-souce-files", {
            "project": project_name
        })
        return response.get("language", "c") if response else ""
