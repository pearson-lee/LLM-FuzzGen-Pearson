import logging
from pathlib import Path

import yaml


def load_config(yaml_file="config.yaml"):
    """
    General-purpose configuration loader with basic error handling.
    """
    config_path = Path(__file__).parent / yaml_file

    if not config_path.exists():
        logging.error(f"Config file not found: {config_path}")
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML: {e}")
        return {}


config = load_config()

MODEL_NAME = config["MODEL_NAME"]
MAX_TOKENS = config["MAX_TOKENS"]
TEMPERATURE = config["TEMPERATURE"]
INTROSPECTOR_API_BASE_URL = config["INTROSPECTOR_API_BASE_URL"]
FUZZ_TARGET_COMPILER_MAX_ATTEMPTS = config["FUZZ_TARGET_COMPILER_MAX_ATTEMPTS"]
ITERATION_LOOP = config["ITERATION_LOOP"]
MIN_COVERAGE_IMPROVEMENT = config["MIN_COVERAGE_IMPROVEMENT"]
NO_GROWTH_STOP_THRESHOLD = config["NO_GROWTH_STOP_THRESHOLD"]
THINK_BUDGET_TOKEN = config["THINK_BUDGET_TOKEN"]
