import logging
import sys
from datetime import datetime
from pathlib import Path

import config.config as config


def setup_logging(project_name: str, log_dir: Path = Path(__file__).parent / "logs") -> None:
    """Configure logging with both file and console handlers."""
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / f"{datetime.now().strftime('%m%d_%H%M%S')}_{project_name}.log"
    handlers = [logging.FileHandler(log_file, mode="w"), logging.StreamHandler(sys.stdout)]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s.%(funcName)s:%(lineno)d - %(levelname)s - %(message)s\033[0m\r",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )
    logging.info("=== Configuration ===")
    logging.info(f"Project Name: {project_name}")
    logging.info(f"Model: {config.MODEL_NAME}")
    logging.info(f"Iteration loop: {config.ITERATION_LOOP}")
    logging.info(f"Temperature: {config.TEMPERATURE}")
    logging.info(f"Max Tokens: {config.MAX_TOKENS}")
    logging.info(f"Think Budget Tokens: {config.THINK_BUDGET_TOKEN}")
    logging.info(f"Max Compiler Attempts: {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}")
    logging.info("=====================")
