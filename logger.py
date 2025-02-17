import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict

import config.config as config


def setup_logging(project_names: list, log_dir: Path = Path(__file__).parent / "logs") -> None:
    """Configure logging with both file and console handlers."""
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / f"fuzz_target_generator_{datetime.now().strftime('%m%d_%H%M%S')}.log"
    handlers = [logging.FileHandler(log_file, mode="w"), logging.StreamHandler(sys.stdout)]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    logging.info("=== Configuration ===")
    logging.info(f"Project Names: {project_names}")
    logging.info(f"Model: {config.MODEL_NAME}")
    logging.info(f"Max Functions: {config.MAX_FUNCTIONS}")
    logging.info(f"Temperature: {config.TEMPERATURE}")
    logging.info(f"Max Tokens: {config.MAX_TOKENS}")
    logging.info(f"Max Compiler Attempts: {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}")
    logging.info("======================\n")
