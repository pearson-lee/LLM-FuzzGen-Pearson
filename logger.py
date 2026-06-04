import logging
import sys
from datetime import datetime
from pathlib import Path

import config.config as config


class ConsoleHandler(logging.StreamHandler):
    """Custom console handler that converts \\n to \\r\\n for proper terminal display."""

    def emit(self, record):
        try:
            msg = self.format(record)
            # Convert all \n to \r\n for proper terminal display
            msg = msg.replace("\n", "\r\n")
            stream = self.stream
            stream.write(msg + "\r\n")
            self.flush()
        except RecursionError:  # See issue 36272
            raise
        except Exception:
            self.handleError(record)


def setup_logging(
    project_name: str,
    model_name: str | None = None,
    log_dir: Path = Path(__file__).parent / "logs",
    log_filename: str | None = None,
) -> None:
    """Configure logging with both file and console handlers."""
    log_dir.mkdir(parents=True, exist_ok=True)

    name = log_filename or f"{datetime.now().strftime('%m%d_%H%M%S')}_{project_name}.log"
    log_file = log_dir / name
    handlers = [
        logging.FileHandler(log_file, mode="w"),
        ConsoleHandler(sys.stdout),  # Use custom console handler
    ]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s.%(funcName)s:%(lineno)d - %(levelname)s - %(message)s\033[0m\r",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )
    logging.info("=== Configuration ===")
    logging.info(f"Project Name: {project_name}")
    logging.info(f"Model: {model_name or config.MODEL_NAME}")
    logging.info(f"Iteration loop: {config.ITERATION_LOOP}")
    logging.info(f"Fuzz Target Temperature: {config.FUZZ_TARGET_TEMPERATURE}")
    logging.info(f"Blocker Classifier Temperature: {config.BLOCKER_CLASSIFIER_TEMPERATURE}")
    logging.info(f"Seed Generator Initial Temperature: {config.SEED_GENERATOR_INITIAL_TEMPERATURE}")
    logging.info(f"Seed Generator Later Temperature: {config.SEED_GENERATOR_LATER_TEMPERATURE}")
    logging.info(f"Max Tokens: {config.MAX_TOKENS}")
    logging.info(f"Think Budget Tokens: {config.THINK_BUDGET_TOKEN}")
    logging.info(f"Max Compiler Attempts: {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}")
    logging.info("=====================")
