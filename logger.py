import logging
import sys
from datetime import datetime
from pathlib import Path

import config.config as config


class TruncatingFileHandler(logging.FileHandler):
    """A file handler that truncates individual log messages if they exceed 1000 lines."""

    def __init__(self, filename, mode="a", encoding=None, delay=False, max_lines=1000, keep_lines=200):
        super().__init__(filename, mode, encoding, delay)
        self.max_lines = max_lines
        self.keep_lines = keep_lines

    def emit(self, record):
        """Emit a record, truncating the message if it exceeds max_lines."""
        # Format the record to get the actual message
        msg = self.format(record)

        # Split the message into lines
        lines = msg.split("\n")

        # Check if this single log message exceeds the line limit
        if len(lines) > self.max_lines:
            # Truncate the message: keep first and last keep_lines
            truncated_lines = (
                lines[: self.keep_lines]
                + [f"... [Omitted {len(lines) - 2 * self.keep_lines} lines] ..."]
                + lines[-self.keep_lines :]
            )

            # Create a new record with truncated message
            truncated_msg = "\n".join(truncated_lines)
            record.msg = truncated_msg
            record.args = ()  # Clear args since we've already formatted the message

        # Emit the (possibly truncated) record
        super().emit(record)


def setup_logging(project_name: str, log_dir: Path = Path(__file__).parent / "logs") -> None:
    """Configure logging with both file and console handlers."""
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / f"{datetime.now().strftime('%m%d_%H%M%S')}_{project_name}.log"
    handlers = [TruncatingFileHandler(log_file, mode="w"), logging.StreamHandler(sys.stdout)]
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
