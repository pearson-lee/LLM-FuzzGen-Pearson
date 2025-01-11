#!/usr/bin/env python3

import os
import sys
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

from api_client import APIClient
from prompt_generator import PromptGenerator
from fuzz_target_generator import FuzzTargetGenerator
from target_saver import TargetSaver
import config

# Configure logging


def setup_logging() -> None:
    """Configure logging with both file and console handlers."""
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / \
        f"fuzz_target_generator_{datetime.now().strftime('%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='w'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info("=== Configuration ===")
    logging.info(f"Project Names: {sys.argv[1:]}")
    logging.info(f"Model: {config.MODEL_NAME}")
    logging.info(f"Max Functions: {config.MAX_FUNCTIONS}")
    logging.info(f"Temperature: {config.TEMPERATURE}")
    logging.info(f"Max Tokens: {config.MAX_TOKENS}")
    logging.info(
        f"Max Compiler Attempts: {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}")
    logging.info("==================\n")


def generate_fuzz_targets(project_name: str) -> Dict[str, str]:
    """
    Generate fuzz targets for the given project.

    Returns:
        Dictionary mapping function signatures to their generation results
    """
    api_client = APIClient(config.API_BASE_URL)
    prompt_generator = PromptGenerator()
    target_saver = TargetSaver()
    generator = FuzzTargetGenerator(api_client, prompt_generator, target_saver)

    target_functions = api_client.get_target_functions(project_name)[
        :config.MAX_FUNCTIONS]
    if not target_functions:
        raise ValueError("No target functions found")

    attempts: Dict[str, str] = {}
    for function_sig in target_functions:
        logging.info(f"Generating fuzz target for {function_sig}")

        target_file, attempt_count = generator.generate_and_save_target(
            project_name, function_sig)
        attempts[function_sig] = f'success, {attempt_count}' if target_file else f'failure, {attempt_count}'

        if target_file:
            logging.info(
                f"Successfully generated and compiled fuzz target! {function_sig}")
        else:
            logging.warning("Compilation failed, trying next function...")

    return attempts


def log_final_summary(project_results: Dict[str, Dict[str, str]]) -> None:
    """Log summary statistics for all processed projects."""
    logging.info("=== FINAL SUMMARY ===")
    total_functions = 0
    total_attempts = 0
    successful_targets = 0

    for project, attempts in project_results.items():
        project_functions = len(attempts)

        # Parse attempt strings like "success, 3" or "failure, 2"
        project_attempts = sum(
            int(result.split(", ")[1]) for result in attempts.values())
        project_successes = sum(
            1 for result in attempts.values() if result.startswith("success"))

        total_functions += project_functions
        total_attempts += project_attempts
        successful_targets += project_successes

        logging.info(f"=== {project}: ===")
        logging.info(f"  Functions processed: {project_functions}")
        logging.info(f"  Total attempts: {project_attempts}")
        logging.info(f"  Successful targets: {project_successes}")

    logging.info("=== Overall Statistics:  ===")
    logging.info(f"Total functions processed: {total_functions}")
    logging.info(f"Total generation attempts: {total_attempts}")
    logging.info(f"Total successful targets: {successful_targets}")
    logging.info(
        f"Overall success rate: {(successful_targets / total_functions * 100):.2f}%")
    logging.info("==================\n")


def main() -> None:
    """Main entry point of the program."""
    if len(sys.argv) < 2:
        print("Usage: python main.py <project_name1> <project_name2> ...")
        sys.exit(1)

    setup_logging()
    project_names = sys.argv[1:]
    project_results = {}

    for project_name in project_names:
        try:
            attempts = generate_fuzz_targets(project_name)
            project_results[project_name] = attempts

            logging.info(
                f"Fuzz target generation attempts for {project_name}:")
            for function_sig, result in attempts.items():
                logging.info(f"{function_sig}: {result} attempts")

        except Exception as e:
            logging.error(f"Error processing {project_name}: {e}")
            continue

    log_final_summary(project_results)


if __name__ == "__main__":
    main()
