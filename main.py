#!/usr/bin/env python3
import logging
import sys
import time
from pathlib import Path

import config.config as config
import prompts.prompt_generator as prompt_generator
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from external.sut import SUT
from iterator.fuzz_iterator import FuzzIterator
from llm_interface.llm_client import LLMClient
from logger import setup_logging

logger = logging.getLogger(__name__)

sut = SUT()
oss_fuzz = OSSFuzz()
introspector = Introspector()
llm_client = LLMClient()


def _parse_args() -> list[str]:
    if len(sys.argv) < 2:
        logger.error("Usage: python main.py <project_name1> <project_name2> ...")
        sys.exit(1)
    return sys.argv[1:]


def _build_fuzz_target(project_name: str, prompt: str) -> Path | None:
    """Build a fuzz target using prompt iteration with multiple attempts."""
    fuzz_target = llm_client.generate(prompt)

    for attempt in range(config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS):
        logger.info(f"Building fuzz target for {project_name} (attempt {attempt + 1})")
        try:
            fuzz_target_file = oss_fuzz.save_target(project_name, fuzz_target)
            build_res = oss_fuzz.build_fuzzers(project_name)

            if build_res.success:
                logger.info(f"Successfully built fuzz target for {project_name} after {attempt + 1} attempts")
                return fuzz_target_file

            # Clean up failed target
            if fuzz_target_file.exists():
                fuzz_target_file.unlink()

            logger.error(f"Failed to build fuzz target for {project_name} on attempt {attempt + 1}")

            # Generate improved target for next attempt
            if attempt < config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS - 1:
                build_prompt = prompt_generator.build_prompt(
                    fuzz_target_code=fuzz_target, error_messages=build_res.error
                )
                fuzz_target = llm_client.generate(build_prompt)

        except Exception as e:
            logger.error(f"Error during build attempt {attempt + 1}: {e}")

    logger.warning(f"Failed to build fuzz target for {project_name} after all attempts")
    return None


def _generate_report_and_start_webapp(
    project_names: list[str], seconds: int = 10, clean: bool = False
) -> bool:
    if not oss_fuzz.generate_reports(project_names, seconds, clean):
        logger.error("Failed to generate reports")
        return False

    if not introspector.update_start_webapp():
        logger.error("Failed to start web application")
        return False
    return True


def _mutate_fuzz_target(project_name: str, fuzz_target: str, fuzz_target_name: str) -> Path | None:
    logging.info(f"Mutating fuzz target for project: {project_name}")

    prompt = prompt_generator.coverage_prompt(
        fuzz_target_code=fuzz_target,
        coverage_information=oss_fuzz.textcov_reports(project_name, fuzz_target_name),
        sut_info=sut.get_project_info(project_name),
    )

    new_fuzz_target = _build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logging.info(f"Mutated fuzz target for {project_name} successfully")

    return new_fuzz_target


def _regenerate_fuzz_target(project_name: str) -> Path | None:
    logging.info(f"Regenerating fuzz target for project: {project_name}")

    target_function = introspector.target_functions(project_name)[0]
    prompt = prompt_generator.regeneration_prompt(
        signature=target_function,
        source_code_snippet=introspector.function_source_code(project_name, target_function),
        sut_info=sut.get_project_info(project_name),
        fuzz_targets=introspector.fuzz_target_source_code(project_name),
    )

    new_fuzz_target = _build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logging.info(f"Regenerated fuzz target for {project_name} successfully")

    return new_fuzz_target


def process_project(project_name: str) -> bool:
    """Process a single project and generate fuzz targets."""
    try:
        logging.info(f"Starting to process project: {project_name}")
        iterator = FuzzIterator(project_name)

        # Initial setup
        proj_info = sut.get_project_info(project_name)
        fuzz_target_examples = introspector.fuzz_target_source_code(project_name)
        prompt = prompt_generator.initial_prompt(sut_info=proj_info, fuzz_targets=fuzz_target_examples)

        # Create initial fuzz target
        fuzz_target = _build_fuzz_target(project_name, prompt)
        if fuzz_target is None:
            return False

        # Initial coverage recording
        _generate_report_and_start_webapp([project_name])
        iterator.record_cov()

        # Iterative improvement loop
        for iteration in range(config.ITERATION_LOOP):
            if iterator.should_regenerate():
                new_target = _regenerate_fuzz_target(project_name)
            else:
                new_target = _mutate_fuzz_target(project_name, fuzz_target.read_text(), fuzz_target.stem)
                if new_target:
                    # Remove the old fuzz target after mutation
                    fuzz_target.unlink()

            if new_target is None:
                continue

            fuzz_target = new_target

            # Record and report progress
            _generate_report_and_start_webapp([project_name])
            iterator.record_cov()
            logging.info(
                f"Finished iteration {iteration + 1} for {project_name}, coverage: {iterator.latest_cov()}"
            )

        return True

    except Exception as e:
        logger.error(f"Failed to process project {project_name}: {e}")
        return False


def main() -> None:
    try:
        t0 = time.perf_counter()
        project_names = _parse_args()
        setup_logging(project_names)

        if not _generate_report_and_start_webapp(project_names, clean=True):
            sys.exit(1)

        results = [process_project(name) for name in project_names]

        if not _generate_report_and_start_webapp(project_names, clean=True):
            sys.exit(1)

        logger.info("All projects processed")
        logger.info(f"Successful projects: {sum(results)}/{len(results)}")
        logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")

        input("Press Enter to shutdown the server")

    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
    except Exception as e:
        logger.error(f"Process failed with error: {e}")
    finally:
        introspector.shutdown_webapp()


if __name__ == "__main__":
    main()
