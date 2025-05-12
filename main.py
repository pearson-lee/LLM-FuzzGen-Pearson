#!/usr/bin/env python3
import logging
import sys
import time
import argparse
from pathlib import Path

import config.config as config
import prompts.prompt_generator as prompt_generator
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from external.sut import SUT
from iterator.fuzz_iterator import FuzzIterator
from llm_interface.llm_client import LLMClient
from logger import setup_logging
from fuzzing_input import generate_seeds_for_fuzzer, generate_dict_for_proj

logger = logging.getLogger(__name__)

sut = SUT()
oss_fuzz = OSSFuzz()
introspector = Introspector()
llm_client = LLMClient()

# Statistics for tracking coverage growth
regeneration_growth = []
mutation_growth = []


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fuzz target generator for OSS-Fuzz projects.")
    parser.add_argument("project_name", help="The name of the project to process.")

    parser.add_argument(
        "--initial-fuzz-target",
        action="store_true",
        default=False,
        help="Generate an initial fuzz target. Default is not to generate.",
    )

    args = parser.parse_args()
    return args


def generate_report_and_start_webapp(project_name: str, seconds: int = 30, clean: bool = False) -> bool:
    if not oss_fuzz.generate_report(project_name, seconds, clean):
        logger.error(f"Failed to generate report for {project_name}")
        return False

    if not introspector.update_start_webapp():
        logger.error("Failed to start web application")
        return False
    return True


def build_fuzz_target(project_name: str, initial_prompt: str) -> Path | None:
    """
    Builds a fuzz target for the given project using prompt-based iteration with multiple compilation attempts.
    """
    langgraph_threadid = int(time.time())  # Used to correlate a series of LLM interactions
    current_input_for_llm = initial_prompt

    for attempt_num in range(1, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        logger.info(
            f"Attempt {attempt_num}/{config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} to build fuzz target for '{project_name}'."
        )

        fuzz_target_code = llm_client.generate(current_input_for_llm, langgraph_threadid)
        fuzz_target_file: Path | None = None
        try:
            fuzz_target_file = oss_fuzz.save_target(project_name, fuzz_target_code)
            logger.info(
                f"Saved fuzz target to '{fuzz_target_file}' for '{project_name}' (attempt {attempt_num})."
            )

            build_result = oss_fuzz.build_fuzzers(project_name)

            if build_result.success:
                logger.info(
                    f"Successfully built fuzz target '{fuzz_target_file}' for '{project_name}' after {attempt_num} attempts."
                )
                return fuzz_target_file

            logger.error(
                f"Build attempt {attempt_num} for '{project_name}' failed."
            )
            current_input_for_llm = build_result.error
            # Clean up the failed target file
            logger.info(f"Cleaning up target file: '{fuzz_target_file}' after failed attempt {attempt_num}.")
            fuzz_target_file.unlink(missing_ok=True)

        except Exception as e:
            logger.error(
                f"Unexpected error during attempt {attempt_num} for '{project_name}': {e}", exc_info=True
            )
            current_input_for_llm = initial_prompt
            # Clean up the target file if it was created before the exception
            fuzz_target_file.unlink(missing_ok=True)

    logger.warning(
        f"All {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} attempts to build fuzz target for '{project_name}' failed."
    )
    return None


def mutate_fuzz_target(project_name: str, fuzz_target: str, fuzz_target_name: str) -> Path | None:
    logger.info(f"Mutating fuzz target for project: {project_name}")

    prompt = prompt_generator.coverage_prompt(
        fuzz_target_code=fuzz_target,
        coverage_information=oss_fuzz.funcov_reports(project_name, fuzz_target_name),
        lang=oss_fuzz.proj_lang(project_name),
        proj=project_name,
        headers=", ".join(introspector.get_all_header_files(project_name)),
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Mutated fuzz target for {project_name} successfully")

    return new_fuzz_target


def regenerate_fuzz_target(project_name: str) -> Path | None:
    logger.info(f"Regenerating fuzz target for project: {project_name}")

    target_functions_data = introspector.target_functions(project_name)[:50]
    formatted_signatures = []
    for func_info in target_functions_data:
        sig = func_info.get("function_signature", "N/A")
        headers = func_info.get("possible_header_files", [])
        header_str = ", ".join(headers) if headers else ""
        formatted_signatures.append(f"- Signature: `{sig}`\n- Header(s): {header_str}")
    signature_prompt = "\n".join(formatted_signatures)

    prompt = prompt_generator.regeneration_prompt(
        signature=signature_prompt,
        headers=", ".join(introspector.get_all_header_files(project_name)),
        proj=project_name,
        lang=oss_fuzz.proj_lang(project_name),
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Regenerated fuzz target for {project_name} successfully")

    return new_fuzz_target


def process_project(project_name: str, generate_initial_target: bool) -> bool:
    """Process a single project and generate fuzz targets."""
    try:
        logger.info(f"Starting to process project: {project_name}")

        # generate_dict_for_proj(project_name)
        iterator = FuzzIterator(project_name)
        fuzz_target = None  # Will hold the path to the current fuzz target
        iterator.record_cov()  # Record coverage before any fuzz target generation

        if generate_initial_target:
            logger.info("Attempting to generate initial fuzz target.")
            prompt = prompt_generator.initial_prompt(
                sut_info=sut.get_project_info(project_name),
                fuzz_targets=[],
            )

            # Create initial fuzz target
            if not (fuzz_target := build_fuzz_target(project_name, prompt)):
                logger.error(f"Failed to build initial fuzz target for {project_name} when requested.")
                return False

            logger.info(f"Successfully built initial fuzz target: {fuzz_target}")
            # Initial coverage recording after successful generation
            generate_report_and_start_webapp(project_name)
            iterator.record_cov()

        # Iterative improvement loop
        for iteration in range(config.ITERATION_LOOP):
            previous_cov = iterator.latest_cov()
            is_regeneration = iterator.should_regenerate()

            if is_regeneration:
                new_target = regenerate_fuzz_target(project_name)
            elif fuzz_target:  # Only mutate if there's a fuzz_target to mutate
                new_target = mutate_fuzz_target(project_name, fuzz_target.read_text(), fuzz_target.stem)
            else:
                logger.warning("fuzz_target is None and not regenerating, forcing regeneration.")
                new_target = regenerate_fuzz_target(project_name)
                is_regeneration = True  # Mark this as a regeneration

            if new_target is None:
                continue

            if (cov_without_seeds := oss_fuzz.coverage(project_name, new_target.stem)) <= 0:
                oss_fuzz.remove_target(project_name, new_target.stem)
                continue

            generate_seeds_for_fuzzer(
                project_name=project_name,
                fuzzer_name=new_target.stem,
                fuzzer_source_code=new_target.read_text(),
            )

            cov_with_seeds = oss_fuzz.coverage(project_name, new_target.stem)
            coverage_growth = cov_with_seeds - previous_cov
            logger.info(f"Coverage without seeds: {cov_without_seeds}")
            logger.info(f"Coverage with seeds: {cov_with_seeds}")
            logger.info(f"coverage: {previous_cov} -> {cov_with_seeds} (growth: {coverage_growth:.2f})")

            if cov_with_seeds <= previous_cov:
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target's coverage is lower than the previous iteration {iteration + 1}")
                continue

            if not generate_report_and_start_webapp(project_name, 10):
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target is failed to generate report {iteration + 1}")
                continue

            # Record successful growth statistics
            if is_regeneration:
                regeneration_growth.append(coverage_growth)
                logger.info(f"Regeneration growth recorded: {coverage_growth:.2f}")
            else:
                mutation_growth.append(coverage_growth)
                logger.info(f"Mutation growth recorded: {coverage_growth:.2f}")

            fuzz_target = new_target
            iterator.record_cov()
            logger.info(
                f"Finished iteration {iteration + 1} for {project_name}, coverage: {iterator.latest_cov()}"
            )

        return True

    except Exception as e:
        logger.error(f"Failed to process project {project_name}: {e}")
        return False


def calculate_growth_statistics(project_name: str):
    """Calculate and return the growth statistics for both strategies and log the results."""
    stats = {
        "regeneration": {
            "count": len(regeneration_growth),
            "average": (sum(regeneration_growth) / len(regeneration_growth) if regeneration_growth else 0),
        },
        "mutation": {
            "count": len(mutation_growth),
            "average": sum(mutation_growth) / len(mutation_growth) if mutation_growth else 0,
        },
    }

    logger.info("=" * 50)
    logger.info("Coverage Growth Statistics:")
    logger.info(
        f"Regeneration: {stats['regeneration']['count']} iterations, Average growth: {stats['regeneration']['average']:.2f}%"
    )
    logger.info(
        f"Mutation: {stats['mutation']['count']} iterations, Average growth: {stats['mutation']['average']:.2f}%"
    )
    logger.info(f"Project: {project_name} coverage: {introspector.line_coverage(project_name)}%")
    logger.info("=" * 50)

    if total_coverage_summary := oss_fuzz.get_total_coverage_summary(project_name):
        logger.info("Total Coverage Summary:")
        for metric_name, summary in total_coverage_summary.__dict__.items():
            if summary:
                logger.info(
                    f"  {metric_name.capitalize()}: Count={summary.count}, Covered={summary.covered}, Percent={summary.percent:.2f}%"
                )
        logger.info("=" * 50)


def main() -> None:
    try:
        t0 = time.perf_counter()
        args = _parse_args()
        project_name = args.project_name
        setup_logging(project_name)

        generate_report_and_start_webapp(project_name, clean=True)

        result = process_project(project_name, args.initial_fuzz_target)

        if not generate_report_and_start_webapp(project_name, clean=True):
            sys.exit(1)

        calculate_growth_statistics(project_name)

        logger.info("Project processed")
        logger.info(f"Successful project: {result}")
        logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")

        input("Press Enter to shutdown the server (http://localhost:8080)")

    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
    except Exception as e:
        logger.error(f"Process failed with error: {e}")
    finally:
        introspector.shutdown_webapp()


if __name__ == "__main__":
    main()
