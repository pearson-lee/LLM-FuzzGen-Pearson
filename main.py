#!/usr/bin/env python3
from ast import arg
import logging
import sys
import time
import argparse
from pathlib import Path

import config.config as config
import prompts.prompt_generator as prompt_generator
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from iterator.fuzz_iterator import FuzzIterator
from llm_interface.llm_client import LLMClient
from logger import setup_logging
from fuzzing_input import generate_seeds_for_fuzzer, generate_dict_for_proj

logger = logging.getLogger(__name__)

oss_fuzz = OSSFuzz()
introspector = Introspector()
llm_client = LLMClient()


def _find_lowest_coverage_target(project_name: str, exclude_targets: set[str] = None) -> Path | None:
    target_names = introspector.get_fuzz_target_names(project_name)
    if not target_names:
        logger.warning(f"No fuzz targets found for project {project_name}")
        return None

    exclude_targets = exclude_targets or set()
    lowest_target = None
    lowest_coverage = float("inf")

    for target_name in target_names:
        if target_name in exclude_targets:
            logger.info(f"Skipping already mutated target: {target_name}")
            continue

        coverage_summary = oss_fuzz.get_coverage_summary(project_name, target_name)
        if coverage_summary and coverage_summary.functions:
            function_coverage = coverage_summary.functions.percent
            logger.info(f"Target {target_name} function coverage: {function_coverage}%")

            if function_coverage < lowest_coverage:
                lowest_coverage = function_coverage
                lowest_target = target_name

    if lowest_target:
        logger.info(f"Lowest coverage target: {lowest_target} ({lowest_coverage}%)")
        project_dir = oss_fuzz.oss_fuzz_dir / "projects" / project_name
        for file_path in project_dir.glob(f"{lowest_target}.*"):
            if file_path.suffix in [".c", ".cc", ".cpp"]:
                return file_path

    return None


def _format_all_function_for_prompt(project_name: str, coverage_threshold: float = 50.0) -> str:
    """
    Formats function signature data obtained from the introspector into a prompt string.
    Only includes functions with coverage below the specified threshold.
    """
    return "\n".join(
        f"- Signature: `{sig}`\n"
        f"- Header(s): {', '.join(headers)}\n"
        f"- Runtime coverage percent: {coverage}%\n"
        f"- File path: {file_path}"
        for func in introspector.get_all_functions(project_name)[:50]
        for sig, headers, coverage, file_path in [
            (
                func.get("function_signature", "N/A"),
                func.get("possible_header_files", []),
                func.get("runtime_coverage_percent", 0.0),
                func.get("function_filename", ""),
            )
        ]
        if coverage < coverage_threshold
    )


# Statistics for tracking coverage growth
regeneration_growth = []
mutation_growth = []

# Statistics for tracking compilation success
compilation_attempts = 0
compilation_successes = 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fuzz target generator for OSS-Fuzz projects.")
    parser.add_argument("project_name", help="The name of the project to process.")

    parser.add_argument(
        "--initial-fuzz-target",
        action="store_true",
        default=False,
        help="Generate an initial fuzz target. Default is not to generate.",
    )

    parser.add_argument(
        "--seconds",
        type=int,
        default=60,
        help="The number of seconds to wait for report generation. Default is 60 seconds.",
    )

    args = parser.parse_args()
    return args


def generate_report_and_start_webapp(project_name: str, seconds: int = 60, clean: bool = False) -> bool:
    if not oss_fuzz.generate_report(project_name, seconds, clean):
        logger.error(f"Failed to generate report for {project_name}")
        return False

    if not introspector.update_start_webapp():
        logger.error("Failed to start web application")
        return False
    return True


def generate_empty_fuzz_target(project_name: str) -> bool:
    """
    Copies an empty fuzz target to the project directory and attempts to build it.
    Returns True if the build is successful, False otherwise.
    """
    logger.info(f"Generating empty fuzz target for project: {project_name}")
    if not oss_fuzz.copy_empty_fuzz_target(project_name):
        logger.error(f"Failed to copy empty fuzz target for {project_name}.")
        return False

    logger.info(f"Attempting to build the empty fuzz target")
    build_result = oss_fuzz.build_fuzzers(project_name)

    if build_result.success:
        logger.info(f"Successfully built empty fuzz target for {project_name}.")
        return True
    else:
        logger.error(f"Failed to build empty fuzz target for {project_name}: {build_result.error}")
        oss_fuzz.remove_target(project_name, "llm_fuzzgen_empty")
        return False


def build_fuzz_target(project_name: str, prompt: str) -> Path | None:
    """
    Builds a fuzz target for the given project using prompt-based iteration with multiple compilation attempts.
    """
    global compilation_attempts, compilation_successes
    langgraph_threadid = int(time.time())
    current_prompt = prompt
    last_code = None
    using_build_prompt = False

    for attempt in range(1, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        compilation_attempts += 1
        logger.info(f"Build attempt {attempt}/{config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} for '{project_name}'.")

        try:
            last_code = llm_client.generate(current_prompt, langgraph_threadid)
            if not last_code:
                logger.error(f"LLM generation failed for attempt {attempt}. No code generated.")
                break

            fuzz_file = oss_fuzz.save_target(project_name, last_code)
            logger.info(f"Saved fuzz target: '{fuzz_file}'.")

            result = oss_fuzz.run_fuzzer(project_name, fuzz_file.stem)  # Run the fuzzer to check memory leaks and other issues
            if result.success:
                compilation_successes += 1
                logger.info(f"Build succeeded: '{fuzz_file}'.")
                return fuzz_file

            logger.error(f"Build failed (attempt {attempt}).")
            oss_fuzz.remove_target(project_name, fuzz_file.stem)
            if not using_build_prompt:
                using_build_prompt = True
                langgraph_threadid = int(time.time())  # Reset thread ID for the build template
                current_prompt = prompt_generator.build_prompt(
                    fuzz_target_code=last_code,
                    error_messages=result.error,
                    lang=oss_fuzz.proj_lang(project_name),
                    proj=project_name,
                    headers=", ".join(introspector.get_all_header_files(project_name)),
                )
            else:
                current_prompt = result.error

        except Exception as e:
            oss_fuzz.remove_target(project_name, fuzz_file.stem)
            logger.error(f"Error in build attempt {attempt}: {e}", exc_info=True)
            current_prompt = prompt
            using_build_prompt = False

    logger.warning(f"All {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} attempts failed for '{project_name}'.")
    return None


def mutate_fuzz_target(project_name: str, fuzz_target: str, fuzz_target_name: str) -> Path | None:
    logger.info(f"Mutating fuzz target for project: {project_name}")
    # Use regex to search for LLVMFuzzerTestOneInput in order to analyze the fuzz target's coverage
    fuzz_target_coverage_report = oss_fuzz.linecov_reports(project_name, fuzz_target_name, "LLVMFuzzerTestOneInput")
    prompt = prompt_generator.coverage_prompt(
        fuzz_target_code=fuzz_target,
        lang=oss_fuzz.proj_lang(project_name),
        proj=project_name,
        headers=", ".join(introspector.get_all_header_files(project_name)),
        fun_coverage_report=oss_fuzz.funcov_reports(project_name),
        fuzz_target_name=fuzz_target_name,
        fuzz_target_coverage_report=fuzz_target_coverage_report,
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Mutated fuzz target for {project_name} successfully")

    return new_fuzz_target


def regenerate_fuzz_target(project_name: str) -> Path | None:
    logger.info(f"Regenerating fuzz target for project: {project_name}")

    prompt = prompt_generator.regeneration_prompt(
        signature=_format_all_function_for_prompt(project_name),
        fun_coverage_report=oss_fuzz.funcov_reports(project_name),
        headers=", ".join(introspector.get_all_header_files(project_name)),
        proj=project_name,
        lang=oss_fuzz.proj_lang(project_name),
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Regenerated fuzz target for {project_name} successfully")

    return new_fuzz_target


def process_project(project_name: str, seconds: int) -> bool:
    """Process a single project and generate fuzz targets."""
    try:
        logger.info(f"Starting to process project: {project_name}")

        # generate_dict_for_proj(project_name)
        iterator = FuzzIterator(project_name, oss_fuzz)
        fuzz_target = None  # Will hold the path to the current fuzz target
        mutated_targets = set()  # Track mutated targets to avoid re-mutation
        iterator.record_cov()  # Record coverage before any fuzz target generation

        no_growth_count = 0
        # Iterative improvement loop
        for iteration in range(config.ITERATION_LOOP):
            if no_growth_count >= config.NO_GROWTH_STOP_THRESHOLD:
                logger.warning(
                    f"Stopping iteration for {project_name} due to {config.NO_GROWTH_STOP_THRESHOLD} consecutive iterations with no coverage growth."
                )
                break
            previous_cov = iterator.latest_cov()
            is_regeneration = iterator.should_regenerate()

            # Determine target generation strategy
            # total_coverage = oss_fuzz.get_coverage_summary(project_name)
            # function_coverage = total_coverage.functions.percent if total_coverage and total_coverage.functions else 0.0

            # High coverage strategy: mutate lowest coverage target
            # if function_coverage > 90.0 and (lowest_target := _find_lowest_coverage_target(project_name, mutated_targets)):
            #     mutated_targets.add(lowest_target.stem)
            #     new_target = mutate_fuzz_target(project_name, lowest_target.read_text(), lowest_target.stem)
            #     is_regeneration = False
            # Standard strategy: regenerate or mutate existing
            if is_regeneration or fuzz_target is None:
                new_target = regenerate_fuzz_target(project_name)
                is_regeneration = True
            else:
                new_target = mutate_fuzz_target(project_name, fuzz_target.read_text(), fuzz_target.stem)

            if new_target is None:
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                continue

            if (cov_without_seeds := oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)) <= 0:
                oss_fuzz.remove_target(project_name, new_target.stem)
                continue

            # generate_seeds_for_fuzzer(project_name, new_target.stem, new_target.read_text())
            # oss_fuzz.remove_corpus(project_name, new_target.stem)

            cov_with_seeds = oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)
            coverage_growth = cov_with_seeds - previous_cov
            logger.info(f"Coverage without seeds: {cov_without_seeds}")
            logger.info(f"Coverage with seeds: {cov_with_seeds}")
            logger.info(f"coverage: {previous_cov} -> {cov_with_seeds} (growth: {coverage_growth:.2f})")

            if cov_with_seeds <= previous_cov:
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target's coverage is lower than the previous iteration {iteration + 1}")
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                no_growth_count += 1
                logger.info(f"No growth count: {no_growth_count}/{config.NO_GROWTH_STOP_THRESHOLD}")
                continue

            if not generate_report_and_start_webapp(project_name, seconds=seconds):
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target is failed to generate report {iteration + 1}")
                continue

            no_growth_count = 0
            logger.info(f"No growth count reset, 0/{config.NO_GROWTH_STOP_THRESHOLD}")
            # Record successful growth statistics
            if is_regeneration:
                regeneration_growth.append(coverage_growth)
                iterator.clean_cov()  # Clear coverage records for regeneration
                logger.info(f"Regeneration growth recorded: {coverage_growth:.2f}")
            else:
                mutation_growth.append(coverage_growth)
                logger.info(f"Mutation growth recorded: {coverage_growth:.2f}")

            fuzz_target = new_target
            iterator.record_cov()
            logger.info(f"Finished iteration {iteration + 1} for {project_name}, coverage: {iterator.latest_cov()}")

        return True

    except Exception as e:
        logger.error(f"Failed to process project {project_name}: {e}", exc_info=True)
        return False


def calculate_statistics(project_name: str, initial_coverage_percent: float):
    """Calculate and return the growth statistics, compilation success rate, and other metrics."""
    total_coverage_summary = oss_fuzz.get_coverage_summary(project_name)
    total_coverage_summary_exclude_target = oss_fuzz.get_coverage_summary(project_name, exclude_target=True)
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

    # Calculate compilation success rate
    compilation_success_rate = (compilation_successes / compilation_attempts * 100) if compilation_attempts > 0 else 0

    logger.info("=" * 50)
    logger.info("Coverage Growth Statistics:")
    logger.info(
        f"Regeneration: {stats['regeneration']['count']} iterations, Average growth: {stats['regeneration']['average']:.2f}%"
    )
    logger.info(f"Mutation: {stats['mutation']['count']} iterations, Average growth: {stats['mutation']['average']:.2f}%")
    logger.info("=" * 50)
    logger.info("Compilation Success Rate:")
    logger.info(f"Total compilation attempts: {compilation_attempts}")
    logger.info(f"Successful compilations: {compilation_successes}")
    logger.info(f"Success rate: {compilation_success_rate:.2f}% ")
    logger.info("=" * 50)

    logger.info(f"Initial coverage: {initial_coverage_percent:.2f}%")
    if total_coverage_summary:
        logger.info("=" * 50)
        logger.info("Total Coverage Summary:")
        for metric_name, summary in total_coverage_summary.__dict__.items():
            if summary:
                logger.info(
                    f"  {metric_name.capitalize()}: Count={summary.count}, Covered={summary.covered}, Percent={summary.percent:.2f}%"
                )

    if total_coverage_summary_exclude_target:
        logger.info("=" * 50)
        logger.info("Total Coverage Summary (excluding fuzz target):")
        for metric_name, summary in total_coverage_summary_exclude_target.__dict__.items():
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

        if args.initial_fuzz_target:
            logger.info("Generating initial fuzz target")
            if not generate_empty_fuzz_target(project_name):
                logger.error(f"Failed to generate initial fuzz target for {project_name}")
                sys.exit(1)
        else:
            logger.info("Skipping initial fuzz target generation")
        logger.info(f"Starting introspector webapp for initial analysis of {project_name}")

        if not generate_report_and_start_webapp(project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        initial_coverage_percent = oss_fuzz.get_coverage_summary(project_name, exclude_target=True).lines.percent
        logger.info(f"Initial coverage for {project_name}: {initial_coverage_percent:.2f}%")
        if args.initial_fuzz_target:
            oss_fuzz.remove_target(project_name, "llm_fuzzgen_empty")

        result = process_project(project_name, seconds=args.seconds)

        if not generate_report_and_start_webapp(project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        calculate_statistics(project_name, initial_coverage_percent)

        logger.info("Project processed")
        logger.info(f"Successful project: {result}")
        logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")

        user_input = input("Do you want to shutdown the server (http://localhost:8080)? (y/n): ")
        if user_input.lower() == "n":
            logger.info("Server is still running.")
        else:
            introspector.shutdown_webapp()
            logger.info("Server shutdown.")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        try:
            introspector.shutdown_webapp()
            logger.info("Server shutdown due to exception.")
        except Exception as e:
            logger.error(f"Failed to shutdown server in finally block: {e}")


if __name__ == "__main__":
    main()
