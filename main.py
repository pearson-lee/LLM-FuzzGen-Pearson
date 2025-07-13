#!/usr/bin/env python3
import logging
import sys
import time
import argparse
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

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
# The LLMClient will be initialized in main() after parsing arguments.
llm_client: LLMClient | None = None


def minimize_and_generate_report(proj_name: str, run_introspector_seconds: int, clean: bool):
    """Helper function to minimize corpus and then generate a report."""
    oss_fuzz.minimize_corpus(proj_name)
    return oss_fuzz.generate_report(proj_name, run_introspector_seconds, clean)


def run_fuzzers_and_get_coverage(proj_name: str, run_seconds: int):
    """Helper function to run all fuzzers and then get coverage."""
    oss_fuzz.run_all_fuzzers(proj_name, run_seconds)
    oss_fuzz.coverage(proj_name)


def show_current_coverage(project_names: list[str], run_seconds: int, parallel: int):
    """
    Shows the current coverage for the specified projects.
    Runs all fuzzers and generates a coverage report before showing the coverage.
    """
    logger.info("Showing current coverage")

    # Determine which projects to process
    build_out_dir = Path("./external/oss-fuzz/build/out/")
    projects_dir = Path("./external/oss-fuzz/projects/")

    projects_to_process = project_names
    if not projects_to_process:
        projects_to_process = [
            p.name for p in projects_dir.iterdir() if p.is_dir() and not p.name.startswith("non-test-projects")
        ]

    # Determine the number of workers for the executor
    max_workers = parallel
    logger.info(f"Running all fuzzers for {len(projects_to_process)} projects with {max_workers} parallel worker(s)...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_project = {
            executor.submit(run_fuzzers_and_get_coverage, project_name, run_seconds): project_name
            for project_name in projects_to_process
        }

        for future in future_to_project:
            project_name = future_to_project[future]
            try:
                future.result()  # We don't need the result, but this will raise exceptions if any occurred
                logger.info(f"Successfully generated report for {project_name}")
            except Exception:
                logger.exception(f"Failed to generate report for {project_name}")

    # Collect data for the table
    table_data = []
    for proj_name in projects_to_process:
        summary_file = build_out_dir / proj_name / "textcov_reports" / "summary_exclude_target.json"

        row = {"Project": proj_name}

        if summary_file.exists():
            try:
                with open(summary_file, "r") as f:
                    summary_data = json.load(f)
                totals = summary_data["data"][0]["totals"]

                for metric in ["branches", "functions", "lines"]:
                    if metric in totals:
                        count = totals[metric]["count"]
                        covered = totals[metric]["covered"]
                        percent = totals[metric]["percent"]
                        row[metric.capitalize()] = f"{percent:.2f} ({covered}/{count})"
                    else:
                        row[metric.capitalize()] = "N/A"

            except (json.JSONDecodeError, KeyError, IndexError) as e:
                logger.error(f"Could not parse summary for {proj_name}: {e}")
                for metric in ["Branches", "Functions", "Lines"]:
                    row[metric] = "Error"

        else:
            for metric in ["Branches", "Functions", "Lines"]:
                row[metric] = "No Summary"

        # Get fuzz target count
        fuzz_target_file = build_out_dir / proj_name / "fuzzer_stats" / "coverage_targets.txt"
        fuzz_target_count = 0
        if fuzz_target_file.exists():
            with open(fuzz_target_file, "r") as f:
                fuzz_target_count = sum(1 for line in f if line.strip())
        row["Fuzz Targets"] = str(fuzz_target_count)

        table_data.append(row)

    # Display table
    if not table_data:
        logger.info("No projects found to display.")
        return

    headers = ["Project", "Branches (%)", "Functions (%)", "Lines (%)", "Fuzz Targets"]

    # Calculate column widths
    col_widths = {h: len(h) for h in headers}
    for row in table_data:
        for h in headers:
            # Remap keys for lookup
            key = h.split(" ")[0] if h != "Fuzz Targets" else "Fuzz Targets"
            col_widths[h] = max(col_widths[h], len(row.get(key, "")))

    # Print header
    header_line = "| " + " | ".join(f"{h:<{col_widths[h]}}" for h in headers) + " |"
    separator_line = "|-" + "-|-".join("-" * col_widths[h] for h in headers) + "-|"

    logger.info("Coverage Summary")
    logger.info("=" * len(header_line))
    logger.info(header_line)
    logger.info(separator_line)

    # Print rows
    for row in table_data:
        row_line = "| "
        row_line += f"{row['Project']:<{col_widths['Project']}} | "
        row_line += f"{row.get('Branches', 'N/A'):<{col_widths['Branches (%)']}} | "
        row_line += f"{row.get('Functions', 'N/A'):<{col_widths['Functions (%)']}} | "
        row_line += f"{row.get('Lines', 'N/A'):<{col_widths['Lines (%)']}} | "
        row_line += f"{row.get('Fuzz Targets', 'N/A'):<{col_widths['Fuzz Targets']}} |"
        logger.info(row_line)

    logger.info("=" * len(header_line))


# Statistics for tracking coverage growth
regeneration_growth = []
mutation_growth = []

# Statistics for tracking compilation success
compilation_attempts = 0
compilation_successes = 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fuzz target generator for OSS-Fuzz projects.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for the main fuzzing process
    parser_process = subparsers.add_parser("process", help="Process a project to generate and improve fuzz targets.")
    parser_process.add_argument("project_name", help="The name of the project to process.")
    parser_process.add_argument(
        "--initial-fuzz-target",
        "-i",
        action="store_true",
        default=False,
        help="Generate an initial fuzz target. Default is not to generate.",
    )
    parser_process.add_argument(
        "--seconds",
        "-s",
        type=int,
        default=60,
        help="The number of seconds to wait for report generation. Default is 60 seconds.",
    )
    parser_process.add_argument(
        "--dict",
        "-d",
        action="store_true",
        default=False,
        help="Enable dictionary generation.",
    )
    parser_process.add_argument(
        "--seeds",
        action="store_true",
        default=False,
        help="Enable seed generation.",
    )
    parser_process.add_argument(
        "--llm",
        choices=["gemini", "vertexai"],
        default="gemini",
        help="Specify the LLM backend to use.",
    )

    # Subparser for showing current coverage
    parser_cov = subparsers.add_parser("show_current_cov", help="Show current coverage for specified projects.")
    parser_cov.add_argument(
        "project_names", nargs="*", help="The names of the projects to show coverage for. Shows all if none are provided."
    )
    parser_cov.add_argument(
        "--run-fuzzers",
        "-r",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Run all fuzzers for the specified number of seconds before showing coverage. Defaults to 60s.",
    )
    parser_cov.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=1,
        help="The number of projects to run in parallel. Defaults to 1.",
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
    # Search for LLVMFuzzerTestOneInput in order to analyze the fuzz target's coverage
    fuzz_target_coverage_report = oss_fuzz.linecov_reports(project_name, fuzz_target_name)
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
        fun_coverage_report=oss_fuzz.funcov_reports(project_name),
        headers=", ".join(introspector.get_all_header_files(project_name)),
        proj=project_name,
        lang=oss_fuzz.proj_lang(project_name),
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Regenerated fuzz target for {project_name} successfully")

    return new_fuzz_target


def process_project(project_name: str, seconds: int, use_dict: bool, use_seeds: bool) -> bool:
    """Process a single project and generate fuzz targets."""
    try:
        logger.info(f"Starting to process project: {project_name}")

        if use_dict:
            generate_dict_for_proj(project_name, llm_client)
        iterator = FuzzIterator(project_name, oss_fuzz)
        fuzz_target = None  # Will hold the path to the current fuzz target
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

            # Standard strategy: regenerate or mutate existing
            if is_regeneration or fuzz_target is None:
                new_target = regenerate_fuzz_target(project_name)
                is_regeneration = True
            else:
                new_target = mutate_fuzz_target(project_name, fuzz_target.read_text(), fuzz_target.stem)

            if new_target is None:
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                continue

            if (cov := oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)) <= 0:
                oss_fuzz.remove_target(project_name, new_target.stem)
                continue

            logger.info(f"Coverage : {cov}")

            if use_seeds:
                generate_seeds_for_fuzzer(project_name, new_target.stem, new_target.read_text(), llm_client)
                oss_fuzz.remove_corpus(project_name, new_target.stem)
                cov = oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)
                logger.info(f"Coverage with seeds: {cov}")

            coverage_growth = cov - previous_cov
            logger.info(f"coverage: {previous_cov} -> {cov} (growth: {coverage_growth:.2f})")

            if cov <= previous_cov:
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target's coverage is lower than the previous iteration {iteration + 1}")
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                no_growth_count += 1
                logger.info(f"No growth count: {no_growth_count}/{config.NO_GROWTH_STOP_THRESHOLD}")
                continue

            oss_fuzz.run_all_fuzzers(project_name, seconds=seconds)

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

        if args.command == "show_current_cov":
            setup_logging("show_current_cov")
            show_current_coverage(args.project_names, args.run_fuzzers, args.parallel)
            logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")
            return

        project_name = args.project_name
        setup_logging(project_name)

        # Default command is "process"
        # Initialize the LLM client only when the command is "process"
        global llm_client
        llm_client = LLMClient(backend=args.llm)

        if args.initial_fuzz_target:
            logger.info("Generating initial fuzz target")
            if not generate_empty_fuzz_target(project_name):
                logger.error(f"Failed to generate initial fuzz target for {project_name}")
                sys.exit(1)
        else:
            logger.info("Skipping initial fuzz target generation")
        logger.info(f"Starting introspector webapp for initial analysis of {project_name}")

        if not minimize_and_generate_report(project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        initial_coverage_percent = oss_fuzz.get_coverage_summary(project_name, exclude_target=True).lines.percent
        logger.info(f"Initial coverage for {project_name}: {initial_coverage_percent:.2f}%")
        if args.initial_fuzz_target:
            oss_fuzz.remove_target(project_name, "llm_fuzzgen_empty")

        result = process_project(project_name, seconds=args.seconds, use_dict=args.dict, use_seeds=args.seeds)

        if not minimize_and_generate_report(project_name, seconds=args.seconds, clean=True):
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
