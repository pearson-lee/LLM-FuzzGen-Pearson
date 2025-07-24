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
from crash_analyzer.crash_analyzer import CrashAnalyzer
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz, TotalCoverageSummary
from iterator.fuzz_iterator import FuzzIterator
from llm_interface.llm_client import LLMClient
from logger import setup_logging
from fuzzing_input import generate_seeds_for_fuzzer, generate_dict_for_proj

logger = logging.getLogger(__name__)

oss_fuzz = OSSFuzz()
introspector = Introspector()
# The LLMClient will be initialized in main() after parsing arguments.
llm_client: LLMClient | None = None


def minimize_and_generate_report(proj_name: str, seconds: int, clean: bool):
    """Helper function to minimize corpus and then generate a report."""
    oss_fuzz.minimize_corpus(proj_name)
    return generate_report_and_start_webapp(proj_name, seconds, clean)


def run_fuzzers_and_get_coverage(
    proj_name: str, run_seconds: int, minimize_corpus: bool = False, get_coverage: bool = True, start_webapp: bool = False
):
    """Helper function to run all fuzzers and then optionally get coverage."""
    if start_webapp:
        generate_report_and_start_webapp(proj_name, 10, clean=True)
    if minimize_corpus:
        oss_fuzz.minimize_corpus(proj_name)
    oss_fuzz.run_all_fuzzers(proj_name, run_seconds)
    if get_coverage:
        oss_fuzz.coverage(proj_name)


def run_all_fuzzer(
    project_names: list[str],
    run_seconds: int,
    parallel: int,
    minimize_corpus: bool = False,
    print_coverage: bool = False,
    analyze_crashes: bool = False,
):
    """
    Runs all fuzzers for the specified projects, optionally analyzes crashes,
    and optionally shows the coverage summary.
    """
    logger.info("Running all fuzzers")

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

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_project = {
                executor.submit(
                    run_fuzzers_and_get_coverage, project_name, run_seconds, minimize_corpus, print_coverage, analyze_crashes
                ): project_name
                for project_name in projects_to_process
            }

            for future in future_to_project:
                project_name = future_to_project[future]
                try:
                    future.result()  # We don't need the result, but this will raise exceptions if any occurred
                    logger.info(f"Successfully completed fuzzing for {project_name}")
                except BaseException:
                    logger.exception(f"Failed to complete fuzzing for {project_name}")
    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user. Shutting down...")

    if analyze_crashes:
        logger.info("Starting crash analysis phase.")
        analyzer = CrashAnalyzer(llm_client, oss_fuzz)
        for project_name in projects_to_process:
            analyzer.analyze_project(project_name)

        introspector.shutdown_webapp()

    if not print_coverage:
        return

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
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="gemini",
        help="Specify the LLM backend to use.",
    )
    parser_process.add_argument(
        "--model",
        type=str,
        default=None,
        help="Specify the model name to use, overriding the default in config.",
    )

    # Subparser for running all fuzzers
    parser_run = subparsers.add_parser("run_all_fuzzer", help="Run all fuzzers for specified projects.")
    parser_run.add_argument(
        "--minimize-corpus", action="store_true", default=False, help="Minimize corpus before running fuzzers."
    )
    parser_run.add_argument(
        "project_names", nargs="*", help="The names of the projects to run fuzzers for. Runs all if none are provided."
    )
    parser_run.add_argument(
        "--run-fuzzers",
        "-r",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Run all fuzzers for the specified number of seconds. Defaults to 60s.",
    )
    parser_run.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=1,
        help="The number of projects to run in parallel. Defaults to 1.",
    )
    parser_run.add_argument(
        "--print-coverage",
        action="store_true",
        default=False,
        help="Print coverage summary table at the end.",
    )
    parser_run.add_argument(
        "--analyze-crashes",
        action="store_true",
        default=False,
        help="Analyze crashes after fuzzing runs, before calculating coverage.",
    )
    parser_run.add_argument(
        "--llm",
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="gemini",
        help="Specify the LLM backend to use.",
    )
    parser_run.add_argument(
        "--model",
        type=str,
        default=None,
        help="Specify the model name to use, overriding the default in config.",
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

    current_prompt = prompt
    langgraph_threadid = int(time.time())
    is_first_attempt = True

    for attempt in range(1, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        compilation_attempts += 1
        logger.info(f"Build attempt {attempt}/{config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} for '{project_name}'.")

        fuzz_file = None  # Initialize fuzz_file to None for safety
        try:
            code = llm_client.generate(current_prompt, langgraph_threadid)
            if not code:
                logger.error(f"LLM generation failed for attempt {attempt}. No code generated.")
                continue

            fuzz_file = oss_fuzz.save_target(project_name, code)
            logger.info(f"Saved fuzz target: '{fuzz_file}'.")

            result = oss_fuzz.run_fuzzer(project_name, fuzz_file.stem)
            if result.success:
                compilation_successes += 1
                logger.info(f"Build succeeded: '{fuzz_file}'.")
                return fuzz_file

            # --- Build Failed: Prepare for next attempt ---
            logger.error(f"Build failed (attempt {attempt})")

            # On the first failure, create a detailed prompt.
            # On subsequent failures, just send the new error to continue the conversation.
            if is_first_attempt:
                is_first_attempt = False
                langgraph_threadid = int(time.time())  # Reset thread for a new conversational context
                current_prompt = prompt_generator.build_prompt(
                    fuzz_target_code=code,
                    error_messages=result.error,
                    lang=oss_fuzz.proj_lang(project_name),
                    proj=project_name,
                    headers=", ".join(introspector.get_all_header_files(project_name)),
                )
            else:
                current_prompt = result.error

            # Clean up the failed target file before the next attempt
            oss_fuzz.remove_target(project_name, fuzz_file.stem)

        except Exception as e:
            logger.error(f"An unexpected error occurred in build attempt {attempt}: {e}", exc_info=True)
            # Clean up if a file was created before the exception
            if fuzz_file:
                oss_fuzz.remove_target(project_name, fuzz_file.stem)

            # Reset for a fresh attempt in the next iteration
            current_prompt = prompt
            is_first_attempt = True
            langgraph_threadid = int(time.time())

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


def _get_coverage_metric(summary: TotalCoverageSummary | None, metric_name: str) -> float:
    """Safely extracts a coverage metric percentage, defaulting to 0.0."""
    if not summary:
        return 0.0
    metric = getattr(summary, metric_name, None)
    return metric.percent if metric else 0.0


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
            previous_cov_summary = iterator.latest_cov()
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

            new_cov_summary = oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)
            if not new_cov_summary:
                oss_fuzz.remove_target(project_name, new_target.stem)
                continue

            if use_seeds:
                generate_seeds_for_fuzzer(project_name, new_target.stem, new_target.read_text(), llm_client)
                oss_fuzz.remove_corpus(project_name, new_target.stem)
                if cov_with_seeds := oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds):
                    new_cov_summary = cov_with_seeds
                    logger.info("Used coverage from generated seeds.")

            # Extract previous and new metrics using the helper
            prev_line_cov = _get_coverage_metric(previous_cov_summary, "lines")
            prev_branch_cov = _get_coverage_metric(previous_cov_summary, "branches")
            new_line_cov = _get_coverage_metric(new_cov_summary, "lines")
            new_branch_cov = _get_coverage_metric(new_cov_summary, "branches")

            line_growth = new_line_cov - prev_line_cov
            branch_growth = new_branch_cov - prev_branch_cov
            logger.info(f"Line coverage: {prev_line_cov:.2f}% -> {new_line_cov:.2f}% (growth: {line_growth:.2f}%)")
            logger.info(f"Branch coverage: {prev_branch_cov:.2f}% -> {new_branch_cov:.2f}% (growth: {branch_growth:.2f}%)")

            if new_line_cov <= prev_line_cov and new_branch_cov <= prev_branch_cov:
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target's coverage did not improve in iteration {iteration + 1}")
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                no_growth_count += 1
                logger.info(f"No growth count: {no_growth_count}/{config.NO_GROWTH_STOP_THRESHOLD}")
                continue

            run_fuzzers_and_get_coverage(proj_name=project_name, run_seconds=seconds)

            no_growth_count = 0
            logger.info(f"No growth count reset, 0/{config.NO_GROWTH_STOP_THRESHOLD}")
            # Record successful growth statistics (based on line coverage)
            if is_regeneration:
                regeneration_growth.append(line_growth)
                iterator.clean_cov()  # Clear coverage records for regeneration
                logger.info(f"Regeneration growth recorded: {line_growth:.2f}")
            else:
                mutation_growth.append(line_growth)
                logger.info(f"Mutation growth recorded: {line_growth:.2f}")

            fuzz_target = new_target
            iterator.record_cov()
            latest_cov = iterator.latest_cov()
            latest_line_cov = _get_coverage_metric(latest_cov, "lines")
            logger.info(f"Finished iteration {iteration + 1} for {project_name}, coverage: {latest_line_cov:.2f}%")

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

        log_name = "run_all_fuzzer" if args.command == "run_all_fuzzer" else args.project_name
        setup_logging(log_name, model_name=args.model)

        global llm_client
        llm_client = LLMClient(backend=args.llm, model_name=args.model)

        if args.command == "run_all_fuzzer":
            run_all_fuzzer(
                args.project_names,
                args.run_fuzzers,
                args.parallel,
                args.minimize_corpus,
                args.print_coverage,
                args.analyze_crashes,
            )
            logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")
            return

        if args.initial_fuzz_target:
            logger.info("Generating initial fuzz target")
            if not generate_empty_fuzz_target(args.project_name):
                logger.error(f"Failed to generate initial fuzz target for {args.project_name}")
                sys.exit(1)
        else:
            logger.info("Skipping initial fuzz target generation")
        logger.info(f"Starting introspector webapp for initial analysis of {args.project_name}")

        if not minimize_and_generate_report(args.project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        initial_cov_summary = oss_fuzz.get_coverage_summary(args.project_name, exclude_target=True)
        initial_coverage_percent = initial_cov_summary.lines.percent if initial_cov_summary and initial_cov_summary.lines else 0.0
        logger.info(f"Initial coverage for {args.project_name}: {initial_coverage_percent:.2f}%")
        if args.initial_fuzz_target:
            oss_fuzz.remove_target(args.project_name, "llm_fuzzgen_empty")

        result = process_project(args.project_name, seconds=args.seconds, use_dict=args.dict, use_seeds=args.seeds)

        if not minimize_and_generate_report(args.project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        calculate_statistics(args.project_name, initial_coverage_percent)

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
