#!/usr/bin/env python3
import logging
import sys

from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient
import prompts.prompt_generator as prompt_generator


logger = logging.getLogger(__name__)

introspector = Introspector()
oss_fuzz = OSSFuzz()
llm_client = LLMClient()


def validate_dictionary_content(dict_content: str) -> str:
    """
    Validates dictionary content according to libFuzzer format requirements:
    - Removes comment lines (starting with #) - Note: Code keeps comments, docstring is inaccurate.
    - Validates token format (named or unnamed)
    - Ensures proper escaping of backslashes (only allows \\, \", or \\xHH where HH are hex digits)

    Args:
        dict_content: Raw dictionary content string

    Returns:
        Cleaned dictionary content with invalid lines removed
    """
    if dict_content is None:
        return ""

    valid_lines = []

    for line in dict_content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            # Skip comment/empty lines (Adjusted to match docstring intent)
            continue

        # Check basic token format
        is_valid_format = False
        value_part_without_sharp = line  # Default for unnamed

        if "=" in line:
            # Named token format: name="value"
            parts = line.split("=", 1)
            name = parts[0].strip()
            value = parts[1].strip()

            # Handle comments after value
            if "#" in value:
                value_part_without_sharp = value.split("#", 1)[0].strip()
            else:
                value_part_without_sharp = value

            if (
                name
                and value_part_without_sharp.startswith('"')
                and value_part_without_sharp.endswith('"')
                and value_part_without_sharp != '""'
                and value_part_without_sharp != '"'
            ):
                is_valid_format = True

        else:
            # Unnamed token format: "value"
            # Handle comments after value *before* checking format
            if "#" in line:
                value_part_without_sharp = line.split("#", 1)[0].strip()
            # else: value_part_without_sharp remains the stripped line

            # Check the comment-stripped part for quotes, not the original 'line'
            if (
                value_part_without_sharp.startswith('"')
                and value_part_without_sharp.endswith('"')
                and value_part_without_sharp != '""'
                and value_part_without_sharp != '"'
            ):
                is_valid_format = True

        if not is_valid_format:
            continue  # Skip this line

        # --- Escape Sequence Check ---
        # Use value_part_without_sharp which contains the "value" part for both named/unnamed
        content = value_part_without_sharp[1:-1]  # Remove the outer quotes

        i = 0
        has_invalid_escape = False
        while i < len(content):
            if content[i] == "\\":
                if i + 1 >= len(content):
                    has_invalid_escape = True
                    break
                next_char = content[i + 1]
                if next_char == "\\" or next_char == '"':
                    i += 2
                    continue
                elif next_char == "x":
                    # Check hex digits exist and are valid
                    # Corrected check: ensure 2 hex digits follow \x
                    if i + 3 < len(content) and all(
                        c in "0123456789abcdefABCDEF" for c in content[i + 2 : i + 4]
                    ):
                        i += 4
                        continue
                    else:
                        has_invalid_escape = True
                        break  # Invalid hex or not enough chars
                else:
                    has_invalid_escape = True
                    break  # Invalid char after \
            else:
                i += 1

        if has_invalid_escape:
            continue  # Skip this line

        # If we get here, the line is valid
        # Append the value part without the comment
        # For named tokens like key="val" # comment, this appends '"val"'
        # For unnamed tokens like "eng" # comment, this appends '"eng"'
        valid_lines.append(value_part_without_sharp)

    return "\n".join(valid_lines)


def generate_dict_for_proj(project_name: str):
    """Generates a dictionary for the project."""
    git_url = oss_fuzz.main_git_repo(project_name)
    prompt = prompt_generator.dict_prompt(proj=project_name, git_url=git_url)
    dict_content = llm_client.generate_dict(prompt)
    dict_content = validate_dictionary_content(dict_content)
    oss_fuzz.add_dict(project_name, dict_content)


def generate_seeds_for_fuzzer(project_name: str, fuzzer_name: str, fuzzer_source_code: str):
    """Generates seeds for a specific fuzzer."""
    logger.info(f"Generating seeds for fuzzer: {fuzzer_name}")

    try:
        # Generate input prompt
        prompt = prompt_generator.input_prompt(fuzz_target=fuzzer_source_code, proj=project_name)

        # Generate seeds using LLM
        seeds = llm_client.generate_seeds(prompt)

        if not seeds:
            logger.warning(f"No seeds generated for {fuzzer_name}")
            return

        logger.info(f"Generated {len(seeds)} seeds for {fuzzer_name}")

        # Add seeds to OSS-Fuzz
        oss_fuzz.add_seeds(project_name, fuzzer_name, seeds)
        logger.info(f"Added {len(seeds)} seeds to {project_name}/{fuzzer_name}")

    except Exception as e:
        logger.error(f"Error processing fuzzer {fuzzer_name}: {e}")


def process_seed_generation(project_name: str):
    if not project_name:
        logger.error("No project name provided")
        sys.exit(1)

    logger.info(f"Starting seed generation for project: {project_name}")

    # Step 2: Get fuzzer names and code for the project
    fuzz_targets_info = introspector.fuzz_target_source_code(project_name)
    if not fuzz_targets_info:
        logger.warning(f"No fuzzers found for project {project_name}")
        return

    # Filter fuzzers based on name pattern "fuzz*fuzzer"
    fuzz_targets_info = [f for f in fuzz_targets_info if f["name"].startswith("llm_fuzzgen")]

    logger.info(
        f"Found {len(fuzz_targets_info)} llm-fuzz gen fuzzers for {project_name}: {', '.join([f['name'] for f in fuzz_targets_info])}"
    )

    # Process each fuzzer
    for fuzzer_info in fuzz_targets_info:
        fuzzer_name = fuzzer_info["name"]
        fuzzer_code = fuzzer_info["code"]
        generate_seeds_for_fuzzer(project_name, fuzzer_name, fuzzer_code)


if __name__ == "__main__":
    # Parse command line arguments - expect a single project name
    if len(sys.argv) != 2:
        print("Usage: python seeds.py <project_name>")
        sys.exit(1)

    project_name = sys.argv[1]

    # Set up logging
    from logger import setup_logging
    from main import generate_report_and_start_webapp

    setup_logging(project_name)

    try:
        logger.info("Starting introspector webapp for initial analysis")
        if not generate_report_and_start_webapp(project_name):
            logger.error("Failed to start introspector webapp")
            sys.exit(1)

        # Run the seed generation process
        process_seed_generation(project_name)

        logger.info("Restarting introspector webapp to analyze results with new seeds")
        generate_report_and_start_webapp(project_name, clean=True)
        logger.info("Seed generation process completed")
        input("Press Enter to shutdown the server (http://localhost:8080)")

    finally:
        introspector.shutdown_webapp()
