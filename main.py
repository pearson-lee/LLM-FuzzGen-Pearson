#!/usr/bin/env python3
import asyncio
import logging
import sys
import time

import config.config as config
import prompts.prompt_generator as prompt_generator
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from external.sut import SUT
from llm_interface.llm_client import LLMClient
from logger import setup_logging

logger = logging.getLogger(__name__)

sut = SUT()
oss_fuzz = OSSFuzz()
introspector = Introspector()
llm_client = LLMClient()


def _parse_args() -> list:
    if len(sys.argv) < 2:
        print("Usage: python main.py <project_name1> <project_name2> ...")
        sys.exit(1)
    return sys.argv[1:]


async def _build_fuzz_target(project_name: str, prompt: str) -> str | None:
    """Build a fuzz target using prompt iteration (up to config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS times)."""
    fuzz_target = llm_client.generate(prompt)
    for attempt in range(config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS):
        logger.info(f"Building fuzz target for {project_name} (attempt {attempt + 1})")
        fuzz_target_file = oss_fuzz.save_target(project_name, fuzz_target)
        build_res = await oss_fuzz.build_fuzzers(project_name)

        if build_res.success:
            logger.info(f"Successfully built fuzz target for {project_name} after {attempt + 1} attempts")
            return fuzz_target

        fuzz_target_file.unlink()  # Remove the failed fuzz target
        logger.error(f"Failed to build fuzz target for {project_name} on attempt {attempt + 1}")

        # Don't generate new prompt on last attempt
        if attempt < config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS - 1:
            build_prompt = prompt_generator.build_prompt(
                fuzz_target_code=fuzz_target, error_messages=build_res.error
            )
            fuzz_target = llm_client.generate(build_prompt)
    return None


async def process_project(project_name: str) -> bool:
    """Process a single project and generate fuzz targets."""
    logging.info(f"Starting to process project: {project_name}")
    proj_info = sut.get_project_info(project_name)
    fuzz_target_examples = introspector.fuzz_target_source_code(project_name)

    initial_prompt = prompt_generator.initial_prompt(sut_info=proj_info, fuzz_targets=fuzz_target_examples)
    fuzz_target = await _build_fuzz_target(project_name, initial_prompt)
    if fuzz_target is None:
        logger.error(
            f"Failed to build fuzz target for {project_name} after {config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} attempts"
        )
        return False

    await oss_fuzz.generate_report(project_name, seconds=30)
    introspector.update_start_webapp()
    logging.info(f"Successfully finished processing project: {project_name}")
    return True


async def main() -> None:
    start_time = time.perf_counter()
    project_names = _parse_args()
    setup_logging(project_names)
    await oss_fuzz.generator_reports(project_names)

    if not introspector.update_start_webapp():
        return

    async with asyncio.TaskGroup() as tg:
        for project_name in project_names:
            tg.create_task(process_project(project_name), name=f"process-{project_name}")

    logger.info("All projects processed")
    end_time = time.perf_counter()
    logger.info(f"Total execution time: {end_time - start_time:.2f} seconds")

    input("Press Enter to shutdown the server")
    introspector.shutdown_webapp()


if __name__ == "__main__":
    asyncio.run(main())
