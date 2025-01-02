import sys
import logging
from api_client import APIClient
from prompt_generator import PromptGenerator
from fuzz_target_generator import FuzzTargetGenerator
from target_saver import TargetSaver
import config
from helper import test_compilation

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():
    project_name = sys.argv[1]

    api_client = APIClient(config.API_BASE_URL)
    prompt_generator = PromptGenerator()
    target_saver = TargetSaver()
    generator = FuzzTargetGenerator(api_client, prompt_generator, target_saver)

    target_functions = api_client.get_target_functions(project_name)
    if not target_functions:
        logging.error("No target functions found")
        sys.exit(1)

    for function_sig in target_functions:
        logging.info(f"Generating fuzz target for {function_sig}")

        if target_file := generator.generate_and_save_target(project_name, function_sig):
            logging.info("Successfully generated and compiled fuzz target!")
            sys.exit(0)
        logging.warning("Compilation failed, trying next function...")

    logging.error("Failed to generate any working fuzz targets")
    sys.exit(1)


if __name__ == "__main__":
    main()
