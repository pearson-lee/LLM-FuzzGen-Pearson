#!/usr/bin/env python3
import logging
import sys
import os

# TODO: check oss_fuzz add_seeds() func can replace this script

# Ensure we can import from external modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from external.oss_fuzz import OSSFuzz

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

oss_fuzz = OSSFuzz()

def load_seeds_from_directory(directory_path: str) -> list[str]:
    """Reads all files from a directory and returns them as a list of strings."""
    seeds = []
    if not os.path.exists(directory_path):
        logger.error(f"Seed directory not found: {directory_path}")
        return seeds

    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)
        if os.path.isfile(filepath):
            try:
                # Assuming seeds are text based on the LLM context. 
                # If binary, read mode should be 'rb' and handling adjusted.
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if content:
                        seeds.append(content)
            except Exception as e:
                logger.warning(f"Failed to read seed file {filename}: {e}")
    
    return seeds

def upload_seeds(project_name: str, fuzzer_name: str, seed_directory: str):
    """Uploads local files as seeds to OSS-Fuzz."""
    logger.info(f"Preparing to upload seeds for {project_name}/{fuzzer_name}")
    
    seeds = load_seeds_from_directory(seed_directory)
    
    if not seeds:
        logger.warning("No seeds found to upload.")
        return

    logger.info(f"Found {len(seeds)} seeds. Uploading to OSS-Fuzz...")
    
    try:
        # Using the existing interface from your fuzzing_input.py reference
        oss_fuzz.add_seeds(project_name, fuzzer_name, seeds)
        logger.info(f"Successfully added {len(seeds)} seeds to {project_name}/{fuzzer_name}")
    except Exception as e:
        logger.error(f"Failed to upload seeds to OSS-Fuzz: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python upload_seeds.py <project_name> <fuzzer_name> <seed_directory>")
        sys.exit(1)

    project_name = sys.argv[1]
    fuzzer_name = sys.argv[2]
    seed_directory = sys.argv[3]

    upload_seeds(project_name, fuzzer_name, seed_directory)