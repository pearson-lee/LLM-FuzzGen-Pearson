from langchain_core.output_parsers import StrOutputParser, BaseOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from typing import Optional
import logging
import config
from api_client import APIClient
from prompt_generator import PromptGenerator
from target_saver import TargetSaver
from helper import test_compilation
from pathlib import Path
import config
import os
import re

logger = logging.getLogger(__name__)


class CodeBlockParser(BaseOutputParser):
    """Extract code from markdown code blocks."""

    def parse(self, text: str) -> str:
        # Look for code between ```c or ```cpp markers
        pattern = r"```(?:c|cpp|c\+\+)\n(.*?)```"
        if match := re.search(pattern, text, re.DOTALL):
            return match.group(1).strip()
        return text.strip()  # Fallback if no markers found


class FuzzTargetGenerator:
    def __init__(self, api_client: APIClient, prompt_generator: PromptGenerator, target_saver: TargetSaver):
        self.llm = self._initialize_llm()
        self.api_client = api_client
        self.prompt_generator = prompt_generator
        self.target_saver = target_saver
        self.output_parser = CodeBlockParser()

    def _initialize_llm(self) -> BaseOutputParser:
        if config.MODEL_NAME in ["gpt-4o-mini", "gpt-4o"]:
            return ChatOpenAI(
                temperature=config.TEMPERATURE,
                model=config.MODEL_NAME,
                max_tokens=config.MAX_TOKENS,
                api_key=config.API_KEY
            )

        if config.MODEL_NAME in ["gemini-1.5-pro", "gemini-2.0-flash-exp"]:
            return ChatGoogleGenerativeAI(
                temperature=config.TEMPERATURE,
                model=config.MODEL_NAME,
                max_tokens=config.MAX_TOKENS,
                api_key=config.API_KEY
            )

    def _get_build_script_content(self, project_name: str) -> str:
        build_script = Path(config.OSS_FUZZ_PATH) / "projects" / project_name / "build.sh"
        if not os.path.exists(build_script):
            return ""
        with open(build_script, "r") as f:
            file_content = f.read()
            # Split into lines and filter out comments
            lines = file_content.splitlines()
            filtered_lines = [
                line for line in lines if not line.lstrip().startswith('#')]
            # Join lines back together with newlines
            return '\n'.join(filtered_lines)

    def handle_compilation_failure(self, error_message: str, current_code: str) -> Optional[str]:
        prompt = self.prompt_generator.get_compile_fail_prompt()
        chain = prompt | self.llm | self.output_parser
        try:
            return chain.invoke({
                "SOURCE_CODE": current_code,
                "ERROR": error_message
            })
        except Exception as e:
            logger.error(f"Failed to fix compilation error: {e}")
            return None

    def generate_target(self, project_name: str, function_signature: str) -> Optional[str]:
        source_code = self.api_client.get_function_source_code(project_name, function_signature)
        headers = self.api_client.get_function_required_headers(project_name, function_signature)
        language = self.api_client.get_project_language(project_name)
        build_script = self._get_build_script_content(project_name)

        prompt = self.prompt_generator.get_fuzz_target_prompt()
        chain = prompt | self.llm | self.output_parser

        try:
            return chain.invoke({
                "LANGUAGE": language,
                "FUNCTION_SIGNATURE": function_signature,
                "SOURCE_CODE": source_code,
                "HEADERS": headers,
                "BUILD_SCRIPT": build_script
            })
        except Exception as e:
            logger.error(f"Failed to generate fuzz target: {e}")
            return None

    def generate_and_save_target(self, project_name: str, function_signature: str):
        attempts = 1
        current_code = None

        while attempts <= config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS:
            # Generate or use existing code
            if not current_code:
                current_code = self.generate_target(project_name, function_signature)
                if not current_code:
                    return None, attempts

            # Save and test
            target_file = self.target_saver.save_target(
                project_name, current_code, self.api_client.get_project_language(project_name))
            logger.info(
                f"Saved fuzz target to {target_file}. {project_name}_{function_signature}_attempts_{attempts}")

            # Test compilation
            compilation_result = test_compilation(project_name)
            if compilation_result.success:
                logger.info(
                    f"Fuzz target {project_name}_{function_signature} generated successfully after {attempts} attempts.")
                return target_file, attempts

            # remove the target file if compilation failed
            target_file.unlink()

            # Handle compilation failure
            logger.warning(
                f"Compilation failed (attempt {attempts}/{config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}). {project_name}_{function_signature}")
            current_code = self.handle_compilation_failure(
                compilation_result.error, current_code)
            if not current_code:
                return None, attempts

            attempts += 1

        logger.error(
            f"Max attempts({config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS}) reached for compilation fixes. {project_name}_{function_signature}")
        return None, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS
