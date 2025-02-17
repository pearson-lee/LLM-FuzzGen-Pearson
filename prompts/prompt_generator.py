from pathlib import Path

from langchain.prompts import PromptTemplate

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _load_and_format_template(template_name: str, input_variables: list, **kwargs) -> str:
    """Helper function to load template and format prompt"""
    template_path = TEMPLATES_DIR / template_name
    with open(template_path, "r") as f:
        template_content = f.read()

    prompt_template = PromptTemplate(
        input_variables=input_variables,
        template=template_content,
    )
    return prompt_template.format(**kwargs)


def fuzz_target_prompt(
    *, language: str, function_signature: str, source_code: str, headers: str, build_script: str
) -> str:
    return _load_and_format_template(
        "generator_template",
        ["language", "function_signature", "source_code", "headers", "build_script"],
        language=language,
        function_signature=function_signature,
        source_code=source_code,
        headers=headers,
        build_script=build_script,
    )


def compile_fail_prompt(*, source_code: str, error: str) -> str:
    return _load_and_format_template(
        "compile_fail_template",
        ["source_code", "error"],
        source_code=source_code,
        error=error,
    )


def initial_prompt(*, sut_info: str, fuzz_targets: str) -> str:
    return _load_and_format_template(
        "initial_template",
        ["sut_info", "fuzz_targets"],
        sut_info=sut_info,
        fuzz_targets=fuzz_targets,
    )


def build_prompt(*, fuzz_target_code: str, error_messages: str) -> str:
    return _load_and_format_template(
        "build_template",
        ["fuzz_target_code", "error_messages"],
        fuzz_target_code=fuzz_target_code,
        error_messages=error_messages,
    )


def coverage_prompt(*, fuzz_target_code: str, coverage_information: str) -> str:
    return _load_and_format_template(
        "coverage_template",
        ["fuzz_target_code", "coverage_information"],
        fuzz_target_code=fuzz_target_code,
        coverage_information=coverage_information,
    )


def input_prompt(*, fuzz_target: str, symbolic_execution_results: str) -> str:
    return _load_and_format_template(
        "input_template",
        ["fuzz_target", "symbolic_execution_results"],
        fuzz_target=fuzz_target,
        symbolic_execution_results=symbolic_execution_results,
    )


def regeneration_prompt(*, signature: str, source_code_snippet: str) -> str:
    return _load_and_format_template(
        "regeneration_template",
        ["signature", "source_code_snippet"],
        signature=signature,
        source_code_snippet=source_code_snippet,
    )
