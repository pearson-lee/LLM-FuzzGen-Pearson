from pathlib import Path

from langchain.prompts import PromptTemplate

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _load_and_format_template(template_name: str, input_variables: list, **kwargs) -> str:
    """
    Helper function to load a prompt template from a file and format it.

    Args:
        template_name: The name of the template file (without extension).
        input_variables: A list of variable names expected by the template.
        **kwargs: Keyword arguments to fill in the template variables.

    Returns:
        The formatted prompt string.
    """
    template_path = TEMPLATES_DIR / template_name
    with open(template_path, "r") as f:
        template_content = f.read()

    prompt_template = PromptTemplate(
        input_variables=input_variables,
        template=template_content,
    )
    return prompt_template.format(**kwargs)


def fuzz_target_prompt(
    *,
    language: str = "",
    function_signature: str = "",
    source_code: str = "",
    headers: str = "",
    build_script: str = ""
) -> str:
    """Generates a prompt for creating a fuzz target."""
    return _load_and_format_template(
        template_name="generator_template",
        input_variables=["language", "function_signature", "source_code", "headers", "build_script"],
        language=language,
        function_signature=function_signature,
        source_code=source_code,
        headers=headers,
        build_script=build_script,
    )


def compile_fail_prompt(*, source_code: str = "", error: str = "") -> str:
    """Generates a prompt for handling compilation failures."""
    return _load_and_format_template(
        template_name="compile_fail_template",
        input_variables=["source_code", "error"],
        source_code=source_code,
        error=error,
    )


def initial_prompt(*, sut_info: str = "", fuzz_targets: str = "") -> str:
    """Generates the initial prompt for the fuzzing process."""
    return _load_and_format_template(
        template_name="initial_template",
        input_variables=["sut_info", "fuzz_targets"],
        sut_info=sut_info,
        fuzz_targets=fuzz_targets,
    )


def build_prompt(
    *,
    fuzz_target_code: str = "",
    error_messages: str = "",
    lang: str = "c++",
    proj: str = "",
    headers: str = ""
) -> str:
    """Generates a prompt for building the fuzz target."""
    return _load_and_format_template(
        template_name="build_template",
        input_variables=["fuzz_target_code", "error_messages", "lang", "proj", "headers"],
        fuzz_target_code=fuzz_target_code,
        headers=headers,
        error_messages=error_messages,
        lang=lang,
        proj=proj,
    )


def coverage_prompt(
    *,
    fuzz_target_code: str = "",
    coverage_information: str = "",
    lang: str = "c++",
    proj: str = "",
    headers: str = ""
) -> str:
    """Generates a prompt for improving coverage."""
    return _load_and_format_template(
        template_name="coverage_template",
        input_variables=["fuzz_target_code", "coverage_information", "lang", "proj", "headers"],
        fuzz_target_code=fuzz_target_code,
        headers=headers,
        coverage_information=coverage_information,
        lang=lang,
        proj=proj,
    )


def input_prompt(*, fuzz_target: str = "", proj: str = "") -> str:
    """Generates a prompt for creating fuzzing inputs."""
    return _load_and_format_template(
        template_name="input_template",
        input_variables=["fuzz_target", "proj"],
        fuzz_target=fuzz_target,
        proj=proj,
    )


def regeneration_prompt(*, signature: str = "", headers: str = "", lang: str = "c++", proj: str = "") -> str:
    """Generates a prompt for regenerating a fuzz target."""
    return _load_and_format_template(
        template_name="regeneration_template",
        input_variables=["signature", "headers", "lang", "proj"],
        signature=signature,
        headers=headers,
        lang=lang,
        proj=proj,
    )


def dict_prompt(*, proj: str = "", git_url: str = "") -> str:
    """Generates a prompt for creating a dictionary."""
    return _load_and_format_template(
        template_name="dict_template",
        input_variables=["proj", "git_url"],
        proj=proj,
        git_url=git_url,
    )
