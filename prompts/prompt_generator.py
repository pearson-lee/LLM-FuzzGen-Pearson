from pathlib import Path

from langchain.prompts import PromptTemplate

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

FUZZ_TARGET_EXAMPLES = {
    "c": """
// Please note that in C, you do not need to use `extern "C"` to declare the `LLVMFuzzerTestOneInput` function, as it is a C function, not a C++ function.
// Additionally, in C, you cannot use FuzzedDataProvider.
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  DoSomethingInterestingWithMyAPI(Data, Size);
  return 0;
}
""",
    "c++": """
#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

void MyAPI(const std::string& input, int option);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  std::string input = fdp.ConsumeRandomLengthString(100);
  int option = fdp.ConsumeIntegralInRange<int>(0, 10);

  MyAPI(input, option);

  return 0;
}
""",
}


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


def build_prompt(
    *,
    fuzz_target_code: str = "",
    error_messages: str = "",
    lang: str = "c++",
    proj: str = "",
    headers: str = "",
) -> str:
    """Generates a prompt for building the fuzz target."""
    output_example = FUZZ_TARGET_EXAMPLES.get(lang.lower(), "")

    return _load_and_format_template(
        template_name="build_template",
        input_variables=["fuzz_target_code", "error_messages", "lang", "proj", "headers", "output_example"],
        fuzz_target_code=fuzz_target_code,
        headers=headers,
        error_messages=error_messages,
        lang=lang,
        proj=proj,
        output_example=output_example,
    )


def coverage_prompt(
    *,
    fuzz_target_code: str = "",
    lang: str = "c++",
    proj: str = "",
    headers: str = "",
    fun_coverage_report: str = "",
    fuzz_target_name: str = "",
    fuzz_target_coverage_report: str = "",
) -> str:
    """Generates a prompt for improving coverage."""
    output_example = FUZZ_TARGET_EXAMPLES.get(lang.lower(), "")

    return _load_and_format_template(
        template_name="coverage_template",
        input_variables=[
            "fuzz_target_code",
            "lang",
            "proj",
            "headers",
            "output_example",
            "fun_coverage_report",
            "fuzz_target_name",
            "fuzz_target_coverage_report",
        ],
        fuzz_target_code=fuzz_target_code,
        headers=headers,
        lang=lang,
        proj=proj,
        output_example=output_example,
        fun_coverage_report=fun_coverage_report,
        fuzz_target_name=fuzz_target_name,
        fuzz_target_coverage_report=fuzz_target_coverage_report,
    )


def input_prompt(*, fuzz_target: str = "", proj: str = "", coverage_info: str = "") -> str:
    """Generates a prompt for creating fuzzing inputs."""
    return _load_and_format_template(
        template_name="input_template",
        input_variables=["fuzz_target", "proj", "coverage_info"],
        fuzz_target=fuzz_target,
        proj=proj,
        coverage_info=coverage_info,
    )


def regeneration_prompt(*, headers: str = "", lang: str = "c++", proj: str = "", fun_coverage_report: str = "") -> str:
    """Generates a prompt for regenerating a fuzz target."""
    output_example = FUZZ_TARGET_EXAMPLES.get(lang.lower(), "")

    return _load_and_format_template(
        template_name="regeneration_template",
        input_variables=["headers", "lang", "proj", "output_example", "fun_coverage_report"],
        headers=headers,
        lang=lang,
        proj=proj,
        output_example=output_example,
        fun_coverage_report=fun_coverage_report,
    )


def dict_prompt(*, proj: str = "", git_url: str = "") -> str:
    """Generates a prompt for creating a dictionary."""
    return _load_and_format_template(
        template_name="dict_template",
        input_variables=["proj", "git_url"],
        proj=proj,
        git_url=git_url,
    )


def crash_analysis_prompt(
    *,
    project_name: str,
    lang: str,
    fuzzer_source_code: str,
    crash_input_hex: str,
    stack_trace: str,
) -> str:
    """Generates a prompt for analyzing a crash."""
    return _load_and_format_template(
        template_name="crash_analysis_template",
        input_variables=[
            "project_name",
            "lang",
            "fuzzer_source_code",
            "crash_input_hex",
            "stack_trace",
        ],
        project_name=project_name,
        lang=lang,
        fuzzer_source_code=fuzzer_source_code,
        crash_input_hex=crash_input_hex,
        stack_trace=stack_trace,
    )
