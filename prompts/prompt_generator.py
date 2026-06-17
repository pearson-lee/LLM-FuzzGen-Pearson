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

DEFAULT_FUZZ_TARGET_EXAMPLE = FUZZ_TARGET_EXAMPLES["c++"]


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
    heuristic_summary: str,
    reproduce_result: str,
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
            "heuristic_summary",
            "reproduce_result",
        ],
        project_name=project_name,
        lang=lang,
        fuzzer_source_code=fuzzer_source_code,
        crash_input_hex=crash_input_hex,
        stack_trace=stack_trace,
        heuristic_summary=heuristic_summary,
        reproduce_result=reproduce_result,
    )


def crash_audit_prompt(
    *,
    finding: str,
    confidence: float,
    reasoning_summary: str,
    frame_classification: str,
    top_app_frame_source: str,
    stack_trace: str,
    fuzzer_source_code: str,
) -> str:
    """Generates a prompt for the evidence audit pass on a crash analysis."""
    return _load_and_format_template(
        template_name="crash_audit_template",
        input_variables=[
            "finding",
            "confidence",
            "reasoning_summary",
            "frame_classification",
            "top_app_frame_source",
            "stack_trace",
            "fuzzer_source_code",
        ],
        finding=finding,
        confidence=confidence,
        reasoning_summary=reasoning_summary,
        frame_classification=frame_classification,
        top_app_frame_source=top_app_frame_source,
        stack_trace=stack_trace,
        fuzzer_source_code=fuzzer_source_code,
    )


def blocker_reference_guided_prompt(
    *,
    project_name: str,
    language: str,
    function_name: str,
    branch_line_number: str,
    blocked_side_line_number: str,
    blocker_line_code: str,
    blocked_side_line_code: str,
    fuzz_target_name: str,
    fuzz_file: str,
    fuzz_target_code: str,
    source_file: str,
    source_code: str,
    header_code: str,
    branch_window: str,
    blocked_window: str,
    symbol_evidence: str,
    runtime_blocker_segment: str,
    runtime_blocker_segment_source_codes: str,
    cfg_call_chain: str,
    cfg_source_codes: str,
    blocker_call_sites: str,
    triggering_input_path: str,
    triggering_input_preview: str,
) -> str:
    output_example = FUZZ_TARGET_EXAMPLES.get(language.lower(), DEFAULT_FUZZ_TARGET_EXAMPLE)
    return _load_and_format_template(
        template_name="blocker_reference_guided_template",
        input_variables=[
            "project_name",
            "language",
            "function_name",
            "branch_line_number",
            "blocked_side_line_number",
            "blocker_line_code",
            "blocked_side_line_code",
            "fuzz_target_name",
            "fuzz_file",
            "fuzz_target_code",
            "source_file",
            "source_code",
            "header_code",
            "branch_window",
            "blocked_window",
            "symbol_evidence",
            "runtime_blocker_segment",
            "runtime_blocker_segment_source_codes",
            "cfg_call_chain",
            "cfg_source_codes",
            "blocker_call_sites",
            "triggering_input_path",
            "triggering_input_preview",
            "output_example",
        ],
        project_name=project_name,
        language=language,
        function_name=function_name,
        branch_line_number=branch_line_number,
        blocked_side_line_number=blocked_side_line_number,
        blocker_line_code=blocker_line_code,
        blocked_side_line_code=blocked_side_line_code,
        fuzz_target_name=fuzz_target_name,
        fuzz_file=fuzz_file,
        fuzz_target_code=fuzz_target_code,
        source_file=source_file,
        source_code=source_code,
        header_code=header_code,
        branch_window=branch_window,
        blocked_window=blocked_window,
        symbol_evidence=symbol_evidence,
        runtime_blocker_segment=runtime_blocker_segment,
        runtime_blocker_segment_source_codes=runtime_blocker_segment_source_codes,
        cfg_call_chain=cfg_call_chain,
        cfg_source_codes=cfg_source_codes,
        blocker_call_sites=blocker_call_sites,
        triggering_input_path=triggering_input_path,
        triggering_input_preview=triggering_input_preview,
        output_example=output_example,
    )


def blocker_dedicated_generation_prompt(
    *,
    project_name: str,
    language: str,
    function_name: str,
    branch_line_number: str,
    blocked_side_line_number: str,
    blocker_line_code: str,
    blocked_side_line_code: str,
    fuzz_target_name: str,
    fuzz_file: str = "",
    fuzz_target_code: str,
    source_file: str,
    source_code: str,
    header_code: str,
    branch_window: str,
    blocked_window: str,
    symbol_evidence: str,
    runtime_blocker_segment: str,
    runtime_blocker_segment_source_codes: str,
    cfg_call_chain: str,
    cfg_source_codes: str,
    blocker_call_sites: str,
    triggering_input_path: str,
    triggering_input_preview: str,
    ref_handoff_summary: str = "N/A",
) -> str:
    output_example = FUZZ_TARGET_EXAMPLES.get(language.lower(), DEFAULT_FUZZ_TARGET_EXAMPLE)
    return _load_and_format_template(
        template_name="blocker_dedicated_generation_template",
        input_variables=[
            "project_name",
            "language",
            "function_name",
            "branch_line_number",
            "blocked_side_line_number",
            "blocker_line_code",
            "blocked_side_line_code",
            "fuzz_target_name",
            "fuzz_target_code",
            "source_file",
            "source_code",
            "header_code",
            "branch_window",
            "blocked_window",
            "symbol_evidence",
            "runtime_blocker_segment",
            "runtime_blocker_segment_source_codes",
            "cfg_call_chain",
            "cfg_source_codes",
            "blocker_call_sites",
            "triggering_input_path",
            "triggering_input_preview",
            "ref_handoff_summary",
            "output_example",
        ],
        project_name=project_name,
        language=language,
        function_name=function_name,
        branch_line_number=branch_line_number,
        blocked_side_line_number=blocked_side_line_number,
        blocker_line_code=blocker_line_code,
        blocked_side_line_code=blocked_side_line_code,
        fuzz_target_name=fuzz_target_name,
        fuzz_target_code=fuzz_target_code,
        source_file=source_file,
        source_code=source_code,
        header_code=header_code,
        branch_window=branch_window,
        blocked_window=blocked_window,
        symbol_evidence=symbol_evidence,
        runtime_blocker_segment=runtime_blocker_segment,
        runtime_blocker_segment_source_codes=runtime_blocker_segment_source_codes,
        cfg_call_chain=cfg_call_chain,
        cfg_source_codes=cfg_source_codes,
        blocker_call_sites=blocker_call_sites,
        triggering_input_path=triggering_input_path,
        triggering_input_preview=triggering_input_preview,
        ref_handoff_summary=ref_handoff_summary or "N/A",
        output_example=output_example,
    )


def blocker_compile_fix_prompt(
    *,
    project_name: str,
    language: str,
    compile_error: str,
    previous_code: str,
    iteration_feedback: str,
    strategy_contract: str,
    preserve_seed_compatibility: bool,
) -> str:
    seed_compatibility_requirement = _load_and_format_template(
        template_name=(
            "blocker_compile_fix_seed_compatible_template"
            if preserve_seed_compatibility
            else "blocker_compile_fix_seed_flexible_template"
        ),
        input_variables=[],
    )
    return _load_and_format_template(
        template_name="blocker_compile_fix_template",
        input_variables=[
            "project_name",
            "language",
            "compile_error",
            "previous_code",
            "iteration_feedback",
            "strategy_contract",
            "seed_compatibility_requirement",
        ],
        project_name=project_name or "N/A",
        language=language or "N/A",
        compile_error=compile_error or "N/A",
        previous_code=previous_code or "N/A",
        iteration_feedback=iteration_feedback or "N/A",
        strategy_contract=strategy_contract or "N/A",
        seed_compatibility_requirement=seed_compatibility_requirement,
    )


def blocker_contract_fix_prompt(*, contract_error: str, malformed_contract: str) -> str:
    return _load_and_format_template(
        template_name="blocker_contract_fix_template",
        input_variables=["contract_error", "malformed_contract"],
        contract_error=contract_error or "Unknown Strategy Contract validation error.",
        malformed_contract=malformed_contract or "N/A",
    )
