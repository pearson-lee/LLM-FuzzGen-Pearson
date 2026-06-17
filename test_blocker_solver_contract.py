from types import SimpleNamespace

from blocker_process.blocker_classifier import infer_attempt_result
from blocker_process.dependent.input_dependent_solver import (
    build_argument_parser as build_dependent_parser,
    build_context_args,
)
from blocker_process.independent.input_independent_solver import (
    apply_strategy_contract,
    build_argument_parser as build_independent_parser,
    build_iteration_prompt,
    classify_compile_api_diagnostics,
    diagnose_runtime_evaluation,
    extract_strategy_contract,
    generate_and_build_target,
    parse_strategy_contract,
    strip_standalone_markdown_fences,
    strategy_contract_anchors,
    validate_strategy_preservation,
)
from main import _should_persist_blocker_attempt
from prompts.prompt_generator import blocker_compile_fix_prompt


BASE_ARGS = [
    "--project-name",
    "demo",
    "--function-name",
    "blocked",
    "--branch-line-number",
    "10",
    "--blocked-side-line-number",
    "11",
    "--source-file",
    "source.c",
    "--fuzz-file",
    "target.c",
]


def test_dependent_solver_accepts_and_forwards_callsite_evidence() -> None:
    args = build_dependent_parser().parse_args(
        BASE_ARGS + ["--blocker-call-sites", "active callsite evidence"]
    )

    forwarded = build_context_args(args)

    index = forwarded.index("--blocker-call-sites")
    assert forwarded[index + 1] == "active callsite evidence"


def test_independent_solver_accepts_callsite_evidence() -> None:
    args = build_independent_parser().parse_args(
        BASE_ARGS + ["--blocker-call-sites", "active callsite evidence"]
    )

    assert args.blocker_call_sites == "active callsite evidence"


def test_compile_api_diagnostics_distinguish_missing_symbol_from_wrong_signature() -> None:
    diagnostics = classify_compile_api_diagnostics(
        "error: call to undeclared function 'missing_api'; "
        "error: incompatible pointer types passing 'int *' to parameter of type 'char *'"
    )

    assert {"kind": "symbol_not_found", "symbol": "missing_api"} in diagnostics
    assert {"kind": "wrong_signature", "symbol": "unknown"} not in diagnostics


def test_compile_api_diagnostics_do_not_call_link_failure_missing_source_symbol() -> None:
    diagnostics = classify_compile_api_diagnostics("undefined reference to `declared_but_unlinked_api'")

    assert diagnostics == [{"kind": "undefined_link", "symbol": "declared_but_unlinked_api"}]


def test_unstructured_child_failure_is_pipeline_error() -> None:
    result = infer_attempt_result(
        "Input Dependent",
        2,
        {"returncode": 2, "stderr": "unrecognized arguments", "parsed_output": None},
    )

    assert result == "pipeline_error"
    assert not _should_persist_blocker_attempt({"attempt_result": result})


def test_executed_unsolved_solver_is_still_a_persistent_attempt() -> None:
    result = infer_attempt_result(
        "Input Dependent",
        1,
        {
            "returncode": 1,
            "parsed_output": {
                "success": False,
                "attempt_result": "failed",
                "failure_stage": "llm_seed_generator",
            },
        },
    )

    assert result == "failed"
    assert _should_persist_blocker_attempt({"attempt_result": result})


def test_compile_repair_preserves_original_strategy_contract() -> None:
    original = """required_state: special parser state\nstate_constructor: setup_special_state()\ntrigger_api: parse()\npreserved_invariants: state remains special"""
    repaired_code = """/* BLOCKER_STRATEGY_CONTRACT
required_state: ordinary baseline state
state_constructor: setup_baseline()
trigger_api: parse()
preserved_invariants: none
END_BLOCKER_STRATEGY_CONTRACT */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }
"""

    normalized = apply_strategy_contract(repaired_code, original)

    assert extract_strategy_contract(normalized) == original
    assert "ordinary baseline state" not in normalized


def test_contract_parser_tolerates_end_marker_typo_and_canonicalizes() -> None:
    result = parse_strategy_contract(
        """/* BLOCKER_STRATEGY_CONTRACT
required_state: output CLUT is available
state_constructor: cmsCreateDeviceLinkTHR()
trigger_api: cmsDetectDestinationBlackPoint()
preserved_invariants: do not replace with an sRGB matrix profile
END_BLOCKE_STRATEGY_CONTRACT */"""
    )

    assert result.valid
    assert "required_state: output CLUT is available" in result.contract


def test_contract_parser_rejects_missing_required_field() -> None:
    result = parse_strategy_contract(
        """/* BLOCKER_STRATEGY_CONTRACT
required_state: output CLUT is available
state_constructor: cmsCreateDeviceLinkTHR()
trigger_api: cmsDetectDestinationBlackPoint()
END_BLOCKER_STRATEGY_CONTRACT */"""
    )

    assert not result.valid
    assert "preserved_invariants" in result.error


def test_contract_parser_rejects_multiple_contract_comments() -> None:
    contract = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */"""

    result = parse_strategy_contract(f"{contract}\n{contract}")

    assert not result.valid
    assert "found 2" in result.error


def test_apply_contract_collapses_duplicate_comments() -> None:
    original = """required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve constructor and trigger"""
    duplicate_code = """/* BLOCKER_STRATEGY_CONTRACT
required_state: stale state
state_constructor: setup_stale_state()
trigger_api: parse_target()
preserved_invariants: stale invariant
END_BLOCKER_STRATEGY_CONTRACT */
/* BLOCKER_STRATEGY_CONTRACT
required_state: other stale state
state_constructor: setup_other_state()
trigger_api: parse_target()
preserved_invariants: other stale invariant
END_BLOCKER_STRATEGY_CONTRACT */
int target(void) { return 0; }
"""

    normalized = apply_strategy_contract(duplicate_code, original)

    assert normalized.count("BLOCKER_STRATEGY_CONTRACT") == 2
    assert parse_strategy_contract(normalized).valid
    assert "stale state" not in normalized


def test_strategy_preservation_detects_removed_constructor_call() -> None:
    contract = """required_state: output CLUT is available
state_constructor: cmsCreateDeviceLinkTHR()
trigger_api: cmsDetectDestinationBlackPoint()
preserved_invariants: preserve the constructor and trigger"""
    original_code = """
void target(void) {
    cmsHPROFILE p = cmsCreateDeviceLinkTHR();
    cmsDetectDestinationBlackPoint(p);
}
"""
    repaired_code = """
void target(void) {
    cmsHPROFILE p = cmsCreate_sRGBProfileTHR();
    cmsDetectDestinationBlackPoint(p);
}
"""

    anchors = strategy_contract_anchors(contract, original_code)
    preserved, missing = validate_strategy_preservation(repaired_code, anchors)

    assert anchors == ["cmsCreateDeviceLinkTHR", "cmsDetectDestinationBlackPoint"]
    assert not preserved
    assert missing == ["cmsCreateDeviceLinkTHR"]


def test_runtime_diagnosis_distinguishes_route_state_and_success() -> None:
    assert diagnose_runtime_evaluation({"success": True, "branch_hit_count": 0, "blocked_side_hit_count": 0}) == "route_failure"
    assert diagnose_runtime_evaluation({"success": True, "branch_hit_count": 10, "blocked_side_hit_count": 0}) == "predicate_state_failure"
    assert diagnose_runtime_evaluation({"success": True, "branch_hit_count": 10, "blocked_side_hit_count": 1}) == "success"
    assert diagnose_runtime_evaluation({"success": False}) == "coverage_error"


def test_replan_prompt_contains_runtime_diagnosis_and_contract() -> None:
    prompt = build_iteration_prompt(
        "base prompt",
        iteration_index=2,
        max_iterations=3,
        previous_evaluation={
            "runtime_diagnosis": "predicate_state_failure",
            "strategy_contract": "required_state: output CLUT",
            "branch_hit_count_raw": "159k",
            "blocked_side_hit_count_raw": "0",
        },
        previous_code="int target(void) { return 0; }",
    )

    assert "bounded strategy replanning" in prompt
    assert "predicate_state_failure" in prompt
    assert "required_state: output CLUT" in prompt


def test_compile_fix_prompt_receives_strategy_contract() -> None:
    prompt = blocker_compile_fix_prompt(
        project_name="demo",
        language="c",
        compile_error="wrong argument count",
        previous_code="int target(void) { return 0; }",
        iteration_feedback="branch reached, blocked side not reached",
        strategy_contract="required_state: output CLUT",
        preserve_seed_compatibility=False,
    )

    assert "required_state: output CLUT" in prompt
    assert "Compile success alone is insufficient" in prompt


def test_contract_fix_prompt_requests_only_canonical_comment() -> None:
    from prompts.prompt_generator import blocker_contract_fix_prompt

    prompt = blocker_contract_fix_prompt(
        contract_error="Missing preserved_invariants",
        malformed_contract="required_state: output CLUT",
    )

    assert "Do not return C/C++ code" in prompt
    assert "Missing preserved_invariants" in prompt
    assert "END_BLOCKER_STRATEGY_CONTRACT" in prompt


def test_markdown_fences_are_removed_without_changing_contract_or_code() -> None:
    response = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve the constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */

```c
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    setup_special_state();
    parse_target();
    return 0;
}
```
"""

    normalized = strip_standalone_markdown_fences(response)

    assert "```" not in normalized
    assert parse_strategy_contract(normalized).valid
    assert "setup_special_state();" in normalized


def test_generation_strips_markdown_fences_before_first_compile(tmp_path) -> None:
    fenced_code = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve the constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */

```c
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    setup_special_state();
    parse_target();
    return 0;
}
```
"""
    llm = _FakeLLM([fenced_code])
    oss_fuzz = _FakeOSSFuzz(tmp_path / "oss-fuzz", [True])
    iteration_dir = tmp_path / "iteration"
    iteration_dir.mkdir()

    result = generate_and_build_target(
        llm=llm,
        oss_fuzz=oss_fuzz,
        project_name="demo",
        prompt="generate",
        iteration_dir=iteration_dir,
        stem_prefix="target",
        preserve_seed_compatibility=False,
    )

    assert result["success"]
    assert result["compile_attempts"] == 1
    assert oss_fuzz.build_calls == 1
    assert "```" not in result["code"]


class _FakeLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)

    def generate(self, prompt: str, thread_id: int | None = None) -> str:
        assert self.responses
        return self.responses.pop(0)


class _FakeOSSFuzz:
    LANG_EXT = {"c": ".c"}

    def __init__(self, root, build_results: list[bool]) -> None:
        self.oss_fuzz_dir = root
        self.build_results = list(build_results)
        self.build_calls = 0
        (root / "projects" / "demo").mkdir(parents=True)

    def proj_lang(self, project_name: str) -> str:
        return "c"

    def run_fuzzer(self, project_name: str, fuzzer_name: str, **kwargs):
        self.build_calls += 1
        success = self.build_results.pop(0)
        return SimpleNamespace(success=success, error="compile failed" if not success else "")

    def remove_target(self, project_name: str, fuzzer_name: str) -> None:
        return None


def test_generation_repairs_contract_before_first_compile(tmp_path) -> None:
    initial_code = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
END_BLOCKER_STRATEGY_CONTRACT */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    setup_special_state();
    parse_target();
    return 0;
}
"""
    repaired_contract = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve the constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */"""
    llm = _FakeLLM([initial_code, repaired_contract])
    oss_fuzz = _FakeOSSFuzz(tmp_path / "oss-fuzz", [True])
    iteration_dir = tmp_path / "iteration"
    iteration_dir.mkdir()

    result = generate_and_build_target(
        llm=llm,
        oss_fuzz=oss_fuzz,
        project_name="demo",
        prompt="generate",
        iteration_dir=iteration_dir,
        stem_prefix="target",
        preserve_seed_compatibility=False,
    )

    assert result["success"]
    assert result["contract_repair_attempts"] == 1
    assert oss_fuzz.build_calls == 1
    assert "preserved_invariants" in result["strategy_contract"]


def test_compile_repair_removing_constructor_requests_replan(tmp_path) -> None:
    original_code = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve the constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    setup_special_state();
    parse_target();
    return 0;
}
"""
    broken_repair = """/* BLOCKER_STRATEGY_CONTRACT
required_state: special state
state_constructor: setup_special_state()
trigger_api: parse_target()
preserved_invariants: preserve the constructor and trigger
END_BLOCKER_STRATEGY_CONTRACT */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    setup_baseline_state();
    parse_target();
    return 0;
}
"""
    llm = _FakeLLM([original_code, broken_repair])
    oss_fuzz = _FakeOSSFuzz(tmp_path / "oss-fuzz", [False])
    iteration_dir = tmp_path / "iteration"
    iteration_dir.mkdir()

    result = generate_and_build_target(
        llm=llm,
        oss_fuzz=oss_fuzz,
        project_name="demo",
        prompt="generate",
        iteration_dir=iteration_dir,
        stem_prefix="target",
        preserve_seed_compatibility=False,
    )

    assert not result["success"]
    assert result["failure_kind"] == "strategy_replan_required"
    assert result["missing_strategy_anchors"] == ["setup_special_state"]
    assert oss_fuzz.build_calls == 1
