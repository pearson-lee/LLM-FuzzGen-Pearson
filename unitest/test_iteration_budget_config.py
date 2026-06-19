import inspect
import sys
from types import SimpleNamespace

import config.config as config
import main
from blocker_process.dependent.input_dependent_seed_generator import MAX_GENERATOR_ITERATIONS
from blocker_process.dependent.input_dependent_solver import build_argument_parser as build_dependent_parser
from blocker_process.independent import input_independent_solver


BLOCKER_BASE_ARGS = [
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


def test_coverage_and_blocker_budgets_match_experiment_profiles() -> None:
    assert config.COVERAGE_ITERATION_LOOP == 100
    assert config.COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS == 10
    assert config.COVERAGE_NO_GROWTH_STOP_THRESHOLD == 10

    assert config.BLOCKER_MAX_ITERATIONS == 3
    assert config.BLOCKER_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS == 4
    assert config.BLOCKER_NO_GROWTH_STOP_THRESHOLD == 3


def test_run_all_fuzzer_uses_blocker_iteration_default(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "run_all_fuzzer", "demo", "--use-blocker"])

    args = main._parse_args()

    assert args.blocker_max_iterations == config.BLOCKER_MAX_ITERATIONS


def test_blocker_solver_defaults_do_not_use_coverage_iteration_budget() -> None:
    independent_args = input_independent_solver.build_argument_parser().parse_args(BLOCKER_BASE_ARGS)
    dependent_args = build_dependent_parser().parse_args(BLOCKER_BASE_ARGS)

    assert independent_args.max_iterations == config.BLOCKER_MAX_ITERATIONS
    assert dependent_args.max_iterations == config.BLOCKER_MAX_ITERATIONS
    assert MAX_GENERATOR_ITERATIONS == config.BLOCKER_MAX_ITERATIONS
    assert independent_args.max_iterations != config.COVERAGE_ITERATION_LOOP


def test_independent_no_growth_default_uses_blocker_budget() -> None:
    default = inspect.signature(input_independent_solver.run_strategy_iterations).parameters[
        "no_growth_threshold"
    ].default

    assert default == config.BLOCKER_NO_GROWTH_STOP_THRESHOLD


class _EmptyLLM:
    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, prompt: str, thread_id: int | None = None) -> str:
        self.call_count += 1
        return ""


def test_coverage_generation_uses_coverage_compile_budget(monkeypatch) -> None:
    llm = _EmptyLLM()
    monkeypatch.setattr(main, "llm_client", llm)
    monkeypatch.setattr(config, "COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(config, "BLOCKER_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS", 7)

    result = main.build_fuzz_target("demo", "prompt")

    assert result is None
    assert llm.call_count == 2


def test_independent_generation_uses_blocker_compile_budget(monkeypatch, tmp_path) -> None:
    llm = _EmptyLLM()
    monkeypatch.setattr(config, "COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS", 7)
    monkeypatch.setattr(config, "BLOCKER_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS", 2)
    iteration_dir = tmp_path / "iteration"
    iteration_dir.mkdir()

    result = input_independent_solver.generate_and_build_target(
        llm=llm,
        oss_fuzz=SimpleNamespace(),
        project_name="demo",
        prompt="prompt",
        iteration_dir=iteration_dir,
        stem_prefix="target",
        preserve_seed_compatibility=False,
    )

    assert not result["success"]
    assert result["compile_attempts"] == 2
    assert llm.call_count == 2
