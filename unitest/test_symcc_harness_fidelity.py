from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import blocker_process.dependent.build_context as build_context_module
import blocker_process.dependent.symcc_blocker_solver as symcc_solver
from blocker_process.dependent.build_context import BuildContext
from blocker_process.dependent.run_symcc_blocker import merge_build_context_overrides


def coverage_result(seed: Path, branch_hits: int) -> symcc_solver.CoverageResult:
    return symcc_solver.CoverageResult(
        seed=seed,
        branch_hit_count_raw=str(branch_hits),
        blocked_side_hit_count_raw="0",
        branch_hit_count=branch_hits,
        blocked_side_hit_count=0,
        blocked_side_line_reached=False,
    )


def fidelity_args(tmp_path: Path, seed_count: int = 1) -> dict:
    seeds = []
    for index in range(seed_count):
        seed = tmp_path / ("trigger.seed" if index == 0 else f"seed_{index}.bin")
        seed.write_bytes(b"trigger" if index == 0 else f"seed{index}".encode())
        seeds.append(seed)
    binary = tmp_path / "replay_cov"
    binary.write_bytes(b"binary")
    source = tmp_path / "source.c"
    source.write_text("int target(void) { return 0; }", encoding="utf-8")
    return {
        "coverage_bin": binary,
        "branch_source": source,
        "coverage_source": str(source),
        "branch_line": 10,
        "blocked_side_line": 11,
        "fidelity_seeds": seeds,
        "target_args": "@@",
        "input_mode": "file",
        "timeout_sec": 1,
        "coverage_dir": tmp_path / "coverage",
        "keep_report": False,
        "llvm_profdata": "llvm-profdata",
        "llvm_cov": "llvm-cov",
    }


def test_fidelity_is_compatible_when_trigger_reaches_branch(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)
    monkeypatch.setattr(
        symcc_solver,
        "evaluate_seed_with_coverage",
        lambda **kwargs: coverage_result(args["fidelity_seeds"][0], branch_hits=3),
    )

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "compatible"
    assert result["coverage_success"] is True
    assert result["attempt_count"] == 1


def test_fidelity_retries_coverage_then_reports_incompatible(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)
    calls = 0

    def evaluate(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("missing profraw")
        return coverage_result(args["fidelity_seeds"][0], branch_hits=0)

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", evaluate)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "incompatible"
    assert result["coverage_success"] is True
    assert result["attempt_count"] == 2
    assert result["errors"] == ["trigger.seed: missing profraw"]


def test_fidelity_is_unknown_only_after_coverage_retry_fails(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)

    def fail(**kwargs):
        raise RuntimeError("llvm-profdata failed")

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", fail)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "unknown"
    assert result["coverage_success"] is False
    assert result["attempt_count"] == 2
    assert result["errors"] == [
        "trigger.seed: llvm-profdata failed",
        "trigger.seed: llvm-profdata failed",
    ]


def test_fidelity_tries_later_seeds_when_the_first_misses(tmp_path: Path, monkeypatch) -> None:
    # A generated harness can consume bytes differently from the original target, so a seed
    # that reached the branch there may miss here. Judging the harness on the first seed
    # alone ended 30 of 66 archived attempts before SymCC ever ran.
    args = fidelity_args(tmp_path, seed_count=3)
    seen: list[str] = []

    def evaluate(**kwargs):
        seed_path = kwargs["seed_path"]
        seen.append(seed_path.name)
        hits = 5 if seed_path.name == "seed_2.bin" else 0
        return coverage_result(seed_path, branch_hits=hits)

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", evaluate)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "compatible"
    assert result["branch_hit_count"] == 5
    assert result["seeds_tried"] == 3
    assert seen == ["trigger.seed", "seed_1.bin", "seed_2.bin"]


def test_fidelity_stops_at_the_first_reaching_seed(tmp_path: Path, monkeypatch) -> None:
    # Each seed costs a coverage replay of the whole harness, so a hit must end the search.
    args = fidelity_args(tmp_path, seed_count=4)
    seen: list[str] = []

    def evaluate(**kwargs):
        seen.append(kwargs["seed_path"].name)
        return coverage_result(kwargs["seed_path"], branch_hits=2)

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", evaluate)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "compatible"
    assert seen == ["trigger.seed"]
    assert result["seeds_tried"] == 1


def test_fidelity_is_incompatible_only_after_every_seed_misses(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path, seed_count=3)
    monkeypatch.setattr(
        symcc_solver,
        "evaluate_seed_with_coverage",
        lambda **kwargs: coverage_result(kwargs["seed_path"], branch_hits=0),
    )

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "incompatible"
    assert result["seeds_tried"] == 3
    assert result["seeds_available"] == 3


def test_fidelity_ignores_seeds_that_do_not_exist(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path, seed_count=2)
    args["fidelity_seeds"] = [tmp_path / "gone.bin", *args["fidelity_seeds"]]
    seen: list[str] = []

    def evaluate(**kwargs):
        seen.append(kwargs["seed_path"].name)
        return coverage_result(kwargs["seed_path"], branch_hits=0)

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", evaluate)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert "gone.bin" not in seen
    assert result["seeds_available"] == 2


def test_fidelity_is_unknown_when_no_seed_file_exists(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)
    args["fidelity_seeds"] = [tmp_path / "gone.bin"]
    monkeypatch.setattr(
        symcc_solver,
        "evaluate_seed_with_coverage",
        lambda **kwargs: pytest.fail("coverage must not run without a seed"),
    )

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "unknown"
    assert result["seeds_tried"] == 0


def test_generated_harness_context_merges_project_link_flags(tmp_path: Path) -> None:
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    context = BuildContext(
        project_name="demo",
        mode="generated_harness",
        target_source=None,
        branch_source="branch.c",
        harness_source="harness.c",
        source_root=None,
        language="c",
        cflags="-O0",
        ldflags="-pthread",
    )
    args = SimpleNamespace(
        include_dir=[str(include_dir)],
        define=["FEATURE=1"],
        cflags="-g -O0",
        cxxflags="",
        ldflags="-lm -pthread",
    )

    merged = merge_build_context_overrides(context, args)

    assert merged.cflags == "-O0 -g"
    assert merged.ldflags == "-pthread -lm"
    assert merged.include_dirs == [str(include_dir.resolve())]
    assert merged.defines == ["FEATURE=1"]
    assert "Merged project SymCC config" in merged.diagnostics[-1]


def test_generated_harness_context_adds_project_generated_headers(tmp_path: Path, monkeypatch) -> None:
    generated_headers = tmp_path / "libvpx" / "work" / "build"
    generated_headers.mkdir(parents=True)
    (generated_headers / "vpx_config.h").write_text("#define VPX_CONFIG_H 1\n", encoding="utf-8")
    monkeypatch.setattr(build_context_module, "OSS_FUZZ_OUT", tmp_path)
    context = BuildContext(
        project_name="libvpx",
        mode="generated_harness",
        target_source=None,
        branch_source="branch.c",
        harness_source="harness.c",
        source_root=None,
        language="c++",
    )
    args = SimpleNamespace(
        project_name="libvpx",
        include_dir=[],
        define=[],
        cflags="",
        cxxflags="",
        ldflags="",
    )

    merged = merge_build_context_overrides(context, args)

    assert str(generated_headers.resolve()) in merged.include_dirs


def test_coverage_source_args_maps_embedded_source_to_local_mirror(tmp_path: Path) -> None:
    local_source = tmp_path / "session" / "source_root" / "src" / "cmsio1.c"
    local_source.parent.mkdir(parents=True)
    local_source.write_text("int value;\n", encoding="utf-8")

    args = symcc_solver.coverage_source_args(local_source, "/src/lcms/src/cmsio1.c")

    assert args == [
        f"-path-equivalence=/src/lcms,{tmp_path / 'session' / 'source_root'}",
        str(local_source.resolve()),
    ]


def test_coverage_source_args_maps_filename_only_source_identity(tmp_path: Path) -> None:
    local_source = tmp_path / "session" / "source_root" / "gzwrite.c"
    local_source.parent.mkdir(parents=True)
    local_source.write_text("int value;\n", encoding="utf-8")

    args = symcc_solver.coverage_source_args(local_source, "/src/zlib/gzwrite.c")

    assert args == [
        f"-path-equivalence=/src/zlib,{tmp_path / 'session' / 'source_root'}",
        str(local_source.resolve()),
    ]


def test_missing_branch_line_retries_unfiltered_coverage_report(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)
    raw_profile = tmp_path / "coverage" / "trigger.seed.profraw"

    def run_seed(**kwargs):
        raw_profile.parent.mkdir(parents=True, exist_ok=True)
        raw_profile.write_bytes(b"profile")
        return subprocess.CompletedProcess([], 0, "", "")

    command_count = 0

    def run_command(command):
        nonlocal command_count
        command_count += 1
        if command_count == 1:
            output_path = Path(command[-1])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"profdata")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command_count == 2:
            return subprocess.CompletedProcess(command, 0, "unrelated coverage report\n", "")
        return subprocess.CompletedProcess(
            command,
            0,
            "/src/demo/source.c:\n"
            "   10|      7|    if (value) {\n"
            "   11|      0|        return 1;\n",
            "",
        )

    monkeypatch.setattr(symcc_solver, "run_single_seed", run_seed)
    monkeypatch.setattr(symcc_solver, "run_cmd", run_command)

    evaluate_args = dict(args)
    evaluate_args["seed_path"] = evaluate_args.pop("fidelity_seeds")[0]
    result = symcc_solver.evaluate_seed_with_coverage(**evaluate_args)

    assert result.branch_hit_count == 7
    assert result.blocked_side_hit_count == 0
    assert command_count == 3


def test_missing_branch_line_is_coverage_error(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)
    raw_profile = tmp_path / "coverage" / "trigger.seed.profraw"

    def run_seed(**kwargs):
        raw_profile.parent.mkdir(parents=True, exist_ok=True)
        raw_profile.write_bytes(b"profile")
        return subprocess.CompletedProcess([], 0, "", "")

    command_count = 0

    def run_command(command):
        nonlocal command_count
        command_count += 1
        if command_count == 1:
            output_path = Path(command[-1])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"profdata")
        return subprocess.CompletedProcess(command, 0, "unrelated coverage report\n", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", run_seed)
    monkeypatch.setattr(symcc_solver, "run_cmd", run_command)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args, max_attempts=1)

    assert result["status"] == "unknown"
    assert result["coverage_success"] is False
    assert "did not contain blocker branch line" in result["errors"][0]


def symcc_exploration_args(tmp_path: Path, **overrides) -> SimpleNamespace:
    fuzz_target = tmp_path / "target.c"
    fuzz_target.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }", encoding="utf-8")
    values = {
        "fuzz_target": str(fuzz_target),
        "max_generations": 3,
        "max_total_seeds": 60,
        "max_candidate_evaluations": 200,
        "max_retained_seeds": 60,
        "initial_frontier_cap": 30,
        "wall_clock_budget_sec": 0,
        "target_args": "@@",
        "input_mode": "file",
        "timeout_sec": 1,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_symcc_online_oracle_can_find_tail_output(tmp_path: Path, monkeypatch) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"initial")

    def generate_many_outputs(*, env, **_kwargs):
        output_dir = Path(env["SYMCC_OUTPUT_DIR"])
        for index in range(100):
            (output_dir / f"generated-{index}").write_bytes(f"seed-{index}".encode())
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", generate_many_outputs)

    def evaluate(seed: Path, _timeout: float) -> symcc_solver.CoverageResult:
        solved = seed.read_bytes() == b"seed-99"
        return symcc_solver.CoverageResult(
            seed=seed,
            branch_hit_count_raw="1",
            blocked_side_hit_count_raw="1" if solved else "0",
            branch_hit_count=1,
            blocked_side_hit_count=1 if solved else 0,
            blocked_side_line_reached=solved,
        )

    result = symcc_solver.explore_with_symcc(
        symcc_exploration_args(tmp_path, max_generations=1, max_candidate_evaluations=5),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        evaluate,
    )

    assert result.stop_reason == "blocked_side_reached"
    assert result.solved is not None
    assert result.solved.seed.read_bytes() == b"seed-99"
    assert result.candidate_evaluations == 5


def test_symcc_simple_backend_stdout_model_is_materialized(tmp_path: Path, monkeypatch) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"AAAA")

    def generate_simple_backend_model(**_kwargs):
        stderr = "Found diverging input:\nstdin0 -> #x53\nstdin2 -> #x4d\n\n"
        return subprocess.CompletedProcess([], 0, "", stderr)

    monkeypatch.setattr(symcc_solver, "run_single_seed", generate_simple_backend_model)

    def evaluate(seed: Path, _timeout: float) -> symcc_solver.CoverageResult:
        solved = seed.read_bytes() == b"SAMA"
        return symcc_solver.CoverageResult(
            seed=seed,
            branch_hit_count_raw="1",
            blocked_side_hit_count_raw="1" if solved else "0",
            branch_hit_count=1,
            blocked_side_hit_count=1 if solved else 0,
            blocked_side_line_reached=solved,
        )

    result = symcc_solver.explore_with_symcc(
        symcc_exploration_args(tmp_path, max_generations=1),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        evaluate,
    )

    assert result.stop_reason == "blocked_side_reached"
    assert result.outputs_discovered == 1
    assert result.solved is not None
    assert result.solved.seed.read_bytes() == b"SAMA"


def test_symcc_evaluation_budget_is_fair_across_frontier(tmp_path: Path, monkeypatch) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    for index in range(3):
        (corpus_dir / f"initial-{index}.seed").write_bytes(f"frontier-{index}".encode())

    def generate_outputs(*, seed_path, env, **_kwargs):
        output_dir = Path(env["SYMCC_OUTPUT_DIR"])
        frontier_name = seed_path.read_text(encoding="utf-8")
        for index in range(10):
            (output_dir / f"generated-{index}").write_text(
                f"{frontier_name}:output-{index}", encoding="utf-8"
            )
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", generate_outputs)
    evaluated_by_frontier = {"frontier-0": 0, "frontier-1": 0, "frontier-2": 0}

    def evaluate(seed: Path, _timeout: float) -> symcc_solver.CoverageResult:
        frontier_name = seed.read_text(encoding="utf-8").split(":", 1)[0]
        evaluated_by_frontier[frontier_name] += 1
        return coverage_result(seed, branch_hits=0)

    result = symcc_solver.explore_with_symcc(
        symcc_exploration_args(
            tmp_path,
            max_generations=1,
            max_candidate_evaluations=6,
            initial_frontier_cap=3,
        ),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        evaluate,
    )

    assert result.candidate_evaluations == 6
    assert evaluated_by_frontier == {"frontier-0": 2, "frontier-1": 2, "frontier-2": 2}


def test_symcc_candidate_budget_is_cumulative_across_generations(tmp_path: Path, monkeypatch) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"initial")

    execution = 0

    def generate_outputs(*, env, **_kwargs):
        nonlocal execution
        execution += 1
        output_dir = Path(env["SYMCC_OUTPUT_DIR"])
        for index in range(4):
            (output_dir / f"generated-{index}").write_text(
                f"execution-{execution}:output-{index}", encoding="utf-8"
            )
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", generate_outputs)
    result = symcc_solver.explore_with_symcc(
        symcc_exploration_args(
            tmp_path,
            max_generations=3,
            max_candidate_evaluations=5,
            max_retained_seeds=2,
        ),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        lambda seed, _timeout: coverage_result(seed, branch_hits=1),
    )

    assert result.candidate_evaluations == 5
    assert result.stop_reason == "candidate_eval_budget_exhausted"


def test_symcc_systemic_oracle_failure_is_retryable(tmp_path: Path, monkeypatch) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"initial")

    def generate_output(*, env, **_kwargs):
        output_dir = Path(env["SYMCC_OUTPUT_DIR"])
        (output_dir / "generated").write_bytes(b"candidate")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", generate_output)

    def unavailable(_seed: Path, _timeout: float) -> symcc_solver.CoverageResult:
        raise symcc_solver.CoverageOracleError(
            "llvm_cov_failed",
            "llvm-cov failed",
            systemic=True,
        )

    result = symcc_solver.explore_with_symcc(
        symcc_exploration_args(tmp_path, max_generations=1),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        unavailable,
    )

    assert result.stop_reason == "oracle_unavailable"
    assert result.candidate_evaluations == 1
    assert result.oracle_errors == {"llvm_cov_failed": 1}


def test_libvpx_config_exposes_generated_config_header() -> None:
    """libvpx's headers ``#include "./vpx_config.h"``, which configure generates outside the
    source tree. Five archived blockers died on that one missing include path, so the config
    must keep pointing at ``work/build`` for both the harness and native-archive builds."""
    from blocker_process.dependent.run_symcc_blocker import (
        _resolve_config_path,
        load_project_config,
    )

    config = load_project_config("libvpx")
    resolved = [str(_resolve_config_path(path, "libvpx")) for path in config["extra_include_dirs"]]

    assert any(path.endswith("libvpx/work/build") for path in resolved), resolved
    assert "work/build" in config["native_archive_include_dirs"]


def test_every_seed_gets_the_extended_symcc_budget(tmp_path: Path, monkeypatch) -> None:
    """Seeds must not be capped at the short per-execution timeout.

    Under the old 15s cap, 21 archived cases had *every* seed time out and so discovered zero
    candidates. Reserving the longer budget for seeds already proven productive deadlocked:
    a seed whose first run times out writes nothing, never counts as productive, and never
    earns the time it needed.
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"initial")
    budgets: list[float] = []
    runs = 0

    def record_budget(*, timeout_sec, env, **_kwargs):
        nonlocal runs
        runs += 1
        budgets.append(timeout_sec)
        Path(env["SYMCC_OUTPUT_DIR"], f"generated-{runs}").write_bytes(f"cand{runs}".encode())
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", record_budget)

    symcc_solver.explore_with_symcc(
        symcc_exploration_args(tmp_path, max_generations=2, timeout_sec=1, extended_timeout_sec=90),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        lambda seed, _timeout: coverage_result(seed, branch_hits=0),
    )

    assert budgets, "no SymCC execution was attempted"
    assert all(budget == 90 for budget in budgets), budgets


def test_extended_budget_never_overruns_the_wall_clock(tmp_path: Path, monkeypatch) -> None:
    # Handing every seed the long budget is only safe because bounded_timeout clamps it to
    # whatever wall clock is left; without that, one seed could consume the whole run.
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "initial.seed").write_bytes(b"initial")
    budgets: list[float] = []

    def record_budget(*, timeout_sec, env, **_kwargs):
        budgets.append(timeout_sec)
        Path(env["SYMCC_OUTPUT_DIR"], "generated-0").write_bytes(b"candidate")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(symcc_solver, "run_single_seed", record_budget)

    symcc_solver.explore_with_symcc(
        symcc_exploration_args(
            tmp_path,
            max_generations=1,
            timeout_sec=1,
            extended_timeout_sec=900,
            wall_clock_budget_sec=30,
        ),
        tmp_path / "symcc-binary",
        corpus_dir,
        tmp_path / "generated",
        lambda seed, _timeout: coverage_result(seed, branch_hits=0),
    )

    assert budgets and budgets[0] <= 30, budgets


def test_oss_fuzz_build_defaults_supply_target_name_and_fuzzer_headers() -> None:
    """The SymCC build reconstructs the compile that OSS-Fuzz's build.sh normally performs.

    Every project's build.sh passes ``-D_FUZZ_TARGET_NAME="$target_basename"`` so a harness
    can name its own scratch file, and libFuzzer's headers live outside the project tree.
    Missing both stopped 11 archived libtiff blockers before SymCC ran.
    """
    from blocker_process.dependent.run_symcc_blocker import apply_oss_fuzz_build_defaults

    args = SimpleNamespace(target_name="llm_fuzzgen0717082918", define=[], include_dir=[])

    apply_oss_fuzz_build_defaults(args)

    assert '_FUZZ_TARGET_NAME="llm_fuzzgen0717082918"' in args.define
    assert any(path.endswith("compiler-rt/include/fuzzer") for path in args.include_dir)


def test_oss_fuzz_build_defaults_do_not_override_an_explicit_target_name() -> None:
    from blocker_process.dependent.run_symcc_blocker import apply_oss_fuzz_build_defaults

    args = SimpleNamespace(
        target_name="generated_harness",
        define=['_FUZZ_TARGET_NAME="chosen_by_caller"'],
        include_dir=[],
    )

    apply_oss_fuzz_build_defaults(args)

    assert args.define == ['_FUZZ_TARGET_NAME="chosen_by_caller"']
