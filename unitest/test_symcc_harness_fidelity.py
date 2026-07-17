from pathlib import Path
import subprocess
from types import SimpleNamespace

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


def fidelity_args(tmp_path: Path) -> dict:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
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
        "fidelity_seed": seed,
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
        lambda **kwargs: coverage_result(args["fidelity_seed"], branch_hits=3),
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
        return coverage_result(args["fidelity_seed"], branch_hits=0)

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", evaluate)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "incompatible"
    assert result["coverage_success"] is True
    assert result["attempt_count"] == 2
    assert result["errors"] == ["missing profraw"]


def test_fidelity_is_unknown_only_after_coverage_retry_fails(tmp_path: Path, monkeypatch) -> None:
    args = fidelity_args(tmp_path)

    def fail(**kwargs):
        raise RuntimeError("llvm-profdata failed")

    monkeypatch.setattr(symcc_solver, "evaluate_seed_with_coverage", fail)

    result = symcc_solver.evaluate_generated_harness_fidelity(**args)

    assert result["status"] == "unknown"
    assert result["coverage_success"] is False
    assert result["attempt_count"] == 2
    assert result["errors"] == ["llvm-profdata failed", "llvm-profdata failed"]


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
    evaluate_args["seed_path"] = evaluate_args.pop("fidelity_seed")
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
