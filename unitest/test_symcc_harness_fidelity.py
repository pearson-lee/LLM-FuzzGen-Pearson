from pathlib import Path

import blocker_process.dependent.symcc_blocker_solver as symcc_solver


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
