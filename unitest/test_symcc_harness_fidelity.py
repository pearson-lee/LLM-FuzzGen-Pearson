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
