from pathlib import Path
import sys
import time
from types import SimpleNamespace

from blocker_process.dependent.input_dependent_seed_generator import (
    build_corpus_manifest,
    build_seed_records,
    classify_iteration_status,
    prepare_isolated_corpus_snapshot,
    validate_generator,
)
from blocker_process.dependent.input_dependent_solver import (
    build_symcc_cmd,
    build_runtime_sanity_seed_args,
    get_symcc_failure_kind,
    resolve_harness_fidelity_seed,
    resolve_seed_generator_triggering_input,
    run_program,
    run_input_dependent_solver,
    seed_generation_exceeded_budget,
    select_bounded_symcc_handoff_seeds,
    symcc_initial_seed_budget,
)
from blocker_process.dependent.run_symcc_blocker import (
    _should_use_symcc_library,
    load_project_config,
)


def test_lcms_symcc_library_is_enabled_for_branch_reaching_seed(tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    config = load_project_config("lcms")

    assert config["symcc_library"] is True
    assert config["symcc_library_filename"] == "liblcms2.a"
    assert _should_use_symcc_library("lcms", config, [str(seed)]) is True


def test_llm_stage_timeout_returns_retryable_llm_error() -> None:
    started_at = time.monotonic()
    result = run_program(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_sec=0.1,
        timeout_failure_kind="llm_timeout",
    )

    assert time.monotonic() - started_at < 3
    assert result["returncode"] == 124
    assert result["timed_out"] is True
    assert result["parsed_output"]["attempt_result"] == "llm_error"
    assert result["parsed_output"]["failure_kind"] == "llm_timeout"
    assert result["parsed_output"]["retryable"] is True


def test_seed_stage_timeout_stops_before_symcc(monkeypatch, tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    target = tmp_path / "target.c"
    seed.write_bytes(b"trigger")
    target.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }", encoding="utf-8")
    args = SimpleNamespace(
        seed=[str(seed)],
        triggering_input=str(seed),
        output_root=str(tmp_path / "output"),
        project_name="demo",
        function_name="blocked_function",
        target_name="demo_fuzzer",
        fuzz_file=str(target),
        source_file=str(target),
        branch_line_number=1,
        blocked_side_line_number=2,
        max_iterations=2,
        fuzz_seconds=1,
        reset_corpus_per_iteration=False,
        log_dir=None,
        llm_seed_stage_timeout_sec=900,
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_context_args",
        lambda _args: [],
    )

    calls = 0

    def timed_out(_cmd, **kwargs):
        nonlocal calls
        calls += 1
        assert kwargs["timeout_sec"] == 900
        return {
            "returncode": 124,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "parsed_output": {
                "success": False,
                "attempt_result": "llm_error",
                "failure_kind": "llm_timeout",
                "retryable": True,
                "message": "LLM generation stage exceeded 900 seconds.",
            },
        }

    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.run_program",
        timed_out,
    )

    result = run_input_dependent_solver(args)

    assert calls == 1
    assert result["failure_stage"] == "llm_seed_generator"
    assert result["attempt_result"] == "llm_error"
    assert result["stages"]["llm_seed_generator"]["retryable"] is True


def test_symcc_command_supports_fidelity_only_preflight(tmp_path: Path) -> None:
    blocker_json = tmp_path / "blocker.json"
    fuzz_target = tmp_path / "harness.c"
    seed = tmp_path / "trigger.seed"
    blocker_json.write_text("{}", encoding="utf-8")
    fuzz_target.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }", encoding="utf-8")
    seed.write_bytes(b"trigger")
    args = SimpleNamespace(
        project_name="demo",
        source_api_file=None,
        source_file=str(fuzz_target),
        branch_line_number=1,
        blocked_side_line_number=2,
        symcc_max_generations=1,
        symcc_max_total_seeds=10,
        symcc_timeout_sec=5,
        symcc_wall_clock_budget_sec=0,
        keep_coverage_reports=False,
        llvm_profdata=None,
        llvm_cov=None,
    )

    cmd = build_symcc_cmd(
        args=args,
        blocker_json_path=blocker_json,
        work_dir=tmp_path / "work",
        seeds=[str(seed)],
        fuzz_target=str(fuzz_target),
        target_name="demo_fuzzer",
        json_output_path=tmp_path / "summary.json",
        fidelity_seed=str(seed),
        fidelity_only=True,
    )

    assert "--fidelity-only" in cmd
    assert cmd[cmd.index("--fidelity-seed") + 1] == str(seed.resolve())


def test_incompatible_fidelity_preflight_replans_before_focused_fuzzing(
    monkeypatch, tmp_path: Path
) -> None:
    seed = tmp_path / "trigger.seed"
    fuzz_target = tmp_path / "target.c"
    seed.write_bytes(b"trigger")
    fuzz_target.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }", encoding="utf-8")
    args = SimpleNamespace(
        seed=[str(seed)],
        triggering_input=str(seed),
        output_root=str(tmp_path / "output"),
        project_name="demo",
        function_name="blocked_function",
        target_name="demo_fuzzer",
        fuzz_file=str(fuzz_target),
        source_file=str(fuzz_target),
        source_api_file=None,
        branch_line_number=1,
        blocked_side_line_number=2,
        max_iterations=1,
        fuzz_seconds=1,
        reset_corpus_per_iteration=False,
        log_dir=None,
        symcc_max_total_seeds=10,
        libfuzzer_pass_seconds=60,
    )
    calls: list[str] = []
    harness_attempt = 0

    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_context_args",
        lambda _args: [],
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_runtime_sanity_seed_args",
        lambda _seeds: [],
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_symcc_cmd",
        lambda **kwargs: ["symcc", "preflight" if kwargs.get("fidelity_only") else "full"],
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.quarantine_unsolved_generated_harness",
        lambda **_kwargs: {"quarantined": True},
    )

    def fail_if_focused(**_kwargs):
        raise AssertionError("focused fuzzing must not run before fidelity preflight passes")

    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.run_libfuzzer_focused_pass",
        fail_if_focused,
    )

    def fake_run_program(cmd, **_kwargs):
        nonlocal harness_attempt
        if "input_dependent_seed_generator.py" in str(cmd[1]):
            calls.append("seed_generator")
            return {"returncode": 1, "stdout": "", "stderr": "", "parsed_output": {"success": False}}
        if cmd == ["symcc", "full"]:
            calls.append("symcc_probe")
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": "",
                "parsed_output": {"success": False, "symcc": {"failure_kind": "coverage_no_blocked_side"}},
            }
        if "input_dependent_harness_generator.py" in str(cmd[1]):
            harness_attempt += 1
            calls.append(f"harness_generation_{harness_attempt}")
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "parsed_output": {
                    "success": True,
                    "native_build_target_name": f"generated_{harness_attempt}",
                    "harness_path": str(tmp_path / f"harness_{harness_attempt}.c"),
                },
            }
        if cmd == ["symcc", "preflight"]:
            calls.append(f"fidelity_preflight_{harness_attempt}")
            return {
                "returncode": 4,
                "stdout": "",
                "stderr": "",
                "parsed_output": {
                    "success": False,
                    "failure_kind": "harness_seed_incompatible",
                    "harness_fidelity": {"status": "incompatible"},
                },
            }
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.run_program",
        fake_run_program,
    )

    result = run_input_dependent_solver(args)

    assert calls == [
        "seed_generator",
        "symcc_probe",
        "harness_generation_1",
        "fidelity_preflight_1",
        "harness_generation_2",
        "fidelity_preflight_2",
    ]
    assert result["failure_stage"] == "symcc_harness_fidelity_preflight_replan_02"


def test_isolated_snapshot_contains_only_explicit_deduplicated_seeds(tmp_path: Path) -> None:
    formal_corpus = tmp_path / "formal"
    formal_corpus.mkdir()
    (formal_corpus / "historical_seed").write_bytes(b"historical")
    formal_before = build_corpus_manifest(formal_corpus)

    sources = tmp_path / "sources"
    sources.mkdir()
    trigger = sources / "trigger.bin"
    generated = sources / "F01_setter_then_caller_01.bin"
    duplicate = sources / "F02_duplicate_01.bin"
    trigger.write_bytes(b"trigger")
    generated.write_bytes(b"generated")
    duplicate.write_bytes(b"generated")

    records = build_seed_records([trigger], "triggering") + build_seed_records(
        [generated, duplicate], "generated"
    )
    snapshot = tmp_path / "isolated"
    isolated_records, metadata = prepare_isolated_corpus_snapshot(snapshot, records)

    assert metadata["copied_seed_count"] == 2
    assert metadata["duplicate_seed_count"] == 1
    assert len(list(snapshot.iterdir())) == 2
    assert {record["source_kind"] for record in isolated_records} == {"triggering", "generated"}
    assert build_corpus_manifest(formal_corpus) == formal_before


def test_isolated_evaluation_path_can_be_deleted_without_losing_persistent_seed(tmp_path: Path) -> None:
    generated = tmp_path / "F01_setter_then_caller_01.txt"
    generated.write_text("setter caller", encoding="utf-8")
    records = build_seed_records([generated], "generated")
    snapshot = tmp_path / "representative_iter_01"
    isolated_records, _ = prepare_isolated_corpus_snapshot(snapshot, records)

    persistent_path = Path(isolated_records[0]["source_path"])
    evaluation_path = Path(isolated_records[0]["evaluation_seed_path"])
    assert persistent_path.is_file()
    assert evaluation_path.is_file()

    for path in snapshot.iterdir():
        path.unlink()
    snapshot.rmdir()

    assert persistent_path.is_file()
    assert not evaluation_path.exists()


def test_representative_success_is_not_negated_by_aggregate_failure() -> None:
    status, reason = classify_iteration_status(
        validation_ok=True,
        generated_seed_count=2,
        baseline_evaluation={
            "success": True,
            "blocked_side_line_reached": False,
        },
        post_merge_evaluation={
            "success": False,
            "error": "aggregate timeout",
        },
        coverage_delta={
            "success": False,
            "coverage_novelty_success": False,
        },
        representative_results=[
            {
                "success": True,
                "branch_reached": True,
                "blocked_side_reached": True,
            }
        ],
        family_summary={},
        previous_family_signal_score=0,
    )

    assert status == "solved"
    assert "representative" in reason.lower()


def test_baseline_already_covered_precedes_representative_success() -> None:
    status, _ = classify_iteration_status(
        validation_ok=True,
        generated_seed_count=1,
        baseline_evaluation={
            "success": True,
            "blocked_side_line_reached": True,
        },
        post_merge_evaluation={"success": True},
        coverage_delta={},
        representative_results=[{"success": True, "blocked_side_reached": True}],
        family_summary={},
        previous_family_signal_score=0,
    )

    assert status == "already_covered_in_baseline"


def test_solver_seed_falls_back_to_generator_triggering_input(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    seed.write_bytes(b"input")
    args = SimpleNamespace(triggering_input="")

    assert resolve_seed_generator_triggering_input(args, [str(seed)]) == str(seed)


def test_runtime_sanity_seed_args_forward_only_existing_files(tmp_path: Path) -> None:
    first = tmp_path / "first.seed"
    second = tmp_path / "second.seed"
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    assert build_runtime_sanity_seed_args([str(first), str(tmp_path / "missing"), str(second)]) == [
        "--runtime-sanity-seed",
        str(first.resolve()),
        "--runtime-sanity-seed",
        str(second.resolve()),
    ]


def test_harness_fidelity_prefers_existing_triggering_input(tmp_path: Path) -> None:
    trigger = tmp_path / "trigger.seed"
    fallback = tmp_path / "fallback.seed"
    trigger.write_bytes(b"trigger")
    fallback.write_bytes(b"fallback")
    args = SimpleNamespace(triggering_input=str(trigger))

    assert resolve_harness_fidelity_seed(args, [str(fallback)]) == str(trigger.resolve())


def test_harness_fidelity_falls_back_to_existing_seed(tmp_path: Path) -> None:
    fallback = tmp_path / "fallback.seed"
    fallback.write_bytes(b"fallback")
    args = SimpleNamespace(triggering_input="inline input that is not a path")

    assert resolve_harness_fidelity_seed(args, [str(fallback)]) == str(fallback.resolve())


def test_symcc_failure_kind_reads_nested_summary() -> None:
    assert get_symcc_failure_kind({"symcc": {"failure_kind": "harness_seed_incompatible"}}) == (
        "harness_seed_incompatible"
    )


def test_symcc_failure_kind_reads_fidelity_preflight_summary() -> None:
    assert get_symcc_failure_kind(
        {"fidelity_preflight": {"failure_kind": "harness_seed_incompatible"}}
    ) == "harness_seed_incompatible"


def test_bounded_symcc_handoff_prioritizes_original_seeds_and_deduplicates(tmp_path: Path) -> None:
    trigger = tmp_path / "trigger.seed"
    trigger.write_bytes(b"trigger")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "duplicate.seed").write_bytes(b"trigger")
    (corpus / "small.seed").write_bytes(b"a")
    (corpus / "medium.seed").write_bytes(b"bb")
    (corpus / "large.seed").write_bytes(b"ccc")

    selected, metadata = select_bounded_symcc_handoff_seeds(
        priority_seeds=[str(trigger)],
        corpus_dir=corpus,
        max_total_seeds=3,
    )

    assert selected[0] == str(trigger.resolve())
    assert [Path(path).read_bytes() for path in selected] == [b"trigger", b"a", b"bb"]
    assert metadata == {
        "max_total_seeds": 3,
        "candidate_count": 5,
        "selected_count": 3,
        "duplicate_count": 1,
        "dropped_count": 1,
    }


def test_symcc_initial_seed_budget_uses_independent_frontier_cap() -> None:
    assert symcc_initial_seed_budget(60) == 30
    assert symcc_initial_seed_budget(3) == 3
    assert symcc_initial_seed_budget(60, initial_frontier_cap=12) == 12
    assert symcc_initial_seed_budget(1) == 1


def test_prompt_contains_generic_ordering_and_representation_contract() -> None:
    template = Path("prompts/templates/blocker_seed_generator_template").read_text(encoding="utf-8")

    assert "setter_then_caller" in template
    assert "caller_then_setter" in template
    assert "fixed-offset or" in template
    assert "recompute" in template
    assert "source-supported representation category" in template


def test_validate_generator_rejects_oversized_materialized_seeds(tmp_path: Path) -> None:
    generator = tmp_path / "generator.py"
    generator.write_text(
        """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)
(out / "small.bin").write_bytes(b"small")
(out / "large.bin").write_bytes(b"L" * 32)
print("done")
""".strip(),
        encoding="utf-8",
    )

    result = validate_generator(
        generator,
        tmp_path,
        max_seed_size_bytes=8,
        timeout_seconds=5,
    )

    generated_dir = Path(result["generated_dir"])
    rejected_dir = tmp_path / "materialized_by_generator_oversized_rejected"
    assert result["ok"] is True
    assert result["valid_seed_count"] == 1
    assert result["oversized_seed_count"] == 1
    assert (generated_dir / "small.bin").is_file()
    assert not (generated_dir / "large.bin").exists()
    assert (rejected_dir / "large.bin").is_file()


def test_validate_generator_fails_when_all_generated_seeds_are_oversized(tmp_path: Path) -> None:
    generator = tmp_path / "generator.py"
    generator.write_text(
        """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)
(out / "large.bin").write_bytes(b"L" * 32)
print("done")
""".strip(),
        encoding="utf-8",
    )

    result = validate_generator(
        generator,
        tmp_path,
        max_seed_size_bytes=8,
        timeout_seconds=5,
    )

    assert result["ok"] is False
    assert result["error_kind"] == "all_generated_seeds_oversized"
    assert result["valid_seed_count"] == 0
    assert result["oversized_seed_count"] == 1


def test_validate_generator_times_out_without_valid_seed(tmp_path: Path) -> None:
    generator = tmp_path / "generator.py"
    generator.write_text(
        """
import argparse
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
Path(args.output_dir).mkdir(parents=True, exist_ok=True)
time.sleep(5)
""".strip(),
        encoding="utf-8",
    )

    result = validate_generator(
        generator,
        tmp_path,
        max_seed_size_bytes=8,
        timeout_seconds=0.2,
    )

    assert result["ok"] is False
    assert result["error_kind"] == "generator_timeout_no_valid_seeds"
    assert result["generator_timed_out"] is True


def test_solver_skips_symcc_when_seed_generation_exceeds_budget() -> None:
    assert seed_generation_exceeded_budget({"generator_terminal_reason": "seed_budget_exceeded"})
    assert not seed_generation_exceeded_budget({"generator_terminal_reason": "stalled_at_branch"})
