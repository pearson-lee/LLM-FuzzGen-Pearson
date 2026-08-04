from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from blocker_process.dependent.format_inference import FormatInfo
from blocker_process.dependent.input_dependent_seed_generator import (
    MUTATION_EDIT_DISTANCE_MAX_BYTES,
    MUTATION_MAX_CHANGED_BYTES,
    MUTATION_MAX_CHANGED_RATIO,
    MUTATION_MIN_CHANGED_BYTES,
    build_corpus_manifest,
    build_generator_fix_prompt,
    build_seed_records,
    classify_iteration_status,
    diagnose_iteration,
    compute_coverage_delta,
    empty_baseline_evaluation,
    measure_mutation_distance,
    prepare_isolated_corpus_snapshot,
    prepare_mutation_base_seed,
    EVALUATION_FAILED_HANDOFF_SEEDS,
    deterministic_stratified_seed_sample,
    resolve_generation_mode,
    select_best_symcc_candidates,
    select_diverse_handoff_records,
    select_recommended_symcc_generator_seeds,
    template_path_for_generation_mode,
    validate_generator,
)
from blocker_process.dependent.input_dependent_solver import (
    build_symcc_cmd,
    build_runtime_sanity_seed_args,
    choose_symcc_seed_inputs,
    collect_successful_llm_seed_records,
    get_symcc_failure_kind,
    persist_successful_llm_seeds_to_corpus,
    MAX_HARNESS_FIDELITY_SEEDS,
    resolve_harness_fidelity_seeds,
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


def test_cjson_symcc_library_is_enabled_for_branch_reaching_seed(tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    config = load_project_config("cjson")

    assert config["symcc_library"] is True
    assert config["symcc_library_filename"] == "libcjson.a"
    assert _should_use_symcc_library("cjson", config, [str(seed)]) is True


def test_libvpx_symcc_library_is_enabled_for_branch_reaching_seed(tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    config = load_project_config("libvpx")

    assert config["symcc_library"] is True
    assert config["symcc_library_filename"] == "libvpx.a"
    assert _should_use_symcc_library("libvpx", config, [str(seed)]) is True


def test_zlib_symcc_library_is_enabled_for_branch_reaching_seed(tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    config = load_project_config("zlib")

    assert config["symcc_library"] is True
    assert config["symcc_library_filename"] == "libz.a"
    assert _should_use_symcc_library("zlib", config, [str(seed)]) is True


def test_libtiff_symcc_library_is_enabled_for_branch_reaching_seed(tmp_path: Path) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    config = load_project_config("libtiff")

    assert config["symcc_library"] is True
    assert config["symcc_library_filename"] == "libtiff_combined.a"
    assert _should_use_symcc_library("libtiff", config, [str(seed)]) is True


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


def test_seed_stage_timeout_falls_back_to_symcc(monkeypatch, tmp_path: Path) -> None:
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
        symcc_max_total_seeds=10,
        symcc_max_candidate_evaluations=20,
        symcc_max_retained_seeds=10,
        symcc_initial_frontier_cap=5,
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_context_args",
        lambda _args: [],
    )
    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.build_symcc_cmd",
        lambda **_kwargs: ["symcc_probe"],
    )

    calls: list[str] = []

    def timed_out_then_symcc(cmd, **kwargs):
        if cmd == ["symcc_probe"]:
            calls.append("symcc_probe")
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "parsed_output": {"success": True},
            }
        calls.append("seed_generator")
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
        timed_out_then_symcc,
    )

    result = run_input_dependent_solver(args)

    assert calls == ["seed_generator", "symcc_probe"]
    assert result["success"] is True
    assert result["success_stage"] == "symcc_probe_original_target"
    assert result["attempt_result"] == "success"
    assert result["llm_seed_timeout_fallback_to_symcc"] is True
    assert result["stages"]["llm_seed_generator"]["retryable"] is True


def test_collect_successful_llm_seed_records_only_keeps_blocked_side_hits(tmp_path: Path) -> None:
    winner = tmp_path / "winner.seed"
    loser = tmp_path / "loser.seed"
    winner.write_bytes(b"blocked")
    loser.write_bytes(b"branch-only")
    parsed = {
        "best_iteration": {
            "representative_results": [
                {
                    "seed_path": str(loser),
                    "family": "branch",
                    "branch_hit_count": 5,
                    "blocked_side_hit_count": 0,
                    "blocked_side_reached": False,
                },
                {
                    "seed_path": str(winner),
                    "family": "blocked",
                    "branch_hit_count": 5,
                    "blocked_side_hit_count": 3,
                    "blocked_side_reached": True,
                },
            ]
        }
    }

    records = collect_successful_llm_seed_records(parsed, max_records=5)

    assert len(records) == 1
    assert records[0]["source_path"] == str(winner.resolve())
    assert records[0]["blocked_side_hit_count"] == 3


def test_persist_successful_llm_seeds_to_target_corpus(monkeypatch, tmp_path: Path) -> None:
    seed = tmp_path / "winner.seed"
    seed.write_bytes(b"blocked")
    corpus_root = tmp_path / "corpus"

    class FakeOSSFuzz:
        def __init__(self) -> None:
            self.build_corpus_dir = corpus_root

    monkeypatch.setattr(
        "blocker_process.dependent.input_dependent_solver.OSSFuzz",
        FakeOSSFuzz,
    )
    args = SimpleNamespace(
        project_name="demo",
        target_name="demo_fuzzer",
        fuzz_file=str(tmp_path / "demo_fuzzer.c"),
        function_name="BlockedFunction",
        branch_line_number=42,
        max_seed_size_bytes=None,
    )
    parsed = {
        "best_iteration": {
            "representative_results": [
                {
                    "seed_path": str(seed),
                    "family": "blocked",
                    "branch_hit_count": 7,
                    "blocked_side_hit_count": 2,
                    "blocked_side_reached": True,
                }
            ]
        }
    }

    persistence = persist_successful_llm_seeds_to_corpus(args, parsed, max_seeds=5)

    assert persistence["persisted_count"] == 1
    persisted_path = Path(persistence["persisted_seed_paths"][0])
    assert persisted_path.parent == corpus_root / "demo" / "demo_fuzzer"
    assert persisted_path.read_bytes() == b"blocked"


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
        fidelity_seeds=[str(seed)],
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

    assert resolve_harness_fidelity_seeds(args, [str(fallback)])[0] == str(trigger.resolve())


def test_harness_fidelity_falls_back_to_existing_seed(tmp_path: Path) -> None:
    fallback = tmp_path / "fallback.seed"
    fallback.write_bytes(b"fallback")
    args = SimpleNamespace(triggering_input="inline input that is not a path")

    assert resolve_harness_fidelity_seeds(args, [str(fallback)]) == [str(fallback.resolve())]


def test_harness_fidelity_offers_every_branch_reaching_seed(tmp_path: Path) -> None:
    # A generated harness may consume bytes differently from the original target, so one
    # seed missing the branch must not end the case: all of them get offered.
    trigger = tmp_path / "trigger.seed"
    others = [tmp_path / f"seed_{index}.bin" for index in range(3)]
    trigger.write_bytes(b"trigger")
    for path in others:
        path.write_bytes(path.name.encode())
    args = SimpleNamespace(triggering_input=str(trigger))

    resolved = resolve_harness_fidelity_seeds(args, [str(p) for p in others])

    assert resolved[0] == str(trigger.resolve())
    assert resolved[1:] == [str(p.resolve()) for p in others]


def test_harness_fidelity_seeds_deduplicate_and_cap(tmp_path: Path) -> None:
    # Each extra seed costs a coverage replay, and the trigger usually also appears in the
    # seed list, so duplicates must not consume the budget.
    trigger = tmp_path / "trigger.seed"
    trigger.write_bytes(b"trigger")
    extras = [tmp_path / f"seed_{index}.bin" for index in range(MAX_HARNESS_FIDELITY_SEEDS + 4)]
    for path in extras:
        path.write_bytes(path.name.encode())
    args = SimpleNamespace(triggering_input=str(trigger))

    resolved = resolve_harness_fidelity_seeds(args, [str(trigger), *[str(p) for p in extras]])

    assert len(resolved) == MAX_HARNESS_FIDELITY_SEEDS
    assert len(set(resolved)) == len(resolved)


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


def test_symcc_handoff_uses_llm_branch_reaching_seeds_before_original_seeds(tmp_path: Path) -> None:
    original_a = tmp_path / "original_a.seed"
    original_b = tmp_path / "original_b.seed"
    llm_seed = tmp_path / "llm_branch.seed"
    original_a.write_bytes(b"original-a")
    original_b.write_bytes(b"original-b")
    llm_seed.write_bytes(b"llm-branch")

    candidate_seeds, metadata = choose_symcc_seed_inputs(
        fallback_seeds=[str(original_a), str(original_b)],
        parsed_llm_seed={
            "generator_terminal_reason": "stalled_at_branch",
            "recommended_symcc_generator_seed_paths": [str(llm_seed)],
            "recommended_symcc_selection_reason": "branch-reaching representative",
        },
    )
    selected, _ = select_bounded_symcc_handoff_seeds(
        priority_seeds=candidate_seeds,
        corpus_dir=None,
        max_total_seeds=2,
    )

    assert metadata["recommended_generator_seed_paths"] == [str(llm_seed.resolve())]
    assert [Path(path).read_bytes() for path in selected] == [b"llm-branch", b"original-a"]


def test_symcc_candidate_selection_uses_archive_family_and_seed_caps(tmp_path: Path) -> None:
    representative_results = []
    ranked_families = []
    for index in range(1, 6):
        family = f"F0{index}_branch"
        seed = tmp_path / f"{family}_01.seed"
        seed.write_bytes(f"seed-{index}".encode())
        ranked_families.append(
            {
                "family": family,
                "branch_reached_count": 1,
                "blocked_side_reached_count": 0,
                "max_branch_hit_count": 10 - index,
                "branch_reach_ratio": 1.0,
            }
        )
        representative_results.append(
            {
                "family": family,
                "seed_path": str(seed),
                "branch_hit_count": 10 - index,
                "blocked_side_hit_count": 0,
                "branch_reached": True,
                "blocked_side_reached": False,
            }
        )

    bundle = select_best_symcc_candidates(
        {"ranked_families": ranked_families},
        representative_results,
    )
    recommended = select_recommended_symcc_generator_seeds(
        generator_terminal_reason="stalled_at_branch",
        symcc_candidate_bundle=bundle,
        triggering_input_evaluation={"success": True, "branch_hit_count": 99, "seed_size_bytes": 1},
    )

    assert bundle["top_families"] == [
        "F01_branch",
        "F02_branch",
    ]
    assert len(bundle["candidate_seed_paths"]) == 2
    assert len(recommended["recommended_generator_seed_paths"]) == 2


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


MUTATION_GENERATOR_SOURCE = """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
parser.add_argument("--base-seed", required=True)
args = parser.parse_args()

base = Path(args.base_seed).read_bytes()
out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)

start = base.index(b'"depth":') + len(b'"depth":')
end = start
while end < len(base) and base[end:end + 1].isdigit():
    end += 1

# Local edits of the blocker-controlled field, including ones that change its width.
for index, value in enumerate((0, 127, 65535), start=1):
    (out / f"F01_depth_boundary_{index:02d}.json").write_bytes(
        base[:start] + str(value).encode() + base[end:]
    )

# A mid-seed insertion, which shifts every trailing byte.
anchor = base.rindex(b"}")
(out / "F02_member_insert_01.json").write_bytes(base[:anchor] + b',"n":1' + base[anchor:])

# Control cases the gate must reject.
(out / "F03_identical_01.json").write_bytes(base)
(out / "F03_unrelated_01.json").write_bytes(b'{"unrelated":"' + b"x" * 800 + b'"}')
print("done")
""".strip()


def _write_mutation_fixture(tmp_path: Path) -> tuple[Path, Path]:
    generator = tmp_path / "generator.py"
    generator.write_text(MUTATION_GENERATOR_SOURCE, encoding="utf-8")
    base_seed = tmp_path / "base_seed.json"
    base_seed.write_bytes(b'{"name":"demo","depth":3,"flags":[1,2,3],"pad":"' + b"y" * 200 + b'"}')
    return generator, base_seed


def test_mutation_mode_uses_its_own_template_that_documents_the_base_seed_interface() -> None:
    mutation_template = template_path_for_generation_mode("mutation")
    fresh_template = template_path_for_generation_mode("fresh")

    assert mutation_template != fresh_template
    assert mutation_template.is_file(), f"missing template: {mutation_template}"

    text = mutation_template.read_text(encoding="utf-8")
    assert "--base-seed" in text
    assert "build_seeds(base_seed: bytes)" in text
    # The same blocker contract the fresh template enforces must survive in mutation mode.
    assert "setter_then_caller" in text
    assert "caller_then_setter" in text
    assert "source-supported representation category" in text


def test_repair_prompt_keeps_base_seed_option_in_mutation_mode() -> None:
    kwargs = {
        "base_prompt": "BASE",
        "validation_kind": "runtime_failed",
        "validation_output": "boom",
        "previous_generator_code": "print(1)",
        "previous_rationale": "rationale",
        "fix_attempt_index": 1,
        "max_fix_attempts": 2,
    }

    # The validator always re-runs the script with --base-seed, so a repair prompt that tells
    # the model to keep only `--output-dir DIR` makes every later attempt fail on argparse.
    mutation_prompt = build_generator_fix_prompt(**kwargs, generation_mode="mutation")
    assert "--output-dir DIR --base-seed PATH" in mutation_prompt
    assert "never remove it" in mutation_prompt

    fresh_prompt = build_generator_fix_prompt(**kwargs)
    assert "--base-seed" not in fresh_prompt
    assert "--output-dir DIR" in fresh_prompt


def test_replay_flag_recovery_covers_every_flag_each_stage_accepts() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "replay_blocker_seed_generation", "scripts/replay_blocker_seed_generation.py"
    )
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)

    # run.log records the dispatch as a plain space-join, so argument boundaries are only
    # recoverable from the exact flag set. A flag missing from the list does not error --
    # it gets silently swallowed into the previous argument's value.
    for stage, spec_entry in replay.STAGES.items():
        declared = set(replay.accepted_flags(spec_entry["script"]))
        assert declared, f"{stage}: no flags recovered from {spec_entry['script']}"
        assert set(spec_entry["flags"]) == declared, f"{stage}: flag list drifted"

    assert "--seed-generation-mode" in replay.STAGES["seedgen"]["flags"]
    assert "--llm-seed-stage-timeout-sec" in replay.STAGES["solver"]["flags"]
    assert "--symcc-max-candidate-evaluations" in replay.STAGES["solver"]["flags"]


def test_generation_mode_defaults_to_fresh_even_when_a_trigger_exists(tmp_path: Path) -> None:
    trigger = tmp_path / "trigger.json"
    trigger.write_bytes(b'{"depth":3}')

    # Nearly every real blocker ships with a replayable trigger, so inferring the mode
    # would silently put every run in mutation mode and make the two arms incomparable.
    mode, base_seed, reason = resolve_generation_mode(
        "fresh", str(trigger), FormatInfo(), tmp_path / "fresh"
    )
    assert (mode, base_seed) == ("fresh", None)
    assert reason

    mode, base_seed, _ = resolve_generation_mode(
        "mutation", str(trigger), FormatInfo(), tmp_path / "mutation"
    )
    assert mode == "mutation"
    assert base_seed is not None and base_seed.read_bytes() == trigger.read_bytes()

    mode, base_seed, _ = resolve_generation_mode(
        "auto", str(trigger), FormatInfo(), tmp_path / "auto_with_trigger"
    )
    assert mode == "mutation" and base_seed is not None

    mode, base_seed, reason = resolve_generation_mode(
        "auto", "", FormatInfo(), tmp_path / "auto_no_trigger"
    )
    assert (mode, base_seed) == ("fresh", None)
    assert "fresh" in reason.lower()


def test_explicit_mutation_mode_fails_loudly_without_a_base_seed(tmp_path: Path) -> None:
    # Silently degrading to fresh would mislabel the run's arm in the results.
    with pytest.raises(ValueError, match="no usable base seed"):
        resolve_generation_mode("mutation", "", FormatInfo(), tmp_path / "out")

    with pytest.raises(ValueError, match="Unsupported seed generation mode"):
        resolve_generation_mode("hybrid", "", FormatInfo(), tmp_path / "out")


def test_mutation_base_seed_is_only_prepared_when_a_trigger_is_replayable(tmp_path: Path) -> None:
    trigger = tmp_path / "trigger.json"
    trigger.write_bytes(b'{"depth":3}')
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")

    seed, reason = prepare_mutation_base_seed(str(trigger), FormatInfo(), tmp_path / "with_trigger")
    assert seed is not None
    assert seed.read_bytes() == trigger.read_bytes()
    assert reason

    no_seed, no_reason = prepare_mutation_base_seed("", FormatInfo(), tmp_path / "no_trigger")
    assert no_seed is None
    assert no_reason

    empty_seed, empty_reason = prepare_mutation_base_seed(
        str(empty), FormatInfo(), tmp_path / "empty_trigger"
    )
    assert empty_seed is None
    assert "empty" in empty_reason.lower()


def test_mutation_distance_prices_insertions_as_local_edits() -> None:
    base = b'{"records":[' + b",".join(b'{"id":%d}' % i for i in range(60)) + b"]}"
    anchor = base.rindex(b"]")

    # Positional comparison would score each of these as a rewrite of everything that follows.
    assert measure_mutation_distance(base, base[:20] + b"9" + base[21:]) == 1
    assert measure_mutation_distance(base, base[:anchor] + b',{"id":999}' + base[anchor:]) == 11
    assert measure_mutation_distance(base, base[:anchor - 9] + base[anchor:]) == 9
    assert measure_mutation_distance(base, base + b"    ") == 4
    assert measure_mutation_distance(base, base) == 0

    # A wholesale replacement must still score far above any local-edit budget.
    unrelated = bytes((byte + 7) % 256 for byte in base)
    assert measure_mutation_distance(base, unrelated) > len(base) // 2


def test_mutation_distance_stays_exact_and_cheap_on_large_seeds() -> None:
    # Seeds near MAX_SEED_SIZE_BYTES are normal, and the gate runs on every candidate, so the
    # common prefix/suffix must be trimmed before the quadratic diff runs.
    base = bytes(range(256)) * 256
    local_edit = base[:30000] + b"\xff\xff" + base[30000:]
    assert measure_mutation_distance(base, local_edit) == 2

    # A changed region past the cap skips the quadratic path but still scores as a rewrite.
    churned = bytes((byte + 3) % 256 for byte in base)
    budget = min(
        MUTATION_MAX_CHANGED_BYTES,
        max(MUTATION_MIN_CHANGED_BYTES, int(len(base) * MUTATION_MAX_CHANGED_RATIO)),
    )
    assert len(base) > MUTATION_EDIT_DISTANCE_MAX_BYTES
    assert measure_mutation_distance(base, churned) > budget


def test_validate_generator_keeps_bounded_derivatives_and_rejects_the_rest(tmp_path: Path) -> None:
    generator, base_seed = _write_mutation_fixture(tmp_path)

    result = validate_generator(
        generator,
        tmp_path,
        base_seed_path=base_seed,
        require_mutation=True,
        timeout_seconds=30,
    )

    assert result["ok"] is True
    assert result["mutation_candidate_count"] == 6
    retained = {Path(item["seed_path"]).name for item in result["mutation_retained_records"]}
    rejected = {
        Path(item["source_path"]).name: item["reason"]
        for item in result["mutation_rejected_records"]
    }

    # Field edits that change the field's width, and a mid-seed insertion, are all local.
    assert retained == {
        "F01_depth_boundary_01.json",
        "F01_depth_boundary_02.json",
        "F01_depth_boundary_03.json",
        "F02_member_insert_01.json",
    }
    assert rejected["F03_identical_01.json"] == "unchanged_base_seed"
    assert rejected["F03_unrelated_01.json"] == "mutation_exceeds_local_change_budget"

    generated_dir = Path(result["generated_dir"])
    assert not (generated_dir / "F03_identical_01.json").exists()
    assert Path(result["mutation_rejected_dir"], "F03_identical_01.json").is_file()
    assert result["valid_seed_count"] == len(retained)


def test_validate_generator_reports_when_every_candidate_fails_the_mutation_gate(
    tmp_path: Path,
) -> None:
    generator = tmp_path / "generator.py"
    generator.write_text(
        """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
parser.add_argument("--base-seed", required=True)
args = parser.parse_args()
out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)
(out / "fresh.json").write_bytes(b'{"nothing":"to do with the base seed"}')
print("done")
""".strip(),
        encoding="utf-8",
    )
    base_seed = tmp_path / "base_seed.json"
    base_seed.write_bytes(b'{"name":"demo","depth":3}')

    result = validate_generator(
        generator,
        tmp_path,
        base_seed_path=base_seed,
        require_mutation=True,
        timeout_seconds=30,
    )

    assert result["ok"] is False
    assert result["error_kind"] == "no_valid_mutation_output"
    assert result["mutation_retained_count"] == 0


def test_validate_generator_requires_a_base_seed_in_mutation_mode(tmp_path: Path) -> None:
    generator, _ = _write_mutation_fixture(tmp_path)

    result = validate_generator(
        generator,
        tmp_path,
        base_seed_path=tmp_path / "does_not_exist.json",
        require_mutation=True,
        timeout_seconds=30,
    )

    assert result["ok"] is False
    assert result["error_kind"] == "mutation_base_seed_missing"


def test_missing_trigger_still_yields_a_usable_coverage_delta() -> None:
    # Replaying an empty corpus exits non-zero, which used to sink the entire focused
    # evaluation into its except handler and leave every trigger-less iteration reporting
    # evaluation_failed with no coverage signal for the next prompt.
    baseline = empty_baseline_evaluation()
    assert baseline["success"] is True
    assert baseline["branch_hit_count"] == 0
    assert baseline["blocked_side_line_reached"] is False

    post_merge = {
        "success": True,
        "branch_hit_count": 7,
        "blocked_side_hit_count": 0,
        "branch_line_reached": True,
        "blocked_side_line_reached": False,
    }
    delta = compute_coverage_delta(baseline, post_merge)

    assert delta["success"] is True
    assert delta["branch_hit_count_delta"] == 7
    assert delta["newly_reached_branch_line"] is True
    assert delta["newly_reached_blocked_side_line"] is False

    status, _ = classify_iteration_status(
        validation_ok=True,
        generated_seed_count=5,
        baseline_evaluation=baseline,
        post_merge_evaluation=post_merge,
        coverage_delta=delta,
        representative_results=[],
        family_summary={"stable_branch_families": []},
        previous_family_signal_score=0,
    )
    assert status == "coverage_progress"


def test_empty_baseline_never_masks_a_solve() -> None:
    baseline = empty_baseline_evaluation()
    post_merge = {
        "success": True,
        "branch_hit_count": 3,
        "blocked_side_hit_count": 1,
        "branch_line_reached": True,
        "blocked_side_line_reached": True,
    }
    delta = compute_coverage_delta(baseline, post_merge)

    # An empty baseline must not read as "already covered before this iteration".
    assert delta["newly_reached_blocked_side_line"] is True
    status, _ = classify_iteration_status(
        validation_ok=True,
        generated_seed_count=5,
        baseline_evaluation=baseline,
        post_merge_evaluation=post_merge,
        coverage_delta=delta,
        representative_results=[],
        family_summary={"stable_branch_families": []},
        previous_family_signal_score=0,
    )
    assert status == "solved"


def test_fresh_mode_validation_never_runs_the_mutation_gate(tmp_path: Path) -> None:
    generator, base_seed = _write_mutation_fixture(tmp_path)

    result = validate_generator(
        generator,
        tmp_path,
        base_seed_path=base_seed,
        require_mutation=False,
        timeout_seconds=30,
    )

    assert result["ok"] is True
    assert "mutation_candidate_count" not in result
    assert result["valid_seed_count"] == 6


def test_coverage_profiles_are_discarded_unless_reports_are_kept(tmp_path: Path, monkeypatch) -> None:
    import blocker_process.dependent.symcc_blocker_solver as symcc

    # .profraw/.profdata are one-shot inputs to llvm-profdata/llvm-cov; only the hit
    # counts survive in CoverageResult. At ~180 KB per evaluated candidate they are what
    # makes the candidate-evaluation budget scale linearly in disk.
    def fake_measure(**kwargs):
        coverage_dir, name = kwargs["coverage_dir"], kwargs["seed_path"].name
        (coverage_dir / f"{name}.profraw").write_bytes(b"raw")
        (coverage_dir / f"{name}.profdata").write_bytes(b"data")
        if kwargs["branch_line"] == -1:
            raise symcc.CoverageOracleError("branch_line_missing", "simulated failure")
        return symcc.CoverageResult(
            seed=kwargs["seed_path"], branch_hit_count_raw="7", blocked_side_hit_count_raw="0",
            branch_hit_count=7, blocked_side_hit_count=0, blocked_side_line_reached=False,
        )

    monkeypatch.setattr(symcc, "_measure_seed_coverage", fake_measure)
    common = dict(
        coverage_bin=Path("/bin/true"), branch_source=Path("x.c"), coverage_source=None,
        blocked_side_line=2, target_args="@@", input_mode="file", timeout_sec=5,
        llvm_profdata="llvm-profdata", llvm_cov="llvm-cov",
    )

    def run(branch_line: int, keep: bool) -> list[str]:
        work = tmp_path / f"{branch_line}_{keep}"
        work.mkdir()
        seed = work / "s.bin"
        seed.write_bytes(b"s")
        try:
            symcc.evaluate_seed_with_coverage(
                seed_path=seed, coverage_dir=work, branch_line=branch_line,
                keep_report=keep, **common,
            )
        except symcc.CoverageOracleError:
            pass
        return sorted(p.name for p in work.glob("*.prof*"))

    # Failure paths are where junk accumulates fastest, so cleanup must cover them too.
    assert run(1, False) == []
    assert run(-1, False) == []
    assert run(1, True) == ["s.bin.profdata", "s.bin.profraw"]


def test_measurement_failure_is_not_reported_as_a_broken_generator(tmp_path: Path) -> None:
    # "The generator is broken" and "coverage measurement broke" need different labels:
    # invalid_generator is on the handoff deny-list, so conflating them turns a
    # measurement outage into a lost SymCC stage.
    seeds = []
    for index in range(10):
        seed = tmp_path / f"F0{index % 3}_family_{index:02d}.bin"
        seed.write_bytes(b"seed-%d" % index)
        seeds.append(str(seed))

    withheld = select_recommended_symcc_generator_seeds(
        generator_terminal_reason="invalid_generator",
        symcc_candidate_bundle={"candidate_seed_records": []},
        triggering_input_evaluation=None,
        unmeasured_seed_paths=seeds,
    )
    assert withheld["recommended_generator_seed_paths"] == []

    handed_off = select_recommended_symcc_generator_seeds(
        generator_terminal_reason="evaluation_failed",
        symcc_candidate_bundle={"candidate_seed_records": []},
        triggering_input_evaluation=None,
        unmeasured_seed_paths=seeds,
    )
    paths = handed_off["recommended_generator_seed_paths"]
    assert len(paths) == EVALUATION_FAILED_HANDOFF_SEEDS
    assert all(Path(path).is_file() for path in paths)
    # No coverage evidence exists, so the records must not imply any.
    assert all(record["coverage_measured"] is False
               for record in handed_off["recommended_generator_seed_records"])


def test_unmeasured_handoff_spreads_across_seed_families() -> None:
    # Seeds are named by family, so a prefix would hand SymCC near-identical inputs.
    paths = [f"F{index // 4:02d}_family_{index:02d}.bin" for index in range(12)]
    sample = deterministic_stratified_seed_sample(paths, 4)

    assert sample == [paths[0], paths[4], paths[7], paths[11]]
    assert len({path.split("_")[0] for path in sample}) == 3
    assert deterministic_stratified_seed_sample(paths[:3], 4) == paths[:3]
    assert deterministic_stratified_seed_sample([], 4) == []


def test_handoff_accepts_branch_reaching_seeds_that_do_not_beat_the_trigger() -> None:
    # The old gate demanded branch_hits > baseline, or an equal count in a smaller seed.
    # zlib gz_avail's trigger reached the branch 3 times in 13 bytes, so every generated
    # gzip stream failed both tests -- 61 of 62 archived runs handed SymCC nothing.
    records = [
        {"seed_path": f"/tmp/F0{index}_seed.bin", "family": f"F0{index}",
         "branch_hit_count": 3, "seed_size_bytes": 40 + index * 30, "branch_reached": True}
        for index in range(1, 5)
    ]

    result = select_recommended_symcc_generator_seeds(
        generator_terminal_reason="coverage_progress_observed_but_not_solved",
        symcc_candidate_bundle={"candidate_seed_records": records},
        triggering_input_evaluation={"success": True, "branch_hit_count": 3, "seed_size_bytes": 13},
    )

    assert len(result["recommended_generator_seed_paths"]) == 4
    # Seeds that never reach the branch are still worthless as starting points.
    none_reaching = select_recommended_symcc_generator_seeds(
        generator_terminal_reason="coverage_progress_observed_but_not_solved",
        symcc_candidate_bundle={"candidate_seed_records": [dict(r, branch_hit_count=0) for r in records]},
        triggering_input_evaluation={"success": True, "branch_hit_count": 3, "seed_size_bytes": 13},
    )
    assert none_reaching["recommended_generator_seed_paths"] == []


def test_handoff_prefers_unseen_families_over_the_highest_hit_counts() -> None:
    # N near-identical seeds buy one seed's worth of SymCC exploration, and the highest hit
    # counts usually come from one family hammering a loop (fill_window reached the branch
    # 2.68M times without ever crossing the predicate).
    same_family = [
        {"seed_path": f"/tmp/F01_{index}.bin", "family": "F01",
         "branch_hit_count": 1000 - index, "seed_size_bytes": 4096}
        for index in range(6)
    ]
    others = [
        {"seed_path": "/tmp/F02.bin", "family": "F02", "branch_hit_count": 1, "seed_size_bytes": 4096},
        {"seed_path": "/tmp/F03.bin", "family": "F03", "branch_hit_count": 1, "seed_size_bytes": 40},
    ]

    selected = select_diverse_handoff_records(same_family + others, 3)
    families = [item["family"] for item in selected]

    assert families[0] == "F01"          # the strongest seed still leads
    assert set(families) == {"F01", "F02", "F03"}
    assert len(select_diverse_handoff_records(same_family, 3)) == 3   # backfill when diversity runs out
    assert select_diverse_handoff_records([], 3) == []


def test_symcc_frontier_is_not_filled_with_one_loop_hammering_family(tmp_path: Path) -> None:
    import blocker_process.dependent.symcc_blocker_solver as symcc

    def candidate(name: str, size: int, branch_hits: int) -> "symcc.CandidateEvaluation":
        seed = tmp_path / name
        seed.write_bytes(b"x" * size)
        coverage = symcc.CoverageResult(
            seed=seed, branch_hit_count_raw=str(branch_hits), blocked_side_hit_count_raw="0",
            branch_hit_count=branch_hits, blocked_side_hit_count=0, blocked_side_line_reached=False,
        )
        return symcc.CandidateEvaluation(seed=seed, coverage=coverage, status="ok")

    # zlib fill_window reached the branch 2.68M times without ever crossing it: the count is
    # loop iterations, not proximity. Ranking on it alone fills the frontier with one
    # neighbourhood, and SymCC then explores that neighbourhood N times over.
    loop_family = [candidate(f"loop_{index}.bin", 4096, 2_000_000 - index) for index in range(8)]
    structurally_different = [candidate("small.bin", 40, 5), candidate("mid.bin", 600, 7)]

    selected = symcc.select_diverse_frontier(loop_family + structurally_different, 3)

    assert selected[0].seed.name == "loop_0.bin"          # strongest still leads
    assert len({item.seed.stat().st_size.bit_length() for item in selected}) == 3
    assert symcc.select_diverse_frontier([], 3) == []
    assert len(symcc.select_diverse_frontier(structurally_different, 10)) == 2


def _stalled_inputs(**overrides) -> dict:
    """The exact archived signal shape of libtiff _Fax3Close:1238.

    The triggering seed reaches the branch once, the generated seeds reach it zero times, and
    post-merge therefore still reports the branch as reached -- entirely on the trigger's
    behalf.
    """
    values = dict(
        validation_ok=True,
        generated_seed_count=5,
        baseline_evaluation={
            "success": True,
            "branch_hit_count": 1,
            "branch_line_reached": True,
            "blocked_side_line_reached": False,
        },
        post_merge_evaluation={
            "success": True,
            "branch_hit_count": 1,
            "branch_line_reached": True,
            "blocked_side_line_reached": False,
        },
        coverage_delta={"branch_hit_count_delta": 0, "blocked_side_hit_count_delta": 0},
        representative_results=[{"success": True, "branch_reached": False, "blocked_side_reached": False}],
        family_summary={
            "best_family": "F01_Base_Fillbits_Only.tif",
            "generated_family_reached_branch": False,
            "generated_family_reached_blocked_side": False,
            "stable_branch_families": [],
        },
        previous_family_signal_score=0,
    )
    values.update(overrides)
    return values


def test_trigger_reaching_the_branch_is_not_credited_to_generated_seeds() -> None:
    # post_merge is the triggering seed plus the generated seeds, so its branch coverage says
    # nothing about the generated seeds. Reading it as if it did made stalled_at_branch
    # unfalsifiable and mislabelled 31 archived blockers as "at the branch".
    status, reason = classify_iteration_status(**_stalled_inputs())

    assert status == "no_branch_signal"
    assert "generated" in reason.lower()


def test_generated_seeds_that_do_reach_the_branch_still_stall() -> None:
    # The fix must not swing the other way: once the generated families themselves reach the
    # branch, stalled_at_branch is the correct verdict.
    status, _ = classify_iteration_status(
        **_stalled_inputs(
            family_summary={
                "best_family": "F01_reaches",
                "generated_family_reached_branch": True,
                "generated_family_reached_blocked_side": False,
                "stable_branch_families": ["F01_reaches"],
            }
        )
    )

    assert status == "stalled_at_branch"


def test_mislabelled_iteration_now_asks_the_llm_to_fix_the_format() -> None:
    """The consequential half of the bug: the repair prompt told the LLM the wrong thing.

    ``reaches_branch_but_condition_not_satisfied`` asks for the predicate fields to be tuned,
    which is wasted effort when the seeds never enter the function. The correct guidance --
    compare against the reference seed's structure -- already existed but sat behind
    ``no_branch_signal``, which post-merge contamination made unreachable.
    """
    inputs = _stalled_inputs()
    status, _ = classify_iteration_status(**inputs)
    diagnosis = diagnose_iteration(
        iteration_status=status,
        validation_ok=True,
        generated_seed_count=5,
        staging_metadata={"added_seed_count": 5, "skipped_duplicate_seed_count": 0},
        baseline_evaluation=inputs["baseline_evaluation"],
        post_merge_evaluation=inputs["post_merge_evaluation"],
        coverage_delta=inputs["coverage_delta"],
        family_summary=inputs["family_summary"],
    )

    assert diagnosis["diagnosis_code"] == "format_mismatch_seed"
    assert diagnosis["branch_line_reached"] is False
    assert diagnosis["symcc_candidate"] is False


def test_branch_delta_still_counts_as_generated_seeds_reaching_the_branch() -> None:
    # A positive delta can only come from the generated seeds, so it is a legitimate
    # secondary signal even when the per-family measurement missed it.
    inputs = _stalled_inputs()
    diagnosis = diagnose_iteration(
        iteration_status="coverage_progress",
        validation_ok=True,
        generated_seed_count=5,
        staging_metadata={"added_seed_count": 5, "skipped_duplicate_seed_count": 0},
        baseline_evaluation=inputs["baseline_evaluation"],
        post_merge_evaluation=inputs["post_merge_evaluation"],
        coverage_delta={"branch_hit_count_delta": 7, "blocked_side_hit_count_delta": 0},
        family_summary=inputs["family_summary"],
    )

    assert diagnosis["branch_line_reached"] is True
