from pathlib import Path
from types import SimpleNamespace

from blocker_process.dependent.input_dependent_seed_generator import (
    build_corpus_manifest,
    build_seed_records,
    classify_iteration_status,
    prepare_isolated_corpus_snapshot,
    validate_generator,
)
from blocker_process.dependent.input_dependent_solver import (
    build_runtime_sanity_seed_args,
    get_symcc_failure_kind,
    resolve_harness_fidelity_seed,
    resolve_seed_generator_triggering_input,
    seed_generation_exceeded_budget,
)


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
