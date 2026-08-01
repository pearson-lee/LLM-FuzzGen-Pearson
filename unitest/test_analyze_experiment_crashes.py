import argparse
import json
from pathlib import Path
from unittest.mock import Mock

from crash_analyzer.crash_analyzer import CrashAnalyzer, CrashHeuristicTriage
from tools.analyze_experiment_crashes import discover_crash_seeds, run


def _write_artifact(
    experiment_dir: Path,
    *,
    project: str,
    fuzzer: str,
    artifact_name: str,
    artifact_kind: str,
) -> Path:
    artifact_dir = experiment_dir / "crash_seeds" / project / fuzzer
    artifact_dir.mkdir(parents=True, exist_ok=True)
    seed_path = artifact_dir / artifact_name
    seed_path.write_bytes(b"seed")
    metadata = {
        "project": project,
        "fuzzer": fuzzer,
        "artifact_name": artifact_name,
        "artifact_kind": artifact_kind,
        "seed_saved": True,
    }
    (artifact_dir / f"{artifact_name}.metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )
    return seed_path


def test_discovers_metadata_for_crash_and_slow_unit(tmp_path):
    experiment_dir = tmp_path / "experiment"
    crash = _write_artifact(
        experiment_dir,
        project="libvpx",
        fuzzer="llm_fuzzgen_reference_guided_123",
        artifact_name="llm_fuzzgen_reference_guided_123_crash-deadbeef",
        artifact_kind="crash",
    )
    _write_artifact(
        experiment_dir,
        project="lcms",
        fuzzer="llm_fuzzgen1234567890",
        artifact_name="llm_fuzzgen1234567890_slow-unit-cafebabe",
        artifact_kind="slow-unit",
    )

    seeds, issues = discover_crash_seeds([experiment_dir])

    assert not issues
    assert len(seeds) == 2
    assert {seed.artifact_kind for seed in seeds} == {"crash", "slow-unit"}
    reference_seed = next(seed for seed in seeds if seed.project == "libvpx")
    assert reference_seed.fuzzer == "llm_fuzzgen_reference_guided_123"
    assert reference_seed.seed_path == crash


def test_dry_run_writes_selected_and_skipped_counts(tmp_path):
    experiment_dir = tmp_path / "experiment"
    empty_experiment_dir = tmp_path / "empty-experiment"
    empty_experiment_dir.mkdir()
    _write_artifact(
        experiment_dir,
        project="libvpx",
        fuzzer="llm_fuzzgen1234567890",
        artifact_name="llm_fuzzgen1234567890_crash-deadbeef",
        artifact_kind="crash",
    )
    _write_artifact(
        experiment_dir,
        project="lcms",
        fuzzer="llm_fuzzgen1234567891",
        artifact_name="llm_fuzzgen1234567891_slow-unit-cafebabe",
        artifact_kind="slow-unit",
    )
    output_dir = tmp_path / "output"
    args = argparse.Namespace(
        experiment_dirs=[experiment_dir, empty_experiment_dir],
        llm="vertexai",
        model="gemini-2.5-pro",
        temperature=0.1,
        artifact_kinds=["crash"],
        build=False,
        sanitizer="address",
        output_dir=output_dir,
        dry_run=True,
    )

    assert run(args) == 0

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["totals"]["discovered"] == 2
    assert summary["totals"]["selected"] == 1
    assert summary["totals"]["skipped"] == 1
    assert summary["totals"]["pending"] == 1
    assert len(summary["experiments"]) == 2
    assert summary["experiments"][1]["discovered"] == 0
    assert {result["status"] for result in summary["results"]} == {"SELECTED", "SKIPPED"}
    assert (output_dir / "results.csv").is_file()
    assert "| **Total** | **2** | **1** |" in (output_dir / "summary.md").read_text(encoding="utf-8")


def test_explicit_analyze_crash_supports_non_timestamp_fuzzer_names(tmp_path):
    project = "demo"
    fuzzer = "llm_fuzzgen_reference_guided_123"
    oss_fuzz = Mock()
    oss_fuzz.build_out_dir = tmp_path / "out"
    oss_fuzz.oss_fuzz_dir = tmp_path / "oss-fuzz"
    oss_fuzz.reproduce_crash.return_value = (
        "#0 0x123 in parse /src/demo/parser.c:10:2\n"
        "#1 0x456 in LLVMFuzzerTestOneInput /src/llm_fuzzgen_reference_guided_123.cc:20:2"
    )
    (oss_fuzz.build_out_dir / project).mkdir(parents=True)
    (oss_fuzz.build_out_dir / project / fuzzer).write_bytes(b"binary")
    project_dir = oss_fuzz.oss_fuzz_dir / "projects" / project
    project_dir.mkdir(parents=True)
    source_path = project_dir / f"{fuzzer}.cc"
    source_path.write_text("int LLVMFuzzerTestOneInput() { return 0; }", encoding="utf-8")
    seed_path = tmp_path / f"{fuzzer}_crash-deadbeef"
    seed_path.write_bytes(b"seed")

    analyzer = CrashAnalyzer.__new__(CrashAnalyzer)
    analyzer.llm_client = Mock()
    analyzer.oss_fuzz = oss_fuzz
    analyzer.crashes_dir = tmp_path / "analysis"
    analyzer._get_llm_analysis = Mock(
        return_value={
            "finding": "Real Crash",
            "crash_type": "heap-buffer-overflow",
            "crash_site": "library",
            "crash_function": "parse",
            "reasoning_summary": "library crash",
            "suggested_fix": "check bounds",
            "evidence": ["/src/demo/parser.c:10:2"],
            "confidence": 0.9,
        }
    )
    analyzer._heuristic_triage = Mock(
        return_value=CrashHeuristicTriage(
            finding="Real Crash",
            crash_type="heap-buffer-overflow",
            crash_site="library",
            suspected_fuzzer_bug=False,
            confidence=0.7,
            rationale=["library frame"],
            frame_classification="library",
        )
    )

    artifact_dir = analyzer.analyze_crash(project, fuzzer, seed_path)

    assert artifact_dir is not None
    assert (artifact_dir / "analysis.json").is_file()
    assert (artifact_dir / source_path.name).is_file()
    assert (artifact_dir / seed_path.name).is_file()
