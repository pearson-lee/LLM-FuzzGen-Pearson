from argparse import Namespace

from blocker_process import blocker_callpath_extractor
from blocker_process import blocker_classifier
from blocker_process.blocker_classifier import (
    auto_collect_callpath_context,
    build_input_independent_solver_args,
    build_seed_generation_args,
    enrich_classification_args,
    resolve_triggering_input_from_extraction,
)


def test_dependent_timeouts_are_not_forwarded_to_independent_solver() -> None:
    args = Namespace(
        backend="vertexai",
        model="gemini-2.5-pro",
        project_name="demo",
        function_name="blocker_api",
        branch_line_number=10,
        blocked_side_line_number=11,
        source_file="/tmp/source.c",
        source_api_file="/src/demo/source.c",
        fuzz_file="/tmp/fuzzer.c",
        target_name="demo_fuzzer",
        seed=[],
        max_iterations=2,
        fuzz_seconds=15,
        llm_seed_stage_timeout_sec=900,
        llm_harness_stage_timeout_sec=300,
        reset_corpus_per_iteration=False,
        log_dir=None,
    )

    dependent_args = build_seed_generation_args(args)
    independent_args = build_input_independent_solver_args(args)

    assert "--llm-seed-stage-timeout-sec" in dependent_args
    assert "--llm-harness-stage-timeout-sec" in dependent_args
    assert "--llm-seed-stage-timeout-sec" not in independent_args
    assert "--llm-harness-stage-timeout-sec" not in independent_args


def test_missing_yaml_still_collects_textual_callsites(monkeypatch, tmp_path):
    captured = {}

    def fake_extract(**kwargs):
        captured.update(kwargs)
        return {
            "call_sites": {
                "entries": [
                    {
                        "candidate_id": "sample.c:10",
                        "file": "sample.c",
                        "line": 10,
                        "build_status": "unknown",
                        "build_reason": "textual evidence only",
                        "callsite_path_status": "textual_only",
                        "local_context": ">> 10: blocker_api();",
                    }
                ],
                "total_candidates": 1,
                "included_candidates": 1,
                "truncated": False,
                "collection_errors": [],
            },
            "gdb_result": {},
            "cfg_error": "Data file not found",
        }

    monkeypatch.setattr(blocker_callpath_extractor, "extract_blocker_callchain_info", fake_extract)
    source_root = tmp_path / "source"
    source_root.mkdir()
    args = Namespace(
        project_name="demo",
        target_name="demo_fuzzer",
        function_name="blocker_api",
        branch_line_number=11,
        blocked_side_line_number=12,
        source_api_file="/src/demo/sample.c",
        source_file=str(source_root / "sample.c"),
        yaml_file=str(tmp_path / "missing.yaml"),
        callpath_source_root=str(source_root),
        max_gdb_inputs=0,
        runtime_blocker_segment=None,
        runtime_blocker_segment_file=None,
        runtime_blocker_segment_source_codes=None,
        runtime_blocker_segment_source_codes_file=None,
        cfg_call_chain=None,
        cfg_call_chain_file=None,
        cfg_source_codes=None,
        cfg_source_codes_file=None,
        blocker_call_sites=None,
        triggering_input="known-trigger.seed",
    )

    result = auto_collect_callpath_context(args)

    assert captured["source_root"] == str(source_root)
    assert captured["triggering_input"] == "known-trigger.seed"
    assert "sample.c:10" in result.blocker_call_sites
    assert result.cfg_collection_status == "failed"


def test_gdb_failure_falls_back_to_coverage_selected_seed(monkeypatch, tmp_path):
    seed = tmp_path / "branch_reaching.seed"
    seed.write_bytes(b"hit-branch")

    def fake_extract(**_kwargs):
        return {
            "call_sites": {"entries": []},
            "matching_seeds": [{"seed": str(seed)}],
            "gdb_result": {
                "error": "GDB did not hit breakpoints with seed.",
                "selected_seed": str(seed),
                "seed_source": "find_blocker_seeds_by_coverage",
            },
            "cfg_error": "Data file not found",
        }

    monkeypatch.setattr(blocker_callpath_extractor, "extract_blocker_callchain_info", fake_extract)
    args = Namespace(
        project_name="demo",
        target_name="demo_fuzzer",
        function_name="blocker_api",
        branch_line_number=11,
        blocked_side_line_number=12,
        source_api_file="/src/demo/sample.c",
        source_file=str(tmp_path / "sample.c"),
        yaml_file=str(tmp_path / "missing.yaml"),
        callpath_source_root=str(tmp_path),
        max_gdb_inputs=0,
        runtime_blocker_segment=None,
        runtime_blocker_segment_file=None,
        runtime_blocker_segment_source_codes=None,
        runtime_blocker_segment_source_codes_file=None,
        cfg_call_chain=None,
        cfg_call_chain_file=None,
        cfg_source_codes=None,
        cfg_source_codes_file=None,
        blocker_call_sites=None,
        triggering_input="",
    )

    result = auto_collect_callpath_context(args)

    assert result.runtime_collection_status == "failed"
    assert result.triggering_input == str(seed.resolve())


def test_triggering_input_fallback_uses_matching_seed_when_gdb_has_no_seed(tmp_path):
    seed = tmp_path / "matching.seed"
    seed.write_bytes(b"hit-branch")

    result = resolve_triggering_input_from_extraction(
        {"matching_seeds": [{"seed": str(seed)}]},
        {"error": "GDB unavailable"},
    )

    assert result == str(seed.resolve())


def test_enrichment_prefers_cached_local_source_over_unavailable_api(monkeypatch, tmp_path):
    source_file = tmp_path / "source.c"
    source_file.write_text("line one\nif (flag)\nblocked();\n", encoding="utf-8")

    class FakeOSSFuzz:
        def proj_lang(self, project_name):
            return "c"

    monkeypatch.setattr(blocker_classifier, "OSSFuzz", FakeOSSFuzz)
    monkeypatch.setattr(blocker_classifier, "check_function_coverage", lambda *args, **kwargs: "")
    args = Namespace(
        project_name="demo",
        function_name="blocker",
        branch_line_number=2,
        blocked_side_line_number=3,
        source_file=str(source_file),
        source_api_file="/src/demo/missing.c",
        fuzz_file=None,
    )

    result = enrich_classification_args(args)

    assert result.blocker_line_code == "if (flag)"
    assert result.blocked_side_line_code == "blocked();"


def test_enrichment_preserves_live_branch_hit_count_without_fuzz_file(monkeypatch, tmp_path):
    source_file = tmp_path / "source.c"
    source_file.write_text("if (flag)\nblocked();\n", encoding="utf-8")

    class FakeOSSFuzz:
        def proj_lang(self, project_name):
            return "c"

    monkeypatch.setattr(blocker_classifier, "OSSFuzz", FakeOSSFuzz)
    args = Namespace(
        project_name="demo",
        function_name="blocker",
        branch_line_number=1,
        blocked_side_line_number=2,
        source_file=str(source_file),
        source_api_file="/src/demo/missing.c",
        fuzz_file=None,
        branch_hit_count=22800,
    )

    result = enrich_classification_args(args)

    assert result.branch_hit_count == 22800


def test_enrichment_uses_source_section_for_target_branch_hit_count(monkeypatch, tmp_path):
    source_file = tmp_path / "source.c"
    source_file.write_text("if (flag)\nblocked();\n", encoding="utf-8")

    class FakeOSSFuzz:
        def proj_lang(self, project_name):
            return "c"

    report = "/src/demo/source.c:\n    1|150|if (flag)\n    2|0|blocked();\n"
    monkeypatch.setattr(blocker_classifier, "OSSFuzz", FakeOSSFuzz)
    monkeypatch.setattr(blocker_classifier, "check_function_coverage", lambda *args, **kwargs: report)
    args = Namespace(
        project_name="demo",
        function_name="blocker",
        branch_line_number=1,
        blocked_side_line_number=2,
        source_file=str(source_file),
        source_api_file="/src/demo/source.c",
        fuzz_file="/src/demo_fuzzer.c",
        branch_hit_count=100,
    )

    result = enrich_classification_args(args)

    assert result.branch_hit_count == "150"


def test_enrichment_keeps_live_hit_count_when_target_report_has_no_matching_line(monkeypatch, tmp_path):
    source_file = tmp_path / "source.c"
    source_file.write_text("if (flag)\nblocked();\n", encoding="utf-8")

    class FakeOSSFuzz:
        def proj_lang(self, project_name):
            return "c"

    monkeypatch.setattr(blocker_classifier, "OSSFuzz", FakeOSSFuzz)
    monkeypatch.setattr(blocker_classifier, "check_function_coverage", lambda *args, **kwargs: "")
    args = Namespace(
        project_name="demo",
        function_name="blocker",
        branch_line_number=1,
        blocked_side_line_number=2,
        source_file=str(source_file),
        source_api_file="/src/demo/source.c",
        fuzz_file="/src/demo_fuzzer.c",
        branch_hit_count=1850,
    )

    result = enrich_classification_args(args)

    assert result.branch_hit_count == 1850
