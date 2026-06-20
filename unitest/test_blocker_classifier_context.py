from argparse import Namespace

from blocker_process import blocker_callpath_extractor
from blocker_process.blocker_classifier import auto_collect_callpath_context


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
        triggering_input="",
    )

    result = auto_collect_callpath_context(args)

    assert captured["source_root"] == str(source_root)
    assert "sample.c:10" in result.blocker_call_sites
    assert result.cfg_collection_status == "failed"
