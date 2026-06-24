from types import SimpleNamespace
from pathlib import Path

import pytest

from blocker_process.blocker_callpath_extractor import (
    _preprocessor_context_by_line,
    enrich_call_sites_with_calltree,
    enumerate_textual_call_sites,
    extract_blocker_callchain_info,
    get_runtime_function_source_codes,
    get_unique_source_codes,
    render_call_sites_for_prompt,
)


def test_explicit_triggering_input_is_tried_before_corpus(monkeypatch, tmp_path):
    trigger = tmp_path / "trigger.seed"
    trigger.write_bytes(b"trigger")
    corpus_scan_called = False

    class FakeIntrospector:
        pass

    def fail_corpus_scan(**_kwargs):
        nonlocal corpus_scan_called
        corpus_scan_called = True
        raise AssertionError("corpus scan must not run after explicit triggering input succeeds")

    monkeypatch.setattr("blocker_process.blocker_callpath_extractor.INTROSPECTOR_AVAILABLE", True)
    monkeypatch.setattr("blocker_process.blocker_callpath_extractor.Introspector", FakeIntrospector)
    monkeypatch.setattr(
        "blocker_process.blocker_callpath_extractor.enumerate_textual_call_sites",
        lambda *_args, **_kwargs: {"entries": []},
    )
    monkeypatch.setattr(
        "blocker_process.blocker_callpath_extractor.get_data_file_for_target",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "blocker_process.blocker_callpath_extractor.find_matching_seeds",
        fail_corpus_scan,
    )
    monkeypatch.setattr(
        "blocker_process.blocker_callpath_extractor.find_runtime_call_chain_with_gdb",
        lambda *_args, **_kwargs: {
            "gdb_frames": [],
            "triggering_input": str(trigger),
        },
    )

    result = extract_blocker_callchain_info(
        blocker={
            "function_name": "blocked_function",
            "branch_line_number": "10",
            "blocked_side_line_number": "11",
            "source_file": "/src/demo/source.c",
            "best_target": "demo_fuzzer",
        },
        yaml_file=str(tmp_path / "missing.yaml"),
        project_name="demo",
        max_gdb_inputs=1,
        triggering_input=str(trigger),
    )

    assert corpus_scan_called is False
    assert result["gdb_result"]["seed_source"] == "explicit_triggering_input"
    assert result["gdb_result"]["selected_seed"] == str(trigger.resolve())


def _facts(**states):
    return {
        name: {"state": state, "evidence": []}
        for name, state in states.items()
    }


def test_preprocessor_context_marks_ifndef_inactive_when_macro_defined():
    lines = [
        "#ifndef INET6",
        "call_blocker();",
        "#else",
        "fallback();",
        "#endif",
    ]

    contexts = _preprocessor_context_by_line(lines, _facts(INET6="defined"))

    assert contexts[1]["status"] == "inactive"
    assert contexts[1]["conditions"] == ["#ifndef INET6"]
    assert contexts[3]["status"] == "active"
    assert contexts[3]["conditions"] == ["#else"]


def test_preprocessor_context_keeps_unresolved_macro_unknown():
    lines = ["#ifdef OPTIONAL_FEATURE", "call_blocker();", "#endif"]

    contexts = _preprocessor_context_by_line(lines, {})

    assert contexts[1]["status"] == "unknown"
    assert contexts[1]["conditions"] == ["#ifdef OPTIONAL_FEATURE"]


def test_calltree_evidence_upgrades_non_inactive_callsite_to_active():
    call_sites = {
        "entries": [
            {
                "file": "sample.c",
                "line": 42,
                "build_status": "unknown",
                "build_reason": "No positive evidence.",
                "callsite_path_status": "textual_only",
                "caller_function": None,
            }
        ]
    }
    parent = SimpleNamespace(dst_function_name="caller")
    node = SimpleNamespace(
        dst_function_name="blocker",
        dst_function_source_file="sample.c",
        src_linenumber=42,
        parent_calltree_callsite=parent,
    )

    enrich_call_sites_with_calltree(call_sites, [node], "blocker")

    entry = call_sites["entries"][0]
    assert entry["build_status"] == "active"
    assert entry["callsite_path_status"] == "present_in_target_calltree"


def test_textual_callsite_uses_explicit_session_source_root(tmp_path):
    source_root = tmp_path / "source_root"
    source_file = source_root / "src" / "sample.c"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "void caller(void) {\n"
        "    blocker_api(1);\n"
        "}\n",
        encoding="utf-8",
    )

    call_sites = enumerate_textual_call_sites(
        "missing-live-project",
        "blocker_api",
        "/src/missing-live-project/src/sample.c",
        str(source_root),
    )

    assert call_sites["total_candidates"] == 1
    assert call_sites["entries"][0]["file"].endswith("sample.c")


class _FakeIntrospector:
    def __init__(self, functions=None, function_source="", file_source=""):
        self.functions = functions or []
        self.function_source = function_source
        self.file_source = file_source

    def get_all_functions(self, _project_name):
        return self.functions

    def function_source_code(self, _project_name, _signature):
        return self.function_source

    def get_project_source_code(self, _project_name, _file_path, _start, _end):
        return self.file_source


def test_runtime_source_prefers_session_cache(tmp_path):
    source_root = tmp_path / "session" / "source_root"
    source_file = source_root / "src" / "sample.c"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "int helper(int value) {\n"
        "    return value + 1;\n"
        "}\n",
        encoding="utf-8",
    )
    introspector = _FakeIntrospector(
        functions=[{
            "function_name": "helper",
            "raw_function_name": "helper",
            "function_signature": "int helper(int)",
        }],
        function_source="API source must not replace cache source",
    )

    rendered = get_runtime_function_source_codes(
        [{"symbol": "helper", "file": "/src/sample-project/src/sample.c", "line": 2}],
        introspector,
        "sample-project",
        str(source_root),
    )

    assert "Source retrieved from session cache" in rendered
    assert "return value + 1;" in rendered
    assert "API source must not replace cache source" not in rendered


def test_runtime_source_prefers_session_cache_over_existing_live_path(tmp_path):
    live_file = tmp_path / "live" / "sample.c"
    live_file.parent.mkdir(parents=True)
    live_file.write_text(
        "int helper(void) { return 1; }\n",
        encoding="utf-8",
    )
    source_root = tmp_path / "session" / "source_root"
    cached_file = source_root / "sample.c"
    cached_file.parent.mkdir(parents=True)
    cached_file.write_text(
        "int helper(void) { return 2; }\n",
        encoding="utf-8",
    )

    rendered = get_runtime_function_source_codes(
        [{"symbol": "helper", "file": str(live_file), "line": 1}],
        _FakeIntrospector(),
        "sample-project",
        str(source_root),
    )

    assert "Source retrieved from session cache" in rendered
    assert "return 2;" in rendered
    assert "return 1;" not in rendered


def test_runtime_source_falls_back_to_introspector_api():
    introspector = _FakeIntrospector(
        functions=[{
            "function_name": "api_helper",
            "raw_function_name": "api_helper",
            "function_signature": "int api_helper(void)",
        }],
        function_source="int api_helper(void) { return 7; }",
    )

    rendered = get_runtime_function_source_codes(
        [{"symbol": "api_helper", "file": None, "line": None}],
        introspector,
        "missing-project",
    )

    assert "int api_helper(void) { return 7; }" in rendered


def test_runtime_source_marks_missing_evidence_explicitly():
    rendered = get_runtime_function_source_codes(
        [{"symbol": "missing_helper", "file": "/src/missing.c", "line": 10}],
        _FakeIntrospector(),
        "missing-project",
    )

    assert "[Evidence Missing]" in rendered
    assert "missing_helper" in rendered


def test_cfg_source_uses_session_cache(tmp_path):
    source_root = tmp_path / "session" / "source_root"
    source_file = source_root / "src" / "sample.c"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "static int cfg_helper(void)\n"
        "{\n"
        "    return 9;\n"
        "}\n",
        encoding="utf-8",
    )
    node = SimpleNamespace(
        dst_function_name="cfg_helper",
        dst_function_source_file="/src/sample-project/src/sample.c",
    )

    rendered = get_unique_source_codes(
        [node],
        _FakeIntrospector(),
        "sample-project",
        str(source_root),
    )

    assert "Source retrieved from session cache" in rendered
    assert "return 9;" in rendered


def test_libpcap_inactive_callsite_is_filtered_when_build_artifacts_exist():
    source = "external/oss-fuzz/build/out/libpcap/source_code/gencode.c"
    if not Path(source).is_file():
        pytest.skip("libpcap build artifacts are not available")
    call_sites = enumerate_textual_call_sites("libpcap", "gen_prevlinkhdr_check", source)
    entries = {entry["candidate_id"]: entry for entry in call_sites["entries"]}

    entry = entries["gencode.c:5267"]
    assert entry["build_status"] == "inactive"
    assert entry["preprocessor_conditions"] == ["#ifndef INET6"]
    assert any(item["macro"] == "INET6" for item in entry["build_evidence"])

    rendered = render_call_sites_for_prompt(call_sites)
    selectable_section, filtered_section = rendered.split("## Filtered inactive call sites", 1)
    assert "### gencode.c:5267" not in selectable_section
    assert "gencode.c:5267" in filtered_section
