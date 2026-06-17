from types import SimpleNamespace
from pathlib import Path

import pytest

from blocker_process.blocker_callpath_extractor import (
    _preprocessor_context_by_line,
    enrich_call_sites_with_calltree,
    enumerate_textual_call_sites,
    render_call_sites_for_prompt,
)


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
