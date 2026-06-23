import json
import math

import blocker_process.global_blocker_selector as selector
from blocker_process.global_blocker_selector import (
    _analyze_snippet_solvability,
    _compute_actionability_score,
    _compute_impact_score,
    _extract_if_statement,
    _select_source_evidence_candidates,
    _strip_comments_preserve_strings,
    aggregate_score_and_revalidate_blockers,
)


def test_resource_guard_accepts_single_character_variable_and_cast() -> None:
    branch = """
KEYVALUE *p;
p = (KEYVALUE*) AllocChunk(it8, sizeof(KEYVALUE));
if (p == NULL) {
    SynError(it8, "AddToList: out of memory");
    return NULL;
}
"""
    blocked = 'SynError(it8, "AddToList: out of memory");\nreturn NULL;'

    score, reason, _hints, evidence = _analyze_snippet_solvability(
        "if (p == NULL)",
        branch,
        blocked,
    )

    assert score == 0.25
    assert reason == "resource_guard_strong"
    assert evidence["grade"] == "strong"
    assert evidence["callee"] == "AllocChunk"
    assert evidence["checked_variable"] == "p"


def test_reversed_null_check_is_linked_to_same_variable() -> None:
    branch = "result = project_create();\nif (NULL == result) return -1;"
    blocked = 'report_error("allocation failed");'

    score, _reason, _hints, evidence = _analyze_snippet_solvability(
        "if (NULL == result)",
        branch,
        blocked,
    )

    assert score == 0.25
    assert evidence["callee"] == "project_create"


def test_nullable_api_without_resource_evidence_is_not_downranked() -> None:
    branch = "cfg = get_optional_config(input);\nif (!cfg) return DEFAULT_MODE;"

    score, reason, _hints, evidence = _analyze_snippet_solvability(
        "if (!cfg)",
        branch,
        "return DEFAULT_MODE;",
    )

    assert score == 1.0
    assert reason == "normal"
    assert evidence["grade"] == "unknown"


def test_unlinked_resource_text_is_only_weak_evidence() -> None:
    score, reason, _hints, evidence = _analyze_snippet_solvability(
        "if (failed)",
        "if (failed) return -1;",
        'log_error("out of memory");',
    )

    assert score == 1.0
    assert reason == "normal"
    assert evidence["grade"] == "weak"


def test_nearby_null_check_is_not_attributed_to_current_branch() -> None:
    branch = """
LUT = cmsPipelineDup(xform->Lut);
if (LUT == NULL) return NULL;
if ((xform->EntryColorSpace == cmsSigLabData) && (Version < 4.0)) {
    insert_conversion_stage(LUT);
}
"""

    score, reason, _hints, evidence = _analyze_snippet_solvability(
        "if ((xform->EntryColorSpace == cmsSigLabData) && (Version < 4.0))",
        branch,
        "insert_conversion_stage(LUT);",
    )

    assert score == 1.0
    assert reason == "normal"
    assert evidence["grade"] == "none"


def test_multiline_if_statement_is_extracted_from_branch_line() -> None:
    lines = [
        "if ((ptr == NULL) ||",
        "    failed_to_initialize(ptr)) {",
        "    return ERROR;",
        "}",
    ]

    predicate = _extract_if_statement(lines, 1)

    assert predicate == "if ((ptr == NULL) ||\n    failed_to_initialize(ptr))"


def test_comments_are_removed_but_resource_strings_are_preserved() -> None:
    stripped = _strip_comments_preserve_strings(
        '/* fake = malloc(1); */\nlog_error("out of memory"); // fake == NULL\n'
    )

    assert "fake = malloc" not in stripped
    assert "fake == NULL" not in stripped
    assert '"out of memory"' in stripped
    assert stripped.count("\n") == 2


def test_reach_confidence_has_floor_and_saturates() -> None:
    assert _compute_actionability_score(
        {"project_branch_hit_count": 0},
        hit_saturation_threshold=100_000,
    ) == 0.5
    assert _compute_actionability_score(
        {"project_branch_hit_count": 100_000},
        hit_saturation_threshold=100_000,
    ) == 1.0
    assert _compute_actionability_score(
        {"project_branch_hit_count": 100_000_000},
        hit_saturation_threshold=100_000,
    ) == 1.0


def test_coverage_benefit_uses_absolute_gain_and_unlock_ratio() -> None:
    blocker = {
        "blocked_unique_not_covered_complexity": 30,
        "blocked_unique_reachable_complexity": 60,
        "globally_unhit_function_count": 2,
    }
    expected = math.log1p(30) * 0.75 + 0.5

    assert _compute_impact_score(blocker) == expected


def test_hybrid_pool_includes_high_benefit_candidate_outside_top_twenty() -> None:
    blockers = [
        {
            "source_file": f"/src/p/{index}.c",
            "branch_line_number": index,
            "blocked_side": "0",
            "score": 100 - index,
            "coverage_benefit": 1.0,
        }
        for index in range(25)
    ]
    blockers[-1]["coverage_benefit"] = 1000.0

    selected = _select_source_evidence_candidates(blockers)

    assert blockers[-1] in selected
    assert len(selected) == 21


def test_revalidated_selector_infers_function_and_file_coverage_artifacts(
    tmp_path, monkeypatch
) -> None:
    blocker_json = tmp_path / "branch-blockers.json"
    blocker_json.write_text(
        json.dumps(
            {
                "demo_target": [
                    {
                        "source_file": "/src/demo.c",
                        "branch_line_number": "10",
                        "blocked_side": "1",
                        "blocked_side_line_number": "11",
                        "function_name": "entry",
                        "blocked_unique_not_covered_complexity": 30,
                        "blocked_unique_reachable_complexity": 60,
                        "blocked_not_covered_complexity": 30,
                        "blocked_reachable_complexity": 60,
                        "blocked_unique_functions": ["hidden_function"],
                        "sides_hitcount_diff": 5,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "all_functions.js").write_text(
        "var all_functions_table_data = "
        + json.dumps(
            [
                {
                    "Func name": "<span>hidden_function</span>",
                    "Functions filename": "/src/demo.c",
                    "Fuzzers runtime hit": "no",
                    "Func lines hit %": "0%",
                    "Cyclomatic complexity": 4,
                    "Accumulated cyclomatic complexity": 8,
                    "Undiscovered complexity": 8,
                }
            ]
        )
        + ";",
        encoding="utf-8",
    )
    (tmp_path / "summary_exclude_target.json").write_text(
        json.dumps(
            {
                "data": [
                    {
                        "files": [
                            {
                                "filename": "/src/demo.c",
                                "summary": {
                                    "lines": {"percent": 10, "count": 100, "covered": 10},
                                    "branches": {"percent": 20, "notcovered": 16},
                                    "functions": {"percent": 25, "count": 4, "covered": 1},
                                },
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def fail_if_reaggregated(*_args, **_kwargs):
        raise AssertionError("revalidated blockers must be scored without reaggregation")

    monkeypatch.setattr(selector, "aggregate_and_score_blockers", fail_if_reaggregated)

    selected = aggregate_score_and_revalidate_blockers(
        json_path=str(blocker_json),
        project_target_reports={},
        top_k=None,
    )

    assert len(selected) == 1
    assert selected[0]["matched_function_count"] == 1
    assert selected[0]["globally_unhit_function_count"] == 1
    assert selected[0]["score_components"]["globally_unhit_function_bonus"] == 0.25
    assert selected[0]["project_file_lines_percent"] == 10.0
