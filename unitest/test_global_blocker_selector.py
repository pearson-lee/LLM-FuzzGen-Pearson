import math

from blocker_process.global_blocker_selector import (
    _analyze_snippet_solvability,
    _compute_actionability_score,
    _compute_impact_score,
    _select_source_evidence_candidates,
    _strip_comments_preserve_strings,
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
