from blocker_process.target_quality_analyzer import analyze_target_quality


def _runtime_success() -> dict:
    return {
        "success": True,
        "blocked_side_hit_count": 1,
        "blocked_side_line_reached": True,
    }


def _evidence(*symbols: str) -> dict:
    return {
        "entries": [
            {
                "symbol": symbol,
                "kind": "declaration",
                "visibility": "public",
                "preprocessor_status": "active",
            }
            for symbol in symbols
        ]
    }


def test_internal_header_alone_is_only_a_weak_flag() -> None:
    code = """
#include "/src/lcms/src/lcms2_internal.h"
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    cmsMLUsetWide(0, "en", "US", L"value");
    return 0;
}
"""
    report = analyze_target_quality(
        code=code,
        evaluation=_runtime_success(),
        strategy_contract="""required_state: cmsMLUsetWide creates the MLU state
state_constructor: cmsMLUsetWide()
trigger_api: AddMLUBlock()
preserved_invariants: do not call private _cms APIs""",
        symbol_evidence=_evidence("cmsMLUsetWide", "AddMLUBlock"),
    )

    assert "includes_internal_header" in report["quality_flags"]
    assert "internal_api_direct" not in report["success_quality_labels"]


def test_direct_internal_api_call_is_strong_signal() -> None:
    code = """
#include "/src/lcms/src/lcms2_internal.h"
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    _cmsReadDevicelinkLUT(0, 0);
    return 0;
}
"""
    report = analyze_target_quality(
        code=code,
        evaluation=_runtime_success(),
        strategy_contract="""required_state: call the devicelink reader
state_constructor: _cmsReadDevicelinkLUT()
trigger_api: _cmsReadDevicelinkLUT()
preserved_invariants: N/A""",
        symbol_evidence=_evidence(),
    )

    assert report["primary_success_quality"] == "internal_api_direct"
    assert "_cmsReadDevicelinkLUT" in report["evidence"]["internal_api_calls"]


def test_direct_struct_field_write_requires_review_not_rejection() -> None:
    code = """
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    profile->UsedEntries = 4;
    cmsWriteTag(0, 0, 0);
    return 0;
}
"""
    report = analyze_target_quality(
        code=code,
        evaluation=_runtime_success(),
        strategy_contract="""required_state: write a tag after setting profile state
state_constructor: cmsWriteTag()
trigger_api: cmsWriteTag()
preserved_invariants: N/A""",
        symbol_evidence=_evidence("cmsWriteTag"),
    )

    assert report["primary_success_quality"] == "direct_struct_field_write"
    assert report["needs_manual_review"] is True
    assert "profile.UsedEntries" in report["evidence"]["direct_struct_writes"]


def test_contract_alignment_is_orthogonal_to_public_api_quality() -> None:
    code = """
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    cmsMLUsetWide(0, "en", "US", L"value");
    return 0;
}
"""
    report = analyze_target_quality(
        code=code,
        evaluation=_runtime_success(),
        strategy_contract="""required_state: MLU UsedEntries must be manually adjusted
state_constructor: directly write mlu->UsedEntries
trigger_api: AddMLUBlock()
preserved_invariants: keep the MLU structure valid""",
        symbol_evidence=_evidence("cmsMLUsetWide", "AddMLUBlock"),
    )

    assert report["contract_code_alignment"] == "mismatch"
    assert report["primary_success_quality"] == "public_api_with_harness_state"
    assert "internal_api_direct" not in report["success_quality_labels"]


def test_contract_and_comments_are_not_counted_as_code_signals() -> None:
    code = """
/* BLOCKER_STRATEGY_CONTRACT
required_state: direct _cmsPrivate() and obj->field mutation
state_constructor: _cmsPrivate()
trigger_api: cmsPublic()
preserved_invariants: N/A
END_BLOCKER_STRATEGY_CONTRACT */
// _cmsPrivate();
/* obj->field = 1; */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    cmsPublic();
    return 0;
}
"""
    report = analyze_target_quality(
        code=code,
        evaluation=_runtime_success(),
        strategy_contract="""required_state: direct _cmsPrivate() and obj->field mutation
state_constructor: _cmsPrivate()
trigger_api: cmsPublic()
preserved_invariants: N/A""",
        symbol_evidence=_evidence("cmsPublic"),
    )

    assert report["evidence"]["internal_api_calls"] == []
    assert report["evidence"]["direct_struct_writes"] == []
