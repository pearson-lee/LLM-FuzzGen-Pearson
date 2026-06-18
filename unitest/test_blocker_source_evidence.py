from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from blocker_process.blocker_source_evidence import (
    collect_symbol_evidence,
    render_symbol_evidence_for_prompt,
)
from blocker_process.independent.input_independent_solver import collect_prompt_context


def _synthetic_project(tmp_path: Path) -> tuple[Path, Path]:
    header = tmp_path / "include" / "widget.h"
    source = tmp_path / "src" / "widget.c"
    header.parent.mkdir(parents=True)
    source.parent.mkdir(parents=True)
    header.write_text(
        """typedef struct Widget* WidgetHandle;
WidgetHandle widget_create(void);
void widget_set_mode(WidgetHandle handle, int mode);
int widget_ready(WidgetHandle handle, int mode);
#ifdef OPTIONAL_WIDGET
void widget_optional(WidgetHandle handle);
#endif
""",
        encoding="utf-8",
    )
    source.write_text(
        """#include \"widget.h\"
int blocker(WidgetHandle handle, int mode)
{
    if (!widget_ready(handle, mode))
        return 0;
    return mode;
}
""",
        encoding="utf-8",
    )
    return header, source


def test_symbol_evidence_finds_public_constructor_and_setter(tmp_path: Path) -> None:
    header, source = _synthetic_project(tmp_path)
    files = [str(header), str(source)]
    with (
        patch("blocker_process.blocker_source_evidence.collect_project_source_files", return_value=(files, [])),
        patch("blocker_process.blocker_source_evidence.resolve_project_source_file", return_value=str(source)),
        patch("blocker_process.blocker_source_evidence.load_build_macro_facts", return_value={}),
    ):
        evidence = collect_symbol_evidence(
            project_name="widget",
            function_name="blocker",
            source_file=str(source),
            header_file=str(header),
            blocker_line_code="if (widget_optional(handle), !widget_ready(handle, mode))",
            blocked_side_line_code="return mode;",
            branch_window="",
            blocked_window="",
        )

    by_symbol = {entry["symbol"]: entry for entry in evidence["entries"]}
    assert by_symbol["widget_create"]["kind"] == "declaration"
    assert by_symbol["widget_create"]["visibility"] == "public"
    assert by_symbol["widget_set_mode"]["relation"].startswith("declaration_uses_predicate_type")
    assert by_symbol["widget_ready"]["kind"] in {"definition", "declaration", "callsite"}


def test_symbol_evidence_marks_unresolved_preprocessor_as_unknown(tmp_path: Path) -> None:
    header, source = _synthetic_project(tmp_path)
    files = [str(header), str(source)]
    with (
        patch("blocker_process.blocker_source_evidence.collect_project_source_files", return_value=(files, [])),
        patch("blocker_process.blocker_source_evidence.resolve_project_source_file", return_value=str(source)),
        patch("blocker_process.blocker_source_evidence.load_build_macro_facts", return_value={}),
    ):
        evidence = collect_symbol_evidence(
            project_name="widget",
            function_name="blocker",
            source_file=str(source),
            header_file=str(header),
            blocker_line_code="if (!widget_ready(handle, mode))",
            blocked_side_line_code="return mode;",
            branch_window="",
            blocked_window="",
        )

    optional = [entry for entry in evidence["entries"] if entry["symbol"] == "widget_optional"]
    assert optional
    assert optional[0]["preprocessor_status"] == "unknown"


def test_lcms_evidence_reaches_api_declarations_beyond_old_header_clip() -> None:
    source = Path("external/oss-fuzz/build/out/lcms/source_code/src/cmssamp.c")
    header = Path("external/oss-fuzz/build/out/lcms/source_code/include/lcms2.h")
    if not source.is_file() or not header.is_file():
        pytest.skip("lcms build source mirror is unavailable")

    evidence = collect_symbol_evidence(
        project_name="lcms",
        function_name="cmsDetectDestinationBlackPoint",
        source_file=str(source),
        header_file=str(header),
        blocker_line_code="if (!cmsIsCLUT(hProfile, Intent, LCMS_USED_AS_OUTPUT) ||",
        blocked_side_line_code="if (Intent == INTENT_RELATIVE_COLORIMETRIC) {",
        branch_window="",
        blocked_window="",
    )
    rendered = render_symbol_evidence_for_prompt(evidence)

    for symbol in (
        "cmsCreateProfilePlaceholder",
        "cmsPipelineAlloc",
        "cmsStageAllocCLut16bit",
        "cmsSetHeaderRenderingIntent",
    ):
        assert symbol in rendered


def test_prompt_context_replaces_fixed_header_and_source_dumps() -> None:
    source = Path("external/oss-fuzz/build/out/lcms/source_code/src/cmssamp.c")
    header = Path("external/oss-fuzz/build/out/lcms/source_code/include/lcms2.h")
    fuzz_file = Path("external/oss-fuzz/projects/lcms")
    candidates = sorted(fuzz_file.glob("*.cc")) + sorted(fuzz_file.glob("*.c"))
    if not source.is_file() or not header.is_file() or not candidates:
        pytest.skip("lcms focused artifacts are unavailable")

    args = SimpleNamespace(
        project_name="lcms",
        function_name="cmsDetectDestinationBlackPoint",
        branch_line_number=403,
        blocked_side_line_number=416,
        source_file=str(source),
        header_file=str(header),
        fuzz_file=str(candidates[0]),
        language="c",
        blocker_line_code="if (!cmsIsCLUT(hProfile, Intent, LCMS_USED_AS_OUTPUT) ||",
        blocked_side_line_code="if (Intent == INTENT_RELATIVE_COLORIMETRIC) {",
        runtime_blocker_segment_file=None,
        runtime_blocker_segment=None,
        runtime_blocker_segment_source_codes_file=None,
        runtime_blocker_segment_source_codes=None,
        cfg_call_chain_file=None,
        cfg_call_chain=None,
        cfg_source_codes_file=None,
        cfg_source_codes=None,
        blocker_call_sites_file=None,
        blocker_call_sites=None,
        triggering_input="",
    )
    oss_fuzz = SimpleNamespace(proj_lang=lambda _project: "c")

    context = collect_prompt_context(args, oss_fuzz)

    assert context["source_code"] == "N/A: replaced by targeted symbol evidence."
    assert context["header_code"] == "N/A: replaced by targeted symbol evidence."
    assert "cmsPipelineAlloc" in context["symbol_evidence"]
