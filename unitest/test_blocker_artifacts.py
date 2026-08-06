import hashlib
import re

from blocker_process.blocker_artifacts import (
    blocker_artifact_id,
    blocker_log_filename,
    blocker_stage_artifact_name,
)


LONG_MANGLED_FUNCTION = (
    "_ZN4toml2v35table16insert_or_assignIRKNS0_3keyERA17_KcTnNSt3__19enable_ifIXoo"
    "21is_key_or_convertibleIOT_Esr4implE14is_wide_stringISB_EEiE4typeELi0EEENS9_"
    "4pairINS0_4impl14table_iteratorILb0EEEbEESC_OT0_NS0_11value_flagsE"
)


def test_blocker_artifact_id_uses_line_and_short_function_hash() -> None:
    blocker_id = blocker_artifact_id(LONG_MANGLED_FUNCTION, 8635)

    expected_hash = hashlib.sha256(LONG_MANGLED_FUNCTION.encode("utf-8")).hexdigest()[:12]
    assert blocker_id == f"blocker_8635_{expected_hash}"
    assert re.fullmatch(r"blocker_8635_[0-9a-f]{12}", blocker_id)
    assert LONG_MANGLED_FUNCTION not in blocker_id
    assert len(blocker_id) < 32


def test_stage_dir_and_log_filename_keep_raw_function_out_of_path_components() -> None:
    stage_name = blocker_stage_artifact_name(
        "tomlplusplus",
        LONG_MANGLED_FUNCTION,
        8635,
        "20260805_120000",
        "input_independent",
    )
    log_name = blocker_log_filename(
        LONG_MANGLED_FUNCTION,
        8635,
        "20260805_120000",
        "classifier",
    )

    assert stage_name.startswith("tomlplusplus_blocker_8635_")
    assert stage_name.endswith("_input_independent_20260805_120000")
    assert log_name.startswith("20260805_120000_blocker_8635_")
    assert log_name.endswith("_classifier.log")
    assert LONG_MANGLED_FUNCTION not in stage_name
    assert LONG_MANGLED_FUNCTION not in log_name
