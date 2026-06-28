import logging
import time

from external.oss_fuzz import CompilationResult, FuzzerTimeSliceResult, HelperCommandResult, OSSFuzz


class _FakeRunFuzzerOSSFuzz(OSSFuzz):
    def __init__(self, tmp_path, helper_result):
        super().__init__()
        self.build_corpus_dir = tmp_path / "corpus"
        self.helper_result = helper_result
        self.helper_timeouts = []
        self.helper_args = []

    def _run_helper_command(self, args, timeout=None, extra_env=None, output_log_path=None, tail_bytes=None):
        self.helper_args.append(args)
        self.helper_timeouts.append(timeout)
        return self.helper_result


def test_run_fuzzer_timeout_is_bound_to_slice_not_run_deadline(tmp_path):
    oss_fuzz = _FakeRunFuzzerOSSFuzz(tmp_path, HelperCommandResult(True, "", ""))
    oss_fuzz.DEFAULT_FUZZER_TIMEOUT_BUFFER_SECONDS = 7

    deadline = time.monotonic() + 1000
    result = oss_fuzz.run_fuzzer(
        "demo",
        "llm_fuzzgen_demo",
        seconds=11,
        build_fuzzer=False,
        deadline=deadline,
    )

    assert result.success
    assert 17.0 <= oss_fuzz.helper_timeouts[0] <= 18.5
    assert " -max_total_time=11 " in oss_fuzz.helper_args[0]


def test_run_fuzzer_timeout_reports_fuzzer_timeout(tmp_path):
    oss_fuzz = _FakeRunFuzzerOSSFuzz(tmp_path, HelperCommandResult(False, "", "timed out", timed_out=True))
    oss_fuzz.DEFAULT_FUZZER_TIMEOUT_BUFFER_SECONDS = 7

    result = oss_fuzz.run_fuzzer(
        "demo",
        "llm_fuzzgen_demo",
        seconds=11,
        build_fuzzer=False,
    )

    assert not result.success
    assert result.error == "fuzzer timeout"
    assert oss_fuzz.helper_timeouts[0] == 18


class _SlowDrainOSSFuzz(OSSFuzz):
    def __init__(self):
        super().__init__()
        self.DEFAULT_FUZZ_QUANTUM_SECONDS = 1
        self.DEFAULT_SCHEDULER_DRAIN_TIMEOUT_SECONDS = 0.01

    def build_fuzzers(self, *args, **kwargs):
        return CompilationResult(True, "")

    def _list_project_fuzzers(self, project_name):
        return ["llm_fuzzgen_slow"]

    def _run_fuzzer_time_slice(self, project_name, fuzzer_name, seconds, deadline=None):
        time.sleep(3)
        return FuzzerTimeSliceResult(
            fuzzer_name=fuzzer_name,
            requested_seconds=seconds,
            actual_seconds=3.0,
            success=True,
        )


def test_run_all_fuzzers_scheduled_has_bounded_drain(caplog):
    oss_fuzz = _SlowDrainOSSFuzz()

    started_at = time.monotonic()
    with caplog.at_level(logging.ERROR):
        oss_fuzz.run_all_fuzzers_scheduled("demo", seconds=2, max_workers=1)
    elapsed = time.monotonic() - started_at

    assert elapsed < 2.5
    assert "Fuzzer drain timeout" in caplog.text
