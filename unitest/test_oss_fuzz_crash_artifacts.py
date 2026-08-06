import hashlib
import json
from pathlib import Path

from external.oss_fuzz import HelperCommandResult, OSSFuzz


class _FakeArtifactOSSFuzz(OSSFuzz):
    def __init__(self, tmp_path: Path, helper_result_success: bool, log_text: str):
        super().__init__(oss_fuzz_dir=tmp_path / "oss-fuzz")
        self.build_corpus_dir = tmp_path / "corpus"
        self.build_out_dir = tmp_path / "out"
        self.helper_result_success = helper_result_success
        self.log_text = log_text
        self.helper_args = []

    def _run_helper_command(self, args, timeout=None, extra_env=None, output_log_path=None, tail_bytes=None):
        self.helper_args.append(args)
        if output_log_path is not None:
            output_log_path.parent.mkdir(parents=True, exist_ok=True)
            output_log_path.write_text(self.log_text, encoding="utf-8")
        return HelperCommandResult(
            self.helper_result_success,
            self.log_text,
            "",
            output_log_path=str(output_log_path) if output_log_path else "",
        )


def test_run_fuzzer_recovers_crash_seed_from_log_base64(tmp_path):
    artifact_name = "llm_fuzzgen_demo_crash-0123456789abcdef0123456789abcdef01234567"
    log_text = (
        "==15==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo.c:1:1 in demo\n"
        f"artifact_prefix='llm_fuzzgen_demo_'; Test unit written to {artifact_name}\n"
        "Base64: aGk=\n"
    )
    oss_fuzz = _FakeArtifactOSSFuzz(tmp_path, False, log_text)
    crash_dir = tmp_path / "crash_seeds"

    result = oss_fuzz.run_fuzzer(
        "demo",
        "llm_fuzzgen_demo",
        seconds=1,
        build_fuzzer=False,
        crash_artifact_dir=crash_dir,
    )

    saved_seed = crash_dir / "demo" / "llm_fuzzgen_demo" / artifact_name
    metadata = json.loads((saved_seed.parent / f"{artifact_name}.metadata.json").read_text(encoding="utf-8"))

    assert not result.success
    assert saved_seed.read_bytes() == b"hi"
    assert metadata["seed_source"] == "log_base64"
    assert metadata["seed_sha1"] == hashlib.sha1(b"hi").hexdigest()
    assert metadata["summary"]["summary"].startswith("SUMMARY: AddressSanitizer")


def test_run_fuzzer_caps_noisy_log_but_scans_tail_for_artifacts(tmp_path):
    artifact_name = "llm_fuzzgen_demo_crash-abcdefabcdefabcdefabcdefabcdefabcdefabcd"
    log_tail = (
        "==15==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo.c:1:1 in demo\n"
        f"artifact_prefix='llm_fuzzgen_demo_'; Test unit written to {artifact_name}\n"
        "Base64: aGk=\n"
    )
    log_text = ("noisy formatter output\n" * 300) + log_tail
    oss_fuzz = _FakeArtifactOSSFuzz(tmp_path, False, log_text)
    oss_fuzz.RUN_FUZZER_LOG_MAX_BYTES = 1024
    oss_fuzz.RUN_FUZZER_LOG_PRESERVED_TAIL_BYTES = 512
    oss_fuzz.RUN_FUZZER_ARTIFACT_SCAN_TAIL_BYTES = 512
    crash_dir = tmp_path / "crash_seeds"

    result = oss_fuzz.run_fuzzer(
        "demo",
        "llm_fuzzgen_demo",
        seconds=1,
        build_fuzzer=False,
        crash_artifact_dir=crash_dir,
    )

    saved_seed = crash_dir / "demo" / "llm_fuzzgen_demo" / artifact_name
    metadata = json.loads((saved_seed.parent / f"{artifact_name}.metadata.json").read_text(encoding="utf-8"))
    capped_log = Path(metadata["run_fuzzer_log"])

    assert not result.success
    assert saved_seed.read_bytes() == b"hi"
    assert capped_log.stat().st_size <= oss_fuzz.RUN_FUZZER_LOG_MAX_BYTES
    assert "noisy_fuzzer_output" in capped_log.read_text(encoding="utf-8", errors="ignore")
    assert metadata["run_fuzzer_log_status"] == "noisy_fuzzer_output"
    assert metadata["run_fuzzer_log_truncated"] is True
    assert metadata["run_fuzzer_log_original_bytes"] == len(log_text.encode("utf-8"))
    assert metadata["seed_source"] == "log_base64"


class _ReplayCorpusOSSFuzz(_FakeArtifactOSSFuzz):
    def __init__(self, tmp_path: Path):
        super().__init__(tmp_path, True, "")
        self.last_corpus_dir = None

    def _list_project_fuzzers(self, project_name):
        return ["llm_fuzzgen_demo"]

    def _run_helper_command(self, args, timeout=None, extra_env=None, output_log_path=None, tail_bytes=None):
        self.helper_args.append(args)
        corpus_arg = next(arg for arg in args if arg.startswith("--corpus-dir="))
        self.last_corpus_dir = Path(corpus_arg.split("=", 1)[1])
        (self.last_corpus_dir / "new_seed").write_bytes(b"would mutate corpus")
        if output_log_path is not None:
            output_log_path.parent.mkdir(parents=True, exist_ok=True)
            output_log_path.write_text("", encoding="utf-8")
        return HelperCommandResult(True, "", "", output_log_path=str(output_log_path) if output_log_path else "")


def test_replay_uses_temporary_corpus_snapshot_without_growing_original(tmp_path):
    oss_fuzz = _ReplayCorpusOSSFuzz(tmp_path)
    original_corpus = oss_fuzz.build_corpus_dir / "demo" / "llm_fuzzgen_demo"
    original_corpus.mkdir(parents=True)
    (original_corpus / "seed").write_bytes(b"seed")

    results = oss_fuzz.replay_all_fuzzer_corpora("demo", timeout_per_fuzzer=1)

    assert len(results) == 1
    assert results[0].success
    assert (original_corpus / "seed").read_bytes() == b"seed"
    assert not (original_corpus / "new_seed").exists()
    assert oss_fuzz.last_corpus_dir != original_corpus
    assert not oss_fuzz.last_corpus_dir.exists()
    assert " -runs=0 -reload=0 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 " in oss_fuzz.helper_args[0]
