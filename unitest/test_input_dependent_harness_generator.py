from pathlib import Path
from types import SimpleNamespace

from external.oss_fuzz import CompilationResult
import blocker_process.dependent.input_dependent_harness_generator as harness_generator


class FakeOSSFuzz:
    def __init__(self, root: Path, runtime_success: bool = True) -> None:
        self.root = root
        self.build_corpus_dir = root / "corpus"
        self.runtime_success = runtime_success
        self.removed_targets: list[str] = []
        self.run_calls: list[dict] = []

    def save_named_target(self, project_name: str, code: str, stem_prefix: str) -> Path:
        target = self.root / f"{stem_prefix}.c"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        return target

    def ensure_target_binary(self, project_name: str, target_name: str, sanitizer: str = "address"):
        return CompilationResult(success=True)

    def built_target_binary(self, project_name: str, target_name: str) -> Path:
        binary = self.root / "out" / project_name / target_name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"binary")
        return binary

    def run_fuzzer(self, **kwargs):
        self.run_calls.append(kwargs)
        corpus = self.build_corpus_dir / kwargs["proj_name"] / kwargs["fuzzer_name"]
        (corpus / "generated_mutation").write_bytes(b"mutation")
        error = "ERROR: AddressSanitizer: heap-use-after-free" if not self.runtime_success else ""
        return CompilationResult(success=self.runtime_success, error=error)

    def remove_target(self, project_name: str, target_name: str) -> None:
        self.removed_targets.append(target_name)


def test_native_harness_gate_replays_selected_seeds_without_rebuild(tmp_path: Path, monkeypatch) -> None:
    first = tmp_path / "first.seed"
    second = tmp_path / "second.seed"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    fake = FakeOSSFuzz(tmp_path)
    monkeypatch.setattr(harness_generator, "OSSFuzz", lambda: fake)
    args = SimpleNamespace(
        project_name="demo",
        function_name="blocked",
        runtime_sanity_seed=[str(first), str(second)],
    )

    failure_kind, details, metadata = harness_generator.run_harness_native_build_gate(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }",
        args,
        tmp_path / "result",
    )

    assert failure_kind is None
    assert details == ""
    assert metadata["runtime_sanity"]["success"] is True
    assert metadata["runtime_sanity"]["seed_count"] == 2
    assert metadata["runtime_sanity"]["generated_corpus_count"] == 1
    assert metadata["runtime_sanity"]["corpus_restored"] is True
    assert fake.run_calls[0]["build_fuzzer"] is False
    corpus = fake.build_corpus_dir / "demo" / metadata["native_target_name"]
    assert sorted(path.read_bytes() for path in corpus.iterdir()) == [b"first", b"second"]


def test_native_harness_gate_rejects_sanitizer_failure(tmp_path: Path, monkeypatch) -> None:
    seed = tmp_path / "trigger.seed"
    seed.write_bytes(b"trigger")
    fake = FakeOSSFuzz(tmp_path, runtime_success=False)
    monkeypatch.setattr(harness_generator, "OSSFuzz", lambda: fake)
    args = SimpleNamespace(
        project_name="demo",
        function_name="blocked",
        runtime_sanity_seed=[str(seed)],
    )

    failure_kind, details, metadata = harness_generator.run_harness_native_build_gate(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }",
        args,
        tmp_path / "result",
    )

    assert failure_kind == "runtime_sanity_invalid"
    assert "heap-use-after-free" in details
    assert metadata == {}
    assert fake.removed_targets
    assert (tmp_path / "result" / "runtime_sanity.json").is_file()


def test_buildkit_snapshot_failure_is_classified_as_infrastructure_error() -> None:
    details = (
        'failed to prepare extraction snapshot "extract-123": '
        "parent snapshot sha256:abc does not exist"
    )

    assert harness_generator._is_native_build_infrastructure_error(details)
    assert not harness_generator._is_native_build_infrastructure_error(
        "error: 'lcms2.h' file not found"
    )
