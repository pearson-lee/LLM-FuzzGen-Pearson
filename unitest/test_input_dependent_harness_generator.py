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


def _write_runtime_ownership_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    target = tmp_path / "target.c"
    target.write_text(
        "void helper(const unsigned char *data, unsigned long size) {\n"
        "    sut_entry(data, size);\n"
        "}\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "    helper(data, size);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    source_root = tmp_path / "session" / "source_root"
    sut_source = source_root / "src" / "library.c"
    sut_source.parent.mkdir(parents=True)
    sut_source.write_text(
        "int sut_entry(const unsigned char *data, unsigned long size);\n"
        "\n"
        "int sut_entry(const unsigned char *data, unsigned long size)\n"
        "{\n"
        "    return size > 0 && data != 0;\n"
        "}\n"
        "\n"
        "int blocked_function(void)\n"
        "{\n"
        "    return 1;\n"
        "}\n",
        encoding="utf-8",
    )
    segment = (
        "Runtime functions from entry to blocker (Root -> Target, deduplicated):\n"
        "  #0 LLVMFuzzerTestOneInput at /src/target.c:5\n"
        "  #1 helper at /src/target.c:2\n"
        "  #2 sut_entry at /src/demo/src/library.c:5\n"
        "  #3 blocked_function at library.c:10\n"
    )
    return target, sut_source, segment


def test_semantic_validator_accepts_inlined_target_helper(tmp_path: Path) -> None:
    target, sut_source, segment = _write_runtime_ownership_fixture(tmp_path)
    generated = (
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "    return sut_entry(data, size);\n"
        "}\n"
    )

    errors = harness_generator.validate_harness_semantics(
        original_code=target.read_text(encoding="utf-8"),
        generated_code=generated,
        runtime_blocker_segment=segment,
        project_name="demo",
        original_source_path=str(target),
        blocker_source_path=str(sut_source),
    )

    assert errors == []


def test_semantic_validator_rejects_harness_without_observed_sut_calls(tmp_path: Path) -> None:
    target, sut_source, segment = _write_runtime_ownership_fixture(tmp_path)
    generated = (
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
        "    unrelated_api(data, size);\n"
        "    return 0;\n"
        "}\n"
    )

    errors = harness_generator.validate_harness_semantics(
        original_code=target.read_text(encoding="utf-8"),
        generated_code=generated,
        runtime_blocker_segment=segment,
        project_name="demo",
        original_source_path=str(target),
        blocker_source_path=str(sut_source),
    )

    assert len(errors) == 1
    assert "source-grounded SUT call" in errors[0]
    assert "sut_entry" in errors[0]


def test_runtime_source_ownership_uses_definition_containing_gdb_line(tmp_path: Path) -> None:
    target, sut_source, segment = _write_runtime_ownership_fixture(tmp_path)

    evidence = harness_generator.classify_runtime_segment_sources(
        segment,
        "demo",
        str(target),
        str(sut_source),
    )

    owners = {item["short_function"]: item["owner"] for item in evidence}
    assert owners["LLVMFuzzerTestOneInput"] == "target_local"
    assert owners["helper"] == "target_local"
    assert owners["sut_entry"] == "sut"
    assert owners["blocked_function"] == "sut"


def test_semantic_validator_does_not_reject_unknown_runtime_source(tmp_path: Path) -> None:
    target = tmp_path / "target.c"
    original = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n"
    target.write_text(original, encoding="utf-8")
    segment = (
        "Runtime functions from entry to blocker (Root -> Target, deduplicated):\n"
        "  #0 LLVMFuzzerTestOneInput at /src/target.c:1\n"
        "  #1 unresolved_dispatch at unknown_generated_file.c:99\n"
    )

    errors = harness_generator.validate_harness_semantics(
        original_code=original,
        generated_code=original,
        runtime_blocker_segment=segment,
        project_name="demo",
        original_source_path=str(target),
        blocker_source_path=None,
    )

    assert errors == []


def test_runtime_source_ownership_keeps_ambiguous_basename_unknown(tmp_path: Path) -> None:
    target = tmp_path / "target.c"
    target.write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n",
        encoding="utf-8",
    )
    source_root = tmp_path / "session" / "source_root"
    first = source_root / "first" / "duplicate.c"
    second = source_root / "second" / "duplicate.c"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    definition = "int ambiguous_function(void)\n{\n    return 1;\n}\n"
    first.write_text(definition, encoding="utf-8")
    second.write_text(definition, encoding="utf-8")
    segment = (
        "Runtime functions from entry to blocker (Root -> Target, deduplicated):\n"
        "  #0 LLVMFuzzerTestOneInput at /src/target.c:1\n"
        "  #1 ambiguous_function at duplicate.c:3\n"
    )

    evidence = harness_generator.classify_runtime_segment_sources(
        segment,
        "demo",
        str(target),
        str(first),
    )

    assert evidence[1]["owner"] == "unknown"
    assert evidence[1]["resolved_file"] is None
