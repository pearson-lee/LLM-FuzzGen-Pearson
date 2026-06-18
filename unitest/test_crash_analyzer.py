import unittest
import sys
import types

sys.modules.setdefault("prompts", types.ModuleType("prompts"))
sys.modules.setdefault("prompts.prompt_generator", types.ModuleType("prompts.prompt_generator"))
sys.modules.setdefault("external.oss_fuzz", types.ModuleType("external.oss_fuzz"))
sys.modules["external.oss_fuzz"].OSSFuzz = object
sys.modules.setdefault("llm_interface.llm_client", types.ModuleType("llm_interface.llm_client"))
sys.modules["llm_interface.llm_client"].LLMClient = object
from crash_analyzer.crash_analyzer import CrashAnalyzer, CrashHeuristicTriage


class CrashStackFrameParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = CrashAnalyzer.__new__(CrashAnalyzer)

    def test_classifies_fuzz_target_frame_with_source_location(self) -> None:
        trace = """
    #0 0x55d83e7 in LLVMFuzzerTestOneInput /src/project/llm_fuzzgen1234567890.cc:42:7
    #1 0x55d83f0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
"""
        source, function, classification = self.analyzer._parse_stack_frames(
            trace, "llm_fuzzgen1234567890.cc"
        )

        self.assertEqual(source, "/src/project/llm_fuzzgen1234567890.cc:42:7")
        self.assertEqual(function, "LLVMFuzzerTestOneInput")
        self.assertEqual(classification, "fuzz_target")

    def test_classifies_library_frame_after_runtime_frame(self) -> None:
        trace = """
    #0 0x55d83e7 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3
    #1 0x55d83f0 in cJSON_ParseWithOpts /src/cjson/cJSON.c:1109:18
    #2 0x55d8400 in LLVMFuzzerTestOneInput /src/project/llm_fuzzgen1234567890.cc:33:5
"""
        source, function, classification = self.analyzer._parse_stack_frames(
            trace, "llm_fuzzgen1234567890.cc"
        )

        self.assertEqual(source, "/src/cjson/cJSON.c:1109:18")
        self.assertEqual(function, "cJSON_ParseWithOpts")
        self.assertEqual(classification, "library")

    def test_preserves_cpp_demangled_function_with_spaces(self) -> None:
        trace = """
    #0 0x55d83e7 in std::__1::vector<int, std::__1::allocator<int> >::operator[](unsigned long) const /src/libvpx/vp9/decoder/foo.cc:88:12
    #1 0x55d83f0 in LLVMFuzzerTestOneInput /src/project/llm_fuzzgen1234567890.cc:20:3
"""
        source, function, classification = self.analyzer._parse_stack_frames(
            trace, "llm_fuzzgen1234567890.cc"
        )

        self.assertEqual(source, "/src/libvpx/vp9/decoder/foo.cc:88:12")
        self.assertEqual(
            function,
            "std::__1::vector<int, std::__1::allocator<int> >::operator[](unsigned long) const",
        )
        self.assertEqual(classification, "library")


class CrashAnalysisSchemaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = CrashAnalyzer.__new__(CrashAnalyzer)

    def _base_analysis(self) -> dict:
        return {
            "finding": "Real Crash",
            "crash_type": "heap-buffer-overflow",
            "crash_site": "library",
            "crash_function": "parse_input",
            "reasoning_summary": "The crash occurs in library code.",
            "suggested_fix": "Check the buffer length before reading.",
            "evidence": ["#0 in parse_input /src/project/parser.c:10:3"],
            "confidence": 0.9,
        }

    def _triage(self) -> CrashHeuristicTriage:
        return CrashHeuristicTriage(
            finding="Real Crash",
            crash_type="heap-buffer-overflow",
            crash_site="library",
            suspected_fuzzer_bug=False,
            confidence=0.7,
            rationale=[],
            frame_classification="library",
        )

    def test_valid_rubric_scores_are_kept_and_total_is_recomputed(self) -> None:
        analysis = self._base_analysis()
        analysis["rubric_scores"] = {
            "top_frame_ownership": {"score": 2, "evidence": "#0 /src/project/parser.c:10:3"},
            "api_contract": {"score": 2, "evidence": "fuzzer calls parse_input with valid pointer"},
            "normal_caller_feasibility": {"score": 1, "evidence": "no normal caller found in /src/"},
            "sanitizer_signal": {"score": 1, "evidence": "heap-buffer-overflow"},
            "reproducibility": {"score": 1, "evidence": "reproduced by oss-fuzz"},
            "total": 999,
        }

        validated = self.analyzer._validate_analysis_schema(analysis)

        self.assertIsNotNone(validated)
        self.assertEqual(validated["rubric_scores"]["total"], 7)
        self.assertNotIn("validation_warnings", validated)

    def test_invalid_rubric_score_range_is_removed_and_triggers_audit(self) -> None:
        analysis = self._base_analysis()
        analysis["rubric_scores"] = {
            "top_frame_ownership": {"score": 2, "evidence": "#0 /src/project/parser.c:10:3"},
            "api_contract": {"score": 2, "evidence": "fuzzer calls parse_input with valid pointer"},
            "normal_caller_feasibility": {"score": 1, "evidence": "no normal caller found in /src/"},
            "sanitizer_signal": {"score": 2, "evidence": "heap-buffer-overflow"},
            "reproducibility": {"score": 1, "evidence": "reproduced by oss-fuzz"},
        }

        validated = self.analyzer._validate_analysis_schema(analysis)

        self.assertIsNotNone(validated)
        self.assertNotIn("rubric_scores", validated)
        self.assertIn("validation_warnings", validated)
        self.assertIn("sanitizer_signal", validated["validation_warnings"][0])
        self.assertTrue(CrashAnalyzer._needs_audit(validated, self._triage()))

    def test_reproduce_summary_marks_empty_stack_trace_as_failed(self) -> None:
        summary = CrashAnalyzer._build_reproduce_summary("")

        self.assertTrue(summary["attempted"])
        self.assertFalse(summary["succeeded"])
        self.assertIn("empty stack trace", summary["evidence"])

    def test_reproducibility_score_must_match_reproduce_summary(self) -> None:
        analysis = self._base_analysis()
        analysis["rubric_scores"] = {
            "top_frame_ownership": {"score": 2, "evidence": "#0 /src/project/parser.c:10:3"},
            "api_contract": {"score": 2, "evidence": "fuzzer calls parse_input with valid pointer"},
            "normal_caller_feasibility": {"score": 1, "evidence": "no normal caller found in /src/"},
            "sanitizer_signal": {"score": 1, "evidence": "heap-buffer-overflow"},
            "reproducibility": {"score": 1, "evidence": "reproduced by oss-fuzz"},
        }
        reproduce_summary = {
            "attempted": True,
            "succeeded": False,
            "evidence": "oss_fuzz.reproduce_crash returned an empty stack trace",
        }

        validated = self.analyzer._validate_analysis_schema(
            analysis,
            reproduce_summary=reproduce_summary,
        )

        self.assertIsNotNone(validated)
        self.assertNotIn("rubric_scores", validated)
        self.assertIn("validation_warnings", validated)
        self.assertIn("reproducibility", validated["validation_warnings"][0])
        self.assertTrue(CrashAnalyzer._needs_audit(validated, self._triage()))


if __name__ == "__main__":
    unittest.main()
