import json
import unittest
from unittest.mock import Mock

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

    def _analysis_with_passing_gates(self) -> dict:
        analysis = self._base_analysis()
        analysis.update(
            {
                "api_contract_violation": "",
                "missing_evidence": [],
                "minimized_poc": "",
                "reproduce_result": {"succeeded": True},
                "rubric_scores": {
                    "top_frame_ownership": {"score": 2, "evidence": "library frame"},
                    "api_contract": {"score": 2, "evidence": "valid API arguments"},
                    "normal_caller_feasibility": {"score": 2, "evidence": "normal caller"},
                    "sanitizer_signal": {"score": 1, "evidence": "memory error"},
                    "reproducibility": {"score": 1, "evidence": "reproduced"},
                    "total": 8,
                },
            }
        )
        return analysis

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

    def test_api_contract_violation_blocks_real_crash_status(self) -> None:
        analysis = self._analysis_with_passing_gates()
        analysis["api_contract_violation"] = "row_mt must be 0 or 1"
        analysis["rubric_scores"]["api_contract"]["score"] = 0

        CrashAnalyzer._apply_final_status(analysis)

        self.assertEqual(analysis["final_status"], "FP")
        self.assertIn("API contract", analysis["final_status_reason"])

    def test_null_pc_without_minimized_valid_poc_is_tbd(self) -> None:
        analysis = self._analysis_with_passing_gates()
        trace = "AddressSanitizer: SEGV\n#0 0x0  (<unknown module>)"

        CrashAnalyzer._apply_final_status(analysis, trace)

        self.assertEqual(analysis["final_status"], "TBD")
        self.assertIn("independent valid-PoC replay", analysis["final_status_reason"])
        self.assertTrue(CrashAnalyzer._needs_audit(analysis, self._triage(), trace))

    def test_real_crash_passes_only_after_all_hard_gates(self) -> None:
        analysis = self._analysis_with_passing_gates()

        CrashAnalyzer._apply_final_status(
            analysis,
            "#0 0x123 in parse_input /src/project/parser.c:10:3",
        )

        self.assertEqual(analysis["final_status"], "TP")

    def test_audit_can_demote_a_confidence_one_real_crash(self) -> None:
        self.assertTrue(
            CrashAnalyzer._should_adopt_audit_revision(
                "Real Crash",
                "Fuzzer Logic Error",
                1.0,
                0.9,
            )
        )

    def test_audit_requires_stronger_evidence_to_promote_to_real_crash(self) -> None:
        self.assertFalse(
            CrashAnalyzer._should_adopt_audit_revision(
                "Fuzzer Logic Error",
                "Real Crash",
                0.8,
                0.9,
            )
        )

    def test_audit_demotion_changes_final_status_to_fp(self) -> None:
        analyzer = CrashAnalyzer.__new__(CrashAnalyzer)
        analyzer.oss_fuzz = Mock()
        analyzer.oss_fuzz.proj_lang.return_value = "c++"
        initial = self._analysis_with_passing_gates()
        initial["confidence"] = 1.0
        audit = {
            "audit_answers": {
                "Q1": "row_mt=1254310399",
                "Q2": "vp8dx.h restricts row_mt to 0 or 1",
                "Q3": "the fuzzer ignores the failed control call",
                "Q4": "the original explanation contradicts source order",
                "Q5": "not found in /src/",
                "Q6": "not found",
                "Q7": "",
            },
            "revised_finding": "Fuzzer Logic Error",
            "revised_confidence": 0.9,
            "revision_rationale": "The seed violates the row_mt API contract.",
            "missing_evidence": [],
        }
        analyzer.llm_client = Mock()
        analyzer.llm_client.generate.side_effect = [json.dumps(initial), json.dumps(audit)]
        trace = (
            "AddressSanitizer: SEGV on unknown address 0x000000000000\n"
            "#0 0x0 (<unknown module>)\n"
            "#1 0x123 in decode_one /src/libvpx/vp9/vp9_dx_iface.c:328:7"
        )

        result = analyzer._get_llm_analysis(
            "libvpx",
            "int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);",
            b"seed",
            trace,
            self._triage(),
            reproduce_summary={"succeeded": True, "evidence": "reproduced"},
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["finding"], "Fuzzer Logic Error")
        CrashAnalyzer._apply_final_status(result, trace)
        self.assertEqual(result["final_status"], "FP")


if __name__ == "__main__":
    unittest.main()
