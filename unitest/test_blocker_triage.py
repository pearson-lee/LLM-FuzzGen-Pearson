import unittest
from unittest.mock import patch

from blocker_process.blocker_triage import extract_source_identifiers, run_triage_prompt


VALID_TRIAGE_JSON = """{
  "analysis_trace": [],
  "required_condition": "A legal public input must establish the required state.",
  "producer_path_status": "proven",
  "practical_feasibility": "practical",
  "refined_triage_label": "Actionable Target Gap",
  "required_solver_hint": "Use a legal API sequence.",
  "evidence_strength": "B",
  "classifier_agreement": "unclear",
  "source_overrides_classifier": false,
  "source_override_reason": "N/A",
  "cost_note": "test"
}"""


class FakeLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = iter(responses)
        self.calls = 0
        self.thread_ids = []

    def generate(self, _prompt: str, thread_id: int | None = None) -> str:
        self.calls += 1
        self.thread_ids.append(thread_id)
        return next(self.responses)


class BlockerTriageTest(unittest.TestCase):
    def test_short_c_identifiers_are_preserved(self) -> None:
        identifiers = extract_source_identifiers(
            "if ((int) mc < 0 || rc != 0 || fd < 0 || p == NULL || op == 1 || offset == NULL)"
        )

        for identifier in ("mc", "rc", "fd", "p", "op", "offset"):
            self.assertIn(identifier, identifiers)

    def test_invalid_json_retries_twice_then_succeeds(self) -> None:
        fake_llm = FakeLLM(["not json", "", VALID_TRIAGE_JSON])

        with (
            patch("llm_interface.llm_client.LLMClient", return_value=fake_llm),
            patch("blocker_process.blocker_triage.config.BLOCKER_TRIAGE_PARSE_MAX_RETRIES", 2, create=True),
            patch("blocker_process.blocker_triage.config.BLOCKER_TRIAGE_PARSE_RETRY_DELAY_SEC", 0, create=True),
        ):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(fake_llm.calls, 3)
        self.assertEqual(len(set(fake_llm.thread_ids)), 1)
        self.assertIsNotNone(fake_llm.thread_ids[0])
        self.assertEqual(result["triage_status"], "completed")
        self.assertEqual(result["llm_attempt_count"], 3)
        self.assertEqual(result["solver_action"], "run_solver")

    def test_invalid_json_after_retries_is_triage_error(self) -> None:
        fake_llm = FakeLLM(["not json", "still not json", ""])

        with (
            patch("llm_interface.llm_client.LLMClient", return_value=fake_llm),
            patch("blocker_process.blocker_triage.config.BLOCKER_TRIAGE_PARSE_MAX_RETRIES", 2, create=True),
            patch("blocker_process.blocker_triage.config.BLOCKER_TRIAGE_PARSE_RETRY_DELAY_SEC", 0, create=True),
        ):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(fake_llm.calls, 3)
        self.assertEqual(result["triage_status"], "triage_error")
        self.assertEqual(result["llm_attempt_count"], 3)
        self.assertEqual(result["solver_action"], "run_solver")
        self.assertTrue(result["review_required"])
        self.assertTrue(result["triage_error_reason"])

    def test_llm_cannot_forge_runtime_triage_error_status(self) -> None:
        forged = VALID_TRIAGE_JSON[:-1] + ', "triage_status": "triage_error"}'
        fake_llm = FakeLLM([forged])

        with patch("llm_interface.llm_client.LLMClient", return_value=fake_llm):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(result["triage_status"], "completed")
        self.assertIsNone(result["triage_error_reason"])

    def test_routing_is_derived_only_from_label(self) -> None:
        resource_evidence = VALID_TRIAGE_JSON.replace(
            '"practical_feasibility": "practical"',
            '"practical_feasibility": "resource_failure"',
        )
        legacy_conflict = resource_evidence[:-1] + (
            ', "first_layer_decision": "Generation-solvable",'
            ' "solver_action": "run_solver",'
            ' "refined_triage_label": "Resource-Exhaustion Guard"}'
        )
        fake_llm = FakeLLM([legacy_conflict])

        with patch("llm_interface.llm_client.LLMClient", return_value=fake_llm):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(result["first_layer_decision"], "Non-generation-solvable")
        self.assertEqual(result["solver_action"], "skip_solver")
        self.assertEqual(result["raw_first_layer_decision"], "Generation-solvable")
        self.assertEqual(result["raw_solver_action"], "run_solver")
        self.assertTrue(result["normalization_applied"])

    def test_inconclusive_label_fails_open(self) -> None:
        inconclusive = VALID_TRIAGE_JSON.replace("Actionable Target Gap", "Inconclusive")
        fake_llm = FakeLLM([inconclusive])

        with patch("llm_interface.llm_client.LLMClient", return_value=fake_llm):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(result["first_layer_decision"], "Inconclusive")
        self.assertEqual(result["solver_action"], "run_solver")
        self.assertTrue(result["review_required"])

    def test_generation_label_without_proven_path_becomes_inconclusive(self) -> None:
        unsupported = VALID_TRIAGE_JSON.replace(
            '"producer_path_status": "proven"',
            '"producer_path_status": "insufficient"',
        )
        fake_llm = FakeLLM([unsupported])

        with patch("llm_interface.llm_client.LLMClient", return_value=fake_llm):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(result["raw_refined_triage_label"], "Actionable Target Gap")
        self.assertEqual(result["refined_triage_label"], "Inconclusive")
        self.assertEqual(result["solver_action"], "run_solver")
        self.assertFalse(result["evidence_contract_satisfied"])

    def test_bounded_extreme_requires_practical_budget(self) -> None:
        unsupported = VALID_TRIAGE_JSON.replace(
            "Actionable Target Gap",
            "Bounded Extreme Value",
        ).replace(
            '"practical_feasibility": "practical"',
            '"practical_feasibility": "resource_failure"',
        )
        fake_llm = FakeLLM([unsupported])

        with patch("llm_interface.llm_client.LLMClient", return_value=fake_llm):
            result = run_triage_prompt("prompt", backend="test", model=None)

        self.assertEqual(result["refined_triage_label"], "Inconclusive")
        self.assertIn("practical feasibility", result["normalization_reason"])


if __name__ == "__main__":
    unittest.main()
