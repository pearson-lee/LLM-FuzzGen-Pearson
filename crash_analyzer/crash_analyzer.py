import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import prompts.prompt_generator as prompt_generator
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient

try:
    from json_repair import repair_json
except ImportError:
    repair_json = None

logger = logging.getLogger(__name__)


@dataclass
class CrashHeuristicTriage:
    finding: str
    crash_type: str
    crash_site: str
    suspected_fuzzer_bug: bool
    confidence: float
    rationale: list[str]


class CrashAnalyzer:
    """
    Analyzes crashes found by OSS-Fuzz, uses an LLM to determine their
    validity, and generates reports and reduced test cases.
    """

    def __init__(self, llm_client: "LLMClient", oss_fuzz: OSSFuzz):
        """
        Initializes the CrashAnalyzer.
        """
        self.llm_client = llm_client
        self.oss_fuzz = oss_fuzz
        self.crashes_dir = Path(__file__).parent / "crashes"
        self.crashes_dir.mkdir(exist_ok=True)
        self.crash_file_pattern = re.compile(r"llm_fuzzgen\d{10}_.*")
        self.fuzzer_base_name_pattern = re.compile(r"^(llm_fuzzgen\d{10})")

    def analyze_project(self, project_name: str):
        """
        Finds and analyzes all crashes for a given project.
        """
        logger.info(f"Starting crash analysis for project: {project_name}")
        project_out_dir = self.oss_fuzz.build_out_dir / project_name
        if not project_out_dir.is_dir():
            logger.warning(f"Project output directory not found for '{project_name}', skipping.")
            return

        crash_files = [f for f in project_out_dir.iterdir() if f.is_file() and self.crash_file_pattern.match(f.name)]

        if not crash_files:
            logger.info(f"No new crash files found for project '{project_name}'.")
            return

        logger.info(f"Found {len(crash_files)} new crash file(s) for '{project_name}'.")
        for crash_path in crash_files:
            self._process_crash(project_name, crash_path)

    def _process_crash(self, project_name: str, crash_path: Path):
        """
        Processes a single crash: finds source, gets LLM analysis, and saves artifacts.
        """
        logger.info(f"Processing crash: {crash_path.name}")
        match = self.fuzzer_base_name_pattern.match(crash_path.stem)
        if not match:
            logger.error(f"Could not extract fuzzer base name from '{crash_path.name}'.")
            return

        fuzzer_binary_name = match.group(1)
        source_file = self._find_source_file(project_name, fuzzer_binary_name)

        if not source_file:
            logger.error(f"Could not find source file for fuzzer '{fuzzer_binary_name}'.")
            return

        try:
            crash_input_bytes = crash_path.read_bytes()
            fuzzer_source_code = source_file.read_text()
        except IOError as e:
            logger.error(f"Error reading crash files: {e}")
            return

        # Reproduce the crash to get a clean stack trace
        stack_trace = self.oss_fuzz.reproduce_crash(project_name, fuzzer_binary_name, crash_path)
        triage = self._heuristic_triage(fuzzer_binary_name, stack_trace)

        # Get analysis from LLM
        analysis = self._get_llm_analysis(
            project_name,
            fuzzer_source_code,
            crash_input_bytes,
            stack_trace,
            triage,
        )

        if not analysis:
            logger.error(f"LLM analysis failed for '{crash_path.name}'.")
            return

        # Save the artifacts
        self._save_artifacts(
            project_name=project_name,
            fuzzer_binary_name=fuzzer_binary_name,
            original_source_path=source_file,
            crash_input_path=crash_path,
            analysis=analysis,
            stack_trace=stack_trace,
            triage=triage,
        )

    def _find_source_file(self, project_name: str, fuzzer_binary_name: str) -> Path | None:
        """
        Finds the source code file for a given fuzzer binary name.
        """
        project_src_dir = self.oss_fuzz.oss_fuzz_dir / "projects" / project_name
        for ext in [".cc", ".cpp", ".c"]:
            source_file = project_src_dir / (fuzzer_binary_name + ext)
            if source_file.exists():
                return source_file
        return None

    def _extract_json_object(self, content: str) -> dict[str, Any] | None:
        if not content:
            return None

        text = content.strip()
        if repair_json is not None:
            try:
                parsed = repair_json(text, return_objects=True)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                return parsed

        fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced_match:
            text = fenced_match.group(1)
        else:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return None
            text = text[start : end + 1]

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse crash analysis JSON output.")
            return None

        return parsed if isinstance(parsed, dict) else None

    def _validate_analysis_schema(self, analysis: dict[str, Any]) -> dict[str, Any] | None:
        required_string_fields = (
            "finding",
            "crash_type",
            "crash_site",
            "crash_function",
            "reasoning_summary",
            "suggested_fix",
        )
        optional_string_fields = ("cwe", "api_contract_violation", "minimized_poc")
        valid_findings = {"Real Crash", "Fuzzer Logic Error", "Ambiguous"}
        valid_crash_sites = {"library", "fuzzer", "unknown"}

        for field in required_string_fields:
            value = analysis.get(field)
            if not isinstance(value, str) or not value.strip():
                logger.error("Crash analysis schema validation failed: %s must be a non-empty string.", field)
                return None
            analysis[field] = value.strip()

        for field in optional_string_fields:
            value = analysis.get(field, "")
            if not isinstance(value, str):
                logger.error("Crash analysis schema validation failed: %s must be a string.", field)
                return None
            analysis[field] = value.strip()

        if analysis["finding"] not in valid_findings:
            logger.error("Crash analysis schema validation failed: invalid finding %r.", analysis["finding"])
            return None

        if analysis["crash_site"] not in valid_crash_sites:
            logger.error("Crash analysis schema validation failed: invalid crash_site %r.", analysis["crash_site"])
            return None

        evidence = analysis.get("evidence")
        if not isinstance(evidence, list) or not all(isinstance(item, str) and item.strip() for item in evidence):
            logger.error("Crash analysis schema validation failed: evidence must be a list of non-empty strings.")
            return None
        analysis["evidence"] = [item.strip() for item in evidence]

        confidence = analysis.get("confidence")
        if not isinstance(confidence, (int, float)):
            logger.error("Crash analysis schema validation failed: confidence must be numeric.")
            return None
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            logger.error("Crash analysis schema validation failed: confidence %r out of range.", confidence)
            return None
        analysis["confidence"] = confidence

        return analysis

    def _heuristic_triage(self, fuzzer_binary_name: str, stack_trace: str) -> CrashHeuristicTriage:
        trace = stack_trace or ""
        trace_lower = trace.lower()
        rationale: list[str] = []

        crash_site = "unknown"
        if f"/out/{fuzzer_binary_name}" in trace:
            crash_site = "fuzzer"
            rationale.append("Top crash log points to the generated fuzz target binary.")
        elif "/src/" in trace:
            crash_site = "library"
            rationale.append("Stack trace contains project source paths under /src/.")

        crash_type = "unknown"
        if "heap-use-after-free" in trace_lower:
            crash_type = "heap-use-after-free"
        elif "null pointer dereference" in trace_lower or "segv on unknown address 0x000000000000" in trace_lower:
            crash_type = "null-dereference"
        elif "stack-buffer-overflow" in trace_lower:
            crash_type = "stack-buffer-overflow"
        elif "heap-buffer-overflow" in trace_lower:
            crash_type = "heap-buffer-overflow"
        elif "use-of-uninitialized-value" in trace_lower:
            crash_type = "uninitialized-read"
        elif "assertion" in trace_lower or "check failed" in trace_lower:
            crash_type = "assertion"
        elif "timeout" in trace_lower:
            crash_type = "timeout"

        suspected_fuzzer_bug = False
        finding = "Ambiguous"
        confidence = 0.45

        if crash_site == "fuzzer":
            suspected_fuzzer_bug = True
            finding = "Fuzzer Logic Error"
            confidence = 0.8
            rationale.append("Crash appears to happen in fuzz target code before reaching library logic.")
        elif crash_site == "library" and crash_type in {
            "heap-use-after-free",
            "null-dereference",
            "stack-buffer-overflow",
            "heap-buffer-overflow",
            "uninitialized-read",
        }:
            finding = "Real Crash"
            confidence = 0.7
            rationale.append("Sanitizer signal happens in library code with a memory-safety signature.")
        elif crash_type in {"assertion", "timeout"}:
            finding = "Ambiguous"
            confidence = 0.5
            rationale.append("Assertion/timeout needs API-contract review before deciding ownership.")

        if not rationale:
            rationale.append("No strong heuristic signal found from the reproduced stack trace.")

        return CrashHeuristicTriage(
            finding=finding,
            crash_type=crash_type,
            crash_site=crash_site,
            suspected_fuzzer_bug=suspected_fuzzer_bug,
            confidence=confidence,
            rationale=rationale,
        )

    def _render_markdown_report(self, analysis: dict[str, Any], triage: CrashHeuristicTriage) -> str:
        finding = analysis.get("finding", triage.finding)
        crash_type = analysis.get("crash_type", triage.crash_type or "unknown")
        crash_function = analysis.get("crash_function", "unknown")
        confidence = analysis.get("confidence", triage.confidence)
        rationale = analysis.get("reasoning_summary", "No reasoning summary provided.")
        evidence = analysis.get("evidence", [])
        api_contract = analysis.get("api_contract_violation", "")
        suggested_fix = analysis.get("suggested_fix", "")
        poc = analysis.get("minimized_poc", "")
        cwe = analysis.get("cwe", "")

        lines = [f"# Crash Analysis Report: {finding} in `{crash_function}`", "", "## Triage"]
        lines.append(f"- Finding: **{finding}**")
        lines.append(f"- Crash Type: {crash_type}")
        lines.append(f"- Crash Site: {analysis.get('crash_site', triage.crash_site)}")
        lines.append(f"- Confidence: {confidence}")
        if cwe:
            lines.append(f"- CWE: {cwe}")
        if api_contract:
            lines.append(f"- API Contract Violation: {api_contract}")

        lines.extend(["", "## Root Cause Analysis", rationale])

        if evidence:
            lines.extend(["", "## Evidence"])
            for item in evidence:
                lines.append(f"- {item}")

        if poc:
            lines.extend(["", "## Minimized Proof-of-Concept (PoC)", "```", str(poc).strip(), "```"])

        if suggested_fix:
            lines.extend(["", "## Suggested Fix", "```", str(suggested_fix).strip(), "```"])

        lines.extend(["", "## Heuristic Triage Notes"])
        for item in triage.rationale:
            lines.append(f"- {item}")

        return "\n".join(lines).strip() + "\n"

    def _get_llm_analysis(
        self,
        project_name: str,
        source_code: str,
        crash_input_bytes: bytes,
        stack_trace: str,
        triage: CrashHeuristicTriage,
    ) -> dict[str, Any] | None:
        """
        Sends the crash data to an LLM for analysis and returns the report.
        """
        logger.info("Getting analysis from LLM...")
        try:
            crash_input_hex = crash_input_bytes.hex()
            lang = self.oss_fuzz.proj_lang(project_name)
            heuristic_summary = json.dumps(
                {
                    "finding": triage.finding,
                    "crash_type": triage.crash_type,
                    "crash_site": triage.crash_site,
                    "suspected_fuzzer_bug": triage.suspected_fuzzer_bug,
                    "confidence": triage.confidence,
                    "rationale": triage.rationale,
                },
                ensure_ascii=False,
                indent=2,
            )

            prompt = prompt_generator.crash_analysis_prompt(
                project_name=project_name,
                lang=lang,
                fuzzer_source_code=source_code,
                crash_input_hex=crash_input_hex,
                stack_trace=stack_trace,
                heuristic_summary=heuristic_summary,
            )

            raw_response = self.llm_client.generate(prompt)
            parsed = self._extract_json_object(raw_response or "")
            if not parsed:
                logger.error("Crash analysis did not return a valid JSON object.")
                return None

            parsed = self._validate_analysis_schema(parsed)
            if not parsed:
                logger.error("Crash analysis JSON object failed schema validation.")
                return None

            parsed.setdefault("finding", triage.finding)
            parsed.setdefault("crash_type", triage.crash_type)
            parsed.setdefault("crash_site", triage.crash_site)
            parsed.setdefault("confidence", triage.confidence)
            parsed.setdefault("evidence", [])
            parsed["raw_response"] = raw_response
            return parsed
        except Exception as e:
            logger.error(f"An error occurred during LLM analysis: {e}", exc_info=True)
            return None

    def _save_artifacts(
        self,
        project_name: str,
        fuzzer_binary_name: str,
        original_source_path: Path,
        crash_input_path: Path,
        analysis: dict[str, Any],
        stack_trace: str,
        triage: CrashHeuristicTriage,
    ):
        """
        Saves the analysis report and copies the original source and crash input.
        """
        logger.info(f"Saving artifacts for {fuzzer_binary_name}")
        base_artifact_dir = self.crashes_dir / project_name / fuzzer_binary_name
        artifact_dir = base_artifact_dir
        counter = 1
        while artifact_dir.exists():
            artifact_dir = base_artifact_dir.with_name(f"{base_artifact_dir.name}-{counter}")
            counter += 1
        artifact_dir.mkdir(parents=True)

        report_content = self._render_markdown_report(analysis, triage)

        # Save the report from the LLM
        (artifact_dir / "report.md").write_text(report_content)
        (artifact_dir / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False, indent=2))
        (artifact_dir / "heuristic_triage.json").write_text(
            json.dumps(
                {
                    "finding": triage.finding,
                    "crash_type": triage.crash_type,
                    "crash_site": triage.crash_site,
                    "suspected_fuzzer_bug": triage.suspected_fuzzer_bug,
                    "confidence": triage.confidence,
                    "rationale": triage.rationale,
                },
                ensure_ascii=False,
                indent=2,
            )
        )

        # Save the stack trace
        (artifact_dir / "stack_trace").write_text(stack_trace)

        # Copy the original source and crash input for reference
        shutil.copy(original_source_path, artifact_dir / original_source_path.name)
        shutil.copy(crash_input_path, artifact_dir / crash_input_path.name)

        logger.info(f"Artifacts saved to: {artifact_dir}")
