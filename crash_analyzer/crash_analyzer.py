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
    top_app_frame_source: str = ""
    top_app_frame_function: str = ""
    frame_classification: str = "unknown"


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
        reproduce_summary = self._build_reproduce_summary(stack_trace)
        triage = self._heuristic_triage(fuzzer_binary_name, stack_trace, source_file)

        # Get analysis from LLM
        analysis = self._get_llm_analysis(
            project_name,
            fuzzer_source_code,
            crash_input_bytes,
            stack_trace,
            triage,
            reproduce_summary,
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

    @staticmethod
    def _build_reproduce_summary(stack_trace: str) -> dict[str, Any]:
        stack_trace_text = stack_trace or ""
        succeeded = bool(stack_trace_text.strip())
        return {
            "attempted": True,
            "succeeded": succeeded,
            "evidence": (
                "oss_fuzz.reproduce_crash returned a non-empty sanitizer stack trace"
                if succeeded
                else "oss_fuzz.reproduce_crash returned an empty stack trace"
            ),
        }

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

    def _validate_analysis_schema(
        self,
        analysis: dict[str, Any],
        reproduce_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
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

        validation_warnings = analysis.get("validation_warnings", [])
        if not isinstance(validation_warnings, list):
            validation_warnings = []
        validation_warnings = [str(w).strip() for w in validation_warnings if str(w).strip()]

        # --- Optional: rubric_scores validation ---
        rubric = analysis.get("rubric_scores")
        if rubric is not None:
            rubric_schema = {
                "top_frame_ownership": (0, 2),
                "api_contract": (0, 2),
                "normal_caller_feasibility": (0, 2),
                "sanitizer_signal": (0, 1),
                "reproducibility": (0, 1),
            }
            if not isinstance(rubric, dict):
                warning = "invalid_rubric_scores: rubric_scores is not a dict"
                logger.warning(warning)
                validation_warnings.append(warning)
                analysis.pop("rubric_scores", None)
            else:
                valid_rubric = True
                invalid_reason = ""
                for field, (min_score, max_score) in rubric_schema.items():
                    entry = rubric.get(field)
                    if not isinstance(entry, dict):
                        invalid_reason = f"rubric_scores.{field} is missing or not a dict"
                        valid_rubric = False
                        break
                    score = entry.get("score")
                    evidence_val = entry.get("evidence", "")
                    if (
                        isinstance(score, bool)
                        or not isinstance(score, (int, float))
                        or int(score) != score
                    ):
                        invalid_reason = f"rubric_scores.{field}.score is not an integer"
                        valid_rubric = False
                        break
                    score = int(score)
                    if not min_score <= score <= max_score:
                        invalid_reason = (
                            f"rubric_scores.{field}.score {score} out of range "
                            f"{min_score}..{max_score}"
                        )
                        valid_rubric = False
                        break
                    evidence_str = str(evidence_val).strip()
                    if not evidence_str:
                        invalid_reason = f"rubric_scores.{field}.evidence is empty"
                        valid_rubric = False
                        break
                    rubric[field]["score"] = score
                    rubric[field]["evidence"] = evidence_str
                if valid_rubric:
                    reproduce_entry = rubric["reproducibility"]
                    if reproduce_summary and reproduce_summary.get("succeeded") is False:
                        if reproduce_entry["score"] != 0:
                            valid_rubric = False
                            invalid_reason = (
                                "rubric_scores.reproducibility.score conflicts with "
                                "reproduce_summary.succeeded=false"
                            )
                    if reproduce_summary and reproduce_summary.get("succeeded") is True:
                        if reproduce_entry["score"] != 1:
                            valid_rubric = False
                            invalid_reason = (
                                "rubric_scores.reproducibility.score conflicts with "
                                "reproduce_summary.succeeded=true"
                            )
                if valid_rubric:
                    total = sum(rubric[f]["score"] for f in rubric_schema)
                    rubric["total"] = total
                    analysis["rubric_scores"] = rubric
                else:
                    warning = f"invalid_rubric_scores: {invalid_reason}"
                    logger.warning("%s; ignoring rubric.", warning)
                    validation_warnings.append(warning)
                    analysis.pop("rubric_scores", None)

        if validation_warnings:
            analysis["validation_warnings"] = list(dict.fromkeys(validation_warnings))

        # --- Optional: missing_evidence validation ---
        missing = analysis.get("missing_evidence")
        if missing is not None:
            if isinstance(missing, list):
                analysis["missing_evidence"] = [str(m).strip() for m in missing if str(m).strip()]
            else:
                analysis.pop("missing_evidence", None)

        return analysis

    def _parse_stack_frames(self, stack_trace: str, fuzz_target_filename: str) -> tuple[str, str, str]:
        """
        Parse ASAN/MSAN stack frames to find the top application frame.

        Returns (top_app_frame_source, top_app_frame_function, frame_classification)
        where frame_classification is one of: "fuzz_target" | "library" | "runtime" | "unknown"

        OSS-Fuzz/ASAN frame format:
            #N 0xADDR in FUNCTION_NAME /path/to/source.c:LINE:COL
        """
        frame_re = re.compile(
            r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(/[^\s:]+(?::\d+){0,2})(?:\s|$)",
            re.MULTILINE,
        )
        # Sanitizer / libFuzzer runtime indicators — skip these frames
        RUNTIME_FUNC_PREFIXES = (
            "__asan", "__sanitizer", "__msan", "__ubsan", "__lsan",
            "fuzzer::", "Fuzzer::",
            "LLVMFuzzerRunDriver", "LLVMFuzzerInitialize",
        )
        RUNTIME_PATH_PREFIXES = ("/usr/", "/proc/")
        RUNTIME_PATH_KEYWORDS = ("sanitizer", "libFuzzer", "compiler-rt", "llvm-project/compiler")

        fuzz_target_basename = fuzz_target_filename  # e.g. "llm_fuzzgen1234.cc"

        for m in frame_re.finditer(stack_trace):
            func_name = m.group(1)
            source_path = m.group(2)
            source_file_path = re.sub(r":\d+(?::\d+)?$", "", source_path)

            is_runtime = (
                any(func_name.startswith(p) for p in RUNTIME_FUNC_PREFIXES)
                or any(source_file_path.startswith(p) for p in RUNTIME_PATH_PREFIXES)
                or any(kw in source_file_path for kw in RUNTIME_PATH_KEYWORDS)
            )
            if is_runtime:
                continue

            # First non-runtime application frame
            source_basename = Path(source_file_path).name
            if source_basename == fuzz_target_basename:
                classification = "fuzz_target"
            elif "/src/" in source_file_path:
                classification = "library"
            else:
                classification = "unknown"

            return source_path, func_name, classification

        return "", "", "unknown"

    def _heuristic_triage(
        self,
        fuzzer_binary_name: str,
        stack_trace: str,
        source_file: "Path | None" = None,
    ) -> CrashHeuristicTriage:
        trace = stack_trace or ""
        trace_lower = trace.lower()
        rationale: list[str] = []

        # --- Frame-level crash site detection ---
        fuzz_target_filename = source_file.name if source_file else ""
        top_source, top_func, frame_class = self._parse_stack_frames(trace, fuzz_target_filename)

        crash_site = "unknown"
        if frame_class == "fuzz_target":
            crash_site = "fuzzer"
            rationale.append(
                f"Top application frame ({top_func}) is in the generated fuzz target source: {top_source}"
            )
        elif frame_class == "library":
            crash_site = "library"
            rationale.append(
                f"Top application frame ({top_func}) is in library source: {top_source}"
            )
        else:
            rationale.append(
                f"Top application frame source could not be classified (source: {top_source or 'not found'})."
            )

        # --- Crash type from sanitizer header ---
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

        # --- Finding + confidence ---
        suspected_fuzzer_bug = False
        finding = "Ambiguous"
        confidence = 0.45

        if crash_site == "fuzzer":
            suspected_fuzzer_bug = True
            finding = "Fuzzer Logic Error"
            # 0.75 (slightly conservative vs old 0.8): crash in fuzz target source
            # is a strong signal, but could still be API misuse causing a library path
            confidence = 0.75
            rationale.append(
                "Crash occurs in the generated fuzz target source. "
                "Likely a fuzz target logic error or API misuse."
            )
        elif crash_site == "library" and crash_type in {
            "heap-use-after-free",
            "null-dereference",
            "stack-buffer-overflow",
            "heap-buffer-overflow",
            "uninitialized-read",
        }:
            finding = "Real Crash"
            confidence = 0.7
            rationale.append(
                "Memory-safety sanitizer signal originates in library source. "
                "Likely a real library bug."
            )
        elif crash_type in {"assertion", "timeout"}:
            finding = "Ambiguous"
            confidence = 0.5
            rationale.append("Assertion/timeout requires API-contract review to determine ownership.")

        if len(rationale) == 1 and crash_site == "unknown":
            rationale.append("No strong heuristic signal found from the reproduced stack trace.")

        return CrashHeuristicTriage(
            finding=finding,
            crash_type=crash_type,
            crash_site=crash_site,
            suspected_fuzzer_bug=suspected_fuzzer_bug,
            confidence=confidence,
            rationale=rationale,
            top_app_frame_source=top_source,
            top_app_frame_function=top_func,
            frame_classification=frame_class,
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
        reproduce_result = analysis.get("reproduce_result")
        validation_warnings = analysis.get("validation_warnings", [])

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

        if reproduce_result and isinstance(reproduce_result, dict):
            lines.extend(["", "## Reproduce Result"])
            lines.append(f"- Attempted: {reproduce_result.get('attempted')}")
            lines.append(f"- Succeeded: {reproduce_result.get('succeeded')}")
            lines.append(f"- Evidence: {reproduce_result.get('evidence', '')}")

        if validation_warnings:
            lines.extend(["", "## Validation Warnings"])
            for item in validation_warnings:
                lines.append(f"- {item}")

        # --- Evidence Rubric table ---
        rubric = analysis.get("rubric_scores")
        if rubric and isinstance(rubric, dict):
            rubric_field_labels = {
                "top_frame_ownership": "Top Frame Ownership (0–2)",
                "api_contract": "API Contract (0–2)",
                "normal_caller_feasibility": "Normal Caller Feasibility (0–2)",
                "sanitizer_signal": "Sanitizer Signal (0–1)",
                "reproducibility": "Reproducibility (0–1)",
            }
            lines.extend(["", "## Evidence Rubric"])
            lines.append("| Criterion | Score | Evidence |")
            lines.append("|-----------|------:|---------|")
            for field, label in rubric_field_labels.items():
                entry = rubric.get(field, {})
                score = entry.get("score", "?")
                ev = entry.get("evidence", "")
                lines.append(f"| {label} | {score} | {ev} |")
            lines.append(f"| **Total** | **{rubric.get('total', '?')}** | |")

        # --- Evidence Audit (if present) ---
        audit = analysis.get("evidence_audit")
        if audit and isinstance(audit, dict):
            lines.extend(["", "## Evidence Audit"])
            revised = audit.get("revised_finding", "")
            rev_conf = audit.get("revised_confidence", "")
            rationale_rev = audit.get("revision_rationale", "")
            if revised:
                lines.append(f"- Revised Finding: **{revised}** (confidence: {rev_conf})")
            if rationale_rev:
                lines.append(f"- Rationale: {rationale_rev}")
            answers = audit.get("audit_answers", {})
            if answers:
                lines.append("")
                for q, a in answers.items():
                    lines.append(f"**{q}**: {a}")

        # --- Missing evidence ---
        missing = analysis.get("missing_evidence") or []
        if missing:
            lines.extend(["", "## Missing Evidence"])
            for item in missing:
                lines.append(f"- {item}")

        if poc:
            lines.extend(["", "## Minimized Proof-of-Concept (PoC)", "```", str(poc).strip(), "```"])

        if suggested_fix:
            lines.extend(["", "## Suggested Fix", "```", str(suggested_fix).strip(), "```"])

        lines.extend(["", "## Heuristic Triage Notes"])
        if triage.top_app_frame_source:
            lines.append(
                f"- Top app frame: `{triage.top_app_frame_function}` "
                f"in `{triage.top_app_frame_source}` [{triage.frame_classification}]"
            )
        for item in triage.rationale:
            lines.append(f"- {item}")

        return "\n".join(lines).strip() + "\n"

    def _run_evidence_audit(
        self,
        initial_analysis: dict[str, Any],
        triage: CrashHeuristicTriage,
        stack_trace: str,
        source_code: str,
    ) -> dict[str, Any] | None:
        """
        Runs a targeted evidence-gathering pass when the initial analysis is low-confidence,
        Ambiguous, or conflicts with the heuristic frame classification.

        Returns the parsed audit dict or None on failure.
        """
        logger.info("Running evidence audit pass...")
        try:
            prompt = prompt_generator.crash_audit_prompt(
                finding=initial_analysis.get("finding", "Ambiguous"),
                confidence=initial_analysis.get("confidence", 0.0),
                reasoning_summary=initial_analysis.get("reasoning_summary", ""),
                frame_classification=triage.frame_classification,
                top_app_frame_source=triage.top_app_frame_source,
                stack_trace=stack_trace,
                fuzzer_source_code=source_code,
            )
            raw = self.llm_client.generate(prompt)
            parsed = self._extract_json_object(raw or "")
            if not parsed or not isinstance(parsed, dict):
                logger.warning("Evidence audit did not return a valid JSON object; skipping.")
                return None

            # Validate required fields
            revised_finding = parsed.get("revised_finding", "")
            if revised_finding not in {"Real Crash", "Fuzzer Logic Error", "Ambiguous"}:
                logger.warning("Evidence audit returned invalid revised_finding %r; skipping.", revised_finding)
                return None

            revised_conf = parsed.get("revised_confidence")
            if not isinstance(revised_conf, (int, float)) or not 0.0 <= float(revised_conf) <= 1.0:
                logger.warning("Evidence audit returned invalid revised_confidence; skipping.")
                return None

            parsed["revised_confidence"] = float(revised_conf)
            parsed.setdefault("audit_answers", {})
            parsed.setdefault("revision_rationale", "")
            parsed.setdefault("missing_evidence", [])
            return parsed
        except Exception as e:
            logger.error(f"Evidence audit pass failed: {e}", exc_info=True)
            return None

    @staticmethod
    def _needs_audit(analysis: dict[str, Any], triage: CrashHeuristicTriage) -> bool:
        """Returns True when the evidence audit pass should be triggered."""
        confidence = analysis.get("confidence", 1.0)
        finding = analysis.get("finding", "Ambiguous")

        if confidence < 0.75 or finding == "Ambiguous":
            return True

        if analysis.get("validation_warnings"):
            return True

        # Conflict: heuristic frame classification disagrees with LLM finding
        frame_class = triage.frame_classification
        if frame_class == "fuzz_target" and finding == "Real Crash":
            return True
        if frame_class == "library" and finding == "Fuzzer Logic Error":
            return True

        return False

    def _get_llm_analysis(
        self,
        project_name: str,
        source_code: str,
        crash_input_bytes: bytes,
        stack_trace: str,
        triage: CrashHeuristicTriage,
        reproduce_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Sends the crash data to an LLM for analysis and returns the report.
        Runs an evidence audit pass for low-confidence or conflicting results.
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
                    "frame_classification": triage.frame_classification,
                    "top_app_frame_source": triage.top_app_frame_source,
                    "top_app_frame_function": triage.top_app_frame_function,
                },
                ensure_ascii=False,
                indent=2,
            )
            effective_reproduce_summary = reproduce_summary or self._build_reproduce_summary(stack_trace)
            reproduce_result = json.dumps(
                effective_reproduce_summary,
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
                reproduce_result=reproduce_result,
            )

            raw_response = self.llm_client.generate(prompt)
            parsed = self._extract_json_object(raw_response or "")
            if not parsed:
                logger.error("Crash analysis did not return a valid JSON object.")
                return None

            parsed = self._validate_analysis_schema(parsed, reproduce_summary=effective_reproduce_summary)
            if not parsed:
                logger.error("Crash analysis JSON object failed schema validation.")
                return None

            parsed.setdefault("finding", triage.finding)
            parsed.setdefault("crash_type", triage.crash_type)
            parsed.setdefault("crash_site", triage.crash_site)
            parsed.setdefault("confidence", triage.confidence)
            parsed.setdefault("evidence", [])
            parsed["reproduce_result"] = effective_reproduce_summary
            parsed["raw_response"] = raw_response

            # --- Evidence audit pass ---
            if self._needs_audit(parsed, triage):
                logger.info(
                    "Triggering evidence audit (finding=%s, confidence=%.2f, frame=%s).",
                    parsed.get("finding"),
                    parsed.get("confidence", 0.0),
                    triage.frame_classification,
                )
                audit = self._run_evidence_audit(parsed, triage, stack_trace, source_code)
                if audit:
                    initial_conf = float(parsed.get("confidence", 0.0))
                    revised_conf = audit["revised_confidence"]

                    if revised_conf > initial_conf + 0.15:
                        # Strong revision — adopt the new finding
                        logger.info(
                            "Audit revised finding from %r to %r (confidence %.2f → %.2f).",
                            parsed["finding"],
                            audit["revised_finding"],
                            initial_conf,
                            revised_conf,
                        )
                        parsed["finding"] = audit["revised_finding"]
                        parsed["confidence"] = revised_conf
                    else:
                        # Weak or moderate revision — keep original, slightly lower confidence
                        parsed["confidence"] = max(0.0, initial_conf - 0.05)

                    parsed["evidence_audit"] = audit
                    # Merge missing_evidence lists
                    existing_missing = parsed.get("missing_evidence") or []
                    audit_missing = audit.get("missing_evidence") or []
                    merged = list(dict.fromkeys(existing_missing + audit_missing))
                    if merged:
                        parsed["missing_evidence"] = merged

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
                    "frame_classification": triage.frame_classification,
                    "top_app_frame_source": triage.top_app_frame_source,
                    "top_app_frame_function": triage.top_app_frame_function,
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
