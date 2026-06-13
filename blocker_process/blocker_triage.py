#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import config.config as config

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

TRIAGE_TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "blocker_triage_template"

TRIAGE_LABELS = {
    "Actionable Target Gap",
    "Bounded Extreme Value",
    "Resource-Exhaustion Guard",
    "Environmental Failure",
    "Internal Invariant Guard",
    "Generated Parser State",
    "Structurally Unreachable API Path",
    "Infeasible Counter Overflow",
    "Crash-Revealing Path",
    "Inconclusive",
}
TRIAGE_LABEL_ROUTING = {
    "Actionable Target Gap": ("Generation-solvable", "run_solver"),
    "Bounded Extreme Value": ("Generation-solvable", "run_solver"),
    "Resource-Exhaustion Guard": ("Non-generation-solvable", "skip_solver"),
    "Environmental Failure": ("Non-generation-solvable", "skip_solver"),
    "Internal Invariant Guard": ("Non-generation-solvable", "skip_solver"),
    "Generated Parser State": ("Non-generation-solvable", "skip_solver"),
    "Structurally Unreachable API Path": ("Non-generation-solvable", "skip_solver"),
    "Infeasible Counter Overflow": ("Non-generation-solvable", "skip_solver"),
    "Crash-Revealing Path": ("Non-generation-solvable", "skip_solver"),
    # Insufficient evidence must not suppress a potentially solvable blocker.
    "Inconclusive": ("Inconclusive", "run_solver"),
}
CLASSIFIER_AGREEMENT = {"agree", "disagree", "unclear", "not_provided"}
C_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "return",
    "sizeof",
    "struct",
    "union",
    "enum",
    "static",
    "const",
    "volatile",
    "int",
    "char",
    "short",
    "long",
    "unsigned",
    "signed",
    "void",
    "float",
    "double",
    "bool",
    "true",
    "false",
    "NULL",
}


def load_text(path: Path | str | None) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def clip(text: Any, limit: int = 18000) -> str:
    if text is None:
        return "N/A"
    if isinstance(text, (dict, list)):
        text = json.dumps(text, ensure_ascii=False, indent=2)
    text = str(text)
    if not text:
        return "N/A"
    if len(text) <= limit:
        return text
    half = max(1, (limit - 120) // 2)
    return text[:half] + "\n\n... [TRUNCATED] ...\n\n" + text[-half:]


def compact_pipeline_summary(summary: Any) -> str:
    if not summary:
        return "N/A"
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except Exception:
            return clip(summary, 4000)
    if not isinstance(summary, dict):
        return clip(summary, 4000)

    def subset(mapping: Any, keys: list[str]) -> dict:
        if not isinstance(mapping, dict):
            return {}
        return {key: mapping.get(key) for key in keys if key in mapping}

    compact = subset(
        summary,
        [
            "solver",
            "project_name",
            "function_name",
            "branch_line_number",
            "blocked_side_line_number",
            "reference_target_name",
            "success",
            "attempt_result",
            "success_stage",
            "failure_stage",
            "pipeline_methods",
            "message",
            "llm_seed_final_status",
            "llm_seed_generator_terminal_reason",
            "llm_seed_handoff_selection_reason",
        ],
    )
    compact["baseline"] = subset(
        summary.get("baseline"),
        [
            "success",
            "branch_hit_count",
            "branch_hit_count_raw",
            "blocked_side_hit_count",
            "blocked_side_hit_count_raw",
            "branch_line_reached",
            "blocked_side_line_reached",
        ],
    )
    best_iteration = summary.get("best_iteration")
    if isinstance(best_iteration, dict):
        compact["best_iteration"] = subset(
            best_iteration,
            ["iteration", "strategy", "accepted", "success", "score", "note", "last_failure_summary"],
        )
        compact["best_iteration"]["evaluation"] = subset(
            best_iteration.get("evaluation"),
            [
                "success",
                "branch_hit_count",
                "branch_hit_count_raw",
                "blocked_side_hit_count",
                "blocked_side_hit_count_raw",
                "branch_line_reached",
                "blocked_side_line_reached",
            ],
        )

    stage_statuses = summary.get("stage_statuses")
    if isinstance(stage_statuses, dict):
        compact["stage_statuses"] = {
            name: subset(status, ["success", "returncode", "final_status", "message"])
            for name, status in stage_statuses.items()
        }

    stages = summary.get("stages")
    if isinstance(stages, dict):
        compact_stages = {}
        for name, stage in stages.items():
            if not isinstance(stage, dict):
                continue
            item = subset(
                stage,
                [
                    "success",
                    "attempt_result",
                    "final_status",
                    "generator_terminal_reason",
                    "diagnosis_counts",
                    "iterations_run",
                    "progress_iteration_count",
                    "stalled_iteration_count",
                    "invalid_iteration_count",
                    "validation_status",
                    "seed_count_before",
                    "seed_count_after",
                    "new_seeds",
                    "error",
                ],
            )
            symcc = stage.get("symcc")
            if isinstance(symcc, dict):
                item["symcc"] = subset(symcc, ["returncode", "solved", "failure_kind"])
            best = stage.get("best_iteration")
            if isinstance(best, dict):
                item["best_iteration"] = subset(
                    best,
                    [
                        "iteration",
                        "validation_ok",
                        "validation_error_kind",
                        "generated_seed_count",
                        "family_counts",
                    ],
                )
            compact_stages[name] = item
        compact["stages"] = compact_stages

    return json.dumps(compact, ensure_ascii=False, indent=2)


def normalize_line_number(value: Any) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def first_present(*values: Any, default: Any = "N/A") -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def format_template(template: str, mapping: dict[str, Any]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return str(mapping.get(key, "N/A"))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)


def read_resolved_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = load_text(file_path)
        if text:
            return text
    if inline_text:
        return inline_text
    return default


def resolve_source_path(project_name: str | None, source_file: str | None) -> Path | None:
    if not source_file:
        return None
    raw = Path(source_file)
    if raw.is_file():
        return raw

    normalized = str(source_file).replace("\\", "/")
    rel = normalized.lstrip("/")
    project = project_name or ""
    candidates = [
        REPO_ROOT / rel,
    ]
    if project:
        out_root = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out" / project
        candidates.extend(
            [
                out_root / rel,
                out_root / "inspector" / "source-code" / rel,
                out_root / "inspector" / "light" / "source_files" / rel,
                out_root / "source_code" / Path(rel).name,
            ]
        )

    if "/src/" in normalized:
        rel_from_src = normalized[normalized.index("/src/") + 1 :]
        if project:
            out_root = REPO_ROOT / "external" / "oss-fuzz" / "build" / "out" / project
            candidates.extend(
                [
                    out_root / rel_from_src,
                    out_root / "inspector" / "source-code" / rel_from_src,
                    out_root / "inspector" / "light" / "source_files" / rel_from_src,
                ]
            )

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def get_source_line(project_name: str | None, source_file: str | None, line_number: int) -> str:
    path = resolve_source_path(project_name, source_file)
    if not path or line_number <= 0:
        return "N/A"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "N/A"
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return "N/A"


def source_snippet(
    project_name: str | None,
    source_file: str | None,
    branch_line_number: int,
    blocked_side_line_number: int = 0,
    context_lines: int = 25,
) -> str:
    path = resolve_source_path(project_name, source_file)
    if not path:
        return f"N/A: source file not found for {source_file or 'unknown'}"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return f"N/A: failed to read source file {path}: {exc}"

    anchors = [line for line in [branch_line_number, blocked_side_line_number] if line > 0]
    if not anchors:
        return "N/A: missing source line numbers"
    begin = max(1, min(anchors) - context_lines)
    end = min(len(lines), max(anchors) + context_lines)
    rendered = []
    for line_no in range(begin, end + 1):
        marker = ">>" if line_no in anchors else "  "
        rendered.append(f"{marker} {line_no:5d}: {lines[line_no - 1]}")
    return "\n".join(rendered)


def extract_source_identifiers(*texts: str | None) -> list[str]:
    candidates: list[tuple[int, int, str]] = []
    seen: set[str] = set()
    for text_index, text in enumerate(texts):
        if not text:
            continue
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
            if token in C_KEYWORDS:
                continue
            if token not in seen:
                seen.add(token)
                candidates.append((text_index, len(candidates), token))
    candidates.sort(
        key=lambda item: (
            item[0],
            item[2].isupper(),
            0 if "_" in item[2] else 1,
            0 if any(ch.islower() for ch in item[2]) else 1,
            item[1],
        )
    )
    return [token for _, _, token in candidates[:10]]


def related_source_snippets(
    project_name: str | None,
    source_file: str | None,
    identifiers: list[str],
    branch_line_number: int,
    blocked_side_line_number: int,
    context_lines: int = 6,
    max_snippets: int = 12,
) -> str:
    path = resolve_source_path(project_name, source_file)
    if not path:
        return f"N/A: source file not found for {source_file or 'unknown'}"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return f"N/A: failed to read source file {path}: {exc}"

    anchors: list[tuple[int, str]] = []
    branch_line = int(branch_line_number or 0)
    blocked_line = int(blocked_side_line_number or 0)
    excluded = {line for line in [branch_line, blocked_line] if line > 0}
    for ident in identifiers:
        pattern = re.compile(rf"\b{re.escape(ident)}\b")
        ident_hits = 0
        line_order = list(range(1, len(lines) + 1))
        if ident.isupper():
            define_hits = [
                idx
                for idx, line in enumerate(lines, 1)
                if re.search(rf"^\s*#\s*define\s+{re.escape(ident)}\b", line)
            ]
            line_order = define_hits + [idx for idx in line_order if idx not in set(define_hits)]
        for idx in line_order:
            line = lines[idx - 1]
            if idx in excluded:
                continue
            if pattern.search(line):
                anchors.append((idx, ident))
                ident_hits += 1
                if ident_hits >= 3:
                    break

    if not anchors:
        return "N/A: no related identifier occurrences found in the same source file."

    selected: list[tuple[int, str]] = []
    seen_ranges: list[tuple[int, int]] = []
    for line_no, ident in anchors:
        begin = max(1, line_no - context_lines)
        end = min(len(lines), line_no + context_lines)
        if any(not (end < prev_begin or begin > prev_end) for prev_begin, prev_end in seen_ranges):
            continue
        selected.append((line_no, ident))
        seen_ranges.append((begin, end))
        if len(selected) >= max_snippets:
            break

    rendered = []
    for idx, (line_no, ident) in enumerate(selected, 1):
        begin = max(1, line_no - context_lines)
        end = min(len(lines), line_no + context_lines)
        rendered.append(f"// Related snippet {idx}: identifier `{ident}` near line {line_no}")
        for current in range(begin, end + 1):
            marker = ">>" if current == line_no else "  "
            rendered.append(f"{marker} {current:5d}: {lines[current - 1]}")
        rendered.append("")
    return "\n".join(rendered).strip()


def _extract_json_candidate(text: str) -> str:
    stripped = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if fence:
        return fence.group(1)
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first >= 0 and last > first:
        return stripped[first : last + 1]
    return stripped


def extract_json_object(text: str) -> dict:
    candidate = _extract_json_candidate(text)
    try:
        parsed = json.loads(candidate)
    except Exception:
        if repair_json is None:
            raise
        parsed = json.loads(repair_json(candidate))
    if not isinstance(parsed, dict):
        raise ValueError("Triage response must be a JSON object.")
    return parsed


def normalize_triage_result(parsed: dict, *, response_text: str = "", prompt_path: str | None = None) -> dict:
    result = dict(parsed or {})
    raw_first_layer = result.get("first_layer_decision")
    raw_solver_action = result.get("solver_action")
    raw_label = result.get("refined_triage_label")
    label = raw_label
    if label not in TRIAGE_LABELS:
        label = "Inconclusive"
    first_layer, solver_action = TRIAGE_LABEL_ROUTING[label]
    legacy_routing_conflict = (
        raw_first_layer not in (None, first_layer)
        or raw_solver_action not in (None, solver_action)
    )

    evidence_strength = result.get("evidence_strength")
    if evidence_strength not in {"A", "B", "C"}:
        evidence_strength = "C"
    classifier_agreement = result.get("classifier_agreement")
    if classifier_agreement not in CLASSIFIER_AGREEMENT:
        classifier_agreement = "unclear"

    result["first_layer_decision"] = first_layer
    result["refined_triage_label"] = label
    result["solver_action"] = solver_action
    result["raw_first_layer_decision"] = raw_first_layer
    result["raw_refined_triage_label"] = raw_label
    result["raw_solver_action"] = raw_solver_action
    result["routing_source"] = "deterministic_label_mapping"
    result["routing_derived"] = True
    result["normalization_applied"] = raw_label != label or legacy_routing_conflict
    if raw_label != label:
        result["normalization_reason"] = "Unknown label mapped to Inconclusive."
    elif legacy_routing_conflict:
        result["normalization_reason"] = "Legacy LLM routing fields were ignored; routing is derived from the label."
    else:
        result["normalization_reason"] = "N/A"
    result["review_required"] = label == "Inconclusive"
    result["evidence_strength"] = evidence_strength
    result["classifier_agreement"] = classifier_agreement
    result["source_overrides_classifier"] = bool(result.get("source_overrides_classifier", False))
    result.setdefault("analysis_trace", [])
    result.setdefault("required_solver_hint", "N/A")
    result.setdefault("source_override_reason", "N/A")
    result.setdefault("cost_note", "One triage LLM call; source/runtime evidence reused from existing pipeline.")
    # Runtime status is controlled by the pipeline, not by LLM-provided JSON.
    result["triage_status"] = "completed"
    result["triage_error_reason"] = None
    result["llm_attempt_count"] = 1
    if response_text:
        result["response_text"] = response_text
    if prompt_path:
        result["prompt_path"] = prompt_path
    return result


def default_inconclusive(reason: str) -> dict:
    return normalize_triage_result(
        {
            "analysis_trace": [
                "[1. Source-first blocker interpretation]: Inconclusive.",
                "[2. Required blocked-side condition]: Not established.",
                f"[3. Solvability evidence]: {reason}",
                "[4. Classifier conflict check]: Not evaluated.",
                "[5. Triage decision]: Evidence is inconclusive; solver execution is preserved by fail-open routing.",
            ],
            "refined_triage_label": "Inconclusive",
            "required_solver_hint": "N/A",
            "evidence_strength": "C",
            "classifier_agreement": "unclear",
            "source_overrides_classifier": False,
            "source_override_reason": "N/A",
        }
    )


def default_triage_error(reason: str, *, attempt_count: int, response_text: str = "") -> dict:
    result = default_inconclusive(reason)
    result["triage_status"] = "triage_error"
    result["triage_error_reason"] = reason
    result["llm_attempt_count"] = attempt_count
    if response_text:
        result["response_text"] = response_text
    return result


def build_json_retry_prompt(original_prompt: str, response_text: str, error_message: str) -> str:
    return (
        f"{original_prompt}\n\n"
        "---\n\n"
        "## JSON Output Repair\n"
        "The previous response could not be parsed. Re-evaluate the same evidence and return "
        "one valid JSON object only. Do not use Markdown fences or add text before or after JSON.\n\n"
        f"Parse error: {error_message}\n\n"
        "Previous invalid response:\n"
        f"{response_text or '[empty response]'}"
    )


def build_triage_context(
    *,
    project_name: str | None,
    language: str | None = None,
    target_name: str | None = None,
    function_name: str | None,
    branch_line_number: Any,
    blocked_side_line_number: Any,
    source_file: str | None = None,
    blocker_line_code: str | None = None,
    blocked_side_line_code: str | None = None,
    branch_hit_count: Any = "N/A",
    blocked_side_hit_count: Any = "N/A",
    runtime_blocker_segment: str | None = None,
    runtime_blocker_segment_source_codes: str | None = None,
    cfg_source_codes: str | None = None,
    pipeline_failure_stage: str | None = None,
    pipeline_methods: Any = None,
    pipeline_summary: str | None = None,
    classifier_dependency: str | None = None,
    classifier_reason: str | None = None,
    classifier_trace: Any = None,
    source_context_lines: int = 25,
) -> dict[str, str]:
    branch_line = normalize_line_number(branch_line_number)
    blocked_line = normalize_line_number(blocked_side_line_number)
    if not blocker_line_code or blocker_line_code == "N/A":
        blocker_line_code = get_source_line(project_name, source_file, branch_line)
    if not blocked_side_line_code or blocked_side_line_code == "N/A":
        blocked_side_line_code = get_source_line(project_name, source_file, blocked_line)
    if isinstance(pipeline_methods, list):
        pipeline_methods = ", ".join(str(item) for item in pipeline_methods) or "N/A"
    if isinstance(classifier_trace, list):
        classifier_trace = "\n\n".join(str(item) for item in classifier_trace)
    identifiers = extract_source_identifiers(blocker_line_code, blocked_side_line_code)

    return {
        "language": language or "C/C++",
        "project_name": project_name or "N/A",
        "target_name": target_name or "N/A",
        "function_name": function_name or "N/A",
        "branch_line_number": str(branch_line_number or "N/A"),
        "blocked_side_line_number": str(blocked_side_line_number or "N/A"),
        "blocker_line_code": blocker_line_code or "N/A",
        "blocked_side_line_code": blocked_side_line_code or "N/A",
        "branch_hit_count": str(branch_hit_count if branch_hit_count not in (None, "") else "N/A"),
        "blocked_side_hit_count": str(blocked_side_hit_count if blocked_side_hit_count not in (None, "") else "N/A"),
        "pipeline_failure_stage": pipeline_failure_stage or "N/A",
        "pipeline_methods": pipeline_methods or "N/A",
        "source_snippet": clip(
            source_snippet(project_name, source_file, branch_line, blocked_line, context_lines=source_context_lines)
        ),
        "related_source_snippets": clip(
            related_source_snippets(
                project_name,
                source_file,
                identifiers,
                branch_line,
                blocked_line,
            ),
            12000,
        ),
        "runtime_blocker_segment_source_codes": clip(runtime_blocker_segment_source_codes),
        "cfg_source_codes": clip(cfg_source_codes),
        "runtime_blocker_segment": clip(runtime_blocker_segment),
        "pipeline_summary": clip(compact_pipeline_summary(pipeline_summary), 8000),
        "classifier_dependency": classifier_dependency or "not_provided",
        "classifier_reason": classifier_reason or "N/A",
        "classifier_trace": clip(classifier_trace),
    }


def build_context_from_classifier_args(
    args: argparse.Namespace,
    classifier_result: dict | None,
    dependency_result: str | None,
    classifier_reason: str | None,
) -> dict[str, str]:
    classifier_result = classifier_result or {}
    return build_triage_context(
        project_name=getattr(args, "project_name", None),
        language=getattr(args, "language", None),
        target_name=getattr(args, "target_name", None),
        function_name=getattr(args, "function_name", None),
        branch_line_number=getattr(args, "branch_line_number", None),
        blocked_side_line_number=getattr(args, "blocked_side_line_number", None),
        source_file=getattr(args, "source_api_file", None) or getattr(args, "source_file", None),
        blocker_line_code=getattr(args, "blocker_line_code", None),
        blocked_side_line_code=getattr(args, "blocked_side_line_code", None),
        branch_hit_count=getattr(args, "branch_hit_count", "N/A"),
        blocked_side_hit_count=getattr(args, "blocked_side_hit_count", "N/A"),
        runtime_blocker_segment=read_resolved_text(
            getattr(args, "runtime_blocker_segment_file", None),
            getattr(args, "runtime_blocker_segment", None),
        ),
        runtime_blocker_segment_source_codes=read_resolved_text(
            getattr(args, "runtime_blocker_segment_source_codes_file", None),
            getattr(args, "runtime_blocker_segment_source_codes", None),
        ),
        cfg_source_codes=read_resolved_text(
            getattr(args, "cfg_source_codes_file", None),
            getattr(args, "cfg_source_codes", None),
        ),
        pipeline_failure_stage=getattr(args, "pipeline_failure_stage", None),
        pipeline_methods=getattr(args, "pipeline_methods", None),
        pipeline_summary=read_resolved_text(
            getattr(args, "pipeline_summary_file", None),
            getattr(args, "pipeline_summary", None),
        ),
        classifier_dependency=dependency_result,
        classifier_reason=classifier_reason,
        classifier_trace=classifier_result.get("analysis_trace", []),
        source_context_lines=int(getattr(args, "triage_source_context_lines", 25) or 25),
    )


def render_triage_prompt(context: dict[str, str]) -> str:
    template = load_text(TRIAGE_TEMPLATE_PATH)
    if not template:
        raise FileNotFoundError(f"Triage template missing: {TRIAGE_TEMPLATE_PATH}")
    return format_template(template, context)


def write_triage_artifacts(output_dir: Path, prompt: str, response_text: str | None, parsed: dict | None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = output_dir / "prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    paths = {"triage_output_dir": str(output_dir), "triage_prompt_path": str(prompt_path)}
    if response_text is not None:
        response_path = output_dir / "response.txt"
        response_path.write_text(response_text, encoding="utf-8")
        paths["triage_response_path"] = str(response_path)
    if parsed is not None:
        parsed_path = output_dir / "parsed.json"
        parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
        paths["triage_parsed_path"] = str(parsed_path)
    return paths


def run_triage_prompt(
    prompt: str,
    *,
    backend: str,
    model: str | None,
    output_dir: Path | None = None,
    emit_prompt_only: bool = False,
) -> dict:
    if emit_prompt_only:
        paths = write_triage_artifacts(output_dir, prompt, None, None) if output_dir else {}
        result = default_inconclusive("Prompt emitted only; LLM triage was not executed.")
        result["prompt"] = prompt
        result.update(paths)
        return result

    from llm_interface.llm_client import LLMClient

    llm = LLMClient(
        backend=backend,
        model_name=model,
        temperature=getattr(config, "BLOCKER_TRIAGE_TEMPERATURE", config.BLOCKER_CLASSIFIER_TEMPERATURE),
    )
    max_retries = max(0, int(getattr(config, "BLOCKER_TRIAGE_PARSE_MAX_RETRIES", 2)))
    retry_delay_sec = max(0.0, float(getattr(config, "BLOCKER_TRIAGE_PARSE_RETRY_DELAY_SEC", 2.0)))
    total_attempts = max_retries + 1
    response_text = ""
    current_prompt = prompt
    parsed = None
    last_error = "Unknown triage response error."

    for attempt in range(1, total_attempts + 1):
        response_text = llm.generate(current_prompt) or ""
        if not response_text:
            last_error = "LLM returned an empty triage response."
        else:
            try:
                parsed = normalize_triage_result(extract_json_object(response_text), response_text=response_text)
                parsed["llm_attempt_count"] = attempt
                break
            except Exception as exc:
                last_error = f"JSON parse error: {exc}"

        logging.warning(
            "Triage response failed on attempt %d/%d: %s",
            attempt,
            total_attempts,
            last_error,
        )
        if attempt < total_attempts:
            current_prompt = build_json_retry_prompt(prompt, response_text, last_error)
            if retry_delay_sec:
                time.sleep(retry_delay_sec)

    if parsed is None:
        parsed = default_triage_error(
            last_error,
            attempt_count=total_attempts,
            response_text=response_text,
        )
    paths = write_triage_artifacts(output_dir, prompt, response_text, parsed) if output_dir else {}
    parsed.update(paths)
    return parsed


def run_triage_for_classifier(
    args: argparse.Namespace,
    classifier_result: dict | None,
    dependency_result: str | None,
    classifier_reason: str | None,
) -> dict:
    context = build_context_from_classifier_args(args, classifier_result, dependency_result, classifier_reason)
    prompt = render_triage_prompt(context)
    output_dir = None
    if getattr(args, "output_root", None):
        output_dir = Path(args.output_root) / "triage"
    result = run_triage_prompt(
        prompt,
        backend=getattr(args, "backend", "vertexai"),
        model=getattr(args, "model", None),
        output_dir=output_dir,
        emit_prompt_only=bool(getattr(args, "triage_emit_prompts_only", False)),
    )
    if "prompt" not in result and bool(getattr(args, "triage_include_prompt", False)):
        result["prompt"] = prompt
    return result


def iter_json_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_json_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_dicts(child)


def load_blocker_source_map(blocker_json_paths: list[Path]) -> dict[tuple[str, str, str], dict]:
    source_map: dict[tuple[str, str, str], dict] = {}
    for path in blocker_json_paths:
        if not path or not path.exists():
            continue
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logging.warning("Failed to read blocker json %s: %s", path, exc)
            continue
        for item in iter_json_dicts(parsed):
            fn = item.get("function_name")
            branch = str(item.get("branch_line_number", "") or "")
            blocked = str(item.get("blocked_side_line_number", item.get("blocked_side_line_numder", "")) or "")
            if not fn or not branch:
                continue
            source_map[(str(fn), branch, blocked)] = item
            source_map[(str(fn), branch, "")] = item
    return source_map


def read_jsonl(path: Path) -> list[dict]:
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception as exc:
            logging.warning("Skipping malformed JSONL line %s:%d: %s", path, line_no, exc)
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def attempt_key(record: dict, project_override: str | None = None) -> tuple[str, str, str, str]:
    return (
        str(project_override or record.get("project") or record.get("project_name") or ""),
        str(record.get("function_name") or ""),
        str(record.get("branch_line_number") or ""),
        str(record.get("blocked_side_line_number") or ""),
    )


def build_offline_context(
    pipeline_record: dict,
    live_record: dict | None,
    source_record: dict | None,
    source_context_lines: int,
    project_name_override: str | None = None,
) -> dict[str, str]:
    project_name = project_name_override or pipeline_record.get("project") or pipeline_record.get("project_name")
    source_record = source_record or {}
    source_file = source_record.get("source_file") or pipeline_record.get("source_file")
    branch_hit_count = first_present(
        (live_record or {}).get("branch_hit_count"),
        source_record.get("project_branch_hit_count"),
        pipeline_record.get("project_branch_hit_count"),
    )
    blocked_hit_count = first_present(
        (live_record or {}).get("blocked_side_hit_count"),
        source_record.get("project_blocked_hit_count"),
        pipeline_record.get("project_blocked_hit_count"),
    )
    summary_text = compact_pipeline_summary(load_text(pipeline_record.get("pipeline_summary_path")))
    return build_triage_context(
        project_name=project_name,
        language="C/C++",
        target_name=pipeline_record.get("target_name") or source_record.get("best_target"),
        function_name=pipeline_record.get("function_name"),
        branch_line_number=pipeline_record.get("branch_line_number"),
        blocked_side_line_number=pipeline_record.get("blocked_side_line_number"),
        source_file=source_file,
        branch_hit_count=branch_hit_count,
        blocked_side_hit_count=blocked_hit_count,
        runtime_blocker_segment="N/A: offline blocker_attempts.jsonl does not store the full runtime segment.",
        runtime_blocker_segment_source_codes="N/A: offline mode relies on source snippet and saved pipeline summary unless a context file is supplied.",
        cfg_source_codes="N/A: offline mode relies on source snippet and saved pipeline summary unless a context file is supplied.",
        pipeline_failure_stage=pipeline_record.get("pipeline_failure_stage"),
        pipeline_methods=pipeline_record.get("pipeline_methods"),
        pipeline_summary=summary_text,
        classifier_dependency=pipeline_record.get("dependency_result"),
        classifier_reason=pipeline_record.get("reason"),
        classifier_trace=pipeline_record.get("analysis_trace", []),
        source_context_lines=source_context_lines,
    )


def load_manual_labels(path: Path | None) -> dict[tuple[str, str, str], dict]:
    if not path or not path.exists():
        return {}
    labels = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            key = (
                row.get("project", ""),
                row.get("function_name", ""),
                str(row.get("branch_line_number", "")),
            )
            labels[key] = row
    return labels


def add_manual_comparison(
    result: dict,
    pipeline_record: dict,
    manual_labels: dict[tuple[str, str, str], dict],
    project_override: str | None = None,
) -> None:
    key = (
        str(project_override or pipeline_record.get("project") or pipeline_record.get("project_name") or ""),
        str(pipeline_record.get("function_name") or ""),
        str(pipeline_record.get("branch_line_number") or ""),
    )
    manual = manual_labels.get(key)
    if not manual:
        return
    include = (manual.get("include_in_solver_evaluation") or "").strip().lower()
    manual_first_layer = "Generation-solvable" if include == "yes" else "Non-generation-solvable"
    if include not in {"yes", "no"}:
        manual_first_layer = "Inconclusive"
    manual_label = manual.get("refined_triage_label") or ""
    result["manual_first_layer_decision"] = manual_first_layer
    result["manual_refined_triage_label"] = manual_label
    result["matches_manual_first_layer"] = result.get("first_layer_decision") == manual_first_layer
    result["matches_manual_label"] = result.get("refined_triage_label") == manual_label


def filter_pipeline_records(records: list[dict], args: argparse.Namespace) -> list[dict]:
    selected = []
    case_fn = None
    case_branch = None
    if getattr(args, "case", None):
        if ":" not in args.case:
            raise ValueError("--case must use FUNCTION:BRANCH format")
        case_fn, case_branch = args.case.split(":", 1)
    for record in records:
        if record.get("event") != "blocker_pipeline_result":
            continue
        record_project = str(record.get("project") or record.get("project_name") or "")
        if args.project_name and record_project not in {"", args.project_name, "run_all_fuzzer"}:
            continue
        if args.function_name and str(record.get("function_name")) != args.function_name:
            continue
        if args.branch_line_number and str(record.get("branch_line_number")) != str(args.branch_line_number):
            continue
        if args.blocked_side_line_number and str(record.get("blocked_side_line_number")) != str(args.blocked_side_line_number):
            continue
        if case_fn and str(record.get("function_name")) != case_fn:
            continue
        if case_branch and str(record.get("branch_line_number")) != case_branch:
            continue
        selected.append(record)
        if args.limit and len(selected) >= args.limit:
            break
    return selected


def run_offline_triage(args: argparse.Namespace) -> int:
    records = read_jsonl(args.attempts_jsonl)
    live_by_key = {
        attempt_key(record, args.project_name): record
        for record in records
        if record.get("event") == "blocker_live_revalidation"
    }
    source_map = load_blocker_source_map(args.blocker_json_path or [])
    manual_labels = load_manual_labels(args.manual_labels_csv)
    selected = filter_pipeline_records(records, args)
    if not selected:
        logging.warning("No blocker_pipeline_result records matched the requested filters.")
        return 1

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    prompt_dir = args.save_prompts_dir
    if prompt_dir:
        prompt_dir.mkdir(parents=True, exist_ok=True)

    with args.output_jsonl.open("w", encoding="utf-8") as out:
        for record in selected:
            key = attempt_key(record, args.project_name)
            source_record = source_map.get((key[1], key[2], key[3])) or source_map.get((key[1], key[2], ""))
            context = build_offline_context(
                record,
                live_by_key.get(key),
                source_record,
                args.source_context_lines,
                project_name_override=args.project_name,
            )
            prompt = render_triage_prompt(context)
            output_dir = None
            if prompt_dir:
                safe_case = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{key[1]}_{key[2]}")
                output_dir = prompt_dir / safe_case
            started = time.perf_counter()
            triage = run_triage_prompt(
                prompt,
                backend=args.backend,
                model=args.model,
                output_dir=output_dir,
                emit_prompt_only=args.emit_prompts_only,
            )
            elapsed = time.perf_counter() - started
            add_manual_comparison(triage, record, manual_labels, project_override=args.project_name)
            output_record = {
                "project": key[0],
                "function_name": key[1],
                "branch_line_number": key[2],
                "blocked_side_line_number": key[3],
                "target_name": record.get("target_name"),
                "dependency_result": record.get("dependency_result"),
                "pipeline_failure_stage": record.get("pipeline_failure_stage"),
                "triage_elapsed_seconds": elapsed,
                "triage_result": triage,
            }
            if args.include_prompt:
                output_record["prompt"] = prompt
            out.write(json.dumps(output_record, ensure_ascii=False) + "\n")
    logging.info("Wrote triage decisions to %s", args.output_jsonl)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline and shared C/C++ blocker solvability triage.")
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--attempts-jsonl", type=Path, required=True)
    parser.add_argument("--blocker-json-path", type=Path, action="append", default=[])
    parser.add_argument("--manual-labels-csv", type=Path, default=None)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--function-name", default=None)
    parser.add_argument("--branch-line-number", default=None)
    parser.add_argument("--blocked-side-line-number", default=None)
    parser.add_argument("--case", default=None, help="Filter one case by FUNCTION:BRANCH.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--source-context-lines", type=int, default=25)
    parser.add_argument("--save-prompts-dir", type=Path, default=None)
    parser.add_argument("--emit-prompts-only", action="store_true")
    parser.add_argument("--include-prompt", action="store_true")
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args()
    try:
        raise SystemExit(run_offline_triage(args))
    except Exception as exc:
        logging.error("Triage failed: %s", exc, exc_info=True)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
