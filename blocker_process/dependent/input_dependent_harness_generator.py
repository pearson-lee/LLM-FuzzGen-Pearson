#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

OUTPUT_ROOT = MODULE_ROOT / "generated_harnesses"
TEMPLATE_BY_MODE = {
    "symcc": REPO_ROOT / "prompts" / "templates" / "symcc_harness_generator_template",
    "klee": REPO_ROOT / "prompts" / "templates" / "klee_harness_generator_template",
}


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def read_optional_file(path_str: str | None) -> str:
    if not path_str:
        return "N/A"
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        return "N/A"
    text = load_text(path)
    return text if text else "N/A"


def clip_text(text: str, max_chars: int = 12000) -> str:
    if not text or text == "N/A":
        return "N/A"
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n\n... [truncated {omitted} characters] ..."


def resolve_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = read_optional_file(file_path)
        if text != "N/A":
            return text
    if inline_text:
        return inline_text
    return default


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


def extract_line_range_from_file(path_str: str | None, start_line: int, end_line: int) -> str:
    if not path_str or start_line <= 0 or end_line < start_line:
        return "N/A"

    path = Path(path_str)
    if not path.exists():
        return "N/A"

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "N/A"

    start = max(1, start_line)
    end = min(len(lines), end_line)
    rendered = [f"{line_no}: {lines[line_no - 1]}" for line_no in range(start, end + 1)]
    return "\n".join(rendered) if rendered else "N/A"


def extract_source_window_from_file(path_str: str | None, center_line: int, radius: int = 8) -> str:
    if not path_str or center_line <= 0:
        return "N/A"
    return extract_line_range_from_file(path_str, center_line - radius, center_line + radius)


def resolve_triggering_input(triggering_input: str) -> tuple[str, str]:
    if not triggering_input:
        return "N/A", "N/A"

    path = Path(triggering_input)
    if path.exists() and path.is_file():
        try:
            raw = path.read_bytes()
            preview = raw[:512].decode("utf-8", errors="replace")
            return str(path), preview
        except Exception:
            return str(path), "N/A"

    return "inline", triggering_input


def format_prompt(template: str, mapping: dict[str, str]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return mapping.get(key, match.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)


def extract_json(text: str) -> dict:
    if repair_json is not None:
        parsed = repair_json(text, return_objects=True)
        if isinstance(parsed, dict):
            return parsed

    candidates: list[str] = []
    if match := re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL):
        candidates.append(match.group(1))
    if match := re.search(r"(\{.*\})", text, re.DOTALL):
        candidates.append(match.group(1))
    candidates.append(text)

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    raise ValueError("Failed to parse response JSON.")


def strip_markdown_code_fence(text: str) -> str:
    stripped = text.strip()
    match = re.match(r"^```[a-zA-Z0-9_+-]*\n(?P<body>.*)\n```$", stripped, re.DOTALL)
    if match:
        return match.group("body").strip() + "\n"
    return text


def extract_prefixed_calls(code: str, prefixes: tuple[str, ...]) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        if not name.startswith(prefixes):
            continue
        if name in seen:
            continue
        seen.add(name)
        calls.append(name)
    return calls


COMMON_NON_PROJECT_CALLS = {
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "memcmp",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy",
    "strchr", "strrchr", "strstr",
    "snprintf", "vsnprintf", "printf", "fprintf", "perror",
    "fopen", "fclose", "fread", "fwrite",
    "abort", "exit", "assert",
}


def extract_called_functions(code: str) -> list[str]:
    calls: list[str] = []
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        calls.append(name)
    return calls


def extract_defined_functions(code: str) -> set[str]:
    defined: set[str] = set()
    pattern = re.compile(
        r"^\s*(?:[A-Za-z_][A-Za-z0-9_*\s]*\s+)*\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(code):
        name = match.group(1)
        if name in {"if", "for", "while", "switch"}:
            continue
        defined.add(name)
    return defined


def infer_project_prefix(name: str) -> str:
    stripped = name.lstrip("_")
    if "_" in stripped:
        return stripped.split("_", 1)[0]
    match = re.match(r"[a-z]+", stripped)
    return match.group(0) if match else stripped


def is_zero_arg_standalone_call(code: str, name: str) -> bool:
    pattern = re.compile(rf"^\s*{re.escape(name)}\s*\(\s*\)\s*;\s*$", re.MULTILINE)
    return bool(pattern.search(code))


def infer_blocker_relevant_project_calls(code: str) -> list[str]:
    defined = extract_defined_functions(code)
    called = extract_called_functions(code)

    prefix_counts: Counter[str] = Counter()
    for name in called:
        if name in defined or name in COMMON_NON_PROJECT_CALLS or name == "LLVMFuzzerTestOneInput":
            continue
        prefix = infer_project_prefix(name)
        if prefix:
            prefix_counts[prefix] += 1

    dominant_prefixes = {prefix for prefix, count in prefix_counts.items() if count >= 2}
    relevant: list[str] = []
    seen: set[str] = set()
    for name in called:
        if name in seen:
            continue
        seen.add(name)
        if name in defined or name in COMMON_NON_PROJECT_CALLS or name == "LLVMFuzzerTestOneInput":
            continue
        if infer_project_prefix(name) not in dominant_prefixes:
            continue
        if re.search(r"(Free|Delete|Destroy|Close|Release)", name):
            continue
        if is_zero_arg_standalone_call(code, name):
            continue
        relevant.append(name)
    return relevant


def summarize_fidelity_requirements(fuzz_target_code: str) -> str:
    requirements = [
        "- Keep the blocker-relevant control flow and state-building sequence close to the original fuzz target.",
        "- Remove symbolic noise only when it does not change object construction, nullability, formats, flags, or the API calls that produce the blocker state.",
        "- Do not clamp, sanitize, normalize, or replace blocker-relevant input fields unless the original fuzz target already does so.",
        "- If the original fuzz target already uses raw byte consumption instead of FuzzedDataProvider or STL wrappers, preserve that structure instead of inventing a shorter model.",
        "- Preserve format constants and execution-trigger steps that materially affect the blocker path, such as follow-up transform/evaluate calls after object creation.",
    ]

    ordered_calls = extract_prefixed_calls(fuzz_target_code, ("cms", "_cms"))
    if ordered_calls:
        rendered_calls = ", ".join(ordered_calls[:20])
        requirements.append(f"- Prefer preserving this original project API order when those calls are blocker-relevant: {rendered_calls}.")

    return "\n".join(requirements)


def extract_project_function_names(code: str) -> set[str]:
    return set(re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_*\s]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{", code))


def extract_segment_entry_api(runtime_blocker_segment: str, project_functions: set[str]) -> str | None:
    if not runtime_blocker_segment or runtime_blocker_segment == "N/A":
        return None

    for line in runtime_blocker_segment.splitlines():
        match = re.search(r"#\d+\s+([A-Za-z_][A-Za-z0-9_]*)\s+at\s+", line)
        if not match:
            continue
        function_name = match.group(1)
        if function_name == "LLVMFuzzerTestOneInput":
            continue
        if function_name in project_functions:
            return function_name
    return None


def validate_harness_semantics(
    original_code: str,
    generated_code: str,
    runtime_blocker_segment: str | None = None,
) -> list[str]:
    errors: list[str] = []

    if "LLVMFuzzerTestOneInput" not in generated_code:
        errors.append("Generated harness is missing LLVMFuzzerTestOneInput.")

    original_type_constants = sorted(set(re.findall(r"\bTYPE_[A-Za-z0-9_]+\b", original_code)))
    generated_type_constants = set(re.findall(r"\bTYPE_[A-Za-z0-9_]+\b", generated_code))
    missing_types = [item for item in original_type_constants if item not in generated_type_constants]
    if missing_types:
        errors.append(
            "Generated harness changed blocker-relevant format constants from the original fuzz target: "
            + ", ".join(missing_types)
        )

    original_uses_transform = "cmsDoTransform(" in original_code
    generated_uses_transform = "cmsDoTransform(" in generated_code
    if original_uses_transform and not generated_uses_transform:
        errors.append("Generated harness dropped cmsDoTransform even though the original fuzz target executes it.")

    original_has_raw_byte_flow = "FuzzedDataProvider" not in original_code and "std::" not in original_code
    generated_clamps_inputs = bool(
        re.search(r"if\s*\([^)]*(<=|>=|<|>)\s*0[^)]*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*=", generated_code)
    )
    if original_has_raw_byte_flow and generated_clamps_inputs:
        errors.append(
            "Generated harness adds new input clamping/normalization that does not exist in the original fuzz target."
        )

    project_functions = extract_project_function_names(original_code)
    segment_entry_api = extract_segment_entry_api(runtime_blocker_segment or "", project_functions)
    generated_project_calls = set(infer_blocker_relevant_project_calls(generated_code))
    if segment_entry_api and segment_entry_api not in generated_project_calls:
        errors.append(
            "Generated harness dropped the runtime blocker-segment entry API required to reach the blocker: "
            + segment_entry_api
        )

    return errors


def build_prompt(args: argparse.Namespace) -> str:
    template_path = TEMPLATE_BY_MODE[args.mode]
    if not template_path.exists():
        raise FileNotFoundError(f"Template missing: {template_path}")

    fuzz_target_code = clip_text(read_optional_file(args.fuzz_file), max_chars=16000)
    header_code = clip_text(read_optional_file(args.header_file), max_chars=12000)
    source_code = clip_text(read_optional_file(args.source_file), max_chars=18000)
    branch_window = extract_source_window_from_file(args.source_file, int(args.branch_line_number))
    blocked_window = extract_source_window_from_file(args.source_file, int(args.blocked_side_line_number))
    triggering_input_path, triggering_input_preview = resolve_triggering_input(args.triggering_input)

    mapping = {
        "mode": args.mode,
        "project_name": args.project_name,
        "language": args.language or "unknown",
        "function_name": args.function_name,
        "branch_line_number": str(args.branch_line_number),
        "blocked_side_line_number": str(args.blocked_side_line_number),
        "source_file": args.source_file or "N/A",
        "fuzz_file": args.fuzz_file or "N/A",
        "fuzz_target_name": Path(args.fuzz_file).stem if args.fuzz_file else "unknown",
        "fuzz_target_code": fuzz_target_code,
        "fidelity_requirements": summarize_fidelity_requirements(fuzz_target_code),
        "header_code": header_code,
        "source_code": source_code,
        "source_api_file": args.source_api_file or "N/A",
        "branch_window": clip_text(branch_window, max_chars=5000),
        "blocked_window": clip_text(blocked_window, max_chars=5000),
        "runtime_blocker_segment": clip_text(
            resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment),
            max_chars=7000,
        ),
        "runtime_blocker_segment_source_codes": clip_text(
            resolve_text(
                args.runtime_blocker_segment_source_codes_file,
                args.runtime_blocker_segment_source_codes,
            ),
            max_chars=9000,
        ),
        "cfg_call_chain": clip_text(resolve_text(args.cfg_call_chain_file, args.cfg_call_chain), max_chars=7000),
        "cfg_source_codes": clip_text(resolve_text(args.cfg_source_codes_file, args.cfg_source_codes), max_chars=9000),
        "triggering_input_path": triggering_input_path,
        "triggering_input_preview": triggering_input_preview,
        "template_path": str(MODULE_ROOT / "symex_harness_template.cpp"),
        "template_code": clip_text(load_text(MODULE_ROOT / "symex_harness_template.cpp"), max_chars=12000),
    }
    return format_prompt(load_text(template_path), mapping)


def write_harness(output_dir: Path, harness_code: str, suggested_name: str) -> Path:
    filename = sanitize_name(suggested_name or "generated_harness.cpp")
    if "." not in filename:
        filename += ".cpp"
    target = output_dir / filename
    target.write_text(harness_code, encoding="utf-8")
    return target


def run_generation(args: argparse.Namespace) -> dict:
    from llm_interface.llm_client import LLMClient

    prompt = build_prompt(args)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    output_dir = OUTPUT_ROOT / f"{safe_project}_{safe_function}_{args.mode}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    llm = LLMClient(backend=args.backend, model_name=args.model, temperature=args.temperature)
    response_text = llm.generate(prompt)
    if not response_text:
        raise RuntimeError("Empty LLM response.")

    parsed = extract_json(response_text)
    harness_code = strip_markdown_code_fence(parsed.get("harness_code", ""))
    harness_filename = parsed.get("harness_filename", f"{args.mode}_harness.cpp")
    if not harness_code:
        raise RuntimeError("LLM response did not include harness_code.")

    semantic_errors = validate_harness_semantics(
        original_code=read_optional_file(args.fuzz_file),
        generated_code=harness_code,
        runtime_blocker_segment=resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment),
    )
    if semantic_errors:
        raise RuntimeError("Generated harness failed semantic validation: " + " | ".join(semantic_errors))

    harness_path = write_harness(output_dir, harness_code, harness_filename)
    (output_dir / "response.txt").write_text(response_text, encoding="utf-8")
    (output_dir / "parsed.json").write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")

    result = {
        "success": True,
        "mode": args.mode,
        "output_dir": str(output_dir),
        "prompt_path": str(output_dir / "prompt.txt"),
        "response_path": str(output_dir / "response.txt"),
        "parsed_path": str(output_dir / "parsed.json"),
        "harness_path": str(harness_path),
        "harness_filename": harness_path.name,
        "analysis_summary": parsed.get("analysis_summary", []),
        "harness_design_rationale": parsed.get("harness_design_rationale", ""),
        "klee_extract_object": parsed.get("klee_extract_object", "input"),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a SymCC/KLEE-friendly harness for an input-dependent blocker.")
    parser.add_argument("--mode", required=True, choices=["symcc", "klee"])
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True)
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--source-api-file", default=None)
    parser.add_argument("--fuzz-file", required=True)
    parser.add_argument("--header-file", default=None)
    parser.add_argument("--language", default=None)
    parser.add_argument("--runtime-blocker-segment-file", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes-file", default=None)
    parser.add_argument("--cfg-call-chain-file", default=None)
    parser.add_argument("--cfg-source-codes-file", default=None)
    parser.add_argument("--runtime-blocker-segment", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes", default=None)
    parser.add_argument("--cfg-call-chain", default=None)
    parser.add_argument("--cfg-source-codes", default=None)
    parser.add_argument("--triggering-input", default="")
    args = parser.parse_args()

    try:
        result = run_generation(args)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Harness generation failed: %s", exc, exc_info=True)
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
