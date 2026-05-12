#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import re
import sys
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
        "header_code": header_code,
        "source_code": source_code,
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
    harness_code = parsed.get("harness_code", "")
    harness_filename = parsed.get("harness_filename", f"{args.mode}_harness.cpp")
    if not harness_code:
        raise RuntimeError("LLM response did not include harness_code.")

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
