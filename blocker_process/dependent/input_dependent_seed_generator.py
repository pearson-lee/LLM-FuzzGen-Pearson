#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import logging
import re
import shutil
import shlex
import subprocess
import sys
import time
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from external.oss_fuzz import OSSFuzz
from blocker_process.coverage_utils import get_line_execution_count
from blocker_process.dependent.format_inference import FormatInfo, infer_input_format
from blocker_process.dependent.format_strategies import build_format_strategy_notes
import config.config as config

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "blocker_seed_generator_template"
OUTPUT_ROOT = MODULE_ROOT / "generated_generators"
OSS_FUZZ_IMAGE_PREFIX = "gcr.io/oss-fuzz"
FAMILY_TAG_RE = re.compile(r"^(F\d+_[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*)_(\d+)$")
FAMILY_FALLBACK_RE = re.compile(r"^(.*?)(?:_(\d+))?$")
MAX_GENERATOR_ITERATIONS = 3
MAX_GENERATOR_FIX_ATTEMPTS = 2
DEFAULT_REPRESENTATIVE_SEEDS_PER_NEW_FAMILY = 2
DEFAULT_REPRESENTATIVE_SEEDS_PER_EXISTING_FAMILY = 1
DEFAULT_MAX_REPRESENTATIVE_EVALS = 12
DEFAULT_CORPUS_REPLAY_BATCH_SIZE = 300
MAX_SEED_SIZE_BYTES = 65536           # 64KB; oversized seeds are skipped in representative eval
DEFAULT_GENERATOR_TIMEOUT_SEC = 120   # Seed materialization should be short; long runs are pathological
DEFAULT_COVERAGE_SEED_TIMEOUT_SEC = 30    # libfuzzer -timeout per seed (primary defence)
DEFAULT_COVERAGE_EVAL_TIMEOUT_SEC = 120   # subprocess wall-clock limit for per-seed Docker eval
DEFAULT_COVERAGE_BATCH_TIMEOUT_SEC = 600  # subprocess wall-clock limit for aggregate batch eval
_SESSION_FILE_HANDLER_FLAG = "_llm_fuzzgen_session_file_handler"
SEED_BUDGET_ERROR_KINDS = {
    "all_generated_seeds_oversized",
    "generator_timeout_no_valid_seeds",
    "generator_timeout_partial_output",
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


def to_api_filepath(path_str: str) -> str:
    if not path_str:
        return ""
    normalized = path_str.replace("\\", "/")
    marker = "/inspector/source-code"
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    build_out_src_marker = "/build/out/"
    if build_out_src_marker in normalized and "/src/" in normalized:
        return normalized[normalized.index("/src/") :]
    return normalized


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


def extract_source_window_from_file(path_str: str | None, center_line: int, radius: int = 6) -> str:
    if not path_str or center_line <= 0:
        return "N/A"
    return extract_line_range_from_file(path_str, center_line - radius, center_line + radius)


def extract_line_text_from_window(window_text: str, target_line: int) -> str:
    if not window_text or window_text == "N/A":
        return "N/A"
    prefix = f"{target_line}:"
    for line in window_text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip() or "N/A"
    return "N/A"


def build_branch_predicate_description(
    branch_line_number: int,
    blocked_side_line_number: int,
    branch_window: str,
    blocked_window: str,
) -> str:
    branch_text = extract_line_text_from_window(branch_window, branch_line_number)
    blocked_text = extract_line_text_from_window(blocked_window, blocked_side_line_number)
    return (
        f"Reach branch line {branch_line_number} where the blocker predicate is evaluated, "
        f"then drive execution into blocked-side line {blocked_side_line_number}. "
        f"Branch line snippet: {branch_text}. "
        f"Blocked-side snippet: {blocked_text}."
    )


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


def find_function_metadata(project_name: str, function_name: str) -> dict:
    return {}


def get_function_source(
    project_name: str,
    function_signature: str,
    local_source_file: str | None,
    source_line_begin: int,
    source_line_end: int,
) -> str:
    if local_source_file and source_line_begin > 0 and source_line_end >= source_line_begin:
        snippet = extract_line_range_from_file(local_source_file, source_line_begin, source_line_end)
        if snippet != "N/A":
            return snippet

    return "N/A"


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


def salvage_string_field(raw_text: str, key: str) -> str:
    pattern = re.compile(
        rf'"{re.escape(key)}"\s*:\s*"""\s*(.*?)\s*"""|"'
        rf'{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"',
        re.DOTALL,
    )
    match = pattern.search(raw_text)
    if not match:
        return ""
    triple_quoted = match.group(1)
    if triple_quoted is not None:
        return triple_quoted
    quoted = match.group(2) or ""
    try:
        return json.loads(f'"{quoted}"')
    except Exception:
        return quoted


def salvage_list_field(raw_text: str, key: str) -> list:
    pattern = re.compile(rf'"{re.escape(key)}"\s*:\s*(\[[\s\S]*?\])', re.DOTALL)
    match = pattern.search(raw_text)
    if not match:
        return []
    candidate = match.group(1)
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def enrich_parsed_response(raw_text: str, parsed: dict) -> dict:
    enriched = dict(parsed)
    if not enriched.get("generator_code"):
        salvaged_code = salvage_string_field(raw_text, "generator_code")
        if salvaged_code:
            enriched["generator_code"] = salvaged_code
    if not enriched.get("generator_filename"):
        salvaged_name = salvage_string_field(raw_text, "generator_filename")
        if salvaged_name:
            enriched["generator_filename"] = salvaged_name
    if not enriched.get("generator_design_rationale"):
        salvaged_rationale = salvage_string_field(raw_text, "generator_design_rationale")
        if salvaged_rationale:
            enriched["generator_design_rationale"] = salvaged_rationale
    if not isinstance(enriched.get("sample_seeds"), list):
        salvaged_samples = salvage_list_field(raw_text, "sample_seeds")
        if salvaged_samples:
            enriched["sample_seeds"] = salvaged_samples
    return enriched


def format_prompt(template: str, mapping: dict[str, str]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return mapping.get(key, match.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)


def _sample_seed_text_preview(seed: object) -> str:
    if isinstance(seed, str):
        return seed
    if isinstance(seed, (bytes, bytearray)):
        return bytes(seed).decode("utf-8", errors="ignore")
    if isinstance(seed, list):
        if all(isinstance(item, int) for item in seed):
            return bytes(int(item) & 0xFF for item in seed).decode("utf-8", errors="ignore")
        return "".join(str(item) for item in seed)
    if isinstance(seed, int):
        return chr(seed & 0xFF) if 0 <= seed <= 255 else str(seed)
    if seed is None:
        return ""
    if isinstance(seed, (dict, tuple)):
        return json.dumps(seed, ensure_ascii=False)
    return str(seed)


def seed_to_bytes(seed: object) -> bytes:
    if isinstance(seed, bytes):
        return seed
    if isinstance(seed, bytearray):
        return bytes(seed)
    if isinstance(seed, int):
        return bytes([seed & 0xFF]) if 0 <= seed <= 255 else str(seed).encode("utf-8")
    if isinstance(seed, list):
        if all(isinstance(item, int) for item in seed):
            return bytes(int(item) & 0xFF for item in seed)
        if all(isinstance(item, str) for item in seed):
            return "".join(seed).encode("utf-8")
        return json.dumps(seed, ensure_ascii=False).encode("utf-8")
    if seed is None:
        return b""
    if not isinstance(seed, str):
        if isinstance(seed, dict):
            return json.dumps(seed, ensure_ascii=False).encode("utf-8")
        seed = str(seed)

    if r"\x" in seed:
        try:
            return bytes(seed, "utf-8").decode("unicode_escape").encode("latin-1", errors="replace")
        except Exception:
            pass
    compact_hex = seed.strip()
    if compact_hex and len(compact_hex) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact_hex):
        try:
            return bytes.fromhex(compact_hex)
        except ValueError:
            pass
    try:
        return seed.encode("latin-1")
    except UnicodeEncodeError:
        return seed.encode("utf-8")


def choose_seed_extension(seed: object, format_info: FormatInfo) -> str:
    if format_info.extensions:
        return format_info.extensions[0]

    trimmed = _sample_seed_text_preview(seed).lstrip()
    if trimmed.startswith("<"):
        return ".xml"
    if trimmed.startswith("{") or trimmed.startswith("["):
        return ".json"
    return ".txt" if format_info.is_text else ".bin"


def save_sample_seeds(output_dir: Path, sample_seeds: list[object], format_info: FormatInfo) -> list[Path]:
    seeds_dir = output_dir / "sample_seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    saved_paths: list[Path] = []
    for index, seed in enumerate(sample_seeds, start=1):
        try:
            suffix = choose_seed_extension(seed, format_info)
            target = seeds_dir / f"seed_{index:02d}{suffix}"
            target.write_bytes(seed_to_bytes(seed))
            saved_paths.append(target)
        except Exception as exc:
            logging.warning(
                "Skipping malformed sample seed %d (%s): %s",
                index,
                type(seed).__name__,
                exc,
            )
    return saved_paths


def build_prompt(args: argparse.Namespace) -> str:
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template missing: {TEMPLATE_PATH}")

    oss_fuzz = OSSFuzz()
    language = args.language or oss_fuzz.proj_lang(args.project_name) or "unknown"
    fuzz_target_code = clip_text(read_optional_file(args.fuzz_file), max_chars=12000)
    header_code = clip_text(read_optional_file(args.header_file), max_chars=12000)
    source_code = clip_text(read_optional_file(args.source_file), max_chars=16000)
    branch_window = extract_source_window_from_file(args.source_file, int(args.branch_line_number))
    blocked_window = extract_source_window_from_file(args.source_file, int(args.blocked_side_line_number))
    branch_predicate_description = build_branch_predicate_description(
        int(args.branch_line_number),
        int(args.blocked_side_line_number),
        branch_window,
        blocked_window,
    )
    triggering_input_path, triggering_input_preview = resolve_triggering_input(args.triggering_input)

    function_meta = find_function_metadata(args.project_name, args.function_name)
    function_signature = function_meta.get("function_signature", args.function_name)
    possible_headers = ", ".join(function_meta.get("possible_header_files", []))
    if not possible_headers and args.header_file:
        possible_headers = args.header_file
    if not possible_headers:
        possible_headers = "N/A"
    function_source = get_function_source(
        args.project_name,
        function_signature,
        args.source_file,
        int(function_meta.get("source_line_begin", 0) or 0),
        int(function_meta.get("source_line_end", 0) or 0),
    )
    if function_source == "N/A":
        branch_line = int(args.branch_line_number)
        blocked_line = int(args.blocked_side_line_number)
        function_source = extract_line_range_from_file(
            args.source_file,
            min(branch_line, blocked_line) - 20,
            max(branch_line, blocked_line) + 20,
        )

    format_info = infer_input_format(
        project_name=args.project_name,
        function_name=args.function_name,
        fuzz_target_code=fuzz_target_code,
        source_code=source_code,
        triggering_input_path=triggering_input_path if triggering_input_path != "inline" else args.triggering_input,
        triggering_input_preview=triggering_input_preview,
    )
    format_strategy_notes = build_format_strategy_notes(format_info)

    mapping = {
        "project_name": args.project_name,
        "language": language,
        "function_name": args.function_name,
        "function_signature": function_signature,
        "possible_headers": possible_headers,
        "branch_line_number": str(args.branch_line_number),
        "blocked_side_line_number": str(args.blocked_side_line_number),
        "source_file": args.source_file or "N/A",
        "api_source_file": to_api_filepath(args.source_file or "") or "N/A",
        "fuzz_file": args.fuzz_file or "N/A",
        "fuzz_target_name": Path(args.fuzz_file).stem if args.fuzz_file else "unknown",
        "triggering_input_path": triggering_input_path,
        "triggering_input_preview": triggering_input_preview,
        "fuzz_target_code": fuzz_target_code,
        "header_code": header_code,
        "source_code": source_code,
        "target_function_source": clip_text(function_source, max_chars=12000),
        "branch_window": clip_text(branch_window, max_chars=4000),
        "blocked_window": clip_text(blocked_window, max_chars=4000),
        "branch_predicate_description": clip_text(branch_predicate_description, max_chars=1200),
        "runtime_blocker_segment": clip_text(
            resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment),
            max_chars=6000,
        ),
        "runtime_blocker_segment_source_codes": clip_text(
            resolve_text(
                args.runtime_blocker_segment_source_codes_file,
                args.runtime_blocker_segment_source_codes,
            ),
            max_chars=8000,
        ),
        "cfg_call_chain": clip_text(resolve_text(args.cfg_call_chain_file, args.cfg_call_chain), max_chars=6000),
        "cfg_source_codes": clip_text(resolve_text(args.cfg_source_codes_file, args.cfg_source_codes), max_chars=8000),
        "blocker_call_sites": clip_text(
            resolve_text(
                getattr(args, "blocker_call_sites_file", None),
                getattr(args, "blocker_call_sites", None),
            ),
            max_chars=8000,
        ),
        "format_strategy_notes": format_strategy_notes,
    }
    mapping.update(format_info.to_prompt_mapping())
    template = load_text(TEMPLATE_PATH)
    return format_prompt(template, mapping)


def build_iteration_prompt(
    base_prompt: str,
    iteration_index: int,
    max_iterations: int,
    previous_generator_code: str = "",
    previous_rationale: str = "",
    previous_analysis_summary: list[str] | None = None,
    evaluation_summary: str = "",
    generated_seed_preview: str = "",
    family_summary_text: str = "",
    format_hint: str = "",
) -> str:
    if iteration_index == 1:
        return base_prompt

    analysis_text = "\n".join(f"- {item}" for item in (previous_analysis_summary or [])) or "N/A"
    format_hint_section = ""
    if format_hint:
        format_hint_section = f"""

## Format mismatch detected — reference seed hint

{format_hint}
"""
    appended = f"""

# Iteration Context

This is iteration {iteration_index} of {max_iterations}.

You are revising the previous generator based on execution feedback. Keep any working ideas that improved blocker reachability, but change the generator where the evidence shows it is insufficient.
{format_hint_section}
## Previous generator analysis summary
{analysis_text}

## Previous generator rationale
{previous_rationale or 'N/A'}

## Previous generator code
```python
{previous_generator_code or 'N/A'}
```

## Generated seed preview from previous iteration
```text
{generated_seed_preview or 'N/A'}
```

## Execution feedback from previous iteration
```text
{evaluation_summary or 'N/A'}
```

## Family-level blocker feedback summary
```text
{family_summary_text or 'N/A'}
```

## Revision instructions

- Treat this as a blocker-branch-oriented feedback loop, not generic seed generation.
- First write `failure_analysis`, then `family_decisions`, then `revision_plan`, and only then produce `generator_code`.
- Keep stable family names for useful families. Do not rename or reshuffle every family on each iteration.
- If a family reaches the branch line but not the blocked side, refine that family near the blocker condition.
- If a family cannot reach the branch line, either discard it or replace it with a structurally different family.
- Distinguish corpus-level coverage from generated-family coverage. If post-merge coverage says the branch is
  reached but every generated family has branch_hits=0, then the generated seeds did NOT reach the branch. Treat this
  as did_not_reach_branch, not as predicate_false.
- If generated families do not reach the branch, revisit [0A API Anchor], [0B Input Layout], and
  [0C2 Call-Site Reachability] before changing predicate values. Reaching the branch may require an independent
  caller-trigger input feature that is separate from the predicate setter; if the generated input set the predicate
  but still never reached the branch, a required caller-trigger feature is likely missing and must be added.
- If the blocker is selected through a parser, decoder, dispatcher, state machine, opcode switch, field-tag switch,
  handler table, or virtual/visitor dispatch, also revisit whether the generated input used the exact representation
  category that selects the target route. Do not treat a semantically similar surface form as equivalent unless it
  reaches the same function path.
- If generated families reach the branch but not the blocked side, revisit [0C Predicate Setter], [0D Reader Path],
  and [0E Survival Check].
- Do not switch to another input format or another API unless execution feedback proves the current API anchor is
  wrong.
- Preserve useful seed families and add new targeted variants instead of replacing everything blindly.
- Your job is to improve the generator for the next iteration, not to explain why iteration is impossible.
"""
    return base_prompt + appended


def build_generator_fix_prompt(
    *,
    base_prompt: str,
    validation_kind: str,
    validation_output: str,
    previous_generator_code: str,
    previous_rationale: str,
    fix_attempt_index: int,
    max_fix_attempts: int,
) -> str:
    return (
        base_prompt
        + f"""

# Generator Repair Context

The previous generator is invalid. This is repair attempt {fix_attempt_index} of {max_fix_attempts}.

Your job in this repair attempt is different from the normal blocker-solving iteration:

- Repair only the generator's low-level executable issues.
- Preserve the existing blocker-oriented seed strategy unless the error directly requires a local fix.
- Keep the `build_seeds()` interface and `python generator.py --output-dir DIR` behavior intact.
- Keep stable family tags and filenames when possible.
- Do not replace the generator with a brand-new strategy unless the current script is fundamentally unusable.

## Validation failure kind
{validation_kind or 'unknown'}

## Validation failure output
```text
{validation_output or 'N/A'}
```

## Previous generator rationale
{previous_rationale or 'N/A'}

## Previous generator code
```python
{previous_generator_code or 'N/A'}
```

## Repair instructions

1. Fix the reported validation error first.
2. Make the smallest correction that restores generator executability.
3. Preserve the blocker-oriented seed families and intent.
4. Return the same JSON schema as the normal task, with corrected `generator_code`.
"""
    )


def setup_file_logging(func_name: str, log_dir: str | Path | None = None) -> None:
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}_seedgen.log"

    resolved_log_dir = Path(log_dir) if log_dir else REPO_ROOT / "logs"
    resolved_log_dir.mkdir(parents=True, exist_ok=True)
    log_filepath = resolved_log_dir / log_filename

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, _SESSION_FILE_HANDLER_FLAG, False):
            root_logger.removeHandler(handler)
            handler.close()

    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    setattr(file_handler, _SESSION_FILE_HANDLER_FLAG, True)
    root_logger.addHandler(file_handler)
    logging.info("Log file create: %s", log_filepath)


def write_generator(output_dir: Path, generator_code: str, suggested_name: str) -> Path:
    filename = sanitize_name(suggested_name or "seed_generator.py")
    if not filename.endswith(".py"):
        filename += ".py"
    generator_path = output_dir / filename
    generator_path.write_text(generator_code, encoding="utf-8")
    return generator_path


def _coerce_subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def scan_and_reject_oversized_seeds(
    generated_dir: Path,
    *,
    max_seed_size_bytes: int = MAX_SEED_SIZE_BYTES,
) -> dict:
    rejected_dir = generated_dir.parent / f"{generated_dir.name}_oversized_rejected"
    if rejected_dir.exists():
        shutil.rmtree(rejected_dir, ignore_errors=True)

    files = sorted(path for path in generated_dir.rglob("*") if path.is_file()) if generated_dir.exists() else []
    total_bytes = 0
    largest_seed_size = 0
    valid_seed_count = 0
    oversized_records: list[dict] = []

    for seed_path in files:
        try:
            seed_size = seed_path.stat().st_size
        except OSError:
            continue
        total_bytes += seed_size
        largest_seed_size = max(largest_seed_size, seed_size)
        if seed_size <= max_seed_size_bytes:
            valid_seed_count += 1
            continue

        relative_path = seed_path.relative_to(generated_dir)
        rejected_path = rejected_dir / relative_path
        rejected_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(seed_path), str(rejected_path))
        oversized_records.append({
            "source_path": str(seed_path),
            "rejected_path": str(rejected_path),
            "seed_size_bytes": seed_size,
        })

    return {
        "seed_size_limit_bytes": max_seed_size_bytes,
        "generated_seed_count_before_filter": len(files),
        "valid_seed_count": valid_seed_count,
        "oversized_seed_count": len(oversized_records),
        "generated_total_bytes_before_filter": total_bytes,
        "largest_seed_size_bytes": largest_seed_size,
        "oversized_rejected_dir": str(rejected_dir) if oversized_records else "",
        "oversized_seed_records": oversized_records,
    }


def _render_validation_output(base_output: str, scan_metadata: dict) -> str:
    lines: list[str] = []
    if base_output:
        lines.append(base_output.strip())
    lines.append(
        "Seed materialization budget: "
        f"valid={scan_metadata.get('valid_seed_count', 0)}, "
        f"oversized_rejected={scan_metadata.get('oversized_seed_count', 0)}, "
        f"limit={scan_metadata.get('seed_size_limit_bytes', MAX_SEED_SIZE_BYTES)}B, "
        f"largest={scan_metadata.get('largest_seed_size_bytes', 0)}B"
    )
    rejected_dir = str(scan_metadata.get("oversized_rejected_dir") or "")
    if rejected_dir:
        lines.append(f"Oversized seeds moved to: {rejected_dir}")
    return "\n".join(lines).strip()


def validate_generator(
    generator_path: Path,
    output_dir: Path,
    materialized_dir_name: str = "materialized_by_generator",
    *,
    timeout_seconds: int | float = DEFAULT_GENERATOR_TIMEOUT_SEC,
    max_seed_size_bytes: int = MAX_SEED_SIZE_BYTES,
) -> dict:
    validation_started_at = time.monotonic()
    compile_started_at = time.monotonic()
    py_compile = subprocess.run(
        [sys.executable, "-m", "py_compile", str(generator_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    py_compile_elapsed = time.monotonic() - compile_started_at
    if py_compile.returncode != 0:
        return {
            "ok": False,
            "error_kind": "compile_failed",
            "output": py_compile.stderr or py_compile.stdout,
            "generated_dir": output_dir / materialized_dir_name,
            "py_compile_elapsed_seconds": py_compile_elapsed,
            "validation_elapsed_seconds": time.monotonic() - validation_started_at,
        }

    generated_dir = output_dir / materialized_dir_name
    if generated_dir.exists():
        shutil.rmtree(generated_dir, ignore_errors=True)
    generated_dir.mkdir(parents=True, exist_ok=True)
    generator_started_at = time.monotonic()
    generator_timed_out = False
    timeout_output = ""
    try:
        run_result = subprocess.run(
            [sys.executable, str(generator_path), "--output-dir", str(generated_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        generator_timed_out = True
        timeout_output = "\n".join(
            part for part in [
                _coerce_subprocess_text(exc.stdout),
                _coerce_subprocess_text(exc.stderr),
                f"Generator timed out after {timeout_seconds} seconds.",
            ] if part
        )
        run_result = None
    generator_elapsed = time.monotonic() - generator_started_at

    scan_metadata = scan_and_reject_oversized_seeds(
        generated_dir,
        max_seed_size_bytes=max_seed_size_bytes,
    )
    common_metadata = {
        **scan_metadata,
        "generated_dir": generated_dir,
        "py_compile_elapsed_seconds": py_compile_elapsed,
        "generator_elapsed_seconds": generator_elapsed,
        "validation_elapsed_seconds": time.monotonic() - validation_started_at,
        "generator_timeout_seconds": timeout_seconds,
        "generator_timed_out": generator_timed_out,
    }

    if generator_timed_out:
        output = _render_validation_output(timeout_output, scan_metadata)
        if int(scan_metadata.get("valid_seed_count", 0)) > 0:
            return {
                "ok": True,
                "error_kind": "generator_timeout_partial_output",
                "output": output,
                **common_metadata,
            }
        return {
            "ok": False,
            "error_kind": "generator_timeout_no_valid_seeds",
            "output": output,
            **common_metadata,
        }

    assert run_result is not None
    if run_result.returncode != 0:
        return {
            "ok": False,
            "error_kind": "runtime_failed",
            "output": _render_validation_output(run_result.stderr or run_result.stdout, scan_metadata),
            **common_metadata,
        }

    generated_seed_count = int(scan_metadata.get("valid_seed_count", 0))
    if generated_seed_count <= 0 and int(scan_metadata.get("oversized_seed_count", 0)) > 0:
        return {
            "ok": False,
            "error_kind": "all_generated_seeds_oversized",
            "output": _render_validation_output(run_result.stdout.strip(), scan_metadata),
            **common_metadata,
        }
    if generated_seed_count <= 0:
        return {
            "ok": False,
            "error_kind": "no_output",
            "output": _render_validation_output(
                run_result.stdout.strip() or "Generator finished without writing any seed files.",
                scan_metadata,
            ),
            **common_metadata,
        }

    return {
        "ok": True,
        "error_kind": "",
        "output": _render_validation_output(run_result.stdout.strip(), scan_metadata),
        **common_metadata,
    }


def normalize_count(raw: str) -> int:
    raw = (raw or "").strip()
    if not raw or raw == "0":
        return 0

    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kMGT]?)", raw)
    if not match:
        return 0

    value = float(match.group(1))
    suffix = match.group(2)
    multipliers = {
        "": 1,
        "k": 1_000,
        "M": 1_000_000,
        "G": 1_000_000_000,
        "T": 1_000_000_000_000,
    }
    return int(value * multipliers[suffix])


def guess_container_source_file(project_name: str, local_source_file: str) -> str:
    source_path = Path(local_source_file)
    if source_path.is_absolute():
        parts = source_path.parts
        if "src" in parts:
            src_index = parts.index("src")
            return "/out/" + "/".join(parts[src_index:])
        return f"/out/{source_path.name}"

    normalized = local_source_file.replace("\\", "/")
    marker = "/inspector/source-code"
    if marker in normalized:
        inner = normalized.split(marker, 1)[1]
        return f"/out{inner}"
    if "/src/" in normalized:
        return f"/out{normalized[normalized.index('/src/'):]}"
    return f"/out/src/{project_name}/{source_path.name}"


def run_cmd(cmd: list[str], timeout_sec: int | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="",
            stderr=f"Command timed out after {timeout_sec}s",
        )


def run_in_ossfuzz(
    project_name: str,
    out_dir: Path,
    corpus_root: Path,
    command: str,
    timeout_sec: int | None = None,
) -> subprocess.CompletedProcess:
    image = f"{OSS_FUZZ_IMAGE_PREFIX}/{project_name}"
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{out_dir}:/out",
        "-v",
        f"{corpus_root}:/corpus",
        image,
        "bash",
        "-lc",
        command,
    ]
    return run_cmd(docker_cmd, timeout_sec=timeout_sec)


def materialized_seed_preview(generated_dir: Path, max_files: int = 8, max_bytes: int = 160) -> str:
    if not generated_dir.exists():
        return "N/A"

    previews: list[str] = []
    for path in sorted(p for p in generated_dir.rglob("*") if p.is_file())[:max_files]:
        try:
            raw = path.read_bytes()[:max_bytes]
            preview = raw.decode("utf-8", errors="replace")
        except Exception:
            preview = "<unreadable>"
        previews.append(f"{path.name}: {preview}")
    return "\n".join(previews) if previews else "N/A"


def derive_seed_family(path: Path) -> str:
    stem = sanitize_name(path.stem)
    match = FAMILY_TAG_RE.match(stem)
    if match:
        return match.group(1)
    fallback = FAMILY_FALLBACK_RE.match(stem)
    if fallback and fallback.group(1):
        return fallback.group(1)
    return "F00_unclassified"


def summarize_family_inventory(generated_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted(p for p in generated_dir.rglob("*") if p.is_file()):
        family = derive_seed_family(path)
        counts[family] = counts.get(family, 0) + 1
    return counts


def materialize_triggering_input(
    triggering_input: str,
    format_info: FormatInfo,
    dest_dir: Path,
) -> Path:
    if not triggering_input:
        raise ValueError("No triggering input is available.")

    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    trigger_path = Path(triggering_input)
    if trigger_path.exists() and trigger_path.is_file():
        seed_bytes = trigger_path.read_bytes()
        suffix = trigger_path.suffix or choose_seed_extension(seed_bytes, format_info)
    else:
        seed_bytes = seed_to_bytes(triggering_input)
        suffix = choose_seed_extension(triggering_input, format_info)

    materialized_seed = dest_dir / f"triggering_input{suffix}"
    materialized_seed.write_bytes(seed_bytes)
    return materialized_seed


def build_seed_records(seed_paths: list[Path], source_kind: str) -> list[dict]:
    records: list[dict] = []
    for path in seed_paths:
        if not path.is_file():
            continue
        payload = path.read_bytes()
        records.append(
            {
                "source_path": str(path.resolve()),
                "source_kind": source_kind,
                "family": "F00_triggering" if source_kind == "triggering" else derive_seed_family(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "seed_size_bytes": len(payload),
            }
        )
    return records


def build_corpus_manifest(corpus_dir: Path) -> dict[str, dict[str, object]]:
    if not corpus_dir.exists():
        return {}

    manifest: dict[str, dict[str, object]] = {}
    for path in sorted(p for p in corpus_dir.rglob("*") if p.is_file()):
        payload = path.read_bytes()
        manifest[path.relative_to(corpus_dir).as_posix()] = {
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    return manifest


def prepare_isolated_corpus_snapshot(
    snapshot_dir: Path,
    seed_records: list[dict],
) -> tuple[list[dict], dict]:
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    isolated_records: list[dict] = []
    duplicate_records: list[dict] = []
    seen_hashes: dict[str, str] = {}
    for record in seed_records:
        source_path = Path(str(record.get("source_path", "")))
        if not source_path.is_file():
            continue
        payload = source_path.read_bytes()
        digest = str(record.get("sha256") or hashlib.sha256(payload).hexdigest())
        if digest in seen_hashes:
            duplicate_records.append(
                {
                    "source_path": str(source_path),
                    "sha256": digest,
                    "duplicate_of": seen_hashes[digest],
                }
            )
            continue

        suffix = source_path.suffix or ".bin"
        target = snapshot_dir / (
            f"{len(isolated_records):04d}_{sanitize_name(source_path.stem)}_{digest[:12]}{suffix}"
        )
        shutil.copy2(source_path, target)
        isolated_record = dict(record)
        isolated_record.update(
            {
                "source_path": str(source_path.resolve()),
                "sha256": digest,
                "isolated_path": str(target.resolve()),
                "evaluation_seed_path": str(target.resolve()),
            }
        )
        isolated_records.append(isolated_record)
        seen_hashes[digest] = str(source_path.resolve())

    metadata = {
        "isolated_corpus_dir": str(snapshot_dir.resolve()),
        "input_seed_count": len(seed_records),
        "copied_seed_count": len(isolated_records),
        "duplicate_seed_count": len(duplicate_records),
        "duplicate_records": duplicate_records,
    }
    return isolated_records, metadata


def evaluate_iteration_with_coverage(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    function_name: str,
    source_file: str,
    source_api_file: str | None,
    branch_line: int,
    blocked_side_line: int,
    fuzz_seconds: int,
    output_dir: Path,
    report_basename: str = "aggregate",
    corpus_subdir_name: str | None = None,
) -> dict:
    build_result = oss_fuzz.build_fuzzers(project_name, "coverage")
    if not build_result.success:
        return {
            "success": False,
            "error": f"Coverage build failed: {build_result.error}",
        }

    coverage_source = source_api_file or source_file
    container_source_file = guess_container_source_file(project_name, coverage_source)
    out_dir = oss_fuzz.build_out_dir / project_name
    corpus_root = oss_fuzz.build_corpus_dir / project_name
    corpus_name = corpus_subdir_name or fuzzer_name
    batch_size = DEFAULT_CORPUS_REPLAY_BATCH_SIZE
    command = (
        "rm -f /tmp/iter_*.profraw /tmp/iter.profdata && "
        "seed_count=0 && batch_num=0 && batch=() && "
        f"while IFS= read -r -d '' seed; do "
        "batch+=(\"$seed\"); seed_count=$((seed_count + 1)); "
        f"if [ ${{#batch[@]}} -ge {batch_size} ]; then "
        f"LLVM_PROFILE_FILE=\"/tmp/iter_${{batch_num}}.profraw\" "
        f"/out/{shlex.quote(fuzzer_name)} -rss_limit_mb=0 -timeout={DEFAULT_COVERAGE_SEED_TIMEOUT_SEC} \"${{batch[@]}}\" || exit $?; "
        "batch_num=$((batch_num + 1)); batch=(); fi; "
        f"done < <(find /corpus/{shlex.quote(corpus_name)} -type f -print0 | sort -z) && "
        "if [ \"$seed_count\" -eq 0 ]; then echo \"No corpus seeds found for coverage replay.\" >&2; exit 3; fi && "
        "if [ ${#batch[@]} -gt 0 ]; then "
        f"LLVM_PROFILE_FILE=\"/tmp/iter_${{batch_num}}.profraw\" "
        f"/out/{shlex.quote(fuzzer_name)} -rss_limit_mb=0 -timeout={DEFAULT_COVERAGE_SEED_TIMEOUT_SEC} \"${{batch[@]}}\" || exit $?; "
        "fi && "
        "if ! ls /tmp/iter_*.profraw >/dev/null 2>&1; then echo \"Coverage replay did not produce profraw files.\" >&2; exit 4; fi && "
        "llvm-profdata merge -sparse /tmp/iter_*.profraw -o /tmp/iter.profdata && "
        f"llvm-cov show /out/{shlex.quote(fuzzer_name)} "
        "-instr-profile=/tmp/iter.profdata "
        "-show-branches=count "
        "-show-instantiations=false "
        "-Xdemangler c++filt "
        "-path-equivalence=/,/out "
        f"{shlex.quote(container_source_file)}"
    )
    result = run_in_ossfuzz(project_name, out_dir, corpus_root, command, timeout_sec=DEFAULT_COVERAGE_BATCH_TIMEOUT_SEC)
    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr.strip() or result.stdout.strip() or "Coverage command failed.",
            "container_source_file": container_source_file,
        }

    report = result.stdout
    (output_dir / f"{report_basename}.linecovreport").write_text(report, encoding="utf-8")

    branch_raw = get_line_execution_count(report, branch_line, function_name=function_name)
    blocked_raw = get_line_execution_count(report, blocked_side_line, function_name=function_name)
    branch_hits = normalize_count(branch_raw)
    blocked_hits = normalize_count(blocked_raw)
    return {
        "success": True,
        "container_source_file": container_source_file,
        "branch_hit_count_raw": branch_raw or "0",
        "blocked_side_hit_count_raw": blocked_raw or "0",
        "branch_hit_count": branch_hits,
        "blocked_side_hit_count": blocked_hits,
        "branch_line_reached": branch_hits > 0,
        "blocked_side_line_reached": blocked_hits > 0,
    }


def choose_representative_seed_records(
    seed_records: list[dict],
    known_families: set[str],
    per_new_family: int = DEFAULT_REPRESENTATIVE_SEEDS_PER_NEW_FAMILY,
    per_existing_family: int = DEFAULT_REPRESENTATIVE_SEEDS_PER_EXISTING_FAMILY,
    max_total: int = DEFAULT_MAX_REPRESENTATIVE_EVALS,
) -> list[dict]:
    family_groups: dict[str, list[dict]] = {}
    for record in seed_records:
        family = str(record.get("family") or "F00_unclassified")
        family_groups.setdefault(family, []).append(record)

    selected: list[dict] = []
    for family in sorted(family_groups):
        budget = per_new_family if family not in known_families else per_existing_family
        selected.extend(family_groups[family][:budget])
        if len(selected) >= max_total:
            break
    return selected[:max_total]


def evaluate_seed_with_coverage_in_ossfuzz(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    function_name: str,
    source_file: str,
    source_api_file: str | None,
    branch_line: int,
    blocked_side_line: int,
    seed_path: Path,
    output_dir: Path,
    report_name: str,
) -> dict:
    coverage_source = source_api_file or source_file
    container_source_file = guess_container_source_file(project_name, coverage_source)
    out_dir = oss_fuzz.build_out_dir / project_name
    corpus_root = oss_fuzz.build_corpus_dir / project_name
    try:
        relative_seed_path = seed_path.relative_to(corpus_root)
    except ValueError:
        return {
            "success": False,
            "error": f"Representative seed is outside corpus root: {seed_path}",
        }

    container_seed_path = f"/corpus/{relative_seed_path.as_posix()}"
    profile_stem = sanitize_name(report_name)
    command = (
        f"rm -f /tmp/{profile_stem}.profraw /tmp/{profile_stem}.profdata && "
        f"LLVM_PROFILE_FILE=/tmp/{profile_stem}.profraw "
        f"/out/{shlex.quote(fuzzer_name)} -runs=1 -rss_limit_mb=0 -timeout={DEFAULT_COVERAGE_SEED_TIMEOUT_SEC} "
        f"{shlex.quote(container_seed_path)} && "
        f"llvm-profdata merge -sparse /tmp/{profile_stem}.profraw -o /tmp/{profile_stem}.profdata && "
        f"llvm-cov show /out/{shlex.quote(fuzzer_name)} "
        f"-instr-profile=/tmp/{profile_stem}.profdata "
        "-show-branches=count "
        "-show-instantiations=false "
        "-Xdemangler c++filt "
        "-path-equivalence=/,/out "
        f"{shlex.quote(container_source_file)}"
    )
    result = run_in_ossfuzz(project_name, out_dir, corpus_root, command, timeout_sec=DEFAULT_COVERAGE_EVAL_TIMEOUT_SEC)
    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr.strip() or result.stdout.strip() or "Representative coverage command failed.",
        }

    report = result.stdout
    (output_dir / f"{report_name}.linecovreport").write_text(report, encoding="utf-8")
    branch_raw = get_line_execution_count(report, branch_line, function_name=function_name)
    blocked_raw = get_line_execution_count(report, blocked_side_line, function_name=function_name)
    branch_hits = normalize_count(branch_raw)
    blocked_hits = normalize_count(blocked_raw)
    return {
        "success": True,
        "seed_path": str(seed_path),
        "branch_hit_count_raw": branch_raw or "0",
        "blocked_side_hit_count_raw": blocked_raw or "0",
        "branch_hit_count": branch_hits,
        "blocked_side_hit_count": blocked_hits,
        "branch_reached": branch_hits > 0,
        "blocked_side_reached": blocked_hits > 0,
    }


def evaluate_triggering_input_with_coverage(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    function_name: str,
    source_file: str,
    source_api_file: str | None,
    branch_line: int,
    blocked_side_line: int,
    triggering_input: str,
    format_info: FormatInfo,
    output_dir: Path,
) -> dict:
    if not triggering_input:
        return {
            "success": False,
            "error": "No triggering input is available.",
        }

    try:
        project_corpus_root = oss_fuzz.build_corpus_dir / project_name
        eval_corpus_dir = project_corpus_root / f"{fuzzer_name}__triggering_input_eval"
        materialized_seed = materialize_triggering_input(triggering_input, format_info, eval_corpus_dir)
        seed_size = materialized_seed.stat().st_size
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to materialize triggering input for coverage replay: {exc}",
        }

    eval_result = evaluate_seed_with_coverage_in_ossfuzz(
        oss_fuzz=oss_fuzz,
        project_name=project_name,
        fuzzer_name=fuzzer_name,
        function_name=function_name,
        source_file=source_file,
        source_api_file=source_api_file,
        branch_line=branch_line,
        blocked_side_line=blocked_side_line,
        seed_path=materialized_seed,
        output_dir=output_dir,
        report_name="triggering_input",
    )
    if isinstance(eval_result, dict):
        eval_result["seed_size_bytes"] = seed_size
    return eval_result


def evaluate_representative_seed_records(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    function_name: str,
    source_file: str,
    source_api_file: str | None,
    branch_line: int,
    blocked_side_line: int,
    representative_records: list[dict],
    output_dir: Path,
) -> list[dict]:
    representative_results: list[dict] = []
    for index, record in enumerate(representative_records, start=1):
        source_path = Path(str(record.get("source_path", "")))
        evaluation_seed_path = Path(
            str(record.get("evaluation_seed_path") or record.get("isolated_path") or "")
        )
        family = str(record.get("family") or "F00_unclassified")
        seed_size = source_path.stat().st_size if source_path.is_file() else 0
        if seed_size > MAX_SEED_SIZE_BYTES:
            logging.warning(
                "Skipping oversized representative seed (%dB > %dB): %s",
                seed_size, MAX_SEED_SIZE_BYTES, source_path.name,
            )
            representative_results.append({
                "family": family,
                "seed_path": str(source_path),
                "evaluation_seed_path": str(evaluation_seed_path),
                "source_path": str(source_path),
                "success": False,
                "skipped": True,
                "skip_reason": "oversized_seed",
                "seed_size_bytes": seed_size,
            })
            continue
        eval_result = evaluate_seed_with_coverage_in_ossfuzz(
            oss_fuzz=oss_fuzz,
            project_name=project_name,
            fuzzer_name=fuzzer_name,
            function_name=function_name,
            source_file=source_file,
            source_api_file=source_api_file,
            branch_line=branch_line,
            blocked_side_line=blocked_side_line,
            seed_path=evaluation_seed_path,
            output_dir=output_dir,
            report_name=f"representative_{index:02d}_{family}",
        )
        eval_result.pop("seed_path", None)
        representative_results.append(
            {
                "family": family,
                "seed_path": str(source_path),
                "evaluation_seed_path": str(evaluation_seed_path),
                "source_path": str(source_path),
                "sha256": record.get("sha256", ""),
                **eval_result,
            }
        )
    return representative_results


def summarize_family_performance(
    family_counts: dict[str, int],
    representative_results: list[dict],
) -> dict:
    per_family: dict[str, dict] = {}
    for family, seed_count in sorted(family_counts.items()):
        per_family[family] = {
            "family": family,
            "generated_seed_count": int(seed_count),
            "representative_count": 0,
            "branch_reached_count": 0,
            "blocked_side_reached_count": 0,
            "max_branch_hit_count": 0,
            "max_blocked_side_hit_count": 0,
            "seed_results": [],
        }

    for result in representative_results:
        family = str(result.get("family") or "F00_unclassified")
        family_entry = per_family.setdefault(
            family,
            {
                "family": family,
                "generated_seed_count": 0,
                "representative_count": 0,
                "branch_reached_count": 0,
                "blocked_side_reached_count": 0,
                "max_branch_hit_count": 0,
                "max_blocked_side_hit_count": 0,
                "seed_results": [],
            },
        )
        family_entry["representative_count"] += 1
        family_entry["branch_reached_count"] += int(bool(result.get("branch_reached")))
        family_entry["blocked_side_reached_count"] += int(bool(result.get("blocked_side_reached")))
        family_entry["max_branch_hit_count"] = max(
            int(family_entry["max_branch_hit_count"]),
            int(result.get("branch_hit_count", 0) or 0),
        )
        family_entry["max_blocked_side_hit_count"] = max(
            int(family_entry["max_blocked_side_hit_count"]),
            int(result.get("blocked_side_hit_count", 0) or 0),
        )
        family_entry["seed_results"].append(
            {
                "seed_path": result.get("seed_path", ""),
                "branch_hit_count": int(result.get("branch_hit_count", 0) or 0),
                "blocked_side_hit_count": int(result.get("blocked_side_hit_count", 0) or 0),
                "branch_reached": bool(result.get("branch_reached")),
                "blocked_side_reached": bool(result.get("blocked_side_reached")),
            }
        )

    ranked_families: list[dict] = []
    for family_entry in per_family.values():
        representative_count = int(family_entry["representative_count"])
        branch_reach_ratio = (
            float(family_entry["branch_reached_count"]) / representative_count if representative_count > 0 else 0.0
        )
        family_entry["branch_reach_ratio"] = branch_reach_ratio
        if int(family_entry["blocked_side_reached_count"]) > 0:
            rank_bucket = 2
        elif int(family_entry["branch_reached_count"]) > 0:
            rank_bucket = 1
        else:
            rank_bucket = 0
        family_entry["rank_bucket"] = rank_bucket
        ranked_families.append(family_entry)

    ranked_families.sort(
        key=lambda item: (
            int(item["rank_bucket"]),
            int(item["max_branch_hit_count"]),
            float(item["branch_reach_ratio"]),
        ),
        reverse=True,
    )
    best_family = ranked_families[0]["family"] if ranked_families else ""
    stable_branch_families = [
        item["family"]
        for item in ranked_families
        if int(item["branch_reached_count"]) > 0 and int(item["blocked_side_reached_count"]) == 0
    ]
    dead_families = [item["family"] for item in ranked_families if int(item["branch_reached_count"]) == 0]
    keep_families = [
        item["family"]
        for item in ranked_families
        if int(item["blocked_side_reached_count"]) > 0 or float(item["branch_reach_ratio"]) >= 0.5
    ]
    refine_families = [
        item["family"]
        for item in ranked_families
        if int(item["branch_reached_count"]) > 0 and int(item["blocked_side_reached_count"]) == 0
    ]
    discard_families = [item["family"] for item in ranked_families if int(item["branch_reached_count"]) == 0]
    generated_family_reached_branch = any(
        int(item["branch_reached_count"]) > 0 for item in ranked_families
    )
    generated_family_reached_blocked_side = any(
        int(item["blocked_side_reached_count"]) > 0 for item in ranked_families
    )
    return {
        "best_family": best_family,
        "generated_family_reached_branch": generated_family_reached_branch,
        "generated_family_reached_blocked_side": generated_family_reached_blocked_side,
        "seed_contract_reproduction_success": generated_family_reached_blocked_side,
        "stable_branch_families": stable_branch_families,
        "dead_families": dead_families,
        "keep_families": keep_families,
        "refine_families": refine_families,
        "discard_families": discard_families,
        "ranked_families": ranked_families,
    }


def render_family_summary_text(family_summary: dict) -> str:
    ranked_families = family_summary.get("ranked_families", [])
    lines = [
        f"best_family: {family_summary.get('best_family') or 'N/A'}",
        f"generated_family_reached_branch: {family_summary.get('generated_family_reached_branch', False)}",
        f"generated_family_reached_blocked_side: {family_summary.get('generated_family_reached_blocked_side', False)}",
        f"seed_contract_reproduction_success: {family_summary.get('seed_contract_reproduction_success', False)}",
        f"stable_branch_families: {', '.join(family_summary.get('stable_branch_families', [])) or 'none'}",
        f"dead_families: {', '.join(family_summary.get('dead_families', [])) or 'none'}",
        f"keep_families: {', '.join(family_summary.get('keep_families', [])) or 'none'}",
        f"refine_families: {', '.join(family_summary.get('refine_families', [])) or 'none'}",
        f"discard_families: {', '.join(family_summary.get('discard_families', [])) or 'none'}",
    ]
    for item in ranked_families:
        lines.append(
            "family={family} generated={generated} reps={reps} branch_hits={branch_hits} "
            "blocked_hits={blocked_hits} branch_ratio={ratio:.2f} rank_bucket={bucket}".format(
                family=item.get("family", "unknown"),
                generated=int(item.get("generated_seed_count", 0) or 0),
                reps=int(item.get("representative_count", 0) or 0),
                branch_hits=int(item.get("max_branch_hit_count", 0) or 0),
                blocked_hits=int(item.get("max_blocked_side_hit_count", 0) or 0),
                ratio=float(item.get("branch_reach_ratio", 0.0) or 0.0),
                bucket=int(item.get("rank_bucket", 0) or 0),
            )
        )
    return "\n".join(lines)


def compute_family_signal_score(family_summary: dict) -> int:
    ranked_families = family_summary.get("ranked_families", [])
    if not ranked_families:
        return 0
    best = ranked_families[0]
    return (
        int(best.get("rank_bucket", 0) or 0) * 1_000_000
        + int(best.get("max_blocked_side_hit_count", 0) or 0) * 10_000
        + int(best.get("max_branch_hit_count", 0) or 0) * 100
        + int(round(float(best.get("branch_reach_ratio", 0.0) or 0.0) * 100))
    )


def select_best_symcc_candidates(
    family_summary: dict,
    representative_results: list[dict],
) -> dict:
    ranked_families = family_summary.get("ranked_families", []) or []
    if not ranked_families:
        return {
            "best_family": "",
            "top_families": [],
            "candidate_seed_records": [],
            "candidate_seed_paths": [],
            "selection_reason": "No ranked family information is available.",
        }

    top_families = [
        str(item.get("family") or "")
        for item in ranked_families
        if int(item.get("branch_reached_count", 0) or 0) > 0
    ][:2]
    if not top_families:
        top_families = [str(ranked_families[0].get("family") or "")]
    best_family = top_families[0] if top_families else ""

    family_results = [item for item in representative_results if str(item.get("family") or "") in set(top_families)]
    if not family_results:
        return {
            "best_family": best_family,
            "top_families": top_families,
            "candidate_seed_records": [],
            "candidate_seed_paths": [],
            "selection_reason": "Top-ranked branch-reaching families have no representative seed results.",
        }

    def _seed_size(result: dict) -> int:
        seed_path = Path(str(result.get("seed_path", "")))
        try:
            return seed_path.stat().st_size
        except OSError:
            return 1 << 30

    candidate_seed_records: list[dict] = []
    for family in top_families:
        branch_reaching_results = [
            item for item in family_results if str(item.get("family") or "") == family and bool(item.get("branch_reached"))
        ]
        if not branch_reaching_results:
            continue
        best_seed = sorted(
            branch_reaching_results,
            key=lambda item: (
                int(item.get("branch_hit_count", 0) or 0),
                -_seed_size(item),
            ),
            reverse=True,
        )[0]
        candidate_seed_records.append(
            {
                "family": family,
                "seed_path": str(best_seed.get("seed_path", "")).strip(),
                "branch_hit_count": int(best_seed.get("branch_hit_count", 0) or 0),
                "blocked_side_hit_count": int(best_seed.get("blocked_side_hit_count", 0) or 0),
                "branch_reached": bool(best_seed.get("branch_reached")),
                "blocked_side_reached": bool(best_seed.get("blocked_side_reached")),
                "seed_size_bytes": _seed_size(best_seed),
            }
        )

    ranked_seed_records = sorted(
        candidate_seed_records,
        key=lambda item: (
            int(item.get("branch_hit_count", 0) or 0),
            -int(item.get("seed_size_bytes", 1 << 30) or (1 << 30)),
        ),
        reverse=True,
    )

    candidate_seed_paths = [item["seed_path"] for item in ranked_seed_records if item.get("seed_path")][:3]

    return {
        "best_family": best_family,
        "top_families": top_families,
        "candidate_seed_records": ranked_seed_records[:3],
        "candidate_seed_paths": candidate_seed_paths[:3],
        "selection_reason": (
            "Selected one branch-reaching representative seed from each top-ranked family, "
            "then ranked by branch hit count and smaller seed size."
        ),
    }


def select_recommended_symcc_generator_seeds(
    generator_terminal_reason: str,
    symcc_candidate_bundle: dict,
    triggering_input_evaluation: dict | None,
) -> dict:
    if generator_terminal_reason in {
        "no_branch_signal",
        "invalid_generator",
        "already_covered_in_baseline",
        "no_useful_signal",
    }:
        return {
            "recommended_generator_seed_paths": [],
            "recommended_generator_seed_records": [],
            "selection_reason": f"Generator terminal reason {generator_terminal_reason} does not justify generator-seed handoff.",
        }

    candidate_records = list(symcc_candidate_bundle.get("candidate_seed_records", []) or [])
    if not candidate_records:
        return {
            "recommended_generator_seed_paths": [],
            "recommended_generator_seed_records": [],
            "selection_reason": "No branch-reaching candidate seeds were selected from generator families.",
        }

    baseline_branch = -1
    baseline_size = 1 << 30
    if isinstance(triggering_input_evaluation, dict) and triggering_input_evaluation.get("success"):
        baseline_branch = int(triggering_input_evaluation.get("branch_hit_count", 0) or 0)
        baseline_size = int(triggering_input_evaluation.get("seed_size_bytes", 1 << 30) or (1 << 30))

    qualified_records: list[dict] = []
    if generator_terminal_reason == "stalled_at_branch":
        # For stalled_at_branch, the goal is to give SymCC diverse starting points.
        # Seeds from select_best_symcc_candidates() already have branch_reached=True,
        # meaning they've already passed all input-gates. Accept them all regardless of
        # baseline comparison — hitting branch more times than the original is not the goal.
        qualified_records = [
            item for item in candidate_records
            if int(item.get("branch_hit_count", 0) or 0) > 0
        ]
    else:
        for item in candidate_records:
            branch_hits = int(item.get("branch_hit_count", 0) or 0)
            seed_size = int(item.get("seed_size_bytes", 1 << 30) or (1 << 30))
            if branch_hits <= 0:
                continue
            if baseline_branch < 0:
                qualified_records.append(item)
                continue
            if branch_hits > baseline_branch:
                qualified_records.append(item)
                continue
            if branch_hits == baseline_branch and seed_size < baseline_size:
                qualified_records.append(item)

    max_generator_seed_count = 0
    if generator_terminal_reason == "stalled_at_branch":
        max_generator_seed_count = 4
    elif generator_terminal_reason == "coverage_progress_observed_but_not_solved":
        max_generator_seed_count = 4
    elif generator_terminal_reason == "family_progress_observed_but_not_solved":
        max_generator_seed_count = 1

    recommended_records = qualified_records[:max_generator_seed_count]
    recommended_paths = [str(item.get("seed_path", "")).strip() for item in recommended_records if item.get("seed_path")]

    if generator_terminal_reason == "stalled_at_branch":
        baseline_note = (
            "Baseline comparison skipped for stalled_at_branch: all branch-reaching generator seeds "
            "accepted to maximise SymCC starting-point diversity."
        )
    elif baseline_branch < 0:
        baseline_note = "Triggering-input branch coverage was unavailable, so branch-reaching generator seeds were accepted without baseline comparison."
    else:
        baseline_note = (
            f"Compared against triggering input baseline (branch_hit_count={baseline_branch}, "
            f"seed_size_bytes={baseline_size})."
        )

    return {
        "recommended_generator_seed_paths": recommended_paths,
        "recommended_generator_seed_records": recommended_records,
        "selection_reason": (
            f"{baseline_note} Terminal reason {generator_terminal_reason} allows up to {max_generator_seed_count} "
            "generator seeds for SymCC handoff."
        ),
    }


def compute_coverage_delta(baseline: dict, post_merge: dict) -> dict:
    if not baseline.get("success") or not post_merge.get("success"):
        return {
            "success": False,
            "error": "Cannot compute delta because baseline or post-merge coverage failed.",
            "coverage_novelty_success": False,
        }

    baseline_branch = int(baseline.get("branch_hit_count", 0))
    baseline_blocked = int(baseline.get("blocked_side_hit_count", 0))
    post_branch = int(post_merge.get("branch_hit_count", 0))
    post_blocked = int(post_merge.get("blocked_side_hit_count", 0))
    return {
        "success": True,
        "branch_hit_count_delta": post_branch - baseline_branch,
        "blocked_side_hit_count_delta": post_blocked - baseline_blocked,
        "newly_reached_branch_line": (baseline_branch == 0 and post_branch > 0),
        "newly_reached_blocked_side_line": (baseline_blocked == 0 and post_blocked > 0),
        "coverage_novelty_success": (baseline_blocked == 0 and post_blocked > 0),
    }


def classify_iteration_status(
    validation_ok: bool,
    generated_seed_count: int,
    baseline_evaluation: dict,
    post_merge_evaluation: dict,
    coverage_delta: dict,
    representative_results: list[dict],
    family_summary: dict,
    previous_family_signal_score: int,
) -> tuple[str, str]:
    if not validation_ok:
        return "invalid_generator", "Generator validation failed."
    if generated_seed_count <= 0:
        return "invalid_generator", "Generator produced no materialized seeds."
    if baseline_evaluation.get("success") and baseline_evaluation.get("blocked_side_line_reached"):
        return "already_covered_in_baseline", "Blocked-side line was already covered before merging generated seeds."
    representative_solved = any(
        bool(result.get("success")) and bool(result.get("blocked_side_reached"))
        for result in representative_results
    )
    if representative_solved:
        return "solved", "A generated representative seed directly reached the blocked-side line."
    if not baseline_evaluation.get("success"):
        return "evaluation_failed", f"Baseline evaluation failed: {baseline_evaluation.get('error', 'unknown error')}"
    if coverage_delta.get("newly_reached_blocked_side_line"):
        return "solved", "Blocked-side line was newly reached after merging generated seeds."
    if not post_merge_evaluation.get("success"):
        return "evaluation_failed", f"Post-merge evaluation failed: {post_merge_evaluation.get('error', 'unknown error')}"

    branch_delta = int(coverage_delta.get("branch_hit_count_delta", 0))
    blocked_delta = int(coverage_delta.get("blocked_side_hit_count_delta", 0))
    family_signal_score = compute_family_signal_score(family_summary)
    family_progress = family_signal_score > previous_family_signal_score
    best_family = family_summary.get("best_family") or "N/A"
    if blocked_delta > 0:
        return "coverage_progress", "Blocked-side hit count increased but blocker is not fully solved."
    if branch_delta > 0:
        return "coverage_progress", "Branch-line hit count increased."
    if family_progress:
        return "family_progress", f"Best family {best_family} improved blocker-oriented reachability without changing coverage."
    if not post_merge_evaluation.get("branch_line_reached") and not family_summary.get("stable_branch_families"):
        return "no_branch_signal", "No representative family or aggregate corpus can currently reach the branch line."
    if post_merge_evaluation.get("branch_line_reached") and not post_merge_evaluation.get("blocked_side_line_reached"):
        return "stalled_at_branch", f"Best family {best_family} still reaches only the blocker branch path."
    return "no_progress", "No useful blocker-oriented signal was observed from generated seeds."


def diagnose_iteration(
    iteration_status: str,
    validation_ok: bool,
    generated_seed_count: int,
    staging_metadata: dict,
    baseline_evaluation: dict,
    post_merge_evaluation: dict,
    coverage_delta: dict,
    family_summary: dict,
) -> dict:
    branch_delta = int(coverage_delta.get("branch_hit_count_delta", 0) or 0)
    blocked_delta = int(coverage_delta.get("blocked_side_hit_count_delta", 0) or 0)
    added_seed_count = int(staging_metadata.get("added_seed_count", 0) or 0)
    skipped_duplicate_seed_count = int(staging_metadata.get("skipped_duplicate_seed_count", 0) or 0)
    generated_family_reached_branch = bool(family_summary.get("generated_family_reached_branch"))
    generated_family_reached_blocked_side = bool(family_summary.get("generated_family_reached_blocked_side"))
    branch_reached = bool(post_merge_evaluation.get("branch_line_reached")) or generated_family_reached_branch
    blocked_reached = bool(post_merge_evaluation.get("blocked_side_line_reached")) or generated_family_reached_blocked_side
    baseline_blocked_reached = bool(baseline_evaluation.get("blocked_side_line_reached"))
    newly_blocked_reached = bool(coverage_delta.get("newly_reached_blocked_side_line"))
    coverage_novelty_success = bool(coverage_delta.get("coverage_novelty_success")) or (
        bool(baseline_evaluation.get("success"))
        and not baseline_blocked_reached
        and generated_family_reached_blocked_side
    )
    seed_contract_reproduction_success = bool(family_summary.get("seed_contract_reproduction_success"))
    stable_branch_families = family_summary.get("stable_branch_families", [])
    dead_families = family_summary.get("dead_families", [])
    keep_families = family_summary.get("keep_families", [])
    refine_families = family_summary.get("refine_families", [])
    discard_families = family_summary.get("discard_families", [])

    if not validation_ok or generated_seed_count <= 0:
        code = "generator_invalid"
        action = "Inspect generator_code and validation_output before changing prompt strategy."
    elif baseline_evaluation.get("success") and baseline_blocked_reached:
        code = "already_covered_in_baseline"
        action = "Skip blocker solving for this target because the blocked side was already covered before this iteration."
    elif generated_family_reached_blocked_side or newly_blocked_reached:
        code = "solved"
        action = "Stop seed generation for this blocker."
    elif added_seed_count == 0 and skipped_duplicate_seed_count > 0:
        code = "generated_seeds_duplicate_existing_behavior"
        action = "Ask the next iteration for structurally different seed families."
    elif not baseline_evaluation.get("success") or not post_merge_evaluation.get("success"):
        code = "coverage_evaluation_failed"
        action = "Fix build or coverage evaluation before interpreting seed quality."
    elif iteration_status == "no_branch_signal":
        baseline_branch = int(baseline_evaluation.get("branch_hit_count", 0))
        if baseline_branch > 0:
            code = "format_mismatch_seed"
            action = (
                "Your generated seeds cannot reach the branch but the initial corpus seed can. "
                "The next iteration prompt will include a format hint with the reference seed. "
                "Analyze the reference seed's size, encoding, and structure before generating new seeds."
            )
        else:
            code = "no_branch_signal"
            action = "Replace dead families with structurally different families that target input materialization earlier in the harness."
    elif iteration_status == "family_progress":
        code = "family_progress_without_coverage_delta"
        action = "Keep the best family as a SymCC candidate, but refine within that family because aggregate coverage did not improve."
    elif branch_reached and blocked_delta <= 0:
        code = "reaches_branch_but_condition_not_satisfied"
        action = "Refine blocker-controlled fields or escalate to SymCC if the path is stable."
    elif branch_delta > 0 or blocked_delta > 0:
        code = "partial_coverage_progress"
        action = "Preserve useful seed families and refine values near the blocker."
    else:
        code = "structure_not_reaching_blocker"
        action = "Change higher-level input structure or revisit inferred format."

    return {
        "diagnosis_code": code,
        "recommended_next_action": action,
        "symcc_candidate": code == "reaches_branch_but_condition_not_satisfied",
        "branch_hit_count_delta": branch_delta,
        "blocked_side_hit_count_delta": blocked_delta,
        "added_seed_count": added_seed_count,
        "skipped_duplicate_seed_count": skipped_duplicate_seed_count,
        "branch_line_reached": branch_reached,
        "blocked_side_line_reached": blocked_reached,
        "baseline_blocked_side_line_reached": baseline_blocked_reached,
        "newly_reached_blocked_side_line": newly_blocked_reached,
        "coverage_novelty_success": coverage_novelty_success,
        "generated_family_reached_branch": generated_family_reached_branch,
        "generated_family_reached_blocked_side": generated_family_reached_blocked_side,
        "seed_contract_reproduction_success": seed_contract_reproduction_success,
        "iteration_status": iteration_status,
        "best_family": family_summary.get("best_family", ""),
        "stable_branch_families": stable_branch_families,
        "dead_families": dead_families,
        "keep_families": keep_families,
        "refine_families": refine_families,
        "discard_families": discard_families,
    }


def summarize_evaluation(
    iteration_index: int,
    generated_seed_count: int,
    added_seed_count: int,
    skipped_duplicate_seed_count: int,
    total_seed_count_after_merge: int,
    validation_ok: bool,
    validation_error_kind: str,
    validation_output: str,
    baseline_evaluation: dict,
    post_merge_evaluation: dict,
    coverage_delta: dict,
    iteration_status: str,
    status_reason: str,
    diagnosis: dict,
    family_summary: dict,
    family_summary_text: str,
) -> str:
    lines = [
        f"Iteration: {iteration_index}",
        f"Iteration status: {iteration_status}",
        f"Status reason: {status_reason}",
        f"Coverage progress this iteration: {iteration_status == 'coverage_progress' or iteration_status == 'solved'}",
        f"Family progress this iteration: {iteration_status == 'family_progress'}",
        f"Coverage novelty success: {diagnosis.get('coverage_novelty_success', False)}",
        f"Generated family reached branch: {diagnosis.get('generated_family_reached_branch', False)}",
        f"Generated family reached blocked side: {diagnosis.get('generated_family_reached_blocked_side', False)}",
        f"Seed contract reproduction success: {diagnosis.get('seed_contract_reproduction_success', False)}",
        f"Diagnosis: {diagnosis.get('diagnosis_code', 'unknown')}",
        f"Recommended next action: {diagnosis.get('recommended_next_action', 'N/A')}",
        f"SymCC candidate: {diagnosis.get('symcc_candidate', False)}",
        f"Best family: {family_summary.get('best_family') or 'N/A'}",
        f"Best SymCC family: {diagnosis.get('best_symcc_family') or 'N/A'}",
        f"Best SymCC seeds: {', '.join(diagnosis.get('best_symcc_seed_paths', [])) or 'none'}",
        f"Generator validation: {'success' if validation_ok else 'failed'}",
        f"Generator validation kind: {validation_error_kind or 'success'}",
        f"Materialized seed count: {generated_seed_count}",
        f"Added seed count this iteration: {added_seed_count}",
        f"Skipped duplicate seed count: {skipped_duplicate_seed_count}",
        f"Total corpus size after merge: {total_seed_count_after_merge}",
    ]
    if validation_output:
        lines.append(f"Generator execution output: {validation_output}")

    if not baseline_evaluation.get("success"):
        lines.append(f"Baseline coverage evaluation failed: {baseline_evaluation.get('error', 'unknown error')}")
    if not post_merge_evaluation.get("success"):
        lines.append(
            "Post-merge supplementary coverage evaluation failed: "
            f"{post_merge_evaluation.get('error', 'unknown error')}"
        )

    if baseline_evaluation.get("success") and post_merge_evaluation.get("success"):
        lines.extend(
            [
                f"Coverage source file in container: {post_merge_evaluation.get('container_source_file', 'N/A')}",
                f"Baseline branch_line hit count: {baseline_evaluation.get('branch_hit_count_raw', '0')}",
                f"Baseline blocked_side_line hit count: {baseline_evaluation.get('blocked_side_hit_count_raw', '0')}",
                f"Post-merge branch_line hit count: {post_merge_evaluation.get('branch_hit_count_raw', '0')}",
                f"Post-merge blocked_side_line hit count: {post_merge_evaluation.get('blocked_side_hit_count_raw', '0')}",
                f"branch_line hit count delta: {coverage_delta.get('branch_hit_count_delta', 'N/A')}",
                f"blocked_side_line hit count delta: {coverage_delta.get('blocked_side_hit_count_delta', 'N/A')}",
                f"branch_line reached after merge: {post_merge_evaluation.get('branch_line_reached', False)}",
                f"blocked_side_line reached after merge: {post_merge_evaluation.get('blocked_side_line_reached', False)}",
                f"Newly reached branch_line this iteration: {coverage_delta.get('newly_reached_branch_line', False)}",
                f"Newly reached blocked_side_line this iteration: {coverage_delta.get('newly_reached_blocked_side_line', False)}",
            ]
        )
    lines.extend(["", "Family-level representative summary:", family_summary_text or "N/A"])
    return "\n".join(lines)


def get_seed_generator_temperature(iteration_index: int) -> float:
    if iteration_index <= 1:
        return config.SEED_GENERATOR_INITIAL_TEMPERATURE
    return config.SEED_GENERATOR_LATER_TEMPERATURE


def run_seed_generation(args: argparse.Namespace) -> dict:
    from llm_interface.llm_client import LLMClient, new_thread_id

    setup_file_logging(args.function_name, getattr(args, "log_dir", None))
    base_prompt = build_prompt(args)
    triggering_input_path, triggering_input_preview = resolve_triggering_input(args.triggering_input)
    format_info = infer_input_format(
        project_name=args.project_name,
        function_name=args.function_name,
        fuzz_target_code=read_optional_file(args.fuzz_file),
        source_code=read_optional_file(args.source_file),
        triggering_input_path=triggering_input_path if triggering_input_path != "inline" else args.triggering_input,
        triggering_input_preview=triggering_input_preview,
    )
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    _output_root = Path(args.output_root) if getattr(args, "output_root", None) else OUTPUT_ROOT
    output_dir = _output_root / f"{safe_project}_{safe_function}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    oss_fuzz = OSSFuzz()
    fuzzer_name = Path(args.fuzz_file).stem

    previous_generator_code = ""
    previous_rationale = ""
    previous_analysis_summary: list[str] = []
    previous_evaluation_summary = ""
    previous_seed_preview = ""
    previous_family_summary_text = ""
    previous_family_signal_score = 0
    previous_format_hint = ""
    seen_families: set[str] = set()
    iterations: list[dict] = []
    best_iteration: dict | None = None
    max_fix_attempts = MAX_GENERATOR_FIX_ATTEMPTS
    triggering_input_evaluation: dict = {
        "success": False,
        "error": "Triggering input was not evaluated.",
    }

    effective_max_iterations = min(int(args.max_iterations), MAX_GENERATOR_ITERATIONS)

    for iteration_index in range(1, effective_max_iterations + 1):
        iteration_dir = output_dir / f"iter_{iteration_index:02d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)

        prompt = build_iteration_prompt(
            base_prompt=base_prompt,
            iteration_index=iteration_index,
            max_iterations=effective_max_iterations,
            previous_generator_code=previous_generator_code,
            previous_rationale=previous_rationale,
            previous_analysis_summary=previous_analysis_summary,
            evaluation_summary=previous_evaluation_summary,
            generated_seed_preview=previous_seed_preview,
            family_summary_text=previous_family_summary_text,
            format_hint=previous_format_hint,
        )
        logging.info("=============== Iteration %d/%d ===============", iteration_index, effective_max_iterations)
        logging.info("================ Generated Prompt ================\n%s\n", prompt)
        temperature = get_seed_generator_temperature(iteration_index)
        logging.info("Seed generator temperature for iteration %d: %.2f", iteration_index, temperature)
        (iteration_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

        llm = LLMClient(backend=args.backend, model_name=args.model, temperature=temperature)
        llm_thread_id = new_thread_id(
            "input_dependent_seed_generator",
            args.project_name,
            args.function_name,
            args.branch_line_number,
            args.blocked_side_line_number,
            iteration_index,
            iteration_dir,
        )
        logging.info("Seed generator LLM thread_id=%s", llm_thread_id)
        response_text = llm.generate(prompt, thread_id=llm_thread_id)
        if not response_text:
            raise RuntimeError(f"Empty LLM response on iteration {iteration_index}.")

        parsed = enrich_parsed_response(response_text, extract_json(response_text))
        analysis_summary = parsed.get("analysis_summary", [])
        failure_analysis = parsed.get("failure_analysis", [])
        family_decisions = parsed.get("family_decisions", [])
        revision_plan = parsed.get("revision_plan", [])
        rationale = parsed.get("generator_design_rationale", "")
        generator_code = parsed.get("generator_code", "")
        generator_filename = parsed.get("generator_filename", "seed_generator.py")
        sample_seeds = parsed.get("sample_seeds", [])
        if not generator_code:
            raise RuntimeError(f"LLM response did not include generator_code on iteration {iteration_index}.")

        current_response_text = response_text
        current_parsed = parsed
        saved_seed_paths: list[Path] = []
        fix_attempts_used = 0
        validation_result: dict = {
            "ok": False,
            "error_kind": "runtime_failed",
            "output": "Validation was not executed.",
            "generated_dir": iteration_dir / "materialized_by_generator",
        }
        generator_path = iteration_dir / "seed_generator.py"

        for fix_attempt_index in range(0, max_fix_attempts + 1):
            if fix_attempt_index == 0:
                candidate_response_text = current_response_text
                candidate_parsed = current_parsed
            else:
                fix_attempts_used = fix_attempt_index
                fix_prompt = build_generator_fix_prompt(
                    base_prompt=base_prompt,
                    validation_kind=str(validation_result.get("error_kind", "")),
                    validation_output=str(validation_result.get("output", "")),
                    previous_generator_code=generator_code,
                    previous_rationale=rationale,
                    fix_attempt_index=fix_attempt_index,
                    max_fix_attempts=max_fix_attempts,
                )
                (iteration_dir / f"fix_prompt_{fix_attempt_index:02d}.txt").write_text(fix_prompt, encoding="utf-8")
                candidate_response_text = llm.generate(fix_prompt, thread_id=llm_thread_id)
                if not candidate_response_text:
                    raise RuntimeError(
                        f"Empty LLM repair response on iteration {iteration_index}, fix attempt {fix_attempt_index}."
                    )
                candidate_parsed = enrich_parsed_response(candidate_response_text, extract_json(candidate_response_text))

            analysis_summary = candidate_parsed.get("analysis_summary", [])
            failure_analysis = candidate_parsed.get("failure_analysis", [])
            family_decisions = candidate_parsed.get("family_decisions", [])
            revision_plan = candidate_parsed.get("revision_plan", [])
            rationale = candidate_parsed.get("generator_design_rationale", "")
            generator_code = candidate_parsed.get("generator_code", "")
            generator_filename = candidate_parsed.get("generator_filename", "seed_generator.py")
            sample_seeds = candidate_parsed.get("sample_seeds", [])
            if not generator_code:
                raise RuntimeError(
                    f"LLM response did not include generator_code on iteration {iteration_index}, fix attempt {fix_attempt_index}."
                )

            response_path = iteration_dir / (
                "response.txt" if fix_attempt_index == 0 else f"fix_response_{fix_attempt_index:02d}.txt"
            )
            parsed_path = iteration_dir / (
                "parsed.json" if fix_attempt_index == 0 else f"fix_parsed_{fix_attempt_index:02d}.json"
            )
            response_path.write_text(candidate_response_text, encoding="utf-8")
            parsed_path.write_text(json.dumps(candidate_parsed, ensure_ascii=False, indent=2), encoding="utf-8")

            generator_path = write_generator(
                iteration_dir,
                generator_code,
                generator_filename if fix_attempt_index == 0 else f"fix_{fix_attempt_index:02d}_{generator_filename}",
            )
            saved_seed_paths: list[Path] = []
            if isinstance(sample_seeds, list):
                try:
                    saved_seed_paths = save_sample_seeds(iteration_dir, sample_seeds, format_info)
                except Exception as exc:
                    logging.warning("Failed to persist sample seeds on iteration %d: %s", iteration_index, exc)
            validation_result = validate_generator(
                generator_path,
                iteration_dir,
                materialized_dir_name=(
                    "materialized_by_generator"
                    if fix_attempt_index == 0
                    else f"materialized_by_generator_fix_{fix_attempt_index:02d}"
                ),
                timeout_seconds=float(getattr(args, "generator_timeout_sec", DEFAULT_GENERATOR_TIMEOUT_SEC)),
                max_seed_size_bytes=int(getattr(args, "max_seed_size_bytes", MAX_SEED_SIZE_BYTES)),
            )
            if validation_result.get("ok"):
                current_response_text = candidate_response_text
                current_parsed = candidate_parsed
                break
            if fix_attempt_index >= max_fix_attempts:
                current_response_text = candidate_response_text
                current_parsed = candidate_parsed
                break

        validation_ok = bool(validation_result.get("ok"))
        validation_output = str(validation_result.get("output", ""))
        validation_error_kind = str(validation_result.get("error_kind", ""))
        generated_dir = Path(validation_result.get("generated_dir", iteration_dir / "materialized_by_generator"))
        generated_seed_count = len([p for p in generated_dir.rglob("*") if p.is_file()]) if generated_dir.exists() else 0
        validation_metadata = {
            key: validation_result.get(key)
            for key in [
                "seed_size_limit_bytes",
                "generated_seed_count_before_filter",
                "valid_seed_count",
                "oversized_seed_count",
                "generated_total_bytes_before_filter",
                "largest_seed_size_bytes",
                "oversized_rejected_dir",
                "oversized_seed_records",
                "py_compile_elapsed_seconds",
                "generator_elapsed_seconds",
                "validation_elapsed_seconds",
                "generator_timeout_seconds",
                "generator_timed_out",
            ]
            if key in validation_result
        }
        seed_preview = materialized_seed_preview(generated_dir)
        family_counts = summarize_family_inventory(generated_dir) if generated_dir.exists() else {}
        representative_results: list[dict] = []
        representative_records: list[dict] = []
        symcc_candidate_bundle = {
            "best_family": "",
            "candidate_seed_paths": [],
            "selection_reason": "Representative seed selection was not available.",
        }
        family_summary = {
            "best_family": "",
            "stable_branch_families": [],
            "dead_families": [],
            "keep_families": [],
            "refine_families": [],
            "discard_families": [],
            "ranked_families": [],
        }
        family_summary_text = "N/A"

        if validation_ok and generated_seed_count > 0:
            project_corpus_root = oss_fuzz.build_corpus_dir / args.project_name
            formal_corpus_dir = project_corpus_root / fuzzer_name
            baseline_snapshot_name = f"{fuzzer_name}__baseline_iter_{iteration_index:02d}"
            post_merge_snapshot_name = f"{fuzzer_name}__post_merge_iter_{iteration_index:02d}"
            representative_snapshot_name = f"{fuzzer_name}__representative_iter_{iteration_index:02d}"
            baseline_snapshot_dir = project_corpus_root / baseline_snapshot_name
            post_merge_snapshot_dir = project_corpus_root / post_merge_snapshot_name
            representative_snapshot_dir = project_corpus_root / representative_snapshot_name
            formal_manifest_before = build_corpus_manifest(formal_corpus_dir)
            post_merge_records: list[dict] = []
            staging_metadata = {
                "reset_corpus_per_iteration": False,
                "reset_corpus_request_ignored": bool(args.reset_corpus_per_iteration),
                "formal_corpus_mutated": False,
                "added_seed_count": 0,
                "skipped_duplicate_seed_count": 0,
                "total_seed_count_after_merge": 0,
                "family_counts": family_counts,
            }
            if args.reset_corpus_per_iteration:
                logging.warning(
                    "Ignoring --reset-corpus-per-iteration: focused evaluation never mutates the formal corpus."
                )

            try:
                triggering_seed = materialize_triggering_input(
                    args.triggering_input,
                    format_info,
                    iteration_dir / "triggering_input_materialized",
                )
                triggering_records = build_seed_records([triggering_seed], source_kind="triggering")
                generated_paths = sorted(p for p in generated_dir.rglob("*") if p.is_file())
                generated_records = build_seed_records(generated_paths, source_kind="generated")

                _, baseline_snapshot_metadata = prepare_isolated_corpus_snapshot(
                    baseline_snapshot_dir,
                    triggering_records,
                )
                baseline_evaluation = evaluate_iteration_with_coverage(
                    oss_fuzz=oss_fuzz,
                    project_name=args.project_name,
                    fuzzer_name=fuzzer_name,
                    function_name=args.function_name,
                    source_file=args.source_file,
                    source_api_file=args.source_api_file,
                    branch_line=int(args.branch_line_number),
                    blocked_side_line=int(args.blocked_side_line_number),
                    fuzz_seconds=args.fuzz_seconds,
                    output_dir=iteration_dir,
                    report_basename="baseline",
                    corpus_subdir_name=baseline_snapshot_name,
                )
                if not triggering_input_evaluation.get("success"):
                    triggering_input_evaluation = {
                        **baseline_evaluation,
                        "seed_path": str(triggering_seed.resolve()),
                        "seed_size_bytes": triggering_seed.stat().st_size,
                    }

                selected_representatives = choose_representative_seed_records(
                    seed_records=generated_records,
                    known_families=seen_families,
                )
                representative_records, representative_snapshot_metadata = prepare_isolated_corpus_snapshot(
                    representative_snapshot_dir,
                    selected_representatives,
                )
                representative_results = evaluate_representative_seed_records(
                    oss_fuzz=oss_fuzz,
                    project_name=args.project_name,
                    fuzzer_name=fuzzer_name,
                    function_name=args.function_name,
                    source_file=args.source_file,
                    source_api_file=args.source_api_file,
                    branch_line=int(args.branch_line_number),
                    blocked_side_line=int(args.blocked_side_line_number),
                    representative_records=representative_records,
                    output_dir=iteration_dir,
                )
                family_summary = summarize_family_performance(family_counts, representative_results)
                family_summary_text = render_family_summary_text(family_summary)
                symcc_candidate_bundle = select_best_symcc_candidates(family_summary, representative_results)

                post_merge_records, post_merge_snapshot_metadata = prepare_isolated_corpus_snapshot(
                    post_merge_snapshot_dir,
                    triggering_records + generated_records,
                )
                post_merge_evaluation = evaluate_iteration_with_coverage(
                    oss_fuzz=oss_fuzz,
                    project_name=args.project_name,
                    fuzzer_name=fuzzer_name,
                    function_name=args.function_name,
                    source_file=args.source_file,
                    source_api_file=args.source_api_file,
                    branch_line=int(args.branch_line_number),
                    blocked_side_line=int(args.blocked_side_line_number),
                    fuzz_seconds=args.fuzz_seconds,
                    output_dir=iteration_dir,
                    report_basename="post_merge",
                    corpus_subdir_name=post_merge_snapshot_name,
                )
                coverage_delta = compute_coverage_delta(baseline_evaluation, post_merge_evaluation)
                added_seed_count = sum(
                    1 for record in post_merge_records if record.get("source_kind") == "generated"
                )
                staging_metadata.update(
                    {
                        "added_seed_count": added_seed_count,
                        "skipped_duplicate_seed_count": int(
                            post_merge_snapshot_metadata.get("duplicate_seed_count", 0)
                        ),
                        "total_seed_count_after_merge": int(
                            post_merge_snapshot_metadata.get("copied_seed_count", 0)
                        ),
                        "isolated_corpus_dir": str(post_merge_snapshot_dir.resolve()),
                        "baseline_snapshot": baseline_snapshot_metadata,
                        "post_merge_snapshot": post_merge_snapshot_metadata,
                        "representative_snapshot": representative_snapshot_metadata,
                    }
                )
                (iteration_dir / "representative_results.json").write_text(
                    json.dumps(representative_results, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                (iteration_dir / "family_summary.json").write_text(
                    json.dumps(family_summary, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                (iteration_dir / "isolated_seed_records.json").write_text(
                    json.dumps(post_merge_records, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                logging.exception("Focused isolated evaluation failed on iteration %d", iteration_index)
                baseline_evaluation = {
                    "success": False,
                    "error": f"Focused isolated evaluation failed: {exc}",
                }
                post_merge_evaluation = {
                    "success": False,
                    "error": f"Focused isolated evaluation failed: {exc}",
                }
                coverage_delta = {
                    "success": False,
                    "error": f"Focused isolated evaluation failed: {exc}",
                    "coverage_novelty_success": False,
                }
                family_summary = summarize_family_performance(family_counts, representative_results)
                family_summary_text = render_family_summary_text(family_summary)
            finally:
                shutil.rmtree(baseline_snapshot_dir, ignore_errors=True)
                shutil.rmtree(post_merge_snapshot_dir, ignore_errors=True)
                shutil.rmtree(representative_snapshot_dir, ignore_errors=True)

            formal_manifest_after = build_corpus_manifest(formal_corpus_dir)
            staging_metadata["formal_corpus_mutated"] = formal_manifest_before != formal_manifest_after
            staging_metadata["formal_corpus_file_count"] = len(formal_manifest_after)
            if staging_metadata["formal_corpus_mutated"]:
                logging.error("Formal corpus changed during focused isolated evaluation: %s", formal_corpus_dir)
            (iteration_dir / "staging_metadata.json").write_text(
                json.dumps(staging_metadata, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        else:
            staging_metadata = {
                "added_seed_count": 0,
                "skipped_duplicate_seed_count": 0,
                "total_seed_count_after_merge": 0,
            }
            baseline_evaluation = {
                "success": False,
                "error": f"Generator validation failed: {validation_error_kind or 'unknown'}",
            }
            post_merge_evaluation = {
                "success": False,
                "error": f"Generator validation failed: {validation_error_kind or 'unknown'}",
            }
            coverage_delta = {
                "success": False,
                "error": f"Generator validation failed: {validation_error_kind or 'unknown'}",
                "coverage_novelty_success": False,
            }
            family_summary = summarize_family_performance(family_counts, representative_results)
            family_summary_text = render_family_summary_text(family_summary)

        iteration_status, status_reason = classify_iteration_status(
            validation_ok=validation_ok,
            generated_seed_count=generated_seed_count,
            baseline_evaluation=baseline_evaluation,
            post_merge_evaluation=post_merge_evaluation,
            coverage_delta=coverage_delta,
            representative_results=representative_results,
            family_summary=family_summary,
            previous_family_signal_score=previous_family_signal_score,
        )
        diagnosis = diagnose_iteration(
            iteration_status=iteration_status,
            validation_ok=validation_ok,
            generated_seed_count=generated_seed_count,
            staging_metadata=staging_metadata,
            baseline_evaluation=baseline_evaluation,
            post_merge_evaluation=post_merge_evaluation,
            coverage_delta=coverage_delta,
            family_summary=family_summary,
        )
        diagnosis["best_symcc_family"] = symcc_candidate_bundle.get("best_family", "")
        diagnosis["best_symcc_seed_paths"] = list(symcc_candidate_bundle.get("candidate_seed_paths", []))
        diagnosis["best_symcc_selection_reason"] = symcc_candidate_bundle.get("selection_reason", "")

        evaluation_summary = summarize_evaluation(
            iteration_index=iteration_index,
            generated_seed_count=generated_seed_count,
            added_seed_count=int(staging_metadata.get("added_seed_count", 0)),
            skipped_duplicate_seed_count=int(staging_metadata.get("skipped_duplicate_seed_count", 0)),
            total_seed_count_after_merge=int(staging_metadata.get("total_seed_count_after_merge", 0)),
            validation_ok=validation_ok,
            validation_error_kind=validation_error_kind,
            validation_output=validation_output,
            baseline_evaluation=baseline_evaluation,
            post_merge_evaluation=post_merge_evaluation,
            coverage_delta=coverage_delta,
            iteration_status=iteration_status,
            status_reason=status_reason,
            diagnosis=diagnosis,
            family_summary=family_summary,
            family_summary_text=family_summary_text,
        )
        (iteration_dir / "evaluation.txt").write_text(evaluation_summary, encoding="utf-8")

        iteration_record = {
            "iteration": iteration_index,
            "prompt_path": str(iteration_dir / "prompt.txt"),
            "response_path": str(iteration_dir / "response.txt"),
            "parsed_path": str(iteration_dir / "parsed.json"),
            "generator_path": str(generator_path),
            "sample_seed_paths": [str(path) for path in saved_seed_paths],
            "validation_ok": validation_ok,
            "validation_error_kind": validation_error_kind,
            "validation_output": validation_output,
            "validation_metadata": validation_metadata,
            "fix_attempts_used": fix_attempts_used,
            "generated_seed_count": generated_seed_count,
            "staging_metadata": staging_metadata,
            "seed_preview": seed_preview,
            "family_counts": family_counts,
            "representative_records": representative_records,
            "representative_results": representative_results,
            "family_summary": family_summary,
            "family_summary_text": family_summary_text,
            "best_symcc_family": symcc_candidate_bundle.get("best_family", ""),
            "best_symcc_seed_paths": list(symcc_candidate_bundle.get("candidate_seed_paths", [])),
            "best_symcc_selection_reason": symcc_candidate_bundle.get("selection_reason", ""),
            "best_symcc_top_families": list(symcc_candidate_bundle.get("top_families", [])),
            "best_symcc_seed_records": list(symcc_candidate_bundle.get("candidate_seed_records", [])),
            "analysis_summary": analysis_summary,
            "failure_analysis": failure_analysis,
            "family_decisions": family_decisions,
            "revision_plan": revision_plan,
            "generator_design_rationale": rationale,
            "baseline_evaluation": baseline_evaluation,
            "post_merge_evaluation": post_merge_evaluation,
            "coverage_delta": coverage_delta,
            "evaluation": post_merge_evaluation,
            "evaluation_summary": evaluation_summary,
            "success": iteration_status == "solved",
            "coverage_novelty_success": bool(diagnosis.get("coverage_novelty_success")),
            "generated_family_reached_branch": bool(diagnosis.get("generated_family_reached_branch")),
            "generated_family_reached_blocked_side": bool(diagnosis.get("generated_family_reached_blocked_side")),
            "seed_contract_reproduction_success": bool(diagnosis.get("seed_contract_reproduction_success")),
            "iteration_status": iteration_status,
            "status_reason": status_reason,
            "diagnosis": diagnosis,
            "format_info": format_info.to_prompt_mapping(),
        }
        iterations.append(iteration_record)

        score = (
            int(iteration_status == "solved") * 1_000_000
            + int(post_merge_evaluation.get("blocked_side_hit_count", 0)) * 1_000
            + int(post_merge_evaluation.get("branch_hit_count", 0))
        )
        if best_iteration is None:
            best_iteration = iteration_record | {"score": score}
        else:
            best_score = int(best_iteration.get("score", 0))
            if score > best_score:
                best_iteration = iteration_record | {"score": score}

        logging.info("Iteration %d validation success: %s", iteration_index, validation_ok)
        logging.info("Iteration %d evaluation summary:\n%s", iteration_index, evaluation_summary)

        if iteration_status == "solved":
            logging.info("Blocked side was newly reached on iteration %d. Stopping early.", iteration_index)
            break
        if baseline_evaluation.get("blocked_side_line_reached"):
            logging.info("Blocked side was already covered before iteration %d. Stopping early.", iteration_index)
            break

        seen_families.update(family_counts.keys())
        previous_generator_code = generator_code
        previous_rationale = rationale
        previous_analysis_summary = analysis_summary if isinstance(analysis_summary, list) else [str(analysis_summary)]
        previous_evaluation_summary = evaluation_summary
        previous_seed_preview = seed_preview
        previous_family_summary_text = family_summary_text
        previous_family_signal_score = compute_family_signal_score(family_summary)

        previous_format_hint = ""
        if diagnosis.get("diagnosis_code") == "format_mismatch_seed" and args.triggering_input:
            try:
                trigger_path = Path(str(args.triggering_input))
                if trigger_path.exists() and trigger_path.is_file():
                    seed_bytes = trigger_path.read_bytes()
                else:
                    seed_bytes = seed_to_bytes(args.triggering_input)
                seed_size = len(seed_bytes)
                hex_dump = seed_bytes[:256].hex()
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in seed_bytes[:256])
                previous_format_hint = (
                    "Your previous seeds ALL failed to reach the branch (branch_hits=0), "
                    "but the initial corpus seed CAN reach it. This indicates a format mismatch.\n\n"
                    f"Reference seed that WORKS:\n"
                    f"  Size: {seed_size} bytes\n"
                    f"  Hex (first 256 bytes): {hex_dump}\n"
                    f"  Printable: {printable}\n\n"
                    "Analyze the format and size requirements before generating new seeds. "
                    "Pay attention to: minimum input size, binary vs text encoding, header structure."
                )
            except Exception as exc:
                logging.warning("Failed to build format hint: %s", exc)

    success = any(item.get("iteration_status") == "solved" for item in iterations)
    coverage_progress_iteration_count = sum(
        1 for item in iterations if item.get("iteration_status") == "coverage_progress"
    )
    family_progress_iteration_count = sum(
        1 for item in iterations if item.get("iteration_status") == "family_progress"
    )
    stalled_iteration_count = sum(1 for item in iterations if item.get("iteration_status") == "stalled_at_branch")
    no_branch_signal_count = sum(1 for item in iterations if item.get("iteration_status") == "no_branch_signal")
    already_covered_count = sum(1 for item in iterations if item.get("iteration_status") == "already_covered_in_baseline")
    invalid_iteration_count = sum(
        1 for item in iterations if item.get("iteration_status") in {"invalid_generator", "evaluation_failed"}
    )
    seed_budget_exceeded_iteration_count = sum(
        1 for item in iterations if item.get("validation_error_kind") in SEED_BUDGET_ERROR_KINDS
    )
    coverage_novelty_success_count = sum(
        1 for item in iterations if item.get("coverage_novelty_success")
    )
    generated_family_reached_branch_count = sum(
        1 for item in iterations if item.get("generated_family_reached_branch")
    )
    generated_family_reached_blocked_side_count = sum(
        1 for item in iterations if item.get("generated_family_reached_blocked_side")
    )
    seed_contract_reproduction_success_count = sum(
        1 for item in iterations if item.get("seed_contract_reproduction_success")
    )
    diagnosis_counts: dict[str, int] = {}
    symcc_candidate_iteration_count = 0
    for item in iterations:
        diagnosis = item.get("diagnosis", {})
        if not isinstance(diagnosis, dict):
            continue
        diagnosis_code = str(diagnosis.get("diagnosis_code", "unknown"))
        diagnosis_counts[diagnosis_code] = diagnosis_counts.get(diagnosis_code, 0) + 1
        if diagnosis.get("symcc_candidate"):
            symcc_candidate_iteration_count += 1
    best_symcc_bundle = {"best_family": "", "candidate_seed_paths": [], "selection_reason": ""}
    if isinstance(best_iteration, dict):
        best_symcc_bundle = {
            "best_family": best_iteration.get("best_symcc_family", "") or "",
            "top_families": list(best_iteration.get("best_symcc_top_families", []) or []),
            "candidate_seed_records": list(best_iteration.get("best_symcc_seed_records", []) or []),
            "candidate_seed_paths": list(best_iteration.get("best_symcc_seed_paths", []) or []),
            "selection_reason": best_iteration.get("best_symcc_selection_reason", "") or "",
        }
    if success:
        final_status = "solved_by_generator"
    elif already_covered_count > 0:
        final_status = "already_covered_in_baseline"
    else:
        final_status = "not_solved_by_generator"

    if success:
        generator_terminal_reason = "blocked_side_reached"
    elif already_covered_count > 0:
        generator_terminal_reason = "already_covered_in_baseline"
    elif coverage_progress_iteration_count > 0:
        generator_terminal_reason = "coverage_progress_observed_but_not_solved"
    elif family_progress_iteration_count > 0:
        generator_terminal_reason = "family_progress_observed_but_not_solved"
    elif seed_budget_exceeded_iteration_count > 0:
        generator_terminal_reason = "seed_budget_exceeded"
    elif stalled_iteration_count > 0:
        generator_terminal_reason = "stalled_at_branch"
    elif no_branch_signal_count == len(iterations) and iterations:
        generator_terminal_reason = "no_branch_signal"
    elif invalid_iteration_count == len(iterations) and iterations:
        generator_terminal_reason = "invalid_generator"
    else:
        generator_terminal_reason = "no_useful_signal"

    symcc_handoff_bundle = select_recommended_symcc_generator_seeds(
        generator_terminal_reason=generator_terminal_reason,
        symcc_candidate_bundle=best_symcc_bundle,
        triggering_input_evaluation=triggering_input_evaluation,
    )

    return {
        "output_dir": str(output_dir),
        "success": success,
        "final_status": final_status,
        "generator_terminal_reason": generator_terminal_reason,
        "pipeline_methods": ["llm_seed_generator"],
        "used_llm_seed_generator": True,
        "used_symcc": False,
        "iterations_run": len(iterations),
        "progress_iteration_count": coverage_progress_iteration_count + family_progress_iteration_count,
        "coverage_progress_iteration_count": coverage_progress_iteration_count,
        "family_progress_iteration_count": family_progress_iteration_count,
        "stalled_iteration_count": stalled_iteration_count,
        "invalid_iteration_count": invalid_iteration_count,
        "seed_budget_exceeded_iteration_count": seed_budget_exceeded_iteration_count,
        "symcc_candidate_iteration_count": symcc_candidate_iteration_count,
        "no_branch_signal_count": no_branch_signal_count,
        "coverage_novelty_success": coverage_novelty_success_count > 0,
        "coverage_novelty_success_count": coverage_novelty_success_count,
        "generated_family_reached_branch": generated_family_reached_branch_count > 0,
        "generated_family_reached_branch_count": generated_family_reached_branch_count,
        "generated_family_reached_blocked_side": generated_family_reached_blocked_side_count > 0,
        "generated_family_reached_blocked_side_count": generated_family_reached_blocked_side_count,
        "seed_contract_reproduction_success": seed_contract_reproduction_success_count > 0,
        "seed_contract_reproduction_success_count": seed_contract_reproduction_success_count,
        "diagnosis_counts": diagnosis_counts,
        "max_iterations": effective_max_iterations,
        "fuzz_seconds_per_iteration": args.fuzz_seconds,
        "best_iteration": best_iteration,
        "best_symcc_family": best_symcc_bundle.get("best_family", ""),
        "best_symcc_top_families": best_symcc_bundle.get("top_families", []),
        "best_symcc_seed_paths": best_symcc_bundle.get("candidate_seed_paths", []),
        "best_symcc_selection_reason": best_symcc_bundle.get("selection_reason", ""),
        "best_symcc_seed_records": best_symcc_bundle.get("candidate_seed_records", []),
        "triggering_input_evaluation": triggering_input_evaluation,
        "recommended_symcc_generator_seed_paths": symcc_handoff_bundle.get("recommended_generator_seed_paths", []),
        "recommended_symcc_generator_seed_records": symcc_handoff_bundle.get("recommended_generator_seed_records", []),
        "recommended_symcc_selection_reason": symcc_handoff_bundle.get("selection_reason", ""),
        "iterations": iterations,
        "format_info": format_info.to_prompt_mapping(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a blocker-oriented Python seed generator with an LLM.")
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
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
    parser.add_argument("--blocker-call-sites", default=None)
    parser.add_argument("--blocker-call-sites-file", default=None)
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--max-iterations", type=int, default=3)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--generator-timeout-sec", type=float, default=DEFAULT_GENERATOR_TIMEOUT_SEC)
    parser.add_argument("--max-seed-size-bytes", type=int, default=MAX_SEED_SIZE_BYTES)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    parser.add_argument("--output-root", default=None,
                        help="Root directory under which iteration output dirs are created. "
                             "Defaults to generated_generators/.")
    parser.add_argument("--log-dir", default=None,
                        help="Directory for seed generator session logs. Defaults to logs/ when omitted.")
    args = parser.parse_args()

    try:
        result = run_seed_generation(args)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        print(json.dumps({"success": False, "attempt_result": "failed", "error": str(exc)}, ensure_ascii=False, indent=2))
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        print(
            json.dumps(
                {"success": False, "attempt_result": "llm_error", "error": str(exc)},
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(2)
    except Exception as exc:
        logging.error("Seed generation failed: %s", exc, exc_info=True)
        print(
            json.dumps(
                {"success": False, "attempt_result": "failed", "error": f"Seed generation failed: {exc}"},
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
