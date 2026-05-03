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
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from external.oss_fuzz import OSSFuzz

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "blocker_seed_generator_template"
OUTPUT_ROOT = MODULE_ROOT / "generated_generators"
OSS_FUZZ_IMAGE_PREFIX = "gcr.io/oss-fuzz"


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


def format_prompt(template: str, mapping: dict[str, str]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return mapping.get(key, match.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)


def seed_to_bytes(seed: str) -> bytes:
    if r"\x" in seed:
        try:
            return bytes(seed, "utf-8").decode("unicode_escape").encode("latin-1", errors="replace")
        except Exception:
            pass
    try:
        return seed.encode("latin-1")
    except UnicodeEncodeError:
        return seed.encode("utf-8")


def save_sample_seeds(output_dir: Path, sample_seeds: list[str]) -> list[Path]:
    seeds_dir = output_dir / "sample_seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    saved_paths: list[Path] = []
    for index, seed in enumerate(sample_seeds, start=1):
        suffix = ".xml" if seed.lstrip().startswith("<") else ".bin"
        target = seeds_dir / f"seed_{index:02d}{suffix}"
        target.write_bytes(seed_to_bytes(seed))
        saved_paths.append(target)
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
    }
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
) -> str:
    if iteration_index == 1:
        return base_prompt

    analysis_text = "\n".join(f"- {item}" for item in (previous_analysis_summary or [])) or "N/A"
    appended = f"""

# Iteration Context

This is iteration {iteration_index} of {max_iterations}.

You are revising the previous generator based on execution feedback. Keep any working ideas that improved blocker reachability, but change the generator where the evidence shows it is insufficient.

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

## Revision instructions

- If the previous generator reached the blocker but did not cross the blocked side, focus on boundary refinement near the condition.
- If it did not reach the blocker, change higher-level input structure rather than only tweaking constants.
- Preserve useful seed families and add new targeted variants instead of replacing everything blindly.
- Your job is to improve the generator for the next iteration, not to explain why iteration is impossible.
"""
    return base_prompt + appended


def setup_file_logging(func_name: str) -> None:
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}_seedgen.log"

    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    log_filepath = log_dir / log_filename

    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)
    logging.info("Log file create: %s", log_filepath)


def write_generator(output_dir: Path, generator_code: str, suggested_name: str) -> Path:
    filename = sanitize_name(suggested_name or "seed_generator.py")
    if not filename.endswith(".py"):
        filename += ".py"
    generator_path = output_dir / filename
    generator_path.write_text(generator_code, encoding="utf-8")
    return generator_path


def validate_generator(generator_path: Path, output_dir: Path) -> tuple[bool, str, Path]:
    py_compile = subprocess.run(
        [sys.executable, "-m", "py_compile", str(generator_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if py_compile.returncode != 0:
        return False, py_compile.stderr or py_compile.stdout, output_dir / "materialized_by_generator"

    generated_dir = output_dir / "materialized_by_generator"
    generated_dir.mkdir(parents=True, exist_ok=True)
    run_result = subprocess.run(
        [sys.executable, str(generator_path), "--output-dir", str(generated_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if run_result.returncode != 0:
        return False, run_result.stderr or run_result.stdout, generated_dir
    return True, run_result.stdout.strip(), generated_dir


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


def get_line_execution_count(report: str, line_no: int) -> str:
    target_prefix = f"{line_no}|"
    for line in report.splitlines():
        if line.lstrip().startswith(target_prefix):
            parts = line.split("|", 2)
            if len(parts) >= 2:
                return parts[1].strip()
    return ""


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


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def run_in_ossfuzz(project_name: str, out_dir: Path, corpus_root: Path, command: str) -> subprocess.CompletedProcess:
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
    return run_cmd(docker_cmd)


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


def stage_generated_seeds(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    generated_dir: Path,
    iteration_dir: Path,
    reset_corpus_per_iteration: bool = False,
) -> tuple[Path, dict]:
    corpus_dir = oss_fuzz.build_corpus_dir / project_name / fuzzer_name
    if corpus_dir.exists() and reset_corpus_per_iteration:
        shutil.rmtree(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    existing_hashes: dict[str, Path] = {}
    for existing_file in sorted(p for p in corpus_dir.rglob("*") if p.is_file()):
        try:
            digest = hashlib.sha256(existing_file.read_bytes()).hexdigest()
        except Exception:
            continue
        existing_hashes[digest] = existing_file

    count = 0
    added = 0
    skipped_duplicates = 0
    for path in sorted(p for p in generated_dir.rglob("*") if p.is_file()):
        try:
            payload = path.read_bytes()
        except Exception:
            continue

        digest = hashlib.sha256(payload).hexdigest()
        if digest in existing_hashes:
            skipped_duplicates += 1
            continue

        target = corpus_dir / f"{count:04d}_{sanitize_name(path.stem)}{path.suffix or '.bin'}"
        while target.exists():
            count += 1
            target = corpus_dir / f"{count:04d}_{sanitize_name(path.stem)}{path.suffix or '.bin'}"
        shutil.copy2(path, target)
        existing_hashes[digest] = target
        count += 1
        added += 1

    snapshot_dir = iteration_dir / "staged_corpus_snapshot"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    shutil.copytree(corpus_dir, snapshot_dir)
    metadata = {
        "reset_corpus_per_iteration": reset_corpus_per_iteration,
        "added_seed_count": added,
        "skipped_duplicate_seed_count": skipped_duplicates,
        "total_seed_count_after_merge": len([p for p in corpus_dir.rglob("*") if p.is_file()]),
        "corpus_dir": str(corpus_dir),
    }
    (iteration_dir / "staging_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return corpus_dir, metadata


def evaluate_iteration_with_coverage(
    oss_fuzz: OSSFuzz,
    project_name: str,
    fuzzer_name: str,
    source_file: str,
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

    container_source_file = guess_container_source_file(project_name, source_file)
    out_dir = oss_fuzz.build_out_dir / project_name
    corpus_root = oss_fuzz.build_corpus_dir / project_name
    corpus_name = corpus_subdir_name or fuzzer_name
    command = (
        "rm -f /tmp/iter.profraw /tmp/iter.profdata && "
        "LLVM_PROFILE_FILE=/tmp/iter.profraw "
        f"/out/{shlex.quote(fuzzer_name)} /corpus/{shlex.quote(corpus_name)} "
        f"-max_total_time={int(fuzz_seconds)} -rss_limit_mb=0 -timeout=0 && "
        "llvm-profdata merge -sparse /tmp/iter.profraw -o /tmp/iter.profdata && "
        f"llvm-cov show /out/{shlex.quote(fuzzer_name)} "
        "-instr-profile=/tmp/iter.profdata "
        "-show-branches=count "
        "-show-instantiations=false "
        "-Xdemangler c++filt "
        "-path-equivalence=/,/out "
        f"{shlex.quote(container_source_file)}"
    )
    result = run_in_ossfuzz(project_name, out_dir, corpus_root, command)
    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr.strip() or result.stdout.strip() or "Coverage command failed.",
            "container_source_file": container_source_file,
        }

    report = result.stdout
    (output_dir / f"{report_basename}.linecovreport").write_text(report, encoding="utf-8")

    branch_raw = get_line_execution_count(report, branch_line)
    blocked_raw = get_line_execution_count(report, blocked_side_line)
    branch_hits = normalize_count(branch_raw)
    blocked_hits = normalize_count(blocked_raw)
    return {
        "success": True,
        "container_source_file": container_source_file,
        "branch_hit_count_raw": branch_raw or "0",
        "blocked_side_hit_count_raw": blocked_raw or "0",
        "branch_hit_count": branch_hits,
        "blocked_side_hit_count": blocked_hits,
        "branch_line_hit": branch_hits > 0,
        "blocked_side_line_hit": blocked_hits > 0,
        "reached_blocker": branch_hits > 0,
        "crossed_blocked_side": blocked_hits > 0,
    }


def prepare_corpus_snapshot(
    oss_fuzz: OSSFuzz,
    project_name: str,
    source_corpus_name: str,
    snapshot_corpus_name: str,
) -> Path:
    project_corpus_root = oss_fuzz.build_corpus_dir / project_name
    source_dir = project_corpus_root / source_corpus_name
    snapshot_dir = project_corpus_root / snapshot_corpus_name
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    if source_dir.exists():
        shutil.copytree(source_dir, snapshot_dir)
    else:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
    return snapshot_dir


def compute_coverage_delta(baseline: dict, post_merge: dict) -> dict:
    if not baseline.get("success") or not post_merge.get("success"):
        return {
            "success": False,
            "error": "Cannot compute delta because baseline or post-merge coverage failed.",
        }

    baseline_branch = int(baseline.get("branch_hit_count", 0))
    baseline_blocked = int(baseline.get("blocked_side_hit_count", 0))
    post_branch = int(post_merge.get("branch_hit_count", 0))
    post_blocked = int(post_merge.get("blocked_side_hit_count", 0))
    return {
        "success": True,
        "branch_hit_count_delta": post_branch - baseline_branch,
        "blocked_side_hit_count_delta": post_blocked - baseline_blocked,
        "newly_hit_branch_line": (baseline_branch == 0 and post_branch > 0),
        "newly_hit_blocked_side_line": (baseline_blocked == 0 and post_blocked > 0),
        "newly_reached_blocker": (baseline_branch == 0 and post_branch > 0),
        "newly_crossed_blocked_side": (baseline_blocked == 0 and post_blocked > 0),
    }


def summarize_evaluation(
    iteration_index: int,
    generated_seed_count: int,
    added_seed_count: int,
    skipped_duplicate_seed_count: int,
    total_seed_count_after_merge: int,
    validation_ok: bool,
    validation_output: str,
    baseline_evaluation: dict,
    post_merge_evaluation: dict,
    coverage_delta: dict,
) -> str:
    lines = [
        f"Iteration: {iteration_index}",
        f"Generator validation: {'success' if validation_ok else 'failed'}",
        f"Materialized seed count: {generated_seed_count}",
        f"Added seed count this iteration: {added_seed_count}",
        f"Skipped duplicate seed count: {skipped_duplicate_seed_count}",
        f"Total corpus size after merge: {total_seed_count_after_merge}",
    ]
    if validation_output:
        lines.append(f"Generator execution output: {validation_output}")

    if not baseline_evaluation.get("success"):
        lines.append(f"Baseline coverage evaluation failed: {baseline_evaluation.get('error', 'unknown error')}")
        return "\n".join(lines)

    if not post_merge_evaluation.get("success"):
        lines.append(f"Post-merge coverage evaluation failed: {post_merge_evaluation.get('error', 'unknown error')}")
        return "\n".join(lines)

    lines.extend(
        [
            f"Coverage source file in container: {post_merge_evaluation.get('container_source_file', 'N/A')}",
            f"Baseline branch_line hit count: {baseline_evaluation.get('branch_hit_count_raw', '0')}",
            f"Baseline blocked_side_line hit count: {baseline_evaluation.get('blocked_side_hit_count_raw', '0')}",
            f"Post-merge branch_line hit count: {post_merge_evaluation.get('branch_hit_count_raw', '0')}",
            f"Post-merge blocked_side_line hit count: {post_merge_evaluation.get('blocked_side_hit_count_raw', '0')}",
            f"branch_line hit count delta: {coverage_delta.get('branch_hit_count_delta', 'N/A')}",
            f"blocked_side_line hit count delta: {coverage_delta.get('blocked_side_hit_count_delta', 'N/A')}",
            f"branch_line hit after merge: {post_merge_evaluation.get('branch_line_hit', False)}",
            f"blocked_side_line hit after merge: {post_merge_evaluation.get('blocked_side_line_hit', False)}",
            f"Newly hit branch_line this iteration: {coverage_delta.get('newly_hit_branch_line', False)}",
            f"Newly hit blocked_side_line this iteration: {coverage_delta.get('newly_hit_blocked_side_line', False)}",
        ]
    )
    return "\n".join(lines)


def run_seed_generation(args: argparse.Namespace) -> dict:
    from llm_interface.llm_client import LLMClient

    setup_file_logging(args.function_name)
    base_prompt = build_prompt(args)
    llm = LLMClient(backend=args.backend, model_name=args.model)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    output_dir = OUTPUT_ROOT / f"{safe_project}_{safe_function}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    oss_fuzz = OSSFuzz()
    fuzzer_name = Path(args.fuzz_file).stem

    previous_generator_code = ""
    previous_rationale = ""
    previous_analysis_summary: list[str] = []
    previous_evaluation_summary = ""
    previous_seed_preview = ""
    iterations: list[dict] = []
    best_iteration: dict | None = None

    for iteration_index in range(1, args.max_iterations + 1):
        iteration_dir = output_dir / f"iter_{iteration_index:02d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)

        prompt = build_iteration_prompt(
            base_prompt=base_prompt,
            iteration_index=iteration_index,
            max_iterations=args.max_iterations,
            previous_generator_code=previous_generator_code,
            previous_rationale=previous_rationale,
            previous_analysis_summary=previous_analysis_summary,
            evaluation_summary=previous_evaluation_summary,
            generated_seed_preview=previous_seed_preview,
        )
        logging.info("=============== Iteration %d/%d ===============", iteration_index, args.max_iterations)
        logging.info("================ Generated Prompt ================\n%s\n", prompt)
        (iteration_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

        response_text = llm.generate(prompt)
        if not response_text:
            raise RuntimeError(f"Empty LLM response on iteration {iteration_index}.")

        parsed = extract_json(response_text)
        analysis_summary = parsed.get("analysis_summary", [])
        rationale = parsed.get("generator_design_rationale", "")
        generator_code = parsed.get("generator_code", "")
        generator_filename = parsed.get("generator_filename", "seed_generator.py")
        sample_seeds = parsed.get("sample_seeds", [])
        if not generator_code:
            raise RuntimeError(f"LLM response did not include generator_code on iteration {iteration_index}.")

        (iteration_dir / "response.txt").write_text(response_text, encoding="utf-8")
        (iteration_dir / "parsed.json").write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")

        generator_path = write_generator(iteration_dir, generator_code, generator_filename)
        saved_seed_paths = save_sample_seeds(iteration_dir, sample_seeds) if isinstance(sample_seeds, list) else []

        validation_ok, validation_output, generated_dir = validate_generator(generator_path, iteration_dir)
        generated_seed_count = len([p for p in generated_dir.rglob("*") if p.is_file()]) if generated_dir.exists() else 0
        seed_preview = materialized_seed_preview(generated_dir)

        if validation_ok and generated_seed_count > 0:
            baseline_snapshot_name = f"{fuzzer_name}__baseline_iter_{iteration_index:02d}"
            baseline_snapshot_dir = prepare_corpus_snapshot(
                oss_fuzz=oss_fuzz,
                project_name=args.project_name,
                source_corpus_name=fuzzer_name,
                snapshot_corpus_name=baseline_snapshot_name,
            )
            baseline_evaluation = evaluate_iteration_with_coverage(
                oss_fuzz=oss_fuzz,
                project_name=args.project_name,
                fuzzer_name=fuzzer_name,
                source_file=args.source_file,
                branch_line=int(args.branch_line_number),
                blocked_side_line=int(args.blocked_side_line_number),
                fuzz_seconds=args.fuzz_seconds,
                output_dir=iteration_dir,
                report_basename="baseline",
                corpus_subdir_name=baseline_snapshot_name,
            )
            _, staging_metadata = stage_generated_seeds(
                oss_fuzz=oss_fuzz,
                project_name=args.project_name,
                fuzzer_name=fuzzer_name,
                generated_dir=generated_dir,
                iteration_dir=iteration_dir,
                reset_corpus_per_iteration=args.reset_corpus_per_iteration,
            )
            post_merge_snapshot_name = f"{fuzzer_name}__post_merge_iter_{iteration_index:02d}"
            post_merge_snapshot_dir = prepare_corpus_snapshot(
                oss_fuzz=oss_fuzz,
                project_name=args.project_name,
                source_corpus_name=fuzzer_name,
                snapshot_corpus_name=post_merge_snapshot_name,
            )
            post_merge_evaluation = evaluate_iteration_with_coverage(
                oss_fuzz=oss_fuzz,
                project_name=args.project_name,
                fuzzer_name=fuzzer_name,
                source_file=args.source_file,
                branch_line=int(args.branch_line_number),
                blocked_side_line=int(args.blocked_side_line_number),
                fuzz_seconds=args.fuzz_seconds,
                output_dir=iteration_dir,
                report_basename="post_merge",
                corpus_subdir_name=post_merge_snapshot_name,
            )
            coverage_delta = compute_coverage_delta(baseline_evaluation, post_merge_evaluation)
            shutil.rmtree(baseline_snapshot_dir, ignore_errors=True)
            shutil.rmtree(post_merge_snapshot_dir, ignore_errors=True)
        else:
            staging_metadata = {
                "added_seed_count": 0,
                "skipped_duplicate_seed_count": 0,
                "total_seed_count_after_merge": 0,
            }
            baseline_evaluation = {
                "success": False,
                "error": "Generator validation failed or no seeds were materialized.",
            }
            post_merge_evaluation = {
                "success": False,
                "error": "Generator validation failed or no seeds were materialized.",
            }
            coverage_delta = {
                "success": False,
                "error": "Generator validation failed or no seeds were materialized.",
            }

        evaluation_summary = summarize_evaluation(
            iteration_index=iteration_index,
            generated_seed_count=generated_seed_count,
            added_seed_count=int(staging_metadata.get("added_seed_count", 0)),
            skipped_duplicate_seed_count=int(staging_metadata.get("skipped_duplicate_seed_count", 0)),
            total_seed_count_after_merge=int(staging_metadata.get("total_seed_count_after_merge", 0)),
            validation_ok=validation_ok,
            validation_output=validation_output,
            baseline_evaluation=baseline_evaluation,
            post_merge_evaluation=post_merge_evaluation,
            coverage_delta=coverage_delta,
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
            "validation_output": validation_output,
            "generated_seed_count": generated_seed_count,
            "staging_metadata": staging_metadata,
            "seed_preview": seed_preview,
            "analysis_summary": analysis_summary,
            "generator_design_rationale": rationale,
            "baseline_evaluation": baseline_evaluation,
            "post_merge_evaluation": post_merge_evaluation,
            "coverage_delta": coverage_delta,
            "evaluation": post_merge_evaluation,
            "evaluation_summary": evaluation_summary,
            "success": bool(post_merge_evaluation.get("crossed_blocked_side")),
        }
        iterations.append(iteration_record)

        score = (
            int(bool(post_merge_evaluation.get("crossed_blocked_side"))) * 1_000_000
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

        if post_merge_evaluation.get("crossed_blocked_side"):
            logging.info("Blocked side reached on iteration %d. Stopping early.", iteration_index)
            break

        previous_generator_code = generator_code
        previous_rationale = rationale
        previous_analysis_summary = analysis_summary if isinstance(analysis_summary, list) else [str(analysis_summary)]
        previous_evaluation_summary = evaluation_summary
        previous_seed_preview = seed_preview

    success = any(item.get("success") for item in iterations)
    return {
        "output_dir": str(output_dir),
        "success": success,
        "iterations_run": len(iterations),
        "max_iterations": args.max_iterations,
        "fuzz_seconds_per_iteration": args.fuzz_seconds,
        "best_iteration": best_iteration,
        "iterations": iterations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a blocker-oriented Python seed generator with an LLM.")
    parser.add_argument("--backend", default="gemini", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True)
    parser.add_argument("--source-file", required=True)
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
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    args = parser.parse_args()

    try:
        result = run_seed_generation(args)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Seed generation failed: %s", exc, exc_info=True)
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
