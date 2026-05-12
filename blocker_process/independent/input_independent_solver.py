#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import config.config as config
from blocker_process.coverage_utils import get_line_execution_count
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient
from prompts import prompt_generator

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

OUTPUT_ROOT = MODULE_ROOT / "generated_targets"


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


def resolve_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = read_optional_file(file_path)
        if text != "N/A":
            return text
    if inline_text:
        return inline_text
    return default


def clip_text(text: str, max_chars: int = 12000) -> str:
    if not text or text == "N/A":
        return "N/A"
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n\n... [truncated {omitted} characters] ..."


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


def setup_file_logging(func_name: str) -> None:
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}_input_independent_solver.log"

    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    log_filepath = log_dir / log_filename

    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)
    logging.info("Log file create: %s", log_filepath)


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


def build_output_dir(args: argparse.Namespace) -> Path:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    out_dir = OUTPUT_ROOT / f"{safe_project}_{safe_function}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def collect_prompt_context(args: argparse.Namespace, oss_fuzz: OSSFuzz) -> dict[str, str]:
    fuzz_target_code = clip_text(read_optional_file(args.fuzz_file), max_chars=20000)
    header_code = clip_text(read_optional_file(args.header_file), max_chars=12000)
    source_code = clip_text(read_optional_file(args.source_file), max_chars=20000)
    branch_window = clip_text(extract_source_window_from_file(args.source_file, int(args.branch_line_number)), max_chars=4000)
    blocked_window = clip_text(
        extract_source_window_from_file(args.source_file, int(args.blocked_side_line_number)),
        max_chars=4000,
    )
    triggering_input_path, triggering_input_preview = resolve_triggering_input(args.triggering_input)
    fuzz_path = Path(args.fuzz_file)

    return {
        "project_name": args.project_name,
        "language": args.language or oss_fuzz.proj_lang(args.project_name) or "unknown",
        "function_name": args.function_name,
        "branch_line_number": str(args.branch_line_number),
        "blocked_side_line_number": str(args.blocked_side_line_number),
        "blocker_line_code": getattr(args, "blocker_line_code", "N/A") or "N/A",
        "blocked_side_line_code": getattr(args, "blocked_side_line_code", "N/A") or "N/A",
        "fuzz_target_name": fuzz_path.stem,
        "fuzz_file": args.fuzz_file or "N/A",
        "fuzz_target_code": fuzz_target_code,
        "header_code": header_code,
        "source_file": args.source_file or "N/A",
        "source_code": source_code,
        "branch_window": branch_window,
        "blocked_window": blocked_window,
        "runtime_blocker_segment": clip_text(
            resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment),
            max_chars=7000,
        ),
        "runtime_blocker_segment_source_codes": clip_text(
            resolve_text(args.runtime_blocker_segment_source_codes_file, args.runtime_blocker_segment_source_codes),
            max_chars=10000,
        ),
        "cfg_call_chain": clip_text(resolve_text(args.cfg_call_chain_file, args.cfg_call_chain), max_chars=7000),
        "cfg_source_codes": clip_text(resolve_text(args.cfg_source_codes_file, args.cfg_source_codes), max_chars=10000),
        "triggering_input_path": triggering_input_path,
        "triggering_input_preview": triggering_input_preview,
    }


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_solver_summary(args: argparse.Namespace, result: dict) -> dict:
    baseline = result.get("baseline_evaluation") if isinstance(result.get("baseline_evaluation"), dict) else {}
    best_iteration = result.get("best_iteration") if isinstance(result.get("best_iteration"), dict) else {}
    iterations = result.get("iterations") if isinstance(result.get("iterations"), list) else []
    fallback_iterations = result.get("fallback_iterations") if isinstance(result.get("fallback_iterations"), list) else []

    return {
        "solver": "input_independent",
        "project_name": args.project_name,
        "function_name": args.function_name,
        "branch_line_number": int(args.branch_line_number),
        "blocked_side_line_number": int(args.blocked_side_line_number),
        "reference_target_name": Path(args.fuzz_file).stem,
        "reference_target_path": args.fuzz_file,
        "success": bool(result.get("success")),
        "pipeline_methods": result.get("pipeline_methods", []),
        "iteration_budget": result.get("iteration_budget"),
        "output_dir": result.get("output_dir"),
        "baseline": {
            "success": baseline.get("success"),
            "branch_hit_count": baseline.get("branch_hit_count"),
            "branch_hit_count_raw": baseline.get("branch_hit_count_raw"),
            "blocked_side_hit_count": baseline.get("blocked_side_hit_count"),
            "blocked_side_hit_count_raw": baseline.get("blocked_side_hit_count_raw"),
            "branch_line_reached": baseline.get("branch_line_reached"),
            "blocked_side_line_reached": baseline.get("blocked_side_line_reached"),
        },
        "best_iteration": {
            "iteration": best_iteration.get("iteration"),
            "strategy": best_iteration.get("strategy"),
            "target_path": best_iteration.get("target_path"),
            "accepted": best_iteration.get("accepted"),
            "success": best_iteration.get("success"),
            "score": best_iteration.get("score"),
            "evaluation": best_iteration.get("evaluation"),
        }
        if best_iteration
        else None,
        "reference_guided_iteration_count": len(iterations),
        "dedicated_generation_iteration_count": len(fallback_iterations),
        "reference_guided_stalled_out": result.get("reference_guided_stalled_out"),
        "dedicated_generation_stalled_out": result.get("dedicated_generation_stalled_out"),
        "message": result.get("message"),
        "iterations": iterations,
        "fallback_iterations": fallback_iterations,
    }


def copy_corpus_if_present(oss_fuzz: OSSFuzz, project_name: str, source_fuzzer_name: str, target_fuzzer_name: str) -> Path:
    corpus_root = oss_fuzz.build_corpus_dir / project_name
    source_dir = corpus_root / source_fuzzer_name
    target_dir = corpus_root / target_fuzzer_name
    if target_dir.exists():
        shutil.rmtree(target_dir)
    if source_dir.exists():
        shutil.copytree(source_dir, target_dir)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def evaluate_target_with_coverage(
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
) -> dict:
    build_result = oss_fuzz.build_fuzzers(project_name, "coverage")
    if not build_result.success:
        return {
            "success": False,
            "error": f"Coverage build failed: {build_result.error}",
        }

    out_dir = oss_fuzz.build_out_dir / project_name
    corpus_root = oss_fuzz.build_corpus_dir / project_name
    coverage_source = source_api_file or source_file
    container_source_file = guess_container_source_file(project_name, coverage_source)
    command = (
        "rm -f /tmp/blocker.profraw /tmp/blocker.profdata && "
        "LLVM_PROFILE_FILE=/tmp/blocker.profraw "
        f"/out/{shlex.quote(fuzzer_name)} /corpus/{shlex.quote(fuzzer_name)} "
        f"-max_total_time={int(fuzz_seconds)} -rss_limit_mb=0 -timeout=0 && "
        "llvm-profdata merge -sparse /tmp/blocker.profraw -o /tmp/blocker.profdata && "
        f"llvm-cov show /out/{shlex.quote(fuzzer_name)} "
        "-instr-profile=/tmp/blocker.profdata "
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
        }

    report = result.stdout
    write_text(output_dir / "project.linecovreport", report)

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
    image = f"gcr.io/oss-fuzz/{project_name}"
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


def format_refinement_feedback(
    project_name: str,
    language: str,
    compile_error: str,
    previous_code: str,
    iteration_feedback: str,
    preserve_seed_compatibility: bool,
) -> str:
    return prompt_generator.blocker_compile_fix_prompt(
        project_name=project_name,
        language=language,
        compile_error=compile_error,
        previous_code=previous_code,
        iteration_feedback=iteration_feedback,
        preserve_seed_compatibility=preserve_seed_compatibility,
    )


def build_iteration_prompt(
    base_prompt: str,
    iteration_index: int,
    max_iterations: int,
    previous_evaluation: dict | None = None,
    previous_code: str = "",
) -> str:
    if iteration_index == 1:
        return base_prompt

    previous_evaluation = previous_evaluation or {}
    appended = f"""

# Iteration Context

This is iteration {iteration_index} of {max_iterations}.

Previous candidate summary:
- Reached branch line: {previous_evaluation.get('branch_line_reached', False)}
- Reached blocked-side line: {previous_evaluation.get('blocked_side_line_reached', False)}
- Blocker branch hit count: {previous_evaluation.get('branch_hit_count_raw', '0')}
- Blocked side hit count: {previous_evaluation.get('blocked_side_hit_count_raw', '0')}
- Notes: {previous_evaluation.get('note', 'N/A')}

Previous candidate code:
```cpp
{previous_code or 'N/A'}
```

Revise the target based on this feedback. Do not repeat a candidate that keeps the same blocker coverage behavior.
"""
    return base_prompt + appended


def save_named_target(oss_fuzz: OSSFuzz, project_name: str, code: str, stem_prefix: str) -> Path:
    lang = oss_fuzz.proj_lang(project_name)
    extension = OSSFuzz.LANG_EXT.get(lang.lower(), ".c")
    target_dir = oss_fuzz.oss_fuzz_dir / "projects" / project_name
    unique_suffix = datetime.datetime.now().strftime("%m%d%H%M%S_%f")
    target_path = target_dir / f"{stem_prefix}_{unique_suffix}{extension}"
    target_path.write_text(code, encoding="utf-8")
    logging.info("Saved fuzz target to %s", target_path)
    return target_path


def generate_and_build_target(
    *,
    llm: LLMClient,
    oss_fuzz: OSSFuzz,
    project_name: str,
    prompt: str,
    iteration_dir: Path,
    stem_prefix: str,
    preserve_seed_compatibility: bool,
    iteration_feedback: str = "",
) -> dict:
    thread_id = int(time.time() * 1000)
    current_prompt = prompt
    previous_code = ""

    for attempt in range(1, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        logging.info("Compilation-oriented generation attempt %d/%d", attempt, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS)
        write_text(iteration_dir / f"prompt_attempt_{attempt:02d}.txt", current_prompt)
        code = llm.generate(current_prompt, thread_id=thread_id)
        if not code:
            current_prompt = "Return a full fuzz target in a single <fuzz_target> block."
            continue

        previous_code = code
        target_path = save_named_target(oss_fuzz, project_name, code, stem_prefix)
        write_text(iteration_dir / f"candidate_attempt_{attempt:02d}{target_path.suffix}", code)

        build_result = oss_fuzz.run_fuzzer(project_name, target_path.stem, seconds=1, build_fuzzer=True)
        if build_result.success:
            return {
                "success": True,
                "target_path": str(target_path),
                "code": code,
                "compile_attempts": attempt,
            }

        logging.warning("Candidate build failed on attempt %d: %s", attempt, build_result.error)
        oss_fuzz.remove_target(project_name, target_path.stem)
        current_prompt = format_refinement_feedback(
            project_name=project_name,
            language=oss_fuzz.proj_lang(project_name) or "unknown",
            compile_error=build_result.error,
            previous_code=code,
            iteration_feedback=iteration_feedback,
            preserve_seed_compatibility=preserve_seed_compatibility,
        )

    return {
        "success": False,
        "error": "Failed to generate a compiling fuzz target.",
        "last_code": previous_code,
        "compile_attempts": config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS,
    }


def run_strategy_iterations(
    *,
    args: argparse.Namespace,
    oss_fuzz: OSSFuzz,
    llm: LLMClient,
    output_dir: Path,
    base_prompt: str,
    strategy_name: str,
    source_corpus_fuzzer: str,
    preserve_seed_compatibility: bool,
    max_iterations: int,
    baseline_evaluation: dict | None = None,
    no_growth_threshold: int = config.NO_GROWTH_STOP_THRESHOLD,
) -> dict:
    iterations: list[dict] = []
    previous_evaluation: dict | None = None
    previous_code = read_optional_file(args.fuzz_file) if strategy_name == "reference_guided" else ""
    accepted_evaluation: dict = dict(baseline_evaluation or {})
    accepted_evaluation.setdefault("blocked_side_hit_count", 0)
    accepted_evaluation.setdefault("blocked_side_line_reached", False)
    accepted_evaluation.setdefault(
        "note",
        (
            "baseline target: "
            f"{args.fuzz_file} "
            f"(blocked={accepted_evaluation.get('blocked_side_hit_count_raw', '0')})"
        ),
    )
    accepted_target_path = str(args.fuzz_file)
    no_growth_count = 0
    stalled_out = False

    for iteration_index in range(1, max_iterations + 1):
        iteration_dir = output_dir / strategy_name / f"iter_{iteration_index:02d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)

        prompt = build_iteration_prompt(
            base_prompt=base_prompt,
            iteration_index=iteration_index,
            max_iterations=max_iterations,
            previous_evaluation=previous_evaluation,
            previous_code=previous_code,
        )
        write_text(iteration_dir / "prompt.txt", prompt)

        build_info = generate_and_build_target(
            llm=llm,
            oss_fuzz=oss_fuzz,
            project_name=args.project_name,
            prompt=prompt,
            iteration_dir=iteration_dir,
            stem_prefix=f"llm_fuzzgen_{strategy_name}",
            preserve_seed_compatibility=preserve_seed_compatibility,
            iteration_feedback=(previous_evaluation or {}).get("note", ""),
        )

        record: dict = {
            "iteration": iteration_index,
            "strategy": strategy_name,
            "build": build_info,
            "success": False,
        }

        if not build_info.get("success"):
            record["note"] = build_info.get("error", "build failed")
            iterations.append(record)
            previous_evaluation = {"note": record["note"]}
            continue

        target_path = Path(build_info["target_path"])
        copy_corpus_if_present(oss_fuzz, args.project_name, source_corpus_fuzzer, target_path.stem)
        evaluation = evaluate_target_with_coverage(
            oss_fuzz=oss_fuzz,
            project_name=args.project_name,
            fuzzer_name=target_path.stem,
            function_name=args.function_name,
            source_file=args.source_file,
            source_api_file=getattr(args, "source_api_file", None),
            branch_line=int(args.branch_line_number),
            blocked_side_line=int(args.blocked_side_line_number),
            fuzz_seconds=args.fuzz_seconds,
            output_dir=iteration_dir,
        )
        record["evaluation"] = evaluation
        record["target_path"] = str(target_path)
        record["success"] = bool(evaluation.get("blocked_side_line_reached"))
        if evaluation.get("success"):
            record["note"] = (
                f"branch={evaluation.get('branch_hit_count_raw', '0')}, "
                f"blocked={evaluation.get('blocked_side_hit_count_raw', '0')}"
            )
        else:
            record["note"] = (
                f"branch={evaluation.get('branch_hit_count_raw', '0')}, "
                f"blocked={evaluation.get('blocked_side_hit_count_raw', '0')}"
                if evaluation.get("branch_hit_count_raw") is not None
                else evaluation.get("error", "coverage evaluation failed")
            )

        candidate_blocked_hit = int(evaluation.get("blocked_side_hit_count", 0))
        accepted_blocked_hit = int(accepted_evaluation.get("blocked_side_hit_count", 0))
        record["candidate_score"] = {
            "blocked_side_hit_count": candidate_blocked_hit,
        }
        record["rollback_target_path"] = accepted_target_path

        should_accept = bool(evaluation.get("blocked_side_line_reached"))
        record["accepted"] = should_accept

        if not should_accept:
            logging.info(
                "Discarding candidate %s for strategy %s at iteration %d; blocker not crossed.",
                target_path.stem,
                strategy_name,
                iteration_index,
            )
            oss_fuzz.remove_target(args.project_name, target_path.stem)
            record["rolled_back"] = True
            no_growth_count += 1
            record["no_growth_count"] = no_growth_count
            record["note"] = (
                f"{record['note']} | rolled back to {accepted_target_path} "
                f"(blocked={accepted_blocked_hit})"
            )
            iterations.append(record)
            previous_evaluation = accepted_evaluation
            if no_growth_count >= no_growth_threshold:
                stalled_out = True
                logging.info(
                    "Strategy %s stalled after %d consecutive non-improving iterations; switching strategy.",
                    strategy_name,
                    no_growth_count,
                )
                break
            continue

        iterations.append(record)
        previous_evaluation = evaluation | {"note": record["note"]}
        accepted_evaluation = previous_evaluation
        accepted_target_path = str(target_path)
        previous_code = build_info.get("code", "")
        no_growth_count = 0

        if record["success"]:
            logging.info("Strategy %s succeeded at iteration %d", strategy_name, iteration_index)
            break

    return {
        "iterations": iterations,
        "stalled_out": stalled_out,
        "accepted_target_path": accepted_target_path,
        "accepted_evaluation": accepted_evaluation,
    }


def summarize_best_iteration(iterations: list[dict]) -> dict | None:
    scored: list[tuple[int, dict]] = []
    for item in iterations:
        evaluation = item.get("evaluation", {})
        score = (
            int(bool(evaluation.get("blocked_side_line_reached"))) * 1_000_000
            + int(evaluation.get("blocked_side_hit_count", 0)) * 1_000
            + int(evaluation.get("branch_hit_count", 0))
        )
        scored.append((score, item))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    best = dict(scored[0][1])
    best["score"] = scored[0][0]
    return best


def run_input_independent_solver(args: argparse.Namespace) -> dict:
    setup_file_logging(args.function_name)
    oss_fuzz = OSSFuzz()
    llm = LLMClient(backend=args.backend, model_name=args.model)
    output_dir = build_output_dir(args)

    prompt_context = collect_prompt_context(args, oss_fuzz)
    baseline_dir = output_dir / "baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    source_fuzzer_name = Path(args.fuzz_file).stem
    baseline_evaluation = evaluate_target_with_coverage(
        oss_fuzz=oss_fuzz,
        project_name=args.project_name,
        fuzzer_name=source_fuzzer_name,
        function_name=args.function_name,
        source_file=args.source_file,
        source_api_file=getattr(args, "source_api_file", None),
        branch_line=int(args.branch_line_number),
        blocked_side_line=int(args.blocked_side_line_number),
        fuzz_seconds=args.fuzz_seconds,
        output_dir=baseline_dir,
    )

    if baseline_evaluation.get("blocked_side_line_reached"):
        return {
            "success": True,
            "pipeline_methods": [],
            "output_dir": str(output_dir),
            "baseline_evaluation": baseline_evaluation,
            "message": "Baseline fuzz target already reaches the blocked-side line.",
            "iterations": [],
        }

    reference_guided_prompt = prompt_generator.blocker_reference_guided_prompt(**prompt_context)
    dedicated_generation_prompt = prompt_generator.blocker_dedicated_generation_prompt(**prompt_context)
    iteration_budget = config.ITERATION_LOOP

    reference_guided_result = run_strategy_iterations(
        args=args,
        oss_fuzz=oss_fuzz,
        llm=llm,
        output_dir=output_dir,
        base_prompt=reference_guided_prompt,
        strategy_name="reference_guided",
        source_corpus_fuzzer=source_fuzzer_name,
        preserve_seed_compatibility=True,
        max_iterations=iteration_budget,
        baseline_evaluation=baseline_evaluation,
        no_growth_threshold=config.NO_GROWTH_STOP_THRESHOLD,
    )
    reference_guided_iterations = reference_guided_result["iterations"]
    if any(item.get("success") for item in reference_guided_iterations):
        return {
            "success": True,
            "pipeline_methods": ["reference_guided_generation"],
            "output_dir": str(output_dir),
            "baseline_evaluation": baseline_evaluation,
            "iteration_budget": iteration_budget,
            "best_iteration": summarize_best_iteration(reference_guided_iterations),
            "iterations": reference_guided_iterations,
            "fallback_iterations": [],
        }

    dedicated_generation_result = run_strategy_iterations(
        args=args,
        oss_fuzz=oss_fuzz,
        llm=llm,
        output_dir=output_dir,
        base_prompt=dedicated_generation_prompt,
        strategy_name="dedicated_generation",
        source_corpus_fuzzer=source_fuzzer_name,
        preserve_seed_compatibility=False,
        max_iterations=iteration_budget,
        baseline_evaluation=reference_guided_result["accepted_evaluation"],
        no_growth_threshold=config.NO_GROWTH_STOP_THRESHOLD,
    )
    dedicated_generation_iterations = dedicated_generation_result["iterations"]

    all_iterations = reference_guided_iterations + dedicated_generation_iterations
    return {
        "success": any(item.get("success") for item in all_iterations),
        "pipeline_methods": [
            method
            for method, used in [
                ("reference_guided_generation", bool(reference_guided_iterations)),
                ("dedicated_generation", bool(dedicated_generation_iterations)),
            ]
            if used
        ],
        "output_dir": str(output_dir),
        "baseline_evaluation": baseline_evaluation,
        "iteration_budget": iteration_budget,
        "reference_guided_stalled_out": reference_guided_result["stalled_out"],
        "dedicated_generation_stalled_out": dedicated_generation_result["stalled_out"],
        "best_iteration": summarize_best_iteration(all_iterations),
        "iterations": reference_guided_iterations,
        "fallback_iterations": dedicated_generation_iterations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve input-independent blockers via reference-guided and dedicated fuzz target generation."
    )
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True)
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--source-api-file", default=None)
    parser.add_argument("--fuzz-file", required=True)
    parser.add_argument("--target-name", default=None)
    parser.add_argument("--header-file", default=None)
    parser.add_argument("--language", default=None)
    parser.add_argument("--blocker-line-code", default="N/A")
    parser.add_argument("--blocked-side-line-code", default="N/A")
    parser.add_argument("--runtime-blocker-segment-file", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes-file", default=None)
    parser.add_argument("--cfg-call-chain-file", default=None)
    parser.add_argument("--cfg-source-codes-file", default=None)
    parser.add_argument("--runtime-blocker-segment", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes", default=None)
    parser.add_argument("--cfg-call-chain", default=None)
    parser.add_argument("--cfg-source-codes", default=None)
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--max-iterations", type=int, default=config.ITERATION_LOOP)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    args = parser.parse_args()

    try:
        result = run_input_independent_solver(args)
        summary = build_solver_summary(args, result)
        output_dir = Path(result["output_dir"])
        summary_path = output_dir / "summary.json"
        write_json(summary_path, summary)
        result["summary_path"] = str(summary_path)
        logging.info("Wrote input-independent summary to %s", summary_path)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Blocker solver failed: %s", exc, exc_info=True)
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result.get("success") else 4)


if __name__ == "__main__":
    main()
