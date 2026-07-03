#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import logging
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from external.oss_fuzz import OSSFuzz  # noqa: E402
import config.config as config  # noqa: E402

SEED_GENERATOR = MODULE_ROOT / "input_dependent_seed_generator.py"
HARNESS_GENERATOR = MODULE_ROOT / "input_dependent_harness_generator.py"
RUN_SYMCC_BLOCKER = MODULE_ROOT / "run_symcc_blocker.py"
OUTPUT_ROOT = MODULE_ROOT / "generated_symbolic_runs"
DEFAULT_LLVM18_ROOT = Path.home() / "tools" / "llvm-18.1.8" / "bin"
DEFAULT_LLVM_PROFDATA = str(DEFAULT_LLVM18_ROOT / "llvm-profdata")
DEFAULT_LLVM_COV = str(DEFAULT_LLVM18_ROOT / "llvm-cov")


def sanitize_name(value: str) -> str:
    import re

    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_solver_summary(args: argparse.Namespace, result: dict) -> dict:
    stages = result.get("stages", {}) if isinstance(result.get("stages"), dict) else {}
    stage_statuses: dict[str, dict] = {}
    for stage_name, stage_payload in stages.items():
        if isinstance(stage_payload, dict):
            stage_statuses[stage_name] = {
                "success": stage_payload.get("success"),
                "returncode": stage_payload.get("returncode"),
                "final_status": stage_payload.get("final_status"),
                "failure_kind": stage_payload.get("failure_kind"),
                "retryable": stage_payload.get("retryable"),
                "message": stage_payload.get("message"),
            }
        else:
            stage_statuses[stage_name] = {"success": None}

    return {
        "solver": "input_dependent",
        "project_name": args.project_name,
        "function_name": args.function_name,
        "branch_line_number": int(args.branch_line_number),
        "blocked_side_line_number": int(args.blocked_side_line_number),
        "reference_target_name": args.target_name or Path(args.fuzz_file).stem,
        "reference_target_path": args.fuzz_file,
        "success": bool(result.get("success")),
        "attempt_result": result.get("attempt_result", "success" if result.get("success") else "failed"),
        "success_stage": result.get("success_stage"),
        "failure_stage": result.get("failure_stage"),
        "pipeline_methods": result.get("pipeline_methods", []),
        "used_llm_seed_generator": result.get("used_llm_seed_generator"),
        "used_symcc": result.get("used_symcc"),
        "seed_inputs": result.get("seed_inputs", []),
        "symcc_seed_inputs": result.get("symcc_seed_inputs", []),
        "symcc_seed_handoff_limits": result.get("symcc_seed_handoff_limits"),
        "output_dir": result.get("output_dir"),
        "llm_seed_final_status": result.get("llm_seed_final_status"),
        "llm_seed_generator_terminal_reason": result.get("llm_seed_generator_terminal_reason"),
        "llm_seed_best_symcc_family": result.get("llm_seed_best_symcc_family"),
        "llm_seed_best_symcc_top_families": result.get("llm_seed_best_symcc_top_families"),
        "llm_seed_best_symcc_seed_paths": result.get("llm_seed_best_symcc_seed_paths"),
        "llm_seed_recommended_symcc_generator_seed_paths": result.get("llm_seed_recommended_symcc_generator_seed_paths"),
        "llm_seed_handoff_selection_reason": result.get("llm_seed_handoff_selection_reason"),
        "llm_seed_progress_iteration_count": result.get("llm_seed_progress_iteration_count"),
        "message": result.get("message"),
        "generated_harness_retention": result.get("generated_harness_retention"),
        "stage_statuses": stage_statuses,
        "stages": stages,
    }


def run_program(
    cmd: list[str],
    *,
    json_output_file: Path | None = None,
    timeout_sec: float | None = None,
    timeout_failure_kind: str = "stage_timeout",
) -> dict:
    logging.info("Dispatching: %s", " ".join(cmd))
    started_at = time.monotonic()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started_at
        logging.error(
            "Stage timed out after %.1fs (limit=%.1fs): %s",
            elapsed,
            float(timeout_sec or 0),
            " ".join(cmd),
        )
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()

        parsed_timeout = {
            "success": False,
            "attempt_result": "llm_error",
            "failure_kind": timeout_failure_kind,
            "retryable": True,
            "timeout_seconds": float(timeout_sec or 0),
            "elapsed_seconds": elapsed,
            "message": f"LLM generation stage exceeded {float(timeout_sec or 0):.0f} seconds.",
        }
        return {
            "returncode": 124,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "parsed_output": parsed_timeout,
            "timed_out": True,
        }

    parsed: dict | None = None
    if json_output_file and json_output_file.exists():
        try:
            parsed = json.loads(json_output_file.read_text(encoding="utf-8"))
        except Exception:
            parsed = None
    if parsed is None:
        text = (stdout or "").strip()
        if text:
            try:
                parsed_json = json.loads(text)
                if isinstance(parsed_json, dict):
                    parsed = parsed_json
            except Exception:
                parsed = None
    return {
        "returncode": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "parsed_output": parsed,
        "timed_out": False,
    }


def existing_seed_inputs(args: argparse.Namespace) -> list[str]:
    seeds = [str(Path(seed).resolve()) for seed in args.seed]
    if seeds:
        return seeds
    if args.triggering_input:
        trigger_path = Path(args.triggering_input)
        if trigger_path.exists() and trigger_path.is_file():
            return [str(trigger_path.resolve())]
    return []


def resolve_seed_generator_triggering_input(args: argparse.Namespace, seeds: list[str]) -> str:
    if args.triggering_input:
        return str(args.triggering_input)
    return seeds[0] if seeds else ""


def resolve_harness_fidelity_seed(args: argparse.Namespace, seeds: list[str]) -> str:
    if args.triggering_input:
        trigger_path = Path(args.triggering_input)
        if trigger_path.is_file():
            return str(trigger_path.resolve())
    for seed in seeds:
        seed_path = Path(seed)
        if seed_path.is_file():
            return str(seed_path.resolve())
    return ""


def get_symcc_failure_kind(stage: dict | None) -> str:
    if not isinstance(stage, dict):
        return ""
    if stage.get("failure_kind"):
        return str(stage["failure_kind"])
    fidelity_preflight = stage.get("fidelity_preflight")
    if isinstance(fidelity_preflight, dict) and fidelity_preflight.get("failure_kind"):
        return str(fidelity_preflight["failure_kind"])
    symcc = stage.get("symcc")
    return str(symcc.get("failure_kind") or "") if isinstance(symcc, dict) else ""


def get_harness_fidelity_feedback(stage: dict | None) -> str:
    if not isinstance(stage, dict):
        return "Generated harness did not preserve the branch-reaching seed path."
    fidelity = stage.get("harness_fidelity")
    if isinstance(fidelity, dict):
        return json.dumps(fidelity, ensure_ascii=False, indent=2)
    symcc = stage.get("symcc")
    if isinstance(symcc, dict) and symcc.get("output"):
        return str(symcc["output"])[-8000:]
    return "Generated harness did not preserve the branch-reaching seed path."


def choose_symcc_seed_inputs(
    fallback_seeds: list[str],
    parsed_llm_seed: dict | None,
) -> tuple[list[str], dict]:
    fallback = [str(Path(seed).resolve()) for seed in fallback_seeds if Path(seed).exists()]
    if not isinstance(parsed_llm_seed, dict):
        return fallback, {
            "generator_terminal_reason": "",
            "recommended_generator_seed_paths": [],
            "selection_reason": "LLM seed generator did not return structured handoff metadata.",
        }

    generator_terminal_reason = str(parsed_llm_seed.get("generator_terminal_reason") or "")
    recommended_paths = [
        str(Path(path).resolve())
        for path in (parsed_llm_seed.get("recommended_symcc_generator_seed_paths") or [])
        if path and Path(path).exists()
    ]
    combined: list[str] = []
    seen: set[str] = set()
    for seed in recommended_paths + fallback:
        if seed and seed not in seen:
            combined.append(seed)
            seen.add(seed)

    return combined or fallback, {
        "generator_terminal_reason": generator_terminal_reason,
        "recommended_generator_seed_paths": recommended_paths,
        "selection_reason": str(parsed_llm_seed.get("recommended_symcc_selection_reason") or ""),
    }


def build_runtime_sanity_seed_args(seed_paths: list[str]) -> list[str]:
    forwarded: list[str] = []
    for seed_path in seed_paths:
        if seed_path and Path(seed_path).is_file():
            forwarded.extend(["--runtime-sanity-seed", str(Path(seed_path).resolve())])
    return forwarded


def _seed_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_bounded_symcc_handoff_seeds(
    priority_seeds: list[str],
    corpus_dir: Path | None,
    max_total_seeds: int,
) -> tuple[list[str], dict]:
    limit = max(1, int(max_total_seeds))
    ordered_candidates: list[Path] = []
    for raw_path in priority_seeds:
        path = Path(raw_path)
        if path.is_file():
            ordered_candidates.append(path)
    if corpus_dir is not None and corpus_dir.is_dir():
        corpus_candidates = sorted(
            (path for path in corpus_dir.iterdir() if path.is_file()),
            key=lambda path: (path.stat().st_size, path.name),
        )
        ordered_candidates.extend(corpus_candidates)

    selected: list[str] = []
    seen_hashes: set[str] = set()
    duplicate_count = 0
    for path in ordered_candidates:
        try:
            digest = _seed_digest(path)
        except OSError:
            continue
        if digest in seen_hashes:
            duplicate_count += 1
            continue
        if len(selected) >= limit:
            continue
        seen_hashes.add(digest)
        selected.append(str(path.resolve()))

    return selected, {
        "max_total_seeds": limit,
        "candidate_count": len(ordered_candidates),
        "selected_count": len(selected),
        "duplicate_count": duplicate_count,
        "dropped_count": max(0, len(ordered_candidates) - duplicate_count - len(selected)),
    }


def symcc_initial_seed_budget(max_total_seeds: int, initial_frontier_cap: int = 30) -> int:
    """Bound the initial handoff independently from next-generation retention."""
    total = max(1, int(max_total_seeds))
    return min(total, max(1, int(initial_frontier_cap)))


def build_context_args(args: argparse.Namespace) -> list[str]:
    forwarded = [
        "--backend",
        args.backend,
        "--project-name",
        args.project_name,
        "--function-name",
        args.function_name,
        "--branch-line-number",
        str(args.branch_line_number),
        "--blocked-side-line-number",
        str(args.blocked_side_line_number),
        "--source-file",
        args.source_file,
        "--fuzz-file",
        args.fuzz_file,
    ]
    if getattr(args, "source_api_file", None):
        forwarded.extend(["--source-api-file", args.source_api_file])
    if args.model:
        forwarded.extend(["--model", args.model])
    if args.header_file:
        forwarded.extend(["--header-file", args.header_file])
    if args.language:
        forwarded.extend(["--language", args.language])
    if args.runtime_blocker_segment_file:
        forwarded.extend(["--runtime-blocker-segment-file", args.runtime_blocker_segment_file])
    if args.runtime_blocker_segment_source_codes_file:
        forwarded.extend(
            ["--runtime-blocker-segment-source-codes-file", args.runtime_blocker_segment_source_codes_file]
        )
    if args.cfg_call_chain_file:
        forwarded.extend(["--cfg-call-chain-file", args.cfg_call_chain_file])
    if args.cfg_source_codes_file:
        forwarded.extend(["--cfg-source-codes-file", args.cfg_source_codes_file])
    if args.runtime_blocker_segment:
        forwarded.extend(["--runtime-blocker-segment", args.runtime_blocker_segment])
    if args.runtime_blocker_segment_source_codes:
        forwarded.extend(["--runtime-blocker-segment-source-codes", args.runtime_blocker_segment_source_codes])
    if args.cfg_call_chain:
        forwarded.extend(["--cfg-call-chain", args.cfg_call_chain])
    if args.cfg_source_codes:
        forwarded.extend(["--cfg-source-codes", args.cfg_source_codes])
    if getattr(args, "blocker_call_sites_file", None):
        forwarded.extend(["--blocker-call-sites-file", args.blocker_call_sites_file])
    if getattr(args, "blocker_call_sites", None):
        forwarded.extend(["--blocker-call-sites", args.blocker_call_sites])
    if getattr(args, "seed_generator_timeout_sec", None) is not None:
        forwarded.extend(["--generator-timeout-sec", str(args.seed_generator_timeout_sec)])
    if getattr(args, "max_seed_size_bytes", None) is not None:
        forwarded.extend(["--max-seed-size-bytes", str(args.max_seed_size_bytes)])
    if args.triggering_input:
        forwarded.extend(["--triggering-input", args.triggering_input])
    return forwarded


def blocker_payload(args: argparse.Namespace, seeds: list[str]) -> dict:
    target_name = args.target_name or Path(args.fuzz_file).stem
    return {
        "project_name": args.project_name,
        "target_name": target_name,
        "function_name": args.function_name,
        "branch_line_number": int(args.branch_line_number),
        "blocked_side_line_number": int(args.blocked_side_line_number),
        "source_file": args.source_file,
        "source_api_file": getattr(args, "source_api_file", None),
        "fuzz_file": args.fuzz_file,
        "seeds": seeds,
    }


def run_libfuzzer_focused_pass(
    project_name: str,
    target_name: str,
    initial_seeds: list[str],
    fuzz_seconds: int,
) -> dict:
    """Run a short libFuzzer pass on the simplified harness using its already-built ASAN binary.

    Copies initial_seeds into the OSS-Fuzz corpus directory for target_name, then runs
    libFuzzer for fuzz_seconds. The enriched corpus (initial + fuzzer-discovered seeds)
    is returned so Stage 3c (SymCC) can start from a richer set of starting points.

    Returns a dict with keys: success (bool), corpus_dir (str), seed_count (int), error (str).
    """
    oss_fuzz = OSSFuzz()
    corpus_dir = oss_fuzz.build_corpus_dir / project_name / target_name
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Pre-populate corpus with the LLM-generated seeds.
    for src_str in initial_seeds:
        src = Path(src_str)
        if src.is_file():
            dest = corpus_dir / src.name
            if not dest.exists():
                try:
                    shutil.copy2(str(src), str(dest))
                except OSError:
                    pass

    seed_count_before = sum(1 for _ in corpus_dir.iterdir() if _.is_file())
    logging.info(
        "Stage 3b: running libFuzzer on %s for %ds with %d seed(s) in corpus",
        target_name,
        fuzz_seconds,
        seed_count_before,
    )

    address_build = oss_fuzz.ensure_target_binary(
        project_name,
        target_name,
        sanitizer="address",
    )
    if not address_build.success:
        return {
            "success": False,
            "corpus_dir": str(corpus_dir),
            "seed_count_before": seed_count_before,
            "seed_count_after": seed_count_before,
            "new_seeds": 0,
            "error": f"Failed to restore address build before focused fuzzing: {address_build.error}",
        }

    run_result = oss_fuzz.run_fuzzer(
        proj_name=project_name,
        fuzzer_name=target_name,
        seconds=fuzz_seconds,
        build_fuzzer=False,  # ASAN binary was already built by harness native build gate
    )

    seed_count_after = sum(1 for _ in corpus_dir.iterdir() if _.is_file())
    new_seeds = seed_count_after - seed_count_before
    logging.info(
        "Stage 3b: libFuzzer pass finished (success=%s); %d new seed(s) discovered",
        run_result.success,
        new_seeds,
    )

    return {
        "success": run_result.success,
        "corpus_dir": str(corpus_dir),
        "seed_count_before": seed_count_before,
        "seed_count_after": seed_count_after,
        "new_seeds": new_seeds,
        "error": run_result.error or "",
    }


def _resolve_symcc_debug_root(args: argparse.Namespace) -> Path:
    experiments_root = REPO_ROOT / "experiments"
    output_root = Path(args.output_root).resolve() if getattr(args, "output_root", None) else None
    if output_root is not None:
        try:
            relative = output_root.relative_to(experiments_root.resolve())
            if relative.parts:
                return experiments_root / relative.parts[0] / "symcc"
        except ValueError:
            pass
    return experiments_root / "symcc"


def _copy_debug_file(path_value: object, destination: Path, label: str) -> str | None:
    if not path_value:
        return None
    source = Path(str(path_value))
    if not source.is_file():
        return None
    label_dir = destination / label
    label_dir.mkdir(parents=True, exist_ok=True)
    target = label_dir / source.name
    shutil.copy2(source, target)
    return str(target)


def archive_generated_harness_for_debug(
    args: argparse.Namespace,
    parsed_harness: dict,
    symcc_harness_stage: dict | None,
    reason: str,
) -> dict:
    target_name = str(parsed_harness.get("native_build_target_name") or "").strip()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = sanitize_name(
        f"{args.project_name}_{args.function_name}_{args.branch_line_number}_{target_name or 'generated_harness'}_{timestamp}"
    )
    archive_dir = _resolve_symcc_debug_root(args) / archive_name
    archive_dir.mkdir(parents=True, exist_ok=True)

    copied_files = {
        "generated_harness": _copy_debug_file(parsed_harness.get("harness_path"), archive_dir, "source"),
        "oss_fuzz_target": _copy_debug_file(parsed_harness.get("native_build_target_path"), archive_dir, "oss_fuzz_target"),
        "prompt": _copy_debug_file(parsed_harness.get("prompt_path"), archive_dir, "llm"),
        "response": _copy_debug_file(parsed_harness.get("response_path"), archive_dir, "llm"),
        "parsed": _copy_debug_file(parsed_harness.get("parsed_path"), archive_dir, "llm"),
    }
    harness_path = Path(str(parsed_harness.get("harness_path") or ""))
    if harness_path.is_file():
        copied_files["build_context"] = _copy_debug_file(harness_path.parent / "build_context.json", archive_dir, "source")
        copied_files["native_build_check"] = _copy_debug_file(harness_path.parent / "native_build_check.txt", archive_dir, "source")

    metadata = {
        "reason": reason,
        "project_name": args.project_name,
        "function_name": args.function_name,
        "branch_line_number": int(args.branch_line_number),
        "blocked_side_line_number": int(args.blocked_side_line_number),
        "native_build_target_name": target_name or None,
        "parsed_harness": parsed_harness,
        "symcc_harness_stage": symcc_harness_stage or {},
        "copied_files": copied_files,
    }
    write_json(archive_dir / "metadata.json", metadata)
    return {
        "debug_archive_dir": str(archive_dir),
        "copied_files": copied_files,
    }


def quarantine_unsolved_generated_harness(
    args: argparse.Namespace,
    parsed_harness: dict | None,
    symcc_harness_stage: dict | None,
    reason: str,
) -> dict:
    if not isinstance(parsed_harness, dict):
        return {
            "retained": False,
            "quarantined": False,
            "reason": reason,
            "error": "No generated harness metadata available.",
        }

    archive_info = archive_generated_harness_for_debug(args, parsed_harness, symcc_harness_stage, reason)
    target_name = str(parsed_harness.get("native_build_target_name") or "").strip()
    removed = False
    if target_name:
        OSSFuzz().remove_target(args.project_name, target_name)
        removed = True

    return {
        "retained": False,
        "quarantined": True,
        "reason": reason,
        "target_name": target_name or None,
        "oss_fuzz_target_removed": removed,
        **archive_info,
    }


def build_symcc_cmd(
    args: argparse.Namespace,
    blocker_json_path: Path,
    work_dir: Path,
    seeds: list[str],
    fuzz_target: str | None,
    target_name: str | None,
    json_output_path: Path,
    fidelity_seed: str | None = None,
    fidelity_only: bool = False,
) -> list[str]:
    cmd = [
        sys.executable,
        str(RUN_SYMCC_BLOCKER),
        "--blocker-json-file",
        str(blocker_json_path),
        "--project-name",
        args.project_name,
        "--branch-source",
        getattr(args, "source_api_file", None) or args.source_file,
        "--branch-line",
        str(args.branch_line_number),
        "--blocked-side-line",
        str(args.blocked_side_line_number),
        "--work-dir",
        str(work_dir),
        "--max-generations",
        str(args.symcc_max_generations),
        "--max-total-seeds",
        str(args.symcc_max_total_seeds),
        "--max-candidate-evaluations",
        str(getattr(args, "symcc_max_candidate_evaluations", 200)),
        "--max-retained-seeds",
        str(getattr(args, "symcc_max_retained_seeds", args.symcc_max_total_seeds)),
        "--initial-frontier-cap",
        str(getattr(args, "symcc_initial_frontier_cap", 30)),
        "--timeout-sec",
        str(args.symcc_timeout_sec),
        "--wall-clock-budget-sec",
        str(getattr(args, "symcc_wall_clock_budget_sec", 0) or 0),
        "--json-output-file",
        str(json_output_path),
    ]
    if fuzz_target:
        cmd.extend(["--fuzz-target", fuzz_target])
    if target_name:
        cmd.extend(["--target-name", target_name])
    for seed in seeds:
        cmd.extend(["--seed", seed])
    if fidelity_seed and Path(fidelity_seed).is_file():
        cmd.extend(["--fidelity-seed", str(Path(fidelity_seed).resolve())])
    if fidelity_only:
        cmd.append("--fidelity-only")
    if args.keep_coverage_reports:
        cmd.append("--keep-coverage-reports")
    if getattr(args, "llvm_profdata", None):
        cmd.extend(["--llvm-profdata", args.llvm_profdata])
    if getattr(args, "llvm_cov", None):
        cmd.extend(["--llvm-cov", args.llvm_cov])
    return cmd


def successful(parsed_output: dict | None) -> bool:
    return bool(parsed_output and parsed_output.get("success"))


def seed_generation_exceeded_budget(parsed_output: dict | None) -> bool:
    if not isinstance(parsed_output, dict):
        return False
    return str(parsed_output.get("generator_terminal_reason") or "") == "seed_budget_exceeded"


def infer_attempt_result(result: dict) -> str:
    if result.get("success"):
        return "success"

    failure_stage = str(result.get("failure_stage") or "")
    stages = result.get("stages") if isinstance(result.get("stages"), dict) else {}
    stage_payload = stages.get(failure_stage) if failure_stage else None
    if isinstance(stage_payload, dict) and stage_payload.get("attempt_result") == "llm_error":
        return "llm_error"
    if isinstance(stage_payload, dict) and stage_payload.get("attempt_result") == "pipeline_error":
        return "pipeline_error"
    if isinstance(stage_payload, dict):
        nested_symcc = stage_payload.get("symcc")
        if isinstance(nested_symcc, dict) and nested_symcc.get("attempt_result") == "pipeline_error":
            return "pipeline_error"
    return "failed"


def run_input_dependent_solver(args: argparse.Namespace) -> dict:
    seeds = existing_seed_inputs(args)
    if not seeds:
        raise RuntimeError(
            "No blocker-reaching seed is available. Pass --seed or ensure --triggering-input points to a local seed file."
        )

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    _output_root = (Path(args.output_root) / "symbolic_run") if getattr(args, "output_root", None) else OUTPUT_ROOT
    output_dir = _output_root / f"{safe_project}_{safe_function}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    payload_path = output_dir / "blocker_payload.json"
    payload_path.write_text(
        json.dumps(blocker_payload(args, seeds), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    result: dict[str, object] = {
        "success": False,
        "pipeline_methods": [],
        "used_llm_seed_generator": False,
        "used_symcc": False,
        "output_dir": str(output_dir),
        "seed_inputs": seeds,
        "symcc_seed_inputs": list(seeds),
        "generated_harness_retention": None,
        "stages": {},
    }

    seed_generator_context_args = build_context_args(args)
    seed_generator_triggering_input = resolve_seed_generator_triggering_input(args, seeds)
    if seed_generator_triggering_input and not args.triggering_input:
        seed_generator_context_args.extend(["--triggering-input", seed_generator_triggering_input])

    llm_seed_cmd = [
        sys.executable,
        str(SEED_GENERATOR),
        *seed_generator_context_args,
        "--max-iterations",
        str(args.max_iterations),
        "--fuzz-seconds",
        str(args.fuzz_seconds),
    ]
    if args.reset_corpus_per_iteration:
        llm_seed_cmd.append("--reset-corpus-per-iteration")
    if getattr(args, "output_root", None):
        llm_seed_cmd.extend(["--output-root", str(Path(args.output_root) / "generator")])
    if getattr(args, "log_dir", None):
        llm_seed_cmd.extend(["--log-dir", str(args.log_dir)])
    seed_stage_timeout = float(getattr(args, "llm_seed_stage_timeout_sec", 900) or 0)
    llm_seed_result = run_program(
        llm_seed_cmd,
        timeout_sec=seed_stage_timeout if seed_stage_timeout > 0 else None,
        timeout_failure_kind="llm_timeout",
    )
    result["used_llm_seed_generator"] = True
    result["pipeline_methods"].append("llm_seed_generator")
    result["stages"]["llm_seed_generator"] = llm_seed_result.get("parsed_output") or {
        "returncode": llm_seed_result["returncode"],
        "stdout": llm_seed_result["stdout"],
        "stderr": llm_seed_result["stderr"],
    }
    parsed_llm_seed = llm_seed_result.get("parsed_output") if isinstance(llm_seed_result.get("parsed_output"), dict) else {}
    if isinstance(parsed_llm_seed, dict):
        result["llm_seed_final_status"] = parsed_llm_seed.get("final_status")
        result["llm_seed_generator_terminal_reason"] = parsed_llm_seed.get("generator_terminal_reason")
        result["llm_seed_progress_iteration_count"] = parsed_llm_seed.get("progress_iteration_count", 0)
        result["llm_seed_best_symcc_family"] = parsed_llm_seed.get("best_symcc_family", "")
        result["llm_seed_best_symcc_top_families"] = parsed_llm_seed.get("best_symcc_top_families", [])
        result["llm_seed_best_symcc_seed_paths"] = parsed_llm_seed.get("best_symcc_seed_paths", [])
        result["llm_seed_recommended_symcc_generator_seed_paths"] = parsed_llm_seed.get(
            "recommended_symcc_generator_seed_paths", []
        )
    if successful(llm_seed_result.get("parsed_output")):
        result["success"] = True
        result["success_stage"] = "llm_seed_generator"
        result["attempt_result"] = "success"
        return result
    if isinstance(parsed_llm_seed, dict) and parsed_llm_seed.get("failure_kind") == "llm_timeout":
        result["llm_seed_timeout_fallback_to_symcc"] = True
        result["llm_seed_timeout_message"] = str(
            parsed_llm_seed.get("message") or "Seed-generation LLM stage timed out."
        )
    if seed_generation_exceeded_budget(parsed_llm_seed):
        result["success"] = False
        result["failure_stage"] = "llm_seed_generator"
        result["attempt_result"] = "failed"
        result["message"] = (
            "LLM seed generation exceeded the configured seed materialization budget; "
            "skipping SymCC handoff for this blocker attempt."
        )
        return result

    candidate_symcc_seeds, handoff_metadata = choose_symcc_seed_inputs(seeds, parsed_llm_seed)
    initial_seed_limit = symcc_initial_seed_budget(
        args.symcc_max_total_seeds,
        getattr(args, "symcc_initial_frontier_cap", 30),
    )
    symcc_seeds, initial_handoff_limits = select_bounded_symcc_handoff_seeds(
        priority_seeds=[*seeds, *candidate_symcc_seeds],
        corpus_dir=None,
        max_total_seeds=initial_seed_limit,
    )
    initial_handoff_limits["symcc_initial_frontier_cap"] = initial_seed_limit
    initial_handoff_limits["symcc_candidate_eval_budget"] = getattr(
        args, "symcc_max_candidate_evaluations", 200
    )
    initial_handoff_limits["symcc_next_generation_retention"] = getattr(
        args, "symcc_max_retained_seeds", args.symcc_max_total_seeds
    )
    result["symcc_seed_inputs"] = symcc_seeds
    result["llm_seed_handoff_selection_reason"] = handoff_metadata.get("selection_reason")
    result["symcc_seed_handoff_limits"] = initial_handoff_limits

    symcc_probe_json = output_dir / "symcc_probe_summary.json"
    symcc_probe_cmd = build_symcc_cmd(
        args=args,
        blocker_json_path=payload_path,
        work_dir=output_dir / "symcc_probe",
        seeds=symcc_seeds,
        fuzz_target=args.fuzz_file,
        target_name=args.target_name or Path(args.fuzz_file).stem,
        json_output_path=symcc_probe_json,
    )
    symcc_probe_result = run_program(symcc_probe_cmd, json_output_file=symcc_probe_json)
    result["used_symcc"] = True
    result["pipeline_methods"].append("symcc_probe_original_target")
    result["stages"]["symcc_probe_original_target"] = symcc_probe_result.get("parsed_output") or {
        "returncode": symcc_probe_result["returncode"],
        "stdout": symcc_probe_result["stdout"],
        "stderr": symcc_probe_result["stderr"],
    }
    if successful(symcc_probe_result.get("parsed_output")):
        result["success"] = True
        result["success_stage"] = "symcc_probe_original_target"
        result["attempt_result"] = "success"
        return result
    probe_failure_kind = get_symcc_failure_kind(result["stages"]["symcc_probe_original_target"])
    if probe_failure_kind == "oracle_unavailable":
        result["failure_stage"] = "symcc_probe_original_target"
        result["attempt_result"] = "pipeline_error"
        result["message"] = "SymCC coverage oracle was unavailable; this blocker remains retryable."
        return result

    fidelity_seed = resolve_harness_fidelity_seed(args, seeds)
    fidelity_feedback = ""
    previous_harness_file = ""
    parsed_symcc_harness: dict | None = None

    for harness_attempt in range(1, 3):
        suffix = "" if harness_attempt == 1 else f"_replan_{harness_attempt:02d}"
        generation_stage = f"symcc_harness_generation{suffix}"
        fidelity_stage = f"symcc_harness_fidelity_preflight{suffix}"
        libfuzzer_stage = f"libfuzzer_focused_pass{suffix}"
        symcc_stage = f"symcc_generated_harness{suffix}"

        symcc_harness_cmd = [
            sys.executable,
            str(HARNESS_GENERATOR),
            "--mode",
            "symcc",
            *build_context_args(args),
            *build_runtime_sanity_seed_args(symcc_seeds),
        ]
        if fidelity_feedback:
            symcc_harness_cmd.extend(["--fidelity-repair-feedback", fidelity_feedback])
        if previous_harness_file:
            symcc_harness_cmd.extend(["--previous-harness-file", previous_harness_file])
        if getattr(args, "output_root", None):
            symcc_harness_cmd.extend(["--output-root", str(Path(args.output_root) / "harness")])

        harness_stage_timeout = float(getattr(args, "llm_harness_stage_timeout_sec", 300) or 0)
        symcc_harness_gen = run_program(
            symcc_harness_cmd,
            timeout_sec=harness_stage_timeout if harness_stage_timeout > 0 else None,
            timeout_failure_kind="llm_timeout",
        )
        result["stages"][generation_stage] = symcc_harness_gen.get("parsed_output") or {
            "returncode": symcc_harness_gen["returncode"],
            "stdout": symcc_harness_gen["stdout"],
            "stderr": symcc_harness_gen["stderr"],
        }
        parsed_symcc_harness = symcc_harness_gen.get("parsed_output")
        if not successful(parsed_symcc_harness):
            result["failure_stage"] = generation_stage
            result["attempt_result"] = infer_attempt_result(result)
            return result

        simplified_target_name = parsed_symcc_harness.get("native_build_target_name")

        fidelity_json = output_dir / f"symcc_harness_fidelity_preflight{suffix}.json"
        fidelity_cmd = build_symcc_cmd(
            args=args,
            blocker_json_path=payload_path,
            work_dir=output_dir / f"symcc_harness_fidelity_preflight{suffix}",
            seeds=symcc_seeds,
            fuzz_target=parsed_symcc_harness["harness_path"],
            target_name=simplified_target_name,
            json_output_path=fidelity_json,
            fidelity_seed=fidelity_seed,
            fidelity_only=True,
        )
        fidelity_run = run_program(fidelity_cmd, json_output_file=fidelity_json)
        fidelity_payload = fidelity_run.get("parsed_output") or {
            "returncode": fidelity_run["returncode"],
            "stdout": fidelity_run["stdout"],
            "stderr": fidelity_run["stderr"],
        }
        result["stages"][fidelity_stage] = fidelity_payload
        result["pipeline_methods"].append(fidelity_stage)
        fidelity_failure = get_symcc_failure_kind(fidelity_payload)
        if not successful(fidelity_run.get("parsed_output")):
            result["generated_harness_retention"] = quarantine_unsolved_generated_harness(
                args=args,
                parsed_harness=parsed_symcc_harness,
                symcc_harness_stage=fidelity_payload,
                reason=fidelity_failure or "harness_fidelity_preflight_failed",
            )
            if fidelity_failure == "harness_seed_incompatible" and harness_attempt == 1:
                fidelity_feedback = get_harness_fidelity_feedback(fidelity_payload)
                previous_harness_file = str(parsed_symcc_harness.get("harness_path") or "")
                result["pipeline_methods"].append("symcc_harness_fidelity_replan")
                continue
            result["failure_stage"] = fidelity_stage
            if fidelity_failure == "harness_fidelity_unknown":
                result["message"] = (
                    "Generated-harness fidelity could not be measured after a deterministic coverage retry; "
                    "LLM repair was not attempted."
                )
            elif fidelity_failure == "harness_seed_incompatible":
                result["message"] = "Generated harness remained incompatible after one bounded fidelity replan."
            else:
                result["message"] = "Generated-harness fidelity preflight failed."
            result["attempt_result"] = infer_attempt_result(result)
            return result

        libfuzzer_pass_seconds = int(getattr(args, "libfuzzer_pass_seconds", 0) or 0)
        stage3b_seeds = list(symcc_seeds)
        if libfuzzer_pass_seconds > 0 and simplified_target_name:
            stage3b_result = run_libfuzzer_focused_pass(
                project_name=args.project_name,
                target_name=simplified_target_name,
                initial_seeds=symcc_seeds,
                fuzz_seconds=libfuzzer_pass_seconds,
            )
            result["stages"][libfuzzer_stage] = stage3b_result
            result["pipeline_methods"].append(libfuzzer_stage)
            corpus_dir = Path(stage3b_result["corpus_dir"])
            stage3b_seeds, handoff_limits = select_bounded_symcc_handoff_seeds(
                priority_seeds=symcc_seeds,
                corpus_dir=corpus_dir,
                max_total_seeds=initial_seed_limit,
            )
            handoff_limits["symcc_initial_frontier_cap"] = initial_seed_limit
            handoff_limits["symcc_candidate_eval_budget"] = getattr(
                args, "symcc_max_candidate_evaluations", 200
            )
            handoff_limits["symcc_next_generation_retention"] = getattr(
                args, "symcc_max_retained_seeds", args.symcc_max_total_seeds
            )
            stage3b_result["symcc_handoff"] = handoff_limits

        symcc_harness_json = output_dir / f"symcc_harness_summary{suffix}.json"
        symcc_harness_run_cmd = build_symcc_cmd(
            args=args,
            blocker_json_path=payload_path,
            work_dir=output_dir / f"symcc_harness_run{suffix}",
            seeds=stage3b_seeds,
            fuzz_target=parsed_symcc_harness["harness_path"],
            target_name=simplified_target_name,
            json_output_path=symcc_harness_json,
        )
        symcc_harness_run = run_program(symcc_harness_run_cmd, json_output_file=symcc_harness_json)
        result["pipeline_methods"].append(symcc_stage)
        stage_payload = symcc_harness_run.get("parsed_output") or {
            "returncode": symcc_harness_run["returncode"],
            "stdout": symcc_harness_run["stdout"],
            "stderr": symcc_harness_run["stderr"],
        }
        result["stages"][symcc_stage] = stage_payload
        if successful(symcc_harness_run.get("parsed_output")):
            result["success"] = True
            result["success_stage"] = symcc_stage
            result["attempt_result"] = "success"
            result["generated_harness_retention"] = {
                "retained": True,
                "quarantined": False,
                "reason": "blocked_side_line_reached",
                "target_name": simplified_target_name,
                "oss_fuzz_target_path": parsed_symcc_harness.get("native_build_target_path"),
                "harness_path": parsed_symcc_harness.get("harness_path"),
            }
            return result

        failure_kind = get_symcc_failure_kind(stage_payload)
        result["generated_harness_retention"] = quarantine_unsolved_generated_harness(
            args=args,
            parsed_harness=parsed_symcc_harness,
            symcc_harness_stage=stage_payload,
            reason=failure_kind or "symcc_generated_harness_did_not_reach_blocked_side",
        )
        if failure_kind == "harness_seed_incompatible" and harness_attempt == 1:
            fidelity_feedback = get_harness_fidelity_feedback(stage_payload)
            previous_harness_file = str(parsed_symcc_harness.get("harness_path") or "")
            result["pipeline_methods"].append("symcc_harness_fidelity_replan")
            continue

        result["failure_stage"] = symcc_stage
        if failure_kind == "harness_fidelity_unknown":
            result["message"] = (
                "Generated-harness fidelity could not be measured after a deterministic coverage retry; "
                "LLM repair was not attempted."
            )
        elif failure_kind == "harness_seed_incompatible":
            result["message"] = "Generated harness remained incompatible after one bounded fidelity replan."
        else:
            result["message"] = "Input-dependent pipeline ended after generated-harness SymCC fallback."
        result["attempt_result"] = infer_attempt_result(result)
        return result

    result["failure_stage"] = "symcc_generated_harness"
    result["attempt_result"] = "failed"
    return result


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the input-dependent blocker solver: generator -> SymCC probe -> SymCC harness."
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
    parser.add_argument("--header-file", default=None)
    parser.add_argument("--language", default=None)
    parser.add_argument("--target-name", default=None)
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
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--max-iterations", type=int, default=config.BLOCKER_MAX_ITERATIONS)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--seed-generator-timeout-sec", type=float, default=None)
    parser.add_argument(
        "--llm-seed-stage-timeout-sec",
        type=float,
        default=900,
        help="Hard wall-clock timeout for the complete LLM seed-generation stage.",
    )
    parser.add_argument(
        "--llm-harness-stage-timeout-sec",
        type=float,
        default=300,
        help="Hard wall-clock timeout for each complete LLM harness-generation attempt.",
    )
    parser.add_argument("--max-seed-size-bytes", type=int, default=None)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    parser.add_argument("--symcc-max-generations", type=int, default=3)
    parser.add_argument("--symcc-max-total-seeds", type=int, default=60)
    parser.add_argument("--symcc-max-candidate-evaluations", type=int, default=200)
    parser.add_argument("--symcc-max-retained-seeds", type=int, default=60)
    parser.add_argument("--symcc-initial-frontier-cap", type=int, default=30)
    parser.add_argument("--symcc-timeout-sec", type=int, default=15)
    parser.add_argument("--symcc-wall-clock-budget-sec", type=int, default=300)
    parser.add_argument("--libfuzzer-pass-seconds", type=int, default=60,
                        help="Seconds for Stage 3b libFuzzer focused pass on simplified harness. 0 to disable.")
    parser.add_argument("--llvm-profdata", default=DEFAULT_LLVM_PROFDATA)
    parser.add_argument("--llvm-cov", default=DEFAULT_LLVM_COV)
    parser.add_argument("--keep-coverage-reports", action="store_true")
    parser.add_argument("--output-root", default=None,
                        help="Root directory under which output dirs are created. "
                             "Defaults to generated_symbolic_runs/.")
    parser.add_argument("--log-dir", default=None,
                        help="Directory for child session logs. Defaults to logs/ in child tools when omitted.")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()

    try:
        result = run_input_dependent_solver(args)
        summary = build_solver_summary(args, result)
        output_dir = Path(result["output_dir"])
        summary_path = output_dir / "summary.json"
        write_json(summary_path, summary)
        result["summary_path"] = str(summary_path)
        logging.info("Wrote input-dependent summary to %s", summary_path)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Dependent pipeline failed: %s", exc, exc_info=True)
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
