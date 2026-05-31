#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from external.oss_fuzz import OSSFuzz  # noqa: E402

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
        "stage_statuses": stage_statuses,
        "stages": stages,
    }


def run_program(cmd: list[str], *, json_output_file: Path | None = None) -> dict:
    logging.info("Dispatching: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    parsed: dict | None = None
    if json_output_file and json_output_file.exists():
        try:
            parsed = json.loads(json_output_file.read_text(encoding="utf-8"))
        except Exception:
            parsed = None
    if parsed is None:
        text = (result.stdout or "").strip()
        if text:
            try:
                parsed_json = json.loads(text)
                if isinstance(parsed_json, dict):
                    parsed = parsed_json
            except Exception:
                parsed = None
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "parsed_output": parsed,
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


def build_symcc_cmd(
    args: argparse.Namespace,
    blocker_json_path: Path,
    work_dir: Path,
    seeds: list[str],
    fuzz_target: str | None,
    target_name: str | None,
    json_output_path: Path,
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
    if args.keep_coverage_reports:
        cmd.append("--keep-coverage-reports")
    if getattr(args, "llvm_profdata", None):
        cmd.extend(["--llvm-profdata", args.llvm_profdata])
    if getattr(args, "llvm_cov", None):
        cmd.extend(["--llvm-cov", args.llvm_cov])
    return cmd


def successful(parsed_output: dict | None) -> bool:
    return bool(parsed_output and parsed_output.get("success"))


def infer_attempt_result(result: dict) -> str:
    if result.get("success"):
        return "success"

    failure_stage = str(result.get("failure_stage") or "")
    stages = result.get("stages") if isinstance(result.get("stages"), dict) else {}
    stage_payload = stages.get(failure_stage) if failure_stage else None
    if isinstance(stage_payload, dict) and stage_payload.get("attempt_result") == "llm_error":
        return "llm_error"
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
    output_dir = OUTPUT_ROOT / f"{safe_project}_{safe_function}_{timestamp}"
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
        "stages": {},
    }

    llm_seed_cmd = [
        sys.executable,
        str(SEED_GENERATOR),
        *build_context_args(args),
        "--max-iterations",
        str(args.max_iterations),
        "--fuzz-seconds",
        str(args.fuzz_seconds),
    ]
    if args.reset_corpus_per_iteration:
        llm_seed_cmd.append("--reset-corpus-per-iteration")
    llm_seed_result = run_program(llm_seed_cmd)
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

    symcc_seeds, handoff_metadata = choose_symcc_seed_inputs(seeds, parsed_llm_seed)
    result["symcc_seed_inputs"] = symcc_seeds
    result["llm_seed_handoff_selection_reason"] = handoff_metadata.get("selection_reason")

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

    symcc_harness_cmd = [
        sys.executable,
        str(HARNESS_GENERATOR),
        "--mode",
        "symcc",
        *build_context_args(args),
    ]
    symcc_harness_gen = run_program(symcc_harness_cmd)
    result["stages"]["symcc_harness_generation"] = symcc_harness_gen.get("parsed_output") or {
        "returncode": symcc_harness_gen["returncode"],
        "stdout": symcc_harness_gen["stdout"],
        "stderr": symcc_harness_gen["stderr"],
    }
    parsed_symcc_harness = symcc_harness_gen.get("parsed_output")
    if not successful(parsed_symcc_harness):
        result["failure_stage"] = "symcc_harness_generation"
        result["attempt_result"] = infer_attempt_result(result)
        return result

    simplified_target_name = parsed_symcc_harness.get("native_build_target_name")

    # Stage 3b: Run a short libFuzzer pass on the simplified harness to enrich the
    # seed corpus before handing off to SymCC (Stage 3c). This is best-effort —
    # failures are logged but do not abort the pipeline.
    libfuzzer_pass_seconds = int(getattr(args, "libfuzzer_pass_seconds", 0) or 0)
    stage3b_seeds = list(symcc_seeds)
    if libfuzzer_pass_seconds > 0 and simplified_target_name:
        stage3b_result = run_libfuzzer_focused_pass(
            project_name=args.project_name,
            target_name=simplified_target_name,
            initial_seeds=symcc_seeds,
            fuzz_seconds=libfuzzer_pass_seconds,
        )
        result["stages"]["libfuzzer_focused_pass"] = stage3b_result
        result["pipeline_methods"].append("libfuzzer_focused_pass")
        # Use the enriched corpus dir as additional seeds for Stage 3c.
        corpus_dir = Path(stage3b_result["corpus_dir"])
        if corpus_dir.is_dir():
            enriched = [str(p) for p in sorted(corpus_dir.iterdir()) if p.is_file()]
            seen = set(stage3b_seeds)
            for s in enriched:
                if s not in seen:
                    stage3b_seeds.append(s)
                    seen.add(s)
            logging.info(
                "Stage 3b: enriched seed list from %d to %d for Stage 3c",
                len(symcc_seeds),
                len(stage3b_seeds),
            )

    symcc_harness_json = output_dir / "symcc_harness_summary.json"
    symcc_harness_run_cmd = build_symcc_cmd(
        args=args,
        blocker_json_path=payload_path,
        work_dir=output_dir / "symcc_harness_run",
        seeds=stage3b_seeds,
        fuzz_target=parsed_symcc_harness["harness_path"],
        target_name=simplified_target_name,
        json_output_path=symcc_harness_json,
    )
    symcc_harness_run = run_program(symcc_harness_run_cmd, json_output_file=symcc_harness_json)
    result["pipeline_methods"].append("symcc_generated_harness")
    result["stages"]["symcc_generated_harness"] = symcc_harness_run.get("parsed_output") or {
        "returncode": symcc_harness_run["returncode"],
        "stdout": symcc_harness_run["stdout"],
        "stderr": symcc_harness_run["stderr"],
    }
    if successful(symcc_harness_run.get("parsed_output")):
        result["success"] = True
        result["success_stage"] = "symcc_generated_harness"
        result["attempt_result"] = "success"
        return result

    result["failure_stage"] = "symcc_generated_harness"
    result["message"] = "Input-dependent main pipeline ended after LLM seed generation and SymCC fallback."
    result["attempt_result"] = infer_attempt_result(result)
    return result


def main() -> None:
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
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    parser.add_argument("--symcc-max-generations", type=int, default=3)
    parser.add_argument("--symcc-max-total-seeds", type=int, default=60)
    parser.add_argument("--symcc-timeout-sec", type=int, default=15)
    parser.add_argument("--symcc-wall-clock-budget-sec", type=int, default=300)
    parser.add_argument("--libfuzzer-pass-seconds", type=int, default=60,
                        help="Seconds for Stage 3b libFuzzer focused pass on simplified harness. 0 to disable.")
    parser.add_argument("--llvm-profdata", default=DEFAULT_LLVM_PROFDATA)
    parser.add_argument("--llvm-cov", default=DEFAULT_LLVM_COV)
    parser.add_argument("--keep-coverage-reports", action="store_true")
    args = parser.parse_args()

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
