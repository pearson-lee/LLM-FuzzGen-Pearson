#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import subprocess
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

SEED_GENERATOR = MODULE_ROOT / "seeds_generation.py"
HARNESS_GENERATOR = MODULE_ROOT / "harness_generator.py"
SYMCC_THEN_KLEE = MODULE_ROOT / "symcc_then_klee.py"
OUTPUT_ROOT = MODULE_ROOT / "generated_symbolic_runs"


def sanitize_name(value: str) -> str:
    import re

    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


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
        "fuzz_file": args.fuzz_file,
        "seeds": seeds,
    }


def build_symcc_cmd(
    args: argparse.Namespace,
    blocker_json_path: Path,
    work_dir: Path,
    seeds: list[str],
    fuzz_target: str | None,
    json_output_path: Path,
) -> list[str]:
    cmd = [
        sys.executable,
        str(SYMCC_THEN_KLEE),
        "--blocker-json-file",
        str(blocker_json_path),
        "--project-name",
        args.project_name,
        "--branch-source",
        args.source_file,
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
        "--json-output-file",
        str(json_output_path),
    ]
    if fuzz_target:
        cmd.extend(["--fuzz-target", fuzz_target])
    for seed in seeds:
        cmd.extend(["--seed", seed])
    if args.keep_coverage_reports:
        cmd.append("--keep-coverage-reports")
    return cmd


def build_klee_cmd(
    args: argparse.Namespace,
    blocker_json_path: Path,
    work_dir: Path,
    harness_path: str,
    extract_object: str,
    json_output_path: Path,
) -> list[str]:
    output_seed = work_dir / "klee_fallback_seed.bin"
    cmd = [
        sys.executable,
        str(SYMCC_THEN_KLEE),
        "--skip-symcc",
        "--blocker-json-file",
        str(blocker_json_path),
        "--project-name",
        args.project_name,
        "--branch-source",
        args.source_file,
        "--branch-line",
        str(args.branch_line_number),
        "--blocked-side-line",
        str(args.blocked_side_line_number),
        "--work-dir",
        str(work_dir),
        "--klee-harness",
        harness_path,
        "--klee-max-time",
        str(args.klee_max_time),
        "--klee-max-tests",
        str(args.klee_max_tests),
        "--klee-output-seed",
        str(output_seed),
        "--klee-extract-object",
        extract_object,
        "--json-output-file",
        str(json_output_path),
    ]
    return cmd


def successful(parsed_output: dict | None) -> bool:
    return bool(parsed_output and parsed_output.get("success"))


def run_dependent_pipeline(args: argparse.Namespace) -> dict:
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
        "used_klee": False,
        "output_dir": str(output_dir),
        "seed_inputs": seeds,
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
    if successful(llm_seed_result.get("parsed_output")):
        result["success"] = True
        result["success_stage"] = "llm_seed_generator"
        return result

    symcc_probe_json = output_dir / "symcc_probe_summary.json"
    symcc_probe_cmd = build_symcc_cmd(
        args=args,
        blocker_json_path=payload_path,
        work_dir=output_dir / "symcc_probe",
        seeds=seeds,
        fuzz_target=args.fuzz_file,
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
        return result

    symcc_harness_json = output_dir / "symcc_harness_summary.json"
    symcc_harness_run_cmd = build_symcc_cmd(
        args=args,
        blocker_json_path=payload_path,
        work_dir=output_dir / "symcc_harness_run",
        seeds=seeds,
        fuzz_target=parsed_symcc_harness["harness_path"],
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
        return result

    klee_harness_cmd = [
        sys.executable,
        str(HARNESS_GENERATOR),
        "--mode",
        "klee",
        *build_context_args(args),
    ]
    klee_harness_gen = run_program(klee_harness_cmd)
    result["stages"]["klee_harness_generation"] = klee_harness_gen.get("parsed_output") or {
        "returncode": klee_harness_gen["returncode"],
        "stdout": klee_harness_gen["stdout"],
        "stderr": klee_harness_gen["stderr"],
    }
    parsed_klee_harness = klee_harness_gen.get("parsed_output")
    if not successful(parsed_klee_harness):
        result["failure_stage"] = "klee_harness_generation"
        return result

    klee_json = output_dir / "klee_summary.json"
    klee_run_cmd = build_klee_cmd(
        args=args,
        blocker_json_path=payload_path,
        work_dir=output_dir / "klee_run",
        harness_path=parsed_klee_harness["harness_path"],
        extract_object=parsed_klee_harness.get("klee_extract_object", "input"),
        json_output_path=klee_json,
    )
    klee_run = run_program(klee_run_cmd, json_output_file=klee_json)
    result["used_klee"] = True
    result["pipeline_methods"].append("klee_generated_harness")
    result["stages"]["klee_generated_harness"] = klee_run.get("parsed_output") or {
        "returncode": klee_run["returncode"],
        "stdout": klee_run["stdout"],
        "stderr": klee_run["stderr"],
    }
    if successful(klee_run.get("parsed_output")):
        result["success"] = True
        result["success_stage"] = "klee_generated_harness"
        return result

    result["failure_stage"] = "klee_generated_harness"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the input-dependent blocker pipeline: generator -> SymCC probe -> SymCC harness -> KLEE harness."
    )
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
    parser.add_argument("--symcc-max-generations", type=int, default=1)
    parser.add_argument("--symcc-max-total-seeds", type=int, default=20)
    parser.add_argument("--symcc-timeout-sec", type=int, default=10)
    parser.add_argument("--klee-max-time", type=int, default=60)
    parser.add_argument("--klee-max-tests", type=int, default=10)
    parser.add_argument("--keep-coverage-reports", action="store_true")
    args = parser.parse_args()

    try:
        result = run_dependent_pipeline(args)
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
