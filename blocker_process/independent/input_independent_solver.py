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
from dataclasses import dataclass
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import config.config as config
from blocker_process.coverage_utils import get_line_execution_count
from blocker_process.blocker_source_evidence import collect_symbol_evidence, render_symbol_evidence_for_prompt
from blocker_process.target_quality_analyzer import analyze_target_quality
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient, new_thread_id
from prompts import prompt_generator

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

OUTPUT_ROOT = MODULE_ROOT / "generated_targets"
_SESSION_FILE_HANDLER_FLAG = "_llm_fuzzgen_session_file_handler"
_STRATEGY_CONTRACT_COMMENT_RE = re.compile(
    r"/\*\s*BLOCKER_STRATEGY_CONTRACT\b(.*?)\*/",
    re.DOTALL,
)
_STRATEGY_CONTRACT_END_RE = re.compile(
    r"^\s*END_[A-Z_]*STRATEGY_CONTRACT\s*$",
    re.MULTILINE,
)
_STRATEGY_CONTRACT_FIELDS = (
    "required_state",
    "state_constructor",
    "trigger_api",
    "preserved_invariants",
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_C_NON_CODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
    re.DOTALL,
)
_NON_CALL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof"}


@dataclass(frozen=True)
class StrategyContractParseResult:
    valid: bool
    contract: str
    fields: dict[str, str]
    error: str = ""


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


def strip_standalone_markdown_fences(text: str) -> str:
    """Remove Markdown fence lines without changing the generated C/C++ body."""
    if not text:
        return text
    fence_re = re.compile(r"^[ \t]*```(?:c|cc|cpp|cxx|c\+\+|h|hpp)?[ \t]*$")
    return "".join(
        line
        for line in text.splitlines(keepends=True)
        if not fence_re.fullmatch(line.rstrip("\r\n"))
    )


def parse_strategy_contract(code: str) -> StrategyContractParseResult:
    matches = list(_STRATEGY_CONTRACT_COMMENT_RE.finditer(code or ""))
    if not matches:
        return StrategyContractParseResult(False, "", {}, "Missing BLOCKER_STRATEGY_CONTRACT comment.")
    if len(matches) > 1:
        return StrategyContractParseResult(
            False,
            "",
            {},
            f"Expected one BLOCKER_STRATEGY_CONTRACT comment, found {len(matches)}.",
        )

    match = matches[0]
    body = _STRATEGY_CONTRACT_END_RE.sub("", match.group(1)).strip()
    field_names = "|".join(re.escape(field) for field in _STRATEGY_CONTRACT_FIELDS)
    field_re = re.compile(
        rf"^\s*({field_names})\s*:\s*(.*?)(?=^\s*(?:{field_names})\s*:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    matches = list(field_re.finditer(body))
    fields: dict[str, str] = {}
    duplicates: list[str] = []
    for field_match in matches:
        name = field_match.group(1)
        value = " ".join(field_match.group(2).split())
        if name in fields:
            duplicates.append(name)
        else:
            fields[name] = value

    missing = [field for field in _STRATEGY_CONTRACT_FIELDS if not fields.get(field)]
    errors: list[str] = []
    if missing:
        errors.append(f"Missing or empty fields: {', '.join(missing)}.")
    if duplicates:
        errors.append(f"Duplicate fields: {', '.join(sorted(set(duplicates)))}.")
    if errors:
        return StrategyContractParseResult(False, "", fields, " ".join(errors))

    contract = "\n".join(f"{field}: {fields[field]}" for field in _STRATEGY_CONTRACT_FIELDS)
    return StrategyContractParseResult(True, contract, fields)


def extract_strategy_contract(code: str) -> str:
    result = parse_strategy_contract(code)
    return result.contract if result.valid else ""


def extract_strategy_contract_comment(code: str) -> str:
    matches = _STRATEGY_CONTRACT_COMMENT_RE.findall(code or "")
    if not matches:
        return "N/A"
    return "\n\n".join(
        "/* BLOCKER_STRATEGY_CONTRACT\n"
        f"{body.strip()}\n"
        "*/"
        for body in matches
    )


def apply_strategy_contract(code: str, strategy_contract: str) -> str:
    parsed = parse_strategy_contract(
        "/* BLOCKER_STRATEGY_CONTRACT\n"
        f"{strategy_contract or ''}\n"
        "END_BLOCKER_STRATEGY_CONTRACT */"
    )
    if not parsed.valid:
        raise ValueError(f"Invalid Strategy Contract: {parsed.error}")
    contract = parsed.contract
    rendered = (
        "/* BLOCKER_STRATEGY_CONTRACT\n"
        f"{contract}\n"
        "END_BLOCKER_STRATEGY_CONTRACT */"
    )
    implementation = _STRATEGY_CONTRACT_COMMENT_RE.sub("", code or "").lstrip()
    return f"{rendered}\n\n{implementation}"


def strategy_contract_anchors(strategy_contract: str, code: str) -> list[str]:
    parsed = parse_strategy_contract(
        "/* BLOCKER_STRATEGY_CONTRACT\n"
        f"{strategy_contract}\n"
        "END_BLOCKER_STRATEGY_CONTRACT */"
    )
    if not parsed.valid:
        return []

    contract_identifiers = set(
        re.findall(
            r"\b[A-Za-z_][A-Za-z0-9_]*\b",
            f"{parsed.fields['state_constructor']} {parsed.fields['trigger_api']}",
        )
    )
    implementation_code = _C_NON_CODE_RE.sub(" ", code or "")
    code_calls = {
        name for name in _CALL_NAME_RE.findall(implementation_code) if name not in _NON_CALL_KEYWORDS
    }
    return sorted(contract_identifiers & code_calls)


def validate_strategy_preservation(code: str, anchors: list[str]) -> tuple[bool, list[str]]:
    implementation_code = _C_NON_CODE_RE.sub(" ", code or "")
    code_calls = {
        name for name in _CALL_NAME_RE.findall(implementation_code) if name not in _NON_CALL_KEYWORDS
    }
    missing = sorted(anchor for anchor in anchors if anchor not in code_calls)
    return not missing, missing


def diagnose_runtime_evaluation(evaluation: dict | None) -> str:
    evaluation = evaluation or {}
    if not evaluation.get("success"):
        return "coverage_error"
    if int(evaluation.get("blocked_side_hit_count", 0)) > 0:
        return "success"
    if int(evaluation.get("branch_hit_count", 0)) > 0:
        return "predicate_state_failure"
    return "route_failure"


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


def setup_file_logging(func_name: str, log_dir: str | Path | None = None) -> None:
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}_input_independent_solver.log"

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
    _output_root = Path(args.output_root) if getattr(args, "output_root", None) else OUTPUT_ROOT
    out_dir = _output_root / f"{safe_project}_{safe_function}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def collect_prompt_context(args: argparse.Namespace, oss_fuzz: OSSFuzz) -> dict:
    fuzz_target_code = clip_text(read_optional_file(args.fuzz_file), max_chars=20000)
    branch_window = clip_text(extract_source_window_from_file(args.source_file, int(args.branch_line_number)), max_chars=4000)
    blocked_window = clip_text(
        extract_source_window_from_file(args.source_file, int(args.blocked_side_line_number)),
        max_chars=4000,
    )
    symbol_evidence_data = collect_symbol_evidence(
        project_name=args.project_name,
        function_name=args.function_name,
        source_file=args.source_file,
        header_file=args.header_file,
        blocker_line_code=getattr(args, "blocker_line_code", "N/A") or "N/A",
        blocked_side_line_code=getattr(args, "blocked_side_line_code", "N/A") or "N/A",
        branch_window=branch_window,
        blocked_window=blocked_window,
    )
    has_symbol_evidence = bool(symbol_evidence_data.get("entries"))
    symbol_evidence = clip_text(render_symbol_evidence_for_prompt(symbol_evidence_data), max_chars=28000)
    if has_symbol_evidence:
        source_code = "N/A: replaced by targeted symbol evidence."
        header_code = "N/A: replaced by targeted symbol evidence."
    else:
        source_code = clip_text(read_optional_file(args.source_file), max_chars=4000)
        header_code = clip_text(read_optional_file(args.header_file), max_chars=4000)
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
        "symbol_evidence": symbol_evidence,
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
        "blocker_call_sites": clip_text(
            resolve_text(
                getattr(args, "blocker_call_sites_file", None),
                getattr(args, "blocker_call_sites", None),
            ),
            max_chars=10000,
        ),
        "triggering_input_path": triggering_input_path,
        "triggering_input_preview": triggering_input_preview,
        "_symbol_evidence_data": symbol_evidence_data,
    }


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_best_iteration_code(best_iteration: dict | None) -> str:
    if not isinstance(best_iteration, dict):
        return ""
    build = best_iteration.get("build") if isinstance(best_iteration.get("build"), dict) else {}
    if build.get("code"):
        return build["code"]
    if best_iteration.get("target_path"):
        return load_text(Path(best_iteration["target_path"]))
    return ""


def attach_target_quality_report(
    result: dict,
    *,
    output_dir: Path,
    symbol_evidence_data: dict | None,
) -> dict:
    best_iteration = result.get("best_iteration")
    if not isinstance(best_iteration, dict):
        return result

    code = _read_best_iteration_code(best_iteration)
    evaluation = best_iteration.get("evaluation") if isinstance(best_iteration.get("evaluation"), dict) else {}
    build = best_iteration.get("build") if isinstance(best_iteration.get("build"), dict) else {}
    strategy_contract = (
        best_iteration.get("strategy_contract")
        or evaluation.get("strategy_contract")
        or build.get("strategy_contract")
        or ""
    )
    quality_report = analyze_target_quality(
        code=code,
        evaluation=evaluation,
        strategy_contract=strategy_contract,
        symbol_evidence=symbol_evidence_data or {},
    )
    quality_path = output_dir / "target_quality_report.json"
    write_json(quality_path, quality_report)
    result["target_quality_report"] = quality_report
    result["target_quality_report_path"] = str(quality_path)
    best_iteration["target_quality_report"] = quality_report
    result["best_iteration"] = best_iteration
    return result


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
        "attempt_result": result.get("attempt_result", "success" if result.get("success") else "failed"),
        "pipeline_methods": result.get("pipeline_methods", []),
        "iteration_budget": result.get("iteration_budget"),
        "output_dir": result.get("output_dir"),
        "symbol_evidence_path": result.get("symbol_evidence_path"),
        "symbol_evidence_summary": result.get("symbol_evidence_summary"),
        "target_quality_report_path": result.get("target_quality_report_path"),
        "target_quality_report": result.get("target_quality_report"),
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
            "target_quality_report": best_iteration.get("target_quality_report"),
        }
        if best_iteration
        else None,
        "reference_guided_iteration_count": len(iterations),
        "dedicated_generation_iteration_count": len(fallback_iterations),
        "reference_guided_stalled_out": result.get("reference_guided_stalled_out"),
        "dedicated_generation_stalled_out": result.get("dedicated_generation_stalled_out"),
        "reference_guided_strategy_replan_count": result.get("reference_guided_strategy_replan_count"),
        "dedicated_generation_strategy_replan_count": result.get("dedicated_generation_strategy_replan_count"),
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
    strategy_contract: str,
    preserve_seed_compatibility: bool,
) -> str:
    return prompt_generator.blocker_compile_fix_prompt(
        project_name=project_name,
        language=language,
        compile_error=compile_error,
        previous_code=previous_code,
        iteration_feedback=iteration_feedback,
        strategy_contract=strategy_contract,
        preserve_seed_compatibility=preserve_seed_compatibility,
    )


def classify_compile_api_diagnostics(error: str) -> list[dict[str, str]]:
    diagnostics: list[dict[str, str]] = []
    patterns = (
        ("symbol_not_found", r"(?:undeclared function|undeclared identifier)\s+['‘`]([^'’`]+)['’`]"),
        ("symbol_not_found", r"implicit declaration of function\s+['‘`]([^'’`]+)['’`]"),
        ("undefined_link", r"undefined reference to\s+['‘`]([^'’`]+)['’`]"),
        ("wrong_signature", r"(?:too few|too many) arguments to function call[^\n]*?['‘`]([^'’`]+)['’`]"),
    )
    seen: set[tuple[str, str]] = set()
    for kind, pattern in patterns:
        for match in re.finditer(pattern, error or "", re.IGNORECASE):
            symbol = match.group(1).strip()
            key = (kind, symbol)
            if not symbol or key in seen:
                continue
            seen.add(key)
            diagnostics.append({"kind": kind, "symbol": symbol})
    if not diagnostics and re.search(r"incompatible (?:function|pointer|integer|type)|no matching function", error or "", re.IGNORECASE):
        diagnostics.append({"kind": "wrong_signature", "symbol": "unknown"})
    return diagnostics


def repair_strategy_contract(
    *,
    llm: LLMClient,
    code: str,
    parse_error: str,
    iteration_dir: Path,
    thread_id: int,
) -> StrategyContractParseResult:
    prompt = prompt_generator.blocker_contract_fix_prompt(
        contract_error=parse_error,
        malformed_contract=extract_strategy_contract_comment(code),
    )
    write_text(iteration_dir / "contract_repair_prompt.txt", prompt)
    repaired_comment = llm.generate(prompt, thread_id=thread_id) or ""
    write_text(iteration_dir / "contract_repair_response.txt", repaired_comment)
    return parse_strategy_contract(repaired_comment)


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
- Runtime diagnosis: {previous_evaluation.get('runtime_diagnosis', 'N/A')}
- Notes: {previous_evaluation.get('note', 'N/A')}

Strategy Contract from the previous candidate:
```text
{previous_evaluation.get('strategy_contract', 'N/A')}
```

Previous candidate code:
```cpp
{previous_code or 'N/A'}
```

Compiler API diagnostics from the previous iteration:
```text
{json.dumps(previous_evaluation.get('compile_api_diagnostics', []), ensure_ascii=False)}
```

Interpret these diagnostics narrowly: `symbol_not_found` is negative evidence for that spelling in the current build; `wrong_signature` means the API may exist but was called incorrectly; `undefined_link` means declaration/implementation linkage must be checked. Do not convert every compile failure into proof that an API does not exist.

This is bounded strategy replanning, not compile repair:
- `route_failure`: redesign the API route or prerequisite setup so the branch line is reached.
- `predicate_state_failure`: preserve the working route, but redesign the constructor/setter sequence so the blocked predicate state changes.
- `coverage_error`: fix the target/evaluation failure before drawing a semantic conclusion.
- `contract_parse_error`: emit a complete canonical Strategy Contract before attempting compilation.
- `strategy_replan_required`: keep the required state and trigger API, but replace the non-compiling constructor/API sequence with a different supported strategy.

Revise the target based on this diagnosis. Do not repeat a candidate that keeps the same blocker coverage behavior.
"""
    return base_prompt + appended


def score_evaluation(evaluation: dict | None) -> tuple[int, int, int]:
    evaluation = evaluation or {}
    return (
        int(bool(evaluation.get("blocked_side_line_reached"))),
        int(evaluation.get("blocked_side_hit_count", 0)),
        int(evaluation.get("branch_hit_count", 0)),
    )


def should_replace_best(candidate_score: tuple[int, int, int], best_attempt: dict | None) -> bool:
    if best_attempt is None:
        return True
    return candidate_score > tuple(best_attempt.get("score", (0, 0, 0)))


def delete_generated_target(oss_fuzz: OSSFuzz, project_name: str, target_path: str | None) -> None:
    if not target_path:
        return
    stem = Path(target_path).stem
    if stem:
        oss_fuzz.remove_target(project_name, stem)


def summarize_compile_failure(iteration_index: int, build_info: dict) -> str:
    error = (build_info.get("error") or "Unknown compile error.").strip()
    compile_attempts = build_info.get("compile_attempts", config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS)
    return (
        f"Iteration {iteration_index} failed to compile after {compile_attempts} compile-fix attempts. "
        f"Last compile error: {error}"
    )


def summarize_strategy_generation_failure(iteration_index: int, build_info: dict) -> str:
    failure_kind = build_info.get("failure_kind", "strategy_replan_required")
    reason = (
        build_info.get("strategy_preservation_error")
        or build_info.get("contract_parse_error")
        or build_info.get("error")
        or "The candidate could not preserve a valid Strategy Contract."
    )
    return f"Iteration {iteration_index} requires strategy replanning ({failure_kind}): {reason}"


def summarize_coverage_feedback(iteration_index: int, evaluation: dict, became_best: bool) -> str:
    branch_hit = evaluation.get("branch_hit_count_raw", "0")
    blocked_hit = evaluation.get("blocked_side_hit_count_raw", "0")
    diagnosis = evaluation.get("runtime_diagnosis") or diagnose_runtime_evaluation(evaluation)
    if diagnosis == "predicate_state_failure":
        action = (
            "The route reaches the blocker, but the required predicate state was not established. "
            "Replan the state constructor/setter sequence; do not merely increase fuzzing time."
        )
    elif diagnosis == "route_failure":
        action = "The branch was not reached. Replan the API route or prerequisite object setup."
    else:
        action = "Coverage evaluation failed; fix the evaluation or target execution problem first."
    status = "This candidate is the new best-so-far compiled version." if became_best else (
        "This candidate compiled but did not improve over the current best-so-far version."
    )
    return (
        f"Iteration {iteration_index} compiled successfully but did not reach the blocked-side line. "
        f"Branch hit count: {branch_hit}. Blocked-side hit count: {blocked_hit}. "
        f"Runtime diagnosis: {diagnosis}. {action} {status}"
    )


def build_ref_handoff_summary(reference_guided_result: dict, baseline_evaluation: dict | None) -> str:
    iterations = reference_guided_result.get("iterations", []) if isinstance(reference_guided_result, dict) else []
    if not iterations:
        return "Reference-guided stage produced no iterations."

    best_attempt = reference_guided_result.get("best_attempt") if isinstance(reference_guided_result, dict) else None
    best_evaluation = {}
    if isinstance(best_attempt, dict):
        best_evaluation = best_attempt.get("evaluation", {}) or {}
    if not best_evaluation:
        best_evaluation = dict(baseline_evaluation or {})

    compile_failures = 0
    coverage_failures = 0
    last_failure = "N/A"
    for item in iterations:
        evaluation = item.get("evaluation")
        if isinstance(evaluation, dict):
            if not evaluation.get("blocked_side_line_reached"):
                coverage_failures += 1
        else:
            compile_failures += 1
        if item.get("last_failure_summary"):
            last_failure = item["last_failure_summary"]
        elif item.get("note"):
            last_failure = item["note"]

    return (
        "Reference-guided stage failed to cross the blocked-side line.\n"
        f"- Iterations tried: {len(iterations)}\n"
        f"- Compile-failure iterations: {compile_failures}\n"
        f"- Coverage-failure iterations: {coverage_failures}\n"
        f"- Best branch hit count: {best_evaluation.get('branch_hit_count_raw', '0')}\n"
        f"- Best blocked-side hit count: {best_evaluation.get('blocked_side_hit_count_raw', '0')}\n"
        f"- Best blocked-side reached: {best_evaluation.get('blocked_side_line_reached', False)}\n"
        f"- Last observed failure pattern: {last_failure}"
    )


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
    thread_id = new_thread_id(
        "input_independent_target_generation",
        project_name,
        stem_prefix,
        iteration_dir,
    )
    logging.info("Input-independent target generation LLM thread_id=%s", thread_id)
    current_prompt = prompt
    previous_code = ""
    strategy_contract = ""
    strategy_contract_explicit = False
    strategy_anchors: list[str] = []
    contract_repair_attempts = 0
    last_build_error = ""
    saw_nonempty_code = False
    compile_api_diagnostics: list[dict[str, str]] = []

    for attempt in range(1, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        logging.info("Compilation-oriented generation attempt %d/%d", attempt, config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS)
        write_text(iteration_dir / f"prompt_attempt_{attempt:02d}.txt", current_prompt)
        code = strip_standalone_markdown_fences(
            llm.generate(current_prompt, thread_id=thread_id) or ""
        )
        if not code:
            current_prompt = "Return a full fuzz target in a single <fuzz_target> block."
            continue

        saw_nonempty_code = True
        contract_result = parse_strategy_contract(code)
        if not strategy_contract:
            if not contract_result.valid:
                contract_repair_attempts = 1
                contract_result = repair_strategy_contract(
                    llm=llm,
                    code=code,
                    parse_error=contract_result.error,
                    iteration_dir=iteration_dir,
                    thread_id=thread_id,
                )
                if not contract_result.valid:
                    return {
                        "success": False,
                        "error": "Strategy Contract could not be parsed after one format-repair attempt.",
                        "last_code": code,
                        "compile_attempts": attempt - 1,
                        "contract_repair_attempts": contract_repair_attempts,
                        "contract_parse_error": contract_result.error,
                        "strategy_contract": "",
                        "strategy_contract_explicit": False,
                        "failure_kind": "contract_parse_error",
                    }
            strategy_contract = contract_result.contract
            strategy_contract_explicit = True
            code = apply_strategy_contract(code, strategy_contract)
            strategy_anchors = strategy_contract_anchors(strategy_contract, code)
        else:
            if not contract_result.valid:
                return {
                    "success": False,
                    "error": "Compile repair did not preserve a valid Strategy Contract.",
                    "last_code": code,
                    "compile_attempts": attempt - 1,
                    "contract_repair_attempts": contract_repair_attempts,
                    "contract_parse_error": contract_result.error,
                    "strategy_contract": strategy_contract,
                    "strategy_contract_explicit": True,
                    "strategy_anchors": strategy_anchors,
                    "strategy_preservation_error": contract_result.error,
                    "failure_kind": "strategy_replan_required",
                }
            code = apply_strategy_contract(code, strategy_contract)
            preserved, missing_anchors = validate_strategy_preservation(code, strategy_anchors)
            if not preserved:
                return {
                    "success": False,
                    "error": "Compile repair removed blocker-strategy API anchors.",
                    "last_code": code,
                    "compile_attempts": attempt - 1,
                    "contract_repair_attempts": contract_repair_attempts,
                    "strategy_contract": strategy_contract,
                    "strategy_contract_explicit": True,
                    "strategy_anchors": strategy_anchors,
                    "missing_strategy_anchors": missing_anchors,
                    "strategy_preservation_error": (
                        "Compile repair removed required constructor/trigger calls: "
                        f"{', '.join(missing_anchors)}."
                    ),
                    "failure_kind": "strategy_replan_required",
                }
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
                "strategy_contract": strategy_contract,
                "strategy_contract_explicit": strategy_contract_explicit,
                "strategy_anchors": strategy_anchors,
                "contract_repair_attempts": contract_repair_attempts,
                "compile_api_diagnostics": compile_api_diagnostics,
            }

        logging.warning("Candidate build failed on attempt %d: %s", attempt, build_result.error)
        last_build_error = build_result.error or ""
        for diagnostic in classify_compile_api_diagnostics(last_build_error):
            if diagnostic not in compile_api_diagnostics:
                compile_api_diagnostics.append(diagnostic)
        oss_fuzz.remove_target(project_name, target_path.stem)
        current_prompt = format_refinement_feedback(
            project_name=project_name,
            language=oss_fuzz.proj_lang(project_name) or "unknown",
            compile_error=build_result.error,
            previous_code=code,
            iteration_feedback=iteration_feedback,
            strategy_contract=strategy_contract,
            preserve_seed_compatibility=preserve_seed_compatibility,
        )

    return {
        "success": False,
        "error": last_build_error or "Failed to generate a compiling fuzz target.",
        "last_code": previous_code,
        "compile_attempts": config.FUZZ_TARGET_COMPILER_MAX_ATTEMPTS,
        "strategy_contract": strategy_contract,
        "strategy_contract_explicit": strategy_contract_explicit,
        "strategy_anchors": strategy_anchors,
        "contract_repair_attempts": contract_repair_attempts,
        "compile_api_diagnostics": compile_api_diagnostics,
        "failure_kind": "compile_failed" if saw_nonempty_code else "llm_error",
    }


def infer_attempt_result(result: dict) -> str:
    if result.get("success"):
        return "success"

    iterations = result.get("iterations") if isinstance(result.get("iterations"), list) else []
    fallback_iterations = result.get("fallback_iterations") if isinstance(result.get("fallback_iterations"), list) else []
    all_iterations = [*iterations, *fallback_iterations]
    if not all_iterations:
        return "failed"

    saw_llm_error = False
    saw_non_llm_failure = False
    for item in all_iterations:
        if not isinstance(item, dict):
            continue
        build = item.get("build")
        if not isinstance(build, dict) or build.get("success"):
            saw_non_llm_failure = True
            continue
        if build.get("failure_kind") == "llm_error":
            saw_llm_error = True
        else:
            saw_non_llm_failure = True

    if saw_llm_error and not saw_non_llm_failure:
        return "llm_error"
    return "failed"


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
    initial_iteration_note: str = "",
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
    best_attempt: dict | None = None
    last_failure_summary = ""
    if strategy_name == "reference_guided":
        best_attempt = {
            "kind": "baseline",
            "iteration": 0,
            "code": previous_code,
            "target_path": accepted_target_path,
            "evaluation": dict(accepted_evaluation),
            "score": score_evaluation(accepted_evaluation),
        }
    no_growth_count = 0
    stalled_out = False
    replan_code = ""
    replan_evaluation: dict | None = None
    replan_count = 0

    for iteration_index in range(1, max_iterations + 1):
        iteration_dir = output_dir / strategy_name / f"iter_{iteration_index:02d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)

        if replan_evaluation is not None:
            previous_code = replan_code or previous_code
            previous_evaluation = dict(replan_evaluation)
            replan_code = ""
            replan_evaluation = None
        elif strategy_name == "reference_guided" and best_attempt is not None:
            previous_code = best_attempt.get("code", previous_code)
            previous_evaluation = dict(best_attempt.get("evaluation", {}))
            previous_evaluation["note"] = last_failure_summary or previous_evaluation.get("note", "N/A")
        elif iteration_index == 1 and initial_iteration_note:
            previous_evaluation = {"note": initial_iteration_note}

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
            failure_kind = build_info.get("failure_kind")
            if failure_kind in {"contract_parse_error", "strategy_replan_required"}:
                last_failure_summary = summarize_strategy_generation_failure(iteration_index, build_info)
                record["note"] = last_failure_summary
                record["last_failure_summary"] = last_failure_summary
                replan_count += 1
                record["strategy_replan_required"] = True
                record["strategy_replan_number"] = replan_count
                replan_code = build_info.get("last_code", previous_code)
                replan_evaluation = {
                    "runtime_diagnosis": failure_kind,
                    "strategy_contract": build_info.get("strategy_contract") or "N/A",
                    "note": last_failure_summary,
                }
                iterations.append(record)
                continue
            if strategy_name == "reference_guided":
                last_failure_summary = summarize_compile_failure(iteration_index, build_info)
                record["note"] = last_failure_summary
                record["last_failure_summary"] = last_failure_summary
                previous_evaluation = dict((best_attempt or {}).get("evaluation", accepted_evaluation))
                previous_evaluation["note"] = last_failure_summary
                previous_evaluation["compile_api_diagnostics"] = build_info.get("compile_api_diagnostics", [])
            iterations.append(record)
            if strategy_name != "reference_guided":
                previous_evaluation = {
                    "note": record["note"],
                    "compile_api_diagnostics": build_info.get("compile_api_diagnostics", []),
                }
                previous_code = build_info.get("last_code", previous_code)
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
        runtime_diagnosis = diagnose_runtime_evaluation(evaluation)
        evaluation["runtime_diagnosis"] = runtime_diagnosis
        evaluation["strategy_contract"] = build_info.get("strategy_contract", "N/A")
        record["runtime_diagnosis"] = runtime_diagnosis
        record["strategy_contract"] = evaluation["strategy_contract"]
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
        candidate_score_tuple = score_evaluation(evaluation)
        record["accepted"] = should_accept

        if not should_accept:
            logging.info(
                "Discarding candidate %s for strategy %s at iteration %d; blocker not crossed.",
                target_path.stem,
                strategy_name,
                iteration_index,
            )
            kept_as_best = False
            if strategy_name == "reference_guided":
                kept_as_best = should_replace_best(candidate_score_tuple, best_attempt)
                if kept_as_best:
                    old_best_path = (best_attempt or {}).get("target_path")
                    if (best_attempt or {}).get("kind") == "generated" and old_best_path != str(target_path):
                        delete_generated_target(oss_fuzz, args.project_name, old_best_path)
                    best_attempt = {
                        "kind": "generated",
                        "iteration": iteration_index,
                        "code": build_info.get("code", ""),
                        "target_path": str(target_path),
                        "evaluation": dict(evaluation),
                        "score": candidate_score_tuple,
                    }
                else:
                    delete_generated_target(oss_fuzz, args.project_name, str(target_path))
                last_failure_summary = summarize_coverage_feedback(iteration_index, evaluation, kept_as_best)
                record["last_failure_summary"] = last_failure_summary
                record["accepted_as_best"] = kept_as_best
                record["rolled_back"] = not kept_as_best
            else:
                oss_fuzz.remove_target(args.project_name, target_path.stem)
                record["rolled_back"] = True
            no_growth_count += 1
            record["no_growth_count"] = no_growth_count
            if runtime_diagnosis in {"route_failure", "predicate_state_failure", "coverage_error"}:
                replan_count += 1
                record["strategy_replan_required"] = True
                record["strategy_replan_number"] = replan_count
                replan_code = build_info.get("code", "")
                replan_evaluation = dict(evaluation)
                replan_evaluation["note"] = last_failure_summary or record["note"]
            if strategy_name == "reference_guided" and kept_as_best:
                record["note"] = (
                    f"{record['note']} | kept as best-so-far compiled candidate "
                    f"(blocked={candidate_blocked_hit})"
                )
            else:
                record["note"] = (
                    f"{record['note']} | rolled back to {accepted_target_path} "
                    f"(blocked={accepted_blocked_hit})"
                )
            iterations.append(record)
            if strategy_name == "reference_guided":
                if best_attempt is not None:
                    previous_evaluation = dict(best_attempt.get("evaluation", {}))
                    previous_evaluation["note"] = last_failure_summary
                    previous_code = best_attempt.get("code", previous_code)
            else:
                previous_evaluation = dict(evaluation)
                previous_evaluation["note"] = record["note"]
                previous_code = build_info.get("code", previous_code)
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
        if strategy_name == "reference_guided" and best_attempt is not None:
            old_best_path = best_attempt.get("target_path")
            if best_attempt.get("kind") == "generated" and old_best_path != str(target_path):
                delete_generated_target(oss_fuzz, args.project_name, old_best_path)
            success_evaluation = evaluation | {"note": record["note"]}
            best_attempt = {
                "kind": "generated",
                "iteration": iteration_index,
                "code": build_info.get("code", ""),
                "target_path": str(target_path),
                "evaluation": dict(success_evaluation),
                "score": candidate_score_tuple,
            }
        previous_evaluation = evaluation | {"note": record["note"]}
        accepted_evaluation = previous_evaluation
        accepted_target_path = str(target_path)
        previous_code = build_info.get("code", "")
        no_growth_count = 0

        if record["success"]:
            logging.info("Strategy %s succeeded at iteration %d", strategy_name, iteration_index)
            break

    if strategy_name == "reference_guided" and not any(item.get("success") for item in iterations):
        if best_attempt is not None and best_attempt.get("kind") == "generated":
            delete_generated_target(oss_fuzz, args.project_name, best_attempt.get("target_path"))
        accepted_target_path = str(args.fuzz_file)
        accepted_evaluation = dict(baseline_evaluation or {})

    return {
        "iterations": iterations,
        "stalled_out": stalled_out,
        "accepted_target_path": accepted_target_path,
        "accepted_evaluation": accepted_evaluation,
        "best_attempt": best_attempt,
        "strategy_replan_count": replan_count,
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
    setup_file_logging(args.function_name, getattr(args, "log_dir", None))
    oss_fuzz = OSSFuzz()
    llm = LLMClient(backend=args.backend, model_name=args.model)
    output_dir = build_output_dir(args)

    prompt_context = collect_prompt_context(args, oss_fuzz)
    symbol_evidence_data = prompt_context.pop("_symbol_evidence_data")
    symbol_evidence_path = output_dir / "symbol_evidence.json"
    write_json(symbol_evidence_path, symbol_evidence_data)
    symbol_evidence_summary = {
        "total_entries": symbol_evidence_data.get("total_entries", 0),
        "included_entries": symbol_evidence_data.get("included_entries", 0),
        "truncated": symbol_evidence_data.get("truncated", False),
        "symbol_seed_count": len(symbol_evidence_data.get("symbol_seeds", [])),
        "type_seed_count": len(symbol_evidence_data.get("type_seeds", [])),
        "collection_errors": symbol_evidence_data.get("collection_errors", []),
    }
    evidence_result_fields = {
        "symbol_evidence_path": str(symbol_evidence_path),
        "symbol_evidence_summary": symbol_evidence_summary,
    }
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
            "attempt_result": "success",
            "success_stage": "baseline_evaluation",
            "failure_stage": None,
            "pipeline_methods": [],
            "output_dir": str(output_dir),
            "baseline_evaluation": baseline_evaluation,
            "message": "Baseline fuzz target already reaches the blocked-side line.",
            "iterations": [],
            **evidence_result_fields,
        }

    reference_guided_prompt = prompt_generator.blocker_reference_guided_prompt(**prompt_context)
    iteration_budget = max(1, int(getattr(args, "max_iterations", config.ITERATION_LOOP)))

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
        result = {
            "success": True,
            "attempt_result": "success",
            "success_stage": "reference_guided_generation",
            "failure_stage": None,
            "pipeline_methods": ["reference_guided_generation"],
            "output_dir": str(output_dir),
            "baseline_evaluation": baseline_evaluation,
            "iteration_budget": iteration_budget,
            "best_iteration": summarize_best_iteration(reference_guided_iterations),
            "iterations": reference_guided_iterations,
            "fallback_iterations": [],
            "reference_guided_strategy_replan_count": reference_guided_result["strategy_replan_count"],
            "dedicated_generation_strategy_replan_count": 0,
            **evidence_result_fields,
        }
        return attach_target_quality_report(
            result,
            output_dir=output_dir,
            symbol_evidence_data=symbol_evidence_data,
        )

    ref_handoff_summary = build_ref_handoff_summary(reference_guided_result, baseline_evaluation)
    dedicated_generation_prompt = prompt_generator.blocker_dedicated_generation_prompt(
        **(prompt_context | {"ref_handoff_summary": ref_handoff_summary})
    )
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
        initial_iteration_note=ref_handoff_summary,
    )
    dedicated_generation_iterations = dedicated_generation_result["iterations"]

    all_iterations = reference_guided_iterations + dedicated_generation_iterations
    final_success = any(item.get("success") for item in all_iterations)
    attempt_result = "success" if final_success else infer_attempt_result(
        {
            "success": final_success,
            "iterations": reference_guided_iterations,
            "fallback_iterations": dedicated_generation_iterations,
        }
    )
    result = {
        "success": final_success,
        "attempt_result": attempt_result,
        "success_stage": "dedicated_generation" if final_success else None,
        "failure_stage": None if final_success else "dedicated_generation",
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
        "reference_guided_strategy_replan_count": reference_guided_result["strategy_replan_count"],
        "dedicated_generation_strategy_replan_count": dedicated_generation_result["strategy_replan_count"],
        "best_iteration": summarize_best_iteration(all_iterations),
        "iterations": reference_guided_iterations,
        "fallback_iterations": dedicated_generation_iterations,
        **evidence_result_fields,
    }
    return attach_target_quality_report(
        result,
        output_dir=output_dir,
        symbol_evidence_data=symbol_evidence_data,
    )


def build_argument_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--blocker-call-sites", default=None)
    parser.add_argument("--blocker-call-sites-file", default=None)
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--max-iterations", type=int, default=config.ITERATION_LOOP)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    parser.add_argument("--output-root", default=None,
                        help="Root directory under which output dirs are created. "
                             "Defaults to generated_targets/.")
    parser.add_argument("--log-dir", default=None,
                        help="Directory for input-independent solver session logs. Defaults to logs/ when omitted.")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()

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
