#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "blocker_classify_template"

def load_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""

def read_optional_file(path_str: str | None) -> str:
    if not path_str:
        return "N/A"
    p = Path(path_str)
    return load_text(p) if p.exists() else "N/A"


def resolve_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = read_optional_file(file_path)
        if text != "N/A":
            return text
    if inline_text:
        return inline_text
    return default

def format_prompt(template: str, args: argparse.Namespace) -> str:
    mapping = {
        "language": args.language or "N/A",
        "project_name": args.project_name or "N/A",
        "function_name": args.function_name or "N/A",
        "branch_line_number": getattr(args, "branch_line_number", "N/A"),
        "blocked_side_line_number": getattr(args, "blocked_side_line_number", "N/A"),
        "blocker_line_code": getattr(args, "blocker_line_code", "N/A") or "N/A",
        "blocked_side_line_code": getattr(args, "blocked_side_line_code", "N/A") or "N/A",
        "fuzz_target_code": resolve_text(getattr(args, "fuzz_file", None), getattr(args, "fuzz_target_code", None)),
        "header_code": resolve_text(getattr(args, "header_file", None), getattr(args, "header_code", None)),
        "branch_hit_count": getattr(args, "branch_hit_count", "N/A") or "N/A",
        "runtime_blocker_segment": resolve_text(
            getattr(args, "runtime_blocker_segment_file", None),
            getattr(args, "runtime_blocker_segment", None),
        ),
        "runtime_blocker_segment_source_codes": resolve_text(
            getattr(args, "runtime_blocker_segment_source_codes_file", None),
            getattr(args, "runtime_blocker_segment_source_codes", None),
        ),
        "cfg_call_chain": resolve_text(
            getattr(args, "cfg_call_chain_file", None),
            getattr(args, "cfg_call_chain", None),
        ),
        "cfg_source_codes": resolve_text(
            getattr(args, "cfg_source_codes_file", None),
            getattr(args, "cfg_source_codes", None),
        ),
    }

    def repl(m: re.Match) -> str:
        key = m.group(1)
        return mapping.get(key, m.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)

def to_api_filepath(path_str: str) -> str:
    if not path_str:
        return ""
    p = path_str.replace("\\", "/")
    marker = "/inspector/source-code"
    if marker in p:
        # e.g. .../inspector/source-code/src/tinyxml2/tinyxml2.cpp -> /src/tinyxml2/tinyxml2.cpp
        return p.split(marker, 1)[1]
    build_out_src_marker = "/build/out/"
    if build_out_src_marker in p and "/src/" in p:
        return p[p.index("/src/") :]
    return p

def fetch_line_code(project_name: str, filepath: str, line_no: int) -> str:
    if not project_name or not filepath or line_no <= 0:
        return ""
    ins = Introspector()
    return ins.get_project_source_code(
        project_name=project_name,
        filepath=filepath,
        begin_line=line_no,
        end_line=line_no,
    ).strip()

def extract_json(text: str) -> dict:
    if repair_json is not None:
        parsed = repair_json(text, return_objects=True)
        if not isinstance(parsed, dict):
            raise ValueError("Failed to parse JSON into dictionary.")
        return parsed

    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("Failed to parse JSON into dictionary.")
    return parsed

def run_program(script: Path, extra_args: list[str] = None) -> int:
    cmd = [sys.executable, str(script)]
    if extra_args:
        cmd.extend(extra_args)
    logging.info("Dispatching: %s", " ".join(cmd))
    p = subprocess.run(cmd)
    return p.returncode

def check_function_coverage(project_name: str, fuzzer_name: str, func_name: str) -> str:
    """
    Retrieves the line coverage report for a specific function within a given fuzz target.
    It automatically translates the demangled function name to its mangled regex.
    """
    introspector = Introspector()
    oss_fuzz = OSSFuzz()
    
    # 1. Look up the mangled function name (raw_function_name)
    func_name_list = introspector.get_all_functions(project_name)
    function_regex = ""
    for func in func_name_list:
        # Remove spaces to ensure robust string matching
        target_name = func.get('function_name', '').replace(' ', '')
        query_name = func_name.replace(' ', '')
        
        if target_name == query_name:
            function_regex = func.get('raw_function_name', '')
            break  # Found the matching function

    if not function_regex:
        logging.warning(f"Could not find heavily mangled name for '{func_name}' in project '{project_name}'")
        return ""

    logging.info(f"Matched '{func_name}' to regex: '{function_regex}'. Checking coverage...")
    
    # 2. Extract the coverage report
    report = oss_fuzz.linecov_reports(
        proj_name=project_name, 
        fuzzer_name=fuzzer_name, 
        fun_name_regex=function_regex
    )
    
    return report

def get_line_execution_count(report: str, line_no: int) -> str:
    """
    Parses the line coverage report and extracts the execution count for a specific line number.
    Returns the execution count as a string (e.g., "202k", "0", ""), or "" if the line is not found.
    """
    if not report:
        return ""
    
    # Find the target line by matching the line number followed by '|', e.g., " 753|" or "\n753|"
    # Since llvm-cov may pad spaces before the line number, we directly match the line pattern
    target_prefix = f"{line_no}|"
    
    for line in report.splitlines():
        # If the line starts with "753|" after removing leading whitespace
        if line.lstrip().startswith(target_prefix):
            # Once found, split the line at most twice by '|': [line_number, count, code]
            parts = line.split('|', 2)
            if len(parts) >= 2:
                return parts[1].strip()  # Return the execution count part with whitespace trimmed
            
    return ""  # Return empty string if the line is not found at all


def setup_file_logging(func_name: str) -> None:
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}.log"

    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    log_filepath = log_dir / log_filename

    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)
    logging.info(f"Log file create: {log_filepath}")


def log_collection_status(args: argparse.Namespace) -> None:
    logging.info("=============== Collection Status ===============")
    logging.info("Runtime/GDB acquisition status: %s", getattr(args, "runtime_collection_status", "unknown"))
    logging.info("Static/CFG acquisition status: %s", getattr(args, "cfg_collection_status", "unknown"))

    runtime_error = getattr(args, "runtime_collection_error", "")
    cfg_error = getattr(args, "cfg_collection_error", "")
    triggering_input = getattr(args, "triggering_input", "")

    if runtime_error:
        logging.info("Runtime/GDB error: %s", runtime_error)
    if cfg_error:
        logging.info("Static/CFG error: %s", cfg_error)
    if triggering_input:
        logging.info("Triggering input: %s", triggering_input)


def enrich_classification_args(args: argparse.Namespace) -> argparse.Namespace:
    oss_fuzz = OSSFuzz()
    api_filepath = to_api_filepath(args.source_file or "")
    branch_line = int(args.branch_line_number)
    blocked_side_line = int(args.blocked_side_line_number)

    args.language = oss_fuzz.proj_lang(args.project_name)
    args.blocker_line_code = fetch_line_code(args.project_name, api_filepath, branch_line) or "N/A"
    args.blocked_side_line_code = fetch_line_code(args.project_name, api_filepath, blocked_side_line) or "N/A"

    if getattr(args, "fuzz_file", None):
        fuzzer_name = Path(args.fuzz_file).stem
        try:
            cov_report = check_function_coverage(args.project_name, fuzzer_name, args.function_name)
            args.branch_hit_count = get_line_execution_count(cov_report, branch_line)
        except Exception as exc:
            logging.warning("Failed to get branch hit count: %s", exc)
            args.branch_hit_count = "N/A"
    else:
        args.branch_hit_count = "N/A"

    return args


def classify_blocker(args: argparse.Namespace, execute_pipeline: bool = True) -> dict:
    from llm_interface.llm_client import LLMClient

    setup_file_logging(args.function_name)
    log_collection_status(args)
    args = enrich_classification_args(args)

    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template missing: {TEMPLATE_PATH}")

    template = load_text(TEMPLATE_PATH)
    prompt = format_prompt(template, args)
    logging.info("================ Generated Prompt ================\n%s\n", prompt)

    llm = LLMClient(backend=args.backend, model_name=args.model)
    response_text = llm.generate(prompt)
    if not response_text:
        raise RuntimeError("Empty LLM response.")

    try:
        result = extract_json(response_text)
    except Exception as exc:
        logging.error("JSON parsing failed: %s", exc)
        print(response_text)
        raise

    analysis_trace = result.get("analysis_trace", [])
    classification = result.get("classification", {})
    dependency_result = classification.get("dependency", "")
    reason = result.get("reason", "")

    if isinstance(analysis_trace, list):
        formatted_trace = "\n\n".join(analysis_trace)
    else:
        formatted_trace = str(analysis_trace)

    logging.info(
        "Analysis trace:\n\n%s\n\n------------------------\nDependency: %s\nReason: %s\n",
        formatted_trace,
        dependency_result,
        reason,
    )

    output = {
        "prompt": prompt,
        "response_text": response_text,
        "parsed_result": result,
        "dependency_result": dependency_result,
        "reason": reason,
    }

    if not execute_pipeline:
        return output

    if dependency_result == "Input Dependent":
        logging.info("--> Routing to Input Dependent Pipeline (Seed Gen -> Symbolic Execution)")
        returncode = run_program(MODULE_ROOT / "seeds_generation.py")
        output["pipeline_returncode"] = returncode
        return output

    if dependency_result == "Input Independent":
        logging.info("--> Routing to Input Independent Pipeline (Fuzz Target Refine -> New Target -> Drop)")
        returncode = run_program(MODULE_ROOT / "blocker_iteration.py")
        output["pipeline_returncode"] = returncode
        return output

    raise RuntimeError(f"Unknown dependency classification: {dependency_result}")


def main():
    parser = argparse.ArgumentParser(description="Classify blocker via template and dispatch to appropriate program.")
    parser.add_argument("--backend", default="gemini", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default=None)

    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True) 
    parser.add_argument("--source-file", required=True, help="Path to source code file for blocker line lookup and optional extra context")
    parser.add_argument("--fuzz-file", required=True, help="Path to fuzz target code to embed")
    parser.add_argument("--header-file", default=None, help="Path to related header file to embed")
    parser.add_argument("--runtime-blocker-segment-file", default=None, help="Path to the runtime blocker segment text")
    parser.add_argument("--runtime-blocker-segment-source-codes-file", default=None, help="Path to runtime blocker segment source codes")
    parser.add_argument("--cfg-call-chain-file", default=None, help="Path to CFG call chain text")
    parser.add_argument("--cfg-source-codes-file", default=None, help="Path to CFG source codes text")
    parser.add_argument("--runtime-blocker-segment", default=None, help="Inline runtime blocker segment text")
    parser.add_argument("--runtime-blocker-segment-source-codes", default=None, help="Inline runtime blocker segment source code text")
    parser.add_argument("--cfg-call-chain", default=None, help="Inline CFG call chain text")
    parser.add_argument("--cfg-source-codes", default=None, help="Inline CFG source code text")
    parser.add_argument("--runtime-collection-status", default="unknown")
    parser.add_argument("--runtime-collection-error", default="")
    parser.add_argument("--cfg-collection-status", default="unknown")
    parser.add_argument("--cfg-collection-error", default="")
    parser.add_argument("--triggering-input", default="")
    args = parser.parse_args()
    try:
        result = classify_blocker(args, execute_pipeline=True)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Classification failed: %s", exc)
        sys.exit(3)

    pipeline_returncode = result.get("pipeline_returncode")
    if pipeline_returncode is not None:
        sys.exit(pipeline_returncode)
    sys.exit(0)

if __name__ == "__main__":
    main()
