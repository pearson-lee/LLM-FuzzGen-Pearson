#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys
import subprocess
from pathlib import Path
import re
from external.introspector import Introspector
from llm_interface.llm_client import LLMClient
from external.oss_fuzz import OSSFuzz, TotalCoverageSummary
from json_repair import repair_json
import time
import datetime

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
REPO_ROOT = Path(__file__).resolve().parent
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

def format_prompt(template: str, args: argparse.Namespace) -> str:
    mapping = {
        "language": args.language or "N/A",
        "project_name": args.project_name or "N/A",
        "function_name": args.function_name or "N/A",
        "branch_line_number": getattr(args, "branch_line_number", "N/A"),
        "blocked_side_line_number": getattr(args, "blocked_side_line_number", "N/A"),
        "blocker_line_code": getattr(args, "blocker_line_code", "N/A") or "N/A",
        "blocked_side_line_code": getattr(args, "blocked_side_line_code", "N/A") or "N/A",
        "source_code": read_optional_file(args.source_file) if getattr(args, "source_file", None) else (getattr(args, "source_code", "") or "N/A"),
        "fuzz_target_code": read_optional_file(args.fuzz_file) if getattr(args, "fuzz_file", None) else (getattr(args, "fuzz_target_code", "") or "N/A"),
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
        # 例如 .../inspector/source-code/src/tinyxml2/tinyxml2.cpp -> /src/tinyxml2/tinyxml2.cpp
        return p.split(marker, 1)[1]
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
    # repair_json 會自動處理 Markdown、未跳脫引號、遺失的括號與換行符號
    parsed = repair_json(text, return_objects=True)
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
    
    # 尋找以指定行號和 '|' 結尾的特徵字串，例如 " 753|" 或 "\n753|"
    # 因為 llvm-cov 行號前面可能會補空白，所以我們直接找該行特徵
    target_prefix = f"{line_no}|"
    
    for line in report.splitlines():
        # 如果該行清掉前面的空白後，剛好是以 "753|" 開頭
        if line.lstrip().startswith(target_prefix):
            # 找到後，將這行最多切對半兩次: [行號, 次數, 程式碼]
            parts = line.split('|', 2)
            if len(parts) >= 2:
                return parts[1].strip()  # 回傳去頭去尾的次數部分
                
    return ""  # 完全找不到該行時回傳空字串


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


def main():
    parser = argparse.ArgumentParser(description="Classify blocker via template and dispatch to appropriate program.")
    parser.add_argument("--backend", default="gemini", choices=["gemini"])
    parser.add_argument("--model", default=None)

    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True) 
    parser.add_argument("--source-file", required=True, help="Path to source code file to embed")
    parser.add_argument("--fuzz-file", required=True, help="Path to fuzz target code file to embed")
  
    args = parser.parse_args()

    setup_file_logging(args.function_name)

    oss_fuzz = OSSFuzz()
    api_filepath = to_api_filepath(args.source_file or "")
    branch_line = int(args.branch_line_number)
    blocked_side_line = int(args.blocked_side_line_number)
    args.language = oss_fuzz.proj_lang(args.project_name)
    args.blocker_line_code = fetch_line_code(args.project_name, api_filepath, branch_line) or "N/A"
    args.blocked_side_line_code = fetch_line_code(args.project_name, api_filepath, blocked_side_line) or "N/A"

    if not TEMPLATE_PATH.exists():
        logging.error("Template missing: %s", TEMPLATE_PATH)
        sys.exit(1)

    template = load_text(TEMPLATE_PATH)
    prompt = format_prompt(template, args)

    llm = LLMClient(backend=args.backend, model_name=args.model)
    resp = llm.generate(prompt)
    if not resp:
        logging.error("Empty LLM response.")
        sys.exit(2)

    try:
        result = extract_json(resp)
    except Exception as e:
        logging.error("JSON parsing failed: %s", e)
        print(resp)
        sys.exit(3)

    # 提取新版 JSON 結構的值
    analysis_trace = result.get("analysis_trace", [])
    classification = result.get("classification", {})
    dependency_result = classification.get("dependency", "")
    reason = result.get("reason", "")

    if isinstance(analysis_trace, list):
        formatted_trace = "\n\n".join(analysis_trace)
    else:
        formatted_trace = str(analysis_trace)

    # 更新 logging 輸出格式，使其更符合新版的 Binary 分類
    logging.info("Analysis trace:\n\n%s\n\n------------------------\nDependency: %s\nReason: %s\n", 
                 formatted_trace,  
                 dependency_result, 
                 reason)    
    
    # 根據新的二元分類進行腳本派發 (Pipeline 迭代起點)
    if dependency_result == "Input Dependent":
        logging.info("--> Routing to Input Dependent Pipeline (Seed Gen -> Symbolic Execution)")
        # 將任務交給專門處理 Dependent 的迭代腳本 (第一步先生 Seed)
        returncode = run_program(REPO_ROOT / "seeds_generation.py")
        sys.exit(returncode)
        
    elif dependency_result == "Input Independent":
        logging.info("--> Routing to Input Independent Pipeline (Fuzz Target Refine -> New Target -> Drop)")
        # 將任務交給專門處理 Independent 的迭代腳本 (第一步先微調 Fuzz Target)
        returncode = run_program(REPO_ROOT / "blocker_iteration.py")
        sys.exit(returncode)
        
    else:
        logging.error("Unknown dependency classification: %s", dependency_result)
        print(reason or "No reason provided.")
        sys.exit(4)

if __name__ == "__main__":
    main()