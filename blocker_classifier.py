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
    text = text.strip()
    # Try direct JSON
    try:
        return json.loads(text)
    except Exception:
        pass
    # Try fenced code
    import re
    m = re.search(r"```(?:json|text)?\n(.*?)\n```", text, re.DOTALL)
    if m:
        block = m.group(1).strip()
        try:
            return json.loads(block)
        except Exception:
            pass
    # Try first balanced {...}
    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i+1]
                    try:
                        return json.loads(candidate)
                    except Exception:
                        break
    raise ValueError("Failed to parse JSON from LLM output.")

def run_program(script: Path, extra_args: list[str] = None) -> int:
    cmd = [sys.executable, str(script)]
    if extra_args:
        cmd.extend(extra_args)
    logging.info("Dispatching: %s", " ".join(cmd))
    p = subprocess.run(cmd)
    return p.returncode

def main():
    parser = argparse.ArgumentParser(description="Classify blocker via template and dispatch to appropriate program.")
    parser.add_argument("--backend", default="gemini", choices=["gemini"])
    parser.add_argument("--model", default=None)

    parser.add_argument("--language", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True) 
    parser.add_argument("--source-file", required=True, help="Path to source code file to embed")
    parser.add_argument("--fuzz-file", required=True, help="Path to fuzz target code file to embed")

    # TODO: not use
    parser.add_argument("--source-code", default="", help="Inline source code if not using --source-file")
    parser.add_argument("--fuzz-target-code", default="", help="Inline fuzz target code if not using --fuzz-file")

  
    args = parser.parse_args()

    api_filepath = to_api_filepath(args.source_file or "")
    branch_line = int(args.branch_line_number)
    blocked_side_line = int(args.blocked_side_line_number)

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

    analysis_trace = result.get("analysis_trace", [])
    classification = result.get("classification", {})
    decision = result.get("decision", {})
    path = decision.get("path", "")
    reason = classification.get("reason", "")

    logging.info("Analysis trace:\n\n%s \nClassification: %s | Path: %s | Confidence: %s", analysis_trace,  classification.get("category", ""), path, decision.get("confidence", ""))
    
    if path == "A1":
        # Minimal stub call to confirm execution
        returncode = run_program(REPO_ROOT / "llm_seeds_generation.py")
        sys.exit(returncode)
    elif path == "A2":
        # Ensure symbolic script exits early with --dry-run and minimal required args
        returncode = run_program(REPO_ROOT / "symbolic_execution_iteration.py")
        sys.exit(returncode)
    elif path == "B1_PRESERVE":
        returncode = run_program(REPO_ROOT / "blocker_iteration.py")
        sys.exit(returncode)
    elif path == "B1_DESTRUCTIVE":
        returncode = run_program(REPO_ROOT / "harness_generator.py")
        sys.exit(returncode)
    elif path == "B2":
        # Do nothing, only print reason
        print(reason or "No reason provided.")
        sys.exit(0)
    else:
        logging.error("Unknown decision path: %s", path)
        print(reason or "No reason provided.")
        sys.exit(4)

if __name__ == "__main__":
    main()