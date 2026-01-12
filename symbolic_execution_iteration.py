#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Repo-local imports
import config.config as cfg
from llm_interface.llm_client import LLMClient

REPO_ROOT = Path(__file__).resolve().parent
TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "symbolic_template"

LOG_DIR = REPO_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def setup_file_logging(log_path: Path):
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    root_logger = logging.getLogger()
    # 避免重複加 handler
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', '') == str(log_path) for h in root_logger.handlers):
        root_logger.addHandler(file_handler)

def require_env(var: str):
    val = os.getenv(var)
    if not val:
        logging.error(f"Missing environment variable: {var}")
        sys.exit(1)
    return val

def read_text_if_exists(p: Path) -> str:
    if not p:
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def load_symbolic_template() -> str:
    if not TEMPLATE_PATH.exists():
        logging.error(f"Template not found: {TEMPLATE_PATH}")
        sys.exit(1)
    return TEMPLATE_PATH.read_text(encoding="utf-8")

def format_symbolic_prompt(
    *,
    project_name: str,
    project_language: str,
    target_function_name: str,
    function_signature: str,
    source_code: str,
    blocker_function_name: str,
    blocker_line_numbers: str,
    previous_harness: str = "",
    compiler_errors: str = "",
) -> str:
    base = load_symbolic_template()
    prompt = base.format(
        project_name=project_name,
        project_language=project_language,
        target_function_name=target_function_name or "",
        function_signature=function_signature or "",
        source_code=source_code or "",
        blocker_function_name=blocker_function_name or "",
        blocker_line_numbers=blocker_line_numbers or "",
    )

    extras = []
    if previous_harness:
        extras.append(
            "\n\n# Previous Harness (for reference only; fix and output a single complete file)\n"
            "```cpp\n" + previous_harness.strip() + "\n```"
        )
    if compiler_errors:
        extras.append(
            "\n\n# Compiler Errors\n"
            "The harness must compile with clang to LLVM bitcode. Fix any issues below.\n"
            "```\n" + compiler_errors.strip() + "\n```"
        )

    # Re-assert strict output format
    tail_rule = (
        "\n\n# Output Requirement\n"
        "- Output only the complete C/C++ KLEE harness source code.\n"
        "- Do not include explanations or markdown except the source code.\n"
    )
    return prompt + "".join(extras) + tail_rule

def extract_code_block(text: str) -> str:
    # Prefer fenced code content, else return full text.
    m = re.search(r"```[a-zA-Z0-9_+\-]*\n(.*?)\n```", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()

def write_harness(project: str, filename: str, code: str) -> Path:
    proj_dir = REPO_ROOT / "external" / "oss-fuzz" / "projects" / project
    proj_dir.mkdir(parents=True, exist_ok=True)
    out_path = proj_dir / filename
    out_path.write_text(code, encoding="utf-8")
    logging.info(f"Wrote harness: {out_path}")
    return out_path

def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    logging.info("Running: %s", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

def run_bash_script(script: str, args: list[str]) -> tuple[int, str, str]:
    # Prefer bash if available; user environment must have bash/docker
    return run_cmd(["bash", script, *args])

def build_harness(project: str, harness_rel: str) -> tuple[bool, str, str]:
    code, out, err = run_bash_script(str(REPO_ROOT / "build_klee_harness.sh"), [project, harness_rel])
    success = code == 0
    return success, out, err + ("\n" + out if err.strip() == "" else "")

def run_klee(project: str, bc_name: str) -> tuple[bool, str, str]:
    code, out, err = run_bash_script(str(REPO_ROOT / "run_klee.sh"), [project, bc_name])
    return code == 0, out, err

def main():
    parser = argparse.ArgumentParser(description="Iteratively generate, build, and run a KLEE harness via Gemini.")
    parser.add_argument("--project", required=True, help="Project name (e.g., tinyxml2)")
    parser.add_argument("--lang", default="c++", choices=["c", "c++"], help="Harness language")
    parser.add_argument("--target-func", default="", help="Target function name")
    parser.add_argument("--signature", default="", help="Function signature")
    parser.add_argument("--source-txt", default="", help="Path to a .txt file whose contents will be used in the prompt (overrides --source-file)")
    parser.add_argument("--blocker-func", default="", help="Blocker function name (coverage blocker)")
    parser.add_argument("--blocker-lines", default="", help="Blocker line number(s), e.g., 123 or 120-140")
    parser.add_argument("--max-iters", type=int, default=cfg.ITERATION_LOOP, help="Max LLM/build iterations")
    parser.add_argument("--backend", default="gemini", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default=None, help="Override model name")
    args = parser.parse_args()

    # Basic checks
    if args.backend == "gemini":
        require_env("GOOGLE_API_KEY")
    if not (REPO_ROOT / "build_klee_harness.sh").exists() or not (REPO_ROOT / "run_klee.sh").exists():
        logging.error("Missing build_klee_harness.sh or run_klee.sh in repo root.")
        sys.exit(1)

    # Prepare input context
    project = args.project
    lang = args.lang
    ts_id = time.strftime("%Y%m%d_%H%M%S")
    ext = ".c" if lang == "c" else ".cc"
    base_name = f"klee_{ts_id}"
    harness_file = f"{base_name}{ext}"  # placed in /external/oss-fuzz/projects/<project>/
    harness_rel = harness_file  # pass only basename; container searches /src/project/<basename>

    log_path = LOG_DIR / f"symbolic_{project}_{ts_id}.log"
    setup_file_logging(log_path)
    logging.info(f"Log file: {log_path}")

    source_text = read_text_if_exists(Path(args.source_txt)) if args.source_txt else ""
    source_code = source_text if source_text else (read_text_if_exists(Path(args.source_file)) if args.source_file else "")

    # Init LLM
    llm = LLMClient(backend=args.backend, model_name=args.model)

    prev_code = ""
    last_err = ""
    harness_code = ""
    success = False

    for i in range(1, args.max_iters + 1):
        logging.info(f"=== Iteration {i}/{args.max_iters} ===")
        prompt = format_symbolic_prompt(
            project_name=project,
            project_language=lang,
            target_function_name=args.target_func,
            function_signature=args.signature,
            # TODO: change to dynamic source input
            source_code=source_code,
            blocker_function_name=args.blocker_func,
            blocker_line_numbers=args.blocker_lines,
            previous_harness=prev_code,
            compiler_errors=last_err,
        )
        logging.info("Prompt (truncated):\n%s", prompt[:2000])
        logging.info(f"Starting LLM generation for harness.")
        resp = llm.generate(prompt)
        if not resp:
            logging.error("LLM returned empty response. Aborting.")
            break
        harness_code = extract_code_block(resp)
        if not harness_code:
            logging.error("No code extracted from LLM response. Aborting.")
            break

        # Write harness (overwrite same file across iterations)
        path = write_harness(project, harness_file, harness_code)

        # Try build
        ok, out, err = build_harness(project, harness_rel)
        logging.info("Build stdout:\n%s", out.strip())
        logging.info("Build stderr:\n%s", err.strip())
        if ok:
            logging.info("Build succeeded.")
            success = True
            break

        # Collect error for next iteration
        logging.warning("Build failed; feeding errors back to LLM.")
        prev_code = harness_code
        last_err = (err or out or "Unknown compiler/linker error.")[:12000]  # keep prompt size reasonable

    if not success:
        logging.error("All iterations failed to produce a compilable harness.")
        print("\nLast compiler errors:\n", last_err)
        sys.exit(2)

    # Determine linked bc name and run KLEE
    linked_bc = f"{base_name}_linked.bc"
    bc_path = REPO_ROOT / "klee_build_output" / "klee" / linked_bc
    if not bc_path.exists():
        # Fallback: list available and pick matching prefix
        candidates = sorted((REPO_ROOT / "klee_build_output" / "klee").glob(f"{base_name}*_linked.bc"))
        if candidates:
            linked_bc = candidates[-1].name

    ok, out, err = run_klee(project, linked_bc)
    logging.info("KLEE stdout:\n%s", out.strip())
    logging.info("KLEE stderr:\n%s", err.strip())
    if not ok:
        print(err, file=sys.stderr)
        sys.exit(3)

    logging.info("KLEE run completed. See ./klee_output/<RUN_ID>/ for results.")
    print(f"Bitcode: klee_build_output/klee/{linked_bc}")

if __name__ == "__main__":
    main()