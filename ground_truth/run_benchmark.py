#!/usr/bin/env python3
"""
Ground Truth Benchmark Evaluation Runner for Blocker Classifier.
Runs blocker classification over curated Ground Truth test cases and measures accuracy and FP/FN rates.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent
CASES_DIR = BENCHMARK_DIR / "cases"
SELECTED_DIR = CASES_DIR / "selected_cases"
PENDING_DIR = CASES_DIR / "pending_cases"
REPO_ROOT = BENCHMARK_DIR.parent


def parse_args():
    parser = argparse.ArgumentParser(description="Run Ground Truth Blocker Classifier Benchmark")
    parser.add_argument("--case", default=None, help="Specific case ID to run (e.g. cjson_update_offset_547)")
    parser.add_argument("--pending", action="store_true", help="Run benchmark on pending_cases/ instead of selected_cases/")
    parser.add_argument("--model", default="gemini-2.5-flash", help="LLM model name (default: gemini-2.5-flash)")
    parser.add_argument("--backend", default="vertexai", choices=["vertexai", "gemini", "openrouter", "ollama"], help="LLM backend")
    parser.add_argument("--output", default=str(BENCHMARK_DIR / "benchmark_results.json"), help="Output JSON path")
    return parser.parse_args()



def extract_tag_content(log_text: str, tag: str) -> str:
    pattern = rf"<{tag}>\s*\n?(.*?)\n?\s*</{tag}>"
    match = re.search(pattern, log_text, re.DOTALL)
    if not match:
        return ""
    content = match.group(1).strip()
    invalid_placeholders = {
        "n/a", "none", "unavailable", "no runtime source codes captured.",
        "failed to get call chain", "no call chain found"
    }
    if not content or content.lower() in invalid_placeholders:
        return ""
    return content


def run_case(case_dir: Path, backend: str, model: str) -> dict:
    meta_path = case_dir / "meta.json"
    if not meta_path.exists():
        return {"error": f"Missing meta.json in {case_dir}"}

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    case_id = meta.get("case_id", case_dir.name)
    project_name = meta["project_name"]
    function_name = meta["function_name"]
    branch_line = str(meta["branch_line_number"])
    blocked_side_line = str(meta["blocked_side_line_number"])
    target_name = meta.get("target_name", "fuzz_target")

    # Auto-resolve source_file if missing in meta.json
    source_file = meta.get("source_file") or meta.get("source_api_file") or ""
    if not source_file:
        try:
            from blocker_process.blocker_classifier import resolve_source_api_file
            resolved_src = resolve_source_api_file(project_name, function_name)
            if resolved_src:
                source_file = resolved_src
                meta["source_file"] = source_file
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
        except Exception:
            pass

    fuzz_file = case_dir / "fuzz_target.cc"
    if not fuzz_file.exists():
        fuzz_file = case_dir / f"{target_name}.cc"
    header_file = case_dir / "header.h"
    runtime_seg = case_dir / "runtime_blocker_segment.txt"
    runtime_src = case_dir / "runtime_blocker_segment_source_codes.txt"
    cfg_chain = case_dir / "cfg_call_chain.txt"
    cfg_src = case_dir / "cfg_source_codes.txt"

    cmd = [
        sys.executable,
        str(REPO_ROOT / "blocker_process" / "blocker_classifier.py"),
        "--backend", backend,
        "--model", model,
        "--project-name", project_name,
        "--function-name", function_name,
        "--branch-line-number", branch_line,
        "--blocked-side-line-number", blocked_side_line,
        "--target-name", target_name,
        "--classify-only",
        "--keep-auto-context",
    ]

    if source_file:
        cmd.extend(["--source-api-file", source_file])
    if fuzz_file.exists():
        cmd.extend(["--fuzz-file", str(fuzz_file)])
    if header_file.exists():
        cmd.extend(["--header-file", str(header_file)])
    if runtime_seg.exists():
        cmd.extend(["--runtime-blocker-segment-file", str(runtime_seg)])
    if runtime_src.exists():
        cmd.extend(["--runtime-blocker-segment-source-codes-file", str(runtime_src)])
    if cfg_chain.exists():
        cmd.extend(["--cfg-call-chain-file", str(cfg_chain)])
    if cfg_src.exists():
        cmd.extend(["--cfg-source-codes-file", str(cfg_src)])

    start_time = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - start_time
    full_log = (proc.stdout or "") + "\n" + (proc.stderr or "")

    # Auto-Persist (Cache-on-Demand): Extract dynamic/static context and save to case_dir if missing
    tag_file_map = {
        "runtime_blocker_segment": ("runtime_blocker_segment.txt", runtime_seg),
        "runtime_blocker_segment_source_codes": ("runtime_blocker_segment_source_codes.txt", runtime_src),
        "cfg_call_chain": ("cfg_call_chain.txt", cfg_chain),
        "cfg_source_codes": ("cfg_source_codes.txt", cfg_src),
        "header_code": ("header.h", header_file),
    }

    cached_files = []
    for tag, (filename, file_path) in tag_file_map.items():
        if not file_path.exists():
            content = extract_tag_content(full_log, tag)
            if content:
                file_path.write_text(content + "\n", encoding="utf-8")
                cached_files.append(filename)

    if not fuzz_file.exists():
        fuzz_content = extract_tag_content(full_log, "fuzz_target_code")
        if fuzz_content:
            (case_dir / "fuzz_target.cc").write_text(fuzz_content + "\n", encoding="utf-8")
            cached_files.append("fuzz_target.cc")

    if cached_files:
        print(f"  [Cache-on-Demand] Cached context files to {case_dir.name}: {', '.join(cached_files)}")

    # Parse classification result from log output
    pred_label = "Unknown"
    pred_rule = "N/A"
    reason = ""

    for line in full_log.splitlines():
        clean_line = line.strip()
        if "Dependency: Input Independent" in clean_line or '"dependency": "Input Independent"' in clean_line:
            pred_label = "Input Independent"
        elif "Dependency: Input Dependent" in clean_line or '"dependency": "Input Dependent"' in clean_line:
            pred_label = "Input Dependent"
        if "Rule " in clean_line and ("Rule 1" in clean_line or "Rule 2" in clean_line or "Rule 3" in clean_line or "Rule 4" in clean_line or "Rule 5" in clean_line or "Rule 6" in clean_line):
            pred_rule = clean_line
        if clean_line.startswith("Reason: ") and not reason:
            reason = clean_line[len("Reason: "):]

    gt_label = meta.get("ground_truth_label")
    is_correct = (pred_label == gt_label)

    return {
        "case_id": case_id,
        "project": project_name,
        "function": function_name,
        "branch_line": branch_line,
        "gt_label": gt_label,
        "gt_rule": meta.get("ground_truth_rule", "N/A"),
        "pred_label": pred_label,
        "is_correct": is_correct,
        "elapsed_seconds": round(elapsed, 2),
        "returncode": proc.returncode,
        "reason_snippet": reason[:200] if reason else "",
        "cached_files": cached_files,
        "stdout_tail": full_log[-1000:],
    }


def main():
    args = parse_args()
    case_dirs = []

    if args.case:
        candidates = [
            SELECTED_DIR / args.case,
            PENDING_DIR / args.case,
            CASES_DIR / args.case,
        ]
        target = next((c for c in candidates if c.is_dir()), None)
        if not target:
            print(f"[Error] Case directory not found for: {args.case}")
            sys.exit(1)
        case_dirs.append(target)
    else:
        active_dir = PENDING_DIR if args.pending else SELECTED_DIR
        if not active_dir.is_dir():
            print(f"[Error] Directory not found: {active_dir}")
            sys.exit(1)
        case_dirs = sorted([p for p in active_dir.iterdir() if p.is_dir()])

    print(f"================================================================")
    print(f" Ground Truth Blocker Classifier Benchmark")
    print(f" Backend: {args.backend} | Model: {args.model} | Cases: {len(case_dirs)}")
    print(f"================================================================\n")

    results = []
    correct_count = 0

    for idx, c_dir in enumerate(case_dirs, 1):
        print(f"[{idx}/{len(case_dirs)}] Evaluating {c_dir.name}...")
        res = run_case(c_dir, args.backend, args.model)
        results.append(res)

        status_str = "MATCH (OK)" if res.get("is_correct") else "MISMATCH (FAIL)"
        if res.get("is_correct"):
            correct_count += 1

        print(f"  -> GT:   {res.get('gt_label')}")
        print(f"  -> Pred: {res.get('pred_label')} [{status_str}] ({res.get('elapsed_seconds')}s)")
        print()

    accuracy = (correct_count / len(results)) * 100 if results else 0
    print(f"================================================================")
    print(f" Benchmark Finished: {correct_count}/{len(results)} Correct ({accuracy:.1f}%)")
    print(f"================================================================")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"results": results, "summary": {"total": len(results), "correct": correct_count, "accuracy": accuracy}}, f, indent=2)
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
