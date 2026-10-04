#!/usr/bin/env python3
"""
Extract Dependent-Failed Blocker Cases for Ground Truth Benchmark.
Scans historical experiments/ for all blocker attempts where the LLM classified
the blocker as 'Input Dependent' but the pipeline failed (success == False).
Exports them into ground_truth/cases/pending_cases/ for human audit and triage.
"""

import argparse
import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent
CASES_DIR = BENCHMARK_DIR / "cases"
SELECTED_DIR = CASES_DIR / "selected_cases"
PENDING_DIR = CASES_DIR / "pending_cases"
REPO_ROOT = BENCHMARK_DIR.parent
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
OSS_FUZZ_PROJECTS = REPO_ROOT / "external" / "oss-fuzz" / "projects"


def sanitize_filename(name: str) -> str:
    """Sanitize C++ function signatures and names into valid filesystem paths."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", name)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned[:80]


def load_dependent_failed_records() -> list:
    """Load all blocker attempts where dependency == 'Input Dependent' and success == False."""
    records = []

    for fpath in sorted(EXPERIMENTS_DIR.glob("*/blocker_attempts.jsonl")):
        exp = fpath.parent.name
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("dependency_result") == "Input Dependent" and data.get("success") is False:
                        parts = exp.split("_")
                        proj = parts[2] if len(parts) >= 3 else exp
                        data["project_name"] = proj
                        data["experiment_id"] = exp
                        data["record_line"] = line_no
                        records.append(data)
                except Exception:
                    pass

    return records


def find_harness_file(project_name: str, target_name: str) -> Path | None:
    """Find the harness source file under external/oss-fuzz/projects/."""
    if not target_name:
        return None

    # First check project-specific directory
    proj_dir = OSS_FUZZ_PROJECTS / project_name
    if proj_dir.is_dir():
        for ext in (".cc", ".cpp", ".c", ".cxx"):
            cand = proj_dir / f"{target_name}{ext}"
            if cand.is_file():
                return cand

    # Fallback search across all projects
    for cand in OSS_FUZZ_PROJECTS.glob(f"**/{target_name}.*"):
        if cand.is_file() and cand.suffix in (".cc", ".cpp", ".c", ".cxx"):
            return cand

    return None


def extract_prompts_index() -> dict:
    """Index all prompt texts from existing run.log files by (project, function, branch_line)."""
    prompts_index = {}
    marker = "================ Generated Prompt ================"

    for log_path in sorted(EXPERIMENTS_DIR.glob("*/run.log")):
        if not log_path.exists() or log_path.stat().st_size < 1000:
            continue
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        chunks = content.split(marker)
        for chunk in chunks[1:]:
            end_idx = chunk.find("LLM response:")
            if end_idx == -1:
                end_idx = chunk.find("INFO: Dispatching:")
            prompt_text = chunk[:end_idx] if end_idx != -1 else chunk[:30000]

            m_proj = re.search(r"\*\*Project Name\*\*:\s*(\w+)", prompt_text)
            m_func = re.search(r"\*\*Function containing the blocked branch\*\*:\s*([^\n\r]+)", prompt_text)
            m_branch = re.search(r"\*\*Branch Line Number[^\*]*\*\*:\s*`?(\d+)`?", prompt_text)

            if m_func and m_branch:
                proj = m_proj.group(1).strip() if m_proj else ""
                func = m_func.group(1).strip()
                branch = m_branch.group(1).strip()
                prompts_index[(proj, func, branch)] = prompt_text
                prompts_index[(func, branch)] = prompt_text

    return prompts_index


def parse_tag(prompt_text: str, tag: str, default: str = "") -> str:
    m = re.search(rf"<{tag}>\n(.*?)\n</{tag}>", prompt_text, re.DOTALL)
    return m.group(1) if m else default


def main():
    parser = argparse.ArgumentParser(description="Extract all Input Dependent failed blockers into pending_cases/")
    parser.add_argument("--list-only", action="store_true", help="List cases without writing files")
    parser.add_argument("--project", default=None, help="Filter by specific project (e.g. cjson, libpcap, zlib)")
    parser.add_argument("--output-dir", default=str(PENDING_DIR), help="Output directory for pending cases")
    args = parser.parse_args()

    records = load_dependent_failed_records()

    # Group and deduplicate by (project, function_name, branch_line_number)
    unique_cases = {}
    for r in records:
        proj = r.get("project_name", "unknown")
        func = r.get("function_name", "")
        branch = str(r.get("branch_line_number", ""))
        key = (proj, func, branch)
        if key not in unique_cases:
            unique_cases[key] = r

    if args.project:
        unique_cases = {k: v for k, v in unique_cases.items() if k[0].lower() == args.project.lower()}

    print("================================================================")
    print(f" Dependent-Failed Cases Extractor")
    print(f" Found {len(records)} total records | {len(unique_cases)} unique blocker cases")
    print("================================================================\n")

    if args.list_only:
        by_proj = defaultdict(list)
        for (proj, func, branch), r in sorted(unique_cases.items()):
            by_proj[proj].append(r)

        for proj, items in sorted(by_proj.items()):
            print(f"Project: {proj} ({len(items)} cases)")
            for item in items:
                fn = item.get("function_name")
                bl = item.get("branch_line_number")
                bld = item.get("blocked_side_line_number")
                tgt = item.get("target_name")
                stg = item.get("pipeline_failure_stage")
                exp = item.get("experiment_id")
                print(f"  - {fn}:{bl} -> {bld} (target: {tgt}, stage: {stg}, exp: {exp})")
            print()
        return

    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    prompts_index = extract_prompts_index()

    extracted_count = 0
    harness_found_count = 0
    prompt_found_count = 0

    for (proj, func, branch), item in sorted(unique_cases.items()):
        bld = str(item.get("blocked_side_line_number", ""))
        tgt = item.get("target_name", "fuzz_target")
        safe_func = sanitize_filename(func)
        case_id = f"{proj}_{safe_func}_{branch}"
        if (SELECTED_DIR / case_id).exists():
            # Skip if this blocker is already reviewed and present in selected_cases/
            continue

        case_dir = output_path / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        # 1. Find Harness
        harness_path = find_harness_file(proj, tgt)
        target_source_rel = str(harness_path.relative_to(REPO_ROOT)) if harness_path else None

        # 2. Write meta.json
        meta = {
            "case_id": case_id,
            "project_name": proj,
            "function_name": func,
            "branch_line_number": int(branch) if branch.isdigit() else branch,
            "blocked_side_line_number": int(bld) if bld.isdigit() else bld,
            "target_name": tgt,
            "target_source_path": target_source_rel,
            "historical_prediction": "Input Dependent",
            "historical_success": False,
            "pipeline_failure_stage": item.get("pipeline_failure_stage"),
            "pipeline_methods": item.get("pipeline_methods", []),
            "pipeline_output_dir": item.get("pipeline_output_dir"),
            "historical_reason": item.get("reason"),
            "historical_analysis_trace": item.get("analysis_trace", []),
            "source_experiment": item.get("experiment_id"),
            "verification_status": "pending_review",
            "ground_truth_label": "TBD",
            "ground_truth_rule": "TBD",
            "refined_triage_label": "TBD",
            "include_in_solver_evaluation": None,
            "ground_truth_reason_steps": {
                "step_1_predicate_and_target_state": "TBD",
                "step_2_producer_and_input_control": "TBD",
                "step_3_survival_and_path_invariants": "TBD",
                "step_4_alternative_path_and_feasibility": "TBD",
                "step_5_final_adjudication": "TBD",
            },
            "ground_truth_reason": "Pending human triage and verification.",
        }
        (case_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        # 3. Attach Harness if found (Standardized as fuzz_target.cc only)
        if harness_path and harness_path.is_file():
            shutil.copy2(harness_path, case_dir / "fuzz_target.cc")
            harness_found_count += 1

        # 4. Attach prompt context if available in prompt index
        prompt_text = prompts_index.get((proj, func, branch)) or prompts_index.get((func, branch))
        if prompt_text:
            runtime_seg = parse_tag(prompt_text, "runtime_blocker_segment")
            runtime_src = parse_tag(prompt_text, "runtime_blocker_segment_source_codes")
            cfg_chain = parse_tag(prompt_text, "cfg_call_chain")
            cfg_src = parse_tag(prompt_text, "cfg_source_codes")
            header = parse_tag(prompt_text, "header_code")

            if runtime_seg:
                (case_dir / "runtime_blocker_segment.txt").write_text(runtime_seg, encoding="utf-8")
            if runtime_src:
                (case_dir / "runtime_blocker_segment_source_codes.txt").write_text(runtime_src, encoding="utf-8")
            if cfg_chain:
                (case_dir / "cfg_call_chain.txt").write_text(cfg_chain, encoding="utf-8")
            if cfg_src:
                (case_dir / "cfg_source_codes.txt").write_text(cfg_src, encoding="utf-8")
            if header:
                (case_dir / "header.h").write_text(header, encoding="utf-8")
            prompt_found_count += 1

        extracted_count += 1

    print(f"Successfully extracted {extracted_count} cases to: {output_path}")
    print(f" - Harness files attached: {harness_found_count} / {extracted_count}")
    print(f" - Prompt contexts attached: {prompt_found_count} / {extracted_count}")
    print("\nNext step: Inspect cases in ground_truth/cases/pending_cases/ and triage them!")


if __name__ == "__main__":
    main()
