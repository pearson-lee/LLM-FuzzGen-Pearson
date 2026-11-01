#!/usr/bin/env python3
"""Validate the selector's LLM branch priority against ground-truth cases (design H1, checks A/B).

For every case under ground_truth/cases/selected_cases the tool rebuilds the same prompt the
selector would send, classifies it `--repeats` times, and compares the derived tier with the
ground-truth refined label:

    python3 tools/eval_llm_branch_priority.py --repeats 3
    python3 tools/eval_llm_branch_priority.py --case tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494
"""
import argparse
import collections
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import blocker_process.global_blocker_selector as selector  # noqa: E402

CASES_ROOT = REPO_ROOT / "ground_truth" / "cases" / "selected_cases"
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".inl"}
# GT uses one label outside the selector taxonomy.
GT_LABEL_ALIASES = {"External Resource Failure": "Environmental Failure"}


def gt_side(meta: dict) -> str:
    label = GT_LABEL_ALIASES.get(meta.get("refined_triage_label") or "", meta.get("refined_triage_label") or "")
    if label in selector._LLM_SOLVABLE_CATEGORIES:
        return "solvable"
    if label in selector._LLM_UNSOLVABLE_CATEGORIES:
        return "unsolvable"
    return "unlabeled"


def source_roots(project: str) -> list[Path]:
    roots = [
        REPO_ROOT / "external" / project,
        REPO_ROOT / "external" / "oss-fuzz" / "build" / "out" / project / "src" / project,
        REPO_ROOT / "external" / "oss-fuzz" / "build" / "out" / project / "src",
    ]
    return [root for root in roots if root.is_dir()]


def branch_line_looks_right(code_lines: list[str], branch_line: int) -> bool:
    if not 0 < branch_line <= len(code_lines):
        return False
    text = selector._extract_if_statement(code_lines, branch_line)
    return any(token in text for token in ("if", "while", "for", "case", "?", "&&", "||"))


def enclosing_function_matches(code_lines: list[str], branch_line: int, function_name: str) -> bool:
    """True if the nearest unindented signature above the branch defines `function_name`."""
    if not function_name:
        return True
    for index in range(branch_line - 1, -1, -1):
        line = code_lines[index]
        if line[:1].isspace() or not line.strip() or line.lstrip().startswith(("#", "}", "{")):
            continue
        signature = " ".join(code_lines[index:index + 3])
        if "(" not in signature or line.rstrip().endswith(";"):
            continue
        return re.search(rf"\b{re.escape(function_name)}\s*\(", signature) is not None
    return False


def resolve_source(meta: dict) -> tuple[list[str], str, str]:
    """Return (comment-stripped lines, path, how it was resolved); empty lines if not found."""
    project = meta.get("project_name") or ""
    branch_line = int(meta.get("branch_line_number") or 0)
    function_name = str(meta.get("function_name") or "").split("(")[0].split("::")[-1]
    candidates: list[tuple[Path, str]] = []
    declared = str(meta.get("source_file") or "")
    for root in source_roots(project):
        if declared:
            relative = Path(declared.lstrip("/"))
            for candidate in (root / relative, root / Path(*relative.parts[2:]) if len(relative.parts) > 2 else None,
                              root / relative.name):
                if candidate and candidate.is_file():
                    candidates.append((candidate, "declared"))
        if function_name:
            for path in sorted(root.rglob("*")):
                if path.suffix in SOURCE_EXTENSIONS and path.is_file():
                    try:
                        if function_name in path.read_text(encoding="utf-8", errors="replace"):
                            candidates.append((path, "function_search"))
                    except OSError:
                        continue
    seen = set()
    for path, how in candidates:
        if path in seen:
            continue
        seen.add(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = selector._strip_comments_preserve_strings(raw).splitlines()
        if branch_line_looks_right(lines, branch_line) and (
            how == "declared" or enclosing_function_matches(lines, branch_line, function_name)
        ):
            return lines, str(path), how
    return [], "", "not_found"


def build_case_prompt(case_dir: Path, template: str) -> tuple[dict, str, dict]:
    meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))
    code_lines, source_path, how = resolve_source(meta)
    info = {"case": case_dir.name, "source_path": source_path, "source_resolution": how,
            "gt_label": meta.get("ground_truth_label"), "gt_refined": meta.get("refined_triage_label"),
            "gt_side": gt_side(meta)}
    if not code_lines:
        return info, "", meta
    harness = ""
    for name in ("fuzz_target.cc", "fuzz_target.c", "fuzz_target.cpp"):
        if (case_dir / name).is_file():
            harness = (case_dir / name).read_text(encoding="utf-8", errors="replace")
            break
    blocker = {
        "function_name": meta.get("function_name"),
        "source_file": source_path,
        "branch_line_number": meta.get("branch_line_number"),
        "blocked_side_line_number": meta.get("blocked_side_line_number"),
        "blocked_unique_functions": [],
        "project_branch_hit_count": "unknown (offline evaluation)",
    }
    context = selector._llm_priority_context(blocker, code_lines, harness)
    prompt = template
    for name, value in {"project": meta.get("project_name") or "", **context}.items():
        prompt = prompt.replace(f"<<{name}>>", value)
    return info, prompt, meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", action="append", default=[], help="Case directory name (repeatable). Default: all.")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--backend", default="vertexai")
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    case_dirs = [CASES_ROOT / name for name in args.case] if args.case else sorted(
        path for path in CASES_ROOT.iterdir() if (path / "meta.json").is_file()
    )
    output_dir = args.output_dir or REPO_ROOT / "experiments" / f"llm_priority_eval_{datetime.now():%Y%m%d_%H%M%S}"
    output_dir.mkdir(parents=True, exist_ok=True)
    template = selector._LLM_PRIORITY_TEMPLATE.read_text(encoding="utf-8")
    generate = selector._default_llm_priority_generate(args.backend, args.model)

    jobs = []
    for case_dir in case_dirs:
        info, prompt, _ = build_case_prompt(case_dir, template)
        if prompt:
            (output_dir / f"{case_dir.name}.prompt.txt").write_text(prompt, encoding="utf-8")
        for repeat in range(1, args.repeats + 1):
            jobs.append((info, prompt, repeat))

    def run(job: tuple[dict, str, int]) -> dict:
        info, prompt, repeat = job
        row = {**info, "repeat": repeat}
        if not prompt:
            return {**row, "error": "source not resolved"}
        try:
            response = generate(prompt) or ""
            return {**row, **selector._parse_llm_priority_response(response), "raw_response": response}
        except Exception as exc:
            return {**row, "error": f"{type(exc).__name__}: {exc}"}

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        rows = list(pool.map(run, jobs))
    with (output_dir / "results.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    by_case: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        by_case[row["case"]].append(row)
    expected_tier = {"solvable": 2, "unsolvable": 0}
    agree = total = consistent = misplaced = 0
    print(f"{'case':58} {'GT':28} tiers   categories")
    for case, case_rows in sorted(by_case.items()):
        tiers = [r.get("tier") for r in case_rows]
        cats = [r.get("category") or r.get("error", "")[:30] for r in case_rows]
        side = case_rows[0]["gt_side"]
        print(f"{case[:58]:58} {str(case_rows[0]['gt_refined'])[:28]:28} {tiers}  {cats}")
        valid = [t for t in tiers if t is not None]
        if valid and len(set(valid)) == 1 and len(valid) == len(tiers):
            consistent += 1
        if side in expected_tier and valid:
            total += len(valid)
            agree += sum(t == expected_tier[side] for t in valid)
            misplaced += sum(t == 2 - expected_tier[side] for t in valid)
    print(f"\nlabelled verdicts matching GT side: {agree}/{total}; opposite tier: {misplaced}")
    print(f"cases with identical tier across repeats: {consistent}/{len(by_case)}")
    print(f"results: {output_dir / 'results.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
