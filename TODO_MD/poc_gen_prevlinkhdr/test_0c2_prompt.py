#!/usr/bin/env python3
"""Focused offline test for the [0C2 Call-Site Reachability] seed-generator prompt change.

It reuses the REAL gen_prevlinkhdr_check context (extracted verbatim from the saved
generator prompt of the 2026-06-12 run), re-renders the CURRENT template (which now has
[0C2]), makes ONE LLM call, and checks whether the model now:
  1. identifies the independent caller-trigger (a link-layer predicate is needed to CALL
     gen_prevlinkhdr_check), and
  2. produces seeds that COMBINE the geneve setter with a link-layer predicate.

Integrity note: the prompt contains NO answer string. The model must derive the
combination from the call-chain / caller source already present in the context.

Usage:
  .venv/bin/python TODO_MD/poc_gen_prevlinkhdr/test_0c2_prompt.py \
      [--backend vertexai] [--model gemini-2.5-flash]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from blocker_process.dependent.input_dependent_seed_generator import (  # noqa: E402
    TEMPLATE_PATH,
    format_prompt,
    load_text,
)

SAVED_PROMPT = (
    REPO_ROOT
    / "experiments/20260612_020723_run_all_fuzzer/blockers/gen_prevlinkhdr_check_3149"
    / "generator/libpcap_gen_prevlinkhdr_check_20260612_111746/iter_01/prompt.txt"
)

# Exact context headers, in order, mapped to the template placeholder they fill.
SECTION_TO_KEY = [
    ("## Existing fuzz target code", "fuzz_target_code"),
    ("## Related header code", "header_code"),
    ("## Source file excerpt", "source_code"),
    ("## Target function source", "target_function_source"),
    ("## Source window around the branch line", "branch_window"),
    ("## Source window around the blocked side", "blocked_window"),
    ("## Branch predicate description", "branch_predicate_description"),
    ("## Runtime blocker segment", "runtime_blocker_segment"),
    ("## Runtime blocker segment source codes", "runtime_blocker_segment_source_codes"),
    ("## CFG call chain", "cfg_call_chain"),
    ("## CFG source codes", "cfg_source_codes"),
    ("## Format-specific generator guidance", "format_strategy_notes"),
]
# Headers that mark the end of a captured section (any known header or a top-level "# X").
STOP_HEADERS = [h for h, _ in SECTION_TO_KEY] + [
    "## Triggering input hint",
    "## Inferred native input format",
]


def strip_code_fence(body: str) -> str:
    lines = body.strip("\n").splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


def extract_sections(prompt: str) -> dict[str, str]:
    lines = prompt.splitlines()
    # Index of every known section header line.
    header_idx: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if line.rstrip() in STOP_HEADERS or (
            line.startswith("# ") and not line.startswith("## ") and i > 40
        ):
            header_idx.append((i, line.rstrip()))
    out: dict[str, str] = {}
    for header, key in SECTION_TO_KEY:
        start = next((i for i, h in header_idx if h == header), None)
        if start is None:
            continue
        nexts = [i for i, _ in header_idx if i > start]
        end = min(nexts) if nexts else len(lines)
        body = "\n".join(lines[start + 1 : end])
        out[key] = strip_code_fence(body)
    return out


def build_mapping(prompt: str) -> dict[str, str]:
    ctx = extract_sections(prompt)
    mapping = {
        # Known blocker metadata (NOT the answer — just identifiers).
        "project_name": "libpcap",
        "language": "c",
        "function_name": "gen_prevlinkhdr_check",
        "function_signature": "struct block *gen_prevlinkhdr_check(compiler_state_t *cstate)",
        "possible_headers": "N/A",
        "branch_line_number": "3149",
        "blocked_side_line_number": "3150",
        "source_file": "gencode.c",
        "api_source_file": "gencode.c",
        "fuzz_file": "llm_fuzzgen0626013047.c",
        "fuzz_target_name": "llm_fuzzgen0626013047",
        "triggering_input_path": "N/A",
        "triggering_input_preview": "N/A",
        # Neutral format fields (irrelevant to the [0C2] reasoning under test).
        "format_family": "unknown",
        "format_mime_hint": "N/A",
        "format_is_text": "true",
        "format_extensions": "bpf",
        "format_encoding": "ascii",
        "format_container_style": "N/A",
        "format_features": "N/A",
        "format_confidence": "low",
        "format_reasoning": "N/A",
        "format_info_json": "{}",
        "format_strategy_notes": "N/A",
    }
    mapping.update(ctx)  # real context overrides defaults where present
    return mapping


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="vertexai")
    ap.add_argument("--model", default="gemini-2.5-flash")
    ap.add_argument("--save-prompt", default=str(Path(__file__).parent / "rendered_0c2_prompt.txt"))
    args = ap.parse_args()

    if not SAVED_PROMPT.exists():
        print(f"ERROR: saved context prompt not found: {SAVED_PROMPT}")
        return 2

    saved = SAVED_PROMPT.read_text(encoding="utf-8", errors="ignore")
    mapping = build_mapping(saved)
    template = load_text(TEMPLATE_PATH)
    prompt = format_prompt(template, mapping)
    Path(args.save_prompt).write_text(prompt, encoding="utf-8")
    print(f"[i] rendered prompt -> {args.save_prompt} ({len(prompt)} chars)")
    print(f"[i] context sections filled: {sorted(k for k in mapping if mapping[k] not in ('N/A','unknown','{}','low','ascii','bpf','true'))[:6]} ...")

    from llm_interface.llm_client import LLMClient

    llm = LLMClient(backend=args.backend, model_name=args.model, temperature=0.2)
    print(f"[i] calling {args.backend}/{args.model} ...")
    resp = llm.generate(prompt) or ""
    Path(Path(args.save_prompt).with_name("rendered_0c2_response.txt")).write_text(resp, encoding="utf-8")

    m = re.search(r"\{.*\}", resp, re.DOTALL)
    if not m:
        print("ERROR: no JSON object in response. Raw saved to rendered_0c2_response.txt")
        return 1
    try:
        parsed = json.loads(m.group(0))
    except Exception as exc:
        print(f"ERROR: JSON parse failed: {exc}. Raw saved to rendered_0c2_response.txt")
        return 1

    summary = parsed.get("analysis_summary", [])
    seeds = parsed.get("sample_seeds", [])
    print("\n================ analysis_summary ================")
    for item in summary:
        print(f" - {item}")
    print("\n================ sample_seeds ================")
    for s in seeds:
        print(f" - {s!r}")

    blob = (" ".join(map(str, summary)) + " " + " ".join(map(str, seeds))).lower()
    has_0c2 = any("0c2" in str(x).lower() or "call-site" in str(x).lower() for x in summary)
    has_geneve = "geneve" in blob
    link_terms = [t for t in ("ether ", "ether host", "ether dst", "ether broadcast", "vlan", "ehost", "link-layer", "link layer") if t in blob]
    print("\n================ VERDICT ================")
    print(f"  [0C2] contract item present : {has_0c2}")
    print(f"  mentions geneve (setter)    : {has_geneve}")
    print(f"  mentions link-layer trigger : {bool(link_terms)}  {link_terms}")
    print(f"  >> caller-trigger combined  : {has_geneve and bool(link_terms)}")
    print("\n(Integrity: the prompt contains no answer string; any geneve+link-layer")
    print(" combination was derived by the model from the call-chain/caller source.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
