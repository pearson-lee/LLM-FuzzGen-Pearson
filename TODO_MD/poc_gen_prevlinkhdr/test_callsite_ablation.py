#!/usr/bin/env python3
"""Ablation: does the NEW blocker-call-sites evidence flip the seed generator from
"unconditional" to selecting a predicate-compatible call site + combined seed?

Two arms, same template + same real gen_prevlinkhdr_check context:
  - old : {blocker_call_sites} = "N/A" (pre-change evidence)
  - new : {blocker_call_sites} = enumerate_textual_call_sites(...) rendered

For each arm x N runs, report 4 dev-case metrics (Codex):
  1. correctly REJECTS 3208 (the !is_geneve callsite)
  2. does not select build-inactive 5267
  3. selects verified 7238, or explicitly sets evidence_sufficient=false
  4. a sample seed actually REACHES gencode.c:3150 (poc2 + gdb on gen_geneve_ll_check)

Integrity: prompt carries NO answer string; the model derives the combination from the
call-site source evidence.

Usage:
  .venv/bin/python TODO_MD/poc_gen_prevlinkhdr/test_callsite_ablation.py \
      [--runs 3] [--arm both|old|new] [--backend vertexai] [--model gemini-2.5-flash] [--no-reach]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT))

import importlib.util

_spec = importlib.util.spec_from_file_location("t0c2", HERE / "test_0c2_prompt.py")
t0c2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(t0c2)

from blocker_process.blocker_callpath_extractor import (  # noqa: E402
    enumerate_textual_call_sites,
    render_call_sites_for_prompt,
)
from blocker_process.dependent.input_dependent_seed_generator import (  # noqa: E402
    extract_json,
    validate_generator,
    write_generator,
)

GENCODE = REPO_ROOT / "external/oss-fuzz/build/out/libpcap/source_code/gencode.c"
POC2 = HERE / "poc2"
VERIFIED_CALLSITE = "gencode.c:7238"
LINK_TERMS = ("ether ", "ether host", "ether dst", "ether broadcast", "ether multicast",
              "vlan", "ehost", "wlan", "link host", "link broadcast", "link multicast",
              "link-layer", "link layer")
REQUIRED_DECISION_FIELDS = {
    "selected_candidate_id",
    "observed_guard",
    "compatibility_reason",
    "input_trigger",
    "evidence_sufficient",
    "rejected_conflicting_callsites",
}
REQUIRED_TOP_LEVEL_FIELDS = {
    "analysis_summary",
    "failure_analysis",
    "family_decisions",
    "revision_plan",
    "generator_design_rationale",
    "generator_filename",
    "generator_code",
    "sample_seeds",
    "callsite_decision",
}
REQUIRED_ANALYSIS_PREFIXES = (
    "[0A API Anchor]",
    "[0B Input Layout]",
    "[0C Predicate Setter]",
    "[0C2 Call-Site Reachability]",
    "[0D Reader Path]",
    "[0E Survival Check]",
)
MAX_MATERIALIZED_SEEDS = 200
MAX_MATERIALIZED_SEED_BYTES = 1 << 20


def reaches_3150(filter_str: str) -> bool:
    """True if compiling `filter_str` hits gen_geneve_ll_check (sole caller = line 3150)."""
    if not POC2.exists():
        return False
    try:
        out = subprocess.run(
            ["gdb", "-q", "-batch", "-ex", "break gen_geneve_ll_check", "-ex", "run",
             "--args", str(POC2), filter_str],
            capture_output=True, text=True, timeout=60,
            env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0", "PATH": "/usr/bin:/bin"},
        )
        return "Breakpoint 1, gen_geneve_ll_check" in (out.stdout + out.stderr)
    except Exception:
        return False


def extract_filter(sample_seed: str) -> str:
    s = str(sample_seed)
    if ": " in s:
        s = s.split(": ", 1)[1]
    return s.strip().strip("'\"")


def collect_materialized_text_seeds(generated_dir: Path) -> list[dict]:
    """Load actual generated payloads accepted by this text-filter POC."""
    records = []
    for path in sorted(generated_dir.rglob("*")):
        if not path.is_file() or len(records) >= MAX_MATERIALIZED_SEEDS:
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            continue
        if len(payload) > MAX_MATERIALIZED_SEED_BYTES or b"\0" in payload:
            continue
        try:
            text_payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        records.append(
            {
                "path": str(path),
                "relative_path": str(path.relative_to(generated_dir)),
                "size_bytes": len(payload),
                "text": text_payload,
            }
        )
    return records


def validate_callsite_decision(
    parsed: dict,
    candidate_ids: set[str],
    candidate_build_status: dict[str, str] | None = None,
) -> list[str]:
    errors = []
    missing_top_level = sorted(REQUIRED_TOP_LEVEL_FIELDS - set(parsed))
    unexpected_top_level = sorted(set(parsed) - REQUIRED_TOP_LEVEL_FIELDS)
    if missing_top_level:
        errors.append(f"missing top-level fields: {', '.join(missing_top_level)}")
    if unexpected_top_level:
        errors.append(f"unexpected top-level fields: {', '.join(unexpected_top_level)}")

    analysis_summary = parsed.get("analysis_summary")
    if not isinstance(analysis_summary, list) or len(analysis_summary) < len(REQUIRED_ANALYSIS_PREFIXES):
        errors.append("analysis_summary must contain the six ordered evidence-contract entries")
    else:
        for index, prefix in enumerate(REQUIRED_ANALYSIS_PREFIXES):
            if not str(analysis_summary[index]).startswith(prefix):
                errors.append(f"analysis_summary[{index}] must start with {prefix}")

    for key in ("failure_analysis", "family_decisions", "revision_plan", "sample_seeds"):
        if not isinstance(parsed.get(key), list):
            errors.append(f"{key} must be an array")
    if isinstance(parsed.get("sample_seeds"), list) and not parsed["sample_seeds"]:
        errors.append("sample_seeds must not be empty")
    for key in ("generator_design_rationale", "generator_filename", "generator_code"):
        if not isinstance(parsed.get(key), str) or not parsed[key].strip():
            errors.append(f"{key} must be a non-empty string")

    decision = parsed.get("callsite_decision")
    if not isinstance(decision, dict):
        return ["missing top-level callsite_decision object"]

    missing = sorted(REQUIRED_DECISION_FIELDS - set(decision))
    if missing:
        errors.append(f"missing callsite_decision fields: {', '.join(missing)}")

    selected = str(decision.get("selected_candidate_id", "")).strip()
    if not selected:
        errors.append("selected_candidate_id is empty")
    elif selected != "unknown" and selected not in candidate_ids:
        errors.append(f"selected_candidate_id is not a provided candidate: {selected}")

    if not isinstance(decision.get("evidence_sufficient"), bool):
        errors.append("evidence_sufficient must be boolean")
    elif (
        candidate_build_status
        and selected != "unknown"
        and candidate_build_status.get(selected) == "unknown"
        and decision.get("evidence_sufficient") is not False
    ):
        errors.append("selecting a build_status=unknown callsite requires evidence_sufficient=false")
    if selected == "unknown" and decision.get("evidence_sufficient") is not False:
        errors.append("selected_candidate_id=unknown requires evidence_sufficient=false")
    if not isinstance(decision.get("rejected_conflicting_callsites"), list):
        errors.append("rejected_conflicting_callsites must be an array")
    return errors


def evaluate_parsed(
    parsed: dict,
    check_reach: bool,
    materialized_seeds: list[dict] | None = None,
) -> dict:
    sample_seed_texts = [extract_filter(s) for s in parsed.get("sample_seeds", [])]
    seeds = (
        [str(record["text"]) for record in materialized_seeds]
        if materialized_seeds is not None
        else sample_seed_texts
    )
    decision = parsed.get("callsite_decision", {}) or {}
    selected = str(decision.get("selected_candidate_id", "")).strip()
    rejected = decision.get("rejected_conflicting_callsites", [])

    # A rejection is only credited when 3208 is explicitly named and rejected.
    rejects_3208 = any(
        "3208" in str(item.get("candidate_id", ""))
        for item in rejected
        if isinstance(item, dict)
    )
    avoids_inactive_5267 = selected != "gencode.c:5267"
    selects_verified_7238 = selected == VERIFIED_CALLSITE
    reports_insufficient = decision.get("evidence_sufficient") is False
    verified_or_insufficient = selects_verified_7238 or reports_insufficient
    combined = any(
        "geneve" in seed.lower() and any(term in seed.lower() for term in LINK_TERMS)
        for seed in seeds
    )
    reached = False
    reach_seed = ""
    if check_reach:
        for seed in seeds:
            if "geneve" in seed.lower() and reaches_3150(seed):
                reached, reach_seed = True, seed
                break

    return {
        "selected_candidate_id": decision.get("selected_candidate_id"),
        "evidence_sufficient": decision.get("evidence_sufficient"),
        "rejects_3208": rejects_3208,
        "avoids_inactive_5267": avoids_inactive_5267,
        "selects_verified_7238": selects_verified_7238,
        "reports_insufficient": reports_insufficient,
        "verified_or_insufficient": verified_or_insufficient,
        "materialized_seed_count": len(materialized_seeds or []),
        "evaluated_seed_count": len(seeds),
        "combined_seed": combined,
        "reached_3150": reached,
        "reach_seed": reach_seed,
        "0c2_snippet": next(
            (x for x in parsed.get("analysis_summary", []) if "0c2" in str(x).lower()),
            "",
        )[:240],
    }


def run_once(
    mapping: dict,
    template: str,
    backend: str,
    model: str,
    check_reach: bool,
    candidate_ids: set[str],
    candidate_build_status: dict[str, str] | None,
    artifact_dir: Path,
    retries: int,
) -> dict:
    from llm_interface.llm_client import LLMClient

    prompt = t0c2.format_prompt(template, mapping)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    client = LLMClient(backend=backend, model_name=model, temperature=0.3)
    last_parsed = None
    last_failure = "unknown"
    for attempt in range(1, retries + 2):
        response = client.generate(prompt) or ""
        (artifact_dir / f"response_attempt_{attempt:02d}.txt").write_text(response, encoding="utf-8")
        if not response.strip():
            last_failure = "empty_response"
            continue
        try:
            parsed = extract_json(response)
        except Exception as exc:
            last_failure = f"json_parse_error: {exc}"
            continue

        last_parsed = parsed
        (artifact_dir / f"parsed_attempt_{attempt:02d}.json").write_text(
            json.dumps(parsed, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        schema_errors = validate_callsite_decision(parsed, candidate_ids, candidate_build_status)
        if schema_errors:
            last_failure = "schema_invalid: " + "; ".join(schema_errors)
            continue

        generator_attempt_dir = artifact_dir / f"generator_attempt_{attempt:02d}"
        generator_attempt_dir.mkdir(parents=True, exist_ok=True)
        generator_path = write_generator(
            generator_attempt_dir,
            str(parsed["generator_code"]),
            str(parsed["generator_filename"]),
        )
        validation = validate_generator(generator_path, generator_attempt_dir)
        serializable_validation = {
            **validation,
            "generated_dir": str(validation.get("generated_dir", "")),
            "generator_path": str(generator_path),
        }
        (generator_attempt_dir / "validation.json").write_text(
            json.dumps(serializable_validation, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        if not validation.get("ok"):
            last_failure = (
                f"generator_invalid: {validation.get('error_kind')}: "
                f"{str(validation.get('output', '')).strip()[:500]}"
            )
            continue

        generated_dir = Path(validation["generated_dir"])
        materialized_seeds = collect_materialized_text_seeds(generated_dir)
        (generator_attempt_dir / "materialized_seed_manifest.json").write_text(
            json.dumps(
                [{k: v for k, v in record.items() if k != "text"} for record in materialized_seeds],
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        if not materialized_seeds:
            last_failure = "generator_invalid: no text payloads suitable for the libpcap POC"
            continue

        result = {
            "status": "valid",
            "attempts_used": attempt,
            "schema_errors": [],
            "generator_validation": serializable_validation,
            **evaluate_parsed(parsed, check_reach, materialized_seeds),
        }
        (artifact_dir / "result.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return result

    result = {
        "status": (
            "generator_invalid"
            if last_failure.startswith("generator_invalid:")
            else "schema_invalid"
            if last_parsed is not None
            else "technical_failure"
        ),
        "attempts_used": retries + 1,
        "error": last_failure,
        "schema_errors": (
            validate_callsite_decision(last_parsed, candidate_ids, candidate_build_status)
            if last_parsed is not None
            else []
        ),
    }
    # Preserve execution evidence even when the response violated the audit schema.
    if last_parsed is not None:
        result.update(evaluate_parsed(last_parsed, False))
    (artifact_dir / "result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--arm", choices=["both", "old", "new"], default="both")
    ap.add_argument("--backend", default="vertexai")
    ap.add_argument("--model", default="gemini-2.5-flash")
    ap.add_argument("--no-reach", action="store_true", help="skip poc2/gdb reachability (metric 4)")
    ap.add_argument("--retries", type=int, default=1, help="retries after empty/invalid LLM output")
    ap.add_argument("--output-dir", default=None, help="directory for prompts, responses, and parsed results")
    args = ap.parse_args()

    saved = t0c2.SAVED_PROMPT.read_text(encoding="utf-8", errors="ignore")
    base_mapping = t0c2.build_mapping(saved)
    template = t0c2.load_text(t0c2.TEMPLATE_PATH)

    cs = enumerate_textual_call_sites("libpcap", "gen_prevlinkhdr_check", str(GENCODE))
    new_evidence = render_call_sites_for_prompt(cs)
    all_candidate_ids = {str(entry["candidate_id"]) for entry in cs["entries"]}
    selectable_entries = [entry for entry in cs["entries"] if entry.get("build_status") != "inactive"]
    selectable_candidate_ids = {str(entry["candidate_id"]) for entry in selectable_entries}
    selectable_build_status = {
        str(entry["candidate_id"]): str(entry.get("build_status", "unknown"))
        for entry in selectable_entries
    }
    run_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) if args.output_dir else HERE / "ablation_runs" / run_stamp
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[i] enumerated {cs['included_candidates']} call sites: {[e['line'] for e in cs['entries']]}")
    print(f"[i] poc2 present: {POC2.exists()} | reachability check: {not args.no_reach}\n")
    print(f"[i] artifacts: {output_dir}\n")

    arms = ["old", "new"] if args.arm == "both" else [args.arm]
    evidence = {"old": "N/A: (call-site enumeration not available in this arm)", "new": new_evidence}

    for arm in arms:
        mapping = dict(base_mapping)
        mapping["blocker_call_sites"] = evidence[arm]
        agg = {
            "rejects_3208": 0,
            "avoids_inactive_5267": 0,
            "selects_verified_7238": 0,
            "reports_insufficient": 0,
            "verified_or_insufficient": 0,
            "combined_seed": 0,
            "reached_3150": 0,
        }
        valid_agg = dict.fromkeys(agg, 0)
        status_counts = {
            "valid": 0,
            "schema_invalid": 0,
            "generator_invalid": 0,
            "technical_failure": 0,
        }
        print(f"================= ARM: {arm} =================")
        for r in range(1, args.runs + 1):
            res = run_once(
                mapping,
                template,
                args.backend,
                args.model,
                not args.no_reach,
                all_candidate_ids if arm == "old" else selectable_candidate_ids,
                None if arm == "old" else selectable_build_status,
                output_dir / arm / f"run_{r:02d}",
                max(0, args.retries),
            )
            status_counts[res["status"]] += 1
            for k in agg:
                agg[k] += int(bool(res.get(k)))
                if res["status"] == "valid":
                    valid_agg[k] += int(bool(res.get(k)))
            print(
                f"  run {r}: status={res['status']} attempts={res['attempts_used']} "
                f"sel={res.get('selected_candidate_id')} ev_suff={res.get('evidence_sufficient')} "
                f"rej3208={res.get('rejects_3208', False)} "
                f"avoid5267={res.get('avoids_inactive_5267', False)} "
                f"sel7238={res.get('selects_verified_7238', False)} "
                f"insufficient={res.get('reports_insufficient', False)} "
                f"seeds={res.get('materialized_seed_count', 0)} "
                f"combined={res.get('combined_seed', False)} reached3150={res.get('reached_3150', False)}"
                + (f" [{res['reach_seed']}]" if res.get("reach_seed") else "")
                + (f" error={res['error']}" if res.get("error") else "")
            )
        n = args.runs
        valid_n = status_counts["valid"]
        print(
            f"  --- all planned runs ({n}): rejects_3208={agg['rejects_3208']}/{n} "
            f"avoids_inactive_5267={agg['avoids_inactive_5267']}/{n} "
            f"selects_verified_7238={agg['selects_verified_7238']}/{n} "
            f"verified_or_insufficient={agg['verified_or_insufficient']}/{n} "
            f"combined={agg['combined_seed']}/{n} "
            f"REACHED_3150={agg['reached_3150']}/{n} (primary)"
        )
        print(
            f"  --- valid-schema runs ({valid_n}): rejects_3208={valid_agg['rejects_3208']}/{valid_n} "
            f"avoids_inactive_5267={valid_agg['avoids_inactive_5267']}/{valid_n} "
            f"selects_verified_7238={valid_agg['selects_verified_7238']}/{valid_n} "
            f"verified_or_insufficient={valid_agg['verified_or_insufficient']}/{valid_n} "
            f"combined={valid_agg['combined_seed']}/{valid_n} "
            f"REACHED_3150={valid_agg['reached_3150']}/{valid_n}"
            if valid_n
            else "  --- valid-schema runs: 0 (semantic rates unavailable)"
        )
        print(f"  --- statuses: {status_counts}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
