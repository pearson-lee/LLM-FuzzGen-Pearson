#!/usr/bin/env python3
"""Replay a past blocker's seed-generation stage with its original context.

Every archived experiment records the exact seed-generator command in ``run.log``
(``input_dependent_solver.py`` logs it via ``" ".join(cmd)``), and every iteration
directory keeps the fully rendered ``prompt.txt``. Between the two, a past run can be
reproduced without inventing a single byte of context -- which matters, because a replay
that silently loses the CFG, the runtime blocker segment, or the call-site evidence would
produce success/failure numbers that say nothing about the change under test.

The tool therefore refuses to spend an LLM call until it has proven, section by section,
that the prompt it is about to send still carries everything the archived prompt carried.

Usage:
    replay_blocker_seed_generation.py --list
    replay_blocker_seed_generation.py --experiment DIR --blocker FUNC:LINE --verify-only
    replay_blocker_seed_generation.py --experiment DIR --blocker FUNC:LINE --print
    replay_blocker_seed_generation.py --experiment DIR --blocker FUNC:LINE --run
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SEED_GENERATOR = REPO_ROOT / "blocker_process" / "dependent" / "input_dependent_seed_generator.py"
SOLVER = REPO_ROOT / "blocker_process" / "dependent" / "input_dependent_solver.py"
REPLAY_ROOT = REPO_ROOT / "replays"

_ADD_ARGUMENT = re.compile(r"""add_argument\(\s*["'](--[a-z0-9-]+)""")


def accepted_flags(script: Path) -> list[str]:
    """Read a stage's option strings straight out of its argparse calls.

    The dispatch line in run.log is a plain space-join, so argument boundaries are only
    recoverable by knowing the exact flag set. Hand-maintaining that list silently
    corrupts recovery when a flag is added: the unknown flag gets swallowed into the
    previous argument's value.
    """
    return sorted(set(_ADD_ARGUMENT.findall(script.read_text(encoding="utf-8"))))


SEED_GENERATOR_FLAGS = accepted_flags(SEED_GENERATOR)
SOLVER_FLAGS = accepted_flags(SOLVER)

STAGES = {
    "seedgen": {"script": SEED_GENERATOR, "flags": SEED_GENERATOR_FLAGS},
    "solver": {"script": SOLVER, "flags": SOLVER_FLAGS},
}


def _flag_boundary(flags: list[str]) -> re.Pattern[str]:
    return re.compile(
        r"(?<=\s)(" + "|".join(re.escape(f) for f in sorted(flags, key=len, reverse=True)) + r")\s"
    )


def _dispatch_pattern(script: Path) -> re.Pattern[str]:
    return re.compile(rf"Dispatching: \S*python3?\s+\S*{re.escape(script.name)}")


_LOG_LINE_START = re.compile(r"\n(?=\d{2}:\d{2}:\d{2} - |INFO: |ERROR: |WARNING: |DEBUG: |CRITICAL: )")
_BLOCKER_DIR = re.compile(r"^(.*)_(\d+)$")

# Large context values are passed as files rather than inline: the recovered values are
# multi-line, and a file also lets the caller inspect exactly what was sent.
CONTEXT_FILE_ARGS = {
    "--runtime-blocker-segment": ("--runtime-blocker-segment-file", "runtime_blocker_segment.txt"),
    "--runtime-blocker-segment-source-codes": (
        "--runtime-blocker-segment-source-codes-file", "runtime_blocker_segment_source_codes.txt",
    ),
    "--cfg-call-chain": ("--cfg-call-chain-file", "cfg_call_chain.txt"),
    "--cfg-source-codes": ("--cfg-source-codes-file", "cfg_source_codes.txt"),
    "--blocker-call-sites": ("--blocker-call-sites-file", "blocker_call_sites.txt"),
}

# Prompt section -> the archived section that carries the same content. The mutator
# template renamed one heading; everything else is verbatim from the fresh template.
SECTION_ALIASES = {"Base seed": "Triggering input hint"}

# Sections whose content is derived from a file argument, so a missing local file can be
# repaired by writing the archived text back out.
SECTION_TO_FILE_ARG = {
    "Related header code": "--header-file",
    "Existing fuzz target code": "--fuzz-file",
}

VERIFY_SHRINK_TOLERANCE = 0.90


def read_log_text(path: Path) -> str:
    # Prompts embed raw seed previews, so archived logs are not always valid UTF-8.
    return path.read_text(encoding="utf-8", errors="replace")


def parse_dispatched_commands(run_log: Path, stage: str = "seedgen") -> dict[tuple[str, str], dict[str, str]]:
    """Recover each dispatched argv from a run log, keyed by (function, branch line)."""
    if not run_log.is_file():
        return {}
    spec = STAGES[stage]
    dispatch = _dispatch_pattern(spec["script"])
    boundary_re = _flag_boundary(spec["flags"])
    text = read_log_text(run_log)
    commands: dict[tuple[str, str], dict[str, str]] = {}
    for match in dispatch.finditer(text):
        tail = text[match.end():]
        boundary = _LOG_LINE_START.search(tail)
        raw = tail[: boundary.start()] if boundary else tail
        spans = [(m.group(1), m.start(), m.end()) for m in boundary_re.finditer(raw)]
        parsed: dict[str, str] = {}
        repeated: dict[str, list[str]] = {}
        for index, (flag, _start, value_start) in enumerate(spans):
            value_end = spans[index + 1][1] if index + 1 < len(spans) else len(raw)
            value = raw[value_start:value_end].strip()
            if flag == "--seed":
                # The solver takes --seed once per corpus seed.
                repeated.setdefault(flag, []).append(value)
            else:
                parsed[flag] = value
        for flag, values in repeated.items():
            parsed[flag] = values  # type: ignore[assignment]
        key = (parsed.get("--function-name", ""), parsed.get("--branch-line-number", ""))
        if key != ("", ""):
            # Later dispatches supersede earlier ones for the same blocker.
            commands[key] = parsed
    return commands


def parse_prompt_sections(prompt_path: Path) -> dict[str, str]:
    """Split an archived prompt into its ``## `` context sections."""
    text = prompt_path.read_text(encoding="utf-8", errors="replace")
    sections: dict[str, str] = {}
    headings = list(re.finditer(r"^(#{1,2}) (.+?)\s*$", text, re.M))
    for index, heading in enumerate(headings):
        if len(heading.group(1)) != 2:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[heading.end():end]
        body = re.sub(r"^\s*```[a-zA-Z]*\n", "", body)
        body = re.sub(r"\n```\s*$", "", body.rstrip())
        sections[heading.group(2).strip()] = body.strip()
    return sections


def latest_generator_run(blocker_dir: Path) -> Path | None:
    runs = sorted(p for p in (blocker_dir / "generator").glob("*") if p.is_dir())
    return runs[-1] if runs else None


def archived_prompt_path(blocker_dir: Path) -> Path | None:
    run = latest_generator_run(blocker_dir)
    if run is None:
        return None
    for iteration in sorted(run.glob("iter_*")):
        candidate = iteration / "prompt.txt"
        if candidate.is_file():
            return candidate
    return None


def archived_trigger_seeds(blocker_dir: Path) -> list[Path]:
    run = latest_generator_run(blocker_dir)
    if run is None:
        return []
    return [
        seed
        for iteration in sorted(run.glob("iter_*"))
        for seed in sorted((iteration / "triggering_input_materialized").glob("*"))
        if seed.is_file()
    ]


def remap_experiment_path(value: str, experiment: Path) -> str:
    """Rewrite a stale ``experiments/<old-run>/`` prefix onto the real directory."""
    if not value or Path(value).exists():
        return value
    if not value.startswith("experiments/"):
        return value
    remapped = re.sub(r"^experiments/[^/]+/", f"{experiment.as_posix().rstrip('/')}/", value)
    return remapped if Path(remapped).exists() else value


def load_solve_status(experiment: Path) -> dict[tuple[str, str], bool]:
    status: dict[tuple[str, str], bool] = {}
    attempts = experiment / "blocker_attempts.jsonl"
    if not attempts.is_file():
        return status
    for line in attempts.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event") != "blocker_breakthrough_validation":
            continue
        key = (str(record.get("function_name", "")), str(record.get("branch_line_number", "")))
        status[key] = bool(record.get("blocked_side_newly_reached")) or bool(
            record.get("blocker_solved_immediately")
        )
    return status


def discover_cases(experiment: Path, stage: str = "seedgen") -> list[dict]:
    commands = parse_dispatched_commands(experiment / "run.log", stage)
    status = load_solve_status(experiment)
    cases: list[dict] = []
    for generator_dir in sorted((experiment / "blockers").glob("*/generator")):
        blocker_dir = generator_dir.parent
        match = _BLOCKER_DIR.match(blocker_dir.name)
        function_name, branch_line = (
            (match.group(1), match.group(2)) if match else (blocker_dir.name, "")
        )
        key = (function_name, branch_line)
        cases.append(
            {
                "experiment": experiment,
                "blocker_dir": blocker_dir,
                "function_name": function_name,
                "branch_line": branch_line,
                "solved": status.get(key),
                "argv": commands.get(key),
                "prompt": archived_prompt_path(blocker_dir),
                "archived_triggers": archived_trigger_seeds(blocker_dir),
            }
        )
    return cases


def experiment_dirs() -> list[Path]:
    root = REPO_ROOT / "experiments"
    return sorted(p for p in root.glob("*") if p.is_dir() and (p / "blockers").is_dir())


def build_replay(
    case: dict,
    replay_dir: Path,
    overrides: dict[str, str],
    stage: str = "seedgen",
) -> dict:
    """Materialize a runnable argv, repairing anything the archive has to supply."""
    if not case["argv"]:
        raise SystemExit(
            f"No {stage} dispatch found in run.log for "
            f"{case['function_name']}:{case['branch_line']}"
        )
    if case["prompt"] is None:
        raise SystemExit(
            f"No archived prompt.txt for {case['function_name']}:{case['branch_line']}; "
            "context completeness cannot be verified."
        )

    argv = dict(case["argv"])
    experiment = case["experiment"]
    sections = parse_prompt_sections(case["prompt"])
    recovered_dir = replay_dir / "recovered"
    recovered_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []

    # 1. Stale experiment-directory prefixes.
    for flag in ("--source-file", "--fuzz-file", "--header-file", "--triggering-input"):
        if flag not in argv:
            continue
        fixed = remap_experiment_path(argv[flag], experiment)
        if fixed != argv[flag]:
            notes.append(f"{flag}: remapped to {fixed}")
            argv[flag] = fixed

    # 2. File arguments whose target is gone: rewrite the archived text back out.
    #    --source-api-file is deliberately excluded: it is a container path (/src/...)
    #    that evaluate_iteration_with_coverage() needs verbatim for path mapping.
    for section_name, flag in SECTION_TO_FILE_ARG.items():
        value = argv.get(flag, "")
        if not value or Path(value).is_file():
            continue
        body = sections.get(section_name, "").strip()
        if not body or body == "N/A":
            notes.append(f"{flag}: missing and not recoverable from the archived prompt")
            continue
        target = recovered_dir / (Path(value).name or f"{flag.strip('-')}.txt")
        target.write_text(body, encoding="utf-8")
        argv[flag] = str(target)
        notes.append(f"{flag}: recovered {len(body)} chars from archived '## {section_name}'")

    # 3. Large inline context values become files.
    for inline_flag, (file_flag, filename) in CONTEXT_FILE_ARGS.items():
        value = argv.pop(inline_flag, "")
        if file_flag in argv and Path(argv[file_flag]).is_file():
            continue
        if not value:
            continue
        target = recovered_dir / filename
        target.write_text(value, encoding="utf-8")
        argv[file_flag] = str(target)

    # 4. Trigger seed: prefer the original path, fall back to the archived copy.
    trigger = argv.get("--triggering-input", "")
    if not trigger or not Path(trigger).is_file():
        archived = case["archived_triggers"]
        if archived:
            argv["--triggering-input"] = str(archived[0])
            notes.append(f"--triggering-input: fell back to archived {archived[0]}")
        else:
            notes.append("--triggering-input: unavailable; the run would use fresh mode")

    # 5. Corpus seeds the solver replays symbolically (solver stage only).
    seeds = argv.get("--seed")
    if isinstance(seeds, list):
        live_seeds = [s for s in (remap_experiment_path(s, experiment) for s in seeds) if Path(s).is_file()]
        dropped = len(seeds) - len(live_seeds)
        if dropped:
            notes.append(f"--seed: {dropped} of {len(seeds)} archived corpus seeds no longer exist")
        if not live_seeds:
            trigger = argv.get("--triggering-input", "")
            if trigger and Path(trigger).is_file():
                live_seeds = [trigger]
                notes.append("--seed: no archived corpus seed survived; using the triggering input")
        argv["--seed"] = live_seeds

    # 6. Never write into the archived experiment.
    argv["--output-root"] = str(replay_dir / "generated")
    argv["--log-dir"] = str(replay_dir / "logs")
    argv.pop("--reset-corpus-per-iteration", None)

    argv.update(overrides)

    command = [sys.executable, str(STAGES[stage]["script"])]
    for flag, value in argv.items():
        if isinstance(value, list):
            for item in value:
                command.extend([flag, item])
        else:
            command.extend([flag, value])
    return {"argv": argv, "command": command, "sections": sections, "notes": notes}


def namespace_from_argv(argv: dict[str, str]) -> argparse.Namespace:
    """Turn recovered flags into the Namespace build_prompt() expects."""
    def get(flag: str, default=None):
        return argv.get(flag, default)

    return argparse.Namespace(
        project_name=get("--project-name", ""),
        function_name=get("--function-name", ""),
        branch_line_number=get("--branch-line-number", "0"),
        blocked_side_line_number=get("--blocked-side-line-number", "0"),
        source_file=get("--source-file", ""),
        source_api_file=get("--source-api-file"),
        fuzz_file=get("--fuzz-file", ""),
        header_file=get("--header-file"),
        language=get("--language"),
        runtime_blocker_segment=get("--runtime-blocker-segment"),
        runtime_blocker_segment_file=get("--runtime-blocker-segment-file"),
        runtime_blocker_segment_source_codes=get("--runtime-blocker-segment-source-codes"),
        runtime_blocker_segment_source_codes_file=get("--runtime-blocker-segment-source-codes-file"),
        cfg_call_chain=get("--cfg-call-chain"),
        cfg_call_chain_file=get("--cfg-call-chain-file"),
        cfg_source_codes=get("--cfg-source-codes"),
        cfg_source_codes_file=get("--cfg-source-codes-file"),
        blocker_call_sites=get("--blocker-call-sites"),
        blocker_call_sites_file=get("--blocker-call-sites-file"),
        triggering_input=get("--triggering-input", ""),
    )


def verify_context(replay: dict, generation_mode: str = "fresh") -> tuple[bool, list[tuple[str, int, int, str]]]:
    """Render the prompt locally and compare every context section with the archive.

    No LLM call, no Docker. This runs first precisely so a degraded replay never gets
    the chance to produce numbers that look like evidence. The mode must match the one
    the run will use, since the two templates render the context sections differently.
    """
    from blocker_process.dependent.input_dependent_seed_generator import build_prompt

    prompt = build_prompt(namespace_from_argv(replay["argv"]), generation_mode=generation_mode)
    current_dir = Path(replay["argv"]["--output-root"]).parent
    current_dir.mkdir(parents=True, exist_ok=True)
    rendered_path = current_dir / "rendered_prompt_preview.txt"
    rendered_path.write_text(prompt, encoding="utf-8")

    current_sections = parse_prompt_sections(rendered_path)
    archived = replay["sections"]

    rows: list[tuple[str, int, int, str]] = []
    ok = True
    for name, body in current_sections.items():
        archived_name = SECTION_ALIASES.get(name, name)
        if archived_name not in archived:
            continue
        archived_body = archived[archived_name]
        before, after = len(archived_body), len(body)
        # The bar is fidelity to the archive, not an absolute standard: a section the
        # original run never had is supposed to come back empty, and calling that a loss
        # would block replays that are in fact perfectly faithful.
        archived_empty = not archived_body or archived_body == "N/A"
        replay_empty = not body or body == "N/A"
        if archived_empty:
            verdict = "ok (archived N/A)" if replay_empty else "ok (gained)"
        elif replay_empty:
            verdict = "LOST"
            ok = False
        elif after < before * VERIFY_SHRINK_TOLERANCE:
            verdict = "SHRUNK"
            ok = False
        else:
            verdict = "ok"
        rows.append((name, before, after, verdict))
    return ok, rows


def warm_coverage_build(project_name: str) -> None:
    """Materialize the coverage build before the replayed stage needs it.

    A normal pipeline run measures coverage during blocker classification, so
    ``build/out/<project>`` is already populated by the time the solver starts. A replay
    jumps straight to the solver from a cold tree, and the first coverage evaluation then
    races the artifact restore -- costing a whole LLM iteration and, worse, getting
    mislabelled as a broken generator. Doing the build up front removes the race.
    """
    from external.oss_fuzz import OSSFuzz

    oss_fuzz = OSSFuzz()
    out_dir = oss_fuzz.build_out_dir / project_name
    targets = [p for p in out_dir.glob("llm_fuzzgen*") if p.is_file()] if out_dir.is_dir() else []
    if targets:
        print(f"Coverage build : already warm ({len(targets)} target(s) in {out_dir})")
        return

    print(f"Coverage build : warming {project_name} (cold tree, this may take a while)...")
    result = oss_fuzz.build_fuzzers(project_name, "coverage")
    if not getattr(result, "success", False):
        raise SystemExit(f"Coverage build failed for {project_name}: {getattr(result, 'error', 'unknown')}")
    targets = [p for p in out_dir.glob("llm_fuzzgen*") if p.is_file()] if out_dir.is_dir() else []
    if not targets:
        raise SystemExit(f"Coverage build reported success but {out_dir} has no llm_fuzzgen targets.")
    print(f"Coverage build : ready ({len(targets)} target(s))")


def print_case_table(cases: list[dict]) -> None:
    for case in cases:
        argv = case["argv"] or {}
        trigger = argv.get("--triggering-input", "")
        trigger_state = (
            "live" if trigger and Path(trigger).is_file()
            else ("archived" if case["archived_triggers"] else "none")
        )
        missing = [
            flag for flag in ("--source-file", "--fuzz-file", "--header-file")
            if argv.get(flag) and not Path(remap_experiment_path(argv[flag], case["experiment"])).is_file()
        ]
        solved = {True: "SOLVED  ", False: "UNSOLVED", None: "UNKNOWN "}[case["solved"]]
        label = f"{case['function_name']}:{case['branch_line']}"
        print(
            f"  {solved} {label:<46} argv={'Y' if case['argv'] else 'N'} "
            f"prompt={'Y' if case['prompt'] else 'N'} trigger={trigger_state:<8} "
            f"repair={','.join(f.lstrip('-') for f in missing) or '-'}"
        )


def resolve_case(experiment: Path, blocker: str, stage: str = "seedgen") -> dict:
    cases = discover_cases(experiment, stage)
    if ":" in blocker:
        function_name, branch_line = blocker.rsplit(":", 1)
    else:
        function_name, branch_line = blocker, None
    matches = [
        case for case in cases
        if case["function_name"] == function_name
        and (branch_line is None or case["branch_line"] == branch_line)
    ]
    if not matches:
        available = ", ".join(f"{c['function_name']}:{c['branch_line']}" for c in cases)
        raise SystemExit(f"No such blocker: {blocker}\nAvailable: {available}")
    if len(matches) > 1:
        options = ", ".join(f"{c['function_name']}:{c['branch_line']}" for c in matches)
        raise SystemExit(f"Ambiguous blocker '{blocker}'; specify FUNC:LINE. Candidates: {options}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="List replayable cases and exit.")
    parser.add_argument("--emit-commands", action="store_true",
                        help="Print a runnable command per case instead of a summary table.")
    parser.add_argument("--unsolved-only", action="store_true",
                        help="With --list/--emit-commands, skip blockers that were already solved.")
    parser.add_argument("--experiment", help="Experiment directory, e.g. experiments/20260724_025850_cjson")
    parser.add_argument("--blocker", help="Blocker to replay, as FUNC:LINE")
    parser.add_argument("--verify-only", action="store_true", help="Check context completeness and exit.")
    parser.add_argument("--print", dest="print_only", action="store_true", help="Print the command (default).")
    parser.add_argument("--run", action="store_true", help="Execute the replayed stage.")
    parser.add_argument("--force", action="store_true", help="Run even if context verification fails.")
    parser.add_argument("--stage", choices=sorted(STAGES), default="seedgen",
                        help="seedgen: replay the LLM seed generator only. "
                             "solver: replay the whole input-dependent solver (seed generator + SymCC).")
    parser.add_argument("--seed-generation-mode", choices=["fresh", "mutation", "auto"], default="fresh",
                        help="Forwarded to the seed generator. Default fresh reproduces the archived arm.")
    parser.add_argument("--max-iterations")
    parser.add_argument("--fuzz-seconds")
    parser.add_argument("--model")
    parser.add_argument("--backend")
    parser.add_argument("--symcc-max-candidate-evaluations")
    parser.add_argument("--symcc-wall-clock-budget-sec")
    args = parser.parse_args()

    if args.list or args.emit_commands or (not args.experiment and not args.blocker):
        targets = [Path(args.experiment)] if args.experiment else experiment_dirs()
        passthrough = " ".join(
            f"{flag} {value}"
            for flag, value in (
                ("--stage", args.stage if args.stage != "seedgen" else None),
                ("--seed-generation-mode", args.seed_generation_mode),
                ("--max-iterations", args.max_iterations),
                ("--fuzz-seconds", args.fuzz_seconds),
                ("--model", args.model),
                ("--backend", args.backend),
            )
            if value
        )
        for experiment in targets:
            cases = discover_cases(experiment, args.stage)
            if args.unsolved_only:
                cases = [case for case in cases if not case["solved"]]
            if not cases:
                continue
            if args.emit_commands:
                print(f"# {experiment.name}  ({len(cases)} cases)")
                for case in cases:
                    label = f"{case['function_name']}:{case['branch_line']}"
                    print(
                        f"python3 scripts/replay_blocker_seed_generation.py"
                        f" --experiment {experiment.as_posix()}"
                        f" --blocker {shlex.quote(label)} --run"
                        + (f" {passthrough}" if passthrough else "")
                    )
                print()
            else:
                print(f"### {experiment.name}  ({len(cases)} cases)")
                print_case_table(cases)
                print()
        return

    if not args.experiment or not args.blocker:
        raise SystemExit("--experiment and --blocker are both required (or use --list).")

    experiment = Path(args.experiment)
    if not experiment.is_dir():
        raise SystemExit(f"No such experiment directory: {experiment}")

    case = resolve_case(experiment, args.blocker, args.stage)
    overrides = {
        flag: value
        for flag, value in (
            ("--seed-generation-mode", args.seed_generation_mode),
            ("--max-iterations", args.max_iterations),
            ("--fuzz-seconds", args.fuzz_seconds),
            ("--model", args.model),
            ("--backend", args.backend),
            ("--symcc-max-candidate-evaluations", args.symcc_max_candidate_evaluations),
            ("--symcc-wall-clock-budget-sec", args.symcc_wall_clock_budget_sec),
        )
        if value and (flag in STAGES[args.stage]["flags"] or flag == "--seed-generation-mode")
    }

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    project = (case["argv"] or {}).get("--project-name", "unknown")
    replay_dir = REPLAY_ROOT / (
        f"{stamp}_{args.stage}_{project}_{case['function_name']}_{case['branch_line']}"
    )
    replay_dir.mkdir(parents=True, exist_ok=True)

    replay = build_replay(case, replay_dir, overrides, args.stage)

    print(f"Replay dir : {replay_dir}")
    print(f"Stage      : {args.stage}  (seed-generation-mode={args.seed_generation_mode})")
    print(f"Blocker    : {project} {case['function_name']}:{case['branch_line']} "
          f"(archived outcome: {'solved' if case['solved'] else 'unsolved'})")
    print(f"Archived   : {case['prompt']}")
    for note in replay["notes"]:
        print(f"  repair   : {note}")
    print()

    ok, rows = verify_context(replay, args.seed_generation_mode if args.seed_generation_mode != "auto" else "fresh")
    print("Context completeness (archived -> replay):")
    for name, before, after, verdict in rows:
        mark = ">>" if verdict in ("LOST", "SHRUNK") else "  "
        print(f"{mark} {name:<42} {before:>7} -> {after:>7}  {verdict}")
    print()

    (replay_dir / "replay_manifest.json").write_text(
        json.dumps(
            {
                "experiment": str(experiment),
                "stage": args.stage,
                "seed_generation_mode": args.seed_generation_mode,
                "blocker": f"{case['function_name']}:{case['branch_line']}",
                "archived_prompt": str(case["prompt"]),
                "archived_outcome": case["solved"],
                "repairs": replay["notes"],
                "context_verification": [
                    {"section": n, "archived_chars": b, "replay_chars": a, "verdict": v}
                    for n, b, a, v in rows
                ],
                "context_ok": ok,
                "argv": replay["argv"],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    if not ok:
        print("FAILED: at least one context section was lost or degraded.")
        print("Replaying with degraded context would produce results that cannot be trusted.")
        if not args.force:
            sys.exit(1)
        print("Continuing anyway because --force was given.\n")
    else:
        print("PASSED: every archived context section survived the replay.\n")

    if args.verify_only:
        return

    print("Command:")
    print("  " + " \\\n    ".join(shlex.quote(part) for part in replay["command"]))
    print()

    if not args.run:
        return

    project = replay["argv"].get("--project-name", "")
    if project:
        warm_coverage_build(project)

    print(f"Running {args.stage}...\n")
    result = subprocess.run(replay["command"], cwd=REPO_ROOT, check=False)
    print(f"\n{args.stage} exited with {result.returncode}")
    print(f"Artifacts: {replay_dir}")
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
