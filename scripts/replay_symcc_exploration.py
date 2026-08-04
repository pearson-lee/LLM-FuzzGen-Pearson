#!/usr/bin/env python3
"""Replay an archived SymCC exploration with a larger candidate-evaluation budget.

Across the six archived campaigns SymCC discovered 31,252 candidate inputs during the
original-target probe but the coverage oracle only ever replayed 4,501 of them -- 85.6%
were discarded because ``--max-candidate-evaluations`` defaulted to 200. Most of those
runs stopped after using 2-5% of their 300s wall clock, so the cap, not the clock, ended
the search. That leaves the central question unanswered: is ``blocked_side == 0`` because
SymCC never produced a branch-flipping input, or because we never looked at the one it did
produce?

This tool answers that by running a matched two-arm experiment per case. Both arms replay
the archived command verbatim -- same seeds, generations, frontier cap, per-execution
timeout, and prebuilt SymCC archives -- and differ in exactly one value:

    control    --max-candidate-evaluations 200      (what the archive ran with)
    treatment  --max-candidate-evaluations <3x outputs>

The control arm is re-run rather than read from the archive on purpose. The solver has
changed substantially since those campaigns (frontier diversity, timeout retention,
adaptive per-seed timeouts), so comparing a new treatment against an old archive would
confound the budget with every other change. Re-running the control under today's code
isolates the budget. As a side benefit, control-vs-archive shows whether those other
changes moved the baseline at all.

Wall clock is held equal across both arms and set high enough that the evaluation cap,
not the clock, is what ends the control run -- otherwise the treatment could not spend
the budget it was given and the comparison would measure nothing.

The archived work directory is copied rather than reused in place: it holds the prebuilt
SymCC library archives (the expensive part of a run), and rebuilding them would take
longer than the experiment, while writing into the original would destroy the baseline.

Usage:
    replay_symcc_exploration.py --list
    replay_symcc_exploration.py --case zlib:gz_avail_50 --print
    replay_symcc_exploration.py --case zlib:gz_avail_50 --run
    replay_symcc_exploration.py --preset --run
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from replay_blocker_seed_generation import (  # noqa: E402
    _LOG_LINE_START,
    accepted_flags,
    remap_experiment_path,
)

RUNNER = REPO_ROOT / "blocker_process" / "dependent" / "run_symcc_blocker.py"
REPLAY_ROOT = REPO_ROOT / "replays"

RUNNER_FLAGS = accepted_flags(RUNNER)

# run_symcc_blocker.py is invoked three times per blocker with different --work-dir
# leaf names; only the first explores the original target with SymCC.
PROBE_WORK_DIR_LEAF = "symcc_probe"

# Repeatable options must not collapse to a single value when the argv is rebuilt.
REPEATABLE_FLAGS = {"--seed", "--source", "--include-dir", "--define"}

# The six cases the plan selected: every one reached the branch with candidates to spare
# and stopped on the evaluation cap well inside its wall clock, so a larger budget has
# somewhere to go.
PRESET_CASES = [
    "zlib:gz_avail_50",
    "lcms:cmsIT8GetData_2865",
    "lcms:cmsCreateExtendedTransform_1239",
    "cjson:print_number_602",
    "libvpx:vp8_decode_407",
    "libtiff:_TIFFCastUInt64ToSSize_86",
]

# Candidate budget is set from what the archived run actually discovered. A multiplier
# above 1 covers the extra outputs that the deeper generations will produce once the
# earlier ones stop being truncated.
DEFAULT_EVAL_MULTIPLIER = 3
DEFAULT_EVAL_FLOOR = 600

# Every archived probe ran with this cap; the control arm reproduces it under today's code.
CONTROL_EVAL_BUDGET = 200

# Shared by both arms. High enough that the evaluation cap is what stops the control run,
# so the treatment is free to spend the larger budget it was given.
DEFAULT_WALL_CLOCK_SEC = 1800


def _dispatch_pattern() -> re.Pattern[str]:
    return re.compile(rf"Dispatching: \S*python3?\s+\S*{re.escape(RUNNER.name)}")


def _flag_boundary() -> re.Pattern[str]:
    ordered = sorted(RUNNER_FLAGS, key=len, reverse=True)
    return re.compile(r"(?<=\s)(" + "|".join(re.escape(f) for f in ordered) + r")(?=\s)")


def parse_probe_dispatches(run_log: Path) -> dict[str, dict[str, object]]:
    """Recover each archived ``run_symcc_blocker.py`` probe argv, keyed by blocker dir."""
    if not run_log.is_file():
        return {}
    dispatch = _dispatch_pattern()
    boundary_re = _flag_boundary()
    text = run_log.read_text(encoding="utf-8", errors="replace")
    commands: dict[str, dict[str, object]] = {}
    for match in dispatch.finditer(text):
        tail = text[match.end():]
        boundary = _LOG_LINE_START.search(tail)
        raw = tail[: boundary.start()] if boundary else tail
        spans = [(m.group(1), m.start(), m.end()) for m in boundary_re.finditer(raw)]
        parsed: dict[str, object] = {}
        for index, (flag, _start, value_end) in enumerate(spans):
            next_start = spans[index + 1][1] if index + 1 < len(spans) else len(raw)
            value = raw[value_end:next_start].strip()
            if flag in REPEATABLE_FLAGS:
                parsed.setdefault(flag, []).append(value)  # type: ignore[union-attr]
            else:
                parsed[flag] = value
        work_dir = str(parsed.get("--work-dir", ""))
        if Path(work_dir).name != PROBE_WORK_DIR_LEAF:
            continue
        # .../blockers/<blocker>/symbolic_run/<stamp>/symcc_probe
        blocker = Path(work_dir).parent.parent.parent.name
        if blocker:
            commands[blocker] = parsed
    return commands


def archived_exploration(summary_path: Path) -> dict[str, object]:
    """Pull the baseline numbers this replay will be compared against."""
    if not summary_path.is_file():
        return {}
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    exploration = ((summary.get("symcc") or {}).get("exploration")) or {}
    counts = exploration.get("outcome_counts") or {}
    budgets = exploration.get("budgets") or {}
    deadline = budgets.get("deadline_seconds") or 0
    elapsed = exploration.get("elapsed_seconds") or 0
    return {
        "stop_reason": exploration.get("stop_reason"),
        "outputs": exploration.get("outputs_discovered") or 0,
        "evaluations": exploration.get("candidate_evaluations") or 0,
        "branch": counts.get("branch") or 0,
        "blocked_side": counts.get("blocked_side") or 0,
        "elapsed": elapsed,
        "deadline": deadline,
        "wall_pct": (elapsed / deadline * 100) if deadline else 0.0,
        "eval_budget": budgets.get("candidate_evaluations") or 0,
    }


def experiment_dirs() -> list[Path]:
    root = REPO_ROOT / "experiments"
    return sorted(p for p in root.glob("*") if p.is_dir() and (p / "blockers").is_dir())


def discover_cases() -> list[dict]:
    cases: list[dict] = []
    for experiment in experiment_dirs():
        project = experiment.name.split("_")[-1]
        for blocker, argv in parse_probe_dispatches(experiment / "run.log").items():
            work_dir = Path(remap_experiment_path(str(argv.get("--work-dir", "")), experiment))
            summary = Path(
                remap_experiment_path(str(argv.get("--json-output-file", "")), experiment)
            )
            binary = work_dir / "symcc" / "build" / "symcc" / "replay_symcc"
            cases.append(
                {
                    "project": project,
                    "experiment": experiment,
                    "blocker": blocker,
                    "argv": argv,
                    "work_dir": work_dir,
                    "summary": summary,
                    "replayable": binary.is_file(),
                    "archived": archived_exploration(summary),
                }
            )
    return cases


def resolve_case(cases: list[dict], selector: str) -> dict:
    if ":" not in selector:
        raise SystemExit(f"--case expects <project>:<blocker>, got {selector!r}")
    project, blocker = selector.split(":", 1)
    matches = [c for c in cases if c["project"] == project and c["blocker"] == blocker]
    if not matches:
        raise SystemExit(f"no archived probe found for {selector}")
    if len(matches) > 1:
        raise SystemExit(f"{selector} is ambiguous across {[str(c['experiment']) for c in matches]}")
    return matches[0]


def treatment_budget(case: dict, eval_multiplier: int) -> int:
    outputs = int(case["archived"].get("outputs") or 0)
    return max(DEFAULT_EVAL_FLOOR, outputs * eval_multiplier)


def build_replay(case: dict, arm_dir: Path, eval_budget: int, wall_clock: int) -> dict:
    """Rebuild the archived argv with only the budget and output paths changed."""
    experiment = case["experiment"]
    argv: dict[str, object] = dict(case["argv"])

    work_dir = arm_dir / "work"
    summary_path = arm_dir / "symcc_probe_summary.json"

    overrides = {
        "--max-candidate-evaluations": str(eval_budget),
        "--wall-clock-budget-sec": str(wall_clock),
        "--work-dir": str(work_dir),
        "--json-output-file": str(summary_path),
    }
    argv.update(overrides)

    cmd: list[str] = [sys.executable, str(RUNNER)]
    for flag, value in argv.items():
        if isinstance(value, list):
            for item in value:
                cmd.extend([flag, remap_experiment_path(item, experiment)])
        elif value == "":
            cmd.append(flag)
        else:
            cmd.extend([flag, remap_experiment_path(str(value), experiment)])

    return {
        "cmd": cmd,
        "work_dir": work_dir,
        "summary": summary_path,
        "eval_budget": eval_budget,
        "overrides": overrides,
    }


def verify_single_variable(case: dict, replay: dict) -> list[str]:
    """Report every archived flag whose value the replay changed.

    An evaluation-budget experiment is only interpretable if the budget is the sole
    difference, so anything beyond the four intended overrides is surfaced loudly rather
    than left for the reader to notice in a diff.
    """
    intended = set(replay["overrides"])
    drift: list[str] = []
    for flag, value in case["argv"].items():
        if flag in intended or isinstance(value, list):
            continue
        replayed = replay["overrides"].get(flag, value)
        if str(replayed) != str(value):
            drift.append(f"{flag}: {value!r} -> {replayed!r}")
    return drift


def stage_work_dir(source: Path, destination: Path) -> None:
    """Copy the archived work dir so prebuilt archives are reused and the archive survives."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # generated/ holds the previous run's candidates; leaving them would make
    # outputs_discovered double-count against the baseline.
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("generated", "coverage"),
    )


def print_case_table(cases: list[dict]) -> None:
    header = (
        f"{'project':8} {'blocker':40} {'stop':30} {'out':>6} {'eval':>5} "
        f"{'br':>5} {'BS':>3} {'%wall':>6} {'replayable':>10}"
    )
    print(header)
    print("-" * len(header))
    for case in sorted(cases, key=lambda c: (c["project"], c["blocker"])):
        a = case["archived"]
        print(
            f"{case['project']:8} {case['blocker'][:40]:40} {str(a.get('stop_reason'))[:30]:30} "
            f"{a.get('outputs', 0):>6} {a.get('evaluations', 0):>5} {a.get('branch', 0):>5} "
            f"{a.get('blocked_side', 0):>3} {a.get('wall_pct', 0.0):>5.1f}% "
            f"{'yes' if case['replayable'] else 'no':>10}"
        )


def report_outcome(case: dict, control: dict, treatment: dict) -> None:
    archive = case["archived"]
    print()
    print(f"=== {case['project']} {case['blocker']}")
    header = f"{'':16} {'archive':>12} {'control':>12} {'treatment':>12}"
    print(header)
    print("-" * len(header))
    for label, key in (
        ("eval budget", "eval_budget"),
        ("outputs", "outputs"),
        ("evaluations", "evaluations"),
        ("branch", "branch"),
        ("blocked_side", "blocked_side"),
    ):
        print(
            f"{label:16} {str(archive.get(key, '-')):>12} "
            f"{str(control.get(key, '-')):>12} {str(treatment.get(key, '-')):>12}"
        )
    print(
        f"{'stop_reason':16} {str(archive.get('stop_reason'))[:12]:>12} "
        f"{str(control.get('stop_reason'))[:12]:>12} {str(treatment.get('stop_reason'))[:12]:>12}"
    )

    control_eval = int(control.get("evaluations") or 0)
    treatment_eval = int(treatment.get("evaluations") or 0)
    if treatment_eval <= control_eval:
        print(
            f"\n[warn] the treatment did not evaluate more than the control "
            f"({control_eval} -> {treatment_eval}); the budget was not the binding "
            "constraint here, so this case says nothing about it"
        )
    if int(control.get("blocked_side") or 0) > 0:
        print("\n[warn] the control already reached blocked_side; the budget is not what changed it")
    elif int(treatment.get("blocked_side") or 0) > 0:
        print("\n[RESULT] blocked_side reached only in the treatment -- the answer was "
              "in the candidates the 200-eval cap discarded")
    else:
        print("\n[RESULT] blocked_side still 0 in both arms -- SymCC did not produce a "
              "flipping input, so the evaluation budget is not the bottleneck")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="List archived probes and their baseline numbers.")
    parser.add_argument("--case", action="append", default=[], help="<project>:<blocker>. Repeatable.")
    parser.add_argument("--preset", action="store_true", help=f"Use the {len(PRESET_CASES)} planned cases.")
    parser.add_argument("--eval-multiplier", type=int, default=DEFAULT_EVAL_MULTIPLIER)
    parser.add_argument("--wall-clock-budget-sec", type=int, default=DEFAULT_WALL_CLOCK_SEC)
    parser.add_argument("--print", dest="show", action="store_true", help="Print the replay command only.")
    parser.add_argument("--run", action="store_true", help="Execute the replay.")
    args = parser.parse_args()

    cases = discover_cases()
    if args.list or not (args.case or args.preset):
        print_case_table(cases)
        if not (args.case or args.preset):
            print("\nSelect with --case <project>:<blocker> or --preset, then --print or --run.")
        return

    selectors = list(args.case) + (PRESET_CASES if args.preset else [])
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results: list[tuple[dict, dict, dict]] = []

    for selector in selectors:
        case = resolve_case(cases, selector)
        if not case["replayable"]:
            print(f"[skip] {selector}: archived SymCC binary is gone, a rebuild would be needed")
            continue

        case_dir = REPLAY_ROOT / f"{stamp}_symcc_{case['project']}_{case['blocker']}"
        arms = {
            "control": CONTROL_EVAL_BUDGET,
            "treatment": treatment_budget(case, args.eval_multiplier),
        }

        print(f"\n=== {selector}")
        print(f"    archive : {case['archived'].get('outputs', 0)} outputs, "
              f"{case['archived'].get('evaluations', 0)} evaluated "
              f"({case['archived'].get('wall_pct', 0.0):.1f}% wall)")
        print(f"    arms    : control={arms['control']} treatment={arms['treatment']} evaluations, "
              f"both at --wall-clock-budget-sec {args.wall_clock_budget_sec}")

        outcomes: dict[str, dict] = {}
        aborted = False
        for arm, eval_budget in arms.items():
            arm_dir = case_dir / arm
            replay = build_replay(case, arm_dir, eval_budget, args.wall_clock_budget_sec)

            drift = verify_single_variable(case, replay)
            if drift:
                print(f"    [abort] {arm} changed more than the budget:")
                for item in drift:
                    print(f"        {item}")
                aborted = True
                break

            if args.show or not args.run:
                print(f"    [{arm}] " + shlex.join(replay["cmd"]))
                continue

            arm_dir.mkdir(parents=True, exist_ok=True)
            stage_work_dir(case["work_dir"], replay["work_dir"])
            (arm_dir / "replay_command.txt").write_text(shlex.join(replay["cmd"]) + "\n", encoding="utf-8")

            log_path = arm_dir / "replay.log"
            with log_path.open("w", encoding="utf-8") as handle:
                process = subprocess.run(
                    replay["cmd"], cwd=REPO_ROOT, stdout=handle, stderr=subprocess.STDOUT, text=True
                )
            print(f"    [{arm}] exit {process.returncode}, log: {log_path}")
            outcomes[arm] = archived_exploration(replay["summary"])

        if aborted or not args.run:
            continue
        report_outcome(case, outcomes.get("control", {}), outcomes.get("treatment", {}))
        results.append((case, outcomes.get("control", {}), outcomes.get("treatment", {})))

    if len(results) > 1:
        print("\n\n=== summary ===")
        header = (
            f"{'case':40} {'eval ctrl':>10} {'eval trt':>9} "
            f"{'BS ctrl':>8} {'BS trt':>7} {'verdict':>18}"
        )
        print(header)
        print("-" * len(header))
        for case, control, treatment in results:
            ctrl_bs = int(control.get("blocked_side") or 0)
            trt_bs = int(treatment.get("blocked_side") or 0)
            verdict = "budget was it" if (trt_bs > 0 and ctrl_bs == 0) else (
                "already solved" if ctrl_bs > 0 else "budget not it"
            )
            print(
                f"{case['project'] + ':' + case['blocker']:40} "
                f"{control.get('evaluations', 0):>10} {treatment.get('evaluations', 0):>9} "
                f"{ctrl_bs:>8} {trt_bs:>7} {verdict:>18}"
            )


if __name__ == "__main__":
    main()
