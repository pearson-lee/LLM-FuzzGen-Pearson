#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from crash_analyzer.crash_analyzer import CrashAnalyzer
from external.oss_fuzz import OSSFuzz
from llm_interface.llm_client import LLMClient


logger = logging.getLogger(__name__)

FINDING_TO_STATUS = {
    "Real Crash": "TP",
    "Fuzzer Logic Error": "FP",
    "Ambiguous": "TBD",
}
VALID_FINAL_STATUSES = {"TP", "FP", "TBD"}


def _status_from_analysis(analysis: dict[str, Any]) -> str:
    """Prefer the analyzer's hard-gated status, with legacy finding fallback."""
    final_status = analysis.get("final_status")
    if isinstance(final_status, str) and final_status in VALID_FINAL_STATUSES:
        return final_status
    finding = str(analysis.get("finding", "Ambiguous"))
    return FINDING_TO_STATUS.get(finding, "TBD")


@dataclass(frozen=True)
class CrashSeed:
    experiment_dir: Path
    metadata_path: Path
    seed_path: Path
    project: str
    fuzzer: str
    artifact_name: str
    artifact_kind: str


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze saved experiment crash seeds and classify each result as "
            "TP, FP, or TBD with the repository CrashAnalyzer."
        )
    )
    parser.add_argument(
        "experiment_dirs",
        nargs="+",
        type=Path,
        help="Experiment directories containing crash_seeds/.",
    )
    parser.add_argument(
        "--llm",
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="vertexai",
        help="LLM backend. Defaults to vertexai.",
    )
    parser.add_argument(
        "--model",
        default="gemini-2.5-pro",
        help="Model name. Defaults to gemini-2.5-pro.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="Judge temperature. Defaults to 0.1.",
    )
    parser.add_argument(
        "--artifact-kinds",
        nargs="+",
        choices=["crash", "timeout", "oom", "slow-unit"],
        default=["crash"],
        help="Artifact kinds to analyze. Defaults to crash only.",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build or restore address-sanitized fuzzers before analysis.",
    )
    parser.add_argument(
        "--sanitizer",
        choices=["address", "memory", "undefined"],
        default="address",
        help="Sanitizer used by --build. Defaults to address.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Result directory. Defaults to experiments/<timestamp>_crash_analysis.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover and validate seeds without building, reproducing, or calling the LLM.",
    )
    return parser.parse_args()


def _experiment_and_seed_root(path: Path) -> tuple[Path, Path]:
    path = path.resolve()
    if path.name == "crash_seeds":
        return path.parent, path
    return path, path / "crash_seeds"


def discover_crash_seeds(experiment_dirs: list[Path]) -> tuple[list[CrashSeed], list[dict[str, Any]]]:
    seeds: list[CrashSeed] = []
    issues: list[dict[str, Any]] = []

    for requested_dir in experiment_dirs:
        experiment_dir, crash_seed_root = _experiment_and_seed_root(requested_dir)
        if not experiment_dir.is_dir():
            issues.append(
                _record(
                    experiment_dir=experiment_dir,
                    status="ERROR",
                    error="experiment directory does not exist",
                )
            )
            continue
        if not crash_seed_root.is_dir():
            logger.info("No crash_seeds directory in %s", experiment_dir)
            continue

        for metadata_path in sorted(crash_seed_root.glob("*/*/*.metadata.json")):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                issues.append(
                    _record(
                        experiment_dir=experiment_dir,
                        metadata_path=metadata_path,
                        status="ERROR",
                        error=f"invalid metadata: {exc}",
                    )
                )
                continue

            required = ("project", "fuzzer", "artifact_name", "artifact_kind")
            missing = [field for field in required if not str(metadata.get(field, "")).strip()]
            if missing:
                issues.append(
                    _record(
                        experiment_dir=experiment_dir,
                        metadata_path=metadata_path,
                        status="ERROR",
                        error=f"metadata missing fields: {', '.join(missing)}",
                    )
                )
                continue

            artifact_name = str(metadata["artifact_name"])
            seed_path = metadata_path.parent / artifact_name
            seeds.append(
                CrashSeed(
                    experiment_dir=experiment_dir,
                    metadata_path=metadata_path,
                    seed_path=seed_path,
                    project=str(metadata["project"]),
                    fuzzer=str(metadata["fuzzer"]),
                    artifact_name=artifact_name,
                    artifact_kind=str(metadata["artifact_kind"]),
                )
            )

    return seeds, issues


def _record(
    *,
    experiment_dir: Path,
    status: str,
    metadata_path: Path | None = None,
    seed: CrashSeed | None = None,
    finding: str = "",
    confidence: float | None = None,
    artifact_dir: Path | None = None,
    status_reason: str = "",
    error: str = "",
) -> dict[str, Any]:
    return {
        "experiment_dir": str(experiment_dir),
        "project": seed.project if seed else "",
        "fuzzer": seed.fuzzer if seed else "",
        "artifact_name": seed.artifact_name if seed else "",
        "artifact_kind": seed.artifact_kind if seed else "",
        "metadata_path": str(seed.metadata_path if seed else metadata_path or ""),
        "seed_path": str(seed.seed_path if seed else ""),
        "status": status,
        "finding": finding,
        "confidence": confidence,
        "artifact_dir": str(artifact_dir or ""),
        "status_reason": status_reason,
        "error": error,
    }


def _setup_logging(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(output_dir / "run.log", encoding="utf-8"),
        ],
        force=True,
    )


def _write_results(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    fields = [
        "experiment_dir",
        "project",
        "fuzzer",
        "artifact_name",
        "artifact_kind",
        "status",
        "finding",
        "confidence",
        "metadata_path",
        "seed_path",
        "artifact_dir",
        "status_reason",
        "error",
    ]
    with (output_dir / "results.csv").open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(summary["results"])

    markdown_lines = [
        "# Crash Analysis Summary",
        "",
        f"- Backend: `{summary['llm_backend']}`",
        f"- Model: `{summary['model']}`",
        f"- Artifact kinds: `{', '.join(summary['artifact_kinds'])}`",
        f"- Dry run: `{str(summary['dry_run']).lower()}`",
        "",
        "| Experiment | Discovered | Selected | TP | FP | TBD | Pending | Skipped | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for experiment in summary["experiments"]:
        markdown_lines.append(
            "| {experiment_dir} | {discovered} | {selected} | {tp} | {fp} | "
            "{tbd} | {pending} | {skipped} | {errors} |".format(**experiment)
        )
    totals = summary["totals"]
    markdown_lines.append(
        "| **Total** | **{discovered}** | **{selected}** | **{tp}** | **{fp}** | "
        "**{tbd}** | **{pending}** | **{skipped}** | **{errors}** |".format(**totals)
    )
    markdown_lines.append("")
    (output_dir / "summary.md").write_text("\n".join(markdown_lines), encoding="utf-8")


def _status_totals(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(record["status"] for record in records)
    return {
        "analyzed": counts["TP"] + counts["FP"] + counts["TBD"],
        "tp": counts["TP"],
        "fp": counts["FP"],
        "tbd": counts["TBD"],
        "pending": counts["SELECTED"],
        "skipped": counts["SKIPPED"],
        "errors": counts["ERROR"],
    }


def _summarize(
    *,
    args: argparse.Namespace,
    output_dir: Path,
    started_at: datetime,
    seeds: list[CrashSeed],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    selected_kinds = set(args.artifact_kinds)
    requested_experiments = []
    for requested_dir in args.experiment_dirs:
        experiment_dir, _ = _experiment_and_seed_root(requested_dir)
        if experiment_dir not in requested_experiments:
            requested_experiments.append(experiment_dir)

    experiment_summaries = []
    for experiment_dir in requested_experiments:
        experiment_seeds = [seed for seed in seeds if seed.experiment_dir == experiment_dir]
        experiment_records = [
            record for record in records if record["experiment_dir"] == str(experiment_dir)
        ]
        experiment_summaries.append(
            {
                "experiment_dir": str(experiment_dir),
                "discovered": len(experiment_seeds),
                "selected": sum(seed.artifact_kind in selected_kinds for seed in experiment_seeds),
                **_status_totals(experiment_records),
            }
        )

    totals = {
        "discovered": len(seeds),
        "selected": sum(seed.artifact_kind in selected_kinds for seed in seeds),
        **_status_totals(records),
    }
    return {
        "schema_version": 1,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "llm_backend": args.llm,
        "model": args.model,
        "temperature": args.temperature,
        "artifact_kinds": sorted(set(args.artifact_kinds)),
        "dry_run": args.dry_run,
        "output_dir": str(output_dir),
        "totals": totals,
        "experiments": experiment_summaries,
        "results": records,
    }


def run(args: argparse.Namespace) -> int:
    started_at = datetime.now(timezone.utc)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (args.output_dir or Path("experiments") / f"{run_id}_crash_analysis").resolve()
    _setup_logging(output_dir)

    seeds, discovery_issues = discover_crash_seeds(args.experiment_dirs)
    selected_kinds = set(args.artifact_kinds)
    selected = [seed for seed in seeds if seed.artifact_kind in selected_kinds]
    records = list(discovery_issues)
    records.extend(
        _record(
            experiment_dir=seed.experiment_dir,
            seed=seed,
            status="SKIPPED",
            error=f"artifact kind {seed.artifact_kind!r} was not selected",
        )
        for seed in seeds
        if seed.artifact_kind not in selected_kinds
    )

    logger.info(
        "Discovered %d artifact(s); selected %d for analysis (%s).",
        len(seeds),
        len(selected),
        ", ".join(sorted(selected_kinds)),
    )

    if args.dry_run:
        for seed in selected:
            status = "SELECTED" if seed.seed_path.is_file() else "ERROR"
            error = "" if status == "SELECTED" else "saved seed file does not exist"
            records.append(_record(experiment_dir=seed.experiment_dir, seed=seed, status=status, error=error))
        summary = _summarize(
            args=args,
            output_dir=output_dir,
            started_at=started_at,
            seeds=seeds,
            records=records,
        )
        _write_results(output_dir, summary)
        logger.info("Dry-run summary written to %s", output_dir / "summary.json")
        return 1 if summary["totals"]["errors"] else 0

    oss_fuzz = OSSFuzz()
    build_failures: dict[str, str] = {}
    if args.build:
        for project in sorted({seed.project for seed in selected}):
            logger.info("Building/restoring %s fuzzers with sanitizer=%s", project, args.sanitizer)
            result = oss_fuzz.build_fuzzers(project, sanitizer=args.sanitizer)
            if not result.success:
                build_failures[project] = result.error or "fuzzer build failed"

    if selected:
        try:
            llm_client = LLMClient(
                backend=args.llm,
                model_name=args.model,
                temperature=args.temperature,
            )
        except Exception as exc:
            logger.exception("LLM initialization failed: %s", exc)
            for seed in selected:
                records.append(
                    _record(
                        experiment_dir=seed.experiment_dir,
                        seed=seed,
                        status="ERROR",
                        error=f"LLM initialization failed: {exc}",
                    )
                )
            summary = _summarize(
                args=args,
                output_dir=output_dir,
                started_at=started_at,
                seeds=seeds,
                records=records,
            )
            _write_results(output_dir, summary)
            return 1

        analyzer = CrashAnalyzer(llm_client, oss_fuzz)
        analyzer.crashes_dir = output_dir / "artifacts"
        analyzer.crashes_dir.mkdir(parents=True, exist_ok=True)

        for seed in selected:
            if seed.project in build_failures:
                records.append(
                    _record(
                        experiment_dir=seed.experiment_dir,
                        seed=seed,
                        status="ERROR",
                        error=build_failures[seed.project],
                    )
                )
                continue
            if not seed.seed_path.is_file():
                records.append(
                    _record(
                        experiment_dir=seed.experiment_dir,
                        seed=seed,
                        status="ERROR",
                        error="saved seed file does not exist",
                    )
                )
                continue

            try:
                artifact_dir = analyzer.analyze_crash(seed.project, seed.fuzzer, seed.seed_path)
                if artifact_dir is None:
                    raise RuntimeError("CrashAnalyzer did not produce an analysis artifact")
                analysis = json.loads((artifact_dir / "analysis.json").read_text(encoding="utf-8"))
                finding = str(analysis.get("finding", "Ambiguous"))
                status = _status_from_analysis(analysis)
                status_reason = str(analysis.get("final_status_reason", ""))
                confidence_value = analysis.get("confidence")
                confidence = float(confidence_value) if isinstance(confidence_value, (int, float)) else None
                records.append(
                    _record(
                        experiment_dir=seed.experiment_dir,
                        seed=seed,
                        status=status,
                        finding=finding,
                        confidence=confidence,
                        artifact_dir=artifact_dir,
                        status_reason=status_reason,
                    )
                )
                logger.info(
                    "Classified %s as %s (%s, confidence=%s)",
                    seed.artifact_name,
                    status,
                    finding,
                    confidence,
                )
            except Exception as exc:
                logger.exception("Analysis failed for %s: %s", seed.seed_path, exc)
                records.append(
                    _record(
                        experiment_dir=seed.experiment_dir,
                        seed=seed,
                        status="ERROR",
                        error=str(exc),
                    )
                )

    summary = _summarize(
        args=args,
        output_dir=output_dir,
        started_at=started_at,
        seeds=seeds,
        records=records,
    )
    _write_results(output_dir, summary)
    totals = summary["totals"]
    logger.info(
        "Crash analysis finished: TP=%d FP=%d TBD=%d skipped=%d errors=%d",
        totals["tp"],
        totals["fp"],
        totals["tbd"],
        totals["skipped"],
        totals["errors"],
    )
    logger.info("Summary: %s", output_dir / "summary.json")
    return 1 if totals["errors"] else 0


def main() -> int:
    started = time.perf_counter()
    args = _parse_args()
    exit_code = run(args)
    logger.info("Total execution time: %.2fs", time.perf_counter() - started)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
