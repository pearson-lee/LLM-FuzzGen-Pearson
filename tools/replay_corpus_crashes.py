#!/usr/bin/env python3
import argparse
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from external.oss_fuzz import OSSFuzz


logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay existing OSS-Fuzz corpora once and collect crash artifacts without mutating originals."
    )
    parser.add_argument("project_names", nargs="+", help="Project names to replay, e.g. lcms zlib libtiff.")
    parser.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=1,
        help="Number of projects to replay in parallel. Defaults to 1.",
    )
    parser.add_argument(
        "--fuzz-targets-parallel",
        type=int,
        default=1,
        help="Number of fuzz targets to replay in parallel per project. Defaults to 1.",
    )
    parser.add_argument(
        "--timeout-per-target",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="Wall-clock timeout for each target replay. Defaults to 3600 seconds.",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        default=False,
        help="Rebuild fuzzers before replay. Default reuses current build/out binaries.",
    )
    parser.add_argument(
        "--stop-after-first-artifact",
        action="store_true",
        default=False,
        help="Do not pass libFuzzer ignore flags; replay may stop at the first crash/timeout/OOM.",
    )
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=None,
        help="Experiment directory for run.log and default crash_seeds output.",
    )
    parser.add_argument(
        "--crash-artifact-dir",
        type=Path,
        default=None,
        help="Directory for recovered crash seeds. Defaults to <experiment-dir>/crash_seeds.",
    )
    return parser.parse_args()


def _setup_logging(experiment_dir: Path) -> None:
    experiment_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(experiment_dir / "run.log", encoding="utf-8"),
        ],
    )


def _replay_project(project_name: str, args: argparse.Namespace, crash_artifact_dir: Path):
    oss_fuzz = OSSFuzz()
    return oss_fuzz.replay_all_fuzzer_corpora(
        project_name,
        timeout_per_fuzzer=args.timeout_per_target,
        max_workers=max(1, args.fuzz_targets_parallel),
        build_fuzzer=args.build,
        crash_artifact_dir=crash_artifact_dir,
        continue_after_artifact=not args.stop_after_first_artifact,
    )


def main() -> int:
    started_at = time.perf_counter()
    args = _parse_args()
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = args.experiment_dir or Path("experiments") / f"{run_id}_replay_corpus_crashes"
    crash_artifact_dir = args.crash_artifact_dir or experiment_dir / "crash_seeds"
    _setup_logging(experiment_dir)

    logger.info("Experiment directory: %s", experiment_dir)
    logger.info("Crash artifact directory: %s", crash_artifact_dir)
    logger.info("Projects: %s", ", ".join(args.project_names))
    logger.info(
        "Replay config: project_workers=%d target_workers=%d timeout_per_target=%ds build=%s continue_after_artifact=%s",
        max(1, args.parallel),
        max(1, args.fuzz_targets_parallel),
        args.timeout_per_target,
        args.build,
        not args.stop_after_first_artifact,
    )

    overall_success = True
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as executor:
        futures = {
            executor.submit(_replay_project, project_name, args, crash_artifact_dir): project_name
            for project_name in args.project_names
        }
        for future in as_completed(futures):
            project_name = futures[future]
            try:
                results = future.result()
            except BaseException as exc:
                overall_success = False
                logger.exception("Replay failed for %s: %s", project_name, exc)
                continue

            nonzero_results = [result for result in results if not result.success]
            logger.info(
                "Replay finished for %s: targets=%d nonzero_results=%d",
                project_name,
                len(results),
                len(nonzero_results),
            )

    logger.info("Total execution time: %.2fs", time.perf_counter() - started_at)
    return 0 if overall_success else 1


if __name__ == "__main__":
    raise SystemExit(main())
