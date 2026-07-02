#!/usr/bin/env python3
import logging
import sys
import time
import argparse
import json
import os
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from dataclasses import dataclass
from dataclasses import field

import config.config as config
import prompts.prompt_generator as prompt_generator
from blocker_process.blocker_classifier import classify_blocker
from blocker_process.coverage_utils import get_line_execution_count
from blocker_process.dependent.input_dependent_seed_generator import evaluate_iteration_with_coverage
from blocker_process.global_blocker_selector import (
    aggregate_score_and_revalidate_blockers,
    canonical_blocker_key,
)
from crash_analyzer.crash_analyzer import CrashAnalyzer
from experiment_logger import ExperimentLogger
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz, TotalCoverageSummary
from iterator.fuzz_iterator import FuzzIterator
from llm_interface.llm_client import LLMClient
from logger import setup_logging
from fuzzing_input import generate_seeds_for_fuzzer, generate_dict_for_proj

logger = logging.getLogger(__name__)

oss_fuzz = OSSFuzz()
introspector = Introspector()
# The LLMClient will be initialized in main() after parsing arguments.
llm_client: LLMClient | None = None
experiment_logger: ExperimentLogger | None = None
experiment_dir: Path | None = None


@dataclass
class BlockerRuntimeState:
    artifacts_ready: bool = False
    artifacts_dirty: bool = False
    sessions_run: int = 0
    total_blockers_attempted: int = 0
    total_blockers_succeeded: int = 0
    last_artifact_refresh_elapsed: float | None = None
    max_full_refresh_elapsed: float | None = None
    max_light_refresh_elapsed: float | None = None
    max_coverage_elapsed: float | None = None
    max_blocker_attempt_elapsed: float | None = None
    last_artifact_refresh_skip_reason: str | None = None
    last_artifact_refresh_reused_existing: bool = False
    last_stall_elapsed: int | None = None
    artifact_branch_covered_baseline: int | None = None
    artifact_target_fingerprint: str | None = None
    pending_target_fingerprint: str | None = None
    new_targets_since_full_rebuild: int = 0
    light_refreshes_since_full_rebuild: int = 0
    last_session_artifacts: "BlockerSessionArtifacts | None" = None
    attempted_blocker_keys: set[tuple[str, str, str, str]] = field(default_factory=set)


@dataclass
class BlockerCoverageContext:
    project_report: str
    target_reports: dict[str, str]


@dataclass(frozen=True)
class BlockerSessionArtifacts:
    root: Path
    blocker_json: Path
    all_functions_js: Path | None = None
    summary_json: Path | None = None
    yaml_file: Path | None = None
    source_root: Path | None = None
    cfg_data_files: dict[str, Path] = field(default_factory=dict)


BLOCKER_FULL_REFRESH_TARGET_THRESHOLD = 10
BLOCKER_FULL_REFRESH_SESSION_INTERVAL = 3
BLOCKER_FULL_REFRESH_BOOTSTRAP_SECONDS = 1200.0
BLOCKER_LIGHT_REFRESH_BOOTSTRAP_SECONDS = 600.0
BLOCKER_ATTEMPT_BOOTSTRAP_SECONDS = 600.0
BLOCKER_COVERAGE_BOOTSTRAP_SECONDS = 180.0
BLOCKER_SCHEDULING_OVERHEAD_SECONDS = 120.0
BLOCKER_REFRESH_SAFETY_MULTIPLIER = 1.20
BLOCKER_REFRESH_SAFETY_BUFFER_SECONDS = 60.0


def _live_revalidate_blocker_before_classify(
    project_name: str,
    blocker: dict,
    fuzz_seconds: int,
) -> dict:
    target_name = str(blocker.get("best_target") or "").strip()
    function_name = str(blocker.get("function_name") or "").strip()
    source_file = str(blocker.get("source_file") or "").strip()
    branch_line = int(str(blocker.get("branch_line_number", "0")) or 0)
    blocked_side_line = int(
        str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "0"))) or 0
    )

    if not target_name or not function_name or not source_file or branch_line <= 0 or blocked_side_line <= 0:
        return {
            "success": False,
            "reason": "live_revalidation_unavailable",
            "error": "Missing target, function, source file, or blocker line metadata.",
        }

    cached_report_path = (
        oss_fuzz.build_out_dir
        / project_name
        / "textcov_reports"
        / f"{target_name}.linecovreport"
    )
    if cached_report_path.is_file():
        try:
            cached_report = cached_report_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to read live revalidation coverage report %s: %s", cached_report_path, exc)
        else:
            if cached_report.strip():
                branch_hit_count = _normalize_hitcount(
                    get_line_execution_count(
                        cached_report,
                        branch_line,
                        function_name=function_name,
                        source_file=source_file,
                    )
                )
                blocked_side_hit_count = _normalize_hitcount(
                    get_line_execution_count(
                        cached_report,
                        blocked_side_line,
                        function_name=function_name,
                        source_file=source_file,
                    )
                )
                return {
                    "success": True,
                    "reason": "live_revalidation_completed",
                    "error": None,
                    "evidence_source": "current_target_linecovreport",
                    "coverage_report": str(cached_report_path),
                    "branch_hit_count": branch_hit_count,
                    "blocked_side_hit_count": blocked_side_hit_count,
                    "branch_line_reached": branch_hit_count > 0,
                    "blocked_side_line_reached": blocked_side_hit_count > 0,
                    "output_dir": None,
                }

    if experiment_dir is not None:
        output_dir = experiment_dir / "blockers" / f"{function_name}_{branch_line}" / "revalidation"
    else:
        output_dir = Path("artifacts") / "blocker_revalidation" / project_name / (
            f"{target_name}_{function_name}_{branch_line}_{blocked_side_line}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    evaluation = evaluate_iteration_with_coverage(
        oss_fuzz=oss_fuzz,
        project_name=project_name,
        fuzzer_name=target_name,
        function_name=function_name,
        source_file=source_file,
        source_api_file=source_file,
        branch_line=branch_line,
        blocked_side_line=blocked_side_line,
        fuzz_seconds=max(1, int(fuzz_seconds)),
        output_dir=output_dir,
        report_basename="pre_classify_live",
        corpus_subdir_name=target_name,
    )
    evaluation["reason"] = "live_revalidation_completed" if evaluation.get("success") else "live_revalidation_failed"
    evaluation["output_dir"] = str(output_dir)
    return evaluation


def _coverage_metric_snapshot(summary: TotalCoverageSummary | None, metric_name: str) -> dict[str, float | int] | None:
    if not summary:
        return None
    metric = getattr(summary, metric_name, None)
    if not metric:
        return None
    return {
        "count": metric.count,
        "covered": metric.covered,
        "percent": metric.percent,
    }


def _coverage_growth_metric(
    before_summary: TotalCoverageSummary | None,
    after_summary: TotalCoverageSummary | None,
    metric_name: str,
) -> dict[str, float | int] | None:
    before = _coverage_metric_snapshot(before_summary, metric_name)
    after = _coverage_metric_snapshot(after_summary, metric_name)
    if before is None and after is None:
        return None

    before_count = int((before or {}).get("count", 0))
    before_covered = int((before or {}).get("covered", 0))
    before_percent = float((before or {}).get("percent", 0.0))
    after_count = int((after or {}).get("count", 0))
    after_covered = int((after or {}).get("covered", 0))
    after_percent = float((after or {}).get("percent", 0.0))
    return {
        "before_count": before_count,
        "before_covered": before_covered,
        "before_percent": before_percent,
        "after_count": after_count,
        "after_covered": after_covered,
        "after_percent": after_percent,
        "covered_delta": after_covered - before_covered,
        "percent_delta": after_percent - before_percent,
    }


def _get_project_target_fingerprint(project_name: str) -> str | None:
    try:
        return oss_fuzz._get_project_target_fingerprint(project_name)
    except BaseException as exc:
        logger.warning("Failed to compute target fingerprint for %s: %s", project_name, exc)
        return None


def _log_blocker_session_skipped(
    project_name: str,
    state: BlockerRuntimeState,
    reason: str,
    elapsed_seconds: int,
    **extra: object,
) -> None:
    _log_experiment_event(
        "blocker_session_skipped",
        project_name=project_name,
        elapsed_seconds=elapsed_seconds,
        session_number=state.sessions_run,
        reason=reason,
        artifacts_ready=state.artifacts_ready,
        artifacts_dirty=state.artifacts_dirty,
        **extra,
    )


def _default_blocker_json_candidates(project_name: str) -> list[Path]:
    build_out = oss_fuzz.build_out_dir / project_name
    return [
        build_out / "report" / "linux" / "branch-blockers.json",
        build_out / "inspector" / "branch-blockers.json",
        Path("process_blocker") / "branch-blockers.json",
        Path("branch-blockers.json"),
    ]


def _resolve_blocker_json_path(project_name: str, explicit_path: Path | None) -> Path | None:
    candidates = [explicit_path] if explicit_path else _default_blocker_json_candidates(project_name)
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    return None


def _reusable_session_artifacts(
    state: BlockerRuntimeState,
    explicit_path: Path | None,
) -> BlockerSessionArtifacts | None:
    if explicit_path is not None:
        return None
    artifacts = state.last_session_artifacts
    if artifacts and artifacts.blocker_json.is_file():
        return artifacts
    return None


def _update_max_elapsed(current: float | None, elapsed: float) -> float:
    return max(float(current or 0.0), float(elapsed))


def _record_coverage_elapsed(state: BlockerRuntimeState, elapsed: float) -> None:
    state.max_coverage_elapsed = _update_max_elapsed(state.max_coverage_elapsed, elapsed)


def _coverage_with_timing(
    project_name: str,
    state: BlockerRuntimeState,
    *,
    deadline: float | None,
) -> TotalCoverageSummary | None:
    started_at = time.perf_counter()
    summary = oss_fuzz.coverage(project_name, deadline=deadline)
    _record_coverage_elapsed(state, time.perf_counter() - started_at)
    return summary


def _minimum_blocker_attempt_reserve(
    state: BlockerRuntimeState,
    blocker_fuzz_seconds: int,
) -> float:
    attempt_estimate = max(
        float(state.max_blocker_attempt_elapsed or 0.0) * BLOCKER_REFRESH_SAFETY_MULTIPLIER,
        BLOCKER_ATTEMPT_BOOTSTRAP_SECONDS,
        float(max(1, blocker_fuzz_seconds)),
    )
    return attempt_estimate + BLOCKER_SCHEDULING_OVERHEAD_SECONDS


def _minimum_post_refresh_reserve(
    state: BlockerRuntimeState,
    blocker_fuzz_seconds: int,
) -> float:
    coverage_estimate = max(
        float(state.max_coverage_elapsed or 0.0) * BLOCKER_REFRESH_SAFETY_MULTIPLIER,
        BLOCKER_COVERAGE_BOOTSTRAP_SECONDS,
    )
    return _minimum_blocker_attempt_reserve(state, blocker_fuzz_seconds) + coverage_estimate


def _refresh_elapsed_estimate(state: BlockerRuntimeState, refresh_mode: str) -> float:
    if refresh_mode == "light_refresh":
        observed = state.max_light_refresh_elapsed
        bootstrap = BLOCKER_LIGHT_REFRESH_BOOTSTRAP_SECONDS
    else:
        observed = state.max_full_refresh_elapsed
        bootstrap = BLOCKER_FULL_REFRESH_BOOTSTRAP_SECONDS
    base = max(float(observed or 0.0), bootstrap)
    return base * BLOCKER_REFRESH_SAFETY_MULTIPLIER + BLOCKER_REFRESH_SAFETY_BUFFER_SECONDS


def _session_artifact_root(project_name: str, session_number: int) -> Path:
    if experiment_dir is not None:
        return experiment_dir / "blocker_sessions" / project_name / f"session_{session_number:03d}"
    return Path("/tmp/llm-fuzzgen-session-artifacts") / str(os.getpid()) / project_name / (
        f"session_{session_number:03d}"
    )


def _copy_tree_snapshot(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(source, destination, copy_function=os.link)
    except OSError:
        shutil.rmtree(destination, ignore_errors=True)
        shutil.copytree(source, destination, copy_function=shutil.copy2)


def _first_existing_file(candidates: list[Path]) -> Path | None:
    return next((path for path in candidates if path.is_file()), None)


def _first_existing_dir(candidates: list[Path]) -> Path | None:
    return next((path for path in candidates if path.is_dir()), None)


def _create_blocker_session_artifacts(
    project_name: str,
    session_number: int,
    blocker_json_path: Path,
    candidate_blockers: list[dict],
) -> BlockerSessionArtifacts | None:
    """Snapshot static session evidence outside mutable OSS-Fuzz build output."""
    final_root = _session_artifact_root(project_name, session_number)
    temporary_root = final_root.with_name(f".{final_root.name}.tmp")
    shutil.rmtree(temporary_root, ignore_errors=True)
    temporary_root.mkdir(parents=True, exist_ok=True)

    build_out = oss_fuzz.build_out_dir / project_name
    inspector_dir = build_out / "inspector"
    manifest: dict[str, object] = {
        "project_name": project_name,
        "session_number": session_number,
        "source_blocker_json": str(blocker_json_path),
        "candidate_targets": [],
        "copied_cfg_targets": [],
        "missing_cfg_targets": [],
    }

    try:
        cached_blocker_json = temporary_root / "branch-blockers.json"
        shutil.copy2(blocker_json_path, cached_blocker_json)

        all_functions_source = _first_existing_file(
            [blocker_json_path.parent / "all_functions.js", inspector_dir / "all_functions.js"]
        )
        cached_all_functions = None
        if all_functions_source:
            cached_all_functions = temporary_root / "all_functions.js"
            shutil.copy2(all_functions_source, cached_all_functions)

        summary_source = _first_existing_file(
            [
                blocker_json_path.parent / "summary_exclude_target.json",
                blocker_json_path.parent / "summary.json",
                inspector_dir / "summary_exclude_target.json",
                inspector_dir / "summary.json",
            ]
        )
        cached_summary = None
        if summary_source:
            cached_summary = temporary_root / summary_source.name
            shutil.copy2(summary_source, cached_summary)

        yaml_source = inspector_dir / "exe_to_fuzz_introspector_logs.yaml"
        cached_yaml = None
        copied_cfg_files: dict[str, Path] = {}
        candidate_targets = sorted(
            {
                str(blocker.get("best_target") or "").strip()
                for blocker in candidate_blockers
                if str(blocker.get("best_target") or "").strip()
            }
        )
        manifest["candidate_targets"] = candidate_targets
        if yaml_source.is_file():
            cached_yaml = temporary_root / yaml_source.name
            shutil.copy2(yaml_source, cached_yaml)
            from blocker_process.blocker_callpath_extractor import get_data_file_for_target

            # Reranking can promote a target that was outside the initial top-k.
            # All calltree files are small (a few MB per project in aggregate), so
            # snapshot the complete YAML-addressable pool instead of guessing which
            # targets the later runtime coverage ranking will select.
            for source_data in inspector_dir.glob("*.data"):
                if source_data.is_file():
                    shutil.copy2(source_data, temporary_root / source_data.name)

            for target_name in candidate_targets:
                data_file = get_data_file_for_target(str(yaml_source), target_name)
                source_data = Path(data_file) if data_file else None
                if source_data and source_data.is_file():
                    destination = temporary_root / source_data.name
                    copied_cfg_files[target_name] = destination
                    manifest["copied_cfg_targets"].append(target_name)
                else:
                    manifest["missing_cfg_targets"].append(target_name)
            manifest["copied_cfg_file_count"] = len(list(temporary_root.glob("*.data")))

        source_root_source = _first_existing_dir(
            [
                build_out / "source_code",
                inspector_dir / "source-code",
                build_out / "src" / project_name,
                build_out / "src",
            ]
        )
        cached_source_root = None
        if source_root_source:
            cached_source_root = temporary_root / "source_root"
            _copy_tree_snapshot(source_root_source, cached_source_root)
            manifest["source_root"] = str(source_root_source)

        (temporary_root / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        final_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(final_root, ignore_errors=True)
        temporary_root.replace(final_root)

        def final_path(path: Path | None) -> Path | None:
            return final_root / path.name if path is not None else None

        return BlockerSessionArtifacts(
            root=final_root,
            blocker_json=final_root / cached_blocker_json.name,
            all_functions_js=final_path(cached_all_functions),
            summary_json=final_path(cached_summary),
            yaml_file=final_path(cached_yaml),
            source_root=final_root / "source_root" if cached_source_root else None,
            cfg_data_files={target: final_root / path.name for target, path in copied_cfg_files.items()},
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("Failed to create blocker session artifact cache for %s: %s", project_name, exc)
        shutil.rmtree(temporary_root, ignore_errors=True)
        return None


def _resolve_cached_blocker_source(
    project_name: str,
    source_file: str | None,
    session_artifacts: BlockerSessionArtifacts | None,
) -> str | None:
    if not session_artifacts or not session_artifacts.source_root or not source_file:
        return None
    from blocker_process.blocker_callpath_extractor import resolve_project_source_file

    return resolve_project_source_file(
        project_name,
        source_file,
        str(session_artifacts.source_root),
    )


def _branch_blocker_snapshot_path(project_name: str, stage: str | None = None) -> Path:
    run_id = experiment_logger.run_id if experiment_logger is not None else datetime.now().strftime("%Y%m%d_%H%M%S")
    if experiment_dir is not None:
        suffix = f"_{stage}" if stage else ""
        return experiment_dir / "branch_blockers" / f"{project_name}{suffix}.json"
    return Path(__file__).parent / "artifacts" / "branch_blocker_json" / f"{run_id}_{project_name}.json"


def _write_project_blocker_snapshot(
    project_name: str,
    blocker_json_path: Path,
    blockers: list[dict],
    *,
    selection_stage: str,
    blocker_top_k: int,
    aggregated_count: int,
) -> Path | None:
    output_path = _branch_blocker_snapshot_path(project_name, stage=selection_stage)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run_id": experiment_logger.run_id if experiment_logger is not None else None,
        "project": project_name,
        "selection_stage": selection_stage,
        "source_blocker_json_path": str(blocker_json_path),
        "aggregated_count": aggregated_count,
        "filtered_count": len(blockers),
        "blocker_top_k": blocker_top_k,
        "blockers": blockers,
    }
    try:
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to write blocker snapshot to %s: %s", output_path, exc)
        return None
    return output_path


def _snapshot_existing_project_blockers(
    project_name: str,
    blocker_json_path: Path,
    blocker_top_k: int,
    coverage_context: BlockerCoverageContext,
    *,
    selection_stage: str,
    include_resolved: bool = False,
) -> tuple[list[dict], int, Path | None]:
    blockers, aggregated_count = _select_project_blockers(
        project_name,
        blocker_json_path,
        blocker_top_k,
        coverage_context,
        include_resolved=include_resolved,
        return_aggregated_count=True,
    )
    snapshot_path = _write_project_blocker_snapshot(
        project_name,
        blocker_json_path,
        blockers,
        selection_stage=selection_stage,
        blocker_top_k=blocker_top_k,
        aggregated_count=aggregated_count,
    )
    return blockers, aggregated_count, snapshot_path


def ensure_blocker_webapp_ready(project_name: str) -> bool:
    logger.info("Ensuring Introspector webapp is ready for blocker session on %s.", project_name)
    if introspector.update_start_webapp():
        return True
    logger.error("Failed to start Introspector webapp for blocker session on %s.", project_name)
    return False


def ensure_blocker_artifacts(
    project_name: str,
    report_seconds: int,
    state: BlockerRuntimeState,
    force_refresh: bool = False,
    prefer_full_refresh: bool = False,
    deadline: float | None = None,
    post_refresh_reserve_seconds: float = 0.0,
) -> bool:
    state.last_artifact_refresh_skip_reason = None
    state.last_artifact_refresh_reused_existing = False
    if deadline is not None and deadline - time.monotonic() <= 0:
        logger.info("Skipping blocker artifact refresh for %s because the fuzzing deadline was reached.", project_name)
        state.last_artifact_refresh_skip_reason = "deadline_reached"
        return False

    blocker_json_path = _resolve_blocker_json_path(project_name, None)
    first_artifact_refresh = not state.artifacts_ready
    if blocker_json_path is not None and state.artifacts_ready and not force_refresh:
        return True

    use_light_refresh = state.artifacts_ready and force_refresh and not prefer_full_refresh
    refresh_mode = "light_refresh" if use_light_refresh else "full_refresh"
    refresh_deadline = deadline
    if deadline is not None and post_refresh_reserve_seconds > 0:
        refresh_deadline = deadline - max(0.0, post_refresh_reserve_seconds)
        available = refresh_deadline - time.monotonic()
        estimate = _refresh_elapsed_estimate(state, refresh_mode)
        if available <= 0 or estimate > available:
            state.last_artifact_refresh_skip_reason = "insufficient_time_budget"
            logger.info(
                "Skipping blocker artifact refresh for %s: mode=%s estimate=%.2fs available=%.2fs "
                "post_refresh_reserve=%.2fs.",
                project_name,
                refresh_mode,
                estimate,
                max(0.0, available),
                post_refresh_reserve_seconds,
            )
            return False

    logger.info(
        "Refreshing blocker artifacts for %s (mode=%s, force_refresh=%s, report_seconds=%s).",
        project_name,
        refresh_mode,
        force_refresh,
        report_seconds,
    )
    started_at = time.perf_counter()
    if use_light_refresh:
        success = oss_fuzz.refresh_blocker_report_from_existing_introspector(
            project_name,
            deadline=refresh_deadline,
        )
        if not success:
            logger.warning(
                "Light blocker artifact refresh failed for %s; reusing existing blocker artifacts instead of "
                "falling back to a full Introspector refresh.",
                project_name,
            )
            elapsed = time.perf_counter() - started_at
            state.last_artifact_refresh_skip_reason = "light_refresh_failed_reused_existing_artifacts"
            state.last_artifact_refresh_reused_existing = True
            _log_experiment_event(
                "blocker_artifacts_refresh_finished",
                success=True,
                project_name=project_name,
                refresh_mode="light_refresh_reused_existing",
                force_refresh=force_refresh,
                report_seconds=report_seconds,
                elapsed_seconds=elapsed,
                reason=state.last_artifact_refresh_skip_reason,
            )
            return True
    else:
        success = oss_fuzz.generate_report(
            project_name,
            seconds=report_seconds,
            clean=force_refresh,
            deadline=refresh_deadline,
        )
    elapsed = time.perf_counter() - started_at
    _log_experiment_event(
        "blocker_artifacts_refresh_finished",
        success=success,
        project_name=project_name,
        refresh_mode=refresh_mode,
        force_refresh=force_refresh,
        report_seconds=report_seconds,
        elapsed_seconds=elapsed,
    )
    if not success:
        logger.warning("Failed to refresh blocker artifacts for %s.", project_name)
        return False

    state.artifacts_ready = True
    state.artifacts_dirty = False
    state.last_artifact_refresh_elapsed = elapsed
    if refresh_mode.startswith("full_refresh"):
        state.max_full_refresh_elapsed = _update_max_elapsed(state.max_full_refresh_elapsed, elapsed)
    else:
        state.max_light_refresh_elapsed = _update_max_elapsed(state.max_light_refresh_elapsed, elapsed)
    current_fingerprint = _get_project_target_fingerprint(project_name)
    if refresh_mode.startswith("full_refresh"):
        state.artifact_target_fingerprint = current_fingerprint
        state.pending_target_fingerprint = current_fingerprint
        state.new_targets_since_full_rebuild = 0
        state.light_refreshes_since_full_rebuild = 0
    else:
        state.pending_target_fingerprint = current_fingerprint
        state.light_refreshes_since_full_rebuild += 1

    if first_artifact_refresh:
        resolved_json_path = _resolve_blocker_json_path(project_name, None)
        if resolved_json_path is None:
            logger.warning("Initial blocker artifact refresh for %s succeeded but branch-blockers.json is unavailable.", project_name)
            return True
        coverage_context = _load_blocker_coverage_context(
            project_name,
            resolved_json_path,
            deadline=refresh_deadline,
            repair_missing=True,
        )
        if coverage_context is None:
            logger.warning(
                "Initial blocker artifact refresh for %s completed, but project blocker coverage context is incomplete.",
                project_name,
            )
            return True
        _snapshot_existing_project_blockers(
            project_name,
            resolved_json_path,
            blocker_top_k=0,
            coverage_context=coverage_context,
            selection_stage="initial_introspector_refresh",
        )
    return True


def _read_existing_project_linecov_report(project_name: str) -> str:
    report_path = oss_fuzz.build_out_dir / project_name / "textcov_reports" / "project.linecovreport"
    if report_path.exists():
        return report_path.read_text(encoding="utf-8")
    return ""


def _load_project_target_reports(project_name: str) -> dict[str, str]:
    reports_dir = oss_fuzz.build_out_dir / project_name / "textcov_reports"
    if not reports_dir.is_dir():
        return {}

    reports: dict[str, str] = {}
    for report_path in sorted(reports_dir.glob("*.linecovreport")):
        if report_path.stem == "project":
            continue
        reports[report_path.stem] = report_path.read_text(encoding="utf-8")
    return reports


def _normalize_hitcount(raw: str) -> int:
    text = str(raw or "").strip()
    if not text or text == "0":
        return 0

    suffix = text[-1]
    multiplier = {"k": 1_000, "M": 1_000_000, "G": 1_000_000_000}.get(suffix, 1)
    numeric = text[:-1] if multiplier != 1 else text
    try:
        return int(float(numeric) * multiplier)
    except ValueError:
        return 0


def _read_branch_blocker_targets(blocker_json_path: Path) -> list[str]:
    try:
        data = json.loads(blocker_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read blocker json %s: %s", blocker_json_path, exc)
        return []

    if not isinstance(data, dict):
        return []
    return sorted(str(target_name) for target_name in data.keys())


def _expected_blocker_coverage_files(project_name: str, blocker_targets: list[str]) -> list[Path]:
    reports_dir = oss_fuzz.build_out_dir / project_name / "textcov_reports"
    expected = [
        reports_dir / "project.linecovreport",
        reports_dir / "summary_exclude_target.json",
    ]
    expected.extend(reports_dir / f"{target_name}.linecovreport" for target_name in blocker_targets)
    return expected


def _load_blocker_coverage_context(
    project_name: str,
    blocker_json_path: Path,
    deadline: float | None = None,
    repair_missing: bool = True,
) -> BlockerCoverageContext | None:
    blocker_targets = _read_branch_blocker_targets(blocker_json_path)
    expected_files = _expected_blocker_coverage_files(project_name, blocker_targets)
    missing_files = [path for path in expected_files if not path.exists()]

    if missing_files and repair_missing:
        logger.warning(
            "Blocker coverage artifacts missing for %s; attempting repair via coverage(): %s",
            project_name,
            ", ".join(str(path.name) for path in missing_files[:8]),
        )
        oss_fuzz.coverage(project_name, deadline=deadline)
        missing_files = [path for path in expected_files if not path.exists()]

    if missing_files:
        logger.warning(
            "Blocker coverage artifacts are still incomplete for %s: %s",
            project_name,
            ", ".join(str(path) for path in missing_files[:8]),
        )
        return None

    project_report = _read_existing_project_linecov_report(project_name)
    target_reports = _load_project_target_reports(project_name)
    if not project_report:
        logger.warning("Project line coverage report is empty for %s.", project_name)
        return None

    available_targets = {target_name for target_name in blocker_targets if target_name in target_reports}
    if len(available_targets) != len(blocker_targets):
        missing_targets = sorted(set(blocker_targets) - available_targets)
        logger.warning(
            "Blocker target line coverage reports could not be loaded for %s: %s",
            project_name,
            ", ".join(missing_targets[:8]),
        )
        return None

    return BlockerCoverageContext(
        project_report=project_report,
        target_reports=target_reports,
    )


def _filter_and_refine_project_blockers(
    blockers: list[dict],
    coverage_context: BlockerCoverageContext,
) -> list[dict]:
    filtered: list[dict] = []
    for blocker in blockers:
        branch_line = int(str(blocker.get("branch_line_number", "0")) or 0)
        blocked_side_line = int(
            str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "0"))) or 0
        )
        function_name = blocker.get("function_name")
        source_file = blocker.get("source_file") or ""
        project_branch_hit_count = _normalize_hitcount(
            get_line_execution_count(
                coverage_context.project_report,
                branch_line,
                function_name=function_name,
                source_file=source_file,
            )
        )
        project_blocked_hit_count = _normalize_hitcount(
            get_line_execution_count(
                coverage_context.project_report,
                blocked_side_line,
                function_name=function_name,
                source_file=source_file,
            )
        )

        if project_branch_hit_count <= 0 or project_blocked_hit_count > 0:
            continue

        refined = dict(blocker)
        refined["project_branch_hit_count"] = project_branch_hit_count
        refined["project_blocked_hit_count"] = project_blocked_hit_count
        refined["project_branch_reached"] = True
        refined["project_blocked_side_reached"] = False
        refined["project_blocker_state"] = "stalled_at_branch"
        refined["project_relevant"] = True

        contributing_targets = [
            str(target_name)
            for target_name in blocker.get("contributing_targets", [])
            if str(target_name) in coverage_context.target_reports
        ]
        branch_reached_targets: list[str] = []
        blocked_side_reached_targets: list[str] = []
        target_hit_details: list[dict[str, int | str]] = []
        refined_best_target = refined.get("best_target")
        refined_best_score = (-1, -1)

        for target_name in contributing_targets:
            report = coverage_context.target_reports[target_name]
            branch_hit_count = _normalize_hitcount(
                get_line_execution_count(report, branch_line, function_name=function_name, source_file=source_file)
            )
            blocked_hit_count = _normalize_hitcount(
                get_line_execution_count(report, blocked_side_line, function_name=function_name, source_file=source_file)
            )
            if branch_hit_count > 0:
                branch_reached_targets.append(target_name)
            if blocked_hit_count > 0:
                blocked_side_reached_targets.append(target_name)
            if branch_hit_count > 0 or blocked_hit_count > 0:
                target_hit_details.append(
                    {
                        "target_name": target_name,
                        "branch_hit_count": branch_hit_count,
                        "blocked_hit_count": blocked_hit_count,
                    }
                )
            if branch_hit_count > 0 and blocked_hit_count == 0:
                score = (branch_hit_count, 1 if target_name == blocker.get("best_target") else 0)
                if score > refined_best_score:
                    refined_best_score = score
                    refined_best_target = target_name

        refined["project_branch_reached_targets"] = sorted(branch_reached_targets)
        refined["project_blocked_side_reached_targets"] = sorted(blocked_side_reached_targets)
        refined["project_branch_reached_target_count"] = len(branch_reached_targets)
        refined["project_blocked_side_reached_target_count"] = len(blocked_side_reached_targets)
        refined["project_target_hit_details"] = sorted(
            target_hit_details,
            key=lambda item: (int(item["branch_hit_count"]), -int(item["blocked_hit_count"])),
            reverse=True,
        )
        if refined_best_target:
            refined["best_target"] = refined_best_target
        filtered.append(refined)

    return filtered


def _build_blocker_immediate_validation_record(
    project_name: str,
    blocker: dict,
    pipeline_result: dict,
) -> dict | None:
    project_report = _read_existing_project_linecov_report(project_name)
    if not project_report:
        return None

    function_name = blocker.get("function_name")
    source_file = blocker.get("source_file") or ""
    branch_line_number = int(str(blocker.get("branch_line_number", "0")) or 0)
    blocked_side_line_number = int(
        str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "0"))) or 0
    )
    branch_hit_before = int(blocker.get("project_branch_hit_count", 0) or 0)
    blocked_side_hit_before = int(blocker.get("project_blocked_hit_count", 0) or 0)
    branch_hit_after = _normalize_hitcount(
        get_line_execution_count(project_report, branch_line_number, function_name=function_name, source_file=source_file)
    )
    blocked_side_hit_after = _normalize_hitcount(
        get_line_execution_count(project_report, blocked_side_line_number, function_name=function_name, source_file=source_file)
    )

    return {
        "event": "blocker_breakthrough_validation",
        "project": project_name,
        "target_name": blocker.get("best_target"),
        "function_name": function_name,
        "branch_line_number": branch_line_number,
        "blocked_side_line_number": blocked_side_line_number,
        "branch_hit_before": branch_hit_before,
        "branch_hit_after": branch_hit_after,
        "blocked_side_hit_before": blocked_side_hit_before,
        "blocked_side_hit_after": blocked_side_hit_after,
        "branch_newly_reached": branch_hit_before == 0 and branch_hit_after > 0,
        "blocked_side_newly_reached": blocked_side_hit_before == 0 and blocked_side_hit_after > 0,
        "blocker_solved_immediately": blocked_side_hit_before == 0 and blocked_side_hit_after > 0,
        "dependency_result": pipeline_result.get("dependency_result"),
        "attempt_result": pipeline_result.get("attempt_result"),
        "pipeline_methods": pipeline_result.get("pipeline_methods", []),
        "pipeline_success": pipeline_result.get("pipeline_success"),
        "pipeline_success_stage": pipeline_result.get("pipeline_success_stage"),
        "triage_result": pipeline_result.get("triage_result"),
        "classify_elapsed_seconds": pipeline_result.get("classify_elapsed_seconds"),
        "pipeline_elapsed_seconds": pipeline_result.get("pipeline_elapsed_seconds"),
    }


def _blocker_identity(blocker: dict) -> tuple[str, str, str, str]:
    return canonical_blocker_key(blocker)


def _should_persist_blocker_attempt(pipeline_result: dict) -> bool:
    return pipeline_result.get("attempt_result") in {
        "success",
        "failed",
        "triage_skipped",
        "triage_manual_review",
    }


def _select_project_blockers(
    project_name: str,
    blocker_json_path: Path,
    blocker_top_k: int,
    coverage_context: BlockerCoverageContext,
    *,
    include_resolved: bool = False,
    return_aggregated_count: bool = False,
) -> list[dict] | tuple[list[dict], int]:
    selection_started_at = time.perf_counter()
    blockers = aggregate_score_and_revalidate_blockers(
        json_path=str(blocker_json_path),
        project_target_reports=coverage_context.target_reports,
        top_k=None,
        include_resolved=include_resolved,
        project_name=project_name,
    )
    aggregated_count = len(blockers)
    filtered = _filter_and_refine_project_blockers(blockers, coverage_context)
    if blocker_top_k > 0:
        filtered = filtered[:blocker_top_k]
    selection_elapsed = time.perf_counter() - selection_started_at
    logger.info(
        "Blocker selector for %s completed in %.2fs and produced %d candidate(s) after project validation from %d aggregated blocker(s) (top_k=%d).",
        project_name,
        selection_elapsed,
        len(filtered),
        aggregated_count,
        blocker_top_k,
    )
    _log_experiment_event(
        "blocker_selection_completed",
        project_name=project_name,
        blocker_json_path=str(blocker_json_path),
        include_resolved=include_resolved,
        blocker_top_k=blocker_top_k,
        aggregated_count=aggregated_count,
        filtered_count=len(filtered),
        selection_elapsed_seconds=selection_elapsed,
    )
    if return_aggregated_count:
        return filtered, aggregated_count
    return filtered


def run_blocker_pipeline(
    project_name: str,
    llm_backend: str,
    model_name: str | None,
    blocker_json_path: Path | None = None,
    blocker_index: int = 0,
    blocker_record: dict | None = None,
    blocker_top_k: int = 12,
    blocker_max_iterations: int = config.BLOCKER_MAX_ITERATIONS,
    blocker_fuzz_seconds: int = 15,
    blocker_reset_corpus_per_iteration: bool = False,
    blocker_keep_auto_context: bool = False,
    blocker_pipeline_mode: str | None = None,
    skip_input_dependent_pipeline: bool = False,
    skip_input_independent_pipeline: bool = False,
    enable_blocker_triage: bool = False,
    deadline: float | None = None,
    session_artifacts: BlockerSessionArtifacts | None = None,
) -> dict:
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.info("Skipping blocker pipeline for %s because the fuzzing deadline was reached.", project_name)
            return {"success": False, "reason": "deadline_reached", "dependency_result": None}
        blocker_fuzz_seconds = min(blocker_fuzz_seconds, max(1, int(remaining)))

    resolved_json_path = _resolve_blocker_json_path(project_name, blocker_json_path)
    if resolved_json_path is None:
        logger.warning("Blocker mode enabled, but no branch-blockers.json was found for %s.", project_name)
        return {"success": False, "reason": "missing_blocker_json", "dependency_result": None}

    blocker = blocker_record
    if blocker is None:
        coverage_context = _load_blocker_coverage_context(
            project_name,
            resolved_json_path,
            deadline=deadline,
            repair_missing=True,
        )
        if coverage_context is None:
            logger.warning("Blocker coverage context is incomplete for %s.", project_name)
            return {"success": False, "reason": "missing_project_target_linecov", "dependency_result": None}
        blockers = _select_project_blockers(
            project_name,
            resolved_json_path,
            blocker_top_k,
            coverage_context,
            include_resolved=True,
        )
        if not blockers:
            logger.warning("No blockers available in %s.", resolved_json_path)
            return {"success": False, "reason": "no_blockers", "dependency_result": None}

        if blocker_index < 0 or blocker_index >= len(blockers):
            logger.warning(
                "Requested blocker index %d is out of range for %s. Available blockers: %d.",
                blocker_index,
                project_name,
                len(blockers),
            )
            return {"success": False, "reason": "blocker_index_out_of_range", "dependency_result": None}
        blocker = blockers[blocker_index]
    blocked_side_line_number = blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder"))
    logger.info(
        "Running blocker pipeline for %s using blocker #%d: %s:%s target=%s",
        project_name,
        blocker_index,
        blocker.get("function_name", "unknown"),
        blocker.get("branch_line_number", "unknown"),
        blocker.get("best_target", "unknown"),
    )
    _log_experiment_event(
        "blocker_pipeline_started",
        blocker_json_path=resolved_json_path,
        blocker_index=blocker_index,
        function_name=blocker.get("function_name"),
        branch_line_number=blocker.get("branch_line_number"),
        blocked_side_line_number=blocked_side_line_number,
        target_name=blocker.get("best_target"),
    )

    live_revalidation = _live_revalidate_blocker_before_classify(
        project_name=project_name,
        blocker=blocker,
        fuzz_seconds=blocker_fuzz_seconds,
    )
    _log_experiment_event(
        "blocker_live_revalidation",
        project_name=project_name,
        blocker_json_path=str(resolved_json_path),
        blocker_index=blocker_index,
        target_name=blocker.get("best_target"),
        function_name=blocker.get("function_name"),
        branch_line_number=blocker.get("branch_line_number"),
        blocked_side_line_number=blocked_side_line_number,
        success=live_revalidation.get("success"),
        reason=live_revalidation.get("reason"),
        error=live_revalidation.get("error"),
        evidence_source=live_revalidation.get("evidence_source", "coverage_replay"),
        coverage_report=live_revalidation.get("coverage_report"),
        branch_hit_count=live_revalidation.get("branch_hit_count"),
        blocked_side_hit_count=live_revalidation.get("blocked_side_hit_count"),
        branch_line_reached=live_revalidation.get("branch_line_reached"),
        blocked_side_line_reached=live_revalidation.get("blocked_side_line_reached"),
        output_dir=live_revalidation.get("output_dir"),
    )
    if not live_revalidation.get("success"):
        logger.warning(
            "Skipping blocker pipeline for %s because live revalidation failed for %s:%s target=%s: %s",
            project_name,
            blocker.get("function_name", "unknown"),
            blocker.get("branch_line_number", "unknown"),
            blocker.get("best_target", "unknown"),
            live_revalidation.get("error", "unknown error"),
        )
        return {
            "success": False,
            "reason": "live_revalidation_failed",
            "attempt_result": "pipeline_error",
            "dependency_result": None,
            "pipeline_methods": [],
            "pipeline_success": None,
            "pipeline_success_stage": None,
            "pipeline_failure_stage": "live_revalidation",
            "pipeline_returncode": 1,
            "classify_elapsed_seconds": 0.0,
            "pipeline_elapsed_seconds": 0.0,
            "live_revalidation": live_revalidation,
        }
    if live_revalidation.get("blocked_side_line_reached"):
        logger.info(
            "Skipping blocker pipeline for %s because blocker is already covered at solve time: %s:%s target=%s "
            "(branch=%s blocked_side=%s).",
            project_name,
            blocker.get("function_name", "unknown"),
            blocker.get("branch_line_number", "unknown"),
            blocker.get("best_target", "unknown"),
            live_revalidation.get("branch_hit_count", 0),
            live_revalidation.get("blocked_side_hit_count", 0),
        )
        return {
            "success": False,
            "reason": "already_covered_at_solve_time",
            "attempt_result": "skipped",
            "dependency_result": None,
            "pipeline_methods": [],
            "pipeline_success": None,
            "pipeline_success_stage": None,
            "pipeline_failure_stage": "live_revalidation",
            "pipeline_returncode": 0,
            "classify_elapsed_seconds": 0.0,
            "pipeline_elapsed_seconds": 0.0,
            "live_revalidation": live_revalidation,
        }
    if not live_revalidation.get("branch_line_reached"):
        logger.info(
            "Skipping blocker pipeline for %s because live revalidation no longer reaches the blocker branch: %s:%s "
            "target=%s.",
            project_name,
            blocker.get("function_name", "unknown"),
            blocker.get("branch_line_number", "unknown"),
            blocker.get("best_target", "unknown"),
        )
        return {
            "success": False,
            "reason": "branch_not_reached_at_solve_time",
            "attempt_result": "skipped",
            "dependency_result": None,
            "pipeline_methods": [],
            "pipeline_success": None,
            "pipeline_success_stage": None,
            "pipeline_failure_stage": "live_revalidation",
            "pipeline_returncode": 0,
            "classify_elapsed_seconds": 0.0,
            "pipeline_elapsed_seconds": 0.0,
            "live_revalidation": live_revalidation,
        }

    pipeline_started_at = time.perf_counter()
    _blocker_fn = blocker.get("function_name", "unknown")
    _blocker_branch_line = blocker.get("branch_line_number", 0)
    _blocker_base = (
        experiment_dir / "blockers" / f"{_blocker_fn}_{_blocker_branch_line}"
        if experiment_dir is not None
        else None
    )
    _blocker_log_dir = (
        _blocker_base / "logs"
        if (
            _blocker_base is not None
            and experiment_logger is not None
            and experiment_logger.project_name == "run_all_fuzzer"
        )
        else None
    )
    cached_source_file = _resolve_cached_blocker_source(
        project_name,
        blocker.get("source_file"),
        session_artifacts,
    )
    args = argparse.Namespace(
        backend=llm_backend,
        model=model_name,
        project_name=project_name,
        function_name=blocker.get("function_name"),
        branch_line_number=blocker.get("branch_line_number"),
        blocked_side_line_number=blocked_side_line_number,
        blocker_json=None,
        blocker_json_file=str(resolved_json_path),
        source_file=cached_source_file,
        source_api_file=blocker.get("source_file"),
        fuzz_file=None,
        header_file=None,
        target_name=blocker.get("best_target"),
        yaml_file=(str(session_artifacts.yaml_file) if session_artifacts and session_artifacts.yaml_file else None),
        callpath_source_root=(
            str(session_artifacts.source_root)
            if session_artifacts and session_artifacts.source_root
            else None
        ),
        max_gdb_inputs=0,
        runtime_blocker_segment_file=None,
        runtime_blocker_segment_source_codes_file=None,
        cfg_call_chain_file=None,
        cfg_source_codes_file=None,
        runtime_blocker_segment=None,
        runtime_blocker_segment_source_codes=None,
        cfg_call_chain=None,
        cfg_source_codes=None,
        runtime_collection_status="unknown",
        runtime_collection_error="",
        cfg_collection_status="unknown",
        cfg_collection_error="",
        triggering_input="",
        max_iterations=blocker_max_iterations,
        fuzz_seconds=blocker_fuzz_seconds,
        reset_corpus_per_iteration=blocker_reset_corpus_per_iteration,
        keep_auto_context=blocker_keep_auto_context,
        blocker_pipeline_mode=blocker_pipeline_mode,
        skip_input_dependent_pipeline=skip_input_dependent_pipeline,
        skip_input_independent_pipeline=skip_input_independent_pipeline,
        enable_triage=enable_blocker_triage,
        skip_triage=False,
        triage_emit_prompts_only=False,
        triage_source_context_lines=25,
        branch_hit_count=live_revalidation.get("branch_hit_count"),
        blocked_side_hit_count=live_revalidation.get("blocked_side_hit_count"),
        classify_only=False,
        language=None,
        output_root=str(_blocker_base) if _blocker_base is not None else None,
        log_dir=str(_blocker_log_dir) if _blocker_log_dir is not None else None,
    )

    classify_started_at = time.perf_counter()
    try:
        result = classify_blocker(args, execute_pipeline=True)
    except Exception as exc:
        classify_elapsed = time.perf_counter() - classify_started_at
        pipeline_elapsed = time.perf_counter() - pipeline_started_at
        logger.exception(
            "Blocker pipeline classification failed for %s at %s:%s; continuing fuzzing loop.",
            project_name,
            blocker.get("function_name"),
            blocker.get("branch_line_number"),
        )
        failure_result = {
            "success": False,
            "attempt_result": "llm_error",
            "pipeline_returncode": -1,
            "pipeline_methods": [],
            "pipeline_output": {
                "parsed_output": {
                    "success": False,
                    "attempt_result": "llm_error",
                    "failure_stage": "classification",
                }
            },
            "dependency_result": "Classification Failed",
            "reason": str(exc),
            "parsed_result": None,
            "response_text": "",
            "prompt": "",
        }
        _log_experiment_event(
            "blocker_pipeline_result",
            success=False,
            attempt_result="llm_error",
            pipeline_returncode=-1,
            dependency_result="Classification Failed",
            pipeline_methods=[],
            pipeline_success=False,
            pipeline_output_dir=None,
            pipeline_summary_path=None,
            pipeline_success_stage=None,
            pipeline_failure_stage="classification",
            classify_elapsed_seconds=classify_elapsed,
            pipeline_elapsed_seconds=pipeline_elapsed,
            reason=str(exc),
            target_name=blocker.get("best_target"),
            function_name=blocker.get("function_name"),
            branch_line_number=blocker.get("branch_line_number"),
            blocked_side_line_number=blocked_side_line_number,
        )
        _append_blocker_attempt_record(
            event="blocker_pipeline_result",
            success=False,
            attempt_result="llm_error",
            dependency_result="Classification Failed",
            target_name=blocker.get("best_target"),
            function_name=blocker.get("function_name"),
            branch_line_number=blocker.get("branch_line_number"),
            blocked_side_line_number=blocked_side_line_number,
            pipeline_methods=[],
            pipeline_returncode=-1,
            pipeline_success=False,
            pipeline_success_stage=None,
            pipeline_failure_stage="classification",
            classify_elapsed_seconds=classify_elapsed,
            pipeline_elapsed_seconds=pipeline_elapsed,
            pipeline_output_dir=None,
            pipeline_summary_path=None,
            reason=str(exc),
        )
        return failure_result
    finally:
        # Classifier/solver stages run child processes that share build/out but
        # cannot update this process's in-memory sanitizer/build identity.
        oss_fuzz.invalidate_project_build_state(
            project_name,
            reason="blocker_pipeline_subprocess_finished",
        )
    classify_elapsed = time.perf_counter() - classify_started_at
    pipeline_elapsed = time.perf_counter() - pipeline_started_at
    pipeline_returncode = result.get("pipeline_returncode", 0)
    success = bool(result["success"]) if "success" in result else pipeline_returncode == 0
    attempt_result = result.get("attempt_result", "success" if success else "failed")
    pipeline_methods = result.get("pipeline_methods", [])
    pipeline_output = result.get("pipeline_output") or {}
    pipeline_parsed_output = pipeline_output.get("parsed_output") if isinstance(pipeline_output, dict) else None
    triage_result = result.get("triage_result") or {}
    pipeline_success = None
    pipeline_output_dir = None
    pipeline_summary_path = None
    pipeline_success_stage = None
    pipeline_failure_stage = None
    if isinstance(pipeline_parsed_output, dict):
        pipeline_success = pipeline_parsed_output.get("success")
        pipeline_output_dir = pipeline_parsed_output.get("output_dir")
        pipeline_summary_path = pipeline_parsed_output.get("summary_path")
        pipeline_success_stage = pipeline_parsed_output.get("success_stage")
        pipeline_failure_stage = pipeline_parsed_output.get("failure_stage")
    elif attempt_result == "pipeline_error":
        pipeline_failure_stage = "solver_dispatch"

    result_reason = result.get("pipeline_error_reason") or result.get("reason")

    _log_experiment_event(
        "blocker_pipeline_result",
        success=success,
        attempt_result=attempt_result,
        pipeline_returncode=pipeline_returncode,
        dependency_result=result.get("dependency_result"),
        pipeline_methods=pipeline_methods,
        pipeline_success=pipeline_success,
        pipeline_output_dir=pipeline_output_dir,
        pipeline_summary_path=pipeline_summary_path,
        pipeline_success_stage=pipeline_success_stage,
        pipeline_failure_stage=pipeline_failure_stage,
        classify_elapsed_seconds=classify_elapsed,
        pipeline_elapsed_seconds=pipeline_elapsed,
        reason=result_reason,
        analysis_trace=(result.get("parsed_result") or {}).get("analysis_trace", []),
        triage_first_layer_decision=triage_result.get("first_layer_decision"),
        triage_refined_label=triage_result.get("refined_triage_label"),
        triage_solver_action=triage_result.get("solver_action"),
        triage_raw_first_layer_decision=triage_result.get("raw_first_layer_decision"),
        triage_raw_refined_label=triage_result.get("raw_refined_triage_label"),
        triage_raw_solver_action=triage_result.get("raw_solver_action"),
        triage_routing_source=triage_result.get("routing_source"),
        triage_normalization_applied=triage_result.get("normalization_applied"),
        triage_normalization_reason=triage_result.get("normalization_reason"),
        triage_review_required=triage_result.get("review_required"),
        triage_required_condition=triage_result.get("required_condition"),
        triage_producer_path_status=triage_result.get("producer_path_status"),
        triage_practical_feasibility=triage_result.get("practical_feasibility"),
        triage_evidence_contract_satisfied=triage_result.get("evidence_contract_satisfied"),
        triage_status=triage_result.get("triage_status"),
        triage_error_reason=triage_result.get("triage_error_reason"),
        triage_llm_attempt_count=triage_result.get("llm_attempt_count"),
        triage_evidence_strength=triage_result.get("evidence_strength"),
        triage_classifier_agreement=triage_result.get("classifier_agreement"),
        triage_source_overrides_classifier=triage_result.get("source_overrides_classifier"),
        triage_required_solver_hint=triage_result.get("required_solver_hint"),
        triage_prompt_path=triage_result.get("triage_prompt_path"),
        triage_parsed_path=triage_result.get("triage_parsed_path"),
        target_name=blocker.get("best_target"),
        function_name=blocker.get("function_name"),
        branch_line_number=blocker.get("branch_line_number"),
        blocked_side_line_number=blocked_side_line_number,
    )
    _append_blocker_attempt_record(
        event="blocker_pipeline_result",
        success=success,
        attempt_result=attempt_result,
        dependency_result=result.get("dependency_result"),
        target_name=blocker.get("best_target"),
        function_name=blocker.get("function_name"),
        branch_line_number=blocker.get("branch_line_number"),
        blocked_side_line_number=blocked_side_line_number,
        pipeline_methods=pipeline_methods,
        pipeline_returncode=pipeline_returncode,
        pipeline_success=pipeline_success,
        pipeline_success_stage=pipeline_success_stage,
        pipeline_failure_stage=pipeline_failure_stage,
        classify_elapsed_seconds=classify_elapsed,
        pipeline_elapsed_seconds=pipeline_elapsed,
        pipeline_output_dir=pipeline_output_dir,
        pipeline_summary_path=pipeline_summary_path,
        reason=result_reason,
        analysis_trace=(result.get("parsed_result") or {}).get("analysis_trace", []),
        triage_first_layer_decision=triage_result.get("first_layer_decision"),
        triage_refined_label=triage_result.get("refined_triage_label"),
        triage_solver_action=triage_result.get("solver_action"),
        triage_raw_first_layer_decision=triage_result.get("raw_first_layer_decision"),
        triage_raw_refined_label=triage_result.get("raw_refined_triage_label"),
        triage_raw_solver_action=triage_result.get("raw_solver_action"),
        triage_routing_source=triage_result.get("routing_source"),
        triage_normalization_applied=triage_result.get("normalization_applied"),
        triage_normalization_reason=triage_result.get("normalization_reason"),
        triage_review_required=triage_result.get("review_required"),
        triage_required_condition=triage_result.get("required_condition"),
        triage_producer_path_status=triage_result.get("producer_path_status"),
        triage_practical_feasibility=triage_result.get("practical_feasibility"),
        triage_evidence_contract_satisfied=triage_result.get("evidence_contract_satisfied"),
        triage_status=triage_result.get("triage_status"),
        triage_error_reason=triage_result.get("triage_error_reason"),
        triage_llm_attempt_count=triage_result.get("llm_attempt_count"),
        triage_evidence_strength=triage_result.get("evidence_strength"),
        triage_classifier_agreement=triage_result.get("classifier_agreement"),
        triage_source_overrides_classifier=triage_result.get("source_overrides_classifier"),
        triage_required_solver_hint=triage_result.get("required_solver_hint"),
        triage_prompt_path=triage_result.get("triage_prompt_path"),
        triage_parsed_path=triage_result.get("triage_parsed_path"),
    )
    if success:
        logger.info(
            "Blocker pipeline finished successfully for %s in %.2fs (classify=%.2fs).",
            project_name,
            pipeline_elapsed,
            classify_elapsed,
        )
    elif attempt_result in {"triage_skipped", "triage_manual_review"}:
        logger.info(
            "Blocker pipeline stopped by triage for %s in %.2fs (classify=%.2fs): %s/%s.",
            project_name,
            pipeline_elapsed,
            classify_elapsed,
            triage_result.get("first_layer_decision"),
            triage_result.get("refined_triage_label"),
        )
    else:
        logger.warning(
            "Blocker pipeline returned non-zero status for %s in %.2fs (classify=%.2fs): %s",
            project_name,
            pipeline_elapsed,
            classify_elapsed,
            pipeline_returncode,
        )
    return {
        "success": success,
        "attempt_result": attempt_result,
        "reason": result_reason,
        "dependency_result": result.get("dependency_result"),
        "pipeline_methods": pipeline_methods,
        "pipeline_success": pipeline_success,
        "pipeline_success_stage": pipeline_success_stage,
        "pipeline_failure_stage": pipeline_failure_stage,
        "pipeline_returncode": pipeline_returncode,
        "triage_result": triage_result,
        "classify_elapsed_seconds": classify_elapsed,
        "pipeline_elapsed_seconds": pipeline_elapsed,
        "live_revalidation": live_revalidation,
    }


def run_blocker_session(
    project_name: str,
    elapsed_seconds: int,
    llm_backend: str,
    model_name: str | None,
    state: BlockerRuntimeState,
    blocker_json_path: Path | None = None,
    blocker_start_index: int = 0,
    blocker_session_size: int = 1,
    blocker_top_k: int = 12,
    blocker_max_iterations: int = config.BLOCKER_MAX_ITERATIONS,
    blocker_fuzz_seconds: int = 15,
    blocker_reset_corpus_per_iteration: bool = False,
    blocker_keep_auto_context: bool = False,
    blocker_pipeline_mode: str | None = None,
    skip_input_dependent_pipeline: bool = False,
    skip_input_independent_pipeline: bool = False,
    enable_blocker_triage: bool = False,
    blocker_session_refresh_mode: str = "reuse_session_artifacts",
    blocker_artifact_report_seconds: int = 30,
    blocker_refresh_branch_growth_threshold: float = 0.05,
    blocker_refresh_branch_growth_floor: int = 50,
    pre_blocker_coverage_summary: TotalCoverageSummary | None = None,
    deadline: float | None = None,
) -> dict:
    if deadline is not None and deadline - time.monotonic() <= 0:
        logger.info("Skipping blocker session for %s because the fuzzing deadline was reached.", project_name)
        return {"success": False, "attempted": 0, "succeeded": 0, "reason": "deadline_reached"}

    state.sessions_run += 1
    state.last_stall_elapsed = elapsed_seconds
    post_refresh_reserve = _minimum_post_refresh_reserve(state, blocker_fuzz_seconds)
    if deadline is not None and deadline - time.monotonic() <= post_refresh_reserve:
        logger.info(
            "Skipping blocker session for %s because %.2fs remaining is not enough for one blocker attempt "
            "and coverage validation (reserve=%.2fs).",
            project_name,
            max(0.0, deadline - time.monotonic()),
            post_refresh_reserve,
        )
        _log_blocker_session_skipped(
            project_name,
            state,
            "insufficient_time_for_blocker_attempt",
            elapsed_seconds,
            post_refresh_reserve_seconds=post_refresh_reserve,
        )
        return {
            "success": False,
            "attempted": 0,
            "succeeded": 0,
            "reason": "insufficient_time_for_blocker_attempt",
        }
    current_target_fingerprint = _get_project_target_fingerprint(project_name)
    target_fingerprint_changed = (
        state.artifact_target_fingerprint is not None
        and current_target_fingerprint is not None
        and current_target_fingerprint != state.artifact_target_fingerprint
    )
    if target_fingerprint_changed and current_target_fingerprint != state.pending_target_fingerprint:
        state.pending_target_fingerprint = current_target_fingerprint
        state.new_targets_since_full_rebuild += 1
        state.artifacts_dirty = True
        logger.info(
            "Detected target fingerprint change for %s; pending full rebuild count is now %d.",
            project_name,
            state.new_targets_since_full_rebuild,
        )
    prefer_full_refresh = (
        not state.artifacts_ready
        or state.artifact_target_fingerprint is None
        or current_target_fingerprint is None
        or state.new_targets_since_full_rebuild >= BLOCKER_FULL_REFRESH_TARGET_THRESHOLD
        or (
            state.light_refreshes_since_full_rebuild >= BLOCKER_FULL_REFRESH_SESSION_INTERVAL
            and state.artifacts_dirty
        )
    )

    force_refresh = (
        not state.artifacts_ready
        or (state.artifacts_dirty and blocker_session_refresh_mode == "refresh_before_next_blocker")
    )
    if (
        blocker_session_refresh_mode == "reuse_session_artifacts"
        and state.artifacts_ready
        and state.artifact_branch_covered_baseline is not None
    ):
        probe_estimate = max(
            float(state.max_coverage_elapsed or 0.0) * BLOCKER_REFRESH_SAFETY_MULTIPLIER,
            BLOCKER_COVERAGE_BOOTSTRAP_SECONDS,
        )
        if deadline is None or deadline - time.monotonic() > post_refresh_reserve + probe_estimate:
            probe_deadline = deadline - post_refresh_reserve if deadline is not None else None
            refresh_probe_summary = _coverage_with_timing(project_name, state, deadline=probe_deadline)
            current_branch_covered = _get_coverage_count(refresh_probe_summary, "branches")
            branch_growth = current_branch_covered - state.artifact_branch_covered_baseline
            branch_growth_ratio = branch_growth / max(
                state.artifact_branch_covered_baseline,
                blocker_refresh_branch_growth_floor,
            )
            logger.info(
                "Blocker artifact refresh check for %s: baseline=%d current=%d delta=%d ratio=%.4f threshold=%.4f.",
                project_name,
                state.artifact_branch_covered_baseline,
                current_branch_covered,
                branch_growth,
                branch_growth_ratio,
                blocker_refresh_branch_growth_threshold,
            )
            if branch_growth_ratio >= blocker_refresh_branch_growth_threshold:
                force_refresh = True
                state.artifacts_dirty = True
                logger.info(
                    "Refreshing blocker artifacts for %s because covered branch growth ratio %.4f reached the threshold.",
                    project_name,
                    branch_growth_ratio,
                )
        else:
            logger.info(
                "Skipping blocker refresh coverage probe for %s to preserve %.2fs for blocker work.",
                project_name,
                post_refresh_reserve,
            )
    if target_fingerprint_changed:
        force_refresh = True
    if prefer_full_refresh and state.artifacts_ready and force_refresh:
        logger.info(
            "Escalating blocker artifact refresh for %s to full rebuild (new_targets_since_full_rebuild=%d, light_refreshes_since_full_rebuild=%d).",
            project_name,
            state.new_targets_since_full_rebuild,
            state.light_refreshes_since_full_rebuild,
        )
    requested_artifact_refresh = (not state.artifacts_ready) or force_refresh
    if not ensure_blocker_artifacts(
        project_name=project_name,
        report_seconds=blocker_artifact_report_seconds,
        state=state,
        force_refresh=force_refresh,
        prefer_full_refresh=prefer_full_refresh,
        deadline=deadline,
        post_refresh_reserve_seconds=post_refresh_reserve,
    ):
        _log_blocker_session_skipped(
            project_name,
            state,
            state.last_artifact_refresh_skip_reason or "artifact_refresh_failed",
            elapsed_seconds,
            force_refresh=force_refresh,
            prefer_full_refresh=prefer_full_refresh,
        )
        return {
            "success": False,
            "attempted": 0,
            "succeeded": 0,
            "reason": state.last_artifact_refresh_skip_reason or "artifact_refresh_failed",
        }
    refreshed_artifacts = requested_artifact_refresh and not state.last_artifact_refresh_reused_existing
    baseline_summary: TotalCoverageSummary | None = None
    if refreshed_artifacts:
        attempt_reserve = _minimum_blocker_attempt_reserve(state, blocker_fuzz_seconds)
        baseline_coverage_deadline = deadline - attempt_reserve if deadline is not None else None
        baseline_summary = _coverage_with_timing(
            project_name,
            state,
            deadline=baseline_coverage_deadline,
        )
        state.artifact_branch_covered_baseline = _get_coverage_count(baseline_summary, "branches")
        logger.info(
            "Updated blocker artifact branch baseline for %s to %d covered branches.",
            project_name,
            state.artifact_branch_covered_baseline,
        )

    session_artifacts = None
    resolved_json_path = _resolve_blocker_json_path(project_name, blocker_json_path)
    if resolved_json_path is None:
        session_artifacts = _reusable_session_artifacts(state, blocker_json_path)
        if session_artifacts is not None:
            resolved_json_path = session_artifacts.blocker_json
            logger.info(
                "Reusing cached blocker session artifacts for %s from %s because live branch-blockers.json is unavailable.",
                project_name,
                session_artifacts.root,
            )
        else:
            logger.warning("Blocker session skipped for %s because branch-blockers.json is unavailable.", project_name)
            _log_blocker_session_skipped(
                project_name,
                state,
                "missing_blocker_json",
                elapsed_seconds,
            )
            return {"success": False, "attempted": 0, "succeeded": 0, "reason": "missing_blocker_json"}

    selection_deadline = (
        deadline - _minimum_blocker_attempt_reserve(state, blocker_fuzz_seconds)
        if deadline is not None
        else None
    )
    coverage_context = _load_blocker_coverage_context(
        project_name,
        resolved_json_path,
        deadline=selection_deadline,
        repair_missing=True,
    )
    if coverage_context is None:
        logger.warning("No complete blocker coverage context is available for blocker selection in %s.", project_name)
        _log_blocker_session_skipped(
            project_name,
            state,
            "missing_project_target_linecov",
            elapsed_seconds,
            blocker_json_path=str(resolved_json_path),
        )
        return {"success": False, "attempted": 0, "succeeded": 0, "reason": "missing_project_target_linecov"}

    if session_artifacts is None and not ensure_blocker_webapp_ready(project_name):
        _log_blocker_session_skipped(
            project_name,
            state,
            "introspector_webapp_unavailable",
            elapsed_seconds,
            blocker_json_path=str(resolved_json_path),
        )
        return {"success": False, "attempted": 0, "succeeded": 0, "reason": "introspector_webapp_unavailable"}
    if session_artifacts is not None:
        logger.info("Using cached immutable blocker context for %s without restarting Introspector webapp.", project_name)

    blockers = _select_project_blockers(
        project_name,
        resolved_json_path,
        blocker_top_k,
        coverage_context,
    )
    if not blockers:
        logger.warning("Blocker session skipped for %s because no blockers were found.", project_name)
        _log_blocker_session_skipped(
            project_name,
            state,
            "no_blockers",
            elapsed_seconds,
            blocker_json_path=str(resolved_json_path),
            candidate_count=0,
        )
        return {"success": False, "attempted": 0, "succeeded": 0, "reason": "no_blockers"}

    if session_artifacts is None:
        session_artifacts = _create_blocker_session_artifacts(
            project_name=project_name,
            session_number=state.sessions_run,
            blocker_json_path=resolved_json_path,
            candidate_blockers=blockers,
        )
    if session_artifacts is not None:
        resolved_json_path = session_artifacts.blocker_json
        state.last_session_artifacts = session_artifacts
        logger.info(
            "Using immutable blocker session artifacts for %s from %s.",
            project_name,
            session_artifacts.root,
        )
    else:
        logger.warning(
            "Blocker session artifact cache is unavailable for %s; preserving the initial queue if live reranking fails.",
            project_name,
        )

    attempted = 0
    succeeded = 0
    pipeline_errors = 0
    skipped_before_solver = 0
    session_reason = "completed"
    session_seen_blocker_keys: set[tuple[str, str, str, str]] = set()
    selected_blockers: list[dict] = []
    for blocker in blockers:
        blocker_key = _blocker_identity(blocker)
        if blocker_key in state.attempted_blocker_keys:
            continue
        selected_blockers.append(blocker)
        if len(selected_blockers) >= blocker_session_size:
            break
    _log_experiment_event(
        "blocker_session_started",
        project_name=project_name,
        elapsed_seconds=elapsed_seconds,
        session_number=state.sessions_run,
        blocker_json_path=resolved_json_path,
        candidate_count=len(blockers),
        selected_blockers=[
            {
                "function_name": blocker.get("function_name"),
                "branch_line_number": blocker.get("branch_line_number"),
                "blocked_side_line_number": blocker.get("blocked_side_line_number"),
                "best_target": blocker.get("best_target"),
                "project_blocker_state": blocker.get("project_blocker_state"),
                "project_branch_hit_count": blocker.get("project_branch_hit_count"),
                "project_blocked_hit_count": blocker.get("project_blocked_hit_count"),
            }
            for blocker in selected_blockers
        ],
        blocker_session_refresh_mode=blocker_session_refresh_mode,
        blocker_artifact_report_seconds=blocker_artifact_report_seconds,
        artifacts_ready=state.artifacts_ready,
        artifacts_dirty=state.artifacts_dirty,
        session_artifact_root=str(session_artifacts.root) if session_artifacts else None,
    )

    if not selected_blockers:
        logger.info("No new project-relevant blockers remain for %s in this session.", project_name)
        _log_blocker_session_skipped(
            project_name,
            state,
            "no_unattempted_relevant_blockers",
            elapsed_seconds,
            blocker_json_path=str(resolved_json_path),
            candidate_count=len(blockers),
        )
        return {"success": False, "attempted": 0, "succeeded": 0, "reason": "no_unattempted_relevant_blockers"}

    current_pre_blocker_coverage = (
        pre_blocker_coverage_summary
        if pre_blocker_coverage_summary is not None
        else baseline_summary
    )
    for _ in range(blocker_session_size):
        if deadline is not None and deadline - time.monotonic() <= 0:
            logger.info("Stopping blocker session for %s because the fuzzing deadline was reached.", project_name)
            break
        if (
            deadline is not None
            and deadline - time.monotonic()
            <= _minimum_blocker_attempt_reserve(state, blocker_fuzz_seconds)
        ):
            logger.info(
                "Stopping blocker session for %s because the remaining budget cannot fit another blocker attempt.",
                project_name,
            )
            break
        if not selected_blockers:
            break
        blocker = selected_blockers.pop(0)
        blocker_key = _blocker_identity(blocker)
        session_seen_blocker_keys.add(blocker_key)
        attempt_started_at = time.perf_counter()
        pipeline_result = run_blocker_pipeline(
            project_name=project_name,
            llm_backend=llm_backend,
            model_name=model_name,
            blocker_json_path=resolved_json_path,
            blocker_record=blocker,
            blocker_top_k=blocker_top_k,
            blocker_max_iterations=blocker_max_iterations,
            blocker_fuzz_seconds=blocker_fuzz_seconds,
            blocker_reset_corpus_per_iteration=blocker_reset_corpus_per_iteration,
            blocker_keep_auto_context=blocker_keep_auto_context,
            blocker_pipeline_mode=blocker_pipeline_mode,
            skip_input_dependent_pipeline=skip_input_dependent_pipeline,
            skip_input_independent_pipeline=skip_input_independent_pipeline,
            enable_blocker_triage=enable_blocker_triage,
            deadline=deadline,
            session_artifacts=session_artifacts,
        )
        state.max_blocker_attempt_elapsed = _update_max_elapsed(
            state.max_blocker_attempt_elapsed,
            time.perf_counter() - attempt_started_at,
        )
        attempt_result = pipeline_result.get("attempt_result")
        if attempt_result == "skipped":
            skipped_before_solver += 1
            logger.info(
                "Skipping obsolete blocker candidate %s:%s before solver dispatch: %s",
                blocker.get("function_name"),
                blocker.get("branch_line_number"),
                pipeline_result.get("reason"),
            )
            continue
        if not _should_persist_blocker_attempt(pipeline_result):
            pipeline_errors += 1
            logger.error(
                "Retryable blocker pipeline infrastructure error for %s:%s; "
                "the blocker will remain eligible in a later session.",
                blocker.get("function_name"),
                blocker.get("branch_line_number"),
            )
            _log_experiment_event(
                "blocker_pipeline_retryable_error",
                project_name=project_name,
                function_name=blocker.get("function_name"),
                branch_line_number=blocker.get("branch_line_number"),
                blocked_side_line_number=blocker.get("blocked_side_line_number"),
                pipeline_returncode=pipeline_result.get("pipeline_returncode"),
                pipeline_failure_stage=pipeline_result.get("pipeline_failure_stage"),
            )
            continue

        state.attempted_blocker_keys.add(blocker_key)
        attempted += 1
        state.total_blockers_attempted += 1
        success = bool(pipeline_result.get("success"))
        if success:
            succeeded += 1
            state.total_blockers_succeeded += 1

        blocker_kind = pipeline_result.get("dependency_result")
        if blocker_kind == "Input Independent":
            state.artifacts_dirty = True

        if deadline is not None and deadline - time.monotonic() <= 0:
            logger.info("Skipping post-blocker coverage for %s because the fuzzing deadline was reached.", project_name)
            break
        next_attempt_reserve = (
            _minimum_blocker_attempt_reserve(state, blocker_fuzz_seconds)
            if attempted < blocker_session_size
            else 0.0
        )
        post_coverage_deadline = deadline - next_attempt_reserve if deadline is not None else None
        post_summary = _coverage_with_timing(
            project_name,
            state,
            deadline=post_coverage_deadline,
        )
        coverage_success = post_summary is not None
        _log_experiment_event(
            "coverage_after_blocker_attempt",
            project_name=project_name,
            elapsed_seconds=elapsed_seconds,
            function_name=blocker.get("function_name"),
            branch_line_number=blocker.get("branch_line_number"),
            blocked_side_line_number=blocker.get("blocked_side_line_number"),
            coverage_success=coverage_success,
            coverage_failure_reason=None if coverage_success else "coverage_generation_failed",
            line_coverage=_get_optional_coverage_metric(post_summary, "lines"),
            branch_coverage=_get_optional_coverage_metric(post_summary, "branches"),
            functions_coverage=_get_optional_coverage_metric(post_summary, "functions"),
            dependency_result=blocker_kind,
            attempt_result=attempt_result,
            pipeline_methods=pipeline_result.get("pipeline_methods", []),
            pipeline_success=pipeline_result.get("pipeline_success"),
        )
        coverage_growth_payload = (
            _build_coverage_growth_payload(current_pre_blocker_coverage, post_summary)
            if coverage_success
            else {
                "line_coverage_growth": None,
                "branch_coverage_growth": None,
                "functions_coverage_growth": None,
            }
        )
        _log_experiment_event(
            "coverage_growth_after_blocker_attempt",
            project_name=project_name,
            elapsed_seconds=elapsed_seconds,
            function_name=blocker.get("function_name"),
            branch_line_number=blocker.get("branch_line_number"),
            blocked_side_line_number=blocker.get("blocked_side_line_number"),
            coverage_success=coverage_success,
            dependency_result=blocker_kind,
            attempt_result=attempt_result,
            pipeline_methods=pipeline_result.get("pipeline_methods", []),
            pipeline_success=pipeline_result.get("pipeline_success"),
            **coverage_growth_payload,
        )
        if not coverage_success:
            state.artifacts_dirty = True
            session_reason = "post_attempt_coverage_failed"
            logger.error(
                "Stopping blocker session for %s because post-attempt coverage failed after %s:%s; "
                "stale line coverage will not be used for reranking.",
                project_name,
                blocker.get("function_name"),
                blocker.get("branch_line_number"),
            )
            _log_experiment_event(
                "blocker_session_stopped",
                project_name=project_name,
                session_number=state.sessions_run,
                reason=session_reason,
                function_name=blocker.get("function_name"),
                branch_line_number=blocker.get("branch_line_number"),
                blocked_side_line_number=blocker.get("blocked_side_line_number"),
            )
            break

        immediate_validation = _build_blocker_immediate_validation_record(
            project_name=project_name,
            blocker=blocker,
            pipeline_result=pipeline_result,
        )
        if immediate_validation is not None:
            _append_blocker_attempt_record(**immediate_validation)
        current_pre_blocker_coverage = post_summary

        if attempted < blocker_session_size:
            prior_queue = list(selected_blockers)
            refreshed_within_session = False
            if state.artifacts_dirty and blocker_session_refresh_mode == "refresh_before_next_blocker":
                post_refresh_reserve = _minimum_post_refresh_reserve(state, blocker_fuzz_seconds)
                if not ensure_blocker_artifacts(
                    project_name=project_name,
                    report_seconds=blocker_artifact_report_seconds,
                    state=state,
                    force_refresh=True,
                    prefer_full_refresh=(
                        state.new_targets_since_full_rebuild >= BLOCKER_FULL_REFRESH_TARGET_THRESHOLD
                        or state.light_refreshes_since_full_rebuild >= BLOCKER_FULL_REFRESH_SESSION_INTERVAL
                    ),
                    deadline=deadline,
                    post_refresh_reserve_seconds=post_refresh_reserve,
                ):
                    break
                refreshed_json_path = _resolve_blocker_json_path(project_name, blocker_json_path)
                if refreshed_json_path is None:
                    logger.warning(
                        "Blocker session stopped for %s because branch-blockers.json disappeared after refresh.",
                        project_name,
                    )
                    break
                resolved_json_path = refreshed_json_path
                refreshed_within_session = True
            coverage_context = _load_blocker_coverage_context(
                project_name,
                resolved_json_path,
                deadline=deadline,
                repair_missing=True,
            )
            if coverage_context is None:
                logger.warning(
                    "Keeping the existing blocker queue for %s because coverage context is incomplete after rerank.",
                    project_name,
                )
                selected_blockers = prior_queue
                _log_experiment_event(
                    "blocker_session_rerank_fallback",
                    project_name=project_name,
                    session_number=state.sessions_run,
                    reason="coverage_context_unavailable",
                    retained_queue_size=len(selected_blockers),
                )
                continue
            try:
                if not resolved_json_path.is_file():
                    raise FileNotFoundError(resolved_json_path)
                reranked = _select_project_blockers(
                    project_name,
                    resolved_json_path,
                    blocker_top_k,
                    coverage_context,
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Keeping the existing blocker queue for %s because reranking could not read its artifacts: %s",
                    project_name,
                    exc,
                )
                selected_blockers = prior_queue
                _log_experiment_event(
                    "blocker_session_rerank_fallback",
                    project_name=project_name,
                    session_number=state.sessions_run,
                    reason="artifact_read_failed",
                    error=str(exc),
                    retained_queue_size=len(selected_blockers),
                )
                continue
            selected_blockers = [
                candidate
                for candidate in reranked
                if _blocker_identity(candidate) not in state.attempted_blocker_keys
                and _blocker_identity(candidate) not in session_seen_blocker_keys
            ]
            if refreshed_within_session:
                refreshed_session_artifacts = _create_blocker_session_artifacts(
                    project_name=project_name,
                    session_number=state.sessions_run,
                    blocker_json_path=resolved_json_path,
                    candidate_blockers=reranked,
                )
                if refreshed_session_artifacts is not None:
                    session_artifacts = refreshed_session_artifacts
                    resolved_json_path = session_artifacts.blocker_json
                    state.last_session_artifacts = session_artifacts
                elif session_artifacts is not None:
                    logger.warning(
                        "Failed to replace the session artifact cache after refresh for %s; retaining the previous cache.",
                        project_name,
                    )
                    resolved_json_path = session_artifacts.blocker_json

    _log_experiment_event(
        "blocker_session_finished",
        project_name=project_name,
        elapsed_seconds=elapsed_seconds,
        session_number=state.sessions_run,
        attempted=attempted,
        succeeded=succeeded,
        pipeline_errors=pipeline_errors,
        skipped_before_solver=skipped_before_solver,
        reason=session_reason,
        artifacts_ready=state.artifacts_ready,
        artifacts_dirty=state.artifacts_dirty,
    )
    return {
        "success": succeeded > 0,
        "attempted": attempted,
        "succeeded": succeeded,
        "pipeline_errors": pipeline_errors,
        "skipped_before_solver": skipped_before_solver,
        "reason": session_reason,
    }


def run_blocker_once(
    project_name: str,
    llm_backend: str,
    model_name: str | None,
    blocker_json_path: Path | None = None,
    blocker_index: int = 0,
    blocker_top_k: int = 12,
    blocker_max_iterations: int = config.BLOCKER_MAX_ITERATIONS,
    blocker_fuzz_seconds: int = 15,
    blocker_reset_corpus_per_iteration: bool = False,
    blocker_keep_auto_context: bool = False,
    blocker_pipeline_mode: str | None = None,
    skip_input_dependent_pipeline: bool = False,
    skip_input_independent_pipeline: bool = False,
    enable_blocker_triage: bool = False,
    blocker_artifact_report_seconds: int = 30,
    prepare_artifacts: bool = False,
    force_refresh_artifacts: bool = False,
    artifact_refresh_mode: str = "reuse",
    timeout_seconds: int = 0,
) -> bool:
    state = BlockerRuntimeState()
    deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
    session_artifacts: BlockerSessionArtifacts | None = None
    effective_blocker_json_path = blocker_json_path

    if prepare_artifacts:
        if not ensure_blocker_artifacts(
            project_name=project_name,
            report_seconds=blocker_artifact_report_seconds,
            state=state,
            force_refresh=force_refresh_artifacts or artifact_refresh_mode == "refresh",
            deadline=deadline,
        ):
            logger.error("Failed to prepare blocker artifacts for %s.", project_name)
            return False

        resolved_json_path = _resolve_blocker_json_path(project_name, blocker_json_path)
        if resolved_json_path is None:
            logger.error("No blocker JSON is available after preparing artifacts for %s.", project_name)
            return False

        # Introspector generation replaces build/out with an analysis build. Preserve
        # its context before restoring the coverage build needed for per-seed replay.
        session_artifacts = _create_blocker_session_artifacts(
            project_name=project_name,
            session_number=1,
            blocker_json_path=resolved_json_path,
            candidate_blockers=[],
        )
        if session_artifacts is None:
            logger.error("Failed to preserve direct-run Introspector artifacts for %s.", project_name)
            return False
        effective_blocker_json_path = session_artifacts.blocker_json

        coverage_build = oss_fuzz.build_fuzzers(project_name, "coverage", deadline=deadline)
        if not coverage_build.success:
            logger.error(
                "Failed to restore the coverage build required for blocker seed discovery in %s: %s",
                project_name,
                coverage_build.error,
            )
            return False

    result = run_blocker_pipeline(
        project_name=project_name,
        llm_backend=llm_backend,
        model_name=model_name,
        blocker_json_path=effective_blocker_json_path,
        blocker_index=blocker_index,
        blocker_top_k=blocker_top_k,
        blocker_max_iterations=blocker_max_iterations,
        blocker_fuzz_seconds=blocker_fuzz_seconds,
        blocker_reset_corpus_per_iteration=blocker_reset_corpus_per_iteration,
        blocker_keep_auto_context=blocker_keep_auto_context,
        blocker_pipeline_mode=blocker_pipeline_mode,
        skip_input_dependent_pipeline=skip_input_dependent_pipeline,
        skip_input_independent_pipeline=skip_input_independent_pipeline,
        enable_blocker_triage=enable_blocker_triage,
        deadline=deadline,
        session_artifacts=session_artifacts,
    )
    if not result.get("success"):
        logger.warning("Direct blocker run failed for %s: %s", project_name, result.get("reason"))
        return False
    return True


def _coverage_metric_to_dict(summary: TotalCoverageSummary | None, metric_name: str) -> dict[str, float | int] | None:
    if not summary:
        return None
    metric = getattr(summary, metric_name, None)
    if not metric:
        return None
    return {
        "count": metric.count,
        "covered": metric.covered,
        "percent": metric.percent,
    }


def _log_final_run_coverage(
    project_name: str,
    run_seconds: int,
    summary: TotalCoverageSummary | None,
    *,
    includes_blocker: bool,
    initial_summary: TotalCoverageSummary | None = None,
) -> None:
    _log_experiment_event(
        "coverage_growth_summary",
        project_name=project_name,
        coverage_scope="final_post_fuzzing_and_blocker" if includes_blocker else "final_post_fuzzing",
        fuzzing_time_budget_seconds=run_seconds,
        recorded_after_fuzzing_deadline=True,
        line_coverage=_get_coverage_metric(summary, "lines"),
        branch_coverage=_get_coverage_metric(summary, "branches"),
        functions_coverage=_get_coverage_metric(summary, "functions"),
        line_coverage_summary=_coverage_metric_to_dict(summary, "lines"),
        branch_coverage_summary=_coverage_metric_to_dict(summary, "branches"),
        functions_coverage_summary=_coverage_metric_to_dict(summary, "functions"),
        **_build_coverage_growth_payload(initial_summary, summary),
    )


class CoverageTimelineRecorder:
    """Records periodic OSS-Fuzz coverage snapshots as JSONL."""

    def __init__(
        self,
        project_name: str,
        log_path: Path | None = None,
        stagnation_window: int = 2,
        stagnation_threshold: float = 0.01,
    ) -> None:
        self.project_name = project_name
        self.stagnation_window = max(1, stagnation_window)
        self.stagnation_threshold = max(0.0, stagnation_threshold)
        self.records: list[dict] = []
        self.log_path = self._resolve_log_path(project_name, log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _default_log_path(self, project_name: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Path("artifacts") / "coverage" / f"{project_name}_{timestamp}.jsonl"

    def _resolve_log_path(self, project_name: str, log_path: Path | None) -> Path:
        if log_path is None:
            return self._default_log_path(project_name)
        if log_path.exists() and log_path.is_dir():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return log_path / f"{project_name}_{timestamp}.jsonl"
        return log_path

    def record(self, elapsed_seconds: int, summary: TotalCoverageSummary | None) -> bool:
        if not summary:
            logger.warning("Coverage snapshot for %s at %ss is unavailable.", self.project_name, elapsed_seconds)
            return False

        record = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "project": self.project_name,
            "elapsed_seconds": elapsed_seconds,
            "branches": _coverage_metric_to_dict(summary, "branches"),
            "functions": _coverage_metric_to_dict(summary, "functions"),
            "lines": _coverage_metric_to_dict(summary, "lines"),
        }
        self.records.append(record)

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

        lines = record["lines"] or {}
        branches = record["branches"] or {}
        logger.info(
            "Coverage snapshot saved to %s: elapsed=%ss, lines=%s%% (%s/%s), branches=%s%% (%s/%s)",
            self.log_path,
            elapsed_seconds,
            lines.get("percent", "N/A"),
            lines.get("covered", "N/A"),
            lines.get("count", "N/A"),
            branches.get("percent", "N/A"),
            branches.get("covered", "N/A"),
            branches.get("count", "N/A"),
        )
        _log_experiment_event(
            "coverage_snapshot",
            coverage_log_path=self.log_path,
            elapsed_seconds=elapsed_seconds,
            line_coverage=lines.get("percent"),
            line_covered=lines.get("covered"),
            line_total=lines.get("count"),
            branch_coverage=branches.get("percent"),
            branch_covered=branches.get("covered"),
            branch_total=branches.get("count"),
        )
        return True

    def is_stagnated(self) -> bool:
        if len(self.records) <= self.stagnation_window:
            return False

        recent = self.records[-(self.stagnation_window + 1) :]
        line_percents = [(record.get("lines") or {}).get("percent") for record in recent]
        if any(percent is None for percent in line_percents):
            return False

        growth = float(line_percents[-1]) - float(line_percents[0])
        if growth > self.stagnation_threshold:
            return False

        logger.warning(
            "Coverage appears stagnant for %s: line coverage grew %.4f%% over the last %d snapshot(s).",
            self.project_name,
            growth,
            self.stagnation_window,
        )
        _log_experiment_event(
            "coverage_stagnated",
            coverage_log_path=self.log_path,
            stagnation_window=self.stagnation_window,
            stagnation_threshold=self.stagnation_threshold,
            line_growth=growth,
        )
        return True


def minimize_and_generate_report(proj_name: str, seconds: int, clean: bool):
    """Helper function to minimize corpus and then generate a report."""
    oss_fuzz.minimize_corpus(proj_name)
    return generate_report_and_start_webapp(proj_name, seconds, clean)


def run_fuzzers_and_get_coverage(
    proj_name: str,
    run_seconds: int,
    minimize_corpus: bool = False,
    get_coverage: bool = True,
    start_webapp: bool = False,
    fuzz_targets_parallel: int | None = None,
    coverage_interval: int = 0,
    coverage_log_path: Path | None = None,
    coverage_stagnation_window: int = 3,
    coverage_stagnation_threshold: float = 0.01,
    stop_on_coverage_stall: bool = False,
    use_blocker: bool = False,
    blocker_on_stall_only: bool = True,
    blocker_json_path: Path | None = None,
    blocker_index: int = 0,
    blocker_top_k: int = 12,
    blocker_session_size: int = 1,
    blocker_max_iterations: int = config.BLOCKER_MAX_ITERATIONS,
    blocker_fuzz_seconds: int = 15,
    blocker_reset_corpus_per_iteration: bool = False,
    blocker_keep_auto_context: bool = False,
    blocker_pipeline_mode: str | None = None,
    skip_input_dependent_pipeline: bool = False,
    skip_input_independent_pipeline: bool = False,
    enable_blocker_triage: bool = False,
    blocker_session_refresh_mode: str = "reuse_session_artifacts",
    blocker_artifact_report_seconds: int = 30,
    blocker_refresh_branch_growth_threshold: float = 0.05,
    blocker_refresh_branch_growth_floor: int = 50,
    llm_backend: str = "vertexai",
    model_name: str | None = None,
    budget_mode: str = "wall-clock",
    target_exposure_min_seconds: int = 0,
    generated_target_priority_seconds: int = 300,
):
    """Helper function to run all fuzzers and then optionally get coverage."""
    initial_growth_summary: TotalCoverageSummary | None = None
    if start_webapp:
        generate_report_and_start_webapp(proj_name, 10, clean=True)
    if minimize_corpus:
        oss_fuzz.minimize_corpus(proj_name)
    deadline = time.monotonic() + run_seconds if budget_mode == "wall-clock" else None

    if not use_blocker:
        if budget_mode == "fuzzing-cpu":
            remaining_budget = float(run_seconds)
            while remaining_budget > 0:
                chunk_budget = min(float(coverage_interval or run_seconds), remaining_budget)
                result = oss_fuzz.run_all_fuzzers_scheduled(
                    proj_name,
                    seconds=max(1, int(chunk_budget)),
                    max_workers=fuzz_targets_parallel,
                    deadline=None,
                    served_seconds_budget=chunk_budget,
                    generated_target_priority_seconds=generated_target_priority_seconds,
                    target_exposure_min_seconds=target_exposure_min_seconds,
                )
                if result.charged_seconds <= 0:
                    logger.warning(
                        "Stopping fuzzing CPU-budget run for %s because no additional target-seconds were charged.",
                        proj_name,
                    )
                    break
                remaining_budget -= result.charged_seconds
            if get_coverage:
                _log_final_run_coverage(
                    proj_name,
                    run_seconds,
                    oss_fuzz.coverage(proj_name),
                    includes_blocker=False,
                    initial_summary=initial_growth_summary,
                )
            return
        oss_fuzz.run_all_fuzzers(proj_name, run_seconds, max_workers=fuzz_targets_parallel, deadline=deadline)
        if get_coverage:
            _log_final_run_coverage(
                proj_name,
                run_seconds,
                oss_fuzz.coverage(proj_name),
                includes_blocker=False,
                initial_summary=initial_growth_summary,
            )
        return

    if not get_coverage or coverage_interval <= 0 or coverage_interval >= run_seconds:
        logger.warning(
            "Blocker mode for %s requires periodic coverage snapshots. "
            "Falling back to baseline fuzzing because --coverage-interval is not smaller than the fuzzing duration.",
            proj_name,
        )
        if budget_mode == "fuzzing-cpu":
            remaining_budget = float(run_seconds)
            while remaining_budget > 0:
                chunk_budget = remaining_budget
                result = oss_fuzz.run_all_fuzzers_scheduled(
                    proj_name,
                    seconds=max(1, int(chunk_budget)),
                    max_workers=fuzz_targets_parallel,
                    deadline=None,
                    served_seconds_budget=chunk_budget,
                    generated_target_priority_seconds=generated_target_priority_seconds,
                    target_exposure_min_seconds=target_exposure_min_seconds,
                )
                if result.charged_seconds <= 0:
                    logger.warning(
                        "Stopping fallback fuzzing CPU-budget run for %s because no target-seconds were charged.",
                        proj_name,
                    )
                    break
                remaining_budget -= result.charged_seconds
        else:
            oss_fuzz.run_all_fuzzers(proj_name, run_seconds, max_workers=fuzz_targets_parallel, deadline=deadline)
        if get_coverage:
            _log_final_run_coverage(
                proj_name,
                run_seconds,
                oss_fuzz.coverage(proj_name),
                includes_blocker=True,
                initial_summary=initial_growth_summary,
            )
        return

    recorder = CoverageTimelineRecorder(
        proj_name,
        coverage_log_path,
        coverage_stagnation_window,
        coverage_stagnation_threshold,
    )
    blocker_state = BlockerRuntimeState()
    if use_blocker and not blocker_on_stall_only:
        run_blocker_session(
            project_name=proj_name,
            elapsed_seconds=0,
            llm_backend=llm_backend,
            model_name=model_name,
            state=blocker_state,
            blocker_json_path=blocker_json_path,
            blocker_start_index=blocker_index,
            blocker_session_size=blocker_session_size,
            blocker_top_k=blocker_top_k,
            blocker_max_iterations=blocker_max_iterations,
            blocker_fuzz_seconds=blocker_fuzz_seconds,
            blocker_reset_corpus_per_iteration=blocker_reset_corpus_per_iteration,
            blocker_keep_auto_context=blocker_keep_auto_context,
            blocker_pipeline_mode=blocker_pipeline_mode,
            skip_input_dependent_pipeline=skip_input_dependent_pipeline,
            skip_input_independent_pipeline=skip_input_independent_pipeline,
            enable_blocker_triage=enable_blocker_triage,
            blocker_session_refresh_mode=blocker_session_refresh_mode,
            blocker_artifact_report_seconds=blocker_artifact_report_seconds,
            blocker_refresh_branch_growth_threshold=blocker_refresh_branch_growth_threshold,
            blocker_refresh_branch_growth_floor=blocker_refresh_branch_growth_floor,
            pre_blocker_coverage_summary=initial_growth_summary,
            deadline=deadline,
        )
    start_wall_time = time.monotonic()
    fuzzing_budget_consumed = 0.0
    while True:
        real_elapsed_seconds = time.monotonic() - start_wall_time
        if budget_mode == "fuzzing-cpu":
            remaining_seconds = float(run_seconds) - fuzzing_budget_consumed
        else:
            remaining_seconds = deadline - time.monotonic() if deadline is not None else 0.0

        if remaining_seconds <= 0:
            if budget_mode == "fuzzing-cpu":
                logger.info(
                    "Maximum fuzzing CPU budget reached (%.2f target-seconds). Terminating fuzzing loop.",
                    fuzzing_budget_consumed,
                )
            else:
                logger.info(
                    "Maximum wall-clock time reached (%.2fs). Terminating fuzzing loop.",
                    real_elapsed_seconds,
                )
            break

        chunk_seconds = max(1, int(min(coverage_interval, remaining_seconds)))

        if budget_mode == "fuzzing-cpu":
            logger.info(
                "Starting next fuzzing chunk with target-second budget=%d "
                "(remaining fuzzing budget: %.2f target-seconds)...",
                chunk_seconds,
                remaining_seconds,
            )
        else:
            logger.info(
                "Starting next fuzzing chunk for %d seconds (Remaining wall-clock budget: %d seconds)...",
                chunk_seconds,
                int(remaining_seconds),
            )
        
        chunk_result = oss_fuzz.run_all_fuzzers_scheduled(
            proj_name,
            chunk_seconds,
            max_workers=fuzz_targets_parallel,
            deadline=deadline,
            served_seconds_budget=chunk_seconds if budget_mode == "fuzzing-cpu" else None,
            generated_target_priority_seconds=generated_target_priority_seconds,
            target_exposure_min_seconds=target_exposure_min_seconds if budget_mode == "fuzzing-cpu" else 0,
        )
        if budget_mode == "fuzzing-cpu":
            fuzzing_budget_consumed += chunk_result.charged_seconds
            _log_experiment_event(
                "fuzzing_cpu_budget_consumed",
                project_name=proj_name,
                chunk_charged_seconds=chunk_result.charged_seconds,
                cumulative_charged_seconds=fuzzing_budget_consumed,
                fuzzing_budget_seconds=run_seconds,
                runnable_targets=chunk_result.runnable_targets,
                terminal_failures=chunk_result.terminal_failures,
            )
            if chunk_result.charged_seconds <= 0:
                logger.warning(
                    "Stopping fuzzing CPU-budget loop for %s because the scheduler charged no target-seconds.",
                    proj_name,
                )
                break

        fuzzing_elapsed_seconds = (
            int(fuzzing_budget_consumed)
            if budget_mode == "fuzzing-cpu"
            else int(time.monotonic() - start_wall_time)
        )
        if budget_mode == "wall-clock" and deadline is not None and time.monotonic() >= deadline:
            logger.info("Maximum wall-clock time reached after fuzzing chunk. Skipping coverage/blocker work.")
            break

        summary = oss_fuzz.coverage(proj_name, deadline=deadline)
        if initial_growth_summary is None:
            initial_growth_summary = summary
        recorder.record(fuzzing_elapsed_seconds, summary) 

        if recorder.is_stagnated():
            if budget_mode == "fuzzing-cpu" and target_exposure_min_seconds > 0:
                exposure = oss_fuzz.get_project_exposure_seconds(proj_name, include_terminal_failures=False)
                underexposed = {
                    name: seconds
                    for name, seconds in exposure.items()
                    if seconds < float(target_exposure_min_seconds)
                }
                if underexposed:
                    logger.info(
                        "Skipping blocker session for %s because target exposure is incomplete: "
                        "%d/%d runnable target(s) below %ds.",
                        proj_name,
                        len(underexposed),
                        len(exposure),
                        target_exposure_min_seconds,
                    )
                    _log_experiment_event(
                        "blocker_trigger_deferred",
                        project_name=proj_name,
                        reason="target_exposure_incomplete",
                        elapsed_seconds=fuzzing_elapsed_seconds,
                        target_exposure_min_seconds=target_exposure_min_seconds,
                        underexposed_target_count=len(underexposed),
                        active_target_count=len(exposure),
                    )
                    continue
            if use_blocker:
                run_blocker_session(
                    project_name=proj_name,
                    elapsed_seconds=fuzzing_elapsed_seconds, 
                    llm_backend=llm_backend,
                    model_name=model_name,
                    state=blocker_state,
                    blocker_json_path=blocker_json_path,
                    blocker_start_index=blocker_index,
                    blocker_session_size=blocker_session_size,
                    blocker_top_k=blocker_top_k,
                    blocker_max_iterations=blocker_max_iterations,
                    blocker_fuzz_seconds=blocker_fuzz_seconds,
                    blocker_reset_corpus_per_iteration=blocker_reset_corpus_per_iteration,
                    blocker_keep_auto_context=blocker_keep_auto_context,
                    blocker_pipeline_mode=blocker_pipeline_mode,
                    skip_input_dependent_pipeline=skip_input_dependent_pipeline,
                    skip_input_independent_pipeline=skip_input_independent_pipeline,
                    enable_blocker_triage=enable_blocker_triage,
                    blocker_session_refresh_mode=blocker_session_refresh_mode,
                    blocker_artifact_report_seconds=blocker_artifact_report_seconds,
                    blocker_refresh_branch_growth_threshold=blocker_refresh_branch_growth_threshold,
                    blocker_refresh_branch_growth_floor=blocker_refresh_branch_growth_floor,
                    pre_blocker_coverage_summary=summary,
                    deadline=deadline,
                )
            if stop_on_coverage_stall:
                logger.warning("Stopping fuzzing for %s because coverage is stagnant.", proj_name)
                break
            logger.warning("Continuing fuzzing for %s despite stagnant coverage.", proj_name)

    final_summary = oss_fuzz.coverage(proj_name)
    _log_final_run_coverage(
        proj_name,
        run_seconds,
        final_summary,
        includes_blocker=use_blocker,
        initial_summary=initial_growth_summary,
    )

def run_all_fuzzer(
    project_names: list[str],
    run_seconds: int,
    parallel: int,
    minimize_corpus: bool = False,
    print_coverage: bool = False,
    analyze_crashes: bool = False,
    fuzz_targets_parallel: int | None = None,
    coverage_interval: int = 0,
    coverage_log_path: Path | None = None,
    coverage_stagnation_window: int = 3,
    coverage_stagnation_threshold: float = 0.01,
    stop_on_coverage_stall: bool = False,
    use_blocker: bool = False,
    blocker_on_stall_only: bool = True,
    blocker_json_path: Path | None = None,
    blocker_index: int = 0,
    blocker_top_k: int = 12,
    blocker_session_size: int = 1,
    blocker_max_iterations: int = config.BLOCKER_MAX_ITERATIONS,
    blocker_fuzz_seconds: int = 15,
    blocker_reset_corpus_per_iteration: bool = False,
    blocker_keep_auto_context: bool = False,
    blocker_pipeline_mode: str | None = None,
    skip_input_dependent_pipeline: bool = False,
    skip_input_independent_pipeline: bool = False,
    enable_blocker_triage: bool = False,
    blocker_session_refresh_mode: str = "reuse_session_artifacts",
    blocker_artifact_report_seconds: int = 30,
    blocker_refresh_branch_growth_threshold: float = 0.05,
    blocker_refresh_branch_growth_floor: int = 50,
    llm_backend: str = "vertexai",
    model_name: str | None = None,
    budget_mode: str = "wall-clock",
    target_exposure_min_seconds: int = 0,
    generated_target_priority_seconds: int = 300,
):
    """
    Runs all fuzzers for the specified projects, optionally analyzes crashes,
    and optionally shows the coverage summary.
    """
    logger.info("Running all fuzzers")
    overall_success = True

    # Determine which projects to process
    build_out_dir = Path("./external/oss-fuzz/build/out/")
    projects_dir = Path("./external/oss-fuzz/projects/")

    projects_to_process = project_names
    if not projects_to_process:
        projects_to_process = [
            p.name for p in projects_dir.iterdir() if p.is_dir() and not p.name.startswith("non-test-projects")
        ]

    # Determine the number of workers for the executor
    max_workers = parallel
    logger.info(f"Running all fuzzers for {len(projects_to_process)} projects with {max_workers} parallel worker(s)...")

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_project = {
                executor.submit(
                    run_fuzzers_and_get_coverage,
                    project_name,
                    run_seconds,
                    minimize_corpus,
                    print_coverage or use_blocker,
                    analyze_crashes,
                    fuzz_targets_parallel,
                    coverage_interval,
                    coverage_log_path,
                    coverage_stagnation_window,
                    coverage_stagnation_threshold,
                    stop_on_coverage_stall,
                    use_blocker,
                    blocker_on_stall_only,
                    blocker_json_path,
                    blocker_index,
                    blocker_top_k,
                    blocker_session_size,
                    blocker_max_iterations,
                    blocker_fuzz_seconds,
                    blocker_reset_corpus_per_iteration,
                    blocker_keep_auto_context,
                    blocker_pipeline_mode,
                    skip_input_dependent_pipeline,
                    skip_input_independent_pipeline,
                    enable_blocker_triage,
                    blocker_session_refresh_mode,
                    blocker_artifact_report_seconds,
                    blocker_refresh_branch_growth_threshold,
                    blocker_refresh_branch_growth_floor,
                    llm_backend,
                    model_name,
                    budget_mode,
                    target_exposure_min_seconds,
                    generated_target_priority_seconds,
                ): project_name
                for project_name in projects_to_process
            }

            for future in future_to_project:
                project_name = future_to_project[future]
                try:
                    future.result()  # We don't need the result, but this will raise exceptions if any occurred
                    logger.info(f"Successfully completed fuzzing for {project_name}")
                except BaseException:
                    overall_success = False
                    logger.exception(f"Failed to complete fuzzing for {project_name}")
    except KeyboardInterrupt:
        overall_success = False
        logger.info("Fuzzing interrupted by user. Shutting down...")

    if analyze_crashes:
        logger.info("Starting crash analysis phase.")
        analyzer = CrashAnalyzer(llm_client, oss_fuzz)
        for project_name in projects_to_process:
            analyzer.analyze_project(project_name)

        introspector.shutdown_webapp()

    if not print_coverage:
        return overall_success

    # Collect data for the table
    table_data = []
    for proj_name in projects_to_process:
        summary_file = build_out_dir / proj_name / "textcov_reports" / "summary_exclude_target.json"

        row = {"Project": proj_name}

        if summary_file.exists():
            try:
                with open(summary_file, "r") as f:
                    summary_data = json.load(f)
                totals = summary_data["data"][0]["totals"]

                for metric in ["branches", "functions", "lines"]:
                    if metric in totals:
                        count = totals[metric]["count"]
                        covered = totals[metric]["covered"]
                        percent = totals[metric]["percent"]
                        row[metric.capitalize()] = f"{percent:.2f} ({covered}/{count})"
                    else:
                        row[metric.capitalize()] = "N/A"

            except (json.JSONDecodeError, KeyError, IndexError) as e:
                logger.error(f"Could not parse summary for {proj_name}: {e}")
                for metric in ["Branches", "Functions", "Lines"]:
                    row[metric] = "Error"

        else:
            for metric in ["Branches", "Functions", "Lines"]:
                row[metric] = "No Summary"

        # Get fuzz target count
        fuzz_target_file = build_out_dir / proj_name / "fuzzer_stats" / "coverage_targets.txt"
        fuzz_target_count = 0
        if fuzz_target_file.exists():
            with open(fuzz_target_file, "r") as f:
                fuzz_target_count = sum(1 for line in f if line.strip())
        row["Fuzz Targets"] = str(fuzz_target_count)

        table_data.append(row)

    # Display table
    if not table_data:
        logger.info("No projects found to display.")
        return overall_success

    headers = ["Project", "Branches (%)", "Functions (%)", "Lines (%)", "Fuzz Targets"]

    # Calculate column widths
    col_widths = {h: len(h) for h in headers}
    for row in table_data:
        for h in headers:
            # Remap keys for lookup
            key = h.split(" ")[0] if h != "Fuzz Targets" else "Fuzz Targets"
            col_widths[h] = max(col_widths[h], len(row.get(key, "")))

    # Print header
    header_line = "| " + " | ".join(f"{h:<{col_widths[h]}}" for h in headers) + " |"
    separator_line = "|-" + "-|-".join("-" * col_widths[h] for h in headers) + "-|"

    logger.info("Coverage Summary")
    logger.info("=" * len(header_line))
    return overall_success
    logger.info(header_line)
    logger.info(separator_line)

    # Print rows
    for row in table_data:
        row_line = "| "
        row_line += f"{row['Project']:<{col_widths['Project']}} | "
        row_line += f"{row.get('Branches', 'N/A'):<{col_widths['Branches (%)']}} | "
        row_line += f"{row.get('Functions', 'N/A'):<{col_widths['Functions (%)']}} | "
        row_line += f"{row.get('Lines', 'N/A'):<{col_widths['Lines (%)']}} | "
        row_line += f"{row.get('Fuzz Targets', 'N/A'):<{col_widths['Fuzz Targets']}} |"
        logger.info(row_line)

    logger.info("=" * len(header_line))


# Statistics for tracking coverage growth
regeneration_growth = []
mutation_growth = []

# Statistics for tracking compilation success
compilation_attempts = 0
compilation_successes = 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fuzz target generator for OSS-Fuzz projects.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_periodic_coverage_args(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "--coverage-interval",
            type=int,
            default=3600,
            metavar="SECONDS",
            help=(
                "Record coverage every N seconds during fuzzing. "
            ),
        )
        subparser.add_argument(
            "--coverage-log",
            type=Path,
            default=None,
            help="JSONL path for periodic coverage snapshots. Defaults to artifacts/coverage/<project>_<timestamp>.jsonl.",
        )
        subparser.add_argument(
            "--coverage-stagnation-window",
            type=int,
            default=1,
            help="Warn after this many consecutive coverage intervals have no meaningful line coverage growth. Default 3.",
        )
        subparser.add_argument(
            "--coverage-stagnation-threshold",
            type=float,
            default=0.01,
            help="Minimum line coverage percentage-point growth over the stagnation window. Default 0.01.",
        )
        subparser.add_argument(
            "--stop-on-coverage-stall",
            action="store_true",
            default=False,
            help="Stop the fuzzing phase early when periodic coverage snapshots indicate stagnation.",
        )

    # Subparser for the main fuzzing process
    parser_process = subparsers.add_parser("process", help="Process a project to generate and improve fuzz targets.")
    parser_process.add_argument("project_name", help="The name of the project to process.")
    parser_process.add_argument(
        "--initial-fuzz-target",
        "-i",
        action="store_true",
        default=False,
        help="Generate an initial fuzz target. Default is not to generate.",
    )
    parser_process.add_argument(
        "--seconds",
        "-s",
        type=int,
        default=60,
        help="The number of seconds to wait for report generation. Default is 60 seconds.",
    )
    parser_process.add_argument(
        "--dict",
        "-d",
        action="store_true",
        default=False,
        help="Enable dictionary generation.",
    )
    parser_process.add_argument(
        "--seeds",
        action="store_true",
        default=False,
        help="Enable seed generation.",
    )
    parser_process.add_argument(
        "--llm",
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="vertexai",
        help="Specify the LLM backend to use.",
    )
    parser_process.add_argument(
        "--model",
        type=str,
        default="gemini-2.5-flash",
        help="Specify the model name to use, overriding the default in config.",
    )
    add_periodic_coverage_args(parser_process)

    # Subparser for running all fuzzers
    parser_run = subparsers.add_parser("run_all_fuzzer", help="Run all fuzzers for specified projects.")
    parser_run.add_argument(
        "--minimize-corpus", action="store_true", default=False, help="Minimize corpus before running fuzzers."
    )
    parser_run.add_argument(
        "project_names", nargs="*", help="The names of the projects to run fuzzers for. Runs all if none are provided."
    )
    parser_run.add_argument(
        "--run-fuzzers",
        "-r",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Run all fuzzers for the specified number of seconds. Defaults to 60s.",
    )
    parser_run.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=1,
        help="The number of projects to run in parallel. Defaults to 1.",
    )
    parser_run.add_argument(
        "--fuzz-targets-parallel",
        type=int,
        default=None,
        help="The number of fuzz targets to run in parallel within a project. "
        "In scheduled/blocker mode, defaults to min(6, target_count).",
    )
    parser_run.add_argument(
        "--print-coverage",
        action="store_true",
        default=False,
        help="Print coverage summary table at the end.",
    )
    parser_run.add_argument(
        "--analyze-crashes",
        action="store_true",
        default=False,
        help="Analyze crashes after fuzzing runs, before calculating coverage.",
    )
    parser_run.add_argument(
        "--llm",
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="vertexai",
        help="Specify the LLM backend to use.",
    )
    parser_run.add_argument(
        "--model",
        type=str,
        default="gemini-2.5-flash",
        help="Specify the model name to use, overriding the default in config.",
    )
    parser_run.add_argument(
        "--use-blocker",
        action="store_true",
        default=False,
        help="Enable blocker-resolution during the fuzzing stage.",
    )
    parser_run.add_argument(
        "--blocker-before-fuzzing",
        action="store_true",
        default=False,
        help="Run the blocker pipeline once before the first fuzzing window. By default blocker runs only when coverage stalls.",
    )
    parser_run.add_argument(
        "--blocker-json-path",
        type=Path,
        default=None,
        help="Path to branch-blockers.json. If omitted, common project report locations are checked automatically.",
    )
    parser_run.add_argument(
        "--blocker-index",
        type=int,
        default=0,
        help="Which ranked blocker to solve from branch-blockers.json. Default 0.",
    )
    parser_run.add_argument(
        "--blocker-top-k",
        type=int,
        default=12,
        help="How many blockers per target to consider when aggregating global blockers. Default 12.",
    )
    parser_run.add_argument(
        "--blocker-session-size",
        type=int,
        default=1,
        help="How many ranked blockers to process in one blocker session after a stall. Default 1.",
    )
    parser_run.add_argument(
        "--blocker-max-iterations",
        type=int,
        default=config.BLOCKER_MAX_ITERATIONS,
        help=(
            "Maximum iterations for the blocker pipeline. "
            f"Default {config.BLOCKER_MAX_ITERATIONS}."
        ),
    )
    parser_run.add_argument(
        "--blocker-fuzz-seconds",
        type=int,
        default=15,
        help="Fuzzing seconds per blocker iteration. Default 15.",
    )
    parser_run.add_argument(
        "--blocker-reset-corpus-per-iteration",
        action="store_true",
        default=False,
        help="Reset blocker corpus between blocker iterations.",
    )
    parser_run.add_argument(
        "--blocker-keep-auto-context",
        action="store_true",
        default=False,
        help="Keep auto-resolved blocker context files under logs/auto_context.",
    )
    parser_run.add_argument(
        "--blocker-pipeline-mode",
        choices=["dependent", "independent"],
        default=None,
        help="When set, only run the selected blocker pipeline after classification.",
    )
    parser_run.add_argument(
        "--skip-input-dependent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-dependent blockers but skip the input-dependent solver pipeline.",
    )
    parser_run.add_argument(
        "--skip-input-independent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-independent blockers but skip the input-independent solver pipeline.",
    )
    parser_run.add_argument(
        "--enable-blocker-triage",
        action="store_true",
        default=False,
        help="Run C/C++ blocker solvability triage as a hard gate before solver dispatch.",
    )
    parser_run.add_argument(
        "--blocker-session-refresh-mode",
        choices=["reuse_session_artifacts", "refresh_before_next_blocker"],
        default="reuse_session_artifacts",
        help=(
            "Controls whether the blocker session keeps using the current artifacts for the rest of the same session "
            "or refreshes them before selecting the next blocker after an input-independent result."
        ),
    )
    parser_run.add_argument(
        "--blocker-artifact-report-seconds",
        type=int,
        default=30,
        help="Seconds passed to introspector report generation when refreshing blocker artifacts. Default 30.",
    )
    parser_run.add_argument(
        "--blocker-refresh-branch-growth-threshold",
        type=float,
        default=0.05,
        help=(
            "Refresh blocker artifacts before the next blocker session when covered branch growth "
            "since the last refresh reaches this ratio. Default 0.05."
        ),
    )
    parser_run.add_argument(
        "--blocker-refresh-branch-growth-floor",
        type=int,
        default=50,
        help=(
            "Minimum denominator used when computing covered branch growth ratio for blocker artifact refresh. "
            "Default 50."
        ),
    )
    parser_run.add_argument(
        "--budget-mode",
        choices=["wall-clock", "fuzzing-cpu"],
        default="wall-clock",
        help=(
            "Budget accounting mode for run_all_fuzzer. "
            "'wall-clock' keeps the existing end-to-end wall-clock behavior. "
            "'fuzzing-cpu' treats --run-fuzzers as a global target-second fuzzing budget."
        ),
    )
    parser_run.add_argument(
        "--target-exposure-min-seconds",
        type=int,
        default=0,
        help=(
            "In --budget-mode fuzzing-cpu, defer blocker triggering until every non-terminal active target "
            "has received at least this many served target-seconds. Default 0 disables the gate."
        ),
    )
    parser_run.add_argument(
        "--generated-target-priority-seconds",
        type=int,
        default=300,
        help=(
            "Give fuzz targets that newly appear during the current run priority scheduling until they have "
            "received this many served target-seconds. The time is still charged to the same fuzzing budget. "
            "Default 300; set 0 to disable."
        ),
    )
    add_periodic_coverage_args(parser_run)

    parser_blocker = subparsers.add_parser("run_blocker_once", help="Run a single blocker pipeline directly.")
    parser_blocker.add_argument("project_name", help="The project name to run the blocker pipeline for.")
    parser_blocker.add_argument(
        "--llm",
        choices=["gemini", "vertexai", "openrouter", "ollama"],
        default="vertexai",
        help="Specify the LLM backend to use.",
    )
    parser_blocker.add_argument(
        "--model",
        type=str,
        default="gemini-2.5-flash",
        help="Specify the model name to use, overriding the default in config.",
    )
    parser_blocker.add_argument(
        "--blocker-json-path",
        type=Path,
        default=None,
        help="Path to branch-blockers.json. If omitted, common project report locations are checked automatically.",
    )
    parser_blocker.add_argument("--blocker-index", type=int, default=0, help="Which ranked blocker to solve. Default 0.")
    parser_blocker.add_argument("--blocker-top-k", type=int, default=12, help="How many blockers to consider. Default 12.")
    parser_blocker.add_argument(
        "--blocker-max-iterations",
        type=int,
        default=config.BLOCKER_MAX_ITERATIONS,
        help=f"Maximum blocker iterations. Default {config.BLOCKER_MAX_ITERATIONS}.",
    )
    parser_blocker.add_argument("--blocker-fuzz-seconds", type=int, default=15, help="Fuzzing seconds per iteration.")
    parser_blocker.add_argument(
        "--blocker-reset-corpus-per-iteration",
        action="store_true",
        default=False,
        help="Reset blocker corpus between iterations.",
    )
    parser_blocker.add_argument(
        "--blocker-keep-auto-context",
        action="store_true",
        default=False,
        help="Keep auto-resolved blocker context files under logs/auto_context.",
    )
    parser_blocker.add_argument(
        "--blocker-pipeline-mode",
        choices=["dependent", "independent"],
        default=None,
        help="When set, only run the selected blocker pipeline after classification.",
    )
    parser_blocker.add_argument(
        "--skip-input-dependent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-dependent blockers but skip the input-dependent solver pipeline.",
    )
    parser_blocker.add_argument(
        "--skip-input-independent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-independent blockers but skip the input-independent solver pipeline.",
    )
    parser_blocker.add_argument(
        "--enable-blocker-triage",
        action="store_true",
        default=False,
        help="Run C/C++ blocker solvability triage as a hard gate before solver dispatch.",
    )
    parser_blocker.add_argument(
        "--blocker-artifact-report-seconds",
        type=int,
        default=30,
        help="Seconds passed to introspector report generation when preparing blocker artifacts.",
    )
    parser_blocker.add_argument(
        "--prepare-artifacts",
        action="store_true",
        default=False,
        help="Prepare blocker artifacts before running the selected blocker.",
    )
    parser_blocker.add_argument(
        "--force-refresh-artifacts",
        action="store_true",
        default=False,
        help="Force a blocker artifact refresh when preparing artifacts.",
    )
    parser_blocker.add_argument(
        "--artifact-refresh-mode",
        choices=["reuse", "refresh"],
        default="reuse",
        help="Whether artifact preparation reuses current data or forces a refresh.",
    )
    parser_blocker.add_argument(
        "--timeout-seconds",
        type=int,
        default=0,
        help="Optional wall-clock timeout for the entire direct blocker run. 0 disables the timeout.",
    )

    args = parser.parse_args()
    return args


def generate_report_and_start_webapp(project_name: str, seconds: int = 60, clean: bool = False) -> bool:
    started_at = time.perf_counter()
    if not oss_fuzz.generate_report(project_name, seconds, clean):
        _log_experiment_event(
            "introspector_report_finished",
            success=False,
            project_name=project_name,
            requested_seconds=seconds,
            clean=clean,
            elapsed_seconds=time.perf_counter() - started_at,
        )
        logger.error(f"Failed to generate report for {project_name}")
        return False
    _log_experiment_event(
        "introspector_report_finished",
        success=True,
        project_name=project_name,
        requested_seconds=seconds,
        clean=clean,
        elapsed_seconds=time.perf_counter() - started_at,
    )

    if not introspector.update_start_webapp():
        logger.error("Failed to start web application")
        return False
    return True


def generate_empty_fuzz_target(project_name: str) -> bool:
    """
    Copies an empty fuzz target to the project directory and attempts to build it.
    Returns True if the build is successful, False otherwise.
    """
    logger.info(f"Generating empty fuzz target for project: {project_name}")
    if not oss_fuzz.copy_empty_fuzz_target(project_name):
        logger.error(f"Failed to copy empty fuzz target for {project_name}.")
        return False

    logger.info(f"Attempting to build the empty fuzz target")
    build_result = oss_fuzz.build_fuzzers(project_name)

    if build_result.success:
        logger.info(f"Successfully built empty fuzz target for {project_name}.")
        return True
    else:
        logger.error(f"Failed to build empty fuzz target for {project_name}: {build_result.error}")
        oss_fuzz.remove_target(project_name, "llm_fuzzgen_empty")
        return False


def build_fuzz_target(project_name: str, prompt: str) -> Path | None:
    """
    Builds a fuzz target for the given project using prompt-based iteration with multiple compilation attempts.
    """
    global compilation_attempts, compilation_successes

    current_prompt = prompt
    langgraph_threadid = int(time.time())
    is_first_attempt = True

    for attempt in range(1, config.COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS + 1):
        compilation_attempts += 1
        logger.info(
            f"Build attempt {attempt}/{config.COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} "
            f"for '{project_name}'."
        )

        fuzz_file = None  # Initialize fuzz_file to None for safety
        try:
            code = llm_client.generate(current_prompt, langgraph_threadid)
            if not code:
                logger.error(f"LLM generation failed for attempt {attempt}. No code generated.")
                continue

            fuzz_file = oss_fuzz.save_target(project_name, code)
            logger.info(f"Saved fuzz target: '{fuzz_file}'.")

            result = oss_fuzz.run_fuzzer(project_name, fuzz_file.stem)
            if result.success:
                compilation_successes += 1
                logger.info(f"Build succeeded: '{fuzz_file}'.")
                return fuzz_file

            # --- Build Failed: Prepare for next attempt ---
            logger.error(f"Build failed (attempt {attempt})")

            # On the first failure, create a detailed prompt.
            # On subsequent failures, just send the new error to continue the conversation.
            if is_first_attempt:
                is_first_attempt = False
                langgraph_threadid = int(time.time())  # Reset thread for a new conversational context
                current_prompt = prompt_generator.build_prompt(
                    fuzz_target_code=code,
                    error_messages=result.error,
                    lang=oss_fuzz.proj_lang(project_name),
                    proj=project_name,
                    headers=", ".join(introspector.get_all_header_files(project_name)),
                )
            else:
                current_prompt = result.error

            # Clean up the failed target file before the next attempt
            oss_fuzz.remove_target(project_name, fuzz_file.stem)

        except Exception as e:
            logger.error(f"An unexpected error occurred in build attempt {attempt}: {e}", exc_info=True)
            # Clean up if a file was created before the exception
            if fuzz_file:
                oss_fuzz.remove_target(project_name, fuzz_file.stem)

            # Reset for a fresh attempt in the next iteration
            current_prompt = prompt
            is_first_attempt = True
            langgraph_threadid = int(time.time())

    logger.warning(
        f"All {config.COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS} attempts failed for '{project_name}'."
    )
    return None


def mutate_fuzz_target(project_name: str, fuzz_target: str, fuzz_target_name: str) -> Path | None:
    logger.info(f"Mutating fuzz target for project: {project_name}")
    # Search for LLVMFuzzerTestOneInput in order to analyze the fuzz target's coverage
    fuzz_target_coverage_report = oss_fuzz.linecov_reports(project_name, fuzz_target_name)
    prompt = prompt_generator.coverage_prompt(
        fuzz_target_code=fuzz_target,
        lang=oss_fuzz.proj_lang(project_name),
        proj=project_name,
        headers=", ".join(introspector.get_all_header_files(project_name)),
        fun_coverage_report=oss_fuzz.funcov_reports(project_name),
        fuzz_target_name=fuzz_target_name,
        fuzz_target_coverage_report=fuzz_target_coverage_report,
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Mutated fuzz target for {project_name} successfully")

    return new_fuzz_target


def regenerate_fuzz_target(project_name: str) -> Path | None:
    logger.info(f"Regenerating fuzz target for project: {project_name}")

    prompt = prompt_generator.regeneration_prompt(
        fun_coverage_report=oss_fuzz.funcov_reports(project_name),
        headers=", ".join(introspector.get_all_header_files(project_name)),
        proj=project_name,
        lang=oss_fuzz.proj_lang(project_name),
    )

    new_fuzz_target = build_fuzz_target(project_name, prompt)
    if new_fuzz_target:
        logger.info(f"Regenerated fuzz target for {project_name} successfully")

    return new_fuzz_target


def _get_coverage_metric(summary: TotalCoverageSummary | None, metric_name: str) -> float:
    """Safely extracts a coverage metric percentage, defaulting to 0.0."""
    if not summary:
        return 0.0
    metric = getattr(summary, metric_name, None)
    return metric.percent if metric else 0.0


def _get_optional_coverage_metric(summary: TotalCoverageSummary | None, metric_name: str) -> float | None:
    """Extract a measured percentage while preserving unavailable coverage as null."""
    if not summary:
        return None
    metric = getattr(summary, metric_name, None)
    return metric.percent if metric else None


def _get_coverage_count(summary: TotalCoverageSummary | None, metric_name: str) -> int:
    """Safely extracts a covered count, defaulting to 0."""
    if not summary:
        return 0
    metric = getattr(summary, metric_name, None)
    return int(metric.covered) if metric else 0


def _build_coverage_growth_payload(
    before_summary: TotalCoverageSummary | None,
    after_summary: TotalCoverageSummary | None,
) -> dict[str, object]:
    return {
        "line_coverage_growth": _coverage_growth_metric(before_summary, after_summary, "lines"),
        "branch_coverage_growth": _coverage_growth_metric(before_summary, after_summary, "branches"),
        "functions_coverage_growth": _coverage_growth_metric(before_summary, after_summary, "functions"),
    }


def _log_experiment_event(event: str, **payload) -> None:
    if experiment_logger is None:
        return
    experiment_logger.log_event(event, **payload)


def _append_blocker_attempt_record(**payload) -> None:
    if experiment_logger is None:
        return

    if experiment_dir is not None:
        output_path = experiment_dir / "blocker_attempts.jsonl"
    else:
        output_dir = Path(__file__).parent / "artifacts" / "blocker_attempts"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{experiment_logger.run_id}_{experiment_logger.project_name}.jsonl"
    record = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run_id": experiment_logger.run_id,
        "project": experiment_logger.project_name,
    }
    record.update(payload)

    try:
        with output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        logger.warning("Failed to write blocker attempt record to %s: %s", output_path, exc)


def process_project(
    project_name: str,
    seconds: int,
    use_dict: bool,
    use_seeds: bool,
    coverage_interval: int = 0,
    coverage_log_path: Path | None = None,
    coverage_stagnation_window: int = 3,
    coverage_stagnation_threshold: float = 0.01,
    stop_on_coverage_stall: bool = False,
) -> bool:
    """Process a single project and generate fuzz targets."""
    try:
        logger.info(f"Starting to process project: {project_name}")
        _log_experiment_event(
            "process_started",
            seconds=seconds,
            use_dict=use_dict,
            use_seeds=use_seeds,
            iteration_budget=config.COVERAGE_ITERATION_LOOP,
            no_growth_stop_threshold=config.COVERAGE_NO_GROWTH_STOP_THRESHOLD,
        )

        if use_dict:
            generate_dict_for_proj(project_name, llm_client)
        iterator = FuzzIterator(project_name, oss_fuzz)
        fuzz_target = None  # Will hold the path to the current fuzz target
        iterator.record_cov()  # Record coverage before any fuzz target generation
        initial_cov = iterator.latest_cov()
        _log_experiment_event(
            "baseline_coverage",
            iteration=0,
            line_coverage=_get_coverage_metric(initial_cov, "lines"),
            branch_coverage=_get_coverage_metric(initial_cov, "branches"),
            functions_coverage=_get_coverage_metric(initial_cov, "functions"),
        )

        no_growth_count = 0
        # Iterative improvement loop
        for iteration in range(config.COVERAGE_ITERATION_LOOP):
            if no_growth_count >= config.COVERAGE_NO_GROWTH_STOP_THRESHOLD:
                logger.warning(
                    f"Stopping iteration for {project_name} due to "
                    f"{config.COVERAGE_NO_GROWTH_STOP_THRESHOLD} consecutive iterations "
                    "with no coverage growth."
                )
                break
            previous_cov_summary = iterator.latest_cov()
            is_regeneration = iterator.should_regenerate()

            # Standard strategy: regenerate or mutate existing
            if is_regeneration or fuzz_target is None:
                new_target = regenerate_fuzz_target(project_name)
                is_regeneration = True
                action_type = "regenerate"
            else:
                new_target = mutate_fuzz_target(project_name, fuzz_target.read_text(), fuzz_target.stem)
                action_type = "mutate"

            if new_target is None:
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                _log_experiment_event(
                    "target_generation_failed",
                    iteration=iteration + 1,
                    action_type=action_type,
                )
                continue

            new_cov_summary = oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds)
            if not new_cov_summary:
                oss_fuzz.remove_target(project_name, new_target.stem)
                _log_experiment_event(
                    "coverage_failed",
                    iteration=iteration + 1,
                    action_type=action_type,
                    target_name=new_target.stem,
                )
                continue

            if use_seeds:
                generate_seeds_for_fuzzer(project_name, new_target.stem, new_target.read_text(), llm_client)
                oss_fuzz.remove_corpus(project_name, new_target.stem)
                if cov_with_seeds := oss_fuzz.coverage(project_name, new_target.stem, seconds=seconds):
                    new_cov_summary = cov_with_seeds
                    logger.info("Used coverage from generated seeds.")

            # Extract previous and new metrics using the helper
            prev_line_cov = _get_coverage_metric(previous_cov_summary, "lines")
            prev_branch_cov = _get_coverage_metric(previous_cov_summary, "branches")
            new_line_cov = _get_coverage_metric(new_cov_summary, "lines")
            new_branch_cov = _get_coverage_metric(new_cov_summary, "branches")

            line_growth = new_line_cov - prev_line_cov
            branch_growth = new_branch_cov - prev_branch_cov
            logger.info(f"Line coverage: {prev_line_cov:.2f}% -> {new_line_cov:.2f}% (growth: {line_growth:.2f}%)")
            logger.info(f"Branch coverage: {prev_branch_cov:.2f}% -> {new_branch_cov:.2f}% (growth: {branch_growth:.2f}%)")
            _log_experiment_event(
                "candidate_evaluated",
                iteration=iteration + 1,
                action_type=action_type,
                target_name=new_target.stem,
                previous_target_name=fuzz_target.stem if fuzz_target else None,
                line_coverage_before=prev_line_cov,
                line_coverage_after=new_line_cov,
                branch_coverage_before=prev_branch_cov,
                branch_coverage_after=new_branch_cov,
                functions_coverage_after=_get_coverage_metric(new_cov_summary, "functions"),
                line_growth=line_growth,
                branch_growth=branch_growth,
                accepted=new_line_cov > prev_line_cov or new_branch_cov > prev_branch_cov,
            )

            if new_line_cov <= prev_line_cov and new_branch_cov <= prev_branch_cov:
                oss_fuzz.remove_target(project_name, new_target.stem)
                logger.warning(f"Fuzz target's coverage did not improve in iteration {iteration + 1}")
                fuzz_target = None  # set fuzz_target to None so that it can be regenerated in the next iteration
                no_growth_count += 1
                logger.info(
                    f"No growth count: {no_growth_count}/"
                    f"{config.COVERAGE_NO_GROWTH_STOP_THRESHOLD}"
                )
                _log_experiment_event(
                    "candidate_rejected",
                    iteration=iteration + 1,
                    action_type=action_type,
                    target_name=new_target.stem,
                    no_growth_count=no_growth_count,
                )
                continue

            run_fuzzers_and_get_coverage(
                proj_name=project_name,
                run_seconds=seconds,
                coverage_interval=coverage_interval,
                coverage_log_path=coverage_log_path,
                coverage_stagnation_window=coverage_stagnation_window,
                coverage_stagnation_threshold=coverage_stagnation_threshold,
                stop_on_coverage_stall=stop_on_coverage_stall,
            )

            no_growth_count = 0
            logger.info(
                f"No growth count reset, 0/{config.COVERAGE_NO_GROWTH_STOP_THRESHOLD}"
            )
            # Record successful growth statistics (based on line coverage)
            if is_regeneration:
                regeneration_growth.append(line_growth)
                iterator.clean_cov()  # Clear coverage records for regeneration
                logger.info(f"Regeneration growth recorded: {line_growth:.2f}")
            else:
                mutation_growth.append(line_growth)
                logger.info(f"Mutation growth recorded: {line_growth:.2f}")

            fuzz_target = new_target
            iterator.record_cov()
            latest_cov = iterator.latest_cov()
            latest_line_cov = _get_coverage_metric(latest_cov, "lines")
            logger.info(f"Finished iteration {iteration + 1} for {project_name}, coverage: {latest_line_cov:.2f}%")
            _log_experiment_event(
                "candidate_accepted",
                iteration=iteration + 1,
                action_type=action_type,
                target_name=fuzz_target.stem,
                line_coverage=_get_coverage_metric(latest_cov, "lines"),
                branch_coverage=_get_coverage_metric(latest_cov, "branches"),
                functions_coverage=_get_coverage_metric(latest_cov, "functions"),
            )

        final_cov = iterator.latest_cov()
        _log_experiment_event(
            "process_finished",
            success=True,
            final_line_coverage=_get_coverage_metric(final_cov, "lines"),
            final_branch_coverage=_get_coverage_metric(final_cov, "branches"),
            final_functions_coverage=_get_coverage_metric(final_cov, "functions"),
        )
        return True

    except Exception as e:
        logger.error(f"Failed to process project {project_name}: {e}", exc_info=True)
        _log_experiment_event("process_finished", success=False, error=str(e))
        return False


def calculate_statistics(project_name: str, initial_coverage_percent: float):
    """Calculate and return the growth statistics, compilation success rate, and other metrics."""
    total_coverage_summary = oss_fuzz.get_coverage_summary(project_name)
    total_coverage_summary_exclude_target = oss_fuzz.get_coverage_summary(project_name, exclude_target=True)
    stats = {
        "regeneration": {
            "count": len(regeneration_growth),
            "average": (sum(regeneration_growth) / len(regeneration_growth) if regeneration_growth else 0),
        },
        "mutation": {
            "count": len(mutation_growth),
            "average": sum(mutation_growth) / len(mutation_growth) if mutation_growth else 0,
        },
    }

    # Calculate compilation success rate
    compilation_success_rate = (compilation_successes / compilation_attempts * 100) if compilation_attempts > 0 else 0

    logger.info("=" * 50)
    logger.info("Coverage Growth Statistics:")
    logger.info(
        f"Regeneration: {stats['regeneration']['count']} iterations, Average growth: {stats['regeneration']['average']:.2f}%"
    )
    logger.info(f"Mutation: {stats['mutation']['count']} iterations, Average growth: {stats['mutation']['average']:.2f}%")
    logger.info("=" * 50)
    logger.info("Compilation Success Rate:")
    logger.info(f"Total compilation attempts: {compilation_attempts}")
    logger.info(f"Successful compilations: {compilation_successes}")
    logger.info(f"Success rate: {compilation_success_rate:.2f}% ")
    logger.info("=" * 50)

    logger.info(f"Initial coverage: {initial_coverage_percent:.2f}%")
    if total_coverage_summary:
        logger.info("=" * 50)
        logger.info("Total Coverage Summary:")
        for metric_name, summary in total_coverage_summary.__dict__.items():
            if summary:
                logger.info(
                    f"  {metric_name.capitalize()}: Count={summary.count}, Covered={summary.covered}, Percent={summary.percent:.2f}%"
                )

    if total_coverage_summary_exclude_target:
        logger.info("=" * 50)
        logger.info("Total Coverage Summary (excluding fuzz target):")
        for metric_name, summary in total_coverage_summary_exclude_target.__dict__.items():
            if summary:
                logger.info(
                    f"  {metric_name.capitalize()}: Count={summary.count}, Covered={summary.covered}, Percent={summary.percent:.2f}%"
                )

    logger.info("=" * 50)


def main() -> None:
    try:
        t0 = time.perf_counter()
        args = _parse_args()

        log_name = "run_all_fuzzer" if args.command == "run_all_fuzzer" else args.project_name

        global llm_client
        global experiment_logger
        global experiment_dir
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        experiment_dir = Path("experiments") / f"{run_id}_{log_name}"
        experiment_dir.mkdir(parents=True, exist_ok=True)

        setup_logging(log_name, model_name=args.model, log_dir=experiment_dir, log_filename="run.log")

        llm_client = LLMClient(backend=args.llm, model_name=args.model)
        system_name = "blocker" if args.command == "run_all_fuzzer" and args.use_blocker else "baseline"
        experiment_logger = ExperimentLogger(system_name=system_name, project_name=log_name,
                                             run_id=run_id, output_dir=experiment_dir)
        _log_experiment_event(
            "run_started",
            command=args.command,
            args=vars(args),
            model=args.model,
            llm_backend=args.llm,
        )
        
        coverage_log = (
            experiment_dir / "coverage" / f"{log_name}.jsonl"
            if experiment_dir is not None
            else args.coverage_log
        )

        if args.command == "run_all_fuzzer":
            run_success = run_all_fuzzer(
                args.project_names,
                args.run_fuzzers,
                args.parallel,
                args.minimize_corpus,
                args.print_coverage,
                args.analyze_crashes,
                args.fuzz_targets_parallel,
                args.coverage_interval,
                coverage_log,
                args.coverage_stagnation_window,
                args.coverage_stagnation_threshold,
                args.stop_on_coverage_stall,
                args.use_blocker,
                not args.blocker_before_fuzzing,
                args.blocker_json_path,
                args.blocker_index,
                args.blocker_top_k,
                args.blocker_session_size,
                args.blocker_max_iterations,
                args.blocker_fuzz_seconds,
                args.blocker_reset_corpus_per_iteration,
                args.blocker_keep_auto_context,
                args.blocker_pipeline_mode,
                args.skip_input_dependent_pipeline,
                args.skip_input_independent_pipeline,
                args.enable_blocker_triage,
                args.blocker_session_refresh_mode,
                args.blocker_artifact_report_seconds,
                args.blocker_refresh_branch_growth_threshold,
                args.blocker_refresh_branch_growth_floor,
                args.llm,
                args.model,
                args.budget_mode,
                args.target_exposure_min_seconds,
                args.generated_target_priority_seconds,
            )
            _log_experiment_event("run_finished", success=run_success, total_seconds=time.perf_counter() - t0)
            logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")
            return

        if args.command == "run_blocker_once":
            run_success = run_blocker_once(
                project_name=args.project_name,
                llm_backend=args.llm,
                model_name=args.model,
                blocker_json_path=args.blocker_json_path,
                blocker_index=args.blocker_index,
                blocker_top_k=args.blocker_top_k,
                blocker_max_iterations=args.blocker_max_iterations,
                blocker_fuzz_seconds=args.blocker_fuzz_seconds,
                blocker_reset_corpus_per_iteration=args.blocker_reset_corpus_per_iteration,
                blocker_keep_auto_context=args.blocker_keep_auto_context,
                blocker_pipeline_mode=args.blocker_pipeline_mode,
                skip_input_dependent_pipeline=args.skip_input_dependent_pipeline,
                skip_input_independent_pipeline=args.skip_input_independent_pipeline,
                enable_blocker_triage=args.enable_blocker_triage,
                blocker_artifact_report_seconds=args.blocker_artifact_report_seconds,
                prepare_artifacts=args.prepare_artifacts,
                force_refresh_artifacts=args.force_refresh_artifacts,
                artifact_refresh_mode=args.artifact_refresh_mode,
                timeout_seconds=args.timeout_seconds,
            )
            _log_experiment_event("run_finished", success=run_success, total_seconds=time.perf_counter() - t0)
            logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")
            return

        if args.initial_fuzz_target:
            logger.info("Generating initial fuzz target")
            if not generate_empty_fuzz_target(args.project_name):
                logger.error(f"Failed to generate initial fuzz target for {args.project_name}")
                sys.exit(1)
        else:
            logger.info("Skipping initial fuzz target generation")
        logger.info(f"Starting introspector webapp for initial analysis of {args.project_name}")

        if not minimize_and_generate_report(args.project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        initial_cov_summary = oss_fuzz.get_coverage_summary(args.project_name, exclude_target=True)
        initial_coverage_percent = initial_cov_summary.lines.percent if initial_cov_summary and initial_cov_summary.lines else 0.0
        logger.info(f"Initial coverage for {args.project_name}: {initial_coverage_percent:.2f}%")
        if args.initial_fuzz_target:
            oss_fuzz.remove_target(args.project_name, "llm_fuzzgen_empty")

        result = process_project(
            args.project_name,
            seconds=args.seconds,
            use_dict=args.dict,
            use_seeds=args.seeds,
            coverage_interval=args.coverage_interval,
            coverage_log_path=coverage_log,
            coverage_stagnation_window=args.coverage_stagnation_window,
            coverage_stagnation_threshold=args.coverage_stagnation_threshold,
            stop_on_coverage_stall=args.stop_on_coverage_stall,
        )

        if not minimize_and_generate_report(args.project_name, seconds=args.seconds, clean=True):
            sys.exit(1)

        calculate_statistics(args.project_name, initial_coverage_percent)

        logger.info("Project processed")
        logger.info(f"Successful project: {result}")
        _log_experiment_event(
            "run_finished",
            success=result,
            total_seconds=time.perf_counter() - t0,
            initial_line_coverage=initial_coverage_percent,
        )
        logger.info(f"Total execution time: {time.perf_counter() - t0:.2f} seconds")

        user_input = input("Do you want to shutdown the server (http://localhost:8080)? (y/n): ")
        if user_input.lower() == "n":
            logger.info("Server is still running.")
        else:
            introspector.shutdown_webapp()
            logger.info("Server shutdown.")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        _log_experiment_event("run_finished", success=False, error=str(e))
        try:
            introspector.shutdown_webapp()
            logger.info("Server shutdown due to exception.")
        except Exception as e:
            logger.error(f"Failed to shutdown server in finally block: {e}")


if __name__ == "__main__":
    main()
