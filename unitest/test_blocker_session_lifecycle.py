import json
import time
from pathlib import Path

import main
from external.oss_fuzz import CompilationResult, CoverageMetricSummary


def _blocker(name: str, line: int, target: str) -> dict:
    return {
        "function_name": name,
        "source_file": f"/src/demo/{name}.c",
        "branch_line_number": str(line),
        "blocked_side_line_number": str(line + 1),
        "best_target": target,
        "project_blocker_state": "stalled_at_branch",
        "project_branch_hit_count": 1,
        "project_blocked_hit_count": 0,
    }


def _write_static_artifacts(tmp_path: Path, blockers: list[dict]) -> tuple[Path, Path]:
    build_out = tmp_path / "out"
    inspector = build_out / "demo" / "inspector"
    inspector.mkdir(parents=True)
    raw = {blocker["best_target"]: [blocker] for blocker in blockers}
    blocker_json = inspector / "branch-blockers.json"
    blocker_json.write_text(json.dumps(raw), encoding="utf-8")
    (inspector / "all_functions.js").write_text("var all_functions_table_data = [];", encoding="utf-8")
    (inspector / "summary.json").write_text('{"data": []}', encoding="utf-8")

    pairings = []
    for index, blocker in enumerate(blockers):
        log_name = f"fuzzer-log-{index}"
        pairings.append(
            f"- executable_path: /out/{blocker['best_target']}\n  fuzzer_log_file: {log_name}\n"
        )
        (inspector / f"{log_name}.data").write_text("calltree", encoding="utf-8")
    (inspector / "exe_to_fuzz_introspector_logs.yaml").write_text(
        "pairings:\n" + "".join(pairings),
        encoding="utf-8",
    )
    source_root = build_out / "demo" / "source_code"
    source_root.mkdir(parents=True)
    for blocker in blockers:
        (source_root / f"{blocker['function_name']}.c").write_text("void f(void) {}\n", encoding="utf-8")
    return build_out, blocker_json


def test_session_artifact_bundle_copies_candidate_cfg_and_source(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a"), _blocker("second", 20, "target_b")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    inspector = build_out / "demo" / "inspector"
    with (inspector / "exe_to_fuzz_introspector_logs.yaml").open("a", encoding="utf-8") as stream:
        stream.write("- executable_path: /out/future_reranked_target\n  fuzzer_log_file: future-log\n")
    (inspector / "future-log.data").write_text("future calltree", encoding="utf-8")
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")

    bundle = main._create_blocker_session_artifacts("demo", 1, blocker_json, blockers)

    assert bundle is not None
    assert bundle.blocker_json.is_file()
    assert set(bundle.cfg_data_files) == {"target_a", "target_b"}
    assert (bundle.root / "future-log.data").is_file()
    assert bundle.source_root is not None and bundle.source_root.is_dir()
    manifest = json.loads((bundle.root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["missing_cfg_targets"] == []
    assert manifest["copied_cfg_file_count"] == 3


def test_direct_blocker_run_snapshots_introspector_before_restoring_coverage(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")
    def fake_full_refresh(**kwargs):
        kwargs["state"].last_artifact_refresh_mode = "full_refresh"
        return True

    monkeypatch.setattr(main, "ensure_blocker_artifacts", fake_full_refresh)
    monkeypatch.setattr(main, "_resolve_blocker_json_path", lambda *args, **kwargs: blocker_json)

    lifecycle = []

    def restore_coverage(project_name, sanitizer, deadline=None):
        lifecycle.append(("coverage", project_name, sanitizer))
        assert (tmp_path / "experiment" / "blocker_sessions" / "demo" / "session_001" / "manifest.json").is_file()
        return CompilationResult(success=True)

    monkeypatch.setattr(main.oss_fuzz, "build_fuzzers", restore_coverage)

    captured = {}

    def fake_pipeline(**kwargs):
        captured.update(kwargs)
        return {"success": True}

    monkeypatch.setattr(main, "run_blocker_pipeline", fake_pipeline)

    assert main.run_blocker_once(
        project_name="demo",
        llm_backend="vertexai",
        model_name="model",
        blocker_json_path=blocker_json,
        prepare_artifacts=True,
    )

    assert lifecycle == [("coverage", "demo", "coverage")]
    assert captured["session_artifacts"] is not None
    assert captured["blocker_json_path"] == captured["session_artifacts"].blocker_json


def test_pipeline_error_before_solver_does_not_count_as_attempt(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")
    monkeypatch.setattr(main, "ensure_blocker_artifacts", lambda **kwargs: True)
    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", lambda project_name: True)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})
    monkeypatch.setattr(main, "_load_blocker_coverage_context", lambda *args, **kwargs: coverage_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: list(blockers))
    monkeypatch.setattr(
        main,
        "run_blocker_pipeline",
        lambda **kwargs: {
            "success": False,
            "attempt_result": "pipeline_error",
            "reason": "live_revalidation_failed",
            "pipeline_failure_stage": "live_revalidation",
        },
    )
    state = main.BlockerRuntimeState(artifacts_ready=True)

    result = main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=0,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_json_path=blocker_json,
        blocker_session_size=1,
        blocker_top_k=1,
    )

    assert result["attempted"] == 0
    assert result["pipeline_errors"] == 1
    assert state.attempted_blocker_keys == set()


def test_only_terminal_pipeline_or_triage_results_are_persisted():
    assert main._should_persist_blocker_attempt({"attempt_result": "success"})
    assert main._should_persist_blocker_attempt({"attempt_result": "failed"})
    assert main._should_persist_blocker_attempt({"attempt_result": "triage_skipped"})
    assert main._should_persist_blocker_attempt({"attempt_result": "triage_manual_review"})
    assert not main._should_persist_blocker_attempt({"attempt_result": "pipeline_error"})
    assert not main._should_persist_blocker_attempt({"attempt_result": "llm_error"})
    assert not main._should_persist_blocker_attempt({})


def test_selector_filters_attempted_blockers_before_top_k(monkeypatch, tmp_path):
    first = _blocker("first", 10, "target_a")
    second = _blocker("second", 20, "target_b")
    blockers = [first, second]

    monkeypatch.setattr(main, "aggregate_score_and_revalidate_blockers", lambda **kwargs: list(blockers))
    monkeypatch.setattr(main, "_filter_and_refine_project_blockers", lambda candidates, _context: list(candidates))

    selected = main._select_project_blockers(
        "demo",
        tmp_path / "branch-blockers.json",
        blocker_top_k=1,
        coverage_context=main.BlockerCoverageContext(project_report="", target_reports={}),
        attempted_blocker_keys={main._blocker_identity(first)},
    )

    assert selected == [second]


def test_empty_validated_blocker_pool_marks_full_refresh_needed(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "_get_project_target_fingerprint", lambda project_name: "fingerprint")

    def fake_ensure(**kwargs):
        kwargs["state"].last_artifact_refresh_reused_existing = True
        return True

    monkeypatch.setattr(main, "ensure_blocker_artifacts", fake_ensure)
    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", lambda project_name: True)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})
    monkeypatch.setattr(main, "_load_blocker_coverage_context", lambda *args, **kwargs: coverage_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: [])
    state = main.BlockerRuntimeState(
        artifacts_ready=True,
        artifact_target_fingerprint="fingerprint",
    )

    result = main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=0,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_json_path=blocker_json,
    )

    assert result["reason"] == "no_blockers"
    assert state.blocker_pool_exhausted


def test_coverage_context_ignores_stale_blocker_targets(monkeypatch, tmp_path):
    build_out = tmp_path / "out"
    reports_dir = build_out / "demo" / "textcov_reports"
    reports_dir.mkdir(parents=True)
    blocker_json = tmp_path / "branch-blockers.json"
    blocker_json.write_text(
        json.dumps(
            {
                "active_target": [_blocker("active", 10, "active_target")],
                "deleted_target": [_blocker("deleted", 20, "deleted_target")],
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "project.linecovreport").write_text("project", encoding="utf-8")
    (reports_dir / "summary_exclude_target.json").write_text("{}", encoding="utf-8")
    (reports_dir / "active_target.linecovreport").write_text("active", encoding="utf-8")
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)

    context = main._load_blocker_coverage_context("demo", blocker_json, repair_missing=False)

    assert context is not None
    assert set(context.target_reports) == {"active_target"}


def test_selector_skips_candidates_without_target_report(monkeypatch):
    active = _blocker("active", 10, "active_target")
    deleted = _blocker("deleted", 20, "deleted_target")

    def fake_line_count(_report, line, **_kwargs):
        return "1" if int(line) == 10 else "0"

    monkeypatch.setattr(main, "get_line_execution_count", fake_line_count)

    selected = main._filter_and_refine_project_blockers(
        [deleted, active],
        main.BlockerCoverageContext(project_report="project", target_reports={"active_target": "active"}),
    )

    assert [blocker["best_target"] for blocker in selected] == ["active_target"]


def test_blocker_pipeline_invalidates_parent_build_state_on_solver_exception(monkeypatch, tmp_path):
    blocker = _blocker("first", 10, "target_a")
    blocker_json = tmp_path / "branch-blockers.json"
    blocker_json.write_text(json.dumps({"target_a": [blocker]}), encoding="utf-8")
    monkeypatch.setattr(
        main,
        "_live_revalidate_blocker_before_classify",
        lambda **kwargs: {
            "success": True,
            "branch_line_reached": True,
            "blocked_side_line_reached": False,
            "branch_hit_count": 1,
            "blocked_side_hit_count": 0,
        },
    )

    def raise_solver_error(*args, **kwargs):
        raise RuntimeError("solver failed")

    monkeypatch.setattr(main, "classify_blocker", raise_solver_error)
    invalidations = []
    monkeypatch.setattr(
        main.oss_fuzz,
        "invalidate_project_build_state",
        lambda project_name, reason: invalidations.append((project_name, reason)) or True,
    )

    result = main.run_blocker_pipeline(
        project_name="demo",
        llm_backend="vertexai",
        model_name="model",
        blocker_json_path=blocker_json,
        blocker_record=blocker,
    )

    assert result["attempt_result"] == "llm_error"
    assert invalidations == [("demo", "blocker_pipeline_subprocess_finished")]


def test_blocker_pipeline_passes_live_branch_hit_count_to_classifier(monkeypatch, tmp_path):
    blocker = _blocker("first", 10, "target_a")
    blocker_json = tmp_path / "branch-blockers.json"
    blocker_json.write_text(json.dumps({"target_a": [blocker]}), encoding="utf-8")
    monkeypatch.setattr(
        main,
        "_live_revalidate_blocker_before_classify",
        lambda **kwargs: {
            "success": True,
            "branch_line_reached": True,
            "blocked_side_line_reached": False,
            "branch_hit_count": 22800,
            "blocked_side_hit_count": 0,
        },
    )
    captured = {}

    def fake_classifier(args, execute_pipeline):
        captured["branch_hit_count"] = args.branch_hit_count
        return {
            "dependency_result": "Input Independent",
            "pipeline_result": {"success": False, "attempt_result": "failed"},
        }

    monkeypatch.setattr(main, "classify_blocker", fake_classifier)
    monkeypatch.setattr(main.oss_fuzz, "invalidate_project_build_state", lambda *args, **kwargs: True)

    main.run_blocker_pipeline(
        project_name="demo",
        llm_backend="vertexai",
        model_name="model",
        blocker_json_path=blocker_json,
        blocker_record=blocker,
    )

    assert captured["branch_hit_count"] == 22800


def test_refresh_budget_guard_does_not_start_expensive_refresh(monkeypatch):
    state = main.BlockerRuntimeState()

    def fail_if_called(*args, **kwargs):
        raise AssertionError("refresh should not start")

    monkeypatch.setattr(main.oss_fuzz, "generate_report", fail_if_called)
    success = main.ensure_blocker_artifacts(
        project_name="demo",
        report_seconds=30,
        state=state,
        deadline=time.monotonic() + 100,
        post_refresh_reserve_seconds=50,
    )

    assert not success
    assert state.last_artifact_refresh_skip_reason == "insufficient_time_budget"


def test_cached_revalidation_reuses_existing_static_artifacts(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, _blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "_get_project_target_fingerprint", lambda project_name: "fingerprint")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("cached revalidation must not run full refresh")

    monkeypatch.setattr(main.oss_fuzz, "generate_report", fail_if_called)
    events = []
    monkeypatch.setattr(main, "_log_experiment_event", lambda event, **payload: events.append((event, payload)))
    state = main.BlockerRuntimeState(artifacts_ready=True, artifacts_dirty=True)

    success = main.ensure_blocker_artifacts(
        project_name="demo",
        report_seconds=30,
        state=state,
        force_refresh=True,
        prefer_full_refresh=False,
    )

    assert success
    assert state.artifacts_ready
    assert state.artifacts_dirty
    assert state.last_artifact_refresh_reused_existing
    assert state.last_artifact_refresh_mode == "cached_revalidation"
    assert state.cached_sessions_since_full_rebuild == 1
    assert state.last_artifact_refresh_skip_reason is None
    event, payload = events[-1]
    assert event == "blocker_artifacts_refresh_finished"
    assert payload["success"] is True
    assert payload["refresh_mode"] == "cached_revalidation"


def test_session_reuses_cached_artifacts_when_live_blocker_json_is_missing(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")
    cached_artifacts = main._create_blocker_session_artifacts("demo", 1, blocker_json, blockers)
    assert cached_artifacts is not None
    blocker_json.unlink()

    monkeypatch.setattr(main, "ensure_blocker_artifacts", lambda **kwargs: True)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("cached blocker artifacts should not require a webapp restart")

    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", fail_if_called)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})

    def load_context(project_name, path, **kwargs):
        assert path == cached_artifacts.blocker_json
        return coverage_context

    monkeypatch.setattr(main, "_load_blocker_coverage_context", load_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: list(blockers))
    monkeypatch.setattr(main, "_coverage_with_timing", lambda *args, **kwargs: main.TotalCoverageSummary())

    captured = {}

    def fake_pipeline(**kwargs):
        captured.update(kwargs)
        return {
            "success": True,
            "attempt_result": "success",
            "dependency_result": "Input Independent",
            "pipeline_methods": ["reference_guided_generation"],
            "pipeline_success": True,
        }

    monkeypatch.setattr(main, "run_blocker_pipeline", fake_pipeline)
    state = main.BlockerRuntimeState(
        artifacts_ready=True,
        artifacts_dirty=True,
        last_session_artifacts=cached_artifacts,
    )

    result = main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=3600,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_session_size=1,
        blocker_top_k=1,
    )

    assert result["attempted"] == 1
    assert result["succeeded"] == 1
    assert captured["blocker_json_path"] == cached_artifacts.blocker_json
    assert captured["session_artifacts"] == cached_artifacts
    assert state.last_session_artifacts == cached_artifacts


def test_session_keeps_running_after_live_blocker_json_disappears(monkeypatch, tmp_path):
    blockers = [
        _blocker("first", 10, "target_a"),
        _blocker("second", 20, "target_b"),
        _blocker("third", 30, "target_c"),
    ]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")
    monkeypatch.setattr(main, "ensure_blocker_artifacts", lambda **kwargs: True)
    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", lambda project_name: True)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})
    monkeypatch.setattr(main, "_load_blocker_coverage_context", lambda *args, **kwargs: coverage_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: list(blockers))
    monkeypatch.setattr(main, "_coverage_with_timing", lambda *args, **kwargs: main.TotalCoverageSummary())

    attempted = []

    def fake_pipeline(**kwargs):
        attempted.append(kwargs["blocker_record"]["function_name"])
        assert kwargs["blocker_json_path"].is_file()
        assert kwargs["session_artifacts"].yaml_file.is_file()
        if len(attempted) == 1:
            blocker_json.unlink()
        return {
            "success": False,
            "attempt_result": "failed",
            "dependency_result": "Input Independent",
            "pipeline_methods": [],
            "pipeline_success": False,
        }

    monkeypatch.setattr(main, "run_blocker_pipeline", fake_pipeline)
    state = main.BlockerRuntimeState(artifacts_ready=True)

    result = main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=0,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_json_path=blocker_json,
        blocker_session_size=3,
        blocker_top_k=3,
    )

    assert attempted == ["first", "second", "third"]
    assert result["attempted"] == 3


def test_session_stops_when_post_attempt_coverage_fails(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a"), _blocker("second", 20, "target_b")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")
    monkeypatch.setattr(main, "ensure_blocker_artifacts", lambda **kwargs: True)
    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", lambda project_name: True)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})
    monkeypatch.setattr(main, "_load_blocker_coverage_context", lambda *args, **kwargs: coverage_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: list(blockers))
    monkeypatch.setattr(main, "_coverage_with_timing", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main,
        "run_blocker_pipeline",
        lambda **kwargs: {
            "success": False,
            "attempt_result": "failed",
            "dependency_result": "Input Independent",
            "pipeline_methods": ["reference_guided_generation"],
            "pipeline_success": False,
        },
    )
    events = []
    monkeypatch.setattr(main, "_log_experiment_event", lambda event, **payload: events.append((event, payload)))
    state = main.BlockerRuntimeState(artifacts_ready=True)

    result = main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=0,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_json_path=blocker_json,
        blocker_session_size=2,
        blocker_top_k=2,
    )

    assert result["attempted"] == 1
    assert result["reason"] == "post_attempt_coverage_failed"
    coverage_event = next(payload for event, payload in events if event == "coverage_after_blocker_attempt")
    assert coverage_event["coverage_success"] is False
    assert coverage_event["line_coverage"] is None
    assert coverage_event["branch_coverage"] is None
    assert any(event == "blocker_session_stopped" for event, _ in events)


def test_refreshed_session_baseline_is_used_for_first_growth_event(monkeypatch, tmp_path):
    blockers = [_blocker("first", 10, "target_a")]
    build_out, blocker_json = _write_static_artifacts(tmp_path, blockers)
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")

    def fake_full_refresh(**kwargs):
        kwargs["state"].last_artifact_refresh_mode = "full_refresh"
        return True

    monkeypatch.setattr(main, "ensure_blocker_artifacts", fake_full_refresh)
    monkeypatch.setattr(main, "ensure_blocker_webapp_ready", lambda project_name: True)
    coverage_context = main.BlockerCoverageContext(project_report="report", target_reports={})
    monkeypatch.setattr(main, "_load_blocker_coverage_context", lambda *args, **kwargs: coverage_context)
    monkeypatch.setattr(main, "_select_project_blockers", lambda *args, **kwargs: list(blockers))

    baseline = main.TotalCoverageSummary(
        branches=CoverageMetricSummary(count=100, covered=60, percent=60.0),
        functions=CoverageMetricSummary(count=20, covered=10, percent=50.0),
        lines=CoverageMetricSummary(count=200, covered=120, percent=60.0),
    )
    post_attempt = main.TotalCoverageSummary(
        branches=CoverageMetricSummary(count=100, covered=62, percent=62.0),
        functions=CoverageMetricSummary(count=20, covered=11, percent=55.0),
        lines=CoverageMetricSummary(count=200, covered=125, percent=62.5),
    )
    coverage_results = iter([baseline, post_attempt])
    monkeypatch.setattr(main, "_coverage_with_timing", lambda *args, **kwargs: next(coverage_results))
    monkeypatch.setattr(
        main,
        "run_blocker_pipeline",
        lambda **kwargs: {
            "success": False,
            "attempt_result": "failed",
            "dependency_result": "Input Independent",
            "pipeline_methods": ["reference_guided_generation"],
            "pipeline_success": False,
        },
    )
    events = []
    monkeypatch.setattr(main, "_log_experiment_event", lambda event, **payload: events.append((event, payload)))
    state = main.BlockerRuntimeState(artifacts_ready=False)

    main.run_blocker_session(
        project_name="demo",
        elapsed_seconds=0,
        llm_backend="vertexai",
        model_name="model",
        state=state,
        blocker_json_path=blocker_json,
        blocker_session_size=1,
        blocker_top_k=1,
        pre_blocker_coverage_summary=None,
    )

    growth_event = next(payload for event, payload in events if event == "coverage_growth_after_blocker_attempt")
    assert growth_event["branch_coverage_growth"]["before_covered"] == 60
    assert growth_event["branch_coverage_growth"]["after_covered"] == 62
    assert growth_event["branch_coverage_growth"]["covered_delta"] == 2
