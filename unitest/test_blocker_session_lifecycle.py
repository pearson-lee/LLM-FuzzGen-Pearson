import json
import time
from pathlib import Path

import main


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
    monkeypatch.setattr(main.oss_fuzz, "build_out_dir", build_out)
    monkeypatch.setattr(main, "experiment_dir", tmp_path / "experiment")

    bundle = main._create_blocker_session_artifacts("demo", 1, blocker_json, blockers)

    assert bundle is not None
    assert bundle.blocker_json.is_file()
    assert set(bundle.cfg_data_files) == {"target_a", "target_b"}
    assert bundle.source_root is not None and bundle.source_root.is_dir()
    manifest = json.loads((bundle.root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["missing_cfg_targets"] == []


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
    monkeypatch.setattr(main, "_coverage_with_timing", lambda *args, **kwargs: None)

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
        blocker_session_refresh_mode="reuse_session_artifacts",
    )

    assert attempted == ["first", "second", "third"]
    assert result["attempted"] == 3
