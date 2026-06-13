#!/usr/bin/env python3
"""
從 export_real_blockers.py 匯出的 JSON 挑選 blocker，進入 blocker_callpath_extractor 求解流程。

用法：
  python tools/solve_from_blocker_json.py <blocker_json> --index 0 --classify --execute-pipeline
  python tools/solve_from_blocker_json.py <blocker_json> --list
  python tools/solve_from_blocker_json.py <blocker_json> --index 2 --dry-run
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.blocker_classifier import resolve_fuzz_target_path


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _format_blocker_summary(idx: int, blocker: dict) -> str:
    fn = blocker.get("function_name", "?")
    src = blocker.get("source_file", "?")
    branch = blocker.get("branch_line_number", "?")
    blocked = blocker.get("blocked_side_line_number", "?")
    target = blocker.get("best_target", "?")
    score = blocker.get("score", None)
    state = blocker.get("project_blocker_state", "?")
    score_str = f"  score={score:.3f}" if isinstance(score, float) else ""
    return (
        f"[{idx:>3}] {fn}  branch={branch} blocked={blocked}\n"
        f"       file={src}\n"
        f"       target={target}  state={state}{score_str}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="從匯出的 blocker JSON 挑選 blocker 並進入求解流程。"
    )
    parser.add_argument("blocker_json", type=Path, help="export_real_blockers.py 匯出的 JSON 路徑")
    parser.add_argument("--index", type=int, default=0, help="要求解的 blocker 索引（預設 0）")
    parser.add_argument("--list", action="store_true", help="列出前 20 筆 blocker 後退出")
    parser.add_argument("--dry-run", action="store_true", help="只印出指令，不實際執行")
    parser.add_argument("--header-file", default=None, help="選填：傳遞給 extractor 的 header 路徑")
    parser.add_argument("--max-gdb-inputs", type=int, default=0, help="GDB 最多嘗試的 corpus 數（0 = 全部）")
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--classify", action="store_true", help="執行 LLM 分類")
    parser.add_argument("--execute-pipeline", action="store_true", help="分類後繼續進入 dependent/independent 求解")
    args = parser.parse_args()

    payload = _load_json(args.blocker_json)
    project_name = payload.get("project", "")
    blockers = payload.get("blockers", [])

    if not blockers:
        raise SystemExit("JSON 內沒有 blocker。")

    if args.list:
        print(f"Project: {project_name}  total blockers: {len(blockers)}\n")
        for i, b in enumerate(blockers[:20]):
            print(_format_blocker_summary(i, b))
            print()
        return

    if args.index < 0 or args.index >= len(blockers):
        raise SystemExit(f"--index {args.index} 超出範圍（共 {len(blockers)} 筆）。")

    blocker = blockers[args.index]
    print(f"選取 blocker [{args.index}]:")
    print(_format_blocker_summary(args.index, blocker))
    print()

    function_name = blocker.get("function_name", "")
    branch_line = str(blocker.get("branch_line_number", ""))
    blocked_side_line = str(blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", "")))
    source_file = blocker.get("source_file", "")
    best_target = blocker.get("best_target", "")

    fuzz_file = resolve_fuzz_target_path(project_name, best_target)
    if fuzz_file:
        print(f"[Info] Fuzz file 解析：{fuzz_file}")
    else:
        print(f"[Warn] 找不到 {best_target} 的 fuzz file，extractor 將使用預設 .cc 路徑。")

    cmd = [
        sys.executable, "-m", "blocker_process.blocker_callpath_extractor",
        "--project-name", project_name,
        "--manual-target", best_target,
        "--manual-function", function_name,
        "--manual-branch-line", branch_line,
        "--manual-blocked-side-line", blocked_side_line,
        "--manual-source-file", source_file,
        "--max-gdb-inputs", str(args.max_gdb_inputs),
        "--backend", args.backend,
        "--model", args.model,
    ]
    if fuzz_file:
        cmd += ["--fuzz-file", fuzz_file]
    if args.header_file:
        cmd += ["--header-file", args.header_file]
    if args.classify:
        cmd.append("--classify")
    if args.execute_pipeline:
        cmd.append("--execute-pipeline")

    print("執行指令：")
    print(" ".join(cmd))
    print()

    if args.dry_run:
        print("[dry-run] 不實際執行。")
        return

    subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
