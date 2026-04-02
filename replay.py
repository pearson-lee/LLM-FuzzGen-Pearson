#!/usr/bin/env python3
"""
replay_corpus_dfsan.py
對指定 corpus 進行 DFSan replay，追蹤特定 blocker line 的 taint 狀態

前提：fuzz target binary 已在 blocker 位置插入如下 instrumentation：
  fprintf(stderr, "[GroundTruth] Line %d: %s (flags:%d, *p:%d)\\n",
          LINE_NO, dfsan_get_label(val) ? "TAINTED" : "NOT TAINTED", flags, p_val);

用法：
  python3 replay_corpus_dfsan.py <fuzz_target> <corpus_dir> \\
      [--line <line_no>] [--out_dir <out_dir>] [--timeout <sec>]
"""

import os
import re
import sys
import logging
import argparse
import subprocess
from pathlib import Path
from enum import Enum


class TaintResult(Enum):
    UNKNOWN           = "UNKNOWN"
    INPUT_INDEPENDENT = "INPUT INDEPENDENT"
    INPUT_DEPENDENT   = "INPUT DEPENDENT"


def setup_logging(log_file: str | None = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    return logging.getLogger(__name__)


def parse_dfsan_output(output: str, target_line: int):
    """
    支援任意 label 格式，例如：
      [GroundTruth] Line 160: TAINTED (this_lbl:1, other_lbl:0) -> Input Dependent
      [GroundTruth] Line 160: UNTAINTED (this_lbl:0, other_lbl:0) -> Input Independent
    """
    pattern = re.compile(
        r"\[GroundTruth\] Line "
        + str(target_line)
        + r": (TAINTED|UNTAINTED|NOT TAINTED)"
        + r".*"   # 括號內容完全不管
    )
    match = pattern.search(output)
    if not match:
        return None

    raw_line = match.group(0)   # 保留完整原始行
    tainted = match.group(1) == "TAINTED"
    result = TaintResult.INPUT_DEPENDENT if tainted else TaintResult.INPUT_INDEPENDENT
    return result, raw_line

def run_seed(binary: str, seed_path: str, timeout: int) -> str:
    """執行單一 seed，回傳 stdout + stderr 合併"""
    try:
        proc = subprocess.run(
            [
                binary,
                f"-timeout={timeout}",      # libFuzzer 層級的 timeout，對齊 subprocess timeout
                f"-rss_limit_mb=4096",      # 避免大型 seed 被 OOM kill 而無輸出
                "-print_final_stats=0",     # 抑制 libFuzzer 結尾的統計輸出，減少 parse 雜訊
                seed_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return ""


def determine_final_gt(results: list[TaintResult]) -> str:
    valids = [r for r in results if r != TaintResult.UNKNOWN]
    if not valids:
        return "UNKNOWN"
    return valids[0].value if len(set(valids)) == 1 else "INCONSISTENT"


def main():
    parser = argparse.ArgumentParser(description="DFSan corpus replay & taint analysis")
    parser.add_argument("fuzz_target",  help="fuzz target 名稱 (e.g. parse_fuzzer)")
    parser.add_argument("corpus_dir",   help="corpus 資料夾路徑")
    parser.add_argument("--line",       type=int, default=317,  help="追蹤的 blocker line number (預設: 317)")
    parser.add_argument("--out_dir",    default="/out",          help="binary 所在目錄 (預設: /out)")
    parser.add_argument("--timeout",    type=int, default=30,   help="每個 seed 的 timeout 秒數 (預設: 30)")
    parser.add_argument("--log_file",   default=None,            help="額外輸出 log 到指定檔案")
    args = parser.parse_args()

    logger = setup_logging(args.log_file)

    binary = os.path.join(args.out_dir, args.fuzz_target)
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        logger.error(f"Binary not found or not executable: {binary}")
        sys.exit(1)

    seed_files = sorted(p for p in Path(args.corpus_dir).iterdir() if p.is_file())
    total = len(seed_files)
    if total == 0:
        logger.error(f"No seed files found in: {args.corpus_dir}")
        sys.exit(1)

    logger.info(f"=== Starting processing {total} Seeds ===")

    results = []
    counts = {r: 0 for r in TaintResult}

    for idx, seed_path in enumerate(seed_files, start=1):
        output = run_seed(binary, str(seed_path), args.timeout)
        parsed = parse_dfsan_output(output, args.line)

        if parsed is None:
            results.append(TaintResult.UNKNOWN)
            counts[TaintResult.UNKNOWN] += 1
        else:
            result, raw_line = parsed
            logger.info(f"[{idx}/{total}] {seed_path.name} -> {raw_line}")
            results.append(result)
            counts[result] += 1

    final_gt = determine_final_gt(results)

    logger.info("=== 分析結果 ===")
    logger.info(f"  UNKNOWN: {counts[TaintResult.UNKNOWN]}")
    logger.info(f"  INPUT INDEPENDENT: {counts[TaintResult.INPUT_INDEPENDENT]}")
    logger.info(f"  INPUT DEPENDENT: {counts[TaintResult.INPUT_DEPENDENT]}")
    logger.info("=" * 50)
    logger.info(f"  Final Ground Truth: {final_gt}")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()