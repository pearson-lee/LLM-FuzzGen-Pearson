import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Tuple


class LogAnalyzer:
    def __init__(self, log_directory: str):
        self.log_directory = log_directory
        self.project_stats = defaultdict(
            lambda: {
                "total_attempts": 0,
                "successful_builds": 0,
                "first_attempt_success": 0,
                "total_compilation_error_records": 0,  # 總編譯錯誤記錄數
                "total_sanitizer_error_records": 0,  # 總消毒器錯誤記錄數
                "build_sequences": [],  # 記錄每個build sequence的詳細資料
            }
        )

    def analyze_logs(self):
        """分析指定目錄下的所有log檔案"""
        if not os.path.exists(self.log_directory):
            print(f"錯誤：目錄 {self.log_directory} 不存在")
            return

        log_files = [f for f in os.listdir(self.log_directory) if f.endswith(".log") and "show_current_cov" not in f]

        if not log_files:
            print("沒有找到符合條件的log檔案")
            return

        print(f"找到 {len(log_files)} 個log檔案進行分析...")

        for log_file in log_files:
            print(f"正在分析: {log_file}")
            self._analyze_single_log(os.path.join(self.log_directory, log_file))

        self._display_results()

    def _analyze_single_log(self, log_file_path: str):
        """分析單個log檔案"""
        try:
            with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # 提取專案名稱
            project_name = self._extract_project_name(content)
            if not project_name:
                print(f"警告：無法從 {log_file_path} 提取專案名稱")
                return

            # 分析build attempts
            self._analyze_build_attempts(content, project_name)

        except Exception as e:
            print(f"錯誤：無法讀取檔案 {log_file_path}: {e}")

    def _extract_project_name(self, content: str) -> str:
        """從log內容中提取專案名稱"""
        # 尋找 "Project Name: xxx" 的模式
        project_match = re.search(r"Project Name:\s*([\w-]+)", content)
        if project_match:
            return project_match.group(1)

        # 尋找 "Build attempt x/y for 'xxx'" 的模式作為備選
        build_match = re.search(r"Build attempt \d+/\d+ for '([\w-]+)'", content)
        if build_match:
            return build_match.group(1)

        return None

    def _analyze_build_attempts(self, content: str, project_name: str):
        """分析build attempts和成功率"""
        # 將log內容按行分割，並加上行號方便追蹤
        lines = content.split("\n")

        # 找到所有 Build attempt 的記錄，包含行號
        build_attempts = []
        success_lines = []
        compilation_error_lines = []
        sanitizer_error_lines = []

        for i, line in enumerate(lines, 1):
            # 檢查 Build attempt
            build_match = re.search(r"Build attempt (\d+)/(\d+) for '([\w-]+)'", line)
            if build_match and build_match.group(3) == project_name:
                attempt_num = int(build_match.group(1))
                max_attempts = int(build_match.group(2))
                build_attempts.append(
                    {
                        "line_num": i,
                        "attempt_num": attempt_num,
                        "max_attempts": max_attempts,
                        "timestamp": self._extract_timestamp(line),
                    }
                )

            # 檢查 Build succeeded
            if "Build succeeded:" in line:
                success_lines.append({"line_num": i, "timestamp": self._extract_timestamp(line)})

            # 檢查編譯錯誤 (包含 "Compilation failed: error:")
            if "Compilation failed: error:" in line:
                compilation_error_lines.append({"line_num": i, "timestamp": self._extract_timestamp(line)})

            # 檢查消毒器錯誤 (包含 "SUMMARY: " 且包含消毒器名稱)
            if "SUMMARY: " in line and (
                "AddressSanitizer:" in line
                or "MemorySanitizer:" in line
                or "ThreadSanitizer:" in line
                or "UndefinedBehaviorSanitizer:" in line
            ):
                sanitizer_error_lines.append({"line_num": i, "timestamp": self._extract_timestamp(line)})

        if not build_attempts:
            return

        # 重新組織build sequences
        sequences = []
        current_sequence = []

        for attempt in build_attempts:
            # 如果是第一次嘗試，或者與上一次嘗試時間差很大，開始新的sequence
            if attempt["attempt_num"] == 1:
                if current_sequence:
                    sequences.append(current_sequence)
                current_sequence = [attempt]
            else:
                current_sequence.append(attempt)

        # 加入最後一個sequence
        if current_sequence:
            sequences.append(current_sequence)

        # 計算這個log檔案的統計資料
        file_stats = {
            "total_attempts": 0,
            "successful_builds": 0,
            "first_attempt_success": 0,
            "build_sequences": [],
        }

        for seq_idx, sequence in enumerate(sequences):
            sequence_attempts = len(sequence)
            file_stats["total_attempts"] += sequence_attempts

            # 檢查這個sequence是否成功
            # 找到sequence範圍內的所有錯誤
            sequence_start_line = sequence[0]["line_num"]
            last_attempt_line = sequence[-1]["line_num"]
            sequence_succeeded = False
            has_compilation_error = False
            has_sanitizer_error = False

            # 確定下一個sequence的開始位置（如果有的話）
            next_sequence_start = None
            if seq_idx + 1 < len(sequences):
                next_sequence_start = sequences[seq_idx + 1][0]["line_num"]

            # 在這個sequence的最後一次嘗試之後尋找成功記錄
            for success in success_lines:
                if success["line_num"] > last_attempt_line:
                    if next_sequence_start is None or success["line_num"] < next_sequence_start:
                        sequence_succeeded = True
                        break

            # 如果沒有成功，檢查sequence範圍內的錯誤
            if not sequence_succeeded:
                # 檢查sequence範圍內的編譯錯誤
                for comp_error in compilation_error_lines:
                    if comp_error["line_num"] > sequence_start_line and (
                        next_sequence_start is None or comp_error["line_num"] < next_sequence_start
                    ):
                        has_compilation_error = True
                        break

                # 檢查sequence範圍內的消毒器錯誤（只有在沒有編譯錯誤的情況下）
                if not has_compilation_error:
                    for san_error in sanitizer_error_lines:
                        if san_error["line_num"] > sequence_start_line and (
                            next_sequence_start is None or san_error["line_num"] < next_sequence_start
                        ):
                            has_sanitizer_error = True
                            break

            # 記錄sequence結果
            sequence_info = {
                "attempts": sequence_attempts,
                "succeeded": sequence_succeeded,
                "first_attempt_success": sequence_succeeded and sequence_attempts == 1,
                "compilation_error": has_compilation_error,
                "sanitizer_error": has_sanitizer_error,
            }

            file_stats["build_sequences"].append(sequence_info)

            if sequence_succeeded:
                file_stats["successful_builds"] += 1
                if sequence_attempts == 1:
                    file_stats["first_attempt_success"] += 1

        # 將這個檔案的統計資料加入到專案總統計中
        stats = self.project_stats[project_name]
        stats["total_attempts"] += file_stats["total_attempts"]
        stats["successful_builds"] += file_stats["successful_builds"]
        stats["first_attempt_success"] += file_stats["first_attempt_success"]
        stats["total_compilation_error_records"] += len(compilation_error_lines)
        stats["total_sanitizer_error_records"] += len(sanitizer_error_lines)
        stats["build_sequences"].extend(file_stats["build_sequences"])

        # Debug information
        print(f"  - 找到 {len(sequences)} 個build sequences")
        print(f"  - 檢測到 {len(compilation_error_lines)} 個編譯錯誤記錄")
        print(f"  - 檢測到 {len(sanitizer_error_lines)} 個消毒器錯誤記錄")

        # Debug: 顯示sequence和錯誤的行號
        for i, seq in enumerate(sequences):
            seq_start = seq[0]["line_num"]
            seq_end = seq[-1]["line_num"]
            print(f"  - Sequence {i+1}: 行號 {seq_start}-{seq_end}")

        print(f"  - 編譯錯誤行號: {[err['line_num'] for err in compilation_error_lines]}")
        print(f"  - 消毒器錯誤行號: {[err['line_num'] for err in sanitizer_error_lines]}")

        print(f"  - 本檔案總計 {file_stats['total_attempts']} 次嘗試")
        print(f"  - 本檔案 {file_stats['successful_builds']} 次成功")
        for i, seq_info in enumerate(file_stats["build_sequences"]):
            status = "成功" if seq_info["succeeded"] else "失敗"
            error_info = ""
            if seq_info["compilation_error"]:
                error_info += " (編譯錯誤)"
            if seq_info["sanitizer_error"]:
                error_info += " (消毒器錯誤)"
            print(f"    Sequence {i+1}: {seq_info['attempts']} 次嘗試 - {status}{error_info}")

    def _extract_timestamp(self, line: str) -> str:
        """從log行中提取時間戳"""
        timestamp_match = re.search(r"(\d{2}:\d{2}:\d{2})", line)
        return timestamp_match.group(1) if timestamp_match else ""

    def _display_results(self):
        """顯示分析結果"""
        if not self.project_stats:
            print("沒有找到任何項目統計資料")
            return

        print("\n" + "=" * 60)
        print("LOG 分析結果")
        print("=" * 60)

        for project_name, stats in self.project_stats.items():
            total_attempts = stats["total_attempts"]
            successful_builds = stats["successful_builds"]
            first_attempt_success = stats["first_attempt_success"]
            total_compilation_error_records = stats["total_compilation_error_records"]
            total_sanitizer_error_records = stats["total_sanitizer_error_records"]
            build_sequences = stats["build_sequences"]

            if total_attempts == 0:
                continue

            total_sequences = len(build_sequences)

            # 計算成功率
            success_rate = (successful_builds / total_sequences) * 100 if total_sequences else 0
            first_attempt_rate = (first_attempt_success / total_sequences) * 100 if total_sequences else 0

            # 計算平均嘗試次數
            total_sequence_attempts = sum(seq["attempts"] for seq in build_sequences)
            avg_attempts = total_sequence_attempts / total_sequences if total_sequences else 0

            print(f"\n專案名稱: {project_name}")
            print(f"總編譯sequence數量: {total_sequences}")
            print(f"總嘗試編譯次數: {total_attempts}")
            print(f"編譯一次即成功的次數: {first_attempt_success}/{total_sequences} ({first_attempt_rate:.2f}%)")
            print(f"編譯成功率: {successful_builds}/{total_sequences} ({success_rate:.2f}%)")
            print(f"平均編譯嘗試次數: {total_sequence_attempts}/{total_sequences} ({avg_attempts:.2f})")
            print(f"總編譯錯誤記錄數: {total_compilation_error_records}")
            print(f"總消毒器錯誤記錄數: {total_sanitizer_error_records}")
            print("-" * 40)


def main():
    if len(sys.argv) != 2:
        print("使用方法: python log_analyzer_fixed.py <log_directory_path>")
        sys.exit(1)

    log_directory = sys.argv[1]
    analyzer = LogAnalyzer(log_directory)
    analyzer.analyze_logs()


if __name__ == "__main__":
    main()
