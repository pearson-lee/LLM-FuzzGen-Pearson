# Crash Analyzer 資料收集規則

目的：建立一個小型 labeled validation set，用來校正 Crash Analyzer 的 Evidence Rubric threshold。這份資料集不是拿來訓練模型，也不是要證明每個 crash 都能在本機重現；重點是讓 TP / FP / Ambiguous 的分數分布可被人工檢查。

---

## 1. 收集規模

時間有限時，不需要每個 project 各 20 個。先從多個 project 混合收集，總數達到 20 個 labeled cases 即可。

建議配置：

| 類型 | 數量 | 說明 |
|---|---:|---|
| TP / Real Crash | 5-7 | 已確認 library bug |
| FP / Fuzzer Logic Error | 5-7 | fuzz target API misuse |
| Ambiguous / Confusing | 4-6 | assertion、timeout、API contract 不清楚、library frame 但可能是 misuse |

最低可接受 sanity check：12 個 cases（TP 4 / FP 4 / Ambiguous 4）。但 12 個只能做初步檢查，20 個才比較適合作為論文方法驗證的最低門檻。

Project 不必平均分布，但不要全部來自同一個 project。建議至少涵蓋 3 個 project。

---

## 2. 受測 Project 範圍

目前沿用上一屆實驗對象：

| Project | Version / Commit | 備註 |
|---|---|---|
| tomlplusplus | `708fff7` | 小型 C++ project，TP 可能較難找 |
| lcms | `2.15` | 適合找 historical TP |
| zlib | `1.3` | 適合找 historical TP |
| libtiff | `4.7` | TP 優先來源 |
| tinyxml2 | `e6caeae` | 小型 C++ project，TP 可能較少 |
| cjson | `1.7.18` | 可找 TP，也適合找 FP |
| libvpx | `1.14` | TP 優先來源 |
| libpcap | `1.10.4` | 適合找 FP / Ambiguous |

本機 OSS-Fuzz project slug：

```text
tomlplusplus
lcms
zlib
libtiff
tinyxml2
cjson
libvpx
libpcap
```

---

## 3. 版本相符規則

用於 rubric calibration 的 TP 不要求和本機版本完全相符。

可接受：

```text
project 相同
issue 狀態為 Fixed / Verified
有完整 stack trace
top non-runtime frame 在 library source
人工判斷不是明顯 fuzz target misuse
```

不需要：

```text
本機 reproduce 成功
seed 對上目前 checkout 的 exact commit
本機版本和 OSS-Fuzz issue revision 完全一致
```

但標記時要分清楚用途：

| 等級 | version_matched | reproduced_locally | 用途 |
|---|---|---|---|
| Level 1 | `false` / `unknown` | `false` / `unknown` | rubric calibration only |
| Level 2 | `true` | `true` | end-to-end reproduction / patch validation |

目前優先收 Level 1。不要為了追 exact revision 卡住資料集建立。

底線：project 必須相符。不要把其他 library 的 crash 混進本 project。

---

## 4. TP 收集規則

TP 來源優先使用 OSS-Fuzz 已確認 issue。

優先 project：

```text
第一優先：libtiff, libvpx, zlib, lcms
第二優先：cjson, libpcap
第三優先：tinyxml2, tomlplusplus
```

TP 判定條件：

```text
Status = Fixed / Verified
sanitizer = AddressSanitizer / MemorySanitizer / UndefinedBehaviorSanitizer
top non-runtime frame 在 library source
issue 看起來不是 fuzz target API misuse
最好有 fix commit、verified fixed、或 maintainer 接受
```

不要優先當 TP 的案例：

```text
timeout
OOM
assertion only
top frame 在 fuzz target
API contract 不清楚
issue 本身疑似 harness misuse
```

這些可以先放 Ambiguous 候選。

搜尋方式：

```text
site:issues.oss-fuzz.com/issues libtiff "Fixed" "ERROR: AddressSanitizer"
site:issues.oss-fuzz.com/issues libvpx "Fixed" "ERROR: AddressSanitizer"
site:issues.oss-fuzz.com/issues zlib "Fixed" "ERROR: AddressSanitizer"
site:issues.oss-fuzz.com/issues lcms "Fixed" "ERROR: AddressSanitizer"
```

放寬搜尋：

```text
site:issues.oss-fuzz.com/issues libtiff "heap-buffer-overflow"
site:issues.oss-fuzz.com/issues libvpx "use-after-free"
site:issues.oss-fuzz.com/issues zlib "stack-buffer-overflow"
site:issues.oss-fuzz.com/issues lcms "MemorySanitizer"
```

舊 tracker 可作備援：

```text
site:bugs.chromium.org/p/oss-fuzz/issues/detail libtiff "Fixed" "AddressSanitizer"
```

TP 最小批次：

```text
libtiff 2
libvpx  2
zlib/lcms/cjson/libpcap 中挑 2
合計 6
```

---

## 5. FP 收集規則

FP 優先從本系統 LLM-FuzzGen 產生的 crash analyzer output 收。

候選來源：

```text
crash_analyzer/crashes/<project>/<fuzzer>/heuristic_triage.json
```

優先挑：

```json
"frame_classification": "fuzz_target"
```

常見 FP pattern：

| Pattern | 例子 |
|---|---|
| NULL 傳給不接受 NULL 的 API | `pcap_dump(NULL, &hdr, data)` |
| 跳過 required setup / teardown | `pcap_loop(p, ...)` 前沒有 `pcap_activate()` |
| use-after-free in harness | `cJSON_Delete(root); cJSON_Print(root)` |
| out-of-range 參數 | `cJSON_PrintBuffered(obj, -100, 0)` |
| 未初始化 struct | `struct bpf_program prog; bpf_filter(prog.bf_insns, ...)` |
| ownership 錯誤 | double free / wrong owner frees object |

注意：`frame_classification == "fuzz_target"` 只是 FP 候選，不是自動 label。仍需人工看 fuzz target crash 行和 API contract。

---

## 6. Ambiguous 收集規則

Ambiguous 要刻意收容易混淆的案例，避免 threshold 過度樂觀。

優先類型：

```text
assertion failure
timeout
NULL deref in library，但 fuzz target 可能傳了非法 NULL
crash 在 library，但 API precondition 不清楚
需要特定 init / teardown 順序的 API
normal caller feasibility 找不到
```

Ambiguous label_reason 必須寫清楚缺什麼證據，例如：

```text
crash occurs in library frame, but API header does not clarify whether NULL is valid; no normal caller found
```

---

## 7. 每筆資料要記錄的欄位

建議用 JSONL。每行一個 case。

必要欄位：

```json
{
  "case_id": "libtiff_tp_001",
  "project": "libtiff",
  "label": "TP",
  "label_reason": "OSS-Fuzz fixed issue; top non-runtime frame is in libtiff source; no obvious fuzz target API misuse.",
  "source": "oss-fuzz-issue",
  "issue_url": "https://issues.oss-fuzz.com/issues/...",
  "issue_status": "Fixed",
  "sanitizer": "AddressSanitizer heap-buffer-overflow",
  "crash_function": "function_name",
  "top_library_frame": "/src/libtiff/...",
  "fuzz_target_name": "target_name",
  "version_matched": "unknown",
  "reproduced_locally": "unknown",
  "used_for": "rubric_calibration_only",
  "analysis_json": "",
  "heuristic_json": "",
  "report_md": "",
  "notes": ""
}
```

對本機 Crash Analyzer output 的 case，補上：

```json
{
  "analysis_json": "crash_analyzer/crashes/<project>/<fuzzer>/analysis.json",
  "heuristic_json": "crash_analyzer/crashes/<project>/<fuzzer>/heuristic_triage.json",
  "report_md": "crash_analyzer/crashes/<project>/<fuzzer>/report.md"
}
```

---

## 8. 校正方式

收完後，不要先改 prompt。先統計 label 對 rubric total 的分布。

目前初始 threshold：

```text
0-2 → FP strong
3   → FP lean
4   → Ambiguous
5   → TP lean
6-8 → TP strong
```

檢查項目：

```text
TP 是否大多落在 5-8
FP 是否大多落在 0-3
Ambiguous 是否集中在 3-5
誤判時是哪個 criterion 拉錯分數
api_contract 是否太常被打成 1 而不是 0
normal_caller_feasibility 是否太容易被猜成 2
```

若 TP 很多低於 5，或 FP 很多高於 3，不要立刻只改 total threshold。先看是哪一欄 evidence/rubric 定義失真，再決定是否：

```text
調 threshold
改 prompt evidence 要求
加 rule，例如 api_contract=0 且 normal_caller_feasibility<=1 時不得直接判 TP
```

