# Crash Analyzer：TP/FP 分類系統設計文件

## 1. 問題定義

LLM-FuzzGen 以 LLM 生成 fuzz target，再由 libFuzzer 執行。執行過程中產生的 crash 有兩類性質完全不同的來源：

| 類型 | 來源 | 處理方式 |
|------|------|----------|
| **True Positive (TP)** | Library 自身的 bug（記憶體安全問題、邊界錯誤等） | 值得回報，是 fuzzing 的目標成果 |
| **False Positive (FP)** | Fuzz target 錯誤使用 API（NULL 誤傳、漏掉初始化、違反 API precondition）| 是 harness 的問題，不是 library 的 bug |

如果把 FP 當 TP 回報，會浪費時間甚至誤導研究結論；反過來把 TP 漏掉，則無法展示 fuzzer 的發現能力。

---

## 2. 原有系統的缺陷

### 缺陷 1：Heuristic 誤判

舊版 `_heuristic_triage()` 用以下條件判斷 crash site：

```python
if f"/out/{fuzzer_binary_name}" in trace:   # ← 有問題
    crash_site = "fuzzer"
    confidence = 0.8
```

**問題**：OSS-Fuzz 的編譯產物放在 `/out/<target>`，library code 被 link 進同一個 binary 後，ASAN 輸出的每行（binary path 欄位）都可能出現 `/out/` 字串。這個字串比對會把 **stack frame 明確在 `/src/` library 的 crash** 誤判成 FP，confidence 高達 0.8。

### 缺陷 2：LLM 單次無結構判斷

原有 prompt 只問 LLM「這是 Real Crash 還是 Fuzzer Logic Error？」，沒有強制要求：
- 引用具體的 stack frame source path
- 查驗 API precondition
- 確認正常 caller 是否可能走到同一路徑

同一份 crash 資料，不同次呼叫可能用不同標準判斷，結果不穩定。

---

## 3. 改後系統架構

```
_process_crash(crash_path)
  │
  ├─ oss_fuzz.reproduce_crash()
  │    └─ 取得 ASAN stack trace
  │
  ├─ _heuristic_triage(fuzzer_binary_name, stack_trace, source_file)
  │    ├─ _parse_stack_frames()  ← 解析每個 frame 的 source path
  │    │    分類：fuzz_target / library / runtime / unknown
  │    └─ 根據 top non-runtime frame 決定 crash_site
  │         → CrashHeuristicTriage（含 frame_classification）
  │
  ├─ _get_llm_analysis()
  │    ├─ [Pass 1] crash_analysis_template（含 Evidence Rubric）
  │    │    → LLM 填寫 5 維 rubric + 輸出 JSON
  │    │
  │    └─ _needs_audit() 判斷是否需要第二次 LLM call
  │         觸發條件：confidence < 0.75 | Ambiguous | heuristic ↔ LLM 衝突
  │         └─ [Pass 2] crash_audit_template（Evidence Audit）
  │               → LLM 回答具體程式證據問題
  │               → Blending：confidence 差 > 0.15 才採用修訂結論
  │
  └─ _save_artifacts()
       crashes/<project>/<fuzzer>/
         ├─ report.md          （Markdown 報表，含 Rubric 表格）
         ├─ analysis.json      （完整 LLM 輸出，含 rubric_scores、evidence_audit）
         ├─ heuristic_triage.json （含 frame_classification）
         ├─ stack_trace
         ├─ <fuzzer>.cc
         └─ crash-<hash>
```

---

## 4. 核心機制說明

### 4.1 Frame-Level Crash Site Detection

**`_parse_stack_frames(stack_trace, fuzz_target_filename)`**

OSS-Fuzz/ASAN 的 stack frame 格式：
```
    #N 0xADDR in FUNCTION_NAME /path/to/source.c:LINE:COL
```

解析邏輯：
1. Regex 抽取每個 frame 的 `function_name` 和 `source_path`
2. 跳過 runtime frames（`__asan_*`、`__sanitizer_*`、`fuzzer::` 等，或 source 在 `/usr/`）
3. 取第一個 non-runtime frame，比對 source path：

| source_path | 分類 |
|-------------|------|
| basename 等於 fuzz target 檔名（例如 `llm_fuzzgen1234.cc`）| `fuzz_target` |
| 路徑包含 `/src/` | `library` |
| 其他 | `unknown` |

**FP 強訊號**：`frame_classification == "fuzz_target"`（crash 直接在生成的 fuzz target source 裡）
**TP 強訊號**：`frame_classification == "library"`（crash 在 library source code 裡）

### 4.2 Evidence Rubric（5 維評分）

LLM 在下最終結論之前，必須先填寫一張 5 格的評分表。每格除了分數外，**必須附具體的引文或 source location**，無 evidence 的分數上限為 1。

| Criterion | 滿分 | 說明 |
|-----------|------|------|
| `top_frame_ownership` | 2 | Top frame 在 fuzz target（0）/ 不確定（1）/ library（2） |
| `api_contract` | 2 | Fuzz target 明確違反 API precondition（0）/ 不確定（1）/ 正確使用（2） |
| `normal_caller_feasibility` | 2 | 正常 caller 不可能走到（0）/ 不確定（1）/ 可能走到（2） |
| `sanitizer_signal` | 1 | Assertion/timeout（0）/ Memory-safety 違規（1） |
| `reproducibility` | 1 | 未驗證（0）/ 穩定重現（1） |

**總分 0–8 對應判斷（初始 threshold，需 label 後校正）：**

```
0–2 → Fuzzer Logic Error（FP，強訊號）
  3 → Fuzzer Logic Error（FP，偏向）
  4 → Ambiguous
  5 → Real Crash（TP，偏向）
6–8 → Real Crash（TP，強訊號）
```

> Rubric 是輔助決策工具，不是 oracle。若分數與 evidence 明顯矛盾，以 evidence 為準並在 `reasoning_summary` 說明原因。

### 4.3 Evidence Audit Pass（第二次 LLM call）

**觸發條件（`_needs_audit()`）：**
- `confidence < 0.75`
- `finding == "Ambiguous"`
- Heuristic `frame_classification` 與 LLM `finding` 衝突
  - `frame_classification == "fuzz_target"` 但 LLM 說 `Real Crash`
  - `frame_classification == "library"` 但 LLM 說 `Fuzzer Logic Error`

**Audit 問的問題（依 finding 不同）：**

| Finding | 問題 |
|---------|------|
| `Fuzzer Logic Error` | Q1: Fuzz target 哪行建構了 invalid state？<br>Q2: API header/doc 是否明確禁止這種用法？ |
| `Real Crash` | Q3: /src/ 裡有沒有能走到同樣 crash path 的 caller？<br>Q4: 一個正確寫法的 fuzz target 能否也觸發這個 crash？ |
| `Ambiguous` | Q5: 什麼關鍵證據能解決這個 ambiguity？ |

**Blending 規則：**
- `revised_confidence > initial_confidence + 0.15` → 採用修訂結論
- 否則保留原始結論，`confidence` 降低 0.05，保留 audit 結果供人工審查

---

## 5. 輸出格式

### analysis.json（新增欄位）

```json
{
  "finding": "Real Crash | Fuzzer Logic Error | Ambiguous",
  "confidence": 0.0,
  "rubric_scores": {
    "top_frame_ownership":       {"score": 2, "evidence": "#1 0x... in cjson_parse /src/cjson/cJSON.c:312"},
    "api_contract":              {"score": 2, "evidence": "fuzz target calls cJSON_Parse() with valid null-terminated string"},
    "normal_caller_feasibility": {"score": 1, "evidence": "no normal caller found in /src/ for this path"},
    "sanitizer_signal":          {"score": 1, "evidence": "heap-buffer-overflow on address 0x..."},
    "reproducibility":           {"score": 0, "evidence": "not yet verified"},
    "total": 6
  },
  "missing_evidence": ["API header for cJSON_PrintBuffered negative prebuffer behavior not accessible"],
  "evidence_audit": {
    "audit_answers": {"Q3": "...", "Q4": "..."},
    "revised_finding": "Real Crash",
    "revised_confidence": 0.82,
    "revision_rationale": "..."
  }
}
```

### heuristic_triage.json（新增欄位）

```json
{
  "frame_classification": "library",
  "top_app_frame_source": "/src/cjson/cJSON.c:312",
  "top_app_frame_function": "cjson_parse"
}
```

### report.md（新增區塊）

```markdown
## Evidence Rubric
| Criterion | Score | Evidence |
|-----------|------:|---------|
| Top Frame Ownership (0–2) | 2 | #1 in cjson_parse /src/cjson/cJSON.c:312 |
...

## Evidence Audit
- Revised Finding: **Real Crash** (confidence: 0.82)
- Rationale: ...

## Missing Evidence
- API header for cJSON_PrintBuffered negative prebuffer behavior
```

---

## 6. 修改的檔案

| 檔案 | 修改內容 |
|------|----------|
| `crash_analyzer/crash_analyzer.py` | 新增 `_parse_stack_frames()`、`_run_evidence_audit()`、`_needs_audit()`；修改 `_heuristic_triage()`、`_get_llm_analysis()`、`_validate_analysis_schema()`、`_render_markdown_report()`、`_save_artifacts()` |
| `prompts/templates/crash_analysis_template` | 加入 5 維 Evidence Rubric，強制 evidence 引文 |
| `prompts/templates/crash_audit_template` | 新建，定義 Evidence Audit 問題 |
| `prompts/prompt_generator.py` | 新增 `crash_audit_prompt()` |

---

## 7. 人工標記資料集（Day 3 前置條件）

Evidence Rubric 的 threshold（0–8）是基於 domain knowledge 的初始假設，需有人工標記的 validation set 才能校正。

### 目標規模

至少 **20 個案例**才能計算 precision/recall：
- TP（Real Crash）：5–7 個
- FP（Fuzzer Logic Error）：5–7 個
- Ambiguous / confusing：4–6 個（含 assertion、NULL-deref、API misuse 導致 library crash）

### TP 資料來源

**OSS-Fuzz 公開 issue tracker**：`bugs.chromium.org/p/oss-fuzz/issues/list`

搜尋條件（針對本專案使用的 project）：
```
status:Fixed proj:cjson
status:Fixed proj:libpcap
status:Fixed proj:libtiff
status:Fixed proj:libvpx
```

標記步驟：
1. 從 issue description 複製完整的 ASAN stack trace
2. 在 OSS-Fuzz GitHub 找對應的 fuzz target `.cc` 檔（`google/oss-fuzz/projects/<project>/`）
3. 標記 `label = TP`，附 stack trace + fuzz target source

> **注意**：reproducer seed 跟特定版本綁定，不需要重跑。只需要 stack trace + fuzz target source 就能做標記。

### FP 資料來源

**改完 heuristic 後的自動候選**：

跑完之後，`heuristic_triage.json` 中 `frame_classification == "fuzz_target"` 的案例是 FP 候選。讀對應 fuzz target source 的 crash 那行，確認是否 API misuse → 標 FP。

常見 FP pattern（可直接掃 `external/oss-fuzz/projects/<project>/*.cc`）：

| Pattern | 範例 |
|---------|------|
| 傳 NULL 給不接受 NULL 的參數 | `pcap_dump(NULL, &hdr, data)` |
| 跳過 required setup/teardown | `pcap_loop(p, ...)` 沒先 `pcap_activate()` |
| 使用已 free 的物件 | `cJSON_Delete(root); cJSON_Print(root)` |
| 傳負數給 buffer size | `cJSON_PrintBuffered(obj, -100, 0)` |
| 未初始化 struct 直接傳入 | `struct bpf_program prog; bpf_filter(prog.bf_insns, ...)` |

### Rubric 校正方式

1. 對 20 個 label 案例各算 rubric total score
2. 畫出 TP vs FP 的分數分布
3. 若 TP 案例有很多低於 5 分，或 FP 案例有很多高於 3 分 → 調整 threshold
4. 調整 threshold，不調整 criteria 本身

---

## 8. 相關文獻

| 論文 | 連結 | 相關性 |
|------|------|--------|
| G-Eval (Liu et al., 2023) | https://arxiv.org/abs/2303.16634 | Rubric form-filling 比開放式評分更穩定 |
| MT-Bench / LLM-as-judge (Zheng et al., 2023) | https://arxiv.org/abs/2306.05685 | LLM judge 接近人類偏好，但有 self-enhancement bias |
| Prometheus (Kim et al., 2023) | https://arxiv.org/abs/2310.08491 | Rubric + reference material 是有效 judge 關鍵 |
| FalseCrashReducer (2025) | https://arxiv.org/abs/2510.02185 | **最直接相關**：constraint-based driver generation + context-based crash validation for OSS-Fuzz-Gen FP |
| OSS-Fuzz reproducing | https://google.github.io/oss-fuzz/advanced-topics/reproducing/ | Reproducer seed 與版本對應方式 |
