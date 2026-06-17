# TODO
問題：第一次確實建立出種子後未手動刪除corpus，第二次跑run all fuzzer卻出現同個blocker之問題
## Fix 1 ✅ 已完成：`get_line_execution_count` 加入 `source_file` 過濾

**問題**：`project.linecovreport` 使用 file-path sections（如 `/src/libpcap/optimize.c:`），同一行號（如 2021）可能跨多個 source file 出現，global fallback 永遠回傳第一個 entry，導致已解決的 blocker 被誤判為「未覆蓋」而重複嘗試。

**修法**：在 `get_line_execution_count` 加 `source_file` 可選參數，function-name lookup miss 後，先以 suffix 匹配找到正確的 file section 再查 line_no，避開跨 file 行號衝突。C++ template instantiation 情況下，取任意非零 count。

**已修改的檔案**：
- `blocker_process/coverage_utils.py`：新增 `_count_is_positive`、三個查找函式加 `source_file` 參數
- `main.py`：474, 481, 513, 516, 569, 572 六處 call site
- `blocker_process/global_blocker_selector.py`：531, 536 兩處
- `tools/export_real_blockers.py`：134, 137, 165, 168 四處
- `test_coverage_utils.py`：新增 3 個 regression test

---

## Fix 2 ⏳ 未實作：持久化 `solved_blockers.json`

Fix 1 的跨 run 防線。即使 linecov report 重建，solved 狀態仍能被記住。

- **Identity**：`(source_file, function_name, branch_line, blocked_side_line)`
- **儲存位置**：`artifacts/solved_blockers/{project_name}.json`
- **寫入時機**：`run_blocker_pipeline` 成功後（`main.py` 附近）
- **過濾時機**：`_filter_and_refine_project_blockers`（`main.py:462`）讀取並跳過已解決的 blocker

---

## Fix 3 ⏳ 未實作：`_live_revalidate_blocker_before_classify` 橫跨 contributing targets

Fix 1 的第二道防線。當前只用 `best_target` 的 corpus 做 live revalidation（`main.py:64`），若 `best_target` 跨 run 改變，舊的 solved corpus 會被忽略。改為橫跨所有 `contributing_targets` 的 corpus 搜尋。

優先級低——Fix 1 修好後，blocker 應在 `_filter_and_refine_project_blockers` 就被過濾，正常情況不會走到 live revalidation。

---

## ✅ 已確認不需修改：其他 call sites 的 report 類型

下列 call sites 已調查確認為 **single-file report**，不受跨 file 行號衝突影響，無需加 `source_file`：

| 檔案 | 行號 | Report 來源 | 說明 |
|---|---|---|---|
| `blocker_process/blocker_classifier.py` | 833 | `oss_fuzz.linecov_reports(fun_name_regex=...)` | `llvm-cov show` 加了 `--name-regex`，只輸出該函式的 coverage，無跨 file |
| `blocker_process/find_blocker_seeds_by_coverage.py` | 234, 247, 412, 423 | `render_linecov_report_in_ossfuzz(source_file=...)` | `llvm-cov show` 明確指定單一 source file，不含其他 file sections |

---

---

# Blocker 選取品質改善：加入 solvability_score

## 問題背景（0605 run 案例）

三個 blocker 浪費了共 **~113 分鐘** pipeline 資源：

| Blocker | LLM 分類 | 根因 |
|---------|---------|------|
| `compute_local_ud:641→646` | Input Dependent（**誤判**）| blocked side 是 `abort()`，結構上不可達 |
| `pcap_parse:2056→2057` | Input Dependent | bison auto-generated skeleton state（yyerrstatus），seed 無法到達 branch |
| `convert_code_r:2715→2716` | Input Independent（正確）| calloc OOM，solver 無法解 |

**根本原因**：`global_blocker_selector.py` 目前只算 `actionability_score + impact_score`，完全沒有 solvability 估算。

---

## 採用模型

```
score = (actionability_score + impact_score) × solvability_score
```

**乘法設計原則**（Codex 驗證）：`solvability_score` 必須是「倍率」（乘入 score），不能是排序 tuple 的獨立維度。

```python
# ❌ 錯誤：solvability 變成 bucket filter
key=lambda b: (state_priority, b.get("solvability_score"), b.get("actionability_score"), ...)

# ✅ 正確：solvability 已乘入 score，用 score 排序
key=lambda b: (state_priority, b.get("score"), b.get("actionability_score"), ...)
```

若寫成錯誤形式：所有 solvability=1.0 的 blocker 一定排在任何 terminal blocker 前面，哪怕 terminal blocker 的 impact 是 10000。

---

## 跨專案資料驗證（9 個 OSS-Fuzz 專案）

| 訊號 | 命中數 | Precision | 結論 |
|------|--------|----------|------|
| `abort`/`exit` 等終止函式（blocked_unique_functions）| 64 hits（libpcap + freetype2）| 高 | ✅ 可靠，但覆蓋率低（約 0.1%）|
| `blocked_unique_not_covered_complexity = 0` | 32,037+ | 極低（正常原始碼也有）| ❌ 不能單獨使用 |
| `*.tab.c`/`lex.yy.c` 副檔名 | 0 | N/A | ❌ 現有專案中不存在 |
| `build/grammar.c` 路徑 | 2（libpcap only）| 低（其他專案誤判）| ❌ 不夠泛用 |

**結論**：純 metadata 只有「終止函式」訊號可靠。真正泛用的可解性判斷需要 source code snippet（Phase 2）。

---

## Phase 1：立即實作（Terminal Function Signal）

**修改檔案**：`blocker_process/global_blocker_selector.py`

### 新增常數與評分函式

```python
_TERMINAL_FUNCTIONS: frozenset[str] = frozenset({
    "abort", "_abort", "exit", "_exit", "_Exit", "quick_exit",
    "__assert_fail", "__assert_rtn",
    "__builtin_trap", "__builtin_unreachable",
    "std::terminate", "std::abort",
    "g_assertion_message_expr", "g_assertion_message",  # GLib
    "rust_begin_unwind",                                 # Rust FFI
})
```

**注意**：`xmalloc`/`xcalloc`/`g_malloc` 等 OOM 包裝器不加入——它們的 abort 在函式內部，呼叫者的 blocked_unique_functions 看不到（已驗證）。

```python
def _compute_static_solvability(blocker: Dict[str, Any]) -> tuple[float, str]:
    blocked_funcs = blocker.get("blocked_unique_functions", [])
    if any(f in _TERMINAL_FUNCTIONS for f in blocked_funcs):
        return 0.15, "terminal_function"
    return 1.0, "normal"
```

### 套用到兩處評分迴圈

在 `aggregate_score_and_revalidate_blockers()` inline 評分迴圈（line 683 前後，目前是 `enriched["score"] = actionability_score + impact_score`）：

```python
static_solv, static_reason = _compute_static_solvability(enriched)
enriched["solvability_score"] = round(static_solv, 4)
enriched["solvability_reason"] = static_reason
enriched["score_components"]["solvability_score"] = round(static_solv, 4)
enriched["score"] = (actionability_score + impact_score) * static_solv  # 取代原有純加法
```

在 `aggregate_and_score_blockers()` 的評分迴圈（line 385 前後，目前是 `gb["score"] = actionability_score + impact_score`）也加入相同邏輯。

### 排序鍵更新（兩處）—— 關鍵：用 score 而非 solvability_score

```python
# aggregate_score_and_revalidate_blockers (line 695)
scored.sort(
    key=lambda b: (
        state_priority.get(str(b.get("project_blocker_state")), -1),
        b.get("score", 0.0),                               # ← (actionability + impact) × solvability
        b.get("actionability_score", 0.0),
        b.get("impact_score", 0.0),
        b.get("project_branch_hit_count", 0),
        b.get("globally_unhit_function_count", 0),
        b.get("sum_blocked_function_undiscovered_complexity", 0),
    ),
    reverse=True,
)
# aggregate_and_score_blockers (line 388) 同樣修改
```

---

## Phase 2：Conservative Source-Level Penalty

### 速度影響評估

| 指標 | 數值 |
|------|------|
| Selector 目前執行時間 | 8–47 秒（通常 15–35 秒），376–498 blockers |
| 每個 LLM+pipeline 時間 | 1740–2651 秒（29–44 分鐘）|
| 0605 run 浪費總時間 | ~113 分鐘 |
| Phase 2 新增開銷 | top 20 候選 × 2 snippet fetch × 300ms ≈ **+4–12 秒** |
| **結論** | 完全可接受；節省一個錯誤 blocker = 節省 30+ 分鐘 |

### Snippet 取得策略

- Phase 1 scoring 完成後，只取 **top-K×2（最多 30）個候選**（bounded）
- 每個 source file 只讀一次（range fetch），存入 `file_cache`，後續取值直接切片
- 取 `branch_line_text`（branch 那一行本身）與 `branch_snippet`（±3 行）；不取 blocked side snippet
- 先嘗試直接讀本地檔案，不可用才呼叫 Introspector API
- 若取不到：graceful fallback，維持 Phase 1 的 solvability

### Phase 2 保守原則（Codex 驗證）

以下訊號**太鬆、有誤判風險**，不能直接降分：

| 訊號 | 問題 |
|------|------|
| `yychar` 單獨出現 | bison 的 user semantic action 也會引用 `yychar` |
| `!ptr` 不含變數關聯 | 任何 null check 都觸發，大量誤判 |
| `"not enough"` 單獨出現 | 可能是格式錯誤訊息，非 OOM |
| `ASSERT(x)` 一般形式 | assertion 條件本身可能是 fuzzer 值得觸發的 bug surface |

### 兩個保留的高 Precision 模式

> P3（blocked side 直接 abort/exit）已移除：`blocked_side_line` 是 else 側入口點，abort() 可能隔很多行或在巢狀 if 裡，固定 radius 在不同專案格式下不可靠。Phase 1 的 `blocked_unique_functions` 已覆蓋 metadata 層面的 terminal function 偵測。

```python
# P1：bison 錯誤恢復狀態（只看 branch line 本身，確認條件式本身就是 yyerrstatus）
_PAT_BISON_SKELETON = re.compile(r'\b(yyerrstatus|yyerrlab1?)\b')

# P2：OOM null check - 需要同一變數名稱同時出現在 alloc call 和 null check（高 precision）
_PAT_OOM_ALLOC = re.compile(
    r'\b(\w{3,})\s*=\s*(?:malloc|calloc|realloc|g_try_malloc|zmalloc)\s*\('
)
_PAT_OOM_NULL_CHECK = re.compile(
    r'\bif\s*\(\s*(?:!\s*(\w+)|(\w+)\s*==\s*NULL)\s*\)'
)
```

套用邏輯：
```python
def _apply_snippet_solvability(
    branch_line_text: str,   # branch line 本身（P1 用）
    branch_snippet: str,     # branch_line ± 3（P2 用）
    file_lines: list[str],   # 整個檔案（_is_generated_parser 用）
) -> tuple[float, str, list[str]]:
    hints: list[str] = []
    # Audit-only 弱訊號（不影響排分，只看 branch_snippet）
    for pat, hint in _AUDIT_HINTS:
        if pat.search(branch_snippet):
            hints.append(hint)

    # P1：只看 branch_line_text 本身；若只是「附近」有 yyerrstatus 不算
    if _PAT_BISON_SKELETON.search(branch_line_text):
        if _is_generated_parser(file_lines):
            return 0.20, "bison_skeleton_state", hints
        hints.append("unconfirmed_bison_pattern")

    # P2：OOM null check with variable correlation
    alloc_vars = {m.group(1) for m in _PAT_OOM_ALLOC.finditer(branch_snippet)}
    if alloc_vars:
        for m in _PAT_OOM_NULL_CHECK.finditer(branch_snippet):
            checked = m.group(1) or m.group(2)
            if checked in alloc_vars:
                return 0.25, "oom_null_check", hints

    return 1.0, "normal", hints
```

降為 audit metadata 的弱訊號（`solvability_hints` 欄位，不影響 score）：
- `yychar`/`yytable`/`yyreduce` → `"possible_parser_var"`
- `NOTREACHED`/`UNREACHABLE`/`ASSERT(false|0)` → `"possible_assertion_macro"`
- `"out of memory"`/`"ENOMEM"` 等錯誤字串 → `"possible_oom_string"`

### 新增參數

```python
def aggregate_score_and_revalidate_blockers(
    ...,
    project_name: Optional[str] = None,   # None 時跳過 Phase 2
) -> List[Dict[str, Any]]:
```

---

## 預期效果驗證

| Blocker | Phase 1 | Phase 2（snippet）| 最終 score 效果 |
|---------|---------|-----------------|----------------|
| `compute_local_ud:667` | solvability=0.15（terminal func）| — | score 降為原本 15%，大幅下降 |
| `pcap_parse:2056` | solvability=1.0（無 metadata 訊號）| 0.20（branch line 本身是 `if (yyerrstatus)`，且 grammar.c 確認為 bison 生成）| score 降為原本 20% |
| `convert_code_r:2715` | solvability=1.0 | 0.25 若 calloc 和 null check 在 branch snippet 範圍內；否則 1.0 | score 降為原本 25%（若範圍足夠）|
| 一般高覆蓋收益 blocker | 1.0 | 1.0 | 不受影響 |

---

## Future Work（暫不做）

- **History backoff**：讀取 `experiments/*/blocker_attempts.jsonl`，對重複失敗的 blocker 施加 `max(0.05, 0.5^n)` 指數退避。典型碩士論文「單專案一次跑到底」設置下增益有限，長期多次實驗時價值高。
- **Cost score**：估算 pipeline 執行成本（harness 編譯難度、corpus 大小）。
- **LLM 信心度回饋**：分類後若 confidence=LOW，降低 solvability 或提前終止 pipeline。
