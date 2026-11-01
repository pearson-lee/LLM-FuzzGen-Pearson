# H1 設計：以 LLM 評估 blocker 的分支價值（2026-10-24）

狀態：設計草案，尚未實作。對應 `backlog/TBD.md` H1。

## 1. 目標與非目標

**目標**：飽和專案中大多數候選 `score = 0`，目前同分時依 regex `branch_kind` → `reach_confidence`（hit count）排序。regex 分不出以下情況，H1 要讓 LLM 補上：

| regex 分類 | regex 分不出的情況 | 實例 |
|---|---|---|
| `semantic_result` | 正常結果分支 vs 防禦性提早離開 / 內部不變量 | `table::equal` 的 `return false`（可解）vs `at_path:494` 的 `return {}`（GT：Internal Invariant Guard，四次實驗都被選中且失敗） |
| `other` | 可由輸入達成的比較結果 | `date_time.hpp:416` 的 `return lhs.time < rhs.time;`（GT：Bounded Extreme Value，已有 POC） |

**非目標**：

- 不刪除任何候選（沿用「只降順序、不排除」原則）。
- 不取代 `blocker_classifier` 的 Dependent/Independent 分類，也不取代 `blocker_triage`；H1 只用於排序。
- 不改動 `score` 公式。

## 2. 在流程中的位置

```
aggregate_blockers → annotate + project_relevant → 計分 → _enrich_with_snippet_solvability（Phase 2 + regex branch_kind）
    → ★ _enrich_with_llm_priority（新增）→ 重新排序 → main.py 的 coverage 過濾與 top_k
```

- 新增函式放在 `global_blocker_selector.py`，由 `aggregate_score_and_revalidate_blockers()` 在 `project_name` 有值且啟用時呼叫（與 Phase 2 相同條件）。
- 只評估「排序後前 `N` 名」中尚未有快取結果的候選（預設 `N = 30`）。快取命中的候選直接套用，不再呼叫 LLM。

## 3. 排序 key

```
目前： (state, score, coverage_benefit,                        branch_kind_priority, reach_confidence, …)
改成： (state, score, coverage_benefit, llm_tier, llm_score,   branch_kind_priority, reach_confidence, …)
```

- 有分數的候選仍由 `score` 決定，LLM 只影響同分群組。
- 沒有 LLM 結果（未啟用、超出 `N`、呼叫失敗）時，`llm_tier = 1`、`llm_score = 0.5`（中間值），由 regex 與 hit count 決定，不會被提前或壓到最後。
- regex `branch_kind` 保留為 LLM 同分或失敗時的次要依據，並作為比較基準。

## 4. LLM 的輸入（只用靜態、低成本的資料）

| 欄位 | 來源 | 上限 |
|---|---|---|
| 專案、函式名稱、檔案、branch 行號、blocked side 行號 | blocker 欄位 | — |
| branch 條件文字 | `_extract_if_statement()` | 8 行 |
| blocked side 程式碼 | `_extract_blocked_side_body()` | 6 行 |
| 所在函式的原始碼（標示 branch 與 blocked side 行） | 已讀入的 `code_lines`，以 branch 行為中心擷取 | ±40 行 |
| 只能經由 blocked side 到達的函式名稱 | `blocked_unique_functions` | 10 個 |
| runtime 觀測 | `project_branch_hit_count`、blocked side 為 0 | — |
| 最佳 target 的 harness | `best_target` 對應的 `.cc` | 截斷至 4 KB（可關閉，見第 10 節） |

**刻意不放入**：regex 的 `branch_kind`，以及任何分數。避免 LLM 照抄既有判斷（anchor bias），否則無法比較兩者。

## 5. LLM 的輸出

只輸出一個 JSON 物件：

```json
{
  "category": "Actionable Target Gap",
  "required_condition": "兩個 date_time 的 date 相同、time 不同",
  "solvability": 0.8,
  "evidence": "predicate compares parsed values; both are produced from input TOML",
  "confidence": "medium"
}
```

- `category` 採用 GT 協議的分類（`TODO_MD/minimal_ground_truth_protocol.md`），再加上 `Uncertain`。這樣結果可以直接和 GT 的 `refined_triage_label` 比對。
- `tier` 不由 LLM 決定，由程式依 `category` 推導（同 `blocker_triage` 由 label 推導 `first_layer_decision` 的做法）：

  | `category` | `llm_tier` |
  |---|---|
  | `Actionable Target Gap`、`Bounded Extreme Value` | 2 |
  | `Uncertain`、解析失敗 | 1 |
  | `Internal Invariant Guard`、`Structurally Unreachable API Path`、`Resource-Exhaustion Guard`、`Environmental Failure`、`Generated Parser State`、`Infeasible Counter Overflow`、`Crash-Revealing Path` | 0 |

- `llm_score = solvability`（0–1，夾在範圍內），只用於同一 tier 內的排序。
- `confidence` 為 `low` 時，tier 0 降級為 1（避免 LLM 在沒把握時把可解分支壓到最後）。

## 6. 呼叫方式與成本控制

- **不走 LangGraph tool loop**：使用沒有綁定 tool 的 LLM（同 `generate_dict()` 走的 `_llm_without_tools`），一次請求一個候選。理由：
  - 參考 `blocker_triage` 的紀錄，帶完整 context 的單次評估平均約 26 秒；若再加上 tool call，一次選擇會更久。
  - 輸入已包含所需的靜態原始碼。
- **並行**：thread pool，預設 4 個 worker。
- **模型**：預設 `gemini-2.5-flash`、temperature 0（分類任務，速度與穩定性優先）；可用參數改成 `gemini-2.5-pro`。
- **逾時**：單一候選逾時或錯誤時記錄 `llm_error`，該候選退回中間值，不影響其他候選與整個選擇流程。
- **JSON 解析**：沿用專案現有的 `json_repair` fallback。

## 7. 快取

- 分支價值是靜態性質，同一份原始碼在整個實驗中不會改變，因此每個 blocker 每次實驗只需評估一次；session rerank 時幾乎全部命中快取。
- key：`canonical_blocker_key` + 輸入內容（條件、blocked side、函式原始碼）的 sha1 + prompt 版本號。
- 位置：預設 `experiments/<run_id>_<log_name>/llm_branch_priority_cache.jsonl`；可用 `--blocker-llm-priority-cache <path>` 指定跨實驗共用的檔案（離線評估與重跑時使用）。

## 8. 紀錄

- `score_components` 新增 `llm_category`、`llm_tier`、`llm_score`。
- `_blocker_score_summary()`（`blocker_score_history.jsonl`）新增 `llm_category`、`llm_tier`、`llm_score`、`llm_confidence`、`llm_required_condition`、`llm_evidence`（截斷）、`llm_cached`、`llm_error`。
- prompt 與原始回應寫入 `experiments/<run>/llm_branch_priority/<blocker_id>/`，供人工檢查。

## 9. 驗證計畫（不需要 24 小時實驗）

| 驗證 | 資料 | 指標 | 通過標準（草案） |
|---|---|---|---|
| A. GT 一致性 | 19 個 selected cases（Internal Invariant Guard 6、Bounded Extreme Value 4、Structurally Unreachable 3、External Resource Failure 2、Resource-Exhaustion 1、未標 3） | `category` 是否落在 GT 同一側（generation-solvable vs non-solvable）；完全一致率 | 生成可解（`Bounded Extreme Value`）案例不得被判為 tier 0；494 必須是 tier 0 |
| B. 重複性 | 同 A，各跑 3 次 | 同一案例三次的 tier 是否相同 | 參考 triage 紀錄（三次 first-layer agreement 約 5/9），H1 應高於此 |
| C. 離線重排 | 1010、1012、1018 的初始 snapshot，搭配當次實際成敗 | 前 5 / 前 10 名成功數、失敗耗時，與 regex 排序比較 | 不低於 regex 排序 |

A、B 只需要 selector 的單一候選評估函式，可寫成 `tools/eval_llm_branch_priority.py`。C 沿用先前的離線重排方式（`rescore_existing_blockers()`）。

## 10. 介面與預設值

| 參數 | 預設 | 說明 |
|---|---|---|
| `--blocker-llm-priority` | 關閉 | 開啟 H1；預設關閉以保留與先前實驗的可比較性 |
| `--blocker-llm-priority-top-n` | 30 | 每次選擇最多評估的候選數（不含快取命中） |
| `--blocker-llm-priority-model` | `gemini-2.5-flash` | 分類用模型 |
| `--blocker-llm-priority-workers` | 4 | 並行數 |
| `--blocker-llm-priority-cache` | 實驗目錄內 | 快取檔案路徑 |
| `--blocker-llm-priority-include-harness` | 開啟 | 是否附上 harness（4 KB） |

`rescore_existing_blockers()` 也加上同名參數，讓離線重排可以使用。

## 11. 實作步驟

1. `prompts/templates/blocker_branch_priority_template`：prompt 與 GT 分類定義。
2. `global_blocker_selector.py`：`_build_llm_priority_context()`、`_classify_branch_with_llm()`、`_enrich_with_llm_priority()`、快取讀寫、sort key 調整。
3. `main.py`：CLI 參數、傳入 selector、`_blocker_score_summary()` 新欄位。
4. unit test：tier 推導、低信心降級、快取命中、LLM 失敗退回中間值、sort key 順序（以假 LLM 測試，不呼叫真實 API）。
5. `tools/eval_llm_branch_priority.py`：執行驗證 A、B。
6. 依驗證結果調整 prompt，再做驗證 C。

## 12. 風險

- **LLM 自信但錯誤的推論**：triage 的紀錄顯示 FP 多來自「confident but invalid producer claims」。對策：tier 由程式從 category 推導、低信心不降到 tier 0、只影響同分排序。
- **只看靜態片段**：可能看不出 harness 層級的限制（例如 harness 固定某些參數）。對策：附上截斷的 harness；必要時之後再加 tool 查詢。
- **成本**：首次選擇最多 30 次請求（flash、4 並行，預估數分鐘），之後幾乎全部命中快取。
- **與 H4 的關係**：仍受 Vertex AI 90 秒單次請求上限影響；flash 回應較快，影響較小。
