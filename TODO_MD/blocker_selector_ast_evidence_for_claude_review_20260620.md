# Blocker Selector 優化：局部 AST 證據、Reach 與 Benefit 設計（請 Claude 評估）

日期：2026-06-20

## 0. 目的

目前 Blocker Selector 容易讓「branch hit 很多，但不可實用或解開效益很低」的 blocker 進入昂貴 solver。
本文整理已驗證根因、最新收斂方案與待確認問題，請評估：

1. 技術設計是否足夠泛用於 C/C++ project。
2. Tree-sitter AST evidence 是否值得加入主程式。
3. Selector 與 LLM triage 的責任邊界是否合理。
4. Reach/Benefit 新公式是否有明顯偏差。
5. 實作範圍能否再縮小而不犧牲方法可信度。

---

## 1. 已驗證的現況

### 1.1 目前 Score

`blocker_process/global_blocker_selector.py`：

```python
score = (actionability_score + impact_score) * solvability_score
```

Actionability 目前同時包含：

```text
log1p(project_branch_hit_count)
0.75 * log1p(project_branch_reached_target_count)
0.3 * log1p(sides_hitcount_diff)
```

blocked side hit count 為 0 時，`sides_hitcount_diff` 幾乎又等於 branch hit count，造成 hotness 重複計分。

Impact 同時累加：

```text
blocked_unique_not_covered_complexity
blocked_not_covered_complexity
blocked_unique_reachable_complexity
blocked_reachable_complexity
function/file coverage signal
occurrence_count
```

unique/non-unique、reachable/not-covered 同時使用，可能重複計算，也可能獎勵已覆蓋的 reachable 區域。

### 1.2 AddToList 根因已由保存 snapshot 證實

來源：

```text
experiments/20260618_213959_run_all_fuzzer/
  branch_blockers/lcms_initial_introspector_refresh.json
```

`AddToList:1274`：

```text
project_branch_hit_count = 5,760,000
blocked_unique_not_covered_complexity = 30
solvability_reason = normal
solvability_score = 1.0
score = 35.6399
```

實際 blocked side 是 allocation failure / out-of-memory error path。它因 hit count 高進入 top-10，但 downstream
未覆蓋效益很低，最後浪費 target-generation solver 預算。

### 1.3 OOM pattern 的通用缺口

目前 `_PAT_OOM_ALLOC` 只認固定 allocator roots：

```text
malloc / calloc / realloc / g_try_malloc / zmalloc
```

這會漏掉 project wrapper。但直接把 `_cmsMalloc`、`xmalloc`、`png_malloc` 等名稱加進清單不是泛用設計，
也不能保證其他 C/C++ project。

### 1.4 Session queue 不是固定批次

實際流程：

```text
selector 取 top-N
→ 初始放前 M 顆到 selected_blockers
→ pop 第一顆求解
→ coverage evaluation
→ 重新載入 coverage context
→ 再跑 selector top-N
→ 用新的未嘗試排名替換 selected_blockers
```

因此 M 是「本 session 最多執行幾顆」，不是固定 queue 成員。求解前不能因 A 被挑中就扣除 B 的 benefit；
只有 A runtime-confirmed 成功並實際新增 coverage 後，才能重算 B 的剩餘效益。

### 1.5 Artifact 與 Ranking 的 freshness 不同

每次 attempt 後 ranking 會重跑，但 `reuse_session_artifacts` 下，Introspector artifact 可能仍是舊的：

- live branch/blocked-side hit count：可更新
- resolved state / best target：可更新
- static downstream complexity / `blocked_unique_functions` / `all_functions.js`：可能 stale

因此不能把預測的 downstream functions 當成「成功 target 已全部覆蓋」的事實。

---

## 2. 最新問題定義

Selector 需要便宜地回答兩個問題：

```text
1. 這顆 blocker 已經靠得夠近嗎？
2. 解開後預期能增加多少 coverage？
```

Selector 不應負責完整回答：

```text
這個 custom function 的深層 call chain 最終是否呼叫 malloc？
這個 internal state 是否存在合法 API producer path？
```

後者屬於 classifier/triage/source evidence 的深層語意工作。

因此目標不是建立完整 static analyzer，而是加入「高 precision、證據不足即 unknown」的局部 Resource Guard
辨識，避免明顯 OOM guard 靠 hotness 排到前面。

---

## 3. 提案：Tree-sitter 局部 AST Evidence

### 3.1 為什麼不繼續擴大 Regex

泛用 C/C++ 需要處理：

```c
p = function(...);
Type *p = function(...);
auto p = function(...);

if (!p)
if (p == NULL)
if (NULL == p)
if (p == nullptr)
if (p == 0)       // 只有能確認 p 為 pointer 時才接受
```

Regex 很難可靠處理 declaration、pointer declarator、namespace、template、括號和 comments。若要確認 assignment 與
NULL check 是同一個 local variable，應使用 AST。

### 3.2 環境現況

- Repo vendored 的 Fuzz Introspector 已使用 `tree-sitter`、`tree-sitter-c`、`tree-sitter-cpp`。
- 主程式 `.venv` 目前沒有安裝這三個 package。
- `pycparser` 已存在，但只支援 C，且容易受 macro/preprocessor 影響，不適合泛用 C/C++。

若採用方案，需要把 Tree-sitter C/C++ 加入主程式 dependency；不直接耦合 Fuzz Introspector 內部 class，避免外部子專案
更新造成介面 regression。

### 3.3 AST 辨識流程

已知 metadata：

```text
source_file
branch_line_number
blocked_side_line_number
blocked_side
```

步驟：

1. Parse 整份 source file。
2. 找出涵蓋 `branch_line_number` 的 `if_statement`。
3. 從 condition 正規化 NULL check，抽出 `checked_variable`。
4. 在同一 `compound_statement` 往前搜尋最多 5 個 sibling statements。
5. 找最近一次對同一變數的 initializer/assignment。
6. 若 RHS 是 `call_expression`，記錄 `producer_callee` 與 line。
7. 用 `blocked_side_line_number` 定位未覆蓋 consequence/alternative subtree。
8. 從 blocked-side subtree 擷取 OOM/ENOMEM/allocation-failure string/constants 與 error return。
9. 若 AST 出現 ERROR、alias、macro 或無法建立同變數關聯，輸出 `unknown`。

輸出 evidence schema：

```json
{
  "checked_variable": "p",
  "check_kind": "null_check",
  "check_form": "p == NULL",
  "producer_kind": "call_expression",
  "producer_callee": "AllocChunk",
  "producer_line": 1273,
  "same_variable_flow": true,
  "resource_evidence": [
    "oom_string: out of memory",
    "error_return: NULL"
  ],
  "confidence": "strong",
  "reason": "same_call_result_null_checked_with_oom_path"
}
```

這裡不判斷 `AllocChunk` 是哪個 project 的 allocator；判斷依據是局部資料流與 blocked-side 明確 OOM 語意。

### 3.4 Evidence 分級

```text
Strong
  同變數 call-result + NULL check + blocked-side OOM/ENOMEM/allocation-failure evidence
  或 direct standard allocation primitive + NULL check
  → solvability penalty 0.25

Medium
  同變數 call-result + NULL check，但只有弱 resource hint
  → penalty 0.5（是否保留這級請 Claude 評估）

Weak
  只有 allocator-like 名稱或只有 OOM 字串，沒有同變數 flow
  → 只記 audit hint，不降權

Unknown
  AST/error/macro/alias 無法確認
  → 不降權，交給 triage/source analysis
```

禁止事項：

- 不加入 project-specific API whitelist。
- 不做 alias analysis。
- 不追跨函式 call chain。
- 不因函式名稱含 `alloc` 就 hard reject。
- 不把 selector heuristic 當成 triage ground truth。

---

## 4. Reach Confidence 修正

現有 live validation 已排除 `project_branch_hit_count <= 0`，因此 Reach 只需區分「池內低 hit」與「已充分 hit」，
不能繼續讓 1M、100M 拉開巨大差距。

初版提案：

```python
saturated_hotness = min(
    1.0,
    math.log1p(branch_hit_count) / math.log1p(HIT_SATURATION_THRESHOLD),
)

reach_confidence = 0.5 + 0.5 * saturated_hotness
```

`sides_hitcount_diff` 不再作第二份 hotness 分數，只保留為 consistency/audit signal。

初版使用固定 threshold；percentile normalization 延後。

待確認：固定 threshold 應如何選，是否以 10k/100k hits 做 replay sensitivity analysis，而不是直接 hand-tune。

---

## 5. Coverage Benefit 修正

### 5.1 Unlock Ratio

```python
not_covered = max(0, blocked_unique_not_covered_complexity)
reachable = max(0, blocked_unique_reachable_complexity)

unlock_ratio = min(1.0, not_covered / max(reachable, 1))
```

意義：blocked side 後方可到達的 unique complexity 中，目前尚未覆蓋的比例。

- `not_covered`：能增加多少（absolute amount）
- `unlock_ratio`：後方有多大比例仍未探索（unexplored density）

Ratio 不能單獨使用，因為 `2/2=100%` 但絕對效益仍很小。

初版 benefit：

```python
benefit = math.log1p(not_covered) * (0.5 + 0.5 * unlock_ratio)
```

候選的 globally-unhit function evidence 若來自 stale `all_functions.js`，只能作次要 signal，必須標記 freshness。

### 5.2 不做求解前 Marginal Deduction

目前 queue 每次 attempt 後會替換，因此：

```text
A 只被選中         → B 不扣 benefit
A solver 失敗      → B 不扣 benefit
A runtime 成功     → 只根據實際新增 coverage 重算 B
```

如果無法可靠取得 per-function runtime delta，就不做 overlap deduction。Soft diversity 降為 future tie-breaker，不是本輪
主要修改。

---

## 6. Triage 的責任與論文定位

本提案不假設 triage 常駐開啟。

```text
Selector
  deterministic、便宜、triage 關閉也可運作
  只處理高 precision 的局部 evidence 與 coverage value

Classifier/Triage
  optional、較昂貴
  分析 producer path、internal state、跨函式語意與 practical feasibility
```

論文建議把 triage 定位為 optional LLM-guided prioritization/cost-control component，而不是正確性 oracle。實驗需比較：

```text
Selector + Solver
Selector + Triage + Solver
```

報告 solved blockers、coverage gain、solver wall time、false-defer/false-skip、success retention。若 held-out 評估仍不穩定，
triage 可作 ablation/optional design，不影響 selector/solver 主結果。

---

## 7. Runtime 成本控制

不可對全部 blockers 反覆 parse。初版限制：

```text
只對初步分數前 20 顆做 AST evidence
每個 source file 只 parse 一次
cache key = path + size + mtime_ns + language
cache 最多 64 個 source files
同一 block 向前最多找 5 個 statements
不做 alias/interprocedural analysis
parse/query 失敗 → unknown
```

記錄：

```text
ast_parsed_file_count
ast_cache_hit_count
ast_parse_seconds
ast_query_seconds
ast_unknown_count
```

驗收：

```text
AST 額外成本 < selector 總時間 10%
或每次 rerank 額外成本 < 1 秒
```

若超標，先縮小 candidate cap 或改善 persistent cache，不改成 project-specific pattern。

---

## 8. 驗證方案

### 8.1 Unit Tests

C/C++ snippets：

- declaration initializer + `if (!p)`
- assignment + `p == NULL`
- reversed `NULL == p`
- C++ `nullptr`
- `p == 0` 且 p 可確認為 pointer
- variable reassignment，需選最近 producer
- 不同變數 assignment/null-check，不得配對
- alias (`q = p`) → unknown
- macro/ERROR node → unknown
- OOM strong evidence
- 非 OOM NULL return 反例
- 名稱含 alloc、但沒有同變數/OOM 關聯的反例
- AddToList regression fixture

### 8.2 Offline Replay

固定：

```text
experiments/20260618_213959_run_all_fuzzer/
  branch_blockers/lcms_initial_introspector_refresh.json
```

比較舊/新 ranking：

- AddToList 名次與 score component
- known runtime-success blockers 名次
- `Solved@K`
- benefit-weighted `Solved@K`
- top-k Resource Guard 比例
- selector runtime/AST cache metrics

lcms 僅作 development/replay set；至少一個未參與設計的 project 作 held-out evaluation，不能用同一 snapshot 調參後稱
一般化 accuracy。

---

## 9. 本輪範圍

要做：

1. AST local evidence prototype + tests。
2. Resource Guard evidence 分級。
3. Hotness saturation。
4. Benefit 改用 absolute not-covered + unlock ratio。
5. Offline replay。

暫不做：

- Cost 秒數模型。
- Triage look-ahead window。
- 跨 run exclusion。
- Interprocedural allocator wrapper discovery。
- Alias analysis。
- 求解前 diversity/marginal deduction。
- 24hr experiment。

---

## 10. 請 Claude 重點回答

1. Tree-sitter dependency 與 AST local-flow 設計是否值得，或仍有更小且同樣可防守的方法？
2. Strong/Medium/Weak evidence 的門檻是否合理？Medium 是否會誤傷太多一般 NULL-return API？
3. 只分析 top-20 是否可能因初始 hotness 偏差而永遠看不到高效益 blocker？應使用 top-score + high-benefit 混合候選嗎？
4. Reach floor 0.5 與固定 saturation threshold 是否合理？應如何做 sensitivity analysis？
5. Benefit 公式是否會低估 small-but-semantic function unlock，是否需保留 globally-unhit function bonus？
6. 在 `all_functions.js` 可能 stale 的條件下，runtime success 後應如何安全更新 downstream benefit？
7. Triage 作 optional ablation 而非核心 oracle，是否更符合目前證據與論文可防守性？
8. 三週時限下，哪些項目應再延後？
