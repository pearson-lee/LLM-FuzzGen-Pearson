# Blocker Selector 與 Triage 整合優化方案（2026-06-20）

## 1. 最終目標

系統不應優先選「最常被 hit 的 blocker」，而應在有限時間內優先選：

> **可解機率高、解開後能增加最多邊際 coverage、且求解成本合理的 blocker。**

統一目標函數：

```text
Expected Utility
= Reach Confidence
× Solvability Probability
× Marginal Coverage Benefit
÷ Estimated Solver Cost
```

四個分量必須分開記錄，不能只留一個總分，否則無法稽核 selector 為何選錯。

---

## 2. 目前已確認的問題

### 2.1 Hot branch 被重複獎勵

目前 `actionability_score` 同時包含：

- `log1p(project_branch_hit_count)`
- `log1p(project_branch_reached_target_count)`
- `log1p(sides_hitcount_diff)`

當 blocked side hit count 為 0 時，`sides_hitcount_diff` 幾乎又是 branch hit count，因此 hotness 被重複計分。
這會讓高頻 error guard 壓過 branch hit 較少、但解開後能進入新 function 的 blocker。

### 2.2 Impact 分數沒有聚焦「邊際未覆蓋收益」

目前 impact 同時加總 unique/non-unique、reachable/not-covered complexity，容易重複計算，也會獎勵已覆蓋的
reachable 區域。應把主訊號改為：

- `blocked_unique_not_covered_complexity`
- `unlock_ratio = unique_not_covered / max(unique_reachable, 1)`
- blocked side 後方目前仍 globally-unhit / low-coverage 的 function
- 扣除已選 blocker 會解鎖的重複 function 後，剩餘的 marginal gain

### 2.3 OOM heuristic 漏掉專案 allocator wrapper

目前 OOM pattern 只認 `malloc/calloc/realloc/g_try_malloc/zmalloc`。20260618 lcms run 的 `AddToList:1274`
使用 `_cmsMalloc`/`AllocChunk` 類 wrapper，因此被錯標：

```text
solvability_reason = normal
solvability_score  = 1.0
project_branch_hit_count = 5,760,000
blocked_unique_not_covered_complexity = 30
```

它靠 hotness 進入 top-10，但 blocked side 實際需要 allocation failure，最後浪費 target solver 預算。

這是跨 C/C++ 專案的通用缺口，但不能只把 regex 放寬成任意含 `alloc` 的名稱後就 hard reject；命名 heuristic
可能誤判。應採證據分級：

```text
強證據：同一變數 = allocator-like call，隨後做 NULL check，並有 OOM/ENOMEM/error-return 證據
中證據：同一變數關聯成立，但只有 wrapper 名稱像 allocator
弱證據：只有 OOM 字串或 allocator 名稱
```

selector 只做降權；是否屬 Resource-Exhaustion 仍由 source evidence/triage 確認。

### 2.4 Triage 現況的證據仍不足以支撐永久排除

`20260615_235134` 的 10 個 lcms blocker 中：

- triage 跳過 3 個，人工查核都正確
- 其餘 7 個跑 solver，5 成功、2 失敗
- 3 個 Inconclusive 經 fail-open 後全部成功

這證明 fail-open 必要，也顯示 triage 有節省 solver 成本的潛力；但它仍只是同一 development project 的 10 個
case，不能推出跨 run、跨 project 永久排除安全，也不能稱為一般化 accuracy/recall。

### 2.5 「批次內排序」目前只能部分生效

目前每次 blocker attempt 後會重新讀 coverage 並 rerank，因此不是完全固定批次；但 triage verdict 沒有寫回
selector score。triage skip 會被記入 run-local `attempted_blocker_keys`，同一 run 不再選，已足以避免重複浪費。

因此現階段不需要再新增另一份 run-local exclusion set。跨 run 的永久 `triage_excluded_keys` 風險過高。

---

## 3. 建議的新分數模型

### 3.1 Reach Confidence：只證明「已靠近」，不代表效益或可解

branch hit 超過一個合理門檻後應飽和，不再因 1M、100M 次 hit 拉開巨大差距。

```text
reach_confidence = saturated(branch_hit_count) × target_reach_support
```

建議先用 project 內 percentile 或固定飽和門檻，不直接把 raw hit count 累加兩次。

### 3.2 Coverage Benefit：以未覆蓋且不重複的 downstream 區域為主

```text
base_benefit =
    normalized(unique_not_covered_complexity)
  + unlock_ratio
  + weighted_unhit_function_count

marginal_benefit = base_benefit × (1 - overlap_with_already_selected)
```

`blocked_unique_functions` 可用 Jaccard overlap 或 set difference 做 diversity penalty，避免 top-k 都指向同一片 code。

### 3.3 Solvability Probability：deterministic evidence 為主，LLM triage 為輔

初始 prior：

```text
visible input/setter/public API transition        高
current target hardcodes wrong but legal state   高
evidence insufficient                            中／保留探索
allocator/environment/internal invariant         低
infeasible counter/crash-before-observe          很低
```

來源依序為：

1. live coverage revalidation
2. source snippet deterministic patterns
3. producer/callsite/setter evidence
4. LLM triage label + evidence contract
5. 過去同類 blocker 的 runtime solver 成敗

LLM triage 不直接產生永久真值，只調整 run 內 priority。

### 3.4 Estimated Cost：使用實際歷史耗時，不交給 LLM 自評

```text
estimated_cost_seconds =
    route_base_median
  + expected_llm_calls × median_llm_latency
  + expected_builds × median_build_time
  + expected_evaluations × median_evaluation_time
  + P(symcc) × symcc_budget
```

資料來自 `blocker_attempts.jsonl` 與 solver `summary.json`。沒有歷史資料時使用 route-level default：

- simple seed/target generation：low
- repeated build/repair/evaluation：medium
- SymCC 或已有多次 no-growth：high

先用 low/medium/high 三級即可，資料累積後再改成秒數回歸模型。

---

## 4. Triage 應如何併入 Selector

### 4.1 保留 taxonomy，但 operational action 簡化

10 個 label 可保留做分析與論文 taxonomy；scheduler 實際只需要：

```text
actionable   → 高 solvability multiplier
deferred     → 低 multiplier，留在 backlog
inconclusive → 中 multiplier，fail-open
triage_error → 不懲罰，fail-open
```

Input Dependent / Independent classifier 仍負責決定 seed solver 或 target solver，不能和 triage taxonomy 混在一起。

### 4.2 不做跨 run 永久 hard exclusion

建議：

- 高信心 non-generation-solvable：本次 run 延後，避免立即吃 solver 預算
- Inconclusive：降權但保留
- triage_error：不降權
- 每個 session 保留 10–20% exploration quota 給高效益 unknown/deferred blocker
- 下一個 run 重新以新 coverage/source evidence 評估

只有 deterministic、可重現的事實（例如目前 build 中 inactive callsite）才適合 hard filter；LLM verdict 不適合永久封鎖。

### 4.3 讓 triage 真正影響「成員」，不只影響單顆 dispatch

最小實作可使用 bounded look-ahead window：

1. cheap selector 產生 top-N candidate pool（例如 20）
2. 對目前最高分的 3–5 顆做 classifier + triage
3. 依更新後 Expected Utility 選一顆執行 solver
4. 執行後更新 coverage、cost history、attempt outcome，再補下一顆進 window

這比一次 triage 全部 20 顆便宜，也比「拿到一顆就立刻 solver」更能讓 triage 發揮排序效果。

---

## 5. 實作順序

### Phase 1：先修 deterministic selector 缺口（低風險）

1. 一般化 allocator wrapper detection，但維持「assignment variable 與 NULL check 必須相同」的關聯。
2. 加入 evidence confidence，只有強證據使用 0.25；中證據先用較輕懲罰，例如 0.5。
3. 對 `AddToList:1274` 建 regression test，要求 reason 不再是 `normal`。
4. 加反例測試：名稱含 `alloc` 但不是 resource failure，不得被 hard reject。
5. selector output 記錄 pattern、callee、checked variable 與 evidence confidence。

### Phase 2：修 ranking，不先引入更多 LLM

1. hotness 飽和，移除 branch hit 與 side gap 的重複獎勵。
2. impact 改以 unique not-covered、unlock ratio、globally-unhit functions 為主。
3. top-k 加 downstream function diversity/marginal gain。
4. 每個 score component 做 project 內 normalization，避免不同專案 raw complexity 尺度不同。

### Phase 3：加入 cost-aware feedback

1. 從既有 attempt/summary 建 route-level median cost。
2. 把 repeated failure/no-growth、compile repair、SymCC 使用納入成本。
3. 每次 attempt 後更新成本估計與 blocker history。
4. 記錄 `estimated_cost_seconds`、`actual_cost_seconds` 和誤差。

### Phase 4：把 triage 從 hard gate 改為 bounded ranking signal

1. 實作 look-ahead window。
2. 將 label 映射成 multiplier/deferred 狀態，而不是跨 run permanent exclusion。
3. 保留 fail-open 與 exploration quota。
4. 沿用 `blocker_attempts.jsonl` 作單一 audit source；除非有明確查詢需求，不新增重複的 `triage_verdicts.jsonl`。

---

## 6. 驗證方法

### 6.1 Offline replay（先做，不跑 24hr）

使用既有 lcms candidate snapshots 重算舊版與新版 ranking，檢查：

- `AddToList:1274` 是否因 OOM evidence 明顯降名次
- 已知成功 blocker（cmsDetectBlackPoint、cmsDetectDestinationBlackPoint、cmsDeleteContext、AddMLUBlock）是否前移
- high-benefit blocker 是否沒有被 hot error guard 壓過
- top-k downstream function overlap 是否下降

### 6.2 指標

不要只看 classifier accuracy，應報：

- `Solved@K`：top-K 中最後被 solver 解出的數量
- `Value-weighted Solved@K`：成功 blocker 對應的 coverage benefit
- `Solver seconds per solved blocker`
- `New covered branches/functions per solver hour`
- `Wasted solver seconds`：花在人工確認 non-generation-solvable blocker 的時間
- `False-defer rate`：被延後但人工/runtime 證實可解的比例
- `Triage stability`：同 blocker 重跑 3 次 label/priority 一致率
- `Cost calibration error`：estimated vs actual seconds

### 6.3 資料切分

- lcms 既有案例只能作 development/replay set
- 至少一個未參與規則設計的 project 作 held-out evaluation
- 不可用同 10 cases 改 prompt/規則後再稱 accuracy

### 6.4 Production 驗證順序

1. unit tests
2. lcms offline ranking replay
3. focused blocker session（短時間）
4. held-out project short run
5. 最後才跑 24hr A/B

24hr A/B 必須固定 target set、fuzzing budget、coverage build 與 random/environment 條件；比較：

```text
舊 selector + 現有 triage
新版 Expected Utility selector + ranking triage
```

---

## 7. 這一輪不應做的事

- 不把單次 lcms 3/3 skip 正確寫成一般化 100% precision
- 不建立跨 run 永久 LLM exclusion blacklist
- 不為了圖表平衡硬拆可解 label
- 不把 allocator 名稱 regex 當成不可解真值
- 不先調大量權重再用同一組 10 cases 宣稱進步
- 不立刻再跑 24hr；先確認 ranking replay 與 focused 指標真的改善

## 8. 最小下一步

目前最高 ROI 的順序是：

1. 修 allocator wrapper evidence，讓 `AddToList` 類 blocker 正確降權。
2. 將 hotness 改為飽和訊號，避免 hit count 重複主導。
3. 建 offline replay 報告，比較舊/新 top-10 的 Solved@K、預估效益與 wasted solver time。
4. replay 有改善後，再實作 cost model與 triage look-ahead window。

這樣可以先用 deterministic、可驗證的修正改善 selector，再處理較昂貴且不穩定的 LLM triage 排序。
