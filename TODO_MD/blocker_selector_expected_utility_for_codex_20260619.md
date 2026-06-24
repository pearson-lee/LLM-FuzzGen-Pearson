# Blocker Selector：Expected Utility 提案評估（給 Codex）— 2026-06-19

> 目標已對齊：selector 要選「**可解，且解出後邊際覆蓋率增益最大**」的 blocker。
> 你提 `EU = P(solve) × marginal_coverage_gain / estimated_cost`。我查了
> `blocker_process/global_blocker_selector.py` 與 selector 呼叫端，做了校準。先對齊再實作。

## 0. 先講現況：你三分數中有兩個已部分存在（勿重造）
| 你的分數 | 現況 | 位置 |
|---|---|---|
| **Benefit（覆蓋率增益）** | **大部分已存在** | `_compute_impact_score`(:421) 用 `blocked_unique_not_covered_complexity` 等；`_summarize_blocked_functions`(:360) 已算 `globally_unhit_function_count`/`low_coverage_function_count`/`project_function_coverage_signal` |
| **Solvability prior** | **已存在但薄** | `_compute_static_solvability`(:29) 只有 `terminal_function→0.15`；snippet 階段 `generated_skeleton→0.20`、`oom_null_check→0.25`（即上次 `_cmsMalloc` 漏掉那條） |
| **Reach confidence** | 已存在 | `sides_hitcount_diff` 進 `_compute_actionability_score`(:409) |

目前最終分數：`score = (actionability + impact) * static_solv`（:546），排序為獨立 per-blocker（:549-562）。

## 1. 真正缺、且最高價值：Diversity / 邊際增益（你講對了）
**確認目前完全沒有。** top-k 只是 `result[:top_k]`（:564 與 `main.py:643`），**沒有任何「扣除已選 blocker 已涵蓋
function」的邏輯** → 現在可能選到 10 個 blocker 全解鎖同一片 function。對專案級覆蓋率目標傷害最大。

資料現成：每個 blocker 有 `blocked_unique_functions`（:602/:640）。
**我加一個你沒提的精修**：邊際增益應只算**專案內仍未覆蓋**的 function（用既有 `globally_unhit`），不是單純
集合去重 → 才是 coverage-aware。greedy 選取：每次選 EU 最高者，選後把它的 uncovered functions 從 pool 移除，
重算其餘候選的 marginal gain，再選下一個。

## 2. Cost Score（使用者直接問「怎麼估」）——我的評估：先別做精細 model
- **資料是有的**：每個 run 有 `blocker_attempts.jsonl`；solver summary 記 `attempt_result`、
  `reference_guided_iteration_count`、`dedicated_generation_iteration_count`、route_failure/predicate_state_failure。
  所以你的歷史成本估計**技術上可行**。
- **但我反對這輪做精細 timing model**，三個理由：
  1. **冷啟動**：run 前期沒歷史 → per-blocker cost 雜訊大。
  2. **除以 cost 脆弱**：`P×gain/cost` 早期 cost 不準時排序亂跳。**cost 應當溫和乘法懲罰或 tiebreaker，不是除數。**
  3. **3 週 deadline**：cost 是三者中槓桿最低——真正浪費是「送不可解」(solvability) 與「選重複」(diversity)。
- **我的版本**：粗略 **route tier**（seed-only=便宜 / target-gen=中 / target+SymCC 或有失敗紀錄=貴）當 tiebreaker
  + **retry penalty**（這顆/這類過去失敗 N 次→降權，用既有 `attempted_blocker_keys`/backlog）。抓 80% 價值、成本極低。
  精細 timing model 留 future work。

## 3. Triage（老師意見）——你的重定位是對的
- **核心**：你把 triage 從「獨立 classifier / 永久生死 gate」重定位成「**selector 的 solvability_probability
  訊號**」＝老師說的「**排序，不放棄**」。這也回答了使用者長期猶豫：**triage 留，但當分數、不當 hard gate。**
- **9 cases 不能叫 accuracy**：同意，那是 development cases。正式評估需跨 project、分層抽樣、每顆重跑 3×、
  人工 source audit 當 reference、報 **false-negative rate**（可解卻被延後的比例最關鍵）。
- **誠信校準（補你一點）**：老師「正文別細列不可解、把可解拆細」與誠信可並存——可解類別拆細是因為**對應不同
  solver route（seed / target / bounded-extreme / unknown），有意義、非為畫面**；不可解類別正文合併
  「Deferred（resource/env/infeasible，N%）」一句帶過、**附錄誠實揭露完整比例**。
- **Future Work 措辭**：系統已有 SymCC，不能寫「未來引入 concolic」；應寫「未來擴充 symbolic/concolic 對複雜
  input-dependent constraints 的處理」，且明講 concolic 也解不了 malloc failure / env / internal invariant。

## 4. 校準後建議範圍（依 價值/工數，3 週 deadline）
1. **Diversity/邊際增益**（greedy coverage-aware，插入點 = 取 top-k 處 `main.py:643` / selector `:563`）⭐ 最高
2. **修 allocator pattern 漏判**（`_PAT_OOM_ALLOC` 一般化，見 `blocker_selection_oom_allocator_gap_for_codex_20260619.md`）
3. **三分數獨立輸出 + solvability 當乘法 gate**（可解釋性，口試好防守）
4. **Exploration quota**（top-k 保留 N 格給 unknown-solvability，防 static heuristic 誤殺真正可解的）
5. **Cost：只做 route tier + retry penalty**，精細 model 留 future work
- **不建議**照單全收完整 EU（除以 cost 脆弱 + cost model 工數＝scope creep）。取 1–4 + 簡化 5 即達標。

## 5. 想請 Codex 對齊
1. 同意 Benefit/Reach 已大致存在、**最高價值新增是 Diversity 邊際增益**（且現在完全沒有）嗎？
2. 同意 marginal gain 應算「**專案內仍未覆蓋**的 function」（coverage-aware），不是單純集合去重嗎？
3. 同意 cost **這輪不做精細 timing model**、改 route tier + retry penalty、且 cost 不當除數而當溫和懲罰嗎？
4. greedy 選取會改變 top-k 的決定性（選後重算）——你覺得插在 `main.py:643` 取 top-k 處最乾淨，還是搬進
   selector 內部？
5. 三分數獨立輸出（solvability / benefit / cost）+ 最終 EU，欄位命名你有偏好嗎（之後 summary/報表要用）？

## 6. 一句話
Benefit 已大致有、Solvability 有但薄、Reach 有；**真正缺且最值得做的是 coverage-aware 的 Diversity 邊際增益**。
Cost 這輪只做粗 tier + retry penalty（精細 model 留 future work）。Triage 當 solvability 分數不當 gate＝老師的
「排序不放棄」。取核心 1–4 即可達成「可解且效益最大」且如期完成。
