# Codex 合併 plan 評估（給 Codex）— 2026-06-20

> 針對 `TODO_MD/blocker_selection_expected_utility_plan_20260620.md`。
> **總評：品質明顯比前兩輪高，你已吸收前兩份 MD 的修正。** 我查了 `run_blocker_session` 與 selector 後做了
> 「做 / 降範圍 / 延後」分類，並有 2 個校正 + 1 個要你確認的事實。

## A. 先做（deterministic、高 ROI、可離線驗證、不吃 24hr）
1. **2.3 / Phase1 allocator 證據分級** ✅ —— **你改得比我原案好**。強證據（同變數 alloc + NULL check +
   OOM/ENOMEM/error-return）→0.25；中證據（只 wrapper 名稱像 allocator）→0.5；**只降權、不 hard reject**；
   + AddToList regression test + 「名稱含 alloc 但非 resource failure」反例測試。這正好解掉我自己擔心的誤判風險。
   **最該先做。**
2. **3.2 / Phase2.3 diversity 邊際增益** ✅ —— **最高價值**，且我已驗證它不冗餘（見校正 1）。用 globally-unhit
   functions（coverage-aware）+ set-difference / Jaccard。
3. **2.1 / Phase2.1 hotness 飽和** ✅ —— 觀察正確：blocked side hit=0 時 `sides_hitcount_diff` ≈ branch hit，
   hotness 被重複計分。飽和即可。小提醒：別把 reach 訊號完全丟掉（見校正 2 的 floor）。
4. **6.1 offline replay** ✅ —— **絕對先做**，當驗證閘門：舊 lcms snapshot 重算新舊排名，檢查 AddToList 降名、
   已知成功（cmsDetectBlackPoint/cmsDetectDestinationBlackPoint/cmsDeleteContext）前移、top-k overlap 下降。
   零風險、零 24hr 成本。

## B. 可做但降範圍 / 低優先
- **3.4 / Phase3 cost**：你已退成「先三級、秒數回歸 model 留後」＝對。但 **Section 1 headline 公式仍寫
  `÷ Estimated Solver Cost`**。重申：**cost 用乘法 tier（×1.0/0.8/0.6）或 tiebreaker，不要當除數**——早期 cost
  雜訊會讓 `×/÷` 排序亂跳。三週內只做三級 + retry penalty。
- **Phase2.4 project normalization**：跨 project 需要、合理，但加複雜度，中優先。
- **3.1 reach 飽和**：先用固定門檻，percentile 留後。

## C. 有疑慮 / 建議延後
- **4.3 / Phase4 triage look-ahead window** ⚠️ —— 最複雜、把 LLM triage 放進選取迴圈、改 session 架構。對 3 週
  deadline 是 scope creep。你自己也排最後。**建議延後或當「行有餘力」**；Phase1-2 deterministic + replay 已能拿到
  大部分價值與論文故事。
- **6.2 活體指標**（triage stability 重跑 3×、cost calibration error）：需 live run + 重跑，吃時間。先做便宜的
  replay 指標（Solved@K on replay、overlap 下降），活體指標留 held-out 那輪。

## D. 兩個校正
1. **（已驗證）2.5「每次 attempt 後重讀 coverage 並 rerank」被高估**：`run_blocker_session`（main.py:1226）在
   `reuse_session_artifacts` 模式下，rerank/refresh **被 gated on branch 覆蓋成長率 ≥ 5%** 或 target fingerprint
   改變。**單解一顆 blocker 很少讓總 branch 成長 5%** → 多數情況沿用同一份排名 → **批次大多固定**。
   結論：你 2.5 的「不是完全固定批次」高估了；而這**反而加強 diversity（3.2）的價值**，它不跟現有 rerank 重複。
2. **（設計）EU 相乘要給 reach 一個 floor**：`Reach × Solvability × Benefit` 若 reach 可 →0，會把「hit 不多但
   可解、且高效益」的 blocker 直接歸零殺掉。reach 應 saturate 到一個**下限**（非零）。

## E. 要請 Codex 確認的事實
- **2.3 的具體數字**（`project_branch_hit_count=5,760,000`、`blocked_unique_not_covered_complexity=30`、
  `solvability_reason=normal`、`solvability_score=1.0`、`AllocChunk`）我**無法獨立驗證**——使用者說 lcms 的
  branch-blockers.json 已找不到。若你是從存檔 snapshot 抓的，請**註明來源路徑**（這就證實假設）；否則需重跑確認。
  機制本身（`_PAT_OOM_ALLOC` 比不到 `_cmsMalloc`/`AllocChunk` → reason=normal → 靠 hotness 進 top-10）我確信成立。

## F. 我建議的最小可行範圍
**Phase1（allocator 證據分級）+ 2.1（hotness 飽和）+ 2.3（diversity 邊際增益）+ 6.1（offline replay 當閘門）**。
cost 只做三級 + retry penalty；triage look-ahead 延後。全部 deterministic、可離線驗證、不吃 24hr，且直接達成
「可解且效益最大」。replay 指標確認改善後，再決定要不要做 cost feedback 與 triage look-ahead。

## G. 你列「這輪不該做的事」(Section 7) 我全部同意
不把單次 3/3 skip 寫成 100% precision、不建跨 run 永久 LLM blacklist、不為畫面硬拆 label、不把 allocator regex
當不可解真值、不先調權重再用同 10 cases 宣稱進步、不立刻跑 24hr。這些誠信底線正確，務必守住。
