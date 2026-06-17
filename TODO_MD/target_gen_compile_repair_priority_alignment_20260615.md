# Target-gen compile-repair：優先序對齊（給 Codex）— 2026-06-15

> 回應 `lcms_cmsDetectDestinationBlackPoint_20260615_161055` 的分析。結論：**同意你的診斷與四個方向，
> 但建議重排優先序**——最深的問題是 API 幻覺，不是 contract parser。以下是收斂版。

## 同意（已驗證）
- **runtime guard 成立**：coverage 403:2.41k → 409:2.41k → **416:0**，正確標 `predicate_state_failure`，
  沒把「編譯成功」當「解題成功」。**這是 target-gen 架構正確的證據，本身可寫進論文**（solver 以
  blocker-focused coverage 為驗收，非僅編譯）。
- 兩個 bug 真實存在：contract parse typo（`END_BLOCKE...` 少一個 R → 默默套空 fallback、甚至雙 contract）；
  repair 仍刪 constructor 改成從 fuzz input 開 profile（contract 註解還在、程式已不執行策略）。

## 重排優先序：API evidence 應為 #1（你列 #4）
**最深的問題是 API 幻覺**：LLM 產生 `cmsCreateProfileTHR` / `cmsCreateDeviceLinkTHR` 等不存在/連不到的 API；
repair 編不過就刪 constructor。

- **contract parser 修好也救不了**——就算 contract 完美，LLM 仍叫不出 lcms 真實 API，generation 與 repair 都失敗。
- **這與 seed 路徑成功原理同構**：seed 路徑當初 surface 真實 **call sites**（evidence）讓 LLM 不用猜；target 路徑
  要 surface 真實**可用 public API 簽章**（從 header / introspector）讓它不要幻覺 constructor。同一招：證據取代訓練知識。
- **順帶解 token/429**：叫對 API → repair 輪數變少 → prompt 不再膨脹到 20k–45k。但 API evidence 要**聚焦**：
  用 Strategy Contract 的 `required_state`（「建 output-CLUT profile」）**篩出相關 API 家族**（profile 建構 / intent /
  color space），不要塞整份 header。

## 收斂版 compile-repair 迴圈
1. **API evidence（#1）**：generation 與 repair prompt 注入「required_state 相關的真實可用 public API 簽章」。
2. **可行動 regression 回饋（你的 #3）**：runtime guard 拒收後，回饋「**哪個 required_state 消失**（CLUT
   constructor 被刪）」+「**這些是真實可用的替代 API**」→ repair 才有機會修對，而非再亂刪。
3. **parser hygiene（你的 #1/#2，必要但次要）**：容錯結尾拼字 / 解析整段 comment；缺失或格式錯 → 標
   `contract_parse_error`，**不得默默套空 fallback**。
4. **repair 驗收 = 你說的三條**：compile ok + Strategy Contract 仍成立 + blocker coverage 無退化；其中
   **第 3 條（runtime）是確定性主守門員**，1/2 當引導。
5. **bounded replan**：找不到語意等價 API → `strategy_replan_required` 交回 generator，設 max replans 避免 runaway。

## 誠實的範圍提醒
target-gen 是**較難的一半**（產生正確 C code：對的 profile API + header intent + curves，比 seed 的 filter 字串難）。
現在多問題疊加（API 幻覺 + repair 退化 + parser + token/429），**不保證此 case 合理時間內收斂**。
- seed 路徑（libpcap）是**已到手的穩結果**；runtime guard 成立已是 target-gen 的架構結果。
- 建議：**做一次聚焦修正**（API evidence + 可行動 regression 回饋 + parser hygiene）→ **跑一次** →
  解開＝target-gen 驗證成功；解不開＝documented limitation，不再 grind。

## 想請 Codex 對齊
1. 同意把 **API evidence 提到 #1**（parser hygiene 次要）嗎？理由：parser 修好但 API 仍幻覺則無解。
2. API evidence 來源用 **header 簽章 grep** 還是 **introspector get_all_functions**？哪個對 lcms 較可靠、且容易用
   `required_state` 篩家族？
3. 「runtime guard 拒收 → 回饋消失的 required_state + 真實替代 API」這個 closed-loop，是否在你現有 repair
   架構容易接？
4. 同意「聚焦修正 → 只跑一次 → 不解開就 documented limitation」的硬停損嗎？
