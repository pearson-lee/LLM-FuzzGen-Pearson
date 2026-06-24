# SymCC seed budget：改成 oracle 驅動收集（收斂版）— 2026-06-24

> 狀態：**已與 Codex 收斂**。核心＝用「線上 oracle + 命中即停 + 分級 retention + candidate/deadline 雙預算 +
> stratified sampling」取代目前的 arrival-order 硬截斷。下含 Codex 三修正、batch 粒度釐清、與一個 input-side 小補。

## 1. 已查證的根因（symcc_blocker_solver.py 生成迴圈 ~789–858）
- 一個數字 `max_total_seeds`(=60) 同時當「處理上限」與「保留上限」。
- 每顆起始 seed 跑 SymCC 後，`new_outputs = sorted(...)` **按檔名序**收進 corpus，**達 60 就 `break` 丟掉其餘**（848–849）。
- **迴圈內完全沒有 coverage replay**；replay（`evaluate_seed_with_coverage`）是**之後**才對「活下來的 ≤60 顆」逐一跑。
- 致命點：blocked-side oracle **只作用在「按檔名序活下來的 60 顆」**；解題候選若排在後面，在檢查前就被丟，永遠沒被 replay。

## 2. SymCC 實際運作的粒度（重要，先講清楚）
- **「生」＝跑一次 SymCC ＝ 餵「一顆」起始 seed**；但**一次執行會一口氣吐出一整批候選**（可能上百顆），數量由 SymCC 決定、無法控制成「只生一顆」。
- **「檢查」＝replay 一顆候選**（跑 coverage 看是否到 blocked side）＝**另一個動作、另一支程式**。
- 所以「邊生邊檢查」**不是**叫 SymCC 一次只生一顆，而是：**SymCC 吐出一批後，先檢查這一整批，而不是先按檔名砍到剩 60。**

## 3. 解法（oracle 驅動收集）
把「丟掉誰」的依據從 **arrival order** 改成 **「replay 試了開不開」**，並把混用的一個數字拆成**兩個獨立預算**：

| | 意義 | 建議初值 |
|---|---|---|
| **candidate eval budget** | 這一輪願意 replay（檢查）幾顆候選＝搜尋廣度 | 200（數量上限） |
| **next-generation retention** | 留幾顆當下一代起始 seed＝下一輪原料 | 60（純防爆量） |
| **total search deadline** | 每個 blocker 的總時間上限（最終保護，replay 成本因 target 而異） | 300 秒 |
| **initial frontier cap** | 第一代最多幾顆起始 seed | 30 |
| **max generations** | 最多幾代 | 3 |

每一代流程：
1. 對 frontier 內每顆起始 seed 跑一次 SymCC，**收集所有 unique outputs**（一整批，可能很多）。
2. **若該批 outputs > eval budget → 對「完整序列」做 deterministic stratified sampling**（含頭/中/尾），**不可只取前 200**
   （否則只是把「前 60 截斷」換成「前 200 截斷」，同一個 arrival-order bug）。
3. **逐顆 coverage replay**（`evaluate_seed_with_coverage` 一次同時回傳 branch 與 blocked-side hit，不需另做輕量預篩）。
4. **任一顆 `blocked_side_hit > 0` → 立即 export + early-exit 成功**（要的就是那一顆，找到就停，不必再跑後續 generation）。
5. 沒命中 → 依**分級 retention** 挑 ≤60 顆當下一代起始 seed（見 §4），其餘淘汰。
6. 直到：命中（成功）／eval budget 用完／**deadline 到**／generation 達上限／無新 seed。

**可複用既有元件**：`evaluate_seed_with_coverage`（~866，一次給 branch+blocked-side 兩個 count）、既有 branch-reach + `break`
pattern（OSS-Fuzz supplement ~1119/1125）。

## 4. Codex 三修正（已併入）
1. **不是所有起始 seed 都驗過到 branch**：進 SymCC 的 seed 來自 LLM 推薦 + focused fuzzing +（僅 corpus 稀疏<4 時的）
   branch-reaching supplement → **LLM 與 focused seed 未驗到 branch**。所以不能假設「餵的都是 branch-reaching」。
2. **「餵 branch-reaching seed＝directed」說太滿**：正確說法是 **target-conditioned starting seed**——它決定**從哪裡**開始
   探索，但 SymCC（QSYM backend）仍翻轉路徑上**所有 interesting 的 symbolic branch**，不是只處理 blocker predicate。
3. **不可「只留 branch-reaching、其餘全淘汰」**（太激進，會丟掉墊腳石）。**分級 retention 排序**：
   - `blocked_side` reaching → 立即成功
   - `branch` reaching → 優先保留
   - coverage unknown → 保守保留
   - non-branch-reaching → **有剩餘空間才保留**（可能是「下一代才走得到」的 stepping stone）

## 5. 我的小補（input-side，選配，方向一致）
Codex 修了 **output 側**（收哪些 candidate）；既然 §4-1 顯示起始 seed 不一定到 branch，**初始 frontier（30 顆）也可先用同一
oracle 驗一次、優先排 branch-reaching**（用同樣的分級邏輯，一樣別 discard stepping stone）。30 顆 replay 在 lcms ≈ 1 秒，極便宜。

## 6. 誠實邊界
- **任何有限 budget 都不保證找到解**。constraint 可能語意/結構上難解（`LabK2cmyk=_cmsReadInputLUT(profile)`，profile 由
  fuzz bytes 解析），或 negate 出的 bytes concretize 回去非合法 profile（mismatch）。stratified sampling **減少** arrival-order
  偏差但**不消除**「有限搜尋可能漏掉後面的解」。
- 論文措辭：**bounded best-effort search**，報「在 eval budget / deadline 內是否找到 blocked-side-reaching seed」，不宣稱完備。
- stratified 的效益視 SymCC output 檔名是否帶順序意義而定（hash 命名→近隨機；sequential→時間覆蓋）；安全的預設，實作時確認。

## 7. 這輪不做（避免發散）
- 輕量 branch prefilter（既有 oracle 一次就給兩個 count，不需要）。
- 改 SymCC runtime 加 target branch / directed concolic。
- grammar-aware symbolic model。
- AST/CFG distance ranking（挑「離 blocker 最近的 output」優先；stratified sampling 是它的務實替代）。

## 8. 一句話
把「**先按檔名序砍到 60、之後才 replay**」改成「**SymCC 吐一批就 replay 一批（太多用 stratified 抽）、命中即停；要丟的時候按
『有沒有接近解』分級丟，不是按檔名丟**」，並把「檢查幾顆」與「留幾顆養下一代」拆成兩個預算、外加 deadline 當最終保護。
