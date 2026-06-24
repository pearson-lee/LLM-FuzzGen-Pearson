# Blocker Triage 系統：成效、標籤分類與設計評估（送 Codex 評估）

> 目的：請 Codex 評估本文的「事實正確性、技術分類合理性、設計提案可行性」。
> 文中所有程式碼引用為 repo 相對路徑，實測數據來自 `experiments/20260615_235134_run_all_fuzzer`（lcms）。
> 日期：2026-06-20。

---

## 0. 一句話背景

系統會在覆蓋率停滯時挑出一批「blocker（卡住的分支）」嘗試突破。`triage` 是一層 LLM 判斷，
決定某個 blocker 的條件式是「可用輸入/harness 生成解開（→ 跑 solver）」或「防禦性/不可解（→ 跳過）」，
目的是別把昂貴的 solver 預算浪費在記憶體配置失敗、內部斷言等本就無法用輸入觸發的程式碼上。

---

## 1. 實際流程順序與成本模型（已對照程式碼）

```
覆蓋率停滯 → global_blocker_selector 選一批 top-k
          → classifier（先跑，LLM）→ triage（後跑，LLM）→ solver dispatch
```

- **選批次（便宜、靜態）**：`blocker_process/global_blocker_selector.py`
  `score = (actionability + impact) × solvability_score`（global_blocker_selector.py:546）。
  `solvability_score` 已會降權防禦碼：abort/assert/trap=0.15、OOM null-check=0.25、flex/bison parser state=0.20
  （global_blocker_selector.py:19-33, 106-166）。
- **classifier 先跑**（blocker_process/blocker_classifier.py:881-930）：產出
  `dependency_result`（Input Dependent / Input Independent）與 `reason`。
- **triage 後跑**（blocker_process/blocker_classifier.py:965-1009）：
  `run_triage_for_classifier(args, result, dependency_result, reason)` 把 classifier 結果當輸入，
  做可解/不可解判定與路由；有 classifier 衝突檢查與 `classifier_agreement`（agree/disagree）。
  triage 是 classifier 之後的「第二意見＋路由閘門」，**非前置 pre-filter**。
- **成本模型**：開 triage＝每 blocker 在 classifier 1 次 LLM call 外，再 +1 次 triage LLM call；
  省下的是後面昂貴的 solver pipeline（reference_guided / dedicated / symcc）。**不省 classifier 成本。**

### 路由與證據契約（決定性，非 LLM 任意決定）
- label → 路由表為固定對應（blocker_process/blocker_triage.py:38-50）。
- 證據契約：即使 LLM 標了可解 label，若 `producer_path_status != proven` 或 `practical_feasibility` 不符，
  會被降級為 `Inconclusive`（blocker_triage.py:484-505）。
- `Inconclusive` 採 **fail-open**：仍送 solver，避免誤殺。

---

## 2. 實測成效（lcms run，10 個 blocker）

| 結果 | 數量 | 說明 |
|---|---|---|
| 被 triage 跳過（skip_solver） | 3 | 全部經原始碼查證為真實防禦碼，無誤殺 |
| 跑 solver | 7 | 5 成功、2 失敗 |

### 2.1 三個被跳過的 blocker（逐一對照原始碼，判斷正確）

| Blocker | Label | 原始碼真相 | 證據 |
|---|---|---|---|
| `_cmsContextGetClientChunk:769` | Internal Invariant Guard | `if ((int) mc < 0 \|\| mc >= MemoryClientMax)` → "Bad context client -- possible corruption"。`mc` 在所有呼叫端都寫死成 `MemPlugin` 列舉值，輸入無法越界 | external/oss-fuzz/build/out/lcms/source_code/src/cmsplugin.c:769 |
| `AddToList:1274` | Resource-Exhaustion Guard | `if (p == NULL) SynError("AddToList: out of memory")`，`AllocChunk` 回傳 NULL 的 OOM 防護 | .../src/cmscgats.c:1274 |
| `cmsWriteTag:1869` | Resource-Exhaustion Guard | `if (Icc->TagPtrs[i] == NULL)`，`DupPtr` 對寫死的 MLU 物件配置失敗才會 NULL | .../src/cmsio0.c:1869 |

三者皆 `evidence_strength=A`、`evidence_contract_satisfied=true`、classifier 一致同意；
`pipeline_methods=[]`、`failure_stage=triage` 確認確實省下了 solver 執行。

### 2.2 昨天 10 筆實際 label 分布
- Actionable Target Gap ×4、Inconclusive ×3、Resource-Exhaustion Guard ×2、Internal Invariant Guard ×1。
- `Bounded Extreme Value` 0 筆（故本文主張：勿為視覺平衡硬拆出空殼可解類別）。
- 3 筆 Inconclusive 都是「LLM 想標可解、但 producer_path 未達 proven 被降級」，靠 fail-open 仍跑 solver，**最後全部解出**。

**小結**：triage 在此 run 精確跳過 3 個防禦碼（精確率 100%、無誤殺），同時靠 fail-open 保住 3 個證據不足但實際可解的 blocker，未犧牲召回。

---

## 3. Triage 標籤輸出規格表

10 個 `refined_triage_label` → 3 個第一層決策（Generation-solvable / Non-generation-solvable / Inconclusive）→ 2 個動作。

| # | Label | 代表意涵 | 可解/不可解（動作） | 文獻 |
|---|-------|---------|--------------------|------|
| 1 | Actionable Target Gap | 分支可達，但現有 harness 沒走到能建構該狀態的 API 路徑；合法 producer 路徑存在（producer_path_status=proven）。改/生 fuzz target 即可達（input-independent） | ✅ 可解（run_solver） | [A] |
| 2 | Bounded Extreme Value | 分支由 input 控制，需特定/極端輸入值才會走到（input-dependent） | ✅ 可解（run_solver） | [B] |
| 3 | Resource-Exhaustion Guard | 防護 malloc/記憶體配置失敗（OOM）的錯誤處理碼，輸入無法控制 | ❌ 不可解（skip_solver） | [C] |
| 4 | Environmental Failure | 由系統呼叫/函式庫失敗觸發的錯誤處理碼（非輸入可控） | ❌ 不可解（skip_solver） | [C] |
| 5 | Internal Invariant Guard | 針對內部 corruption 的防禦斷言；合法輸入不可能違反該不變量 | ❌ 不可解（skip_solver） | [C][E] |
| 6 | Generated Parser State | 需 parser/lexer（bison/flex）生成的內部狀態（如 error-recovery） | ❌ 不可解（skip_solver） | [B][D] |
| 7 | Structurally Unreachable API Path | 不存在任何合法 API 路徑能構造出該狀態（producer_path_status=contradicted） | ❌ 不可解（skip_solver） | [A] |
| 8 | Infeasible Counter Overflow | 需內部計數器溢位/wrap 才會走到，預算內不可行（UNSAT/不可行約束） | ❌ 不可解（skip_solver） | [D] |
| 9 | Crash-Revealing Path | 在觀測到目標分支前程式就先 crash（runtime 證據） | ❌ 不可解（skip_solver） | [C] |
| 10 | Inconclusive | 證據不足；保守採 fail-open 仍送 solver，避免誤殺 | ⚠️ 證據不足（run_solver） | — |

**Meta 觀點（方法論貢獻）**：triage 的兩個證據欄位正好對應文獻的兩條可達性軸——
`producer_path_status`(proven/contradicted) = harness 可達性軸（可解① vs Label 7）；
`practical_feasibility`(practical/resource_failure/environmental/infeasible/internal_invariant/crash_before_observe)
= 可行性軸。系統把文獻的兩條軸 operationalize 成可機器判定欄位。

---

## 4. 文獻對照（含 NotebookLM 核對）

可解面對應系統的兩條 solver pipeline（兩條獨立文獻線），不可解面分三超類別。

- **[A] Fuzz driver/harness 生成（input-independent；可達性取決於 API 序列而非 input）**
  → Label 1（可解）/ Label 7（反面，不可達）。
  UTopia（從 unit test 提取合法 API 序列、避免 spurious crash）、Hopper（interpreter 模式補未走到的 API 路徑）、
  WildSync（從外部程式碼補 API 路徑）、IntelliGen、Prompt Fuzzing(LLM)、
  Fuzz Driver Synthesis for Rust Generic APIs（Zhang et al., 2023，建立於 RULF；定義 Reachable API / Valid API Sequence，
  部分 API 因無法實例化而不可達）。

- **[B] Input-dependent / taint・約束求解** → Label 2、Label 6。
  SIVO（輕量符號區間推理、處理整數不等式約束＝Label 2 找極端值翻轉分支）、
  Matryoshka（深層巢狀分支、梯度下降；點名 parser 分支順序影響內部狀態＝Label 6）。

- **[C] 錯誤處理碼由偶發系統錯誤觸發、需 SFI（軟體故障注入）而非 input generation** → Label 3/4/9。
  FIFUZZ、EH-Fuzz（明確區分「輸入相關錯誤」vs「偶然錯誤(OOM/網路失敗)」，須以 SFI 觸發；
  Label 9 對應「分支到達前先 crash → 無法做有效錯誤變異分析」）。

- **[D] 不可行路徑（迴圈相關 / 約束矛盾 UNSAT）** → Label 8（亦關聯 Label 6）。
  LDEP（loop-dependent 等式約束是路徑不可行主因）、IPEG（loop counter 未增至目標值→UNSAT，erfill 例）。

- **[E] 防禦/斷言碼背景** → Label 5。
  Analyzing Impact of Coverage Metrics in Greybox Fuzzing (RAID'19)。⚠️ 連結較廣泛（主軸是 seed/覆蓋率指標），
  Label 5 引用時宜補更直接的斷言/不變量文獻。

### NotebookLM 核對結果（2026-06-16，對使用者的 13 份來源）
- 整體技術分類與來源「高度吻合」；[C] 類（Label 3/4/9）核對為「非常精確」。
- **修正**：先前稱「RuMono」應以正式標題「Fuzz Driver Synthesis for Rust Generic APIs」為準（建立於 RULF）。
- **注意**：Label 10(Inconclusive) 是工程 fail-open 慣例，**文獻無此標籤命名**；DSE 工具於 solver 超時/證據不足時
  普遍採「不排除路徑」的保守做法可作支撐。
- 書目鍵值（Source 編號、EH-Fuzz/LDEP/IPEG 等簡稱）以 NotebookLM 來源為準；下方 URL 為 web 搜尋所得，需逐一對齊。

### 參考 URL（web 搜尋所得，待與 NotebookLM 來源對齊）
- UTopia — https://ieeexplore.ieee.org/document/10179394/
- Hopper: Interpretative Fuzzing for Libraries — https://arxiv.org/pdf/2309.03496
- IntelliGen — https://arxiv.org/pdf/2103.00862
- WildSync (ISSTA'25) — https://futures.cs.utah.edu/papers/25ISSTA.pdf
- Prompt Fuzzing for Fuzz Driver Generation — https://arxiv.org/pdf/2312.17677
- Fuzz Driver Synthesis for Rust Generic APIs — https://arxiv.org/html/2312.10676v2
- Matryoshka (CCS'19) — https://www.cs.ucdavis.edu/~hchen/paper/chen2019matryoshka.pdf
- Refined Grey-Box Fuzzing with SIVO — https://arxiv.org/pdf/2102.02394
- FIFUZZ (USENIX Sec'20) — https://www.usenix.org/system/files/sec20-jiang.pdf
- Testing Error Handling Code with SFI (TDSC'23) — https://jzuming.github.io/paper/tdsc23-bai.pdf
- EH-Fuzz（疑為，待確認） — https://ieeexplore.ieee.org/document/10589809/
- Infeasible Path Detection (MPE'20) — https://www.hindawi.com/journals/mpe/2020/4258291/
- Infeasible Path Generalization in DSE — https://www.sciencedirect.com/science/article/abs/pii/S0950584914001803
- Analyzing Impact of Coverage Metrics in Greybox Fuzzing (RAID'19) — https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf

---

## 5. 已知設計議題與提案（請 Codex 評估）

### 5.1 議題：triage「skip→排序」在批次架構下成效存疑
- 現況：selector 用便宜靜態分先選一批 top-k，triage 跑在選批次「之後」，且該批會全部跑完。
- 後果：triage 的「降權/排序」只能在已選批內重排，無法回頭換進更好的 blocker；若整批跑完，批內排序無意義。
- 另一層顧慮：selector 分數會隨求解過程的覆蓋率變動而漂移，加入 triage 訊號後優先序可能不穩。

### 5.2 提案：把 triage 判定寫入「乘法通道」+ 持久化回饋
- `score = (actionability + impact) × solvability_score`：會漂移的是加法項，`solvability_score` 是乘法項。
- triage 判「不可解」是 blocker 的穩定性質（與覆蓋率無關），寫進 `solvability_score`（趨近 0）→
  不論加法項怎麼漲，乘積維持在底部、優先序不彈回。
- **兩段式**：
  - 高信心（evidence_strength=A 且 evidence_contract_satisfied 的 non-solvable）→ 加入持久排除集
    `triage_excluded_keys`，比照 `attempted_blocker_keys`（main.py:1517-1519）過濾，永久不再選入。
  - 低信心 / Inconclusive → 只乘懲罰係數（soft），保留召回（覆蓋率讓它變有價值時仍可回來）。
- 需新增 `experiments/<run>/triage_verdicts.jsonl`（key 用 `_blocker_identity`）做持久化與回饋。

### 5.3 待 Codex 回答的問題
1. 第 1–2 節對程式碼流程/成本模型的描述是否正確？有無誤讀 selector/classifier/triage 的相對位置？
2. 第 3 節「10 label → 3 決策 → 2 動作 + 證據契約」是否與 `blocker_triage.py` 實作一致？
3. 第 4 節文獻分類是否合理？是否有 label↔文獻的錯配或過度延伸（特別是 [E] 與 Label 6 跨 [B][D]）？
4. 第 5.2 提案（乘法通道 + 持久排除集 + verdicts 回饋）是否健全？是否有更簡單或更穩健的做法？
   特別是「分數隨覆蓋率漂移」與「triage 訊號穩定」之間的互動處理是否正確？
5. 是否有遺漏的失敗模式（例如 triage false-positive 把可解 blocker 永久排除的風險如何界定門檻）？
