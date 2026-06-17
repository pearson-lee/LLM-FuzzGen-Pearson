# Minimal Ground-Truth Protocol for Blocker Triage

這份文件的目的不是建立完整 ground truth，而是提供一個可在論文中防守的 minimal protocol，用來區分哪些 uncovered branch side 適合納入 solver evaluation，哪些只是程式例外處理、環境失敗、resource guard 或 generated-code artifact。

## 核心立場

本研究不假設所有 uncovered blocked side 都是有效的 input-generation target。原始 blocker selection 只代表「某個 branch side 在目前 fuzzing run 中未被覆蓋」，不代表該 side 一定能透過合理 input 觸發。

因此，在評估 solver 前，先對 blocker 做 source-level triage。這個 triage 是 operational ground truth：標註依據是可重複檢查的 source code dataflow、producer domain、runtime hit count、pipeline outcome，而不是人工主觀猜測。

## Case Selection Scope

case selection 必須先定義 population，再做標註，不能事後只挑看起來有趣或容易解釋的例子。

本研究建議使用以下順序定義 case set：

1. **candidate population**：由 `global_blocker_selector.py` 在固定 experiment run 中選出的 coverage-stalled blockers。
2. **pipeline-audited set**：實際進入 blocker pipeline，且有 `blocker_pipeline_started` 與 `blocker_pipeline_result` 紀錄的 blockers。
3. **triage set**：對 pipeline-audited set 全部做 minimal triage，不因為 classifier 原始標成 `Input Dependent` 或 `Input Independent` 而排除。
4. **solver-evaluation set**：只從 triage set 中取 `Actionable Target Gap` 與 evidence `A/B` 的 `Bounded Extreme Value`。

以 `experiments/20260612_020723_run_all_fuzzer` 為例，session selection event 中曾列出 10 個 selected blockers，但實際有 pipeline result 的是 9 個。因此這 9 個適合定義為該 run 的 pipeline-audited triage set；沒有 pipeline result 的 selected blocker 不應混入 solver outcome 統計，但可以在實驗限制中說明。

這 9 個 case 可以用來做完整 failure/triage audit，證明 broad selector 會挑到不少 non-actionable blockers。不過它們不應被描述成「所有 blocker 的完整 ground truth」或「隨機代表樣本」。若論文要主張方法對 actionable blocker 有效，主結果應只統計 triage 後的 solver-evaluation set。

## Scope of Triage

triage 必須套用在 `Input Dependent` 和 `Input Independent` 兩類 blocker 上。

`Input Dependent` 只表示 blocked predicate 與 input 或 input-derived state 有關，不代表它可被實務解出。例子包括 resource exhaustion、counter overflow、generated parser recovery state，這些都可能是 input dependent，但不適合作為一般 seed-generation 成功目標。

`Input Independent` 也不等於沒救。有些 input-independent blockers 是環境失敗或 allocator failure，應排除；但也有些是 target/harness design gap，例如缺少初始化、缺少設定函式、缺少 call sequence、使用錯誤 API 入口。這類反而可能是 fuzz target generation 應該處理的對象。

因此，dependency classifier 的角色是決定後續 solver strategy 的參考，不是決定 blocker 是否值得解的 ground truth。是否納入 solver evaluation，要由 refined triage label 決定。

## 兩層分類

triage 先不要從細 label 開始想，先做第一層大分類：這個 blocker 要不要安排進 solve pipeline。

| 第一層分類 | 意義 | 是否進 solve pipeline |
|---|---|---:|
| `Generation-solvable` | 這類 blocker 的 blocked side 可望透過合法 fuzz target、seed、call sequence、target configuration 或 bounded input value 達成。它不保證 solver 一定成功，但它是合理的求解目標。 | Yes |
| `Non-generation-solvable` | 這類 blocker 需要記憶體配置失敗、resource exhaustion、系統環境失敗、internal invariant violation、generated parser/scanner 內部狀態、不可實務 counter overflow、或 crash 才能觀察。這不是一般 target/seed generation 應該解的問題。 | No |
| `Inconclusive` | 目前 source/runtime evidence 不足，不能可靠判定是否可由 target/seed generation 解。 | No, until evidence is sufficient |

第二層 refined label 只是說明「為什麼」它屬於上面哪一類：

| 第一層分類 | 第二層 refined label |
|---|---|
| `Generation-solvable` | `Actionable Target Gap`, `Bounded Extreme Value` |
| `Non-generation-solvable` | `Resource-Exhaustion Guard`, `Environmental Failure`, `Internal Invariant Guard`, `Generated Parser State`, `Structurally Unreachable API Path`, `Infeasible Counter Overflow`, `Crash-Revealing Path` |
| `Inconclusive` | `Inconclusive` |

這裡的「不可解」不是數學上絕對不可達，而是指 **不屬於本研究的正常 target/seed generation 求解範圍**。例如 allocator fault injection、patch library、降低內部 limit、或用 debugger 操作 internal state 也許能讓某些 blocked side 被 hit，但那不是本文的 solve pipeline。

相反地，「可能可解」也不是保證 solver 一定成功，而是指它符合本文方法的求解假設：缺的是 target 設計、call sequence、target config、seed 結構，或合法但極端的 input value。

## Minimal Evidence Requirements

每個 blocker 至少檢查四項：

1. **Runtime evidence**：branch line 是否真的被執行，blocked side 是否為 0。
2. **Producer evidence**：predicate 變數由誰產生，值域是否可由 input 合理控制。
3. **Survival evidence**：input-derived value 是否能一路活到 blocked predicate，中途是否會被重設、abort、或轉成固定 state。
4. **Feasibility evidence**：觸發 blocked side 是否需要 OOM、fixed-size allocation failure、counter wraparound、internal invariant violation 或 target crash。

只有同時滿足以下條件的 case 才納入 solver evaluation：

- predicate value 或 required semantic state 可由 input 或 parsed input structure 合理控制；
- required value 位於合法、bounded、可實務達成的 domain；
- 不依賴 malloc/calloc failure、system API failure、UINT overflow、internal defensive abort；
- 不要求 target crash 才能觀察路徑；
- current API path 沒有固定把該 side 變成 unreachable；若 current path 確實不可達，必須額外證明存在合法 alternative public API path 或 call sequence，才可納入 target-generation evaluation；
- classifier 能說清楚 target/seed/harness 目前缺少的具體條件。

## 實際標註流程

標註時不要一開始就問「它是 input dependent 還是 input independent」。那個分類太粗，容易把 resource failure、parser internal state、target gap 混在一起。實際流程應該是先確認 blocked side 的真實觸發條件，再判斷它是否可由 target/seed generation 合理達成。

每個 case 依序做以下 6 步：

1. **建立 case 摘要**

   記錄 `source_file`、`branch_line_number`、`blocked_side_line_number`、branch condition、classifier 原始 label、classifier reason、目前 pipeline 結果。這一步只整理事實，不下結論。

2. **確認 runtime 狀態**

   檢查 branch line 是否被目前 project target 執行過，以及 blocked side hit count 是否為 0。若 branch 沒被執行，這不是 stalled-at-branch case；若 blocked side 已被打到，這不是未解 blocker。

3. **還原 blocked predicate**

   回到 source code 看 branch condition，明確寫出「要進 blocked side 必須滿足什麼」。不要只寫「需要特殊 input」，要寫成具體條件，例如 `yy_fill_buffer != 0`、`ptr == NULL`、`yyerrstatus == 3`、`cstate->is_geneve == 1 && later link-layer check occurs`。

4. **追 producer/dataflow**

   對 predicate 裡的關鍵變數往回追來源：它是來自 input bytes、parser semantic state、target function argument、global/config state、allocator return value、generated parser state，還是 internal counter。這一步決定它是不是 input/target 可以控制。

5. **檢查 survival / API path**

   檢查 current harness/API path 是否會固定初始化、覆寫、重設或封住該 state。若 current path 固定把 predicate 設成不可達值，先記為 current-path issue；接著確認是否存在合法 alternative public API path、target configuration 或 call sequence。若存在，歸到 target-design 類的 `Actionable Target Gap`；若不存在，才標成 `Structurally Unreachable API Path`。

6. **判斷 feasibility 與 label**

   若 blocked side 需要 malloc/calloc 失敗、system API failure、固定大小 allocation failure，標 `Environmental Failure` 或 `Resource-Exhaustion Guard`。若需要 internal assert/abort 的不合法狀態，標 `Internal Invariant Guard`。若需要 Bison/Flex recovery/scanner internal state，標 `Generated Parser State`。若需要 counter wraparound 或不可實務配置的巨大結構，標 `Infeasible Counter Overflow`。若 target 會先 crash 導致 coverage 無法穩定觀察，標 `Crash-Revealing Path`。若 current API path 固定不可達，但可找到合法 alternative public API path 或 call sequence，應改視為 target-design 類的 `Actionable Target Gap`；若找不到合法替代 path，才標 `Structurally Unreachable API Path`。只有在條件能由合法 input、seed structure、target call sequence、target config 或 bounded value 達成時，才標 `Actionable Target Gap` 或 `Bounded Extreme Value`。

最終輸出至少要有這些欄位：

```text
case
original_dependency_label
refined_triage_label
evidence_strength
include_in_solver_evaluation
core_evidence
main_risk_or_note
```

`include_in_solver_evaluation` 的規則要固定：只有 `Actionable Target Gap` 和 evidence `A/B` 的 `Bounded Extreme Value` 可以填 `yes`。其他類別不是 solver failure，而是 non-actionable blocker，應放在 taxonomy、error analysis 或 threats to validity。

## Label 與可求解性

triage label 的目的不是只描述 blocker 長什麼樣子，而是決定它是否屬於 generation-solvable blocker。solver evaluation 只應評估 generation-solvable blockers；non-generation-solvable blockers 不應計為 solver failure，而應計為 triage outcome。

| Label | 代表意義 | Generation-solvable? | Solver evaluation |
|---|---|---:|---:|
| `Actionable Target Gap` | 現有 target、seed 或 harness 沒有建立正確語意狀態，但合法 input、call sequence、target config 或 seed structure 可以達成 blocked side。 | Yes | Yes |
| `Bounded Extreme Value` | 需要極端但合法、有限、可實務產生的 value 或 structure，例如最大合法 length、深但有限的 nesting、特定 flag combination。 | Conditional Yes | Yes, if bound is explicit and feasible |
| `Resource-Exhaustion Guard` | input 會增加資源需求，但 blocked side 本質是 malloc/calloc failure、chunk exhaustion 或 resource exhaustion。 | No, not by normal target/seed generation | No |
| `Environmental Failure` | blocked side 取決於固定大小 allocation failure、system API failure 或外部環境狀態。 | No | No |
| `Internal Invariant Guard` | blocked side 是程式防守理論上不該發生的內部非法狀態，例如 defensive `abort()`。若能由合法 public API path 建立該狀態，應改標 `Actionable Target Gap`。 | No | No |
| `Generated Parser State` | Bison/Flex generated parser/scanner 的 internal recovery/refill state，例如 `yyerrstatus` 或 `yy_fill_buffer`。若能證明有合法 parser/scanner state sequence，應改標 `Actionable Target Gap` 或 `Bounded Extreme Value`。 | No | No |
| `Structurally Unreachable API Path` | 目前 target/API path 固定把 predicate 設成不可達值，且尚未找到合法 alternative public API path 或 call sequence。若找到合法替代 path，應改標 `Actionable Target Gap`。 | No | No |
| `Infeasible Counter Overflow` | 理論上受 input 結構大小影響，但需要整數 wraparound 或不可實務配置的巨大資料結構。 | No in practical fuzzing setting | No |
| `Crash-Revealing Path` | input 可能導向相關路徑，但 target/library 先 crash，導致 coverage 無法穩定觀察。 | Not evaluated as normal solver case | No; discuss separately |
| `Inconclusive` | source 或 runtime evidence 不足，無法可靠判斷可求解性。 | Unknown | No |

因此，實驗章若要回報「求解正確率」或「solver success rate」，分母應是 solver-evaluation set，而不是 selector 挑出的所有 coverage-stalled blockers。所有 non-generation-solvable cases 應回報在 triage analysis 中，表示系統辨識出方法邊界，而不是求解失敗。

### `Bounded Extreme Value` vs `Infeasible Counter Overflow`

這兩類都可能看起來像「需要很大的值」，但判斷標準不同。

`Bounded Extreme Value` 是 generation-solvable：blocked side 需要極端但合法、有限、可在正常 fuzzing budget 內實務產生的 input value 或結構。重點是 required bound 必須可明確描述，而且不需要整數 overflow、allocator failure、修改 library limit 或建構不可實務的大型內部資料結構。

`Infeasible Counter Overflow` 是 non-generation-solvable：blocked side 只有在 unsigned counter wraparound、近 `UINT_MAX` 次遞增、或需要先成功配置不可實務數量的內部資料結構時才會出現。這類雖然可能和 input 結構大小有語意關係，但不是正常 target/seed generation 應該求解的目標。

簡單判斷：

```text
需要一個很大但有限、可跑完的合法 input 結構
=> Bounded Extreme Value

需要 UINT_MAX overflow、不可實務配置量、或超出正常 fuzzing budget 的內部 counter 狀態
=> Infeasible Counter Overflow
```

論文可使用這個定義：

> We evaluate solving accuracy only on blockers classified as generation-solvable. Non-generation-solvable blockers are not counted as solver failures; they are reported as triage outcomes that define the boundary of target/seed generation.

中文寫法：

> 本研究只在 triage 後判定為 generation-solvable 的 blocker 上評估求解正確率。對於環境失敗、資源耗盡、內部 invariant、generated parser state、結構性不可達 API path 等 blocker，本文不將其計為 solver failure，而是作為 triage 結果與方法邊界討論。

## Labels

### `Actionable Target Gap`

input 合理可控，但現有 target、seed 或 harness 沒有建立正確語意狀態。這類是主要 evaluation target。

例子：需要先設定 protocol context，再接續 inner protocol predicate；或 target 把 input 切錯，導致有效語法永遠沒被餵到 API。

### `Bounded Extreme Value`

需要極端但合法、有限、可實務達成的 input value 或 structure。這類可納入 evaluation，但必須說明 bound。

例子：最大合法 length、深但有限的 nesting、特定 enum / flag combination。

### `Resource-Exhaustion Guard`

input 會放大資源需求，但 blocked side 本質是 malloc/calloc failure、chunk exhaustion 或其他 resource exhaustion。這類不應作為一般 seed-generation 成功目標。

### `Environmental Failure`

blocked side 由固定大小 allocation failure、system API failure 或外部環境決定。這類排除。

### `Internal Invariant Guard`

blocked side 是程式用來防守「理論上不該發生」的內部狀態，例如 defensive `abort()`。如果 input 無法透過合法 public API 產生該 internal state，排除。

### `Generated Parser State`

Bison/Flex generated code 的 internal state，例如 `yyerrstatus`、`yy_fill_buffer`。除非能證明 current API path 中有可達的 parser/scanner state sequence，否則不納入主要 evaluation。

### `Structurally Unreachable API Path`

current public API path 固定把 predicate 設成某個值，使 blocked side 在此 path 下不可達。這類不能直接算 seed solver failure。

若能找到另一個合法 public API、target initialization、target configuration 或 call sequence 讓該 predicate 可達，這個 case 應改歸到 target-design 類的 `Actionable Target Gap`，並可納入 target-generation evaluation。若只能透過操作 internal generated-code state、private scanner buffer、fault injection 或 patch library 才能觸發，則維持 `Structurally Unreachable API Path`，不納入一般 solver evaluation。

### `Infeasible Counter Overflow`

理論上受 input 結構大小影響，但需要整數 counter wraparound 或不可實務配置的資料結構數量。這類排除。

### `Crash-Revealing Path`

input 可能進入 blocked path 附近，但 target 自身 crash 導致 coverage 無法可靠寫出。這類不算普通 solver failure，應獨立討論。

### `Inconclusive`

source 或 runtime evidence 不足。保守做法是不納入主要 solver evaluation。

## Evidence Strength

- `A`：source-level producer domain 清楚，runtime evidence 完整，結論穩定。
- `B`：source-level 結論清楚，但部分路徑仍依賴推論。
- `C`：只有 runtime 或 pipeline 現象，source proof 不足。

論文主結果只應納入 evidence `A` 或 `B` 的 `Actionable Target Gap` / `Bounded Extreme Value`。其他類別可放到 taxonomy 或 threats to validity。

## Suggested Thesis Wording

> We do not treat every uncovered branch side as a valid target for input generation. Before solving, each blocker is assigned an operational triage label based on source-level dataflow audit, producer-domain analysis, and runtime validation. This separates actionable target-design gaps from environmental failures, resource-exhaustion guards, internal invariants, and generated parser/scanner artifacts.

中文論述可以寫成：

> 本研究不將所有未覆蓋 branch side 都視為適合 input generation 的目標。在求解前，我們根據 source-level dataflow、producer domain 與 runtime validation 對 blocker 進行 operational triage，用以區分真正可由 target 或 seed 設計改善的 semantic blocker，以及環境失敗、資源耗盡、內部 invariant 或 generated parser/scanner artifact。
