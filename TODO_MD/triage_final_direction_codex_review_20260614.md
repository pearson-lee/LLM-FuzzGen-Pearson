# Codex Review: Triage 最終方向（2026-06-14）

## 結論

Claude 的方向有一半正確：**不值得為 9-case development set 引入 Tree-sitter 或擴張成完整 evidence verifier**，也應停止繼續追逐 7/9、8/9 這類數字。

但文件目前的核心推論有一個重大錯誤：

> `Inconclusive` 與 `triage_error` fail-open，不等於整個 hard gate「by construction 不會誤跳可解 blocker」。

現行程式只要 LLM 選到任一 non-generation label，就會產生 `skip_solver`，並且 `main.py` 已先將該 blocker 加入 attempted set。對新的、沒有 ground truth 的 project，LLM 仍可能把真正 generation-solvable 的 blocker 自信地誤判為 non-generation label。這仍然是 false negative，而且會永久略過 solver。

因此：

- **同意**停止 Tree-sitter/full verifier。
- **同意**9 cases 僅作 development case study，不報 accuracy。
- **不同意**目前直接用 normal hard gate 跑 12 小時完整實驗。
- **不同意**把「不誤跳可解 blocker」寫成目前系統的 by-construction guarantee。
- 最能收斂的方案是：**凍結 taxonomy/prompt，完整實驗採 shadow triage；hard gate 只作為可選的 system mode，不作為本次主實驗的可信前提。**

## 1. 對 Context 兩個主張的評估

### 1.1 「目前所有錯誤都是 false positive」：在 9-case dataset 上正確

三次 rerun 的 generation-solvable manual case 只有 `gen_prevlinkhdr_check_3149`，三次都被送入 solver。其他錯誤都是把 manual non-generation case 判成 generation-solvable。

所以可以寫：

> No false-negative routing decision was observed in the nine development cases across the three repeated runs.

不能擴張成：

> The triage system does not produce false negatives.

9 個同 project、且參與 taxonomy/prompt 開發的 cases，只能描述 observed behavior，不能證明新 project 不會出現 false negative。

### 1.2 「系統現況是正確但偏慢」：過度推論

這句話只對這 9 個已人工 audit 的 cases 成立。新 project 沒有 manual ground truth，因此無法知道 LLM 是否會自信地輸出錯誤 non-generation label。

現行 routing 是：

```text
Resource-Exhaustion Guard
Environmental Failure
Internal Invariant Guard
Generated Parser State
Structurally Unreachable API Path
Infeasible Counter Overflow
Crash-Revealing Path
    -> skip_solver
```

只有 `Inconclusive` 和 `triage_error` fail-open。LLM 若錯選上述任一 label，不會自動落入 fail-open。

### 1.3 「fail-open guarantee by construction」：只對錯誤處理成立，不對分類成立

目前可以合法宣稱的程式性質是：

- JSON parse failure 最終為 `triage_error -> run_solver`。
- evidence contract 不符時為 `Inconclusive -> run_solver`。
- unknown label 為 `Inconclusive -> run_solver`。

不能宣稱：

- 所有 uncertain semantic cases 都會被 LLM 選成 `Inconclusive`。
- 所有 generation-solvable blockers 都不會被錯標成 non-generation label。

後兩項不是程式保證，而是 LLM 判斷品質問題。

## 2. 對最小 enclosing-guard 方案的評估

### 2.1 只處理 `convert_code_r` 是合理的 scope control

三個穩定錯誤中，`convert_code_r` 的確是唯一能靠 local lexical nesting 明確反證的 case。停止延伸到 parser state 與 optimizer semantic domain，是符合 deadline 的決定。

但這個修正只能稱為：

> A local consistency safeguard for enclosing control-flow conditions.

不適合稱為完整 evidence verifier，也不應成為論文主要方法貢獻。它最多是 triage 的 implementation safeguard。

### 2.2 40–50 行 brace matching 的可靠性被低估

純 brace matching 有以下 C/C++ 邊界：

- `if (x) statement;` 沒有大括號。
- `if/else` 中，blocked side 位於 `else` 時要求的是 condition=false，不是所有 guard=true。
- `do { ... } while (x)` 的 body 不要求 `x` 先為 true。
- `switch` 需要 case matching，不能表示成單一 true guard。
- `{`、`}` 可能存在 comment、string、character literal 或 macro 中。
- `#if/#else` 可能改變實際編譯結構。
- `goto` 可以進入 lexical block；generated parser source 大量使用 label/goto。
- C++ lambda、initializer、class/namespace scope 都使用大括號，但不是 control guard。

所以文件中的：

> EVERY guard below must be entered (its condition must be true)

不是一般 C/C++ 的正確敘述。

### 2.3 誤抽 guard 不一定安全地 fail-open

文件稱 deterministic check 永遠不會獨自產生 skip，因為它只會 reprompt。但如果錯誤 guard 觸發 reprompt，LLM 接著改成 non-generation label，現行 deterministic label mapping 仍會 `skip_solver`。

因果關係仍可能是：

```text
錯誤 lexical extraction
  -> 錯誤 refutation
  -> LLM 改選 non-generation label
  -> hard gate skip
```

因此「這個檢查不可能導致誤跳」也不能成立，除非 refutation 後的結果固定為 `Inconclusive -> run_solver`，而不是接受新的 skip label。

### 2.4 `blocked_side_reach_requires` echo 不能作為可靠 verifier

LLM 可以：

- 正確 echo `slen`，但分析文字仍說 `slen==0`。
- 用語意等價但字串不同的表示，例如 `slen > 0`、`slen != 0`、`!!slen`。
- 遺漏 guard，但理由其實沒有依賴該 guard。

只比較 list 是否包含 condition 字串，驗證的是格式，不是 reasoning correctness。比較 `required_condition` 自由文字會更 fragile。

若仍要做，應用 stable guard ID：

```json
{
  "id": "G1",
  "line": 2713,
  "condition": "slen",
  "required_outcome": true
}
```

但這仍只能檢查 LLM 是否引用 `G1`，不能證明其推論真的遵守 G1。

## 3. 對 refute-and-reprompt 的評估

### 3.1 一次 reprompt 足夠

這是 consistency repair，不應變成新的 iterative solver。最多一次合理，否則會增加成本與不穩定性。

### 3.2 重跑後仍牴觸 guard，必須固定 fail-open

若保留此功能，結果應為：

```text
第一次 response 與 deterministic guard 衝突
  -> reprompt 一次
  -> 仍衝突：Inconclusive + run_solver
```

不能再接受矛盾的 generation-solvable label。

### 3.3 重跑後改成 skip 仍不是 correctness guarantee

對 `convert_code_r`，改成 Resource-Exhaustion Guard 很可能正確。但這是 development case 的修正結果，不代表 reprompt 機制對一般 C/C++ 都能可靠產生 skip。

如果實驗採 hard gate，這仍需新的、獨立案例驗證。以目前 deadline，不值得再建立這組 ground truth。

## 4. 對 hard gate 完整實驗的評估

### 4.1 目前不應直接 enforce hard gate

現行程式在 triage 輸出 `skip_solver` 後直接 return，並且 `main.py` 在執行 pipeline 前已將 blocker 加入 attempted set。也就是說：

```text
一次錯誤 non-generation label
  -> solver 不執行
  -> blocker 被視為已嘗試
  -> 同一 run 不再重新處理
```

在新 project 沒有 ground truth 的情況下，這會讓完整實驗無法判斷被 skip 的 blocker 是否其實可解。

### 4.2 Shadow triage 更符合目前研究狀態

主實驗應採：

```text
triage 產生 label 與 hypothetical solver_action
solver 仍照常執行
記錄 triage decision、solver outcome、時間成本
```

這能回答：

- triage 在新 project 會分出哪些類型？
- 被 triage 判定 skip 的 cases，solver 實際是否成功？
- 是否觀察到 false-negative candidate？
- 若 counterfactually enforce gate，可省多少 solver 時間？

這些資料比直接 hard skip 更有論文價值，因為結果可被檢驗。

### 4.3 Shadow mode 不是放棄 triage

程式仍可保留 `enforce` mode，論文方法也可描述 hard-gate architecture；但本次 evaluation 應明確說 triage 尚在 retrospective/shadow validation 階段。

建議模式：

```text
off      不執行 triage
shadow   執行 triage但不阻止 solver
enforce  skip_solver 真的阻止 solver
```

完整 12 小時實驗使用 `shadow`。

## 5. 對論文措辭的評估

### 可以保留

- 9 cases 是 development case study，不是 independent accuracy evaluation。
- 報三次 first-layer agreement 與 stability。
- 說明 dependency classification 與 generation solvability 是不同問題。
- `Inconclusive`、parse error、schema/evidence validation failure 採 fail-open。
- 跨函式 producer path、parser state、internal semantic domain 是 limitation。

### 必須修改

原文：

> fail-open 結構保證不誤跳可解 blocker

應改為：

> The implementation fails open on parsing errors, unknown labels, and insufficient evidence. However, semantic misclassification into a non-generation label may still suppress a solvable blocker in enforce mode; therefore, the full experiment evaluates triage in shadow mode.

原文：

> 確定性 enclosing-guard 檢查作為方法貢獻

建議改為：

> enclosing-guard consistency checking is an implementation safeguard used to reject locally contradictory reasoning.

不要把 40–50 行 lexical brace matcher包裝成一般 C/C++ static-analysis contribution。

## 6. 對 Claude 四個問題的直接回答

### 6.1 Brace matching 是否有 lexical 陷阱？是否全部安全 fail-open？

有，而且很多；不保證全部安全 fail-open。最危險的是 `else`、無大括號 statement、macro conditional compilation、comment/string braces，以及 goto 進入 lexical block。錯誤 extraction 經 reprompt 後仍可能導向 skip。

若要實作，只支援非常窄的 pattern：

- 同一函式內。
- blocked line 位於明確 `{}` compound statement。
- guard 是同一行或可可靠取得的 `if (...) {`。
- 不含 preprocessor directive、label/goto、else、switch、do/while。
- 任一不確定即不產生 authoritative guard。

### 6.2 Reprompt 一次是否足夠？

足夠。第二次仍衝突就固定 `Inconclusive -> run_solver`。不要進入更多輪。

### 6.3 `blocked_side_reach_requires` echo 是否可靠？

不足以驗證 reasoning。若保留，只能作 audit field，不能單獨作 hard-gate correctness evidence。使用 guard ID 比文字比對好，但仍只驗證引用，不驗證語意。

### 6.4 是否同意不引入 Tree-sitter？

同意。以目前 deadline，不值得為 9-case dev set 提升 agreement 而新增 parser dependency與新的 validation burden。但同一理由也表示不應再把手寫 brace matcher擴張成 generic verifier。

## 7. 最終可收斂方案

### 必做，半天內

1. 新增 `shadow` triage mode，讓完整實驗保留 solver execution。
2. 記錄 `triage_hypothetical_action`、實際 solver outcome、solver elapsed time。
3. 修正文獻與方法敘述，移除「整個 triage 不會 false skip」的保證。
4. 凍結 taxonomy 與 prompt，不再用同一 9 cases 反覆調參。

### 可做，但不是完整實驗前置條件

針對 `convert_code_r` 加一個非常保守的 local consistency check。只要 source pattern 超出支援範圍，就不抽 guard。這應定位為 development safeguard，不作 accuracy 提升主張。

### 不做

- Tree-sitter/full dataflow verifier。
- 繼續追求 9-case agreement 數字。
- 在新 project 上直接 enforce 未驗證的 hard gate。
- 為 `pcap_parse`、`compute_local_ud` 加 project/case-specific 規則。

## 8. Go / No-Go 判斷

**No-Go：**依 Claude 原文件直接做 brace matcher、reprompt，接著 enforce hard gate 跑 12 小時實驗。

**Go：**停止擴張 triage correctness 機制，新增極小 shadow mode 後跑完整實驗。這條路能產出可檢驗的新資料，也不會因 triage 誤判讓 solver outcome 消失。

這是目前最能在期限內收斂、同時保留論文可防守性的方向。
