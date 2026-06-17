# Blocker Triage：目前問題與解決方案評估稿

## 1. 背景與目標

目前系統流程為：

```text
blocker selection
  -> dependency classifier (Input Dependent / Input Independent)
  -> triage LLM
  -> deterministic label routing
  -> input-dependent / input-independent solver
```

Dependency classifier 只判斷 blocker predicate 是否受到 fuzz input 影響；triage 則判斷 blocker 是否能透過 seed、target、harness、API sequence 或 practical bounded input 求解。

Triage 的目的不是提升一般分類 accuracy，而是避免把 allocator failure、environmental failure、internal invariant、generated parser state、infeasible overflow 等 blocker 當成 solver failure。

目前 label 由 LLM 選擇，程式再固定映射：

```text
Actionable Target Gap / Bounded Extreme Value -> run_solver
其他明確 non-generation labels                -> skip_solver
Inconclusive / triage_error                    -> run_solver (fail-open)
```

## 2. 已完成的設計

目前已經完成：

1. LLM 只選 `refined_triage_label`，不再自行決定 routing。
2. `first_layer_decision` 和 `solver_action` 由程式固定映射。
3. JSON parse failure 最多 retry 2 次；仍失敗則標成 `triage_error` 並 fail-open。
4. Prompt 要求 source-first analysis，classifier trace 只作為 prior opinion。
5. Prompt 要求輸出：
   - `required_condition`
   - `producer_path_status`: proven / contradicted / insufficient
   - `practical_feasibility`
6. Generation-solvable label 若不是 `proven + practical`，會被程式降成 `Inconclusive`。
7. Prompt 已明確要求：
   - 檢查 enclosing control flow。
   - line hit 不等於 true-side hit。
   - setter 必須位於合法 API/caller path。
   - internal field 受到 input 影響，不代表任意值都合法可控。

## 3. 三次重複執行結果

同一組 9 個 libpcap development cases 重跑三次：

| Run | Completed | First-layer agreement | Exact-label agreement | 總時間 |
|---|---:|---:|---:|---:|
| 1 | 9/9 | 4/9 | 2/9 | 242.8 秒 |
| 2 | 9/9 | 5/9 | 3/9 | 221.1 秒 |
| 3 | 9/9 | 5/9 | 2/9 | 229.7 秒 |

27 次 LLM call 全部第一次成功，不是 JSON parsing 或 retry 問題。平均每個 blocker 約 25.7 秒。

這些數字只能稱為 development-set retrospective agreement，不能稱為 independent accuracy，因為 taxonomy 和 prompt 都曾參考這 9 個 cases。

## 4. 目前主要問題

### 4.1 Evidence contract 目前只是 self-report

現在程式只檢查 LLM 是否填入：

```json
{
  "producer_path_status": "proven",
  "practical_feasibility": "practical"
}
```

但程式沒有驗證 LLM 所稱的 proof 是否真的符合 source。因此 LLM 可以先做出錯誤推論，再用 `proven` 自我證明。

所以 `evidence_contract_satisfied = true` 目前只代表欄位與組合合法，不代表 evidence 正確。

### 4.2 三個穩定的 false generation-solvable

#### `convert_code_r_2715`

Source：

```c
if (slen) {
    offset = calloc(slen, sizeof(struct slist *));
    if (!offset) {
        conv_error(conv_state, "not enough core");
    }
}
```

三次都被判成 `Actionable Target Gap`。LLM 認為 `slen == 0` 會讓 `offset == NULL` 並到達 blocked side。

實際上 `slen == 0` 會跳過整個外層 block。Blocked side 必須滿足：

```text
slen != 0 AND calloc(...) == NULL
```

這是明確的 enclosing control-flow 誤判。

#### `pcap_parse_3594`

三次都被判成 `Actionable Target Gap`。LLM 將「syntax error 後 EOF」視為足以建立 `yyerrstatus == 3` 並進入指定 recovery path。

但目前 evidence 沒有證明完整 parser state transition。部分 response 還把 condition line hit count 誤讀成 true branch 曾經成立。

這是 generated parser state 與 coverage semantics 的誤判。

#### `compute_local_ud_641`

三次都被判成 generation-solvable。LLM 將 BPF input 中的 offset/immediate value，直接等同 optimizer internal `atom` domain，並提出 `mem[1000000]` 之類 seed。

Manual audit 顯示該值受到 scratch-memory/register producer domain 限制，blocked `abort()` 是 internal invariant guard。

這是「input 影響 internal IR」被錯誤擴張成「input 可任意控制 internal field」。

### 4.3 兩個不穩定 cases

- `yy_get_next_buffer_4629`: 兩次 Actionable Target Gap，一次 Generated Parser State。兩次錯誤結果引用不屬於目前 `pcap_compile -> pcap__scan_string` path 的 refill/file-buffer transition。
- `newchunk_642`: 兩次 Bounded Extreme Value，一次 Resource-Exhaustion Guard。核心不確定點是 `NCHUNKS` exhaustion 是否能在 practical fuzzing budget 內達成；目前 evidence 沒有量化 bound。

### 4.4 Exact-label taxonomy 還有邊界問題

- `pcap_compile_788`: manual label 是 Environmental Failure，LLM 三次都是 Resource-Exhaustion Guard；但 first-layer routing 都正確為 skip。
- `pcap_parse_2056`: manual label 使用 Crash-Revealing Path，LLM 三次使用 Generated Parser State；但 prompt 缺少完整 crash evidence，因此 exact-label mismatch 不一定代表 routing error。

因此 first-layer agreement 比 exact-label agreement更適合目前的系統目標，但 taxonomy 邊界仍需固定。

## 5. Root Cause 判斷

Prompt 已經明文要求 control-flow、producer path、value domain 與 line-hit semantics，但模型仍連續違反。繼續增加文字規則，預期改善有限。

Root cause 是：

```text
LLM 同時負責提出事實、解釋事實、判斷 evidence 是否充分、選 label。
程式只檢查輸出欄位是否自洽，沒有檢查 source fact 是否成立。
```

## 6. 建議的最小解決方案

不是建立完整 C/C++ static analyzer，而是在 LLM 前後加入一個保守的 evidence verifier。

### 6.1 Query-driven evidence extraction

只從 blocked line 反向抽取做 solvability 判斷所需的局部事實：

1. Blocked line 的 enclosing `if` / loop / switch 條件。
2. 到達 blocked side 所需的 predicate outcome。
3. 同一函式內直接 assignment 或 function-return producer。
4. 明確 allocator-return check。
5. Coverage 欄位究竟是 line evaluation 還是 side-specific hit。

不試圖處理完整跨函式 alias、function pointer、macro semantics 或所有 C/C++ dataflow。

### 6.2 Structured evidence

程式先產生：

```json
{
  "control_flow_evidence": [
    {
      "id": "CF1",
      "line": 2713,
      "condition": "slen",
      "required_outcome": true
    },
    {
      "id": "CF2",
      "line": 2715,
      "condition": "!offset",
      "required_outcome": true
    }
  ],
  "producer_evidence": [
    {
      "id": "DF1",
      "line": 2714,
      "target": "offset",
      "producer": "calloc(slen, sizeof(struct slist *))"
    }
  ]
}
```

### 6.3 LLM 必須引用 evidence IDs

LLM output 增加：

```json
{
  "refined_triage_label": "Resource-Exhaustion Guard",
  "control_flow_evidence_ids": ["CF1", "CF2"],
  "producer_evidence_ids": ["DF1"]
}
```

### 6.4 Post-verification 與 fail-open

程式檢查：

- 引用的 evidence ID 是否存在。
- proposed path 是否違反 enclosing condition。
- `proven` 是否至少引用具體 producer evidence。
- generation-solvable 是否建立在 local source 可支持的 producer/value domain 上。

驗證失敗時不猜另一個 non-generation label，而是：

```json
{
  "verified_refined_triage_label": "Inconclusive",
  "evidence_verified": false,
  "solver_action": "run_solver"
}
```

也就是 fail-open：分析不完整最多造成多跑 solver，不會錯誤跳過可解 blocker。

## 7. 無法提供的保證

這個方案無法保證抓到所有 C/C++ facts，特別是：

- 跨 translation unit dataflow
- pointer alias
- function pointer / virtual dispatch
- 複雜 macro expansion
- generated parser 完整 state machine
- project-specific semantic invariants

因此真正保證的是保守性，不是完整性：

```text
抓得到且可驗證 -> 可以作為 routing evidence
抓不到          -> Inconclusive -> run_solver
```

## 8. 成本估計

最小版本預估：

| 成本 | 估計 |
|---|---:|
| 實作與測試 | 1 至 2 天 |
| 每個 blocker 額外 AST/evidence extraction | 約 0.1 至 2 秒 |
| 額外 LLM call | 0 |
| 主要 dependency | Tree-sitter C/C++ 或等價 parser |
| 主要運行代價 | 更多 evidence 不足的 cases fail-open 進 solver |

目前環境有 Clang 14，但 Python 環境沒有 `clang.cindex`、`tree_sitter`、`tree_sitter_c`、`tree_sitter_cpp`。若採 Tree-sitter，需要新增 dependency。

完整跨函式 static analysis 需要數週，不在本次方案範圍內。

## 9. 實驗策略選項

### 選項 A：先實作 verifier，再跑完整 12 小時實驗

優點：hard gate 的技術主張較完整。

風險：1 至 2 天開發後，跨函式/parser semantic cases 仍可能大量 Inconclusive；仍需重新驗證。

### 選項 B：不再強化 hard gate，改用 shadow triage 跑完整實驗

```text
triage 照常輸出 decision
但 skip_solver 不實際阻止 solver
事後比較 triage decision、solver outcome 與人工 audit
```

優點：不會因 triage false negative 漏掉可解 blocker，可直接收集泛化資料。

缺點：無法在本次完整實驗中證明 triage 實際節省 downstream solver cost，只能做 counterfactual analysis。

### 選項 C：只修 deterministic control-flow，其他維持 fail-open

先修 `convert_code_r` 類的 enclosing-block 錯誤，不企圖在期限內解決完整 producer semantics；然後用 shadow mode 跑完整實驗。

這是目前認為最符合 deadline 的折衷方案。

## 10. 希望 Claude 評估的問題

請針對以下問題嚴格評估：

1. 以上 root cause 是否正確？是否還有更直接的原因被忽略？
2. 在不到一個月的 thesis deadline 下，加入最小 evidence verifier 是否值得？
3. Tree-sitter local AST + fail-open 是否足以形成可防守的方法貢獻，還是會讓系統複雜度大於論文價值？
4. 是否應選擇「只修 deterministic control-flow + shadow triage」而非完整 hard gate？
5. `pcap_compile_788` 的 fixed-size allocation failure 應統一為 Environmental Failure 還是 Resource-Exhaustion Guard？
6. `pcap_parse_2056` 在缺少 crash runtime evidence 時，應標 Generated Parser State、Crash-Revealing Path，還是 Inconclusive？
7. 三次 run 的驗收標準應該是 first-layer stability、manual agreement，還是更適合使用其他指標？
8. 論文應如何描述 triage，才不會把 development-set agreement 誤寫成 accuracy 或泛化能力？

## 11. 目前傾向

目前傾向採選項 C：

1. 實作最小 deterministic control-flow evidence，先阻止明確違反 lexical nesting 的 proof。
2. 對無法驗證的 producer path 強制 `Inconclusive` 並 fail-open。
3. 完整實驗先採 shadow triage，避免尚未充分驗證的 hard gate 漏掉可解 blocker。
4. 論文將 9 cases 定位為 retrospective development case study，不報 independent accuracy。

請不要只評估「是否能實作」，而要同時評估 deadline、論文可防守性、系統風險與實驗價值。
