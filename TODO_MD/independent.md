# Blocker 分類分析：INPUT INDEPENDENT 判定品質

本文件針對 `20260607_012651_run_all_fuzzer` 實驗中的 blocker，逐一做完整的 dataflow 推論、分類驗證，
並對照 `prompts/templates/blocker_classify_template`，記錄 LLM 推論的問題與 template 改進建議。

---

## Case 1：yy_get_next_buffer（line 4629 → blocked side 4651）

### 基本資訊

| 項目 | 值 |
|------|-----|
| 函數 | `yy_get_next_buffer`（Flex scanner，scanner.c） |
| Branch line | 4629 |
| Blocked side line | 4651 |
| Branch hit count | 71,500 |
| Blocked side hit count | 0 |
| LLM 分類 | Input Independent ✓ |

---

### Dataflow 完整推論

**Branch 條件與方向：**

```c
// scanner.c:4629
if ( YY_CURRENT_BUFFER_LVALUE->yy_fill_buffer == 0 )
{   // condition TRUE → 進 if block，line 4630-4645（return EOB_ACT_END_OF_FILE / LAST_MATCH）
}
// condition FALSE（fall-through）→ line 4651 ← BLOCKED SIDE
number_to_move = (int) (yyg->yy_c_buf_p - yyg->yytext_ptr - 1);
```

**Blocked side 需要：`yy_fill_buffer != 0`（即 == 1）**

**`yy_fill_buffer` 的已知設定點（observed path 與 provided evidence）：**

| 設定位置 | 值 | 觸發路徑 |
|----------|-----|----------|
| `yy_scan_buffer()` line 5192 | **0** | `pcap__scan_string` → `yy_scan_bytes` → `yy_scan_buffer`（observed path） |
| `yy_init_buffer()` line 5020 | **1** | `pcap__create_buffer(FILE*)` → `yy_init_buffer`（provided evidence 中可見） |

**Fuzz Target → Blocker 完整 call chain：**

```
LLVMFuzzerTestOneInput  [if (Size < 4) return]  ← gates entry only; not a setter of yy_fill_buffer
  └─ pcap_compile(p, &fcode, filter_string, ...)
       └─ pcap__scan_string(xbuf)          [gencode.c:791]
            └─ yy_scan_string(str, scanner)
                 └─ yy_scan_bytes(bytes, len, scanner)
                      └─ yy_scan_buffer(buf, size, scanner)
                           └─ b->yy_fill_buffer = 0;  ← 硬設定，永遠不會是 1
```

在 L1 scope（current target, input-only）下：`pcap_compile` 路徑固定走 `pcap__scan_string`
→ `yy_scan_buffer`，`yy_fill_buffer` 恆被設為 0，無論餵什麼 input bytes 都無法改變。

`pcap__create_buffer(FILE*)` 路徑（可設 `yy_fill_buffer = 1`）在 provided evidence 中可見，
但 current target 無法走到這條路徑。一個 generated candidate 嘗試繞道時，因 `compiler_state_t`
（`struct _compiler_state`）是 incomplete type（`gencode.h:310` 只有 forward declaration）
而編譯失敗——這只說明該 candidate 的寫法行不通，不代表所有 internal scanner route 都不可行。

**結論：INPUT INDEPENDENT（L1 scope）— 分類正確。**
在目前 target 的 `pcap_compile` observed path 與 L1 input-only scope 下，
blocked side（4651）無法到達。其他 scope（L2/L3/L4）的可達性不影響此結論。

---

### LLM 推論問題

LLM 給出的 `reason`（原文節錄）：

> "The `LLVMFuzzerTestOneInput` function includes a guard `if (Size < 4) { return 0; }`,
> ensuring that the fuzzer input `Size` is always at least 4. This in turn guarantees that
> the `filter_string` will always have a length of at least 2 characters. **If the
> `filter_string` were allowed to be empty (e.g., if `Size` could be 1), the Flex scanner's
> internal `yy_fill_buffer` flag would likely be initialized to 0**, making the blocked branch
> reachable. Since the fuzz target's minimum input size constraint prevents the `filter_string`
> from being empty, **the condition `yy_fill_buffer == 0` can never be true**."

**問題 1：因果鏈完全錯誤**
LLM 認為「filter_string 非空 → yy_fill_buffer ≠ 0」，但 `yy_fill_buffer` 由呼叫的 API 函數
決定（`yy_scan_buffer` 無論收到什麼字串都設為 0），與 filter_string 長度或內容無關。

**問題 2：結論方向完全相反**
LLM 說「`yy_fill_buffer == 0` can never be true」。現實是：`yy_fill_buffer == 0` **恆為 true**
（硬設定）。Blocked side 需要的是 `yy_fill_buffer == 1`（condition FALSE），LLM 把方向搞反了。

**問題 3：Size < 4 guard 對此 blocker 完全無關**
移除 guard 後 filter_string 可以是空字串，但路徑依然是
`pcap__scan_string → yy_fill_buffer = 0`，guard 的存在與否對此 blocker 毫無影響。

**問題 4：根本原因沒找到**
在 L1 scope 下，真正原因是：`pcap_compile` 的 observed path 只走 string buffer，
`yy_fill_buffer` 恆為 0；FILE* buffer path 不在 current target 的 L1 input-only scope 內。
某個 generated candidate 因 `compiler_state_t` incomplete type 編譯失敗，
只是補充性的 build evidence，不代表所有 internal route 都不可行。

---

### LLM 推論問題所呈現的通用 Pattern

這個 case 揭示了兩種與 libpcap 無關、任何 C/C++ 函式庫都可能發生的失敗模式：

**通用 Pattern A：條件方向混淆（Direction Confusion）**

當 branch 的形式是 `if (flag == VALUE) { ... }` 而 blocked side 在 if block **外側（fall-through）** 時，
LLM 很容易誤以為「要讓 blocked side 可達，需要讓 `flag == VALUE` 成立」，
而實際上需要的是 `flag != VALUE`。

任何 `if/else`、`switch`、guard + fall-through 的結構都有這個風險，
與具體函式庫無關。

**通用 Pattern B：以最近的 fuzz target 元素作為錨點（Anchor Bias）**

LLM 傾向於找到 fuzz target 中最顯眼的元素（如 size guard、hardcoded argument）
作為解釋原因，而不是追蹤真正的 predicate 設定路徑。
這種錨點偏誤導致 LLM 把無關的 target 元素與 predicate 的值做出虛假的因果連結。

---

## Case 2：pcap_parse（line 2056 → blocked side 2057）

### 基本資訊

| 項目 | 值 |
|------|-----|
| 函數 | `pcap_parse`（Bison parser，grammar.c） |
| Branch line | 2056 |
| Blocked side line | 2057 |
| Branch hit count | 5,980,000 |
| Blocked side hit count | 0 |
| LLM 分類 | Input Dependent |
| **實際應為** | **Input Independent（LLM 誤判）** |

---

### Dataflow 完整推論

**Branch 條件與方向：**

```c
// grammar.c:2056 — 在 Bison 的 token shift 迴圈內
/* Count tokens shifted since error; after three, turn off error status. */
if (yyerrstatus)   // ← condition TRUE → blocked side
    yyerrstatus--;  // ← BLOCKED SIDE (line 2057)
```

**Blocked side 需要：`yyerrstatus > 0`（非零）**

**`yyerrstatus` 的狀態轉移：**

| 時機 | 值 | 觸發點 |
|------|-----|--------|
| 初始化 | **0** | grammar.c:1914 |
| 偵測到 parse error | **3** | grammar.c:3640（`yyerrlab1` label: line 3639，`yyerrstatus = 3` assignment: line 3640） |
| error recovery 後每次成功 shift | **遞減** | grammar.c:2057（正是 blocked side） |
| 恢復完成 | **0** | 減到 0 後 |

**`yyerrstatus` 理論上可被 input 影響的路徑：**

```
filter_string（含語法錯誤）
  └─ pcap_compile → pcap__yyparse（Bison parser）
       └─ lookahead token 無法被當前 state 接受
            └─ goto yyerrlab → yyerrstatus = 3（yyerrlab1:3639）
                 └─ Bison error recovery：尋找可接受 error token 的 state
                      └─ 若找到 → shift error token → yyerrstatus 在 line 2057 遞減 ← BLOCKED SIDE
                      └─ 若找不到 → 彈出整個 stack → YYABORT（返回錯誤）
```

**關鍵（主證據）：generated parser table 中沒有 error recovery transition**

對於 generated parser 或 table-driven state machine，grammar source 是宣告層，
generated transition table 或 generated control flow 才是實際行為層。
Survival check 的正確做法是查 generated 產物確認某個 token/transition 是否真的有
positive entry，而非只看 grammar source 的宣告。兩者可能不一致。
- Bison/yacc：檢查 YYTERROR shift entry
- 其他 parser generator：檢查對應的 recovery transition 或 error dispatch entry

本 case（libpcap）的具體驗證：解析 `grammar.c` 的 generated table，
確認所有 parser state 對 YYTERROR 均無 positive shift entry → recovery 必然走 YYABORT。

**輔助確認（source-level explanation）：grammar.y 沒有顯式的 `error` production rules**

Bison 的 error recovery 只能在有 `error` pseudo-token 的 production rule 對應的 state 接受
error token。grammar.y grep 無 error production 是對 generated table 結果的 source-level
解釋，兩者一致。若兩者矛盾，以 generated table 為準。

**統計驗證：5,980,000 次 branch 評估，blocked side 命中 = 0**

Line 2056 是 Bison shift 迴圈的一部分，每次成功 shift 都會執行一次。5.98M 次評估中
`yyerrstatus` 全部為 0，說明 parser 從未在 error recovery 模式下成功 shift token。
這與「無 error production rules → recovery 永遠失敗 → YYABORT」的分析完全一致。

**結論：INPUT INDEPENDENT（L1 scope）— LLM 誤判為 Input Dependent。**
在 L1 input-only scope 下，`yyerrstatus` 雖然理論上由 input 語法錯誤觸發，
但 blocked side 的到達需要 error recovery 成功（找到可接受 YYTERROR 的 parser state），
而 generated table 確認所有 state 均無 YYTERROR positive shift，recovery 必然走 YYABORT，
blocked side 無法到達。

---

### LLM 推論問題

LLM 給出的 `reason`（原文）：

> "The blocked predicate `if (yyerrstatus)` is input dependent because the value of
> `yyerrstatus` is an internal state of the `pcap_parse` function, which is a
> Bison-generated parser. This internal state is directly influenced by the syntax and
> structure of the `filter_string` provided by the fuzzer's input. **The fact that the
> `yyerrstatus--` branch is never hit indicates that the fuzzer has not yet discovered
> an input that triggers a specific error recovery path where `yyerrstatus` is non-zero
> at that point in execution. This is a matter of input coverage, not input independence**,
> as the input alone can determine the parser's error state."

**問題 1：推論在「設定 yyerrstatus」就停止，沒有繼續追蹤「是否能到達 blocked side」**

LLM 正確識別了「語法錯誤輸入 → yyerrstatus 被設為非零」的鏈，但沒有繼續追蹤：
yyerrstatus 被設為 3 之後，需要 error recovery 成功才能在 shift 時執行 line 2057。
LLM 在因果鏈的中間就停下來了，沒走完到 blocked side 的完整路徑。

**問題 2：對 5.98M hits + 0 blocked 的統計現象解讀錯誤**

LLM 說「fuzzer has not yet discovered an input」，把這當成 coverage 不足的問題。
但 5.98M 次評估全為 0，且 Bison 對同一個語法錯誤的行為是 deterministic 的，
這應觸發強烈的懷疑：是否有 structural 的原因使 blocked side 根本無法被到達？

**問題 3：沒有檢查 generated parser table / recovery transition**

LLM 應直接查 generated transition table 確認沒有 YYTERROR positive shift entry；
grammar.y 沒有 error production 只是 source-level explanation，真正判準以 generated
table / generated control flow 為準。LLM 跳過了這個步驟。

---

### LLM 推論問題所呈現的通用 Pattern

這個 case 揭示了兩種與 libpcap 無關、任何 C/C++ 函式庫都可能發生的失敗模式：

**通用 Pattern C：因果鏈在中途截斷（Incomplete Causal Chain）**

LLM 成功追蹤到「input → predicate 被設為所需值」，但沒有繼續追蹤
「predicate 設定後 → 是否能到達 blocked side 的讀取點」。

這在以下場景中普遍存在：
- 狀態機（state machine）：狀態被設定，但回到讀取點需要特定的轉移路徑
- 旗標（flag）被設定在某個 error handler 中，但 error handler 的執行需要先通過其他條件
- 計數器（counter）被設定，但讀取它的迴圈有前置條件

在所有這些情境中，「predicate 被設為所需值」是必要條件，但不是充分條件。
LLM 需要額外問：「這個值能在 blocked side 的讀取點存活（survive）嗎？」

**通用 Pattern D：高 hit + 零 blocked 被誤解為 coverage 問題**

當 branch_hit_count 極高且 blocked_side_hit_count = 0 時，
LLM 傾向於解釋為「fuzzer 還沒找到對的 input」。

但高 hit count 只代表「到達該 branch 很多次」，不代表「已充分探索能滿足 blocked side
的語意空間」。許多 C/C++ blocker（checksum、magic + nested structure、高維 input format、
hash bucket、parser deep state）就算 branch 被打到百萬次，blocked side 的語意條件
仍需要特定的 input 結構才能滿足。

正確解讀：高 hit + 零 blocked 是搜尋 structural blocker 的強 signal，應優先尋找
structural 原因；但不能單靠統計就否定 Input Dependent。必須找到具體的 structural blocker
才能下 Input Independent 的結論。

---

## 整體 Template 修改方案（泛用版）

以下修改均設計為對任意 C/C++ 函式庫有效，不依賴特定函式庫知識。

---

### 修改零（前置）：全域 Classification Scope 定義

**解決 Rule 3/5 混淆、避免 LLM 用 hypothetical API route 帶偏分類**

放在所有 Rule 之前：

```
CLASSIFICATION SCOPE:
The primary classification is current-target input-only.
Ask only: without modifying the current fuzz target code, can arbitrary fuzzer
input bytes make execution reach the blocked side?

Do not classify as Input Dependent merely because the blocked side might be
reachable by modifying the fuzz target, using a different public API sequence,
writing a new fuzz target, or calling internal/generated APIs.

If input bytes alone cannot reach the blocked side under the current target,
classify as Input Independent. The later solver may decide whether to adjust
the existing target or generate a new one.
```

理由：classifier 的責任很窄——只判斷「目前 target、只改 input bytes，blocked side 可不可達」。
後續的修復策略（微調現有 target / 生成新 target）是 solver pipeline 的責任，
不應該讓 classifier 提前決定。L2/L3/L4 的概念不進 prompt，避免 LLM 把「分類」和「修復策略」混在一起。

> **實作注意**：修改六（L1–L4 scope table）是開發分析工具，幫助人類釐清 scope 邊界，
> 不作為 template 的直接內容。Classifier prompt 只採用上面的短版 CLASSIFICATION SCOPE。

---

### 修改一：新增 `[1.5. Blocked Side Direction]` 步驟

**解決 Pattern A（方向混淆）**

在 `[1. Target Variable]` 之後、`[2. Fuzz Target Call Site]` 之前強制插入：

```
[1.5. Blocked Side Direction]:
- Using the surrounding source, state whether line {blocked_side_line_number}
  is reached when the branch condition is TRUE, FALSE, an else case, a switch
  case/default, a fall-through after early return/goto, or some other control
  flow path.
- Pin the required predicate value/state for the blocked side.
- All later reasoning must target this required value/state, not the opposite.
```

涵蓋 C/C++ 常見的 `goto`、`switch`、macro-expanded guard、early return，
比只考慮 if-body/fall-through 更完整。

---

### 修改二：`[3. Origin Trace]` — 兩段式追蹤

**解決 Pattern B（錨點偏誤）、Pattern C（因果鏈截斷）**

現有的 `[3. Origin Trace]` 只要求「cite the exact assignment/update site」，沒有要求完整路徑。替換為：

```
[3A. Setter / Transition Evidence]:
- Enumerate every visible assignment, update, initializer, API call, callback,
  macro, or state transition in the provided evidence that can affect the predicate.
- For each: (a) the value/state it produces, (b) where it occurs,
  (c) whether it lies on the observed runtime path.
- If complete setter coverage is not provable from provided evidence,
  explicitly state "Not provable from provided code."
- Identify which visible setter(s) can produce the target value from [1.5].

[3B. Survival / Feasibility Check]:
- If a visible path can produce the required value/state, trace whether execution
  can reach the blocked side while that value/state still holds.
- Check for: early return, abort, goto, longjmp, cleanup reset, object destruction,
  parser/state-machine transition failure, required second condition, feature flag,
  platform guard, or API lifecycle invariant.
- If the value is input-reachable but cannot survive to the blocked-side read
  under the current target (L1 scope), classify as Input Independent.
```

注意：要求的是 **visible** setter，不是 ALL。要求 ALL 會誘導 LLM 在有限 evidence 下
做假設性 whole-program analysis，產生「唯一 setter」的幻覺。

---

### 修改三：`[1. Target Variable]` — 高 hit + 零 blocked 的解讀

**解決 Pattern D（統計誤解）**

在現有「If `{branch_hit_count}` > 0」段落後加入：

```
[Statistical Signal]:
If branch_hit_count is large and blocked_side_hit_count is 0, treat this as
a prompt to search for a structural reason before concluding Input Dependent.
Do not conclude "coverage issue" unless you can identify a concrete
input-controlled path that would satisfy the required blocked-side value/state.
Do not conclude Input Independent from hit counts alone.
```

注意：刻意不寫「不要解讀為 coverage 不足」，因為 checksum、magic + nested structure、
parser deep state 等 blocker 即使 branch hit 很高，blocked side 仍可能只需正確的 input
語意就能觸及。統計 signal 只能促發 structural 搜尋，不能直接下結論。

---

### 修改四：Rule 3 vs Rule 5 的 scoped wording

**解決 Pattern B（Rule 選錯）**

取代原本「ANY fuzz target restricted to public API」的斷言，改用 scoped wording：

```
NOTE: Rule selection is secondary to the L1 dependency label.
First answer: under L1 (current target, input-only), can arbitrary input bytes
reach the blocked side? If NO, the label is Input Independent regardless of
whether Rule 3 or Rule 5 applies. Rule selection only determines WHY and guides
solver direction — it does not change the primary classification.

Rule 3 explains observed-path invariants enforced by the executed library/API
path that input bytes cannot break — the value/state is locked by the library's
own initialization or transition logic on the observed runtime path.
Do not generalize this to all public APIs unless the provided evidence explicitly
proves it.

Rule 5 applies when the required value/state would require changing the
current fuzz target's setup, API sequence, hardcoded args, guards, or object
materialization — the library could produce it, but this target's design prevents it.

Do NOT claim "no public API can reach this" unless the provided evidence
explicitly supports that broad claim. C/C++ public APIs may include macros,
optional features, platform-specific sources, generated headers, deprecated
APIs, and callback APIs that are not visible in the provided evidence.
```

理由：LLM 可能花太多力氣在 Rule 3/5 的區分上，反而忽略主問題：L1 input-only 是否可達。
Rule selection 是二階問題，不能讓它蓋過主分類的判斷。

---

### 修改五：`analysis_trace` 寫入 log

**解決推論無法事後 debug 的問題**

目前 `blocker_pipeline_result` event 只儲存 `reason` 字串，無法事後看出 LLM 在哪步出錯。

改法（`main.py`，`blocker_pipeline_result` event dict 建構處）：

```python
analysis_trace = (result.get("parsed_result") or {}).get("analysis_trace", [])
```

同時寫入 `_log_experiment_event(...)` 和 `_append_blocker_attempt_record(...)`，
否則 events.jsonl 有、blocker_attempts.jsonl 沒有，debug 仍不完整。

---

### 附記：compiler_state_t build failure 不能當通用證據

在分析 `yy_get_next_buffer` 時，一個 generated candidate 因 `compiler_state_t` incomplete type
編譯失敗。這只證明「那個 candidate 的寫法行不通」，不能推論「所有 internal scanner route 都不可行」。
Prompt 應避免讓 LLM 把單次 build failure 等同於 structural impossibility。

---

### 附記：L4（internal API）可達 ≠ library invariant

若只有透過 internal/generated API 才能到達 blocked side，這不等於「library invariant」；
這代表 public API boundary 阻擋了該路徑（Rule 3 的 observed-path 條件不符合）。
真正的 library invariant 是：連合法的 API sequence / object lifecycle 都無法讓那個狀態成立，
與 L4 是否可達無關。

---

### 概念補充：Classification Scope 分層（L1–L4）

> **注意**：此分層是人類分析時的概念工具，用來釐清 scope 邊界，幫助 debug classifier 推論。
> **不作為 classifier prompt 的直接內容。** Classifier prompt 只採用「修改零」的短版 CLASSIFICATION SCOPE。
> 完整放進 prompt 會讓 LLM 把「分類」和「修復策略」混在一起，
> 並可能繞過 pipeline 預設的「先微調現有 target → 不行才生成新 target」順序。

**背景**

Rule 3 和 Rule 5 的核心差異是「能不能在 current scope 內解決」，但 current scope 的邊界
需要明文化，否則 LLM 可能把「public API 可達」誤用為「現有 target 可達」。

**分層定義**（開發分析用，不進 prompt）：

| Scope 層級 | 定義 | 對應 Rule |
|-----------|------|----------|
| **L1：current target, input-only** | 只改 fuzzer 的 input bytes，不改 fuzz target 程式碼 | Primary scope。input bytes 可達 blocked side → Input Dependent（Rule 1/2）；不可達 → Input Independent，原因可能是 Rule 3/4/5/6 |
| **L2：current target, code edit** | 允許修改現有 fuzz target 的程式碼（但仍用 public API） | Rule 5（被修改的 target 能解決 → Input Independent at L1） |
| **L3：any public API target** | 允許寫全新 fuzz target，但只能呼叫 library 的 public API | Rule 5 or Rule 3 boundary |
| **L4：internal/generated API** | 允許 include internal header、直接呼叫 internal 函式 | 只有 L4 才能解決 → public API / current harness boundary confirmed；不等於 library invariant |

**在 yy_get_next_buffer case 的應用**：

- L1：Input Independent（pcap_compile 路徑固定設 yy_fill_buffer=0）
- L2：在 provided evidence 中未看到「修改 target 但限定 public API」能改變 scanner buffer creation 路徑（不排除有未見到的 code path）
- L3：在 provided evidence 中未看到任何 public pcap_* API 能讓 target 走 FILE buffer scanner path（不排除有未見到的 public API）
- L4：理論上可達（直接呼叫 pcap__create_buffer + pcap_set_extra），但這超出 public API scope

**結論**：Template 的 dependency label（Input Dependent / Input Independent）應固定基於
**L1（current target, input-only）** 判定。L2/L3/L4 只用作 scope notes：
解釋為何 L1 下無法到達 blocked side，以及後續 solver 應往哪個方向改 target。
不能用 L2/L3/L4 的可達性改變主分類 label。

---

## 整體修改摘要

| 修改 | 解決的 Pattern | 適用場景 |
|------|---------------|---------|
| 全域 Classification Scope（短版，只說 L1） | Rule 3/5 混淆、hypothetical API route 帶偏 | 所有 C/C++ case；L2/L3/L4 不進 prompt |
| 新增 `[1.5. Blocked Side Direction]` | A：方向混淆 | `if/else`、`switch`、`goto`、macro guard、fall-through |
| `[3A]` visible setter 枚舉（非 ALL） | B：錨點偏誤 | 任何多 setter 情境 |
| `[3B]` Survival / Feasibility Check | C：因果鏈截斷 | 狀態機、object lifecycle、parser recovery |
| `[Statistical Signal]` 弱化版 | D：統計誤判（雙向） | 任何 deterministic 函式庫函數 |
| Rule 3/5 scoped wording（不要求全域證明） | B：Rule 選錯、evidence 不足時過強斷言 | 任何 closed-box library fuzzing |
| `analysis_trace` 寫入兩個 log | — | 工程改善 |
