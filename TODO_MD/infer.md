# Blocker Seed Generator 推斷失敗問題與改善方向

## 結論

這兩個 blocker 都應該判為 **Input Dependent**，但 seed generator 失敗的原因不是同一種。

`gen_prevlinkhdr_check` 的問題是只找到 `cstate->is_geneve` 的 setter，卻沒有找「setter 之後仍會讀到這個 flag 的 caller」。`geneve` 本身會把 `is_geneve` 設成 1，但 `gen_linktype()` 在 `is_geneve == 1` 時會跳過 `gen_prevlinkhdr_check()`，所以單純產生 `geneve`、`geneve and tcp` 這類 filter 不會跨過 line 3150。可行路徑是先用 `geneve` 設 state，再用 link-layer host expression 走到 `gen_ecode()` 裡的 `gen_prevlinkhdr_check()`（`gen_scode()` 依賴外部 name database 查找，`pcap_ether_hostton()` 失敗即 longjmp，是非 input-only path；fuzzing 環境下 `/etc/ethers` 通常為空，幾乎確定失敗，見修正一）。

`gen_scode` 的問題更偏向 seed materialization。LLM 有抓到 `Q_LINK` 的方向，但產生的 bytes 沒有符合 fuzz target 的 input split，而且使用 MAC literal 會走 `gen_ecode()`，不是 `gen_scode()`。正確 seed 要讓 `filter_string` 位於 `Data[1:]` 的後半段，且 filter 應該用 `link host <ID>` 這種會讓 grammar 呼叫 `gen_scode()` 的形式，而不是 `link host 00:11:22:33:44:55` 這種 MAC literal。

---

## Case A：`gen_prevlinkhdr_check` at `gencode.c:3149`

### 判斷

**Input Dependent。** 在目前 fuzz target 不改 code 的前提下，input bytes 可以透過 `filter_str` 控制 libpcap filter parser，讓同一個 `compiler_state_t` 先進入 Geneve 狀態，再在後續 expression 中呼叫 `gen_prevlinkhdr_check()`，使 `cstate->is_geneve` 為 true。

### 完整 data flow

Fuzz target 的關鍵資料流：

```c
memcpy(filter_str, Data, Size);
filter_str[Size] = '\0';
pcap_compile(p, &fcode, filter_str, 1, PCAP_NETMASK_UNKNOWN);
```

`Data` 全量成為 `pcap_compile()` 的 filter string。`pcap_compile()` 建立 `compiler_state_t cstate`，`init_linktype()` 先把 `cstate->is_geneve = 0`，接著 `pcap_parse()` 解析 filter。

Geneve setter：

```c
// grammar.y.in
other:
    GENEVE pnum { $$ = gen_geneve(cstate, $2, 1); }
  | GENEVE      { $$ = gen_geneve(cstate, 0, 0); }

// gencode.c
gen_geneve(...) {
    ...
    cstate->is_geneve = 1;
    return b1;
}
```

Blocked predicate：

```c
gen_prevlinkhdr_check(cstate) {
    if (cstate->is_geneve)
        return gen_geneve_ll_check(cstate);
    ...
}
```

可跨 blocked side 的 parser route：

```c
// scanner.l
link|ether|ppp|slip  return LINK;

// grammar.y.in
pname: LINK { $$ = Q_LINK; }
nid: EID { $$.b = gen_ecode(cstate, $1, $$.q = $<blk>0.q); }

// gencode.c
gen_ecode(...) {
    if ((q.addr == Q_HOST || q.addr == Q_DEFAULT) && q.proto == Q_LINK) {
        ...
        tmp = gen_prevlinkhdr_check(cstate);
        b = gen_ehostop(cstate, cstate->e, (int)q.dir);
        ...
    }
}
```

因此最小候選 filter 是（source-level 推導合理，仍需 replay/coverage 驗證）：

```text
geneve and link host 00:11:22:33:44:55
geneve and ether host 00:11:22:33:44:55
```

這裡 MAC literal 走 `EID -> gen_ecode()`，`link`/`ether` 走 `LINK -> Q_LINK`，而 `geneve` 已先把同一個 `cstate->is_geneve` 設成 1，所以 `gen_prevlinkhdr_check()` 的 true side 可被 input 觸發。

### 對 log / 原推論的修正

log 中 observed runtime segment 是：

```text
pcap_compile -> pcap_parse -> gen_proto_abbrev -> gen_proto -> gen_linktype -> gen_prevlinkhdr_check
```

這條 observed path 只能證明目前 corpus 會用 protocol abbreviation 走到 line 3149，而且當時 `is_geneve` 是 false。它不是跨 line 3150 的可行路徑。原因在 `gen_linktype()`：

```c
if (!cstate->is_geneve)
    b0 = gen_prevlinkhdr_check(cstate);
else
    b0 = NULL;
```

也就是說，當 `is_geneve == 1` 時，`gen_linktype()` 反而不會呼叫 `gen_prevlinkhdr_check()`。所以「找到 `gen_geneve()` setter」還不夠，還必須找 setter 之後仍會讀該 state 的 caller。`gen_ecode()` + MAC literal 是這個 case 目前 source-level 推導的高可信 candidate route（`gen_scode()` 因外部 name database 依賴而不可靠，見修正一；`gen_prevlinkhdr_check` 尚有其他 callsite 如 `gen_broadcast()`、`gen_multicast()` 未被排除，見修正五；需 replay/coverage 驗證才能稱為 confirmed route）。

seedgen log 也支持這點：第一輪其實產生了 `F01_simple_geneve`，不是一開始就全偏到 BPF binary；但代表 seed 的 linecov 顯示 line 3149 hit count 是 0。這表示 `geneve` seed 連 reader 都沒打到。後續 iteration 被 `PUSH_LINKHDR` reset 的分析誤導，才轉去 `bpf_validate()` raw BPF bytes；那條 path 和 `compiler_state_t cstate` 沒有資料流關係。

---

## Case B：`gen_scode` at `gencode.c:6703`

### 判斷

**Input Dependent。** `proto` 來自 parser 對 filter string 的 `qual`，而 filter string 來自 fuzzer input。只要 input 被正確切成「valid pcap file half + filter half」，並讓 filter 產生 `q.proto == Q_LINK` 且呼叫 `gen_scode()`，line 6704 就能被 hit。

### 完整 data flow

Fuzz target 的 input layout：

```c
const int dlt = Data[0];
const size_t pcap_data_size = (Size - 1) / 2;
const uint8_t *pcap_data = Data + 1;
const char *filter_string_data = (const char *)(pcap_data + pcap_data_size);
const size_t filter_string_size = Size - 1 - pcap_data_size;

pcap_file = buffer_to_file(pcap_data, pcap_data_size, ...);
p = pcap_fopen_offline(pcap_file, errbuf);
pcap_set_datalink(p, dlt);
pcap_compile(p, &fcode, filter_string, 1, PCAP_NETMASK_UNKNOWN);
```

所以 seed 不是 `Data[0] + pcap_header + filter` 就好；`filter` 必須剛好落在 `Data[1:]` 的後半段。若剩餘資料長度是 `N`，`pcap_compile()` 看到的 filter 會從 `Data + 1 + floor(N / 2)` 開始。log 裡 generator 產生的 `F01_link_ether_dlt_en10mb_00.bin` 長度是 52 bytes，內容是：

```text
Data[0] + 24-byte pcap header + "link host 00:11:22:33:44:55"
```

但 `N = 51`，`pcap_data_size = 25`，filter 實際會從第 26 byte 開始，也就是跳過 `link...` 的第一個 byte，變成 `"ink host ..."`。代表 seed 的 linecov 顯示 line 6703 hit count 是 0，這不是「到 branch 但 proto 不對」，而是 generated seed 根本沒正確 materialize 到 parser path。

這個 target 的 seed layout 應該用公式產生：

```text
Data = dlt_byte + pcap_half + filter_half
len(pcap_half) == len(filter_half) 或 len(filter_half) - 1
pcap_half 必須以 valid 24-byte pcap global header 開頭
filter_half 才是 pcap_compile() 實際收到的 filter string
```

如果 filter 太短，就加長 identifier 或在 filter 後補合法 whitespace；如果 pcap half 太短，就在 valid pcap header 後補 padding。重點是滿足 target 的 `floor((Size - 1) / 2)` 切點。

`Q_LINK` 的來源：

```c
// scanner.l
link|ether|ppp|slip  return LINK;

// grammar.y.in
pname: LINK { $$ = Q_LINK; }
```

`gen_scode()` 的 caller 條件：

```c
// grammar.y.in
nid: ID { $$.b = gen_scode(cstate, $1, $$.q = $<blk>0.q); }
```

blocked predicate：

```c
gen_scode(...) {
    int proto = q.proto;
    ...
    case Q_DEFAULT:
    case Q_HOST:
        if (proto == Q_LINK) {
            switch (cstate->linktype) {
            ...
```

因此要進 `gen_scode()`，`host` 後面的 name 必須是 `ID` token。`link host 00:11:22:33:44:55` 不是好 seed，因為 MAC literal 是 `EID`，grammar 會走 `gen_ecode()`：

```c
nid: EID { $$.b = gen_ecode(cstate, $1, $$.q = $<blk>0.q); }
```

對這個 blocker 更精準的 filter 是：

```text
link host fuzzgen_name
ether host fuzzgen_name
```

`fuzzgen_name` 查不到 ether host 也沒關係；`pcap_ether_hostton(name)` 的錯誤發生在 line 6704 之後，blocked side 的 `switch` statement 已經被執行。

### 對 log / 原推論的修正

原文說「`ether` 對應 Q_ETHER，不是 Q_LINK」不成立。這份 source 裡沒有 `Q_ETHER`；`scanner.l` 明確把 `ether` 和 `link` 都映到 `LINK` token，`grammar.y.in` 再映成 `Q_LINK`。

Case B seedgen 真正踩到兩個問題：

1. **Input slicing 錯**：沒有依照 target 的 `(Size - 1) / 2` 切分規則安排 bytes，導致 filter string 被切歪。
2. **Parser route 錯**：用 MAC literal 會走 `EID -> gen_ecode()`，不會走目標函式 `gen_scode()`；要用一般 identifier 才會走 `ID -> gen_scode()`。

iteration feedback 也有誤導性。它回報 `stalled_at_branch`，但 family-level representative 的 `branch_hits=0`，代表 generated families 沒有 hit branch line。這種狀況應該回報 `did_not_reach_branch`，並附上「API gate / parser route / input slice」哪一層失敗，而不是只說 predicate 沒滿足。

---

## 對原 `infer.md` 的評估

原本的主方向「不要只看整個 fuzz target，要沿著通往 blocker 的 input path 做推論」是對的，但需要修正成更嚴格的版本。

正確的部分：

- Runtime-anchored format inference 是必要的。multi-path target 裡，`bpf_validate()` 和 `pcap_compile()` 同時吃 `Data`，不能因為看到 raw BPF API 就把 blocker input format 判成 BPF instruction binary。
- Predicate setter search 是必要的。`is_geneve`、`Q_LINK` 這類 predicate value 通常不是直接 byte compare，而是 parser/state machine 產生的語意狀態。
- Iteration feedback 太粗。只回 `stalled_at_branch` 不足以讓下一輪知道是 input slice 錯、parser route 錯、predicate value 錯，還是 state 被 reset。

需要修正的部分：

- Case A 不能只說「看到 `gen_geneve()` setter，所以產生 `geneve`」。必須再檢查 setter 之後是否有 reader call site 會讀到該 state。`gen_linktype()` 在 `is_geneve == 1` 時跳過 reader，`gen_ecode()` + MAC literal 是目前 source-level 推導的高可信 candidate route（`gen_scode()` 因外部 name database 依賴而不可靠，見修正一；`gen_prevlinkhdr_check` 有其他 callsite 尚待枚舉，見修正五；需 replay 驗證）。
- Case A 不是一開始就全部被推成 BPF binary；第一輪有 geneve filter families，只是缺少能觸發 reader 的後半段 expression。BPF binary 是後續錯誤 refinement 的結果。
- Case B 不是 `ether` 對應錯 constant。`ether` 和 `link` 都會產生 `Q_LINK`；失敗主因是 input split 錯，以及 MAC literal 走 `gen_ecode()` 而不是 `gen_scode()`。
- `PUSH_LINKHDR` reset 不能被當成全域不可達證明。它只證明某些 encapsulation transition path 會清掉 `is_geneve`；若另一個 caller 在 reset 後或不經 reset 的狀態下讀 predicate，就仍然可達。

---

## 泛用改善方向

### 1. Runtime-Anchored Argument Materialization

format inference 不只要找「第一個 library API」，還要還原該 API 的 blocker-relevant argument 是怎麼從 `Data` materialize 出來的。

必做資訊：

| 項目 | 需要回答 |
|---|---|
| API anchor | runtime path 第一個和 blocker 相關的 library API，例如 `pcap_compile()` |
| argument anchor | 哪個參數控制 predicate，例如 `buf/filter_string`、file content、length、mode flag |
| byte slice | 該參數來自 `Data` 的哪個 slice、是否有 split、padding、length prefix、delimiter、FDP consume |
| transform | 是否經過 null termination、temporary file、decompression、parser、endianness、struct packing |
| gate | 到達 API 前有沒有 file magic、header、checksum、size、open/parse success gate |

Case B 就是這層失敗：LLM 生成了看似正確的 filter，但沒有放到 target 實際傳給 `pcap_compile()` 的 slice。

### 2. Predicate Setter-Reader-Survival Trace

PVOT 應該擴充成「setter + reader + survival」三段，不然會只找到能設值的語法，卻找不到能在 blocked predicate 讀到該值的路徑。

流程：

1. 解析 blocked predicate，找出 target variable 與 required value。
2. 搜尋 setter：assignments、constructor/init、parser semantic action、state transition、enum/macro mapping。
3. 搜尋 reader call sites：哪些 caller 會在 setter 後讀這個 variable 或把它傳進 blocked function。
4. 檢查 survival：setter 到 reader 之間是否有 reset、macro side effect、RAII destructor、cleanup、longjmp、early return、parser reduce order、state pop。
5. 只有 setter 和 reader 都能被同一份 input 串起來，才交給 seed generator。

Case A 的關鍵不是 `gen_geneve()` 本身，而是 `gen_geneve()` 之後接 `gen_ecode()`（source-level 推導的高可信 candidate route，需 replay 驗證；`gen_scode()` 在此 case 中因外部 name database 依賴而不可靠，見修正一；`gen_prevlinkhdr_check` 有其他 callsite 尚待枚舉，見修正五）。

### 3. Parser / DSL 專案要收 lexer + grammar + semantic action

對 C/C++ parser 類專案，不能只收 target function 和 header。至少要補：

- lexer token rules：表面字串如何變 token。
- grammar reduction：token 如何變 enum/qualifier/AST node。
- semantic action：哪個 reduction 呼叫目標 function 或 setter。
- token class 分流：例如 `ID` 走 `gen_scode()`，`EID` 走 `gen_ecode()`。

Case B 如果只知道 `Q_LINK = 1` 還不夠；必須知道 `link|ether -> LINK -> Q_LINK`，以及 `ID -> gen_scode()`、`EID -> gen_ecode()` 的分流。

### 4. Feedback 要分成 branch reach、predicate value、route diagnosis

每個 generated seed / family 都要回報自己的結果，不能只看 merge 後 corpus 是否已經 hit 過 branch。

最低限度 feedback：

```yaml
seed_result:
  reached_target_function: true/false
  branch_line_hit_count: 0
  blocked_side_hit_count: 0
  status: did_not_reach_branch | reached_branch_predicate_false | reached_blocked_side
  api_gate:
    pcap_fopen_offline: success/fail/unknown
    pcap_compile: success/fail/unknown
  argument_observation:
    filter_string_preview: "ink host ..."
    expected_prefix: "link host"
  route_observation:
    expected_caller: gen_scode
    observed_caller: gen_ecode | none | unknown
  predicate_gap:
    expression: "proto == Q_LINK"
    required: "Q_LINK = 1"
    observed: "Q_DEFAULT = 0" # only when branch is actually hit
```

如果 branch hit count 是 0，就不要回 `stalled_at_branch`；應該先診斷 target function / API gate / parser route / input slice 哪一層沒到。

### 5. Input-Dependent / Input-Independent 分類規則要避免兩種誤判

判為 **Input Dependent** 的條件：

- current target 不改 code 時，input bytes 能 materialize 成 blocker-relevant API argument；
- 該 argument 能經 parser/decoder/state machine 產生 required predicate value；
- required state/value 能 survive 到 blocked predicate；
- blocked side 之前沒有不可由 input 控制的 hard gate。

判為 **Input Independent** 的條件：

- required setter 在目前 target 範圍內不存在；
- setter 存在但所有 reader path 前都必定 reset/覆寫；
- harness 固定值、FDP starvation、固定 size/slice 讓 required argument 無法被 materialize；
- predicate 依賴環境或系統錯誤，input bytes 不能可靠控制；
- blocked side 需要改 fuzz target lifecycle/API sequence 才可能到達。

Case A 和 Case B 都沒有符合 Input Independent 條件；它們是 seed generation context 不足與 materialization 錯誤。

---

## 實作優先順序

以 `blocker_input_contract` 為核心機制，統一覆蓋從 Data bytes 到 blocked predicate 之間各層的失敗：

```
Data bytes
→ [P0-A] harness slicing contract（bytes 如何對應 API argument）
→ [P0-B] API argument preview（API 實際收到什麼）
→ [P0-C] setter-reader-survival trace（predicate variable 的設值路徑是否通）
→ [P0-D] parser/DSL context（lexer token + grammar reduction + semantic action）
→ [P1-A] per-seed feedback taxonomy（branch hit / predicate false / blocked hit 分清楚）
→ [P1-B] predicate value instrumentation（branch 已 hit 但 false 才需要）
```

| 優先級 | 能力 | 解決的根本問題 | 實作方式 |
|---|---|---|---|
| P0-A | Harness slicing contract | seed bytes 放錯位置（Case B）| prompt Step 0B 強制輸出 layout table |
| P0-B | API argument preview | 確認 API 收到的是否就是設計的 input | feedback 加 `argument_preview` 欄位 |
| P0-C | Setter-Reader-Survival trace | 只找 setter、沒驗 reader 是否可達（Case A）| prompt Step 0C/D/E；search setter → reader → survival |
| P0-D | Parser/DSL context | LLM 不知道 token → qualifier → API 的映射（Case B）| 對 parser 類專案，targeted 收入 lexer rule + grammar reduction + semantic action |
| P1-A | Per-seed feedback taxonomy | `stalled_at_branch` 掩蓋「根本沒打到 target function」的問題 | feedback 加 `did_not_reach_branch / predicate_false / blocked_side_hit` 三分類 |
| P1-B | Predicate value instrumentation | branch 已 hit 但 predicate false，下一輪不知差在哪 | 只在 `predicate_false` 狀態下觸發，捕獲 observed value |

最小可行修正（Phase 1，只改 prompt）：在 `blocker_seed_generator_template` 加入 Step 0 的 `blocker_input_contract` 前置分析區塊（見下節），強制 LLM 在生 seed 前先完成 P0-A + P0-C 的推導，並在 Step 0A 中明確指出 runtime trace 是 false-side path 而非設計目標。

---

## Phase 1 實作建議：Prompt Template 為主 + 輕量 Python Evaluation 補強

上述 `blocker_input_contract` 的概念可以用最低成本先在 prompt 層落地：在 `blocker_seed_generator_template` 加一段強制的前置分析區塊，讓 LLM 在生 seed 之前先推導出 contract 再行動。Evaluation 層的 `generated_family_reached_blocked_side` 欄位屬於輕量 Python 補強，工作量小，可同步進行。

### 加入 prompt 的區塊

```
## Step 0: Blocker Input Contract (REQUIRED — complete this before designing any seed)

You MUST fill in this contract before writing any generator code.
If you skip or hallucinate any field, the generated seeds will likely fail.

### 0A. API Anchor
Which specific fuzz target API call is the one that eventually leads to the blocker function?
Quote the exact call site line from the fuzz target code.
(Use the Runtime Call Trace above as primary evidence, not static guessing.)

**NOTE: The runtime trace shows how CURRENT seeds travel toward the blocker —
the OBSERVED route, typically ending at the false side of the predicate.
Use it to identify the API call and the argument's byte range in Data.
Do NOT copy the same internal semantic route (caller, expression form, token type).
Find a different route that satisfies the predicate and reaches the BLOCKED SIDE instead.**

### 0B. Input Layout
How does `Data[0..Size]` map to the API anchor's blocker-relevant argument?

Determine the input mode first:
- **Raw mode**: fuzz target uses pointer arithmetic / memcpy / array indexing
- **FDP mode**: fuzz target uses FuzzedDataProvider (fdp.ConsumeXXX calls)

**[Raw mode]** Output a layout table:
| Field name | Byte range formula | Notes |
(e.g., `filter_string | Data[1 + floor((Size-1)/2) : end] | pcap_compile 3rd arg`)

If the blocker-relevant argument receives ALL of Data verbatim without any slicing
or transformation, write "trivial: entire Data is the argument" and skip the table.

**[FDP mode]** List FDP consume calls in order with their fixed/variable byte sizes:
| Call # | FDP method | Byte size | Maps to | Blocker-relevant? |
For variable-length consumes, note that position of later fields is data-dependent.

### 0C. Predicate Setter Path
Which input syntax / value / call sets the predicate variable to the required value?
(Do NOT just name the internal setter function — name the input-level trigger, e.g.,
"filter string containing the keyword 'geneve'" or "FDP consume call #3 returning 1")

### 0D. Reader Path
After the setter fires, which call path leads to the blocked predicate reading that value?
Is this the same path the runtime trace showed, or a different caller?

### 0E. Survival Check
Between setter and reader, is there any reset / override / early-return that would
clear the required value before the predicate is evaluated?
If yes, describe how the seed must avoid triggering it.

---
Only after completing the contract above, proceed to design the seed families.
Each seed MUST:
1. Place the blocker-relevant content at the byte offset identified in 0B.
2. Use the input syntax identified in 0C to trigger the setter.
3. Ensure the execution reaches the reader path identified in 0D.
```

### 為何不需要改系統

這個區塊只加在 template 裡，不需要改任何 Python 代碼。效果是：
- LLM 被強制先輸出 contract，再寫 generator code；contract 中的每一步暴露了推斷過程，便於 debug
- 若 LLM 的 0B 分析是錯的，生出的 seed 馬上會在 layout 就失敗，可以在下一個 iteration 用 `argument_observation.filter_string_preview` 的 feedback 修正
- FDP 的變長 consume 問題在 0B 中被明確標注，LLM 至少會意識到後續 field 的 offset 不確定

### 局限性

- LLM 仍可能幻覺 layout（尤其是複雜 FDP target 的變長 consume 後面的 field）
- 若 0C 的 setter 在 `grammar.y` / lexer 等 context 缺失的情況下，LLM 可能猜錯 input syntax
- 這些局限性是長期需要補入 grammar/lexer context 和動態 layout 偵測（Future Work）才能根本解決的

---

## 第二輪評估修正（source code 驗證後）

### 修正一：Case A 的可行 seed 路徑

**gen_scode() + ID token 路徑對 Case A 不可靠**，source code 確認：

```c
// gen_scode(), proto == Q_LINK, linktype == DLT_EN10MB
eaddr = pcap_ether_hostton(name);     // 查外部 name database（/etc/ethers）；fuzzing 環境通常為空
if (eaddr == NULL)
    bpf_error(cstate, "...");         // longjmp — 非 input-only path，gen_prevlinkhdr_check 永遠到不了
tmp = gen_prevlinkhdr_check(cstate);  // 死碼
```

**gen_ecode() + EID token（MAC literal）是目前 source-level 最可靠的候選路徑**：

```c
// gen_ecode(), q.proto == Q_LINK, linktype == DLT_EN10MB  
cstate->e = pcap_ether_aton(s);      // 解析 MAC literal，只有 malloc 才失敗
// ...
tmp = gen_prevlinkhdr_check(cstate); // 對合法 MAC 必定到達
```

**Case A 目前最高可信候選 seed**（基於 gen_ecode() route；其他 callsite routes 尚待枚舉，見修正五）：`"geneve and ether host 00:11:22:33:44:55"`
（走 EID → gen_ecode() → gen_prevlinkhdr_check，is_geneve 已被 "geneve" 設為 1）

此 seed 應標為「最小候選種子，需用覆蓋率驗證 line 3150」，而非「已證實正確解」。

---

### 修正二：「Runtime-Anchored」的正確定義

Runtime path 只用來固定兩件事：
1. **API anchor**：哪個 library API call（如 `pcap_compile`）
2. **Argument anchor**：blocker-relevant argument 對應 Data 的哪個 slice

Runtime path 上的 internal call chain（如 `gen_linktype → gen_prevlinkhdr_check`）是 **false-side 路徑**，不應成為 seed generator 的設計約束。seed generator 必須在同一 API 下找不同的語意路徑（如 gen_ecode path），而非模仿 observed 的 false-side path。

此 NOTE 已整合進上方 Phase 1 建議的 **Step 0A** prompt 本文，不需重複。

---

### 修正三：「找不到 setter」≠「Input Independent」

分類器若找不到 setter，不應直接判為 Input Independent。可能原因：
- grammar.y / lexer 等 context 沒有被收入
- macro 展開未追到
- cross-TU / generated code 未分析

建議分類器輸出時加 `evidence_confidence` 欄位：
- `confirmed_independent`：setter 存在但所有 reader path 都被 reset 或 blocked
- `low_evidence_independent`：找不到 setter，但 context 可能不完整
- `input_dependent`：setter + reader + survival 都可追溯

---

### 修正四：優先順序精修

argument preview 比 predicate value 更早應做，因為 root cause 通常在 input layout 而非 predicate value：

| 優先級 | 能力 | 對應的失敗層 |
|---|---|---|
| P0-A | Harness slicing contract（Step 0B）| seed bytes 放錯位置（Case B）|
| P0-B | API argument preview in feedback | 確認 API 收到的是否就是設計的 input |
| P0-C | Setter-Reader-Survival trace（Step 0C/D/E）| 只找 setter、沒驗 reader 是否可達（Case A）|
| P0-D | Parser/DSL context（lexer + grammar + semantic action）| LLM 不知道 token → qualifier 映射（Case B）|
| P1-A | Per-seed feedback taxonomy | `stalled_at_branch` 掩蓋更上游的失敗 |
| P1-B | Predicate value instrumentation | branch 已 hit 但 false，此時才需要 |

**Predicate value instrumentation 降為 P1-B**：只有在 branch line 確實被 hit、且 blocked side 沒被 hit 的情況下才啟用；其他情況先用 argument preview 診斷更有效率。

---

### 修正五：Reader Callsite Enumeration 原則（第五輪評估補充）

**背景**：前四輪修正把 Case A 的可靠 reader 描述為「唯一是 gen_ecode()」，但 `gen_prevlinkhdr_check()` 的 callsite 不止 gen_ecode() 一個。已知的 callsite 包括：

| Caller | Filter 觸發形式 | external dependency? | 與 is_geneve=1 相容? |
|---|---|---|---|
| `gen_ecode()` | `ether host <MAC literal>` | 無（pcap_ether_aton 只有 malloc 會失敗）| ✅ source code 靜態確認（replay 尚未完成）|
| `gen_broadcast()` | `geneve and broadcast` | 無 | 🔶 尚未驗證 |
| `gen_multicast()` | `geneve and multicast` | 無 | 🔶 尚未驗證 |
| `gen_linktype()` | 任何 proto keyword | 無 | ❌ is_geneve==1 時跳過 |
| `gen_scode()` | `ether host <hostname>` | pcap_ether_hostton → /etc/ethers | ❌ fuzzing env 幾乎確定失敗 |

**原則**：系統在找到第一條 viable reader route 後不應停止搜尋。應枚舉所有 callsite → 評估各自 input trigger（是否可由 filter bytes 控制）+ external dependency + survival → 排序候選 → 對高可信 route 各產生一個 family。

這是 P0-C（Setter-Reader-Survival trace）的自然延伸：

```
P0-C 擴充流程：
1. 解析 blocked predicate，找 target variable
2. 搜尋 setter（gen_geneve → is_geneve=1）
3. 枚舉所有讀取該 variable 的 reader callsite
4. 對每個 callsite 評估：input trigger / external dep / survival
5. 排序：無外部依賴 + input-only path → 最高優先
6. 對排名前 N 個 route 各產生一個 seed family
```

**already_covered_in_baseline 策略（確認）**：系統的停止邏輯不因此改變。增加 `seed_contract_reproduction_success` 欄位是為了回報「seed generator 是否成功」，不是為了讓系統繼續 iterate。

---

## 最終結論（多輪分析收斂）

### 文件狀態

本文件已歷經多輪分析與評估，技術方向已收斂。核心機制是 `blocker_input_contract`：在 seed generator 生成任何 seed 之前，先強制建立「Data bytes → API argument → semantic state → predicate reader」的完整鏈條，再依此 contract 產生 bytes。

### 已確立的技術共識

| 項目 | 結論 |
|---|---|
| `gen_ecode()` + MAC literal 是 Case A 目前最高可信 reader route | ✅ source code 確認（gencode.c:7231-7238）；`gen_prevlinkhdr_check` 其他 callsite 尚待枚舉，見修正五 |
| `gen_scode()` 對 Case A 不可靠 | ✅ pcap_ether_hostton() 依賴外部 name database，失敗即 longjmp |
| `ether`/`link` 都映射到 `Q_LINK`（非 Q_ETHER）| ✅ scanner.l:259 確認 |
| MAC literal → EID → gen_ecode()；ID → gen_scode() | ✅ grammar.y.in:446/492 確認 |
| gen_linktype() 在 is_geneve==1 時跳過 gen_prevlinkhdr_check() | ✅ gencode.c:3202-3209 確認 |
| Case B 失敗根因：input split 錯 + EID/ID 分流錯 | ✅ log 與 source 雙重確認 |

### Case A 最小候選 seed（需 replay 驗證）

```text
geneve and ether host 00:11:22:33:44:55
```

推導路徑：`"geneve"` 設 `cstate->is_geneve = 1`；`"ether host <MAC>"` 走 `EID → gen_ecode()`；`gen_ecode()` 在 `Q_LINK + DLT_EN10MB` 下呼叫 `gen_prevlinkhdr_check()`；此時 `is_geneve == 1`，predicate 為 true，進入 line 3150。

此 seed 為 source-level 推導的高可信候選，**仍需執行 coverage/replay run 確認 line 3150 被 hit**。

### Phase 1 行動項目

最低成本的第一步是把 `blocker_input_contract` 概念加進 `blocker_seed_generator_template` 的 Step 0 區塊（見「Phase 1 實作建議」節），讓 LLM 在生 seed 前先明確推導 layout → setter → reader → survival。Step 0 contract 可先由 prompt template 落地；`generated_family_reached_blocked_side` / `seed_contract_reproduction_success` evaluation 欄位屬於輕量 Python 補強，可同步實作。

更完整的系統解法（P0-B API argument preview、P1-A per-seed feedback taxonomy）需改動 Python feedback 層，作為後續階段實作。

---

## 系統機制升級提案評估（2026-06-12）

### 背景：兩個 log 的對比

| | log 164420（舊 prompt）| log 170817（新 prompt）|
|---|---|---|
| [0C] 選的 filter 形式 | `host 1.2.3.4 link`（語法錯誤）| `link host example.com`（正確）|
| 所有 family branch_hits | 全 0 | F02_filter_dns_host: branch_hits=1, blocked_hits=1 |
| 整體 status | already_covered_in_baseline | already_covered_in_baseline |
| blocked_side 計數 | 2（unchanged）| 2 → 3（F02 新增 +1）|

**根本原因**：`link host example.com`（DNS name = ID token → gen_scode）與 `link host 1.2.3.4`（IP address token → 不走 gen_scode）和 `link host 00:11:22:33:44:55`（EID → gen_ecode）在 parser dispatch 層是完全不同的路徑，儘管三者語意上看起來都是「link-layer host expression」。

---

### 提案評估

#### 提案一：硬化 [0C] representation category（prompt 改動）

**判斷：✅ 應立即實作**

Log 對比直接支持：新 prompt 加了「exact representation category」的說明，但 [0C] 的 example 還是混了 IP、DNS、MAC 三種形式，只有 DNS name 成功。需要在 [0C] 說明中補充：

- 不同 token class 的 surface form 必須分開成不同 family
- 必須以 parser/lexer 定義為依據（ID token vs EID vs HOSTID），不能僅憑語意相似性

**改動範圍**：只改 `blocker_seed_generator_template` 的 [0C] 說明段落，無需動系統程式。

---

#### 提案二：自動補 parser/dispatcher context（系統改動）

**判斷：✅ 應實作，P0-D，但非第一優先**

兩個 log 的 LLM 都沒有 grammar.y/scanner.l 作為 context 輸入，靠 training data 推斷 token dispatch。這次 libpcap 是碰運氣（LLM 熟悉 BPF 語法）；對陌生的 parser 類專案會直接失敗。

**實作方向**：偵測 runtime blocker segment 中是否包含 parser/grammar/lexer 函式（如 `pcap_parse`、`yyparse`、ANTLR runtime 等），若有，自動收入對應的 lexer token rule + grammar production + semantic action source code 作為額外 context。

**風險**：中。需要偵測啟發式邏輯（可能誤判）。建議先用「blocklist of known parser function names」起步，再擴充為通用偵測。

---

#### 提案三：evaluation 拆出 `generated_family_reached_blocked_side`（Python 評估層）

**判斷：✅ 應實作，工作量小**

資料已存在（family-level branch_hits/blocked_hits），只需新增欄位。兩個 log 的整體 status 都是 `already_covered_in_baseline`，讓人誤以為本輪完全無進展，但 log 2 實際上成功了（F02_filter_dns_host）。需要把兩個概念分開：

- `coverage_novelty_success`：generated seeds 是否新增了 baseline 沒有的 coverage
- `generated_family_reached_blocked_side`：任何 generated family 的代表 seed 是否本身能觸發 blocked side

**策略確認（已解決）**：若 `generated_family_reached_blocked_side = True` 但 `coverage_novelty_success = False`（如兩個 log 的情況），系統應繼續跑還是停止？**結論：停止條件不變。** `already_covered_in_baseline` 時停止是正確的預設行為。`seed_contract_reproduction_success` 是新增的回報欄位，讓 post-hoc 分析可以看清楚「這輪 seed generator 是否成功解出了 contract」，但它不是繼續 iteration 的觸發條件。「refine」邏輯只在 diagnostic/benchmark mode 才有意義，不應成為 default。

---

#### 提案四：iteration repair 根據 keep/refine/discard 精準修（prompt + 邏輯）

**判斷：🔶 方向正確，需先完成提案三**

keep/refine/discard taxonomy 已存在（log 2 輸出：`keep_families: F02_filter_dns_host`）。缺的是把這個 taxonomy 結構化地傳回下一輪 iteration prompt，要求 LLM「保留成功 family 的 representation category，只在附近做 variant」。

**依賴**：提案三需先完成。keep/refine/discard 只在非 terminal case 啟用；`already_covered_in_baseline` 預設仍停止。diagnostic/benchmark mode 才考慮繼續 refine，不應成為 default 行為。

---

#### 提案五：predicate / route value instrumentation（P1）

**判斷：🔶 確認為 Future Work**

從兩個 log 可知，當前失敗原因在 representation category 錯（提案一）和 parser context 缺失（提案二），不是「predicate value 不知道」。在 branch_hits=0 的情況下，predicate instrumentation 沒有診斷價值。只有在 branch_hits > 0 but blocked_hits = 0 時才有用，屬於 P1-B。

---

### 實作優先順序（更新，依「求解率」vs「觀測性」分層）

**短期低成本（觀測性 + prompt 直接強化）**

| # | 項目 | 目的 | 工作量 |
|---|---|---|---|
| 1 | 硬化 [0C] representation category | 求解率：避免 token class 混淆導致路徑錯誤 | 小（prompt only）|
| 2 | 新增 `generated_family_reached_blocked_side` / `seed_contract_reproduction_success` | 觀測性：區分 coverage novelty 失敗 vs seed contract 成功 | 小（Python 評估層）|

**中期提高求解率**

| # | 項目 | 目的 | 工作量 |
|---|---|---|---|
| 3 | Reader callsite enumeration（P0-C 擴充）| 求解率：找所有 viable reader routes，不只第一條 | 中（prompt + 搜尋邏輯）|
| 4 | 自動補 parser/dispatcher context（P0-D）| 求解率：對陌生 parser 類專案不依賴 LLM training data | 中（系統改動）|
| 5 | Iteration repair：keep/refine/discard（非 terminal case）| 求解率：保留成功 family，對失敗 family 做 variant | 中（prompt + 邏輯，依賴 #2）|

**長期**

| # | 項目 | 目的 | 工作量 |
|---|---|---|---|
| 6 | Predicate/route value instrumentation（P1-B）| 觀測性：branch 已 hit 但 blocked side 未 hit 時診斷 | 大（系統改動）|
