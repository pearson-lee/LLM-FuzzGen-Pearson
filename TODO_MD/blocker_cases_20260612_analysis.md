# 20260612 run_all_fuzzer blockers analysis

分析範圍：

- `experiments/20260612_020723_run_all_fuzzer/blockers/compute_local_ud_641`
- `experiments/20260612_020723_run_all_fuzzer/blockers/convert_code_r_2715`
- `experiments/20260612_020723_run_all_fuzzer/blockers/gen_prevlinkhdr_check_3149`
- `experiments/20260612_020723_run_all_fuzzer/blockers/newchunk_642`
- `experiments/20260612_020723_run_all_fuzzer/blockers/number_blks_r_2471`
- `experiments/20260612_020723_run_all_fuzzer/blockers/pcap_compile_788`
- `experiments/20260612_020723_run_all_fuzzer/blockers/pcap_parse_2056`
- `experiments/20260612_020723_run_all_fuzzer/blockers/pcap_parse_3594`
- `experiments/20260612_020723_run_all_fuzzer/blockers/yy_get_next_buffer_4629`

## 總結

這批 case 不應全部視為「input dependent 解不出來」。真實狀況可以分成五類：

1. **確定 input-independent / environmental**：`pcap_compile_788`。
2. **結構性不可由目前 API path 觸發，classifier 誤判成 dependent**：`yy_get_next_buffer_4629`、`compute_local_ud_641`。
3. **input 會放大資源需求，但 blocked side 本質是 OOM / overflow / allocation failure，不是普通可求解 predicate**：`newchunk_642`、`convert_code_r_2715`、`number_blks_r_2471`。
4. **Bison error recovery 類，和 malformed input 有關，但目前 coverage/recovery 行為不支持「簡單 dependent 可解」**：`pcap_parse_2056`、`pcap_parse_3594`。其中 `pcap_parse_2056` 另有既有紀錄指出是 crash-revealing blocker。
5. **真正 input-dependent，但 classifier 少講必要時序與後續 filter 條件**：`gen_prevlinkhdr_check_3149`。

revalidation 數字如下，全部都是 branch line 已達、blocked side 仍為 0：

| Case | Branch line | Blocked side | Live hit count |
|---|---:|---:|---:|
| `compute_local_ud_641` | 641 | 646 | 32.7M / 0 |
| `convert_code_r_2715` | 2715 | 2716 | 47.5M / 0 |
| `gen_prevlinkhdr_check_3149` | 3149 | 3150 | 163k / 0 |
| `newchunk_642` | 642 | 643 | 19.2M / 0 |
| `number_blks_r_2471` | 2471 | 2475 | 665k / 0 |
| `pcap_compile_788` | 788 | 789 | 27.5k / 0 |
| `pcap_parse_2056` | 2056 | 2057 | 6.56M / 0 |
| `pcap_parse_3594` | 3594 | 3599 | 8.72k / 0 |
| `yy_get_next_buffer_4629` | 4629 | 4651 | 40.9k / 0 |

## Case-by-case

### `pcap_compile_788`

判斷：classifier 正確，這是 input-independent / environmental。

Source 條件在 `external/oss-fuzz/build/out/libpcap/src/libpcap/gencode.c:788`：

```c
if (pcap_lex_init(&scanner) != 0)
    pcap_fmt_errmsg_for_errno(...);
in_buffer = pcap__scan_string(xbuf ? xbuf : "", scanner);
```

真實 dataflow：

1. Fuzzer input 只會進入 `buf` / `xbuf`。
2. `pcap_lex_init(&scanner)` 發生在 `pcap__scan_string()` 前。
3. `pcap_lex_init` 對應 Flex `yylex_init`，只有 `ptr_yy_globals == NULL` 或 `yyalloc(sizeof(struct yyguts_t)) == NULL` 會回傳 non-zero。
4. 這裡傳入的是 local stack variable `&scanner`，不可能是 NULL。
5. 剩下就是固定大小 allocation failure，和 input bytes 無關。

pipeline 現況：走 independent target pipeline，`reference_guided_generation` 與 `dedicated_generation` 都失敗，這符合預期。

優化：這類應直接標成 `Environmental Allocation Failure`，不要進 seed generation。

### `yy_get_next_buffer_4629`

判斷：classifier 誤判。它標成 Input Dependent，但目前 `pcap_compile` API path 下是結構性不可達。

Source 條件在 `build/scanner.c:4629`：

```c
if (YY_CURRENT_BUFFER_LVALUE->yy_fill_buffer == 0) {
    return EOB_ACT_END_OF_FILE or EOB_ACT_LAST_MATCH;
}
number_to_move = ...;  // blocked side at 4651
```

真實 dataflow：

1. `pcap_compile` 用 `pcap__scan_string(xbuf ? xbuf : "", scanner)`。
2. `pcap__scan_string()` 是 `yy_scan_string()`，它呼叫 `yy_scan_bytes()`.
3. `yy_scan_bytes()` 建立一份 buffer 後呼叫 `yy_scan_buffer()`.
4. `yy_scan_buffer()` 固定設 `b->yy_fill_buffer = 0`。
5. 因此不管 filter string 是空、非空、很長、或 malformed，`yy_fill_buffer` 都不是 input-controlled non-zero。
6. `yy_fill_buffer = 1` 只在 `yy_create_buffer(FILE*, ...)` / `yy_init_buffer()` 這類檔案輸入 scanner path 會出現，但目前 `pcap_compile` 用的是 scan-string path。

classifier 問題：

- 錯把「filter string 非空」推成 `yy_fill_buffer != 0`。
- 少追 `pcap__scan_string -> yy_scan_bytes -> yy_scan_buffer`。
- 少區分 Flex buffer source 類型：scan-string buffer 不會 refill。

pipeline 現況：LLM generator、original-target SymCC、generated-harness SymCC 都沒有打到 blocked side。這不是 seed 不夠，是 API path 限制。

優化：classifier 應加入 Flex generated scanner 規則，看到 `scan_string` / `scan_bytes` 應直接把 `yy_fill_buffer != 0` side 標為 current-path unreachable。

### `compute_local_ud_641`

判斷：classifier 誤判或至少嚴重過度樂觀。它標成 Input Dependent，但真實 blocked side 是 libpcap 內部 BPF scratch memory invariant 被破壞。

Source 條件在 `optimize.c:641`：

```c
atom = atomuse(&s->s);
...
else if (atom < N_ATOMS) {
    ...
}
else
    abort();
```

`N_ATOMS = BPF_MEMWORDS + 2`，`BPF_MEMWORDS = 16`，所以 `N_ATOMS = 18`。合法 atom domain 是：

- `0..15`：BPF scratch memory `M[0..15]`
- `16`：A register
- `17`：X register
- `18`：特殊 `AX_ATOM`，在前一個 branch 被處理

真實 dataflow：

1. `atomuse()` 在 `BPF_LD|BPF_MEM` / `BPF_LDX|BPF_MEM` 時回傳 `s->k`。
2. 這裡的 `s->k` 不是 `ip[1000000]` 這種 packet offset，而是 BPF scratch memory index。
3. libpcap compiler 內部用 `alloc_reg()` 配 scratch register。
4. `alloc_reg()` 只會回傳 `0..15`，用完會 `bpf_error("too many registers needed...")`，不會合法產生 `>= 18`。
5. 因此 line 646 的 `abort()` 表示 compiler 產生了非法 internal BPF_MEM index，或記憶體被破壞，不是 filter string 可直接指定的大 offset。

classifier 問題：

- 把 packet access offset `ip[20]` / `ip[1000000]` 誤當成 BPF scratch memory index。
- 沒追 `alloc_reg()` 的 bounded domain。
- 沒把 `abort()` 辨識成 internal invariant guard。

pipeline 現況：

- LLM generator 產生 arithmetic / X register 相關 filters，但 representative 都沒有達到該 branch。
- Generated harness + LibFuzzer + SymCC 有跑，最終 corpus 5543，blocked side 仍 0。

優化：classifier 要把 `BPF_MEM` 的 `s->k` 語意分清楚。看到 `atomuse/atomdef` 這類 optimizer internal register domain，要追 producer 是否為 `alloc_reg()`，不能只看到 `s->k` 就判 input dependent。

### `convert_code_r_2715`

判斷：目前分類為 Input Dependent 但理由錯；更準確是 input-amplified allocation failure / resource-dependent。

Source 條件在 `optimize.c:2713-2716`：

```c
if (slen) {
    offset = calloc(slen, sizeof(struct slist *));
    if (!offset) {
        conv_error(conv_state, "not enough core");
    }
}
```

真實 dataflow：

1. `slen = slength(p->stmts)`，確實由 filter compiler 產生的 block statements 數量決定，間接受 input 影響。
2. 但 blocked side 不是 `slen == 0`。`if (!offset)` 位在 `if (slen)` 裡，所以 `slen == 0` 時根本不會執行 line 2715。
3. line 2715 的 blocked side 只代表 `calloc(slen, ...)` 回傳 NULL。
4. 因此要打到 blocked side，要嘛 `slen` 大到 allocation fail，要嘛系統環境 OOM。

classifier 問題：

- 明確誤判：它說「如果 `slen == 0`，`offset` 會保持 NULL，blocked branch 會 taken」。這和 source 相反。
- 少把 allocation failure 和 semantic predicate 分開。

pipeline 現況：

- Generator 產生很長的 arithmetic filter，evaluation 出現 timeout，stack 在 `sappend -> gen_arth -> pcap_parse`。
- SymCC generated harness：baseline 1270 seeds，final corpus 3725，blocked side 仍 0。

優化：這類應標為 `Resource-dependent allocation failure`。如果真的要驗證，應用 allocator fault injection 或 memory limit，而不是期待 SymCC 解出 `calloc` NULL。

### `newchunk_642`

判斷：目前分類為 Input Dependent 只在很寬鬆意義上成立；更準確是 input-amplified resource exhaustion。

Source 條件在 `gencode.c:641-643`：

```c
p = newchunk_nolongjmp(cstate, n);
if (p == NULL) {
    longjmp(cstate->top_ctx, 1);
}
```

`newchunk_nolongjmp()` 回傳 NULL 的條件：

1. `k >= NCHUNKS`，其中 `NCHUNKS = 16`。
2. `malloc(size)` 失敗。
3. `n > size`。

真實 dataflow：

1. Input filter 越複雜，會生成越多 `new_block`、`new_stmt`、`newchunk` allocation。
2. 但每次 allocation 大多是固定 struct size，不是 input byte 直接指定 `n`。
3. 要觸發 blocked side，本質上是耗盡 chunk pool 或讓 malloc 失敗。
4. live revalidation 顯示 line 642 執行 19.2M 次仍無 NULL，代表一般 corpus/seed 增長遠未造成 chunk pool/OOM failure。

pipeline 現況：

- LLM generator iteration 1 產生 OR/host 類 chunk exhaustion seeds，部分 representative 到 branch，blocked side 0。
- iteration 2 是空 LLM response，stage 記錄為 `llm_error`。
- 後續 generated harness + LibFuzzer 擴到 1338 seeds，SymCC final corpus 4403，仍未 hit blocked side。

優化：與 `convert_code_r` 一樣，應分到 resource-exhaustion 類。可選策略是 fault-injection allocator、降低 `NCHUNKS` / chunk size 的 test build、或 memory limit replay；不應把它當普通 input predicate 給 SymCC。

### `number_blks_r_2471`

判斷：classifier 的「理論 input dependent」過度寬鬆。真實狀況是 practically infeasible overflow guard。

Source 條件在 `optimize.c:2470-2475`：

```c
n = opt_state->n_blocks++;
if (opt_state->n_blocks == 0) {
    opt_error(opt_state, "filter is too complex to optimize");
}
```

真實 dataflow：

1. `opt_state->n_blocks` 是 `u_int` block counter。
2. blocked side 只有在 post-increment 從 `UINT_MAX` wrap 到 0 時發生。
3. 在 `opt_init()` 裡，進入 `number_blks_r()` 前會先：
   - `n = count_blocks(ic, ic->root)`
   - `calloc(n, sizeof(*opt_state->blocks))`
   - `opt_state->n_blocks = 0`
   - `number_blks_r(...)`
4. 所以要 hit line 2475，需要先成功建立並配置接近 2^32 個 CFG block。這在現實 fuzz / SymCC pipeline 中不可行。

classifier 問題：

- 只說「block count 是 filter structure 的 semantic property」，但沒有把 `UINT_MAX` overflow 與前置 `calloc(n)` feasibility 納入判斷。

pipeline 現況：

- Generator 的 long OR/AND filters 確實提升 branch hit count，代表方向能增加 CFG block。
- 但 blocked side 仍 0，SymCC final corpus 2264 也未 hit。

優化：新增 `counter-overflow infeasible` 分類。這類可以報告為 input-amplified but infeasible，不應要求 generator/SymCC 解到。

### `pcap_parse_2056`

判斷：目前 classifier 標 Input Independent，基本合理，但需要保留既有 crash-revealing 補充結論。

Source 條件在 `build/grammar.c:2056-2057`：

```c
if (yyerrstatus)
    yyerrstatus--;
```

真實 dataflow：

1. `yyerrstatus` 是 Bison parser error recovery counter。
2. 語法錯誤後會在 `yyerrlab1` 設為 3。
3. 要 hit line 2057，parser 必須成功 shift recovery token，回到 main parse loop，且在後續 token shift 時 `yyerrstatus` 仍為 non-zero。
4. 一般 malformed input 會讓 parser abort，沒有成功復原到 shift 路徑。

pipeline 現況：

- independent target pipeline 失敗。
- 既有 `TODO_MD/symcc_exception.md` 記錄指出，修過 generated harness format mismatch 後，SymCC 可生成大量 error-recovery 相關 seeds，但 coverage binary 會因 libpcap error recovery double free 而 SIGABRT，導致 coverage profile 無法可靠寫出。

結論：這個 case 不應當作普通 failed blocker。比較準確的定性是 `crash-revealing / parser error recovery blocker`。

優化：若要讓 coverage 能量到 crash 前路徑，需要在 replay driver 層加 SIGABRT profile flush，或用不 abort 的 allocator / 修 libpcap double free。

### `pcap_parse_3594`

判斷：classifier 標 Input Dependent 偏樂觀。它和 `pcap_parse_2056` 同屬 Bison error recovery，但要 hit 的條件更具體。

Source 條件在 `build/grammar.c:3594-3603`：

```c
if (yyerrstatus == 3) {
    if (yychar <= YYEOF) {
        if (yychar == YYEOF)
            YYABORT;
    }
    ...
}
```

真實 dataflow：

1. line 3594 位於 `yyerrlab` 中。
2. 第一次 syntax error 進來時，`yyerrstatus` 通常仍是 0，所以 line 3599 不會執行。
3. 要 hit line 3599，需要 parser 已經在 error recovery 狀態，也就是 `yyerrstatus == 3`，又再次進入 error handling。
4. 因此不只是「malformed input 後 EOF」；它需要一條會讓 parser 進入 recovery、再重用或丟棄 lookahead 的特定錯誤復原路徑。

classifier 問題：

- 少說明「第二次 error during recovery」或「failed to reuse lookahead token after error」這個時序。
- 把 `yychar <= YYEOF` 描述得像單純結尾即可，但實際上 outer `yyerrstatus == 3` 是主要 blocker。

pipeline 現況：

- Generator 的 `pflog and reason invalid_reason`、`ip and )` 類 inputs 可提高 branch-line hit count。
- 但 line 3599 仍 0。
- SymCC generated harness final corpus 3655，仍未 hit。

優化：classifier prompt 應針對 Bison template 加規則：`yyerrstatus == 3` 在 `yyerrlab` 中不是一般 input token predicate，而是 error recovery phase predicate，需要找能成功 shift `error` token 的 grammar state。

### `gen_prevlinkhdr_check_3149`

判斷：這是此批裡最接近真正 input-dependent 的 case，但 classifier 少給關鍵時序與後續 expression 條件。

Source 條件在 `gencode.c:3149-3150`：

```c
if (cstate->is_geneve)
    return gen_geneve_ll_check(cstate);
```

真實 dataflow：

1. `cstate->is_geneve` 在 `init_linktype()` 初始化為 0。
2. `gen_geneve()` 會在處理 `geneve` token 後設定 `cstate->is_geneve = 1`。
3. `gen_geneve_offsets()` 會 `PUSH_LINKHDR(... DLT_EN10MB ...)` 並配置 `off_linkhdr.reg`、`off_linkpl.reg` 等 variable offsets。
4. `gen_prevlinkhdr_check()` 有多個呼叫點，例如 `gen_linktype()`、link host/broadcast/multicast 相關 expression。
5. 若 filter 只有 `geneve`，通常只會設定 flag，不一定在 flag 設好後再次走到需要 previous link-header check 的 expression。
6. 要 hit blocked side，filter 需要先建立 Geneve context，再接一個會在 inner Ethernet/link-layer context 呼叫 `gen_prevlinkhdr_check()` 的後續條件。

classifier 問題：

- 說「包含 `geneve` keyword 就能讓 blocked branch taken」不完整。
- 少說明順序：`geneve` 必須先設定 state，之後還要有會再次觸發 `gen_prevlinkhdr_check` 的 link-layer predicate。
- 少提醒 bare `geneve`、`udp port 6081 and geneve`、`geneve and udp port 6081` 很可能只到 branch line 或不走後續 blocked side。

pipeline 現況：

- Generator 產生 geneve family，但 representative branch hit 都是 0。
- Summary 顯示 family progress/stalled，但 blocked side 0。
- SymCC final corpus 5878 仍未 hit。

優化：給 generator 的 hint 應明確要求 sequence，例如 `geneve and ether host ...`、`geneve and ether multicast`、`geneve and ether proto ip` 這類「geneve 後接 inner Ethernet/link-layer predicate」的格式，而不是只要求 `geneve`。

## Pipeline 與 prompt 層共通問題

1. **format inference 噪音**：多個 case 的 `format_info` 被猜成 ini/xml，但真實核心 input 是 pcap filter string，或前綴幾個 control bytes 後接 filter string。這會污染 generator prompt。
2. **resource predicate 沒有獨立分類**：`newchunk`、`convert_code_r`、`number_blks_r` 都不適合用一般 input-dependent solver 處理。
3. **generated harness 方向整體合理，但分類錯會讓 harness 解錯問題**：純 filter string harness 對 `pcap_compile` 類 blocker 是好方向；問題在必要條件沒被 classifier 講準。
4. **Bison/Flex generated code 需要專門規則**：`yy_fill_buffer`、`yyerrstatus` 這類 generated-code state 不能只靠變數名與表層 dataflow 判斷。
5. **status wording 有誤導**：有些 generator result 說 `stalled_at_branch`，但 representative branch hit 是 0；應分清楚「baseline corpus reached branch」和「new generated seeds reached branch」。

## 建議優化優先序

1. 新增分類：`Environmental Allocation Failure`、`Resource-Exhaustion Guard`、`Infeasible Counter Overflow`、`Generated Parser Recovery State`、`Flex Scan-String EOF Buffer`。
2. classifier 必須輸出「producer domain」：例如 `alloc_reg()` 只能產生 `0..15`，`yy_scan_buffer()` 固定 `yy_fill_buffer=0`。
3. 對 allocation failure 類 case，不再跑 LLM seed/SymCC；改用 fault injection allocator 或降低內部 limit 的 instrumented build 做 feasibility check。
4. 對 Bison parser case，prompt 要要求 recovery-state proof，不只要求 malformed input。
5. 對 `gen_prevlinkhdr_check`，seed generator 應拿到「先 `geneve`，再 inner link-layer predicate」這個必要 sequencing。
6. 修正 format detector：libpcap filter string 應優先識別為 `pcap-filter-expression`，不要因 symbol name 誤判成 ini/xml。
