# Blocker Triage Case Study: libpcap

在原先的 blocker selection 中，即使系統已經使用 coverage、impact 與部分 heuristic 來排序 blocker，實驗結果仍顯示：被 selector 選出的 coverage-stalled blocker 不一定都適合直接送進 target/seed generation pipeline。換句話說，raw blocker candidate 只代表目前 fuzzing run 卡在某個 branch side，並不代表該 blocked side 一定能透過正常 fuzz target 或 seed 設計求解。

因此，本節針對 `20260612_020723_run_all_fuzzer` 中實際進入 blocker pipeline 並產生結果的 9 個 libpcap cases 做 case study。目的不是建立完整 ground truth，而是說明為什麼 selector 後面需要加入 solvability-aware triage，將 blocker 先分成 `Generation-solvable` 與 `Non-generation-solvable`，再決定是否進入 solve pipeline。

## Case Selection

本 case study 的範圍是固定 experiment run 中的 pipeline-audited blockers：

- Project: `libpcap`
- Run ID: `20260612_020723`
- Source: `experiments/20260612_020723_run_all_fuzzer/events.jsonl`
- Selection basis: `global_blocker_selector.py` 選出的 coverage-stalled blockers
- Inclusion criterion: 同時具有 `blocker_pipeline_started` 與 `blocker_pipeline_result`

該 session 一開始曾列出 10 個 selected blockers，但實際有 pipeline result 的是 9 個。因此本文只把這 9 個納入 triage audit；沒有 pipeline result 的 selected blocker 不納入 solver outcome 統計。

## Triage Rule

本研究採用兩層 triage：

| Layer | Decision | Meaning |
|---|---|---|
| 第一層 | `Generation-solvable` / `Non-generation-solvable` / `Inconclusive` | 決定是否安排進 solve pipeline |
| 第二層 | refined triage label | 說明為什麼這個 blocker 可解或不可解 |

`Generation-solvable` 指 blocked side 可望透過合法 fuzz target、seed、call sequence、target configuration 或 bounded input value 達成。`Non-generation-solvable` 指 blocked side 需要記憶體配置失敗、resource exhaustion、環境錯誤、internal invariant violation、generated parser/scanner internal state、不可實務 counter overflow 或 crash 才能觀察。這些 case 不應計為 target/seed generation solver failure，而應作為 triage outcome。

## Triage Results

| Case | Original label | First-layer decision | Refined label | Solver eval | Core evidence |
|---|---|---|---|---:|---|
| `gen_prevlinkhdr_check_3149` | Input Dependent | Generation-solvable | Actionable Target Gap | Yes | manual seed `geneve and ether host 00:11:22:33:44:55` confirmed blocked-side reachability; generator missed required post-Geneve link-layer predicate. |
| `pcap_compile_788` | Input Independent | Non-generation-solvable | Environmental Failure | No | `pcap_lex_init(&scanner)` runs before input is scanned; failure requires fixed-size scanner allocation failure. |
| `yy_get_next_buffer_4629` | Input Dependent | Non-generation-solvable | Structurally Unreachable API Path | No | current `pcap_compile` path uses `pcap__scan_string -> yy_scan_bytes -> yy_scan_buffer`, which fixes `yy_fill_buffer = 0`. |
| `compute_local_ud_641` | Input Dependent | Non-generation-solvable | Internal Invariant Guard | No | `atom` is BPF scratch-memory/register domain; legal producer is bounded, not arbitrary packet offset. |
| `convert_code_r_2715` | Input Dependent | Non-generation-solvable | Resource-Exhaustion Guard | No | blocked side requires `calloc(slen, ...)` failure while `slen > 0`; `slen == 0` skips the branch entirely. |
| `newchunk_642` | Input Dependent | Non-generation-solvable | Resource-Exhaustion Guard | No | blocked side requires `newchunk_nolongjmp` to return NULL through chunk exhaustion, malloc failure, or oversized request. |
| `number_blks_r_2471` | Input Dependent | Non-generation-solvable | Infeasible Counter Overflow | No | blocked side requires `n_blocks` to wrap from `UINT_MAX` to 0 after successful huge CFG/block setup. |
| `pcap_parse_2056` | Input Independent | Non-generation-solvable | Crash-Revealing Path | No | Bison error recovery path needs parser state to survive into shift loop; existing evidence indicates related path can crash before reliable coverage writeout. |
| `pcap_parse_3594` | Input Dependent | Non-generation-solvable | Generated Parser State | No | blocked side requires `yyerrstatus == 3` inside Bison error handling, i.e., a specific parser recovery state, not merely malformed input. |

Summary:

| First-layer decision | Count |
|---|---:|
| `Generation-solvable` | 1 |
| `Non-generation-solvable` | 8 |
| `Inconclusive` | 0 |

## Case Notes

### `gen_prevlinkhdr_check_3149`

這是本組 case 中最明確的 generation-solvable blocker。`cstate->is_geneve` 可以由 `geneve` filter 語意設定，但 blocked side 不是單靠 `geneve` keyword 就會觸發。真正缺少的是 caller-path sequencing：filter 必須先建立 Geneve context，再接一個會在 inner Ethernet/link-layer context 呼叫 `gen_prevlinkhdr_check()` 的 predicate。

manual validation 顯示 seed `geneve and ether host 00:11:22:33:44:55` 可以 hit blocked side。因此這個 case 應納入 solver evaluation；它代表 generator context 不夠精確，而不是 blocker 本身不可解。

### `pcap_compile_788`

這是 clean input-independent environmental failure。blocked predicate 是 `pcap_lex_init(&scanner) != 0`，而 `pcap_lex_init()` 發生在 `pcap__scan_string()` 處理 input 之前。由於 `scanner` 是 local stack variable，非 NULL；剩下可使該 call 失敗的主要條件是固定大小 `yyalloc(sizeof(struct yyguts_t))` 失敗。這不是正常 seed 或 target generation 應求解的情況。

### `yy_get_next_buffer_4629`

classifier 原先把它判成 Input Dependent，原因是它認為非空 filter string 可以讓 `yy_fill_buffer != 0`。source-level dataflow 顯示這是錯的：目前 `pcap_compile` 走的是 scan-string path，`pcap__scan_string()` 會經過 `yy_scan_bytes()` 與 `yy_scan_buffer()`，而 `yy_scan_buffer()` 固定設定 `yy_fill_buffer = 0`。因此在目前 public API path 下，blocked side 不是 seed 不夠，而是 current path 結構性不可達。

若未來能找到合法 public API 或 target call sequence 走到 Flex refill buffer path，這類 case 可以改歸 `Actionable Target Gap`；但目前證據不支持把它放進一般 solve pipeline。

### `compute_local_ud_641`

classifier 把 packet offset 與 BPF optimizer internal atom domain 混淆。`atom` 在這裡不是 `ip[1000000]` 這種 packet access offset，而是 BPF scratch memory/register domain。合法 domain 由 compiler internal producer 限制，例如 scratch memory `0..15`、A/X register 與特殊 atom。blocked side 是 `abort()`，代表 internal invariant 被破壞，不是合法 filter string 應該直接產生的狀態。

### `convert_code_r_2715`

這個 case 容易被誤解成 `slen == 0` 可以讓 `offset == NULL`，進而觸發 `conv_error()`。但 source code 明確顯示 `if (!offset)` 位於 `if (slen)` 裡：

```c
if (slen) {
    offset = calloc(slen, sizeof(struct slist *));
    if (!offset) {
        conv_error(conv_state, "not enough core");
    }
}
```

因此 `slen == 0` 時，blocked branch 根本不會被執行。要 hit blocked side，必須是 `slen > 0` 且 `calloc(slen, ...)` 回傳 NULL。這屬於 allocation/resource failure，不是正常 target/seed generation 的求解目標。

### `newchunk_642`

`newchunk()` 的 blocked side 是 `p == NULL`，而 `p` 來自 `newchunk_nolongjmp()`。雖然 input filter 越複雜可能造成更多 internal allocations，但 blocked side 本質上需要 chunk pool exhaustion、malloc failure 或 oversized allocation request。這類 case 可以說是 input-amplified，但不適合作為一般 seed-generation success target。

### `number_blks_r_2471`

`opt_state->n_blocks` 確實與 input-derived CFG complexity 有關，但 blocked side 要求 counter 從 `UINT_MAX` wrap 到 0。更重要的是，進入該狀態前還需要建立並配置不可實務數量的 internal blocks。這不同於一般 `Bounded Extreme Value`；它需要的是不可實務 counter overflow，因此歸為 `Infeasible Counter Overflow`。

### `pcap_parse_2056`

這個 case 與 Bison error recovery state 有關。要 hit `yyerrstatus--`，parser 必須進入 error recovery、成功 shift recovery token，並讓 `yyerrstatus` 活到 main parse loop。既有 evidence 顯示相關路徑會暴露 crash/double-free，導致 coverage profile 可能無法可靠寫出。因此本 case 不應當成普通 solver failure，而應作為 crash-revealing/parser recovery case 獨立討論。

### `pcap_parse_3594`

這也是 Bison generated parser state，但它比單純 malformed input 更嚴格。blocked side 需要 parser 已經處於 `yyerrstatus == 3` 的 recovery 狀態，並再次進入 error handling 與 EOF/lookahead 判斷。classifier 若只說「malformed input 後 EOF」會過度簡化，因為真正困難點是 parser recovery phase predicate。

## Implications

這 9 個 cases 顯示，coverage-stalled blocker 不等於 generation-solvable blocker。若 selector 後直接送入 solver，會把 environmental failure、resource exhaustion、internal invariant、generated parser state、structurally unreachable API path 與 counter overflow 都混入 solver failure，導致 evaluation denominator 不合理。

因此，本研究的 evaluation 應分成兩個層次：

1. **Triage evaluation**：系統是否能把 raw blocker candidates 分成 generation-solvable 與 non-generation-solvable。
2. **Solver evaluation**：只在 generation-solvable blockers 上評估 target/seed generation 是否成功。

在本 case study 中，9 個 pipeline-audited blockers 中只有 `gen_prevlinkhdr_check_3149` 屬於 generation-solvable，且已由 manual seed validation 確認 blocked side 可達。其他 8 個不應計為 solver failure，而應作為 triage outcome 與方法邊界討論。

## Thesis Wording

可放入論文的描述：

> The global blocker selector identifies coverage-stalled branch sides, but such candidates are not necessarily valid targets for target or seed generation. In a libpcap case study, we audited nine pipeline-executed blockers and found that only one represented a generation-solvable target/seed gap. The remaining cases were environmental failures, resource-exhaustion guards, internal invariants, generated parser states, structurally unreachable API paths, infeasible counter overflows, or crash-revealing paths. Therefore, we introduce a solvability-aware triage step before solver evaluation.

中文版本：

> blocker selector 找到的是 coverage-stalled candidates，不代表每個 blocked side 都適合由 fuzz target 或 seed generation 求解。本研究在 libpcap 的 9 個 pipeline-audited cases 中進行 source-level triage，發現其中只有 1 個屬於 generation-solvable 的 target/seed gap，其餘則是環境失敗、資源耗盡、內部 invariant、generated parser state、結構性不可達 API path、不可實務 counter overflow 或 crash-revealing path。因此，在 solver evaluation 前加入 solvability-aware triage 是必要的。
