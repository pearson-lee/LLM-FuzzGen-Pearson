# Minimal Blocker Triage Labels

這張表不是完整 ground truth，而是 minimal defensible triage，用來決定哪些 blocker 適合納入 solver evaluation。完整可追溯欄位見 `TODO_MD/blocker_ground_truth_labels.csv`。

| Case | Original label | Refined label | Evidence | Include in solver eval | 核心理由 |
|---|---|---|---|---|---|
| `pcap_compile_788` | Input Independent | Environmental Failure | A | No | `pcap_lex_init(&scanner)` 發生在 input 被 scanner consume 前；blocked side 需要 fixed-size allocation failure。 |
| `yy_get_next_buffer_4629` | Input Dependent | Structurally Unreachable API Path | A | No | `pcap__scan_string -> yy_scan_bytes -> yy_scan_buffer` 固定設 `yy_fill_buffer = 0`，目前 API path 不可能走到 refill side。 |
| `compute_local_ud_641` | Input Dependent | Internal Invariant Guard | A | No | `atom` 是 BPF scratch memory/register domain；`alloc_reg()` 只回傳 `0..15`，不是 packet offset。 |
| `convert_code_r_2715` | Input Dependent | Resource-Exhaustion Guard | A | No | blocked side 是 `calloc(slen, ...)` 失敗；`slen == 0` 反而不會進 `if (!offset)`。 |
| `newchunk_642` | Input Dependent | Resource-Exhaustion Guard | B | No | input 可增加 allocation pressure，但要 hit blocked side 需要 chunk pool exhaustion 或 malloc failure。 |
| `number_blks_r_2471` | Input Dependent | Infeasible Counter Overflow | A | No | blocked side 需要 `n_blocks` 從 `UINT_MAX` wrap 到 0，且前面要先成功配置近 2^32 blocks。 |
| `pcap_parse_2056` | Input Independent | Crash-Revealing Path | B | No | 需要 Bison error recovery 成功存活並 shift；既有紀錄指出相關路徑會 double free crash。 |
| `pcap_parse_3594` | Input Dependent | Generated Parser State | B | No | 需要 `yyerrstatus == 3` 時再次進 error handling，不是單純 malformed input 或 EOF。 |
| `gen_prevlinkhdr_check_3149` | Input Dependent | Actionable Target Gap | A | Yes | manual seed `geneve and ether host 00:11:22:33:44:55` 已確認可 hit；seed 必須在 Geneve context 後接 inner Ethernet/link-layer predicate 才會再次觸發 check。 |

## Minimal Evaluation Set

若時間不足，主實驗只把 `gen_prevlinkhdr_check_3149` 當作這批 case 中的 `Actionable Target Gap`。其他 case 不要算 solver failure，改放 taxonomy / threats to validity。

這樣寫法比較能防守：系統原本挑到的是 broad blocker set，而不是全部都該被 solver 解。refined triage 的功能是把 non-actionable blocker 排除，避免錯把 exception-handling branch 當成 target-design gap。
