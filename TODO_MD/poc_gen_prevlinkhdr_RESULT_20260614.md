# PoC 驗證結果：gen_prevlinkhdr_check 的 blocked side 可由 seed 打到

日期：2026-06-14　|　target：libpcap `gencode.c:3150`（`gen_prevlinkhdr_check` 的 geneve 分支）

## 結論（已實證）

**blocked side（gencode.c:3150）確實可達，而且需要先處理 `geneve`，再處理 inner ether-host。**
這證明此 blocker 是**真正可解的（actionable）**，先前 pipeline 失敗是 seed 組合不對，不是 blocker 不可解。

## 驗證方法

- harness：自寫 `poc.c`，與 libpcap fuzzer 一致：`pcap_open_dead(DLT_EN10MB, 65535)` + `pcap_compile(...)`。
- 連結既有的 instrumented `libpcap.a`（`external/oss-fuzz/build/out/libpcap/src/libpcap/build/`）。
- 可達性判定：`gen_geneve_ll_check` 在整個 gencode.c **只有 line 3150 一個呼叫點**（grep 確認），因此在該函式下 gdb 中斷點 = blocked side 是否執行的決定性證據。
- 檔案：`TODO_MD/poc_gen_prevlinkhdr/poc.c`、`poc2`(binary)。

## 結果表

| Filter | pcap_compile | 到達 line 3150（blocked side）|
|--------|:---:|:---:|
| `geneve and ether host 00:11:22:33:44:55` | 0（成功）| **YES ✅** |
| `geneve and ether broadcast` | 0（成功）| **YES ✅** |
| `ether host 00:00:00:00:00:00 and geneve` | 0（成功）| no |
| `ip proto geneve and ether host 00:00:00:00:00:00` | -1（syntax error）| no |
| `ether host 00:00:00:00:00:00 and ip proto geneve` | -1（syntax error）| no |
| `geneve`（對照組）| 0（成功）| no |
| `ether host 00:11:22:33:44:55`（對照組）| 0（成功）| no |

對照證明三件事：

1. 單獨 `geneve` 或單獨 ether-host 都到不了，必須組合。
2. 組合順序有語義：`geneve` 必須先設定 parser/compiler state，後續 ether-host 才能在 reader path 讀到該狀態。
3. `ip proto geneve` 不是此 setter 的等價表達，在目前 grammar 中是 syntax error；不能把語義相似字串視為相同 parser route。

## 為什麼 pipeline 之前失敗（精確 failure analysis）

到達 line 3150 需要兩件事同時成立：
1. `is_geneve = 1` — 唯一設定處 `gencode.c:9434`（在 `gen_geneve()` 內）→ filter 需含 `geneve`。
2. `gen_prevlinkhdr_check` 必須在 `is_geneve=1` 後，從 predicate-compatible callsite 被呼叫。MAC literal
   `ether host 00:...` 的 source-supported route 是 `gen_ecode` 的 `gencode.c:7238`。最近的 observed callsite
   `3208` 被 `if (!cstate->is_geneve)` 擋住，`is_geneve=1` 時不走；`5267` 在目前 build 受
   `#ifndef INET6` 排除，也不能當候選。

先前 generator 產生的是 **geneve-only / geneve+ip** 的 seeds：可能設定 state，但沒有在後續觸發
predicate-compatible inner ether-host reader path。Focused production rerun 又產生 `ether host ... and ip proto geneve`，
同時犯了兩個錯誤：setter representation 錯誤，且 caller-trigger 排在 setter 前。這就是「缺 caller-path、
representation 與 ordering context」的精確內容。

## 與 baseline 的對照（受控差異，已具雛形）

- Baseline（20260612 真實實驗，12h fuzzing）：`gen_prevlinkhdr_check` 的 branch line 3149 **有**到達（`branch_line_reached=True`），但 blocked side 3150 **未**到達（`blocked_side_line_reached=False`）。
  → 這只能證明既有 corpus 曾呼叫 `gen_prevlinkhdr_check`，但沒有在 reader 執行時保留 `is_geneve=1`。
  Coverage aggregate 無法證明 corpus 是否曾分別包含 geneve 與 ether-host，不能從這份結果反推出具體 input 組成。
- Method（本 PoC seed `geneve and ether host ...`）：blocked side 3150 **到達 ✅**。

這正是老師 RQ「blocker 上的差異」的一個**正面案例**：方法用對的 seed 打到 fuzzing 高原後到不了的 blocked side。

## 對論文的意義

1. **第一個 proof-of-concept**：target/seed generation 能到達 fuzzing 到不了的 blocked side。
2. **乾淨的 failure analysis**：pipeline 為何漏掉（geneve-only，缺 inner ether-host 組合）——可寫成 generator 的具體改進方向（seed/target 需組合 tunnel 關鍵字 + inner link-layer qualifier）。
3. **驗證 triage 分類正確**：此 blocker 的確是 Actionable Target Gap（可解），triage 判 run_solver 是對的。

## 下一步（建議）

1. 使用 isolated baseline（只有 triggering seed）與 isolated post-merge（triggering seed + 本輪 generated seeds），避免歷史 corpus timeout 污染 focused evaluation。
2. Prompt 同時保留 parser representation 與 operation ordering：standalone `geneve` setter 必須先於 inner link-layer caller trigger。
3. 重跑 focused production test，要求至少一顆本輪 generated representative seed 由 coverage 正式確認 line 3150 covered。
