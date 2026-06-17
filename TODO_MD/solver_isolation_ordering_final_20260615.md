# 最終確認：Corpus 隔離 + Oracle 修正 + Ordering（給 Codex 最後確認）— 2026-06-15

> 已**全數採納** Codex round-N 修正。本文件逐點對照「Codex 指出 → 如何處理」，請最後確認無誤即實作。
> 範圍 Fix 1/1b/2/3；硬停損：focused test ≤2 次（完整有效 LLM run）後不論結果凍結。

## 逐點對照（Codex 修正 → 處理）

| # | Codex 指出 | 已驗證 | 定稿處理 |
|---|---|---|---|
| 1 | 不能再呼叫 `stage_generated_seeds()`（寫正式 corpus 807、迴圈 1971 呼叫） | ✅ | **移除迴圈該呼叫**；直接從 `generated_dir` 建 isolated records `{source_path, isolated_path, family, sha256}`，不經 staging |
| 2 | Representative 成功才是主 oracle（solved 只看 aggregate 1550；timeout 1545 先 fail） | ✅ | `classify_iteration_status` 判定改序：already_covered → **任一 representative 到達=solved** → aggregate → 其餘；aggregate 僅交叉驗證，不否決已成功 seed |
| 3 | triggering seed 要從 `--seed` 補（solver 120/163 只轉 --triggering-input） | 採納 | solver 加 `if not args.triggering_input and seeds: --triggering-input seeds[0]` |
| 4 | Representative 目錄要含 iteration + try/finally cleanup | 採納 | `<fuzzer>__representative_iter_NN`（放 corpus root 下，evaluator 映射 /corpus/，見 988）；try/finally 清 baseline/post-merge/representative |
| 5 | post-merge 要最小 SHA-256 dedup | 採納 | triggering 留一份；generated 依內容 hash 去重；保留 duplicate metadata（重用 815/830 既有 hash 邏輯） |
| 6 | ordering 是 **sequence vs fixed-layout**，非 text vs binary | 採納 | 見下 Fix 2，含 binary TLV/chunks/bytecode；重排後 length/offset/checksum/framing 須重算 |
| 7 | representation：primary=source-supported、unknown=獨立 exploratory family | 採納 | 見 Fix 3 |

## Fix 1（`input_dependent_seed_generator.py`）
- 移除迴圈 `stage_generated_seeds()` 呼叫；isolated records 直接自 generated_dir 建。
- 抽 `materialize_triggering_input()`（複用 1064–1070）；新增
  `prepare_isolated_corpus_snapshot(snapshot_dir, seed_paths)`。
- baseline = triggering only；post-merge = triggering + 本輪 generated（SHA-256 dedup）。
- representative：iteration-scoped 目錄 + try/finally 清理。正式 `<fuzzer>` corpus 不刪改、不 staging。
- **Oracle**：`classify_iteration_status` 改判定序（如上 #2）。

## Fix 1b（`input_dependent_solver.py`）
- 補 `--triggering-input` fallback（如上 #3）。

## Fix 2 — Ordering（`blocker_seed_generator_template` Step 0）
> 當輸入由**可獨立排序的 sequence elements** 組成（含 binary TLV / chunks / bytecode / message sequence），
> 且 source 未證明順序無關、不同順序可能改變 reader 時 state——產生 setter→caller 與 caller→setter 兩種順序，
> 放分開命名 family（`Fxx_setter_then_caller` / `Fyy_caller_then_setter`）。**固定 offset/layout 欄位不得直接
> 交換**；若有 length / offset / checksum / framing，重排後**必須同步重算**，不可只交換 raw bytes。不要假設
> 「含兩 feature 即成功」。

## Fix 3 — Representation（輕量）
ordering 段旁補：primary family 用 source-supported representation；unknown representation 只能是獨立
exploratory family；不得把探索性表示寫成已證實路徑。不加 libpcap/geneve 特例。

## 實作順序（Codex 指定）
1. Fix 1 + 1b + unit tests 全綠。
2. Fix 2 + 3 prompt。
3. focused production test **≤2 次完整有效 run**（program/infra bug 不算模型失敗）。

## Verification
- Unit：isolated baseline 只含 triggering；post-merge 只含 triggering + 本輪 generated（dedup 後）；正式
  corpus 跑前後檔數**不變**；representative 目錄含 iteration 且 finally 清理；rendered prompt 含 ordering rule
  （sequence 軸 + 重算句）；oracle 在「representative 到達 + aggregate timeout」情境回 `solved` 而非 failed。
- `py_compile` + 既有測試綠燈。
- Focused ≤2：baseline 不 timeout、≥1 representative `blocked_side_reached=true`、`final_status=solved`。
  失敗分三類（infra / generator-schema / seeds 未到）。停損後凍結；後備=手動 PoC + ablation 1/3 + failure analysis。

## 唯一想再確認的一點
- Oracle 改「任一 representative 到達即 solved」後，**aggregate post-merge 仍會跑並記錄**（作交叉驗證與
  coverage delta 佐證），只是不再用它否決已成功的 representative——這樣對嗎？還是你希望 representative 成功時
  直接略過 aggregate 評估以省時間？
