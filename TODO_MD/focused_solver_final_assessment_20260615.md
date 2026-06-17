# Focused Solver Final Assessment (2026-06-15)

## 結論

Claude 提出的 corpus 隔離與 ordering-aware generation 方向可實作，也應採用。但 focused run 的證據顯示，
目前不只 ordering 有問題，LLM 還選錯 predicate setter 的 parser representation：`ip proto geneve` 並不會
走 standalone `GENEVE` grammar production，實測為 syntax error。

下一版應同時修正三件事：

1. isolated corpus evaluation
2. ordering-aware seed families
3. representation-preserving contract：不得把語義相似語法當成相同 parser/dispatcher route

## 已確認有效的部分

- Regression tests：`12 passed`
- Build-aware callsite filtering：最新版 ablation 3/3 排除 inactive `gencode.c:5267`
- LLM 能辨識 observed callsite `gencode.c:3208` 的 `!is_geneve` guard 與 blocked-side condition 衝突
- 最新 ablation 有 1/3 實際產生 blocked-side-reaching seed
- Focused production run 兩輪 generator 都可執行並 materialize seeds

目前不能宣稱 LLM 能穩定選出正確 callsite；人工確認的 MAC literal route 是 `gencode.c:7238`，focused run
兩輪都選擇 `gencode.c:6713` 並標記 `evidence_sufficient=false`。

## Claude 回應評估

### 同意

1. `prepare_corpus_snapshot()` 複製完整正式 corpus，是 focused evaluation timeout 的直接原因。
2. 應抽出共用的 triggering-input materialization，統一處理 file path 與 inline content。
3. baseline 應只有 triggering seed；post-merge 應只有 triggering seed與本輪 generated seeds。
4. post-merge 的來源應是 iteration-owned `materialized_by_generator`，不能使用指向正式 corpus 的
   `staged_seed_records.staged_path`。
5. ordering rule 必須排除 fixed-offset binary layout，避免無意義排列欄位。
6. XML format inference 是獨立 issue，可延後處理。
7. baseline branch hit 預期非零；novelty 應以 blocked side 從 0 變成大於 0 判定。這與目前
   `compute_coverage_delta()` 的定義一致。

### 需要修正 Claude 的地方

Claude 說 representative evaluation「本來就不依賴全 corpus」，只說對了一半。目前
`evaluate_representative_seed_records()` 使用 `staged_path`，而 `staged_path` 指向正式 corpus；
`evaluate_seed_with_coverage_in_ossfuzz()` 也要求 seed 位於 OSS-Fuzz corpus root。要真正解耦，必須：

- 將 representative seed 複製到 iteration-owned isolated corpus；或
- 修改 evaluator，讓它先把 materialized seed 暫存進專用 isolated corpus，再執行 coverage。

不能只把 record path 改成 workspace 下的 `materialized_by_generator`，否則 evaluator 會以
`Representative seed is outside corpus root` 失敗。

另外，focused run 不能只歸因於 ordering，因為成功與失敗案例同時改變兩個變因：

- 順序：setter before caller vs caller before setter
- representation：standalone `geneve` vs `ip proto geneve`

## Source 與 GDB 新證據

Source 顯示 `cstate->is_geneve = 1` 位於 `gen_geneve()`。Generated grammar 只有 standalone `GENEVE`
production 會呼叫 `gen_geneve()`：

```text
grammar.c case 123 -> gen_geneve(cstate, vni, 1)
grammar.c case 124 -> gen_geneve(cstate, 0, 0)
```

2026-06-15 使用 `poc2` 與 `gen_geneve_ll_check` breakpoint 的四組最小對照：

| Input | Parse | Blocked side |
|---|---:|---:|
| `geneve and ether host 00:00:00:00:00:00` | success | reached |
| `ether host 00:00:00:00:00:00 and geneve` | success | not reached |
| `ip proto geneve and ether host 00:00:00:00:00:00` | syntax error | not reached |
| `ether host 00:00:00:00:00:00 and ip proto geneve` | syntax error | not reached |

所以可確定：

1. ordering 確實影響 blocked-side reachability。
2. `ip proto geneve` 不是 standalone `geneve` setter 的等價語法。
3. Prompt 必須同時保護 representation category 與 operation ordering。

## Fix 1：Isolated Corpus Evaluation

目前錯誤流程：

```text
完整歷史 corpus -> baseline snapshot
完整歷史 corpus + generated seeds -> post-merge snapshot
```

應改成：

```text
materialized triggering seed -> isolated baseline
materialized triggering seed + 本輪 generated seeds -> isolated post-merge
```

實作要求：

- 新增共用 `materialize_triggering_input(...)`
- 新增 `prepare_isolated_corpus_snapshot(...)`
- 不刪除、不複製、不依賴正式 target corpus
- evaluation 完成後刪除 isolated snapshot
- solver 成功後才另外決定是否 persistence accepted seeds；persistence 與 evaluation 分離
- representative evaluation 使用 iteration-owned isolated seed copies

## Fix 2：Ordering-Aware Families

當 predicate setter 與 caller trigger 是不同、可排序的 input elements，而且 source 未證明順序無關時，
generator 必須建立分開 family：

```text
Fxx_setter_then_caller
Fyy_caller_then_setter
```

不能只檢查兩個 feature 是否同時存在。需要檢查 caller 執行時，setter state 是否已建立且尚未 reset。

不適用情況：fixed-offset binary fields、固定 schema positions，或 source 已證明順序無關。

## Fix 3：Representation-Preserving Contract

如果 setter 由 parser token、grammar production、opcode、field tag、command 或 handler key 選擇，LLM 不得用
語義相似的表達替代。每個 family 必須標記使用的 representation category，並優先保留 source-supported route。

本 case：

```text
source-supported setter = standalone GENEVE token/production
unsupported substitution = `ip proto geneve`
```

若 LLM 想探索 unsupported representation，必須放在獨立 exploratory family，不能取代主要 family。

## 最小實作範圍

修改：

- `blocker_process/dependent/input_dependent_seed_generator.py`
- `prompts/templates/blocker_seed_generator_template`
- 對應 unit tests

不修改：

- 不為了強迫選到 `gencode.c:7238` 增加 libpcap-specific prompt rule
- 不在同一批修 format inference
- 不立即跑完整 12 小時實驗

## 驗證標準

1. isolated baseline 只有一顆 triggering seed。
2. isolated post-merge 只有 triggering seed與本輪 generated seeds。
3. 正式 corpus 在 evaluation 前後檔案數與內容不變。
4. rendered prompt 包含 ordering 與 representation-preserving rules。
5. focused rerun baseline/post-merge 不 timeout。
6. 至少一顆 representative seed `blocked_side_reached=true`。
7. `final_status=solved_by_generator`。

Focused rerun 最多兩次。通過後 freeze 此 case；失敗則分開記錄 coverage infrastructure、schema/generator、
seed reachability 三類，不繼續針對同一 development case 疊加規則。

## 論文使用限制

此 case 參與問題發現與方法設計，屬 development-case feasibility evidence，不是獨立 accuracy 或
generalization evaluation。可用來說明單一路徑 evidence 的限制、build-aware filtering、isolated evaluation、
representation 與 ordering 對 stateful parser blocker 的重要性。
