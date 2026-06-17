# 實作計畫：Corpus 隔離 + Ordering rule（給 Codex review）— 2026-06-15

> 方向已收斂。本文件是**實作前的最終計畫**，請 Codex 最後確認後即開工。
> 範圍：Fix 1（corpus 隔離）+ Fix 2（ordering rule）+ Fix 3（representation 輕量）。**硬停損**：
> focused test ≤2 次後不論結果凍結。

## 為什麼做（一句話）
focused production test 失敗**不是核心機制壞掉**——build-aware callsite 列舉有效（ablation 3/3 排除
inactive、1/3 到達 3150）。卡關在 (1) baseline evaluation 載入 ~12,500 顆歷史 corpus → `bpf_optimize()`
timeout 整輪中止（LLM 只收到 "timeout"、且成功無法歸因於本方法），(2) generated seed 順序/表達錯誤
（PoC 表：`geneve and ether host`✅、`ether host ... and geneve`❌、`ip proto geneve`=syntax error）。

---

## Fix 1 — Corpus 隔離（`blocker_process/dependent/input_dependent_seed_generator.py`）
- 抽 `materialize_triggering_input(triggering_input, format_info, dest_dir) -> Path`：複用
  `evaluate_triggering_input_with_coverage`(1064–1070) 的 path/inline materialize 邏輯，避免兩份漂移。
- 新增 `prepare_isolated_corpus_snapshot(snapshot_dir, seed_paths)`：清空 dir、**只**複製明確 seed_paths
  （取代 `prepare_corpus_snapshot()` 的 `copytree` 整包正式 corpus）。
- 迴圈（1936–1998）：
  - **baseline** = 只放 triggering seed。
  - **post-merge** = triggering seed + 本輪 `materialized_by_generator` 內 seeds（ownership 乾淨；**不**用
    `staged_seed_records.staged_path`，那指向正式 corpus）。
- **Representative 評估隔離（Codex 修正，必做）**：`evaluate_representative_seed_records`(1097)→
  `evaluate_seed_with_coverage_in_ossfuzz`(971) 目前用 `staged_path` 且要求 seed 在 OSS-Fuzz corpus root。
  需改用 **iteration-owned isolated copy**（把 materialized seed 複製到 evaluator 可讀的隔離夾再評估），
  使其完全脫離正式 corpus staging。
- **不**用 `--reset-corpus-per-iteration`（會動正式 corpus）。正式 `<fuzzer>` corpus 全程**不刪改**。

## Fix 2 — Ordering rule（`prompts/templates/blocker_seed_generator_template`，Step 0 survival/ordering）
當 setter 與 caller-trigger 為**可線性排序的獨立 input elements**、source 未證明順序無關、且不同順序可能改變
reader 時 state——產生**兩種 ordering**放分開命名 family（`Fxx_setter_then_caller`/`Fyy_caller_then_setter`）。
**明寫排除**：fixed-offset / 固定 layout binary，欄位位置由 layout 決定、非由順序決定，**不排列**；僅
text command / filter / token stream 套用。

## Fix 3 — Representation（輕量）
Step 0 已有「不要用語義相似但 parser route 不對的表達」；ordering 段旁輕量強調 setter 必須用「已證明能呼叫
target 的 grammar route」表達（不要用 syntax-error 等價詞）。**不**加 libpcap 特例 / 不逼選特定 callsite。

---

## Verification（含硬停損）
1. **Unit tests**：isolated baseline 只含 triggering seed；post-merge 只含 triggering + 本輪 materialized；
   正式 `<fuzzer>` corpus 跑前後檔數**不變**；rendered prompt 含 ordering rule（雙向 + binary 排除句）。
2. `py_compile` + 既有測試綠燈。
3. **Focused rerun ≤2 次**，成功條件：baseline 不 timeout、post-merge 成功、≥1 representative seed
   `blocked_side_reached=true`、`final_status=solved_by_generator`；保留 prompt/response/callsite_decision/
   generated program/materialized seeds/representative coverage/成功 seed 路徑。
4. 失敗**區分三類**：coverage infra / generator-schema / seeds 未到 blocked side——不混成「Solver 無效」。
5. **停損**：≤2 次後不論結果凍結，不再為此 dev case 調 prompt。後備：手動 PoC + ablation 1/3 + failure analysis。

## 論文措辭
development case、參與設計，不報獨立 accuracy。可說：build-aware callsite enumeration 過濾 inactive 並 surface
compatible 候選；識別出可靠驗證所需兩工程要件（isolated corpus evaluation、ordering/representation-aware seed
construction）。不可說：callsite accuracy 已證明 / 已泛化所有 C/C++ / 單一成功=整體 Solver 有效。

## 想請 Codex 最後確認
1. Representative 改 iteration-owned isolated copy：放在 `evaluate_seed_with_coverage_in_ossfuzz` 之前複製到
   `<fuzzer>__representative_eval` 隔離夾，是否符合你說的「脫離正式 corpus」且 evaluator 能讀？
2. post-merge 用 `materialized_by_generator` 全部 seeds（不經 staging dedup）是否同意？還是要先做最小 dedup？
3. ordering rule 的 binary 排除句是否足以避免 fixed-layout 亂排，且不誤傷「有 length-prefix 的半結構文字」？
4. 硬停損（≤2 次後凍結、用手動 PoC 當後備）是否同意？
