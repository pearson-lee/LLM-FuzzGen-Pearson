# Blocker Triage Implementation Notes

## 1. 問題、方法與理由

目前 blocker pipeline 的問題不是只在 dependency classifier。classifier 只回答「predicate 是否受目前 fuzz input 影響」，但 solver 真正需要的是「這個 blocker 是否能靠 seed / target / harness generation 解」。因此 allocator failure、system failure、parser internal recovery state、internal invariant guard 這類 case 即使看起來和 input 有間接關係，也不應該進 solver evaluation。

本次實作加入一個 solver 前的 C/C++ generic triage hard gate：

1. classifier 先輸出 `Input Dependent` / `Input Independent`。
2. triage LLM 根據 source snippet、runtime hit count、pipeline failure stage、classifier trace，只選擇一個 `refined_triage_label`。
3. 程式用固定 mapping 從 label 推導 `first_layer_decision` 與 `solver_action`，不採用 LLM 自行輸出的 routing 欄位。
4. 明確的 non-generation label 才會 `skip_solver`；`Inconclusive` 與 `triage_error` 都採 fail-open，保留原 solver 執行。

這樣做合理，因為 dependency 和 solvability 是兩個不同問題。前者描述 dataflow，後者描述求解手段是否適用。把 non-generation-solvable blocker 排除後，solver evaluation 的 denominator 會變成 generation-solvable blockers，而不是 raw blockers。

## 2. Prompt 撰寫方式

Prompt 在 `prompts/templates/blocker_triage_template`。設計重點：

- source evidence 放在 classifier trace 前面，避免 LLM 先被錯誤 classifier trace anchor。
- classifier trace 被標成 prior opinion，不是 ground truth。
- LLM 輸出 schema 只要求 `refined_triage_label` 與分析證據欄位，不要求它重複決定 first layer 和 solver action。
- pipeline 仍輸出 `first_layer_decision` 與 `solver_action`，但兩者由 deterministic label mapping 產生。
- 舊版 response 若帶有 routing 欄位，會保留在 `raw_first_layer_decision`、`raw_solver_action`，方便稽核，但不影響實際 routing。
- `producer_path_status` 必須說明合法 caller -> producer/setter -> blocked-side read 是否已證明、被 source 否定，或證據不足。
- `practical_feasibility` 必須區分一般 fuzzing budget 內可行、resource/environment failure、infeasible、internal invariant、crash-before-observe 與證據不足。
- `Actionable Target Gap`、`Bounded Extreme Value` 若沒有 `proven + practical`，程式會降為 `Inconclusive` 並 fail-open，而不是直接宣告可解。
- label 使用 C/C++ generic 類別，不寫死 libpcap，例如 allocator failure、system failure、internal invariant、generated parser state、counter overflow、target gap。
- `Structurally Unreachable API Path` 的定義保留可修正邊界：如果 visible evidence 顯示合法 target/API sequence 可以達成，就要改標 `Actionable Target Gap`。

這個順序能避免 `yy_get_next_buffer_4629` 這種 classifier trace 判斷方向錯誤時，triage LLM 直接繼承錯誤。

## 3. 額外成本

線上 pipeline 成本：

- 每個 blocker 多 1 次 LLM triage call。
- source snippet 與 log parsing 成本可以忽略，通常是毫秒級。
- 若 triage 判定 `skip_solver`，會省掉 downstream seed generation、SymCC、target generation、rebuild、fuzz validation 的時間。

離線 retrospective case study 成本：

- `--emit-prompts-only` 不呼叫 LLM，只產生 prompt evidence。
- 真正重分類 9 個 case 需要 9 次 LLM call，不需要重跑 10 小時 fuzzing experiment。

## 4. 重新分類與確認命令

Artifact layout:

- `TODO_MD/triage_final/`: reviewed complete runs and their analysis.
- `TODO_MD/triage_archive/`: historical, superseded, or interrupted runs.
- `TODO_MD/triage_scratch/`: temporary output from new reruns. Review a complete run before moving it into `triage_final/`.

目前三次 evidence-contract rerun 與分析見 `TODO_MD/triage_final/analysis_20260614.md`。三次 first-layer agreement 為 4/9、5/9、5/9；這是 development-set retrospective agreement，不是 independent accuracy。

先產生 9 個 case 的 prompt evidence，不呼叫 LLM：

```bash
.venv/bin/python blocker_process/blocker_triage.py \
  --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl \
  --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json \
  --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv \
  --project-name libpcap \
  --output-jsonl TODO_MD/triage_scratch/prompts_only.jsonl \
  --save-prompts-dir TODO_MD/triage_scratch/prompts \
  --emit-prompts-only \
  --limit 9
```

真正呼叫 LLM 重新分類全部 9 個 case：

```bash
.venv/bin/python blocker_process/blocker_triage.py \
  --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl \
  --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json \
  --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv \
  --project-name libpcap \
  --backend vertexai \
  --model gemini-2.5-flash \
  --output-jsonl TODO_MD/triage_scratch/decisions_all.jsonl \
  --save-prompts-dir TODO_MD/triage_scratch/prompts
```

逐 case 重新分類：

```bash
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case pcap_parse:2056 --output-jsonl TODO_MD/triage_scratch/cases/pcap_parse_2056.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/pcap_parse_2056
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case yy_get_next_buffer:4629 --output-jsonl TODO_MD/triage_scratch/cases/yy_get_next_buffer_4629.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/yy_get_next_buffer_4629
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case pcap_compile:788 --output-jsonl TODO_MD/triage_scratch/cases/pcap_compile_788.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/pcap_compile_788
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case newchunk:642 --output-jsonl TODO_MD/triage_scratch/cases/newchunk_642.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/newchunk_642
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case convert_code_r:2715 --output-jsonl TODO_MD/triage_scratch/cases/convert_code_r_2715.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/convert_code_r_2715
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case pcap_parse:3594 --output-jsonl TODO_MD/triage_scratch/cases/pcap_parse_3594.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/pcap_parse_3594
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case gen_prevlinkhdr_check:3149 --output-jsonl TODO_MD/triage_scratch/cases/gen_prevlinkhdr_check_3149.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/gen_prevlinkhdr_check_3149
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case compute_local_ud:641 --output-jsonl TODO_MD/triage_scratch/cases/compute_local_ud_641.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/compute_local_ud_641
.venv/bin/python blocker_process/blocker_triage.py --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv --project-name libpcap --backend vertexai --model gemini-2.5-flash --case number_blks_r:2471 --output-jsonl TODO_MD/triage_scratch/cases/number_blks_r_2471.jsonl --save-prompts-dir TODO_MD/triage_scratch/prompts/number_blks_r_2471
```

線上 pipeline 啟用 triage：

```bash
.venv/bin/python main.py run_blocker_once libpcap \
  --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json \
  --blocker-index 0 \
  --enable-blocker-triage
```

## 5. 論文 case study defense

這 9 個 case 不應該被寫成 independent accuracy evaluation，因為 taxonomy 本身就是從這批 case 的 source-level audit 整理出來的。正確 defense 是：

> We retrospectively applied the triage module to recorded blocker attempts from one libpcap fuzzing session to validate the feasibility of separating generation-solvable blockers from non-generation-solvable blockers before solver execution.

這樣可以防守，理由是：

- case study 的目的不是證明泛化準確率，而是證明 raw blocker 不能直接當 solver evaluation denominator。
- 9 個 case 含蓋 allocator/resource failure、environmental failure、generated parser/scanner state、internal invariant、infeasible overflow、crash-revealing path、actionable target gap，足以展示 triage 的必要性。
- triage prompt 和 code 是 C/C++ generic，沒有 hardcode libpcap function name；libpcap 只是 retrospective validation dataset。
- evaluation 章可以明確說：solver 只評估 generation-solvable blockers；non-generation-solvable blockers 是 triage outcome，不是 solver failure。
