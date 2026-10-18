# Blocker selector 分數紀錄（2026-10-05）

## 1. 目的

`global_blocker_selector` 會替每個候選 blocker 計分並排序，但過去的實驗只保留最後選出的 blocker，看不到：

- 每次選擇時各候選的分數，以及分數由哪些部分組成；
- 同一個 blocker 在不同 session 之間分數與排名怎麼變化；
- 扣分規則（`solvability_reason`）到底有沒有觸發。

為了判斷「selector 的排序是否有效」，需要把每一次選擇的完整排名記錄下來。

## 2. 修改內容（`main.py`）

| 項目 | 說明 |
|---|---|
| `_blocker_score_summary(blocker)` | 抽出單一 blocker 的分數欄位：`score`、`score_model`、`score_components`、`solvability_reason`、`solvability_evidence_grade/pattern`、`solvability_hints`、`project_branch_hit_count`、`blocked_unique_*` 等 |
| `_append_blocker_score_history(...)` | 每次選擇時，把排名中的每個 blocker 各寫一列到 `experiments/<run_id>_<log_name>/blocker_score_history.jsonl` |
| `_select_project_blockers(...)` | 新增 `selection_context`、`session_number` 參數；在剔除已嘗試的 blocker 之後、取 `top_k` 之前寫入紀錄；全域計數器 `_blocker_selection_count` 產生 `selection_index` |
| `blocker_selection_completed` event | 新增 `selection_index`、`selection_context`、`session_number`、`score_history_path`、`selected_blocker_scores`（最多 50 筆） |
| `blocker_session_started` event | `selected_blockers` 每筆加上 `score`、`score_components`、`solvability_reason` |
| `blocker_attempts.jsonl` | 每筆 attempt 加上 `selection_score`，可以直接對照該 blocker 被選中時的分數 |

`selection_context` 的值：

- `snapshot:<stage>`：artifact 更新後的完整快照（`top_k=0`，全部候選都會記錄）
- `session_start`：blocker session 開始時的選擇
- `session_rerank`：session 中每處理完一個 blocker 後的重新排序
- `single_pipeline`：單次 pipeline 指令

## 3. 每列紀錄的欄位

`timestamp`、`run_id`、`project`、`selection_index`、`selection_context`、`session_number`、`rank`、`within_top_k`，加上 `_blocker_score_summary` 的所有欄位。

## 4. 用這份紀錄得到的發現（tomlplusplus）

| 實驗 | 紀錄筆數 | 分數 > 0 | 說明 |
|---|---|---|---|
| `20261006_135503`（有殘留起點） | 76 | 0 | `coverage_benefit` 全為 0，排序實際上只看 hit count |
| `20261010_143353`（乾淨起點） | 302 | 13（2 個 branch） | 96% 仍為 0 分；`solvability_reason` 全部是 `normal` |

- `coverage_benefit` 以函式為單位計算，blocked side 只有 1–3 行的分支一律 0 分，`score = reach × benefit × solvability` 因此無法區分這些候選。
- 這是後續加入 `branch_kind` 排序（見 `backlog/selector/1012/summary.md`）的依據。

## 5. 使用方式

```bash
wc -l experiments/<run_id>_run_all_fuzzer/blocker_score_history.jsonl
grep blocker_selection_completed experiments/<run_id>_run_all_fuzzer/events.jsonl | tail -1
```

需要啟用 `--use-blocker`；第一筆紀錄會在第一次 blocker artifact 更新（通常是第一次 coverage 停滯）後出現。
