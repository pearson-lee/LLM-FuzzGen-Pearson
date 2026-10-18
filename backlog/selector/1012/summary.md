# Blocker selector 分支類型排序（branch_kind，2026-10-12）

## 1. 問題

`score = reach_confidence × coverage_benefit × solvability`。專案接近飽和時，剩下的 blocker 大多 `coverage_benefit = 0`（blocked side 只有 1–3 行、沒有呼叫新的未覆蓋函式），於是：

- 所有候選同為 0 分，扣分規則乘上 0 也沒有作用；
- 排序退化成只看 `reach_confidence`，也就是 branch 的 hit count；
- 熱路徑上的錯誤處理分支（例如 `stop_recording:13757`，兩次實驗共花約 57 分鐘都失敗）總是排在前面。

0 分的分支多半不是防禦性程式碼：tomlplusplus 的 26 個 0 分候選裡，18 個是 `return false/{}`、`break` 這類正常結果分支，真正的錯誤處理只有 2 個。所以不能用「benefit 為 0 就排除」。

## 2. 修改內容（`blocker_process/global_blocker_selector.py`）

- `_extract_blocked_side_body()`：只取 blocked side 本身的程式碼（有大括號取整個區塊，否則取到第一個分號，最多 6 行；註解已移除）。
- `_classify_branch_kind()`：分成三級。

  | priority | `branch_kind` | 判斷 |
  |---|---|---|
  | 2 | `semantic_result` | 整段只有 `return <常數/識別字/{}/字串>;`、`return;`、`break;`、`continue;` |
  | 1 | `other` | 其他，或讀不到原始碼（預設值） |
  | 0 | `error_path` | `throw`、`*error*(`、`*_err`/`fail`/`panic` 呼叫、`abort/exit/assert`、`*_UNREACHABLE`、`goto err/fail/cleanup/bail`、`return -N;`、resource failure 字樣 |

  先檢查 `error_path`，所以 `return -1;` 屬於 `error_path`。

- `_selector_sort_key()`：在 `coverage_benefit` 之後、`reach_confidence` 之前加入 `branch_kind_priority`。`score` 公式不變，有分數的 blocker 仍排最前面，只有同分的候選會被重新分組。
- `_enrich_with_snippet_solvability()`：Phase 2 原本只檢查前 20 名，排在後面的候選永遠不會被分類；現在會補分類所有候選（只是在已讀入的檔案上跑 regex）。
- `main.py` 的 `_blocker_score_summary()` 多記錄 `branch_kind`、`branch_kind_priority`、`blocked_side_body`（前 120 字元）；`score_components` 也會有 `branch_kind`。

## 3. 驗證

### 離線重排（`20261010_143353` 的初始 snapshot，25 個候選）

| | 前 5 名 | 前 10 名 |
|---|---|---|
| 原排序 | 成功 2/5，失敗耗時 3238s | 成功 5/9，失敗耗時 3490s |
| 新排序 | 成功 3/4，失敗耗時 1052s | 成功 6/8，失敗耗時 2143s |

### 真實重跑（`20261012_161330`，參數與 `20261010_143353` 相同，皆為乾淨起點）

| 指標 | 1010（修改前） | 1012（修改後） |
|---|---|---|
| 前 5 個 pipeline | 成功 2/5，失敗耗時 3238s | 成功 5/5，失敗耗時 0s |
| 前 10 個 pipeline | 成功 5/10 | 成功 8/10 |
| 全部 23 個 pipeline | 成功 11 | 成功 14 |
| pipeline 總耗時 | 5.6 小時 | 3.7 小時 |

三次 tomlplusplus 實驗合計（1006、1010 以事後分類補上，與 1012 的實際紀錄比對 0 筆不符）：

| `branch_kind` | Dependent 成功/嘗試 | Independent 成功/嘗試 |
|---|---|---|
| `semantic_result` | 0/4 | 21/29（72%） |
| `other` | 1/10 | 5/11（45%） |
| `error_path` | 0/0 | 1/3 |

## 4. 限制與後續

- 最終 coverage 沒有因此提高；效益是省下 pipeline 時間、更快處理完候選池。
- `semantic_result` 會混入防禦性的提早離開（例如 `at_path` 的 `return {}`，兩次都失敗）；若要細分需要看 branch 條件。
- `return lhs.time < rhs.time;` 這類比較回傳目前屬於 `other`（`date_time.hpp:416/427`）。
- 成敗受 Dependent/Independent 分類影響更大，Dependent 的問題見 `backlog/building/1018/summary.md`。
