# H1 驗證紀錄：LLM blocker 優先度（2026-10-24）

設計見同目錄 `design.md`。本文件記錄驗證 A（GT 一致性）、B（重複性）與 C（離線重排）的方法、設定、結果與待改項目。驗證 B 與 A 一起執行。

## 1. 共同設定

| 項目 | 值 |
|---|---|
| 程式版本 | `blocker_process/global_blocker_selector.py` Phase 3（`_enrich_with_llm_priority`）、`prompts/templates/blocker_branch_priority_template`（`branch_priority_v1`） |
| LLM | Vertex AI `gemini-2.5-flash`、temperature 0，經 `LLMClient.generate_text()`（不經 LangGraph tool loop） |
| prompt 內容 | branch 條件、blocked side 程式碼、函式前後 ±40 行（`>>B`/`>>X` 標示）、只經 blocked side 可達的函式名稱（最多 10 個）、harness（截斷至 4 KB）；不含 regex `branch_kind` 與分數 |
| tier 推導 | `Actionable Target Gap`、`Bounded Extreme Value` → 2；`Uncertain` 或解析失敗 → 1；其他七類 → 0，但 `confidence = low` 時改為 1 |
| 排序 key | `(state, score, coverage_benefit, llm_tier, llm_score, branch_kind_priority, reach_confidence, …)` |

## 2. 驗證 A + B：GT 一致性與重複性

### 方法

- 工具：`tools/eval_llm_branch_priority.py --repeats 3 --workers 4 --output-dir experiments/llm_priority_eval_flash_r3`
- 對象：`ground_truth/cases/selected_cases` 的 19 個案例，每個案例重建與 selector 相同的 prompt，獨立呼叫 3 次（共 51 次，無快取）。
- 原始碼來源：依 `meta.json` 的 `source_file` 在 `external/<project>` 或 `external/oss-fuzz/build/out/<project>/src` 尋找；沒有 `source_file` 時以函式名稱搜尋。採用條件：branch 行是條件判斷，且（非 declared 來源時）上方最近的函式定義是案例記錄的函式。
- harness：使用案例目錄內的 `fuzz_target.cc`。
- 比對：GT `refined_triage_label` 屬於 `Actionable Target Gap`/`Bounded Extreme Value` 視為可解（預期 tier 2）；屬於其他非生成可解類別視為不可解（預期 tier 0）；`External Resource Failure` 視同 `Environmental Failure`；沒有 refined label 的案例不計分。
- 執行期間出現數次 Vertex AI `429 Resource exhausted`，重試後全部完成。

### 未納入的案例

| 案例 | 原因 |
|---|---|
| `libtiff_JPEGPreDecode_1303` | 本機 libtiff 的第 1303 行不在 `JPEGPreDecode` 內（版本可能不同） |
| `tomlplusplus_void_..._print_floating_point_..._10567` | 行號屬於 `toml.hpp`，meta 的檔案卻是 `print_to_stream.inl` |
| libvpx 3 例 | 有評估，但 GT 沒有 refined label，不計分 |

### 結果

| GT | 案例（3 次的多數結果） | 正確 |
|---|---|---|
| 可解（Bounded Extreme Value） | lcms 442、lcms 2865、libpcap 7517、toml 416 → 皆 tier 2 | 4/4 |
| 不可解，判對（tier 0） | cjson 2772、cjson 602、cjson 547（2/3）、libpcap 5730、toml 494 | 5 |
| 不可解，判錯（tier 2） | lcms 1239、libtiff 281（Structurally Unreachable）；libtiff 211、tinyxml2 1176（Internal Invariant）；libpcap 7226（External Resource） | 5 |

| 指標 | 值 |
|---|---|
| 判斷與 GT 同側 | 26/42 次（62%）；以案例計 9/14 |
| 可解案例被判為 tier 0 | 0 次 |
| tier 0 判斷的準確度 | 14/14 次 |
| 不可解案例被識別 | 5/10 |
| 3 次 tier 完全相同 | 16/17（僅 cjson 547 不一致） |
| 選擇 `Uncertain` | 0 次 |

### 解讀

- 安全性達標：可解案例沒有被壓到最後；416 為 tier 2、494 為 tier 0。
- 主要弱點是過度樂觀：17 例中 12 例被判為 `Actionable Target Gap`。判錯的 5 例分兩類：需要 API 呼叫路徑資訊才能判斷（Structurally Unreachable），以及需要追蹤資料來源（Internal Invariant、External Resource）。
- GT 案例多來自「被判為 Dependent 卻失敗」的 blocker，難度偏高，62% 應視為偏低的估計。參考：既有 triage 在 9 個 libpcap 案例的人工一致率約 5/9。

## 3. 驗證 C：tomlplusplus 離線重排

### 方法

- 對象：`20261010_143353`（25 個候選）、`20261012_161330`（26 個）、`20261018_205808`（14 個）三次實驗的 `branch_blockers/tomlplusplus_initial_introspector_refresh.json`。
- 原始碼：各實驗 `blocker_sessions/tomlplusplus/session_*/source_root` 的第一個 session（行號與實驗當時一致）。
- 三種順序：
  - `recorded`：snapshot 中實驗當時的順序。
  - `regex`：`rescore_existing_blockers()`，不啟用 LLM。
  - `regex+llm`：`rescore_existing_blockers(..., llm_priority=...)`，`top_n = 40`、3 個 worker，三次實驗共用一份快取（`experiments/llm_priority_replay_c/cache.jsonl`）。
- 成敗：
  - 同次：只看該次實驗的 `blocker_attempts.jsonl`（`blocker_pipeline_result`）。
  - 合併：1006、1010、1012、1018 四次實驗中該 blocker 的成功次數／嘗試次數（以檔名 + branch 行號比對）。
- 腳本：session scratchpad 的 `replay_llm.py`；完整輸出 `experiments/llm_priority_replay_c/report.txt`，prompt 與回應在 `experiments/llm_priority_replay_c/prompts/`。
- LLM 呼叫：33 個不同候選，全部成功（25 + 3 + 5，其餘命中快取）。

### 結果（同次：成功/嘗試，失敗 pipeline 耗時）

| 實驗 | 前 K | recorded | regex | regex+llm |
|---|---|---|---|---|
| 1010 | 5 | 2/5，3238s | 3/4，1052s | **4/4，0s** |
| 1010 | 10 | 5/9，3490s | 6/8，2143s | **7/8，1091s** |
| 1012 | 5 | 5/5，0s | 5/5，0s | 4/4，0s |
| 1012 | 10 | 7/9，1755s | 9/9，0s | 9/9，0s |
| 1018 | 5 | 3/5，3202s | 3/5，3202s | **4/5，698s** |
| 1018 | 10 | 5/10，7036s | 5/10，7036s | 4/7，**3834s** |

合併四次實驗的前 10 名：1010 regex 16/18、regex+llm 16/17；1012 17/19、17/18；1018 9/25、8/24。

### LLM 的分類分布

| 分類 | 數量 |
|---|---|
| `Actionable Target Gap`（全部 high） | 30 |
| `Internal Invariant Guard` | 1（`path.inl:494`） |
| `Structurally Unreachable API Path` | 1（`toml.hpp:17652`） |
| `Environmental Failure` | 1（`toml.hpp:12880`） |

`solvability`：1.0 × 25、0.9 × 3、0.8 × 2、0–0.1 × 3。

### 改變排序的候選

| 候選 | LLM 處理 | 四次實驗結果 | 判斷 |
|---|---|---|---|
| `path.inl:494` | tier 0（Internal Invariant） | 0/4 | 正確，與 GT 一致 |
| `parser.inl:701` | 0.8 | 0/1（1982s） | 正確 |
| `parser.inl:1174` | 0.9 | 0/3 | 正確 |
| `toml.hpp:12880` | tier 0（Environmental，理由為 I/O 錯誤） | 1/3 | 大致合理 |
| `toml.hpp:17652` | tier 0（Structurally Unreachable，理由為 `yaml_formatter` 一律使用預設 flag） | 2/3 | **錯誤**：Independent pipeline 改寫 harness、換用其他 API 後成功 |
| `toml.hpp:13284` | 0.8 | 2/3 | 偏錯 |
| `toml.hpp:5535` | 0.9 | 1/1 | 偏錯 |

### 解讀

- 1010 與 1018 前段改善（失敗耗時分別少約 1000 秒與 2500–3200 秒），1012 原本已 9/9，三次都沒有變差。
- LLM 在 tomlplusplus 上的區分度很低：30/33 為 Actionable、信心 high、分數多為 1.0，大部分順序仍由 regex 決定。
- `17652` 顯示「目前的 harness 走不到」正是 Independent pipeline 可以解決的情況，不應排到最後。
- `formatter::print` 的 `16904`（0/4）與 `16895`（0/3）LLM 與 regex 都沒有往後排。

## 4. 待改項目（保留，尚未實作）

1. **`Structurally Unreachable API Path` 改為 tier 1**：依據為 `17652`（2/3 成功）。GT 協議中，存在合法替代 API 路徑時應歸為 `Actionable Target Gap`；而 Independent pipeline 會改寫 harness 尋找替代路徑，因此這類不宜排到最後。修改點：`_LLM_UNSOLVABLE_CATEGORIES` 與 `_derive_llm_tier()`。
2. **提高 LLM 分數的區分度**：目前 30/33 個候選為 high 信心、分數 1.0。可考慮在 prompt 中：
   - 依「需要同時滿足的條件數量」與「輸入結構複雜度」給 `solvability`，而不只是可不可能；
   - 只有寫得出具體的輸入產生路徑時才允許 `confidence = high`，否則 `medium`/`low`；
   - 加入一兩個 Structurally Unreachable 與 Internal Invariant 的範例。

   修改後需要重新執行驗證 A 與 C（`branch_priority_v1` → `v2`，快取 key 會自動失效）。
