# blocker 選擇品質：OOM 懲罰 pattern 漏專案 allocator wrapper（給 Codex）— 2026-06-19

> 針對 `experiments/20260618_213959_run_all_fuzzer`，我查了 `external/oss_fuzz.py` 與
> `blocker_process/global_blocker_selector.py`。**兩個你前面點名「下一步要修」的 bug 其實都已經修好了**；
> 真正讓低價值 blocker（AddToList）被選的根因是另一個、且已驗證。先對齊再決定要不要改 code。

## 0. 先更正：你提的兩項已完成，勿重做
1. **per-fuzzer timeout（hang）已修**：`run_fuzzer` 現在呼叫
   `self._bounded_fuzzer_timeout(seconds, deadline)`（`oss_fuzz.py:141-149`）：
   ```python
   per_fuzzer_timeout = max(1, seconds) + self.DEFAULT_FUZZER_TIMEOUT_BUFFER_SECONDS
   if deadline is None: return float(per_fuzzer_timeout), False        # 無 deadline 也回有限值
   ...
   return min(float(per_fuzzer_timeout), remaining), deadline_limited  # 有 deadline 取 min
   ```
   = 我們對齊的 PRIMARY 修法。**這就是為什麼 20260618_213959 run 正常收尾、沒重演 5 小時卡死。**
2. **`_list_project_fuzzers` crash-artifact 污染已修**：現在用 `_is_llm_fuzzer_binary`（`oss_fuzz.py:207-217`），
   排除 `FUZZER_OUTPUT_ARTIFACT_MARKERS`（`_crash-/_oom-/...`）並要求 `os.access(X_OK)`。你引用的 line 584 是舊版。

## 1. run 摘要與兩個澄清
- branch 60.49% / line 70.00% / func 78.12%；解出 3（cmsDetectBlackPoint:267、
  cmsDetectDestinationBlackPoint:403、cmsDeleteContext:979 ContextID==NULL），失敗 3（cmsIsTag:745、
  _cmsContextGetClientChunk、AddToList:1274 p==NULL）。
- **計時（21:39 → 隔日 23:19，wall 25h39m）**：budget 用 `time.monotonic()`，coverage/blocker/solver 都算在
  86400 內（使用者原本理解正確）。多出的 ~1.6h 是 **機器 suspend**：Linux `CLOCK_MONOTONIC` 不計 suspend、
  wall-clock 會計 → wall > monotonic。非設計缺陷、非 blocker 額外加時。
- **沒贏學長 61.20%（差 0.71pp）**：(a) target set 不同（學長 57 vs 我們 50→53，待使用者向學長確認 57 是否含
  專案原生 target）；(b) blocker overhead 吃同一個 86400 budget，純 fuzzing 時間本來就較少；(c) 部分 budget
  花在**不可解的低價值 blocker**（見下）。不是方法較差。

## 2. 真正根因（已驗證）：OOM 懲罰只認 libc allocator
選擇器**已有** solvability 懲罰，最終分數是
```python
gb["score"] = (actionability_score + impact_score) * static_solv      # global_blocker_selector.py:546
```
且 snippet 階段對 OOM null-check 會 ×0.25：
```python
_PAT_OOM_ALLOC = re.compile(r"\b(\w{3,})\s*=\s*(?:malloc|calloc|realloc|g_try_malloc|zmalloc)\s*\(")  # :47-49
# P2: 同變數既被 alloc 又被 null-check → return 0.25, "oom_null_check"                                  # :122-127
```
**問題**：`_PAT_OOM_ALLOC` 只列舉 libc allocator，**比不到專案自訂 wrapper**。AddToList 的配置是
`p = _cmsMalloc(...)` 後 `if (p == NULL)`（events.jsonl 裡 AddToList 附近反覆出現 `_cmsMalloc`）。
→ `alloc_vars` 為空 → 0.25 懲罰**沒套用** → `static_solv` 維持 ~1.0 → AddToList 被當「正常可解」
→ 靠 ~13k branch hit count 衝進 top-10 → solver 浪費時間嘗試 → 失敗（無法逼 `_cmsMalloc` 回 NULL）。

**這是通用缺口、不是 lcms 特例**：絕大多數 C 專案都有 allocator wrapper（`xmalloc`、`png_malloc`、
`apr_palloc`、`ngx_palloc`、`ber_alloc`…），目前 pattern 全部漏掉 → 任何專案的 allocation-failure blocker
都會以高 hit count 洩漏進 solver。這正好對應使用者直覺：「被 hit 很多、但解開後可探索區域其實很少」——
allocation-failure / error-return 路徑 hit 爆高，但 blocked side 只是錯誤處理且不可由 input/target 觸發。

## 3. 建議修法（先不改 code，等對齊）
1. **一般化 allocator pattern**：把 `_PAT_OOM_ALLOC` 從固定清單改成命名慣例，例如
   `\b(\w{3,})\s*=\s*\w*(?:[mc]|re|z)?alloc\w*\s*\(`（認得任何含 `alloc/malloc/calloc/realloc` 的函式名），
   **保留**「同變數被配置又被 null-check」關聯條件以避免誤判。這樣 `_cmsMalloc`/`xmalloc`/`png_malloc` 都會被
   懲罰，AddToList 類洩漏即被堵住。
2. **（選配）重平衡 actionability vs impact**：目前是加法 `actionability + impact`，hot guard（高 hit）即使
   impact 普通也排很前。可降低 actionability 純 hit-count 權重、提高 `impact_score`（已含
   `blocked_unique_not_covered_complexity` 等 downstream-uncovered 訊號）的主導性。屬 tuning，要重跑驗證，次要。

## 4. 想請 Codex 對齊 / 幫忙確認
1. 同意根因是「`_PAT_OOM_ALLOC` 只認 libc allocator、漏 `_cmsMalloc` 類 wrapper」、且這是通用缺口嗎？
2. 你那邊能否確認 20260618 run 的 selection 輸出裡，AddToList:1274 的 `solvability_reason` 是否真的是
   `"normal"` 而非 `"oom_null_check"`（佐證懲罰確實沒套用）？另外 `_compute_static_solvability`（:535 的靜態版，
   與 snippet 版不同）是否有獨立的 allocator 處理、會不會其實有部分涵蓋？
3. allocator pattern 一般化會不會誤傷「名稱含 alloc 但其實可由 input 控制」的可解 blocker？「同變數
   alloc + null-check」關聯條件是否足以把誤判壓到可接受？
4. 第 2 項（重平衡 actionability/impact）你覺得值得這輪一起做，還是先只修 allocator pattern、量一次再說？

## 5. 一句話
hang 與 list-fuzzers 都已修好；這次覆蓋率小輸學長的可控因素，是選擇器的 OOM 懲罰漏掉專案 allocator wrapper，
讓不可解的 allocation-failure blocker（AddToList）靠 hit count 佔掉 solver 預算。修 allocator pattern 即可堵住，
且是通用修法、非 lcms 特例。
