
# Introspector Refresh / Session Cache 問題：可行性分析與修正計畫

## Context（為什麼要做）

實驗 `experiments/20260704_032608_run_all_fuzzer` 觀察到：blocker 系統第一次 full refresh 成功並建立 `session_001` 後，後半段 selector 一直沿用 `session_001/branch-blockers.json` 的舊 blocker pool，導致候選池 stale、過早出現 `no_unattempted_relevant_blockers`。

`TODO_MD/introspector_refresh_cache_problem_20260704.md` 已提出根因與 9 項修正方向。本文件的目的是：**用實際程式碼驗證該分析、評估每項修正的可行性、指出 md 未涵蓋的盲點。**

> **本次範圍：只做分析，先不實作。** 下方「四、建議實作順序」是給未來實作的參考規劃，本輪不動任何程式碼。

---

## 一、程式碼核實：md 描述是否屬實

三大塊都已對照原始碼確認，md 的問題描述**基本屬實**：

### 1. Light refresh 失敗被當成成功（根因，屬實）
- `ensure_blocker_artifacts()` [main.py:572-708](main.py#L572-L708)。
- refresh mode 決策：`use_light_refresh = artifacts_ready and force_refresh and not prefer_full_refresh`（[main.py:593](main.py#L593)）。
- **關鍵 bug**：light refresh 失敗時（[main.py:626-645](main.py#L626-L645)）記 `skip_reason="light_refresh_failed_reused_existing_artifacts"`、`reused_existing=True`，記 event `refresh_mode="light_refresh_reused_existing" success=True`，然後 **`return True`**。上層視為成功、繼續沿用舊 session cache。
- light refresh 本體 `refresh_blocker_report_from_existing_introspector()`（oss_fuzz.py:1228+）在 `build/out/<proj>/inspector/` 不存在時直接 `return False`。
- **此行為被測試鎖定**：`unitest/test_blocker_session_lifecycle.py:254-279`（`test_light_refresh_failure_reuses_existing_artifacts_without_full_fallback`）。→ 修 Fix 3 必須同步改這個測試。

### 2. remove_target() 連帶摧毀 inspector/（屬實）
- `remove_target()` [oss_fuzz.py:1380-1455](external/oss_fuzz.py#L1380-L1455)。
- 只要刪到任一 target artifact（`removed_any_artifact=True`），就 `rmtree` 掉 project-level 的 `inspector/`、`textcov_reports/`、`report/`、`report_target/`（[oss_fuzz.py:1441-1453](external/oss_fuzz.py#L1441-L1453)）。
- 呼叫情境涵蓋：candidate 編譯失敗（input_independent_solver.py:1032）、coverage 無進展 rollback（:1334）、input-dependent harness quarantine（input_dependent_solver.py:703）、native build 失敗清理、main pipeline 探針清理等 —— 都是 solver 內部很常見的 transient target 清理。
- **直接矛盾**：artifact cache 層刻意保護 inspector（`_copy_directory_contents` 複製時 `if name=="inspector": continue`、`_clear_build_out_dir` 用 `find ... ! -path '/out/inspector'` 保留），但 `remove_target()` 卻把它 rmtree。cache 費心保留、cleanup 順手刪除，兩條路徑方向相反。

### 3. 先切 top_k、再排除 attempted（屬實）
- `_select_project_blockers()` 於 [main.py:981-991](main.py#L981-L991) 先 `filtered = filtered[:blocker_top_k]`，此處**完全沒參考 attempted_blocker_keys**。
- `run_blocker_session()` 於 [main.py:1733-1785](main.py#L1733-L1785) 才在 top_k window 內 `if key in state.attempted_blocker_keys: continue`。
- `no_unattempted_relevant_blockers`（[main.py:1812-1822](main.py#L1812-L1822)）的枯竭判斷只看 top_k window，非整份 JSON → window 內都嘗試過就假性枯竭。
- 與另一份 `TODO_MD/blocker_choose_problem.md` 記載一致。

### 4. Time-enough 判斷「大部分已存在」（重要修正 md 的認知）
- **Fix 9 提的「full refresh 要有 time-enough 判斷」其實已經實作**：`ensure_blocker_artifacts` 於 [main.py:596-611](main.py#L596-L611) 已有 budget guard，用 `_refresh_elapsed_estimate()`（[main.py:324-332](main.py#L324-L332)）= `max(observed, bootstrap) * 1.20 + 60`，`available = deadline - post_refresh_reserve - now`，`estimate > available` 就 skip、記 `insufficient_time_budget`。
- 常數已存在（[main.py:84-92](main.py#L84-L92)）：`BLOCKER_FULL_REFRESH_BOOTSTRAP_SECONDS=1200`、light=600、attempt=600、coverage=180、overhead=120、safety ×1.20 +60。
- **落差**：(a) 這個 guard 只在 `post_refresh_reserve_seconds > 0` 時啟動；deadline=None 或 reserve=0 時不設防。(b) reason 命名是 `insufficient_time_budget`，非 md 期望的 `artifact_refresh_required_but_insufficient_time`。→ Fix 9 大致是重命名 + 補齊觸發條件，不必重寫。

---

## 二、逐項可行性評估

| Fix | 內容 | 可行性 | 主要工作 |
|---|---|---|---|
| 1 | 記錄 full refresh 時的 target set / count | 易 | 新增 state 欄位 `last_full_refresh_target_set/count`，於 [main.py:675-679](main.py#L675-L679) 捕捉 |
| 2 | 先排除 attempted 再切 top_k | 中 | 把 `attempted_blocker_keys` 傳入 `_select_project_blockers`，在 `[:blocker_top_k]` 前先過濾；`no_unattempted` 改看整份 |
| 3 | light refresh 失敗不視為成功 | 中 | 改 [main.py:626-645](main.py#L626-L645)：失敗 → 依剩餘時間 escalate full / cached_static_rerank / skip。**必須改鎖定測試** |
| 4 | remove_target 不摧毀 inspector | 易 | 移除 [oss_fuzz.py:1441-1453](external/oss_fuzz.py#L1441-L1453) 的整包 rmtree；改成只刪 target-specific textcov 檔 + 標 `artifacts_dirty` |
| 5 | light refresh 只處理已知 target set | 中 | 依賴 Fix 1；候選 `best_target ∉ known set` 就降權/跳過 |
| 6 | 新增 cached_static_rerank 模式 | **難** | 見下方盲點 C/D；大量重用既有 rerank 機制但 coverage 新鮮度是關鍵風險 |
| 7 | 區分 session cache 與 pool refresh | 易 | 主要是 state flag / log（`static_context_reused`、`blocker_pool_stale`） |
| 8 | coverage 語意（只排除已覆蓋、不發現新 blocker） | 已部分達成 | 現有兩層 revalidation 已做排除已覆蓋 |
| 9 | full refresh time-enough | **已實作** | 只需補齊觸發條件 + 重命名 reason |

---

## 三、md 未涵蓋的盲點（重點）

### 盲點 A：計數器語意落差 —— 現有的不是「retained new targets」
md 全套狀態機的核心變數是 `retained_new_targets_since_full_refresh`（真正保留、會參與後續 fuzzing 的新 target 數）。但程式碼現有的 `new_targets_since_full_rebuild` 是**在 session 起點偵測 fingerprint 變化時 +1**（[main.py:1563-1565](main.py#L1563-L1565)），是「fingerprint 變化次數」，**不是**保留 target 數。要忠實實作 md，需要新機制：full refresh 時快照 active target 檔名集合，之後每個 session 比對「目前實際存在的 generated targets」做集合差集，而不是數 fingerprint 變化。**這不只是改名，是換演算法。**

### 盲點 B：fingerprint 也含非 target 檔案、且對「編輯」敏感
fingerprint（`_iter_project_target_artifacts` oss_fuzz.py:248-268）涵蓋 `build.sh`、`project.yaml`、`Dockerfile`，以及對既有 harness 的**內容編輯**（compile-fix loop 改寫既有 llm_fuzzgen 檔）。因此：既有 harness 被改一行 → fingerprint 變、但沒有新 target；remove_target 刪暫時檔 → fingerprint 變。→ 需先定義「新 target」到底是「新檔名」還是「內容變更」。

**建議 v1 用檔名集合做 retained 判斷，與 fingerprint 脫鉤。** target 檔名格式為 `llm_fuzzgen*.{c,cc,cpp}`（隨專案語言而定；lcms 實際用 `.c`，如 `llm_fuzzgen_reference_guided_0704...c`、`llm_fuzzgen_dedicated_generation_0704...c`）。實作時應涵蓋 `.c/.cc/.cpp` 三種副檔名，並以 `projects/<proj>/` 下實際出現的 `llm_fuzzgen*` 原始碼檔名集合為準（與 fingerprint glob 的 source 檔清單一致，但只取原始碼、排除 `.options/.dict/_seed_corpus.zip`）。

### 盲點 C：cached_static_rerank 依賴的最新 coverage 也可能被刪（Fix 6 依賴 Fix 4）
cached_static_rerank 要「用最新 textcov_reports 重排 cached pool」，但 `remove_target` 同時刪 `textcov_reports/`。若不先修 Fix 4，inspector 沒了、textcov 也沒了，cached_static_rerank 無 coverage 可用，退化成純 stale。→ **Fix 6 有先後相依：必須先落地 Fix 4。** md 有列 Fix 4 但沒點出這個依賴順序。

### 盲點 D：cached_static_rerank 省的成本可能有限
更深一層：`_clear_build_out_dir` 只 exclude `inspector`，**不保留 `textcov_reports`**。因此即使 remove_target 不刪，只要 solver 切換 sanitizer 觸發 cache restore，live `textcov_reports/` 也可能被清（除非它剛好在該 sanitizer 的 cache snapshot 內）。→ cached_static_rerank 想拿到「最新 coverage」很可能仍需跑一次 `coverage()`（含 coverage build，可從 cache restore）。若如此，它相對 light refresh 主要只省下「重跑 introspector report 產生新 branch-blockers.json」那段，成本節省需實測驗證，不宜假設很省。**建議：先量測 light refresh vs coverage() 的實際耗時，再決定 cached_static_rerank 是否值得。**

### 盲點 E：既有 refresh 觸發器 md 沒納入 —— branch-growth ratio probe
[main.py:1587-1627](main.py#L1587-L1627) 有一個 md 完全沒提的觸發器：`reuse_session_artifacts` 模式下跑 coverage probe，`branch_growth_ratio >= threshold`(預設 0.05) 就 `force_refresh=True`。導入 md 狀態機時必須與此協調，否則 refresh 會比 md 乾淨模型更常觸發。

### 盲點 F：attempted_blocker_keys 只在記憶體、不跨 run
`attempted_blocker_keys` 是 `BlockerRuntimeState` 記憶體欄位（[main.py:64](main.py#L64)），不持久化。Fix 2 在單一 run 內有效；跨 run 重啟會遺失已嘗試紀錄。與 refresh 正交，但續跑實驗時相關。次要。

### 盲點 G：狀態機 step 6 會降低 full refresh 門檻到 retained>0
md 決策 step 6：cached pool 真的耗盡 + `retained>0` → full refresh。這會覆寫 step 4 —— 即使只有 1~2 個 retained target（遠低於 threshold），只要 pool 剛好被嘗試完就觸發昂貴 full refresh。需確認這是否為預期；否則 Fix 2（正確計算 pool 是否真耗盡）落地後，反而可能因 step 6 更頻繁 full refresh。

---

## 四、建議實作順序（未來參考，本輪不實作）

**Phase 1 — 止血（根因，低風險高回報）**
- Fix 4：`remove_target()` 不再 rmtree `inspector/`、`textcov_reports/`（保留 project-level report），改成刪 target-specific 檔 + 標 `artifacts_dirty`。（前置於 Fix 6）
- Fix 3：light refresh 失敗不再 `return True`。改為：時間足夠 → escalate full refresh；不足 → skip（reason `artifact_refresh_required_but_insufficient_time`）。**同步改** `test_blocker_session_lifecycle.py:254-279`。
- Fix 2：`_select_project_blockers` 先排除 `attempted_blocker_keys` 再切 `[:blocker_top_k]`；`no_unattempted_relevant_blockers` 改依整份 JSON 判斷。

**Phase 2 — 正確的 refresh 門檻**
- Fix 1 + 盲點 A/B：新增 `last_full_refresh_target_set/count`，用 `llm_fuzzgen*.c` 檔名集合計算 `retained_new_targets_since_full_refresh`（脫離 fingerprint 計數）。threshold 改 `max(5, ceil(count*0.10))`。
- Fix 9：補齊 budget guard 觸發條件、reason 命名。
- Fix 7：加上 `static_context_reused / coverage_refreshed / blocker_pool_stale` 狀態與 log。

**Phase 3 —（可選、需先量測）cached_static_rerank**
- Fix 6 + Fix 5：先實測 light refresh vs coverage() 成本（盲點 D）。若確有節省，才實作第三模式，重用 `aggregate_score_and_revalidate_blockers`（global_blocker_selector.py:1211-1288）指向 cached `branch-blockers.json` + live `textcov_reports/*.linecovreport`；並限定只處理 known target set。

---

## 五、驗證方式

1. **單元測試**：改寫 `test_blocker_session_lifecycle.py` 中 light-fail 測試；新增 remove_target 保留 inspector 的測試（參考 `unitest/test_oss_fuzz_target_cleanup.py`）；新增 selector「先排除 attempted 再切 top_k」測試。
2. **端對端短測**：lcms 90 分鐘 / 2 小時，觀察 log：
   - 第一次 full refresh 成功、建立 session cache。
   - live inspector 不見時，**不應**再出現「light refresh failed 但當成功」。
   - target set 差異大時看到 full refresh；時間不足時看到 `artifact_refresh_required_but_insufficient_time`。
   - 不同 session 不應長期都用 `blocker_sessions/lcms/session_001/branch-blockers.json`。
3. **回歸**：確認 solver transient target 清理後，`build/out/lcms/inspector/` 仍存在（Fix 4）。

---

## 一句話結論

md 的根因判斷與 Fix 2/3/4 **完全正確且必要**；Fix 9 其實已大致實作。最大盲點是：狀態機核心變數 `retained_new_targets_since_full_refresh` 在現有碼中並不存在（現用的是易被 transient target 擾動的 fingerprint 計數），以及 cached_static_rerank（Fix 6）依賴先修 Fix 4、且其成本節省需實測驗證。建議分三階段：先做 Phase 1 止血，再補正確門檻，cached_static_rerank 列為可選。
