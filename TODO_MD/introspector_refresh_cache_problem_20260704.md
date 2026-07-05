# Introspector Refresh / Session Cache 問題與修正方案

## 一句話結論

修正前的問題不是 solver 途中會重新建 Introspector，而是：

```text
第一次 full refresh 建好的 inspector/
→ solver 生成 transient target
→ failed candidate 觸發 remove_target()
→ remove_target() 整包刪掉 inspector/ 與 textcov_reports/
→ 下一次 light refresh 找不到 live inspector 或找不到 .covreport
→ 系統卻把舊 session cache 當成 refresh 成功
→ 後半段 blocker selector 長期使用 stale blocker pool
```

修正核心是：

> `remove_target()` 只做 target-specific cleanup；是否重建 Introspector 要交給 blocker session 的 refresh decision。session cache 只能穩定同一 session 的 context，不能跨 session 假裝成新的 blocker artifacts。

## 我們真正需要的行為

Blocker 系統需要兩種資訊：

```text
靜態資訊：
  fuzz target set
  branch-blockers.json
  CFG / calltree / .data
  source context

動態資訊：
  最新 coverage
  branch hit count
  blocked side 是否已經被覆蓋
```

理想狀態是：

1. 第一次進 blocker session 時，一定 full refresh，建立完整 Introspector。
2. 同一個 blocker session 內，使用固定的 session cache，避免 build / coverage 切換造成 context 不穩。
3. 不同 session 之間，coverage 要盡量更新，避免解已經不是 blocker 的點。
4. 新 generated target 成功留下來後，不要立刻假裝它已有 CFG/calltree；等 retained target 數量累積到門檻，再 full refresh 正式納入 blocker pool。
5. full refresh 很貴，不能太頻繁；但也不能永遠 fallback 到舊 cache。

## 三種 artifact 的角色

### Full Refresh

Full refresh 會跑 OSS-Fuzz Introspector：

```text
main.py ensure_blocker_artifacts()
→ oss_fuzz.generate_report()
→ introspector --seconds ...
```

它會重新產生：

```text
build/out/<project>/inspector/branch-blockers.json
build/out/<project>/inspector/all_functions.js
build/out/<project>/inspector/summary*.json
build/out/<project>/inspector/exe_to_fuzz_introspector_logs.yaml
build/out/<project>/inspector/*.data
source mirror / source context
```

語意是：

> 用目前 active fuzz targets 重新建立完整 blocker 世界觀。

它能把新 target 正式納入 blocker analysis，但成本高，lcms 可能十幾分鐘以上，而且記憶體尖峰高。

### Light Refresh

Light refresh 不重跑完整 Introspector。它需要既有：

```text
build/out/<project>/inspector/
build/out/<project>/textcov_reports/
```

流程是：

```text
把 textcov_reports/*.covreport 複製進 inspector/
→ fuzz-introspector report --target-dir inspector --out-dir inspector
```

語意是：

> 靜態資料沿用舊 Introspector，只更新 coverage-driven blocker report。

它適合：

```text
target set 沒有大幅變化
live inspector/ 還存在
只需要更新 hit count / blocked-side coverage / ranking
```

它不適合：

```text
新增很多 target
live inspector/ 不見
textcov_reports/ 不見或沒有 .covreport
需要新 target 的 CFG / calltree / .data
```

### Session Cache

Session cache 位於：

```text
experiments/<run>/blocker_sessions/<project>/session_xxx/
```

它保存同一 session 會用到的 context：

```text
branch-blockers.json
all_functions.js
summary.json
exe_to_fuzz_introspector_logs.yaml
*.data
source_root
```

語意是：

> 保證同一個 blocker session 裡，selector / classifier / solver 看到一致的 source / CFG / callpath context。

它不是 refresh。它不能長期替代新的 `branch-blockers.json`。

## 已確認的程式碼事實

### 1. Solver 途中不會主動跑 Introspector

Solver 生成 target 後主要做：

```text
address build
coverage build
runtime sanity
coverage evaluation
remove failed target
```

它不會呼叫 `oss_fuzz.generate_report()`，也不會把 transient target 加進 Introspector。

所以新 target `D` 的狀態是：

```text
full refresh 時 target set = A, B, C
→ Introspector 只有 A/B/C 的 static data

solver 後來生成 D
→ D 可以 build / fuzz / coverage
→ 但 D 沒有 CFG / calltree / .data
→ 除非下一次 full refresh，D 不會正式進 blocker pool
```

### 2. remove_target() 修正前會刪掉 project-level artifacts

修正前 `external/oss_fuzz.py::remove_target()` 會先刪 target-specific files，但只要有刪到任一 artifact，就會整包刪：

```text
build/out/<project>/inspector/
build/out/<project>/textcov_reports/
build/out/<project>/report/
build/out/<project>/report_target/
```

這就是 stale / fallback 問題的直接原因。

重點不是：

```text
solver 生成的 target 已經進 inspector，所以 remove_target 要刪它的 inspector 資料
```

而是：

```text
solver 生成的 target 根本沒進 inspector
但 remove_target 卻把前面 full refresh 建好的 project-level inspector 整包刪掉
```

### 3. light refresh failure 修正前被當成成功

修正前 `main.py::ensure_blocker_artifacts()` 裡，light refresh 失敗時會記：

```text
last_artifact_refresh_skip_reason = light_refresh_failed_reused_existing_artifacts
last_artifact_refresh_reused_existing = true
refresh_mode = light_refresh_reused_existing
success = true
```

然後回傳 `True`。這代表上層會以為 blocker artifacts 已準備好，但實際上只是繼續用舊 session cache。

light refresh 會失敗有兩條主要路徑：

```text
build/out/<project>/inspector/ 不存在
build/out/<project>/textcov_reports/ 不存在或沒有 .covreport
```

修正前 `remove_target()` 會同時刪這兩個 directory，所以它不是只破壞 static context，也會破壞 light refresh 需要的 coverage input。

這個舊行為原本還被測試鎖住：

```text
unitest/test_blocker_session_lifecycle.py
test_light_refresh_failure_reuses_existing_artifacts_without_full_fallback
```

Phase 1 修正時已同步改成 `test_light_refresh_failure_is_not_reported_as_success`。

### 4. branch-growth ratio 已經存在

在 `reuse_session_artifacts` 模式下，目前程式會跑 coverage probe，並計算：

```text
branch_growth_ratio =
  (current_covered_branches - artifact_branch_covered_baseline)
  / max(artifact_branch_covered_baseline, blocker_refresh_branch_growth_floor)
```

若：

```text
branch_growth_ratio >= blocker_refresh_branch_growth_threshold
```

就會提高 refresh 需求。

這個訊號的語意是：

> coverage 已經明顯變化，舊 blocker hit count / ranking 可能不準。

它不代表 target set 變多，也不應該單獨導致 full refresh。

正確解讀：

```text
branch growth 大
→ 至少更新 coverage-driven blocker 狀態
→ live inspector 存在：light refresh
→ live inspector 不存在：cached static rerank / coverage repair

retained target 增加很多
→ static target set 改變
→ full refresh
```

### 5. 現有 fingerprint 不等於 retained target count

目前 `BlockerRuntimeState.new_targets_since_full_rebuild` 是由 target fingerprint 變化推動。fingerprint 包含：

```text
llm_fuzzgen*.c/.cc/.cpp
*.options
seed corpus zip
llm_fuzzgen.dict
build.sh
project.yaml
Dockerfile
```

所以它不是「成功留下來的新 target 數」。它會被 transient target、`.options`、甚至 project metadata 變化干擾。

因此不能直接用它判斷 full refresh threshold。

### 6. full refresh 的時間 guard 已有雛形

目前 `main.py::_refresh_elapsed_estimate()` 已經會用：

```text
max(observed_elapsed, bootstrap_seconds)
* safety_multiplier
+ safety_buffer
```

估計 refresh 成本。`ensure_blocker_artifacts()` 也已經有 deadline guard。

所以這部分不是要重寫一套新的 timeout 系統，而是補齊語意：

```text
guard 目前只在 deadline != None 且 post_refresh_reserve_seconds > 0 時啟動
reason 目前叫 insufficient_time_budget
後續可改成更明確的 artifact_refresh_required_but_insufficient_time
```

也就是：time guard 已經存在；後續修正是讓所有 refresh path 都正確使用它，並把 log reason 命名得更準。

## 目前真正的問題

### 問題 A：局部 cleanup 破壞全域 artifact

`remove_target()` 是局部動作，但它刪掉的是 project-level artifact：

```text
清一個 failed target
→ 刪整個 inspector/
→ 刪整個 textcov_reports/
→ light refresh 需要 inspector/ 與 .covreport，所以失敗
→ 系統 fallback 舊 cache
```

### 問題 B：light refresh failure 被包裝成 success

這讓系統看起來「有 refresh」，但實際只是：

```text
沿用 session_001/branch-blockers.json
```

結果後半段 selector stale。

### 問題 C：new target 沒有 static context，不能靠 light refresh 正式納入 blocker selector

Light refresh 只能更新舊 target pool 的 coverage 狀態。

如果第一次 full refresh 只有：

```text
A, B, C
```

後來 solver 生成：

```text
D
```

那在下一次 full refresh 前：

```text
D 可以被 fuzzing 跑
D 可以貢獻 coverage
但 D 沒有完整 CFG / calltree / .data
D 不應被當成完整 blocker selector target
```

一句話：

> light refresh 只能更新舊世界的 coverage；full refresh 才能把新 target 納入 blocker 世界。

### 問題 D：top-k window 會造成假性候選耗盡

修正前 selector 先取 `top_k`，後面才排除 attempted blockers。

這會造成：

```text
branch-blockers.json 有 100 個候選
top_k = 10
前 10 個都 attempted
→ 系統以為 no_unattempted_relevant_blockers
```

但實際上第 11~100 個還沒看。

正確順序應該是：

```text
整份 JSON aggregate / rank
→ 排除 attempted
→ 再取 top_k / session_size
```

## 修正方案

### 修正 1：remove_target() 只做 target-specific cleanup

改成：

```text
remove_target():
  刪 project source 裡的 target source
  刪 build/out 裡該 target 的 binary/object/options
  刪 build cache 裡該 target 的 snapshot
  刪 corpus/<project>/<target>/
  刪 textcov_reports/<target>.linecovreport / .covreport
  不整包刪 inspector/
  不整包刪 textcov_reports/
  不整包刪 report/
```

原因：

```text
target-specific artifact 可以安全刪
project-level inspector/report 要由 refresh decision 處理
```

可能風險與控制方式：

```text
舊 branch-blockers.json 仍提到已刪 target
→ selector 要檢查 best_target 是否仍是 active target

舊 target coverage report 留下
→ remove_target 刪 target-specific textcov report

target set 真的變很多
→ retained target threshold 觸發 full refresh
```

成本：

```text
執行成本更低，因為少做 rmtree project-level directory
主要增加的是磁碟保留量，不是 RAM
OS kill 通常來自 fuzz-introspect / build / coverage process RSS，不是 inspector 檔案存在本身
```

### 修正 2：light refresh failure 不可回傳 success

新語意：

```text
light refresh failed
→ 不再 success=True
→ 根據狀態轉：
   1. full refresh
   2. cached_static_rerank
   3. skip blocker session
```

如果時間不足 full refresh：

```text
reason = artifact_refresh_required_but_insufficient_time
return to fuzzing
```

要同步更新單元測試：

```text
unitest/test_blocker_session_lifecycle.py
test_light_refresh_failure_is_not_reported_as_success
```

### 修正 3：用 retained target source set 判斷 full refresh 門檻

Full refresh 成功時記錄：

```text
last_full_refresh_target_source_set
last_full_refresh_target_count
```

下一個 session 前重新列出：

```text
current_target_source_set
```

只看真正保留下來的 generated target source：

```text
external/oss-fuzz/projects/<project>/llm_fuzzgen*.c
external/oss-fuzz/projects/<project>/llm_fuzzgen*.cc
external/oss-fuzz/projects/<project>/llm_fuzzgen*.cpp
```

計算：

```text
retained_new_targets_since_full_refresh
  = current_target_source_set - last_full_refresh_target_source_set
```

v1 不計 `removed_targets`，因為目前 solver 裡的刪除多半是 transient candidate cleanup；真正會影響後續 fuzzing 的主要是成功留下的新 target。

門檻：

```text
threshold = max(5, ceil(last_full_refresh_target_count * 0.10))
```

例：

```text
last_full_refresh_target_count = 80
threshold = max(5, 8) = 8
```

也就是累積 8 個 retained generated targets 後，才值得 full refresh。

### 修正 4：branch-growth ratio 只推動 coverage refresh，不直接 full refresh

語意：

```text
branch_growth_ratio 大
→ coverage 狀態有明顯變化
→ blocker hit count / ranking 需要更新
```

決策：

```text
if branch_growth_ratio >= threshold:
  if retained targets also reach full refresh threshold:
    full_refresh
  else if live inspector exists:
    light_refresh
  else:
    cached_static_rerank 或 coverage repair 後 rerank
```

不要讓 branch growth 單獨造成頻繁 full refresh。

### 修正 5：light refresh 只處理 full-refresh 已知 target set

Light refresh 只允許處理上次 full refresh 已知的 target pool。

如果 candidate 的 `best_target` 不在：

```text
last_full_refresh_target_source_set
```

代表這個 target 沒有完整 static context。

v1 最乾淨做法：

```text
跳過或降權該 candidate
標記 static_context_missing
等待下一次 full refresh 正式納入
```

這不代表新 target 沒用。新 target 仍然可以：

```text
被 fuzzing 跑
貢獻 coverage
幫助 branch growth
```

只是它暫時不應進入 LLM blocker solving。

### 修正 6：selector 先排除 attempted，再切 top_k

改成：

```text
aggregate / rank full candidate pool
→ live revalidation / coverage filter
→ 排除 state.attempted_blocker_keys
→ 再取 blocker_top_k
→ 再取 blocker_session_size
```

這可以避免 top-k window 被耗盡時，誤判整個 blocker pool 沒候選。

### 修正 7：cached_static_rerank 作為 fallback，但不要先假設便宜

當：

```text
retained_new_targets_since_full_refresh < threshold
live inspector/ missing
cached branch-blockers.json exists
```

可以考慮：

```text
cached_static_rerank
```

語意：

```text
沿用 cached branch-blockers.json / CFG / source context
讀最新 project.linecovreport
更新 hit count
排除已覆蓋 blocker
重新排序舊 blocker pool
```

但它依賴最新 coverage artifact。

若：

```text
textcov_reports/project.linecovreport 不存在
或 target-level *.linecovreport 不存在
```

就不能假裝 rerank 成功。要：

```text
先跑 coverage() repair
或 skip blocker session
```

這個模式應排在 Phase 3，等 Phase 1/2 修完後，再實測：

```text
coverage() elapsed
light refresh elapsed
full refresh elapsed
```

確認它真的划算。

## 建議狀態機

每次準備進 blocker session 時，先收集：

```text
artifacts_ready
live_inspector_exists
last_full_refresh_target_source_set
current_target_source_set
retained_new_targets_since_full_refresh
full_refresh_threshold
branch_growth_ratio
has_unattempted_candidate_in_cached_pool
remaining_time
full_refresh_required_time
```

決策順序：

```text
1. artifacts_ready == false
   → time enough: full_refresh
   → time not enough: skip

2. retained_new_targets_since_full_refresh >= full_refresh_threshold
   → time enough: full_refresh
   → time not enough: skip

3. branch_growth_ratio >= blocker_refresh_branch_growth_threshold
   → retained target also reaches threshold: full_refresh
   → live inspector exists: light_refresh
   → live inspector missing: cached_static_rerank / coverage repair

4. retained_new_targets_since_full_refresh < full_refresh_threshold
   → live inspector exists: light_refresh
   → live inspector missing: cached_static_rerank

5. selection:
   → aggregate/rank whole JSON
   → filter inactive / already covered / missing active target
   → exclude attempted
   → slice top_k/session_size

6. cached pool truly exhausted
   AND retained_new_targets_since_full_refresh > 0
   → time enough: full_refresh
   → time not enough: skip

7. cached pool exhausted
   AND retained_new_targets_since_full_refresh == 0
   → no blocker work this round, return fuzzing
```

注意：step 6 是 fallback，不是主要 full refresh 條件。不要讓 1~2 個 retained targets 也頻繁觸發 full refresh，除非舊 pool 真的完全耗盡且時間足夠。

## 建議實作順序

### Phase 1：止血

先修這三個，因為它們是 stale cache 的直接根因：

1. `remove_target()` 不再整包刪 `inspector/`、`textcov_reports/`、`report/`。
2. light refresh failure 不再回傳 success，並同步改測試。
3. selector 先排除 attempted，再切 `top_k`。

### Phase 2：正確 refresh threshold

1. Full refresh 成功後記 `last_full_refresh_target_source_set/count`。
2. session 開始前計算 `retained_new_targets_since_full_refresh`。
3. 使用：

```text
threshold = max(5, ceil(last_full_refresh_target_count * 0.10))
```

4. branch-growth ratio 只推動 coverage refresh / rerank，不單獨 full refresh。

### Phase 3：評估 cached_static_rerank

先量測：

```text
coverage()
light refresh
full refresh
```

再決定是否實作 cached static rerank。

## 驗證方式

### 單元測試

需要更新或新增：

```text
unitest/test_blocker_session_lifecycle.py
  - light refresh failure 不再 success

unitest/test_oss_fuzz_target_cleanup.py
  - remove_target 保留 inspector/
  - remove_target 只刪 target-specific textcov

unitest/test_global_blocker_selector.py
  - attempted blockers 在 top_k slice 前被排除
```

### 短跑驗證

跑 lcms 90 分鐘或 2 小時，觀察：

```text
第一次 session full refresh 成功
session cache 建立
solver remove failed target 後，live inspector/ 不應被整包刪掉
light refresh 失敗時不再 success=True
branch growth 大時至少觸發 coverage refresh/rerank
新 target 不到 threshold 時，不頻繁 full refresh
不同 session 不再無條件 fallback 到 session_001
```

### log 應該能看見的語意

理想上 log/event 要明確區分：

```text
refresh_mode = full_refresh
refresh_mode = light_refresh
refresh_mode = cached_static_rerank
refresh_skipped_reason = artifact_refresh_required_but_insufficient_time
static_context_reused = true/false
coverage_refreshed = true/false
blocker_pool_stale = true/false
retained_new_targets_since_full_refresh = N
```

## 最後整理

這套修法不是要讓 Introspector 每次都重建，而是把三件事拆清楚：

```text
coverage 變了
→ 更新 blocker 動態狀態

target set 真的變多了
→ full refresh 重建 static blocker world

solver transient target 失敗
→ 只清該 target，不摧毀整個 project-level artifact
```

這樣才能避免兩個極端：

```text
太保守：
  每次都 full refresh，時間與記憶體爆掉。

太寬鬆：
  永遠 fallback session_001，selector 長期 stale。
```

我們要的是中間狀態：

> 同一 session 穩定、跨 session coverage 更新、target 累積到門檻才重建 Introspector。

## 目前落地狀態

已實作：

```text
1. remove_target() 不再整包刪 inspector/、textcov_reports/、report/、report_target/
2. light refresh failure 不再回報 success
3. selector 先排除 attempted blockers，再切 top_k
4. full refresh 門檻改看 retained generated target source set
5. stale target report 不再讓整個 coverage context 失敗；selector 會跳過 missing target report 的 candidate
```

仍保留未做：

```text
cached_static_rerank
```

原因是它是否比 light refresh 划算還需要實測：

```text
coverage() elapsed
light refresh elapsed
full refresh elapsed
```
