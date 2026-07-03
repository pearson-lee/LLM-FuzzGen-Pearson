# 系統成效檢視：experiments/20260702_224826_run_all_fuzzer (lcms)

> 日期：2026-07-03 ｜ 資料來源：`events.jsonl`(354)、`blocker_attempts.jsonl`(75 rows)、`run.log`(8.4MB)、`blockers/`、`symcc/`

## Run 設定
```
python3 main.py run_all_fuzzer lcms --budget-mode fuzzing-cpu --run-fuzzers 86400 \
  --coverage-interval 3600 --fuzz-targets-parallel 4 --use-blocker \
  --coverage-stagnation-window 1 --coverage-stagnation-threshold 0.05 \
  --target-exposure-min-seconds 30 --generated-target-priority-seconds 300 \
  --blocker-session-size 5 --blocker-top-k 10 --blocker-max-iterations 2 \
  --blocker-fuzz-seconds 15 --blocker-session-refresh-mode reuse_session_artifacts \
  --blocker-artifact-report-seconds 30 --blocker-refresh-branch-growth-threshold 0.05 \
  --blocker-refresh-branch-growth-floor 50 --llm vertexai --model gemini-2.5-pro
```
- 純 fuzzing 86400s、4 targets 平行、`enable_blocker_triage=false`
- `run_finished.success=true`，`total_seconds=68524`

---

## 1. Pipeline 是否有異常 crash

**Orchestration pipeline 本身沒有異常崩潰**：`run.log` Python Traceback = 0 筆，`run_finished.success=true`。

但**生成的 fuzz target 層面極不穩定**，會侵蝕 fuzzing 預算：

| 類型 | 數量 | 影響 |
|---|---|---|
| crash- 單元 | 70 | 生成 target 在 fuzzing 中崩潰 |
| oom- 單元 | 8 | 記憶體耗盡 |
| `==ABORTING` | 43 | libFuzzer 遇 crash 直接中止該 target session（提早結束 → 浪費 CPU 預算）|
| build 失敗 | 19 | 浪費一次 LLM 生成 |
| run 失敗 | 23 | 同上 |

崩潰簽章（多屬 harness 誤用 API，非 orchestration bug）：
- `heap-buffer-overflow cmsnamed.c:277 encodeUTF8` × 42（跨多個 harness 反覆出現；可能 harness 餵畸形 MLU，亦可能為真 lcms bug）
- `heap-use-after-free cmslut.c:1541/1436`（`cmsPipelineInsertStage`/`cmsPipelineFree`）× 8 → harness 生命週期誤用
- `SEGV` × 4、`stack-overflow cmserr.c:518` × 2 → 與 LLM 生成的 `longjmp`/自訂 error handler 繞過 assert 手法有關
- 少數崩潰位於生成的 harness `.c` 檔本身

> 本次 `--analyze-crashes` 未開，未做 crash 去重/真偽分類。無論真偽，`==ABORTING` 都會讓該 target fuzzing 提早收工，是覆蓋率沒衝高的旁因。

---

## 2. Input Independent / Dependent 統計

Blocker 嘗試總數 = **46 次**（`blocker_pipeline_started`），涵蓋 **31 個 unique 函式**。

### Input Independent
| 指標 | 值 |
|---|---|
| 嘗試 | 28 |
| **解出**（`blocked_side_newly_reached=True`）| **20** ✅ |
| 失敗 | 8（卡在 `dedicated_generation`）|
| 成功管道 | 17× `reference_guided_generation`、3× `dedicated_generation` |

### Input Dependent
| 指標 | 值 |
|---|---|
| 嘗試 | 18（僅 **4 個** unique 函式）|
| **解出** | **0** ❌ |
| 用 **LLM** 解 | 18 次全走 `llm_seed_generator`，成功 0（17 次以 `llm_timeout` ~900s 收場 → `attempt_result=llm_error`）|
| 用 **SymCC** 解 | 整場 run **只觸發 1 次**（`cmsDetectDestinationBlackPoint`），失敗於 `symcc_harness_fidelity_preflight_replan_02`，成功 0 |

Dependent 重試分布（浪費預算）：
- `cmsIT8GetData` ×10、`cmsDetectDestinationBlackPoint` ×6、`_cmsReadDevicelinkLUT` ×1、`cmsIT8GetPropertyDbl` ×1 → 皆逾時，無去重/退避

失敗種類（`blockers/**/summary.json`）：`llm_timeout` ×34、`harness_seed_incompatible` ×10、`strategy_replan_required` ×6、`compile_failed` ×3、`coverage_no_blocked_side` ×2、`runtime_sanity_failed` ×2

---

## 3. 為何覆蓋率沒有顯著提升

| | branch | line | function |
|---|---|---|---|
| 我的 | 55.99% (5130/9162) | 69.87% (13923/19926) | 81.37% (961/1181) |
| 學長 | 54.62% (5004) | 68.11% (13571) | — |
| **差距** | **+126 br (+1.37pp)** | **+352 ln (+1.76pp)** | — |

Growth summary（blocker 前→後）：branch 52.84→55.99（+289 br）、line 65.54→69.87（+863 ln）、func 76.55→81.37（+57）。

### 根因（依影響力排序）

1. **Input-dependent 解題完全歸零，且 SymCC 被 LLM 逾時「短路」掉。【最關鍵】**
   `input_dependent_solver.py:717` 的 `llm_seed_stage_timeout_sec` 預設 **900s**；gemini-2.5-pro 幾乎每個 dependent blocker 都跑到逾時（`pipeline_elapsed≈984s`）。而 `input_dependent_solver.py:746-750` 的邏輯是 **LLM 階段一旦 `llm_timeout` 就直接 `return`，不交棒給 SymCC**。
   → 真正能破 input-dependent 條件的 SymCC，整場 19 小時只跑 1 次。系統核心賣點（input-dependent + 符號執行）在本次 run 幾乎沒運作，深層受輸入控制的 branch 全數未觸及，覆蓋率天花板被鎖死。

2. **無解 dependent blocker 反覆重試、浪費預算。**
   `cmsIT8GetData`(10)、`cmsDetectDestinationBlackPoint`(6) 各每次 ~15 分鐘逾時，約 14 次 ≈ 3.5 小時 LLM 時間打水漂，缺少去重/退避（back-off）。

3. **所有覆蓋率增益都來自 Input Independent 的 `reference_guided_generation`。**
   屬較淺增益；差異化的 dependent 貢獻為 0，因此只能小贏 baseline ~1.4pp。

4. **生成 target 不穩定吃掉 fuzzing 預算**（見第 1 節）：42 個 build/run 失敗 + 43 次 ABORTING，讓純 86400s 有效 fuzzing 時間縮水。

### 對「E2E 強制 86400 恐怕也不會好」的評估
大概率成立。目前設計下 dependent+SymCC 這條線近乎零產出，而它正是要拉開差距的關鍵；把系統時間也算進 86400 只會壓縮 fuzzing 與 blocker 的有效時間。**先修好「LLM 逾時短路 SymCC」，才是拉開 baseline 的槓桿點。**

---

## 建議後續（依 CP 值排序）

- [ ] **[最高槓桿] 解開 SymCC 短路**：讓 `llm_timeout` 也能交棒 SymCC，或大幅調低 `llm_seed_stage_timeout_sec` 把時間留給 SymCC。位置 `blocker_process/dependent/input_dependent_solver.py:746-750`。
- [ ] **dependent blocker 去重/退避**：同一函式連續失敗後降權或跳過，避免 `cmsIT8GetData` 被試 10 次。
- [ ] **診斷 seed 生成逾時**：釐清 gemini-2.5-pro 是 API 延遲還是 iteration/seed 預算設太大（`blocker-max-iterations`、seed budget）。
- [ ] **穩定生成 target**：對反覆崩潰（encodeUTF8）與 build 失敗做過濾，減少 fuzzing 預算流失。

## 重現驗證
- `blocker_attempts.jsonl`：依 `event=blocker_pipeline_result` 分組統計 `dependency_result` / `attempt_result` / `pipeline_success` / `pipeline_methods`。
- `blockers/**/summary.json`：統計 `failure_kind`（確認 `llm_timeout` 主導）。
- `run.log`：`grep -c 'crash-'`、`'failed to build'`、`'ABORTING'`。
