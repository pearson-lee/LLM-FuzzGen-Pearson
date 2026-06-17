# Dependent 子系統：Input-Dependent Blocker 解決流程

## 1. 核心概念

**Blocker（阻塞點）** 是 library source code 中，目前 fuzz target 無法觸及的某個分支 side。

| 術語 | 說明 |
|------|------|
| Branch line | 條件分支所在行（if / switch） |
| Blocked side | 分支中無法被觸及的那一側 |
| Blocked-side line | Blocked side 第一個可執行行，作為「是否解鎖」的判斷依據 |
| Input-Dependent Blocker | 只要輸入正確就能觸及 → 不須修改 harness 結構，只需找到正確的輸入 |

---

## 2. 整體架構（兩路並進）

```
┌─────────────────────────────────────────────────────┐
│               Blocker Metadata (JSON)               │
│  project, target, branch_line, blocked_side_line,   │
│  triggering_input, source_code, call_chain ...       │
└────────────────────┬────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
 ┌─────────────────┐   ┌──────────────────┐
 │  Path A         │   │  Path B          │
 │  LLM Seed       │   │  SymCC Symbolic  │
 │  Generator      │   │  Execution       │
 └────────┬────────┘   └────────┬─────────┘
          │                     │
          │  stalled_at_branch  │
          └──────────►──────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  Coverage Evaluation │
          │  (replay_cov binary) │
          └──────────┬───────────┘
                     │
         ┌───────────┴──────────┐
         │                      │
    blocked_side            not reached
    hit_count > 0
         │
         ▼
   Blocker Resolved ✓
```

**設計邏輯**：Path A 讓 LLM 快速嘗試生成 seeds；若 LLM 能到 branch 但卡在符號約束，升級到 Path B 用符號執行突破。

---

## 3. Path A：LLM Seed Generator

### 目的
讓 LLM 產生一個 **Python 程式**（seed generator），由它生成多個 seed 家族，嘗試觸及 blocked side。LLM 每輪根據上輪的 coverage 回饋調整策略，最多迭代 3 輪。

### 流程圖

```
Blocker Metadata
      │
      ▼
 ┌─────────────────────────────────────────────────┐
 │ Prompt: blocker_seed_generator_template          │
 │  - 原始 fuzz target 程式碼                        │
 │  - Branch / blocked-side 周圍的 source window    │
 │  - CFG call chain                               │
 │  - 上一輪的 generator.py 與 coverage 回饋        │
 │    （若非第一輪）                                 │
 └──────────────────┬──────────────────────────────┘
                    │ LLM 回傳 JSON
                    ▼
           generator.py 執行後
     產生 Seed 家族（F01_xxx, F02_xxx ...）
                    │
                    ▼
        用 coverage binary 執行所有 seeds
        取得 branch_line / blocked_side_line 的 hit count
                    │
      ┌─────────────┴──────────────────────────┐
      │                                        │
 hit blocked_side                       hit branch only
      │                                        │
      ▼                                        ▼
solved → 停止                stalled_at_branch → 交給 Path B
                             OR coverage/family_progress → 再迭代
```

### Seed 家族（Family）設計

LLM 將生成的 seeds 按結構策略分組，例如：
- `F01_structure_base` → 基本結構測試
- `F02_boundary_flags` → 邊界條件
- `F03_type_variants` → 類型變化

每個家族各有獨立的 representative seeds 被評估，讓系統追蹤「哪種設計方向有效」。

### Family Signal Score

`family_signal_score` 量化最佳家族的「接近 blocker 程度」：

```
score = rank_bucket                  × 1,000,000
      + max_blocked_side_hit_count   × 10,000
      + max_branch_hit_count         × 100
      + branch_reach_ratio           × 100
```

**`rank_bucket`**（程式自動計算，非 LLM 評定）：

```python
if blocked_side_reached_count > 0:  →  rank_bucket = 2   # 最佳：到達 blocked side
elif branch_reached_count > 0:      →  rank_bucket = 1   # 到達 branch
else:                               →  rank_bucket = 0   # 完全無法到 branch
```

**`branch_reach_ratio`**：該家族 representative seeds 中，能到 branch 的比例（binary：有/無）。

### 迭代狀態判斷

每輪執行後，系統比較兩個層次的指標來決定下一步：

**① `coverage_progress`（aggregate 層）**：比較本輪 baseline（現有 corpus）vs. post-merge（+新 seeds）的整體 hit count。只要 delta > 0 就觸發。

**② `family_progress`（家族層）**：比較這一輪 vs. 上一輪的 family_signal_score。分數提升即觸發。

> **為何兩者可能不一致？**
> `coverage_progress` 是本輪 aggregate 視角（新 seeds 有沒有讓整體 corpus 的 hit count 增加），
> `family_progress` 是跨輪精細視角（家族設計方向有沒有改善）。
>
> 典型情境：baseline corpus 已有 seeds 能到 branch（hit count 已非零）。新 seeds 也能到 branch（家族 ratio 提升），但 aggregate delta 接近 0，coverage_progress 不觸發。此時 family_progress 作為備用信號，確認 LLM 仍在往正確方向走。

| 狀態 | 觸發條件 | 意義 | 下一步 |
|------|----------|------|--------|
| `already_covered_in_baseline` | 合併前 blocked_side_line 已被執行 | Blocker 在生成 seeds 之前就已解決（可能被其他 target 覆蓋） | 停止，標記已解決 |
| `solved` | 合併後 blocked_side_line 首次被執行 | 本批 seeds 成功觸及 blocked side | 停止，標記已解決 |
| `coverage_progress` | branch 或 blocked_side 的 aggregate hit count 增加 | Seeds 正往正確方向逼近，但尚未完全解決 | 繼續迭代 |
| `family_progress` | family_signal_score 提升，但 aggregate hit count 未增加 | 家族設計方向改善（更多 seeds 對準 branch），但尚未反映在整體數字 | 繼續迭代 |
| `stalled_at_branch` | 能到 branch 但無法到 blocked_side，且無上述進展 | 卡在符號約束，LLM 無法突破 | 升級至 SymCC |
| `no_branch_signal` | 沒有任何家族能到 branch | Seeds 完全偏離目標路徑 | 繼續迭代或放棄 |
| `no_progress` | 上述條件皆不符 | 既無 coverage 也無家族進展 | 繼續迭代 |

### 輸出目錄結構

```
generated_generators/{project}_{blocker}_{timestamp}/
  iter_01/
    generator.py               ← LLM 生成的 Python 程式
    materialized_by_generator/ ← 實際 seed 檔案（依家族命名）
    staging_metadata.json      ← 去重統計、家族 seed 數量
    aggregate.linecovreport    ← 整體 corpus coverage 結果
    iteration_summary.json     ← 各家族表現、診斷、下一步建議
  iter_02/
    ...
```

---

## 4. Path B 詳細流程（三階段遞進）

Path B 由 `input_dependent_solver.py` 統一協調，採**遞進策略**：先嘗試最省成本的方案，失敗才升級到下一階段。

```
來自 Path A 的 seeds（能到 branch line）
      │
      ▼
 ┌──────────────────────────────────────────────┐
 │ Stage B-1：SymCC Probe（原始 target 快速試跑） │
 │  run_symcc_blocker.py --fuzz-target 原始檔    │
 └─────────────────┬────────────────────────────┘
                   │
          ┌────────┴────────┐
         成功              失敗
          │                 │
          ▼                 ▼
       Done         ┌──────────────────────────────────────────┐
                    │ Stage B-2：LLM Harness Generator          │
                    │  input_dependent_harness_generator.py     │
                    │  → LLM 生成 SymCC 友善 harness            │
                    │  → Validation Gate（語法 + OSS-Fuzz build）│
                    └────────────────┬─────────────────────────┘
                                     │
                            ┌────────┴────────┐
                          失敗              成功（取得 harness）
                            │                 │
                            ▼                 ▼ （可選）
                          Abort        Stage B-3a：libFuzzer Focused Pass
                                         用 libFuzzer 短跑（N 秒）
                                         讓簡化 harness 豐富 seed corpus
                                              │
                                              ▼
                                       Stage B-3b：SymCC on Generated Harness
                                         run_symcc_blocker.py --fuzz-target harness
                                              │
                                    ┌─────────┴─────────┐
                                   成功               失敗
                                    │                   │
                                    ▼                   ▼
                                 Done              Pipeline Failed
```

### Stage B-1：SymCC Probe（原始 target）

**目的**：先直接用原始 fuzz target 跑 SymCC，不需要任何 LLM 生成。若成功即可省去 harness 生成的成本。

- 使用來自 Path A 的 `stalled_at_branch` seeds 作為初始輸入
- 呼叫 `run_symcc_blocker.py`（同 Stage B-3b，但 target 是原始檔案）
- 成功條件：`blocked_side_line` hit count > 0

**常見失敗原因**：原始 fuzz target 有大量 libFuzzer 基礎設施（fuzzing infrastructure code），SymCC 要追蹤大量無關的符號約束，效率低下。

---

## 5. LLM Harness Generator（Stage B-2）

### 目的
原始 target 無法讓 SymCC 有效探索時，LLM 產生一個**精簡版 harness**，只保留觸及 blocker 所需的最少邏輯，降低 symbolic noise，讓 SymCC 更有效率。

### 流程圖

```
Blocker Metadata
      │
      ▼
 Prompt: symcc_harness_generator_template
  - 原始 fuzz target 程式碼（最多 16KB）
  - 相關 source / header 摘錄（最多 18KB）
  - Branch 與 blocked-side 周圍的程式碼視窗（各 5KB）
  - Runtime blocker segment（實際觸發 blocker 的 call stack，7KB）
  - CFG call chain（函數呼叫路徑）
      │
      ▼
  LLM 回傳 JSON：
    harness_code      ← C/C++ 原始碼（實作 LLVMFuzzerTestOneInput）
    harness_filename  ← 建議檔名
    analysis_summary  ← 設計說明
      │
      ▼
  Sanitization（修正 LLM 可能產生的 Docker 絕對路徑）
  "/src/libpcap/pcap/pcap.h" → <pcap/pcap.h>
      │
      ▼
  Validation Gate：
    ① clang -fsyntax-only（語法快速檢查）
    ② OSS-Fuzz native build（在 Docker 容器內完整編譯確認）
      │
   ┌──┴──┐
  Pass  Fail → LLM Repair（最多 2 次）
   │
  build_context.json（記錄 include dirs、defines、sources，交給 SymCC solver）
```

### Include 路徑正規化（OSS-Fuzz Docker vs. 本機 SymCC）

OSS-Fuzz 在 Docker 容器內編譯（source 在 `/src/libpcap/` 等），但 SymCC 需要在**本機**編譯，這些路徑不存在。

`symcc_blocker_solver.py` 在本機編譯前，對所有 source files 執行 `normalize_source_includes()`：

```
對每個 #include "…/…" 路徑：
  逐層剝除前綴 → 找出在本機 -I include_dir 下實際存在的最短後綴
  改寫為 <angle-bracket> 形式

例：#include "/src/libpcap/pcap/pcap.h"
  嘗試 "src/libpcap/pcap/pcap.h" → 不存在
  嘗試 "libpcap/pcap/pcap.h"     → 不存在
  嘗試 "pcap/pcap.h"             → 在 /home/.../include/pcap/pcap.h 存在 ✓
  改寫為：#include <pcap/pcap.h>

../相對路徑維持不動（不處理）
```

正規化後的 source files 寫出到 `work_dir/normalized_sources/`，供 SymCC / coverage 編譯使用。

> LLM 生成 harness 時已做過一次 sanitization（轉換 Docker 路徑），但 project 的原始 source files 本身也需同樣正規化，才能在本機正確連結。

---

## 6. SymCC Symbolic Execution（Stage B-1 / B-3b 共用機制）

`run_symcc_blocker.py` + `symcc_blocker_solver.py` 負責實際的符號執行，Stage B-1（probe）和 Stage B-3b（generated harness）都呼叫相同的機制，只有傳入的 `--fuzz-target` 不同。

### libFuzzer Focused Pass（Stage B-3a）

**觸發條件**：`libfuzzer_pass_seconds > 0`（**預設值 = 60 秒，預設開啟**）且 Stage B-2 成功產出 `native_build_target_name`。實際上只要 Stage B-2 成功，Stage B-3a 幾乎必然執行。

**為何這樣設計？**

Stage B-2 的 Validation Gate 在 OSS-Fuzz Docker 內做 native build 時，**ASAN binary 就已經編好**，Stage B-3a 直接重用這顆 binary 跑 libFuzzer（`build_fuzzer=False`），幾乎沒有額外 overhead。

- libFuzzer 跑得**快**，60 秒內就能探索簡化 harness 附近的輸入空間
- SymCC 能**解符號約束**但很慢，從豐富的起始 corpus 出發效率更高
- 兩者互補：libFuzzer 先「廣撒網」，SymCC 再「精確突破」

**流程**：
1. 把來自 Path A 的 seeds 複製進 OSS-Fuzz corpus 目錄
2. 在 OSS-Fuzz 容器內對 LLM harness 執行 libFuzzer N 秒
3. 把 libFuzzer 探索出的新 seeds 合併進 seed list
4. 整包傳給 Stage B-3b

此步驟為 best-effort：失敗不會中止 pipeline，Stage B-3b 仍使用原本的 seeds。

> **注意**：這與 `symcc_blocker_solver.py` 內部的「OSS-Fuzz corpus 補充（seeds < 4）」是完全不同的兩層機制，觸發條件與時機都不同。

### 兩個 Binary

同一份 **replay harness**（輕量 C/C++ driver：讀入 seed bytes → 呼叫 `LLVMFuzzerTestOneInput`）用不同 compiler 各編一次：

| Binary | Compiler | 功能 |
|--------|---------|------|
| `replay_symcc` | SymCC（`symcc` / `sym++`） | **探索**：執行時自動追蹤符號約束，推導出滿足不同分支條件的新 seeds，輸出到 `SYMCC_OUTPUT_DIR` |
| `replay_cov` | clang + `-fprofile-instr-generate -fcoverage-mapping` | **判斷**：執行時產生 `.profraw`，用 `llvm-profdata merge` + `llvm-cov show` 查看各行 hit count |

### 各階段使用的 Binary

```
整個 Path B 流程的 binary 使用時機：

① 評估 baseline seeds（初始 seeds 是否已解決 blocker？）
   → replay_cov ✓

② OSS-Fuzz corpus 補充（seeds < 4 時，篩選能到 branch 的 seeds）
   → replay_cov ✓

③ SymCC 探索（從 seed 推導新 seeds）
   → replay_symcc ✓

④ 評估最終 corpus（SymCC 探索完後，確認是否有 seed 解決 blocker）
   → replay_cov ✓
```

`replay_cov` 負責所有「評估（判斷）」，`replay_symcc` 只在「探索（推導新輸入）」步驟使用。

### OSS-Fuzz Corpus 補充（initial seeds 不足時）

**「initial seeds」的定義**：`symcc_blocker_solver.py` 啟動時透過 `--seed` / `--seed-dir` 傳入的 seeds。
- Stage B-1（probe）：Path A handoff 的 seeds（能到 branch 的 seeds）
- Stage B-3b（harness）：Stage B-3a libFuzzer pass 輸出的 enriched seeds + 原始 Path A seeds

**觸發條件**：`len(initial_seeds) < 4`，代表能到 branch 的起始 seeds 太少，SymCC 探索起點不足。

**補充流程**：

```
OSS-Fuzz corpus 目錄（build_corpus_dir/{project}/{target}，libFuzzer 長期累積）
      │
      ▼
  篩選條件：檔名為 40 字元 hex（= libFuzzer 發現的原生二進制 seed）
  排除原因：LLM 生成的 .txt / .bpf seeds 格式未必符合 target 期望的輸入格式
      │
      ▼
  按檔案大小排序（小 → 大），最多取 32 個候選
      │
      ▼
  逐一用 replay_cov 評估：branch_hit_count > 0？
  （即這個 seed 能不能觸及 branch line）
      │
      ▼
  只保留能到 branch 的 seeds
  補充數量上限：4 - len(initial_seeds) 個
  （例如原本 2 個 seeds → 最多再補 2 個）
```

### SymCC 符號探索（Generation Loop）

**參數**：
- 呼叫自 `input_dependent_solver.py`（即 Stage B-1 / B-3b）：**最多 3 輪**，corpus 上限 60 個
- 單獨執行 `symcc_blocker_solver.py`：最多 5 輪，corpus 上限 200 個

**每輪（generation）做什麼**：

```
Generation N 開始
      │
  frontier = 本輪要探索的 seeds（第 1 輪 = 所有 initial seeds + 補充 seeds）
      │
      ▼
  對 frontier 中的每個 seed：
    清空 SYMCC_OUTPUT_DIR
    執行 replay_symcc（SymCC 在此 seed 上做符號執行）
    SymCC 自動生成滿足不同分支條件的新輸入 → 寫入 SYMCC_OUTPUT_DIR
    把輸出的新 seeds SHA256 去重後加入 corpus
    把本輪新增的 seeds 記為 next_frontier
      │
      ▼
  frontier = next_frontier（下一輪只探索本輪新產生的 seeds）
      │
      ▼
  停止條件（滿足任一即停）：
    ① next_frontier 為空（這輪沒有任何新 seed 產生）
    ② 已處理 seed 總數 ≥ 上限（60 / 200）
    ③ wall-clock 預算耗盡（預設 300 秒）
    ④ 已達最大輪數（3 / 5 輪）
```

**為什麼只探索 next_frontier 而不是整個 corpus？**

每輪只探索「這輪新生成的 seeds」，是因為舊 seeds 在上一輪已經被 SymCC 探索過。讓 SymCC 只追蹤新發現的路徑分支，避免重複探索同樣的符號約束。

```
最後：replay_cov 評估整個 final corpus
      │
      ▼
  llvm-profdata merge + llvm-cov show
  → 查看 blocked_side_line hit count
      │
   ┌──┴──┐
  >0    =0
   │      │
  解決   失敗（exit code 1）
```

---

## 8. 完整整合流程（End-to-End）

```
[Blocker 選擇]
  global_blocker_selector.py
  → 從所有 fuzz targets 的 coverage 中，找出尚未觸及的 input-dependent blockers

[Seed 搜尋]
  find_blocker_seeds_by_coverage.py
  → 從現有 corpus 中找出能觸及 branch line 的 seeds（作為初始輸入）

[Path A: LLM Seed Generator]（最多 3 輪迭代）
  input_dependent_seed_generator.py
  → LLM 生成 generator.py → 產生 seed 家族 → coverage 評估 → 根據狀態決定下一步
  → 若 stalled_at_branch：將能到 branch 的 seeds 移交給 Path B

[Path B: SymCC Symbolic Execution]（由 input_dependent_solver.py 協調）

  Stage B-1：SymCC Probe（原始 target 快速試跑）
    初始 seeds = LLM generator 推薦的 stalled seeds + 原始 triggering input
    → 不需 LLM 生成，成本最低；若成功即結束
    → 呼叫 run_symcc_blocker.py（同 B-3b 機制，但 target 是原始 fuzz target）
    → 失敗（原始 target 有過多 fuzzing infrastructure，SymCC 符號噪音太大）→ 進入 Stage B-2

  Stage B-2：LLM Harness Generator
    input_dependent_harness_generator.py
    → LLM 生成精簡版 SymCC 友善 harness（降低 symbolic noise）
    → Sanitization：修正 LLM 產生的 Docker 絕對路徑（"/src/..." → <angle-bracket>）
    → Validation Gate（在 OSS-Fuzz Docker 容器內）：
        ① OSS-Fuzz native build（主要關卡）→ 通過即成功，同時產出 ASAN binary
        ② 若失敗 → 補跑 clang -fsyntax-only 取得精確錯誤訊息 → LLM Repair（最多 2 次）
    → 驗證失敗 → Pipeline 直接中止（不 fallback 回原始 target）

  Stage B-3a：libFuzzer Focused Pass（預設開啟，60 秒）
    初始 seeds = 同一份 symcc_seeds（LLM generator 推薦 + 原始 triggering）
    條件：--libfuzzer-pass-seconds > 0（CLI 參數，預設 60；設為 0 可關閉）且 Stage B-2 成功
    → 重用 Stage B-2 Validation Gate 已編好的 ASAN binary（不需重新編譯）
    → libFuzzer 在 OSS-Fuzz 容器內短跑 N 秒，快速探索簡化 harness 附近路徑
    → 把 libFuzzer 新發現的 seeds 合併進 seed list，整包傳給 Stage B-3b
    → best-effort，失敗不中止 pipeline

  Stage B-3b：SymCC on Generated Harness
    初始 seeds = symcc_seeds + Stage B-3a libFuzzer 新發現的 seeds
    → run_symcc_blocker.py --fuzz-target LLM_harness --seed <enriched_seeds>
    → symcc_blocker_solver.py 執行本機編譯流程：
        ① 正規化 include 路徑（Docker 路徑在本機不存在，需轉換為 <angle-bracket> 形式）
        ② 一次性 build phase：
           - 用 symcc/sym++ 編譯 → replay_symcc（SymCC 探索用，推導新 seeds）
           - 用 clang 編譯     → replay_cov  （coverage 評估用，量測 hit count）
    → replay_cov 評估 baseline seeds（是否已解決？）
    → OSS-Fuzz corpus 補充（initial seeds < 4 時，用 replay_cov 篩選能到 branch 的 seeds）
    → SymCC 探索（最多 3 輪，corpus 上限 60，用 replay_symcc）
    → replay_cov 評估最終 corpus → blocked_side_line hit_count > 0？

[結果判定]
  blocked_side_line hit_count > 0 → blocker 標記為 "resolved"，後續排程跳過
  blocked_side_line hit_count = 0 → 失敗，記錄各 stage 結果
```

---

## 9. 關鍵檔案對照表

| 檔案 | 職責 |
|------|------|
| `input_dependent_solver.py` | **Path B 總協調者**：依序呼叫 SymCC probe → LLM harness → libFuzzer pass → SymCC harness |
| `input_dependent_seed_generator.py` | Path A：LLM 生成 Python seed generator，迭代執行，管理家族評估與狀態判斷 |
| `input_dependent_harness_generator.py` | Stage B-2：LLM 生成 SymCC 友善 C/C++ harness，含 Validation Gate 與 LLM Repair |
| `run_symcc_blocker.py` | Stage B-1 / B-3b 共用：解析 metadata、準備 build context、呼叫 symcc_blocker_solver |
| `symcc_blocker_solver.py` | 核心執行引擎：include 正規化、編譯 replay_symcc + replay_cov、SymCC 探索、coverage 評估 |
| `blocker_seed_generator_template` | LLM prompt：指引生成 seed generator Python 程式（含家族設計、coverage 回饋格式） |
| `symcc_harness_generator_template` | LLM prompt：指引生成 SymCC 友善 harness（含 include 策略、fidelity 需求） |
| `build_context.py` | 編譯上下文資料結構（include dirs、defines、sources 列表） |
| `global_blocker_selector.py` | 跨 target 的 blocker 排名、狀態追蹤（resolved / stalled / unreached） |
| `find_blocker_seeds_by_coverage.py` | 從現有 corpus 篩選能觸及 branch 的初始 seeds |
