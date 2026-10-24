# Input Dependent pipeline：SymCC 從未執行與 fidelity preflight 修復（2026-10-18，10/19 追加）

## 1. 問題概述

tomlplusplus 三次實驗中，被分類為 Input Dependent 的 blocker 合計只成功 1/14，失敗全部停在 `symcc_harness_generation` 或 `symcc_harness_fidelity_preflight`。以 `date_time.hpp:416`（GT 中已有可重現 POC 的 True Positive）追查，發現四個疊加的問題，其中前三個代表 **SymCC 在這台機器上從未真正執行過**。

## 2. 四個問題與修正

### 問題一：PATH 上沒有 `clang`（環境）

- `symcc_blocker_solver.py` 預設呼叫不帶版號的 `clang`/`clang++`；README 只安裝 `clang-14`，不會建立 `/usr/bin/clang`。
- 結果：`FileNotFoundError: Required tool not found: clang`，但被記錄成 `failure_kind: symcc_no_new_outputs`。
- 影響：`20260912`、`20260920`、`20261006`、`20261010`、`20261012` 五次實驗的所有 SymCC probe 與 preflight（9 次 preflight、15 次 probe）都沒有執行。
- 修正：`sudo apt install clang`（Ubuntu 22.04 的 meta 套件，指向 clang 14.0.0，與 README 版本表一致）。README 尚未補上這一步。

### 問題二：header 被當成編譯單元（`build_context.py`）

- `reconstruct_build_context()` 總是把 branch 所在檔案列為 required compilation unit。header-only 專案的 `date_time.hpp` 被直接編譯，產出 precompiled header（檔頭 `CPCH`），link 時 `file format not recognized`。
- 修正：`BuildContext.compilation_sources` 略過 `HEADER_EXTENSIONS`（此常數原本已定義但未使用）。header 仍透過 `#include` 編入。

### 問題三：SymCC runtime 無限遞迴（`symcc_blocker_solver.py`）

- solver 對所有 C++ target 強制 `SYMCC_REGULAR_LIBCXX=yes`。target 中被 instrument 的 libstdc++ inline 函式（例如 `std::_Sp_counted_base::_M_release`）取代了 QSYM runtime 自己使用的版本，runtime 每做一次符號運算又觸發一次，最後 stack overflow（gdb 可見超過 43,000 層）。每次 SymCC 執行都以 `-11` 結束，只產生 2–3 個 input。
- README 與 docs 都把 regular 模式描述成「只是 STL 內部會被 concretize」，沒有提到會崩潰；`docs/integration_blocker_system.md` 建議的模式切換也未實作。
- 修正：新增 `select_cxx_stdlib_mode()`，在編譯前決定 C++ 標準函式庫：

  | 條件 | 模式 |
  |---|---|
  | C target | `none` |
  | 有預先建好的 SymCC library archive（以 libstdc++ 建置） | `regular`，避免混用兩套標準函式庫 |
  | 找不到 `libcxx_symcc_install`（缺 `__config` 或 `libc++.a`） | `regular` |
  | 其他 C++ target | `stl`：`SYMCC_LIBCXX_PATH=libcxx_symcc_install` |

  新增 CLI 參數 `--libcxx-path`；log 會輸出 `[info] SymCC C++ stdlib mode: ...`。
- 驗證：416 的 SymCC probe 由「4 次執行全部 segfault、3 個 input」變成「正常結束、418 個 input、200 次評估」。

### 問題四：fidelity preflight 只接受原 harness 格式的 seed（pipeline 設計）

- preflight 拿原 target 的 corpus seed 去跑 LLM 產生的新 harness，要求至少一個走到 branch。原 harness 用 FuzzedDataProvider 拆 bytes，新 harness 直接把 input 當成 TOML 文字，格式不同，必定失敗（`harness_seed_incompatible`）。
- 手動驗證：新 harness 用 `dt1 = 2024-01-01T10:00:00` / `dt2 = 2024-01-01T12:00:00` 就能走到第 417 行，preflight 淘汰的是正確的 harness。
- 修正：
  - `prompts/templates/symcc_harness_generator_template`：輸出 JSON 新增 `fidelity_seeds`（1–3 個，`description`/`encoding: text|hex`/`content`），要求用新 harness 自己的 input 格式撰寫。
  - `input_dependent_harness_generator.py`：`write_harness_native_seeds()` 寫成 `harness_native_seeds/native_seed_XX.bin`；格式錯誤只跳過並記錄在 `harness_native_seed_problems`。
  - `input_dependent_solver.py`：preflight 的候選 seed 為「原 seed + 新格式 seed」；libFuzzer focused pass 與新 harness 上的 SymCC 改以「新格式 seed 優先」作為起始 seed。

## 3. 416 重跑結果（`experiments/manual_replay_416_20261018_202606`）

| 階段 | 結果 |
|---|---|
| LLM seed generator（原 harness） | 失敗 |
| SymCC probe（原 harness） | 正常執行，未到 417 |
| SymCC harness 產生 | 成功，附 3 個 `fidelity_seeds` |
| fidelity preflight | 通過（`native_seed_01`：branch 1、blocked side 1） |
| 新 harness 上的 SymCC | 成功，`baseline_already_reached`，評估 0 個候選 |

這次成功來自 LLM 撰寫的新格式 seed，SymCC 沒有參與；但 `success_stage` 記為 `symcc_generated_harness`，統計 SymCC 解題率時需要另外區分。

## 4. 10/19 追加：`.inl` 也被當成編譯單元

### 發現經過

套用上述修正後的第一次完整實驗 `20261018_205808` 中，唯一被分類為 Dependent 的 `at_path`（`path.inl:494` → 505）第一次通過 fidelity preflight（新格式 seed `a.c`），但 SymCC probe 與新 harness 上的 SymCC 都在建置時失敗：

```
ValueError: Unsupported source extension for .../normalized_sources/02dd5c6ac2_path.inl
```

與問題二同源：toml++ 的實作放在 `*.inl`，透過 `#include` 引入，但 `HEADER_EXTENSIONS` 只有 `.h/.hpp/.hh/.hxx/.h++`，`path.inl` 仍被列為編譯來源，`path_language()` 不認得 `.inl` 而丟出例外。這次建置崩潰同樣被記成 `symcc_no_new_outputs`。

### 修正

- `build_context.py`：`HEADER_EXTENSIONS` 加入 `.inl`、`.ipp`、`.tpp`、`.tcc`、`.inc`（只會被 `#include` 的實作片段）。
- `unitest/test_symcc_harness_fidelity.py`：`test_compilation_sources_skip_headers` 加入 `path.inl`。

### 494 離線重跑

| 重跑 | 結果 |
|---|---|
| `manual_replay_494_20261019_130312` | SymCC probe 正常建置執行（4 次 SymCC、1023 個 input、200 次評估、42 個走到 494、0 個走到 505）；harness 產生 `llm_timeout`（300 秒），未走到後續階段 |
| `manual_replay_494_20261019_133047` | **整條 pipeline 第一次完整走完**：harness 產生成功 → preflight 通過 → libFuzzer → 新 harness 上的 SymCC 正常執行（99 次 SymCC、2737 個 input、200 次評估、9 個走到 494、0 個走到 505） |

505 沒有被走到是正確結果：GT 案例 `tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494` 已判定為 Input Independent / Internal Invariant Guard（`path_component_type` 是只有 `key`、`array_index` 的封閉 enum，parser 不會產生第三種類型）。494 在 1006、1010、1012、1018 四次實驗都被分類器判為 Dependent，是分類器 FP（見 `backlog/TBD.md` H2）。

## 5. 10/19 追加觀察

### Vertex AI 單次請求上限 90 秒

- `llm_interface/llm_client.py:126` 設定 `{"timeout": 90.0}`。seed generator log 連續出現 `DeadlineExceeded: 504 Deadline expired before operation could complete.`，重試直到 stage 上限（seed generator 900 秒、harness 產生 300 秒）後記為 `llm_timeout`。
- 1010、1012、1018 三次實驗分別有 36、39、56 次 504，各有 4、4、2 個 stage 以 `llm_timeout` 結束。
- 與 `.inl` 修正無關：494 的 harness prompt 修正前後皆為 51,906 bytes（內容只差截斷提示的字數），同一份 prompt 在 1018 實驗約 2 分鐘完成，10/19 第一次重跑 300 秒無回應、第二次成功。

### SymCC 評估額度成為瓶頸

SymCC 能正常執行後，產生的 input 遠多於評估上限 `--symcc-max-candidate-evaluations 200`（416：418 個，494 新 harness：2737 個）。只有 1 個起始 seed 時，第 1 代就分到全部 200 個額度，剩下的 input 未被評估，也不會進入第 2 代（`candidate_eval_budget_exhausted`）。

## 6. 測試

新增 4 個 unit test（header 與 `.inl` 略過、stdlib 模式、native seed 的 text/hex/錯誤/缺漏）。`python -m pytest -q unitest`：225 passed、1 skipped。

## 7. 後續

已整理進 `backlog/TBD.md`：

- H4：調高 Vertex AI 單次請求上限，並放寬 harness 產生的 stage 上限。
- H5：SymCC 建置失敗與崩潰獨立標示；summary 新增實際解題來源（`harness_native_seed` / `libfuzzer` / `symcc`）。
- H2、H3：分類器 FP 離線評估；以修正後的 pipeline 批次重跑歷史 Dependent blocker。
- M1：有 SymCC library archive 的 C++ 專案仍走 regular 模式，可能有相同的崩潰問題。
- M3：評估額度上限。
- M7：GT 66 個 pending 案例中，停在 SymCC 階段的失敗需先確認是否為上述環境問題。
- L1：README 補上 `clang` 安裝、驗證與 regular 模式說明。
