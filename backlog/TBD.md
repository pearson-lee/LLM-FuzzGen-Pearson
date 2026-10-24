# TBD：尚未實作的改進（2026-10-24 整理）

範圍：從 GT 驗證、selector 分數分析、`branch_kind` 排序，到 Input Dependent pipeline 修正（見 `backlog/selector/1005`、`backlog/selector/1012`、`backlog/building/1018`）過程中提出但尚未實作的項目。

優先度：**高** = 影響實驗結論或下一次實驗是否可信；**中** = 能明顯提升解題率或效率；**低** = 整理、可觀測性或小瑕疵。

---

## 高優先

### H1. Blocker 排序改用 LLM 評估分支價值

- **背景**：`coverage_benefit` 以函式為單位，飽和專案的候選幾乎全為 0 分（tomlplusplus 1010：96%）。`branch_kind` 只是 regex 分類，無法分辨「正常結果分支」與「防禦性提早離開」（例如 `at_path` 的 `return {}`，四次實驗都失敗），也把 `return lhs.time < rhs.time;`（GT 已證實可解的 416）歸為 `other`。
- **做法**：在 selector 步驟③（`_enrich_with_snippet_solvability` 之後）對同分候選呼叫 LLM，輸入 branch 條件、blocked side 程式碼與周邊 context，輸出「語意分支 / 防禦性 / 內部不變量」與可解性分數，作為 `branch_kind_priority` 之後、`reach_confidence` 之前的排序依據。只降低順序、不排除候選。
- **注意**：每次選擇都會呼叫 LLM，需要快取（以 `canonical_blocker_key` + 原始碼 hash 為 key），並限制只評估前 N 個同分候選。
- **驗收**：用 GT selected cases 與 1010/1012/1018 的 snapshot 離線重排，比較前 5／前 10 名成功數與失敗耗時；Internal Invariant Guard 類（例如 494）應排到後面。

### H2. 分類器 FP 的離線評估

- **背景**：`path.inl:494`（GT：Input Independent / Internal Invariant Guard）四次實驗都被判為 Dependent，每次浪費約 18–20 分鐘；同一段程式碼在 `toml.hpp:11760` 卻被判為 Independent。`12168`、`17652`、`427` 在不同實驗分類結果不同，被分到 Dependent 幾乎必定失敗。
- **做法**：用 `ground_truth/run_benchmark.py` 對 19 個 selected cases 各重複分類 3–5 次，統計 accuracy、FPR 與一致性（同案例多次結果是否相同）。
- **驗收**：產出每個案例的分類分布，以及 FP 案例的錯誤類型（對應 README 的 Anchor Bias、Incomplete Causal Chain 等）。

### H3. 離線批次重跑歷史 Dependent blocker

- **背景**：1006–1018 的 Dependent 失敗都發生在 SymCC 無法執行的環境下，修正後只驗證了 416（解出）與 494（正確失敗）。
- **做法**：用修正後的 pipeline 逐一重跑 416、427、422、10780、489、494、10567、17652、12168、17066，依 GT 標註分開統計「分類錯誤」與「pipeline 解不出」。
- **驗收**：修正後 Dependent 成功率（修正前三次合計 1/14），以及每個案例實際由哪個 seed 解出（見 H5）。

### H4. Vertex AI 單次請求上限 90 秒

- **背景**：`llm_interface/llm_client.py:126` 設定 `{"timeout": 90.0}`。gemini-2.5-pro 搭配 50–60 KB 的 prompt 時常超過 90 秒，每次實驗出現 36–56 次 `504 Deadline`，seed generator 與 harness 產生多次以 `llm_timeout` 結束。同一份 prompt 一次成功、一次 300 秒無回應。
- **做法**：調高到 240 秒，並把 harness 產生的 stage 上限（`llm_harness_stage_timeout_sec`，目前 300 秒）提高到 600 秒；log 中記錄每次請求耗時。
- **驗收**：504 次數與 `llm_timeout` stage 數明顯下降。

### H5. 失敗類型與解題來源的可觀測性

- **背景**：
  - SymCC 建置失敗（找不到 `clang`、header 被編譯、`.inl` 不支援）與 runtime 崩潰（`-11`）都被記錄成 `symcc_no_new_outputs` 或 `coverage_no_blocked_side`，導致問題長期未被發現。
  - 416 由 LLM 寫的 `fidelity_seeds` 直接走到 blocked side，`success_stage` 卻記為 `symcc_generated_harness`，會高估 SymCC 的解題率。
- **做法**：新增 `symcc_build_failure`、`symcc_runtime_crash` 等 failure kind；summary 新增 `solved_by`（`llm_seed_generator` / `harness_native_seed` / `libfuzzer` / `symcc`）。
- **驗收**：`blocker_attempts.jsonl` 可直接統計各失敗類型與解題來源。

### H6. 實驗在 full refresh 時 OOM

- **背景**：1010、1012、1018 都在候選池用完後的 full refresh（Introspector 產生報告）時被 OOM killer 終止，實際只跑 8–13 小時。
- **做法**：使用者處理 WSL 記憶體設定；程式端可考慮降低 Introspector 並行度，或候選池用完時跳過 full refresh。
- **驗收**：實驗能跑完 `--run-fuzzers` 指定的預算。

---

## 中優先

### M1. SymCC 編譯的穩健性

- **背景**：C++ stdlib 模式切換只對沒有 archive 的專案（tomlplusplus）改用 `stl`。libtiff、libvpx、tinyxml2 等有 `symcc_library` archive 的 C++ 專案仍走 `regular`，可能遇到與 416 相同的 runtime 無限遞迴；尚未驗證。
- **做法**：
  1. 拿 tinyxml2 或 libtiff 的 C++ harness 跑一次 SymCC probe，確認是否以 `-11` 結束。
  2. 若會崩潰，評估讓 container 內的 `symcc_library` 也以 instrumented libc++ 建置，或以 `-Bsymbolic` 重建 runtime。
- **相關**：README 需補充 `regular` 模式會崩潰的說明（見 L1）。

### M2. 共用的 LLM 建置錯誤修復元件

- **現況（已查）**：專案中沒有共用元件，只有四套各自實作、且都只修「LLM 產生的程式碼」：

  | 位置 | 修什麼 | 次數上限 |
  |---|---|---|
  | `main.py` `build_fuzz_target()` | 初始 fuzz target 編譯錯誤（`build_template`，之後只傳錯誤訊息延續對話） | `COVERAGE_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS` = 10 |
  | `input_independent_solver.py` | Independent harness 編譯錯誤（`blocker_compile_fix_*_template`，含 `classify_compile_api_diagnostics`） | `BLOCKER_FUZZ_TARGET_COMPILER_MAX_ATTEMPTS` = 4 |
  | `input_dependent_harness_generator.py` | SymCC harness 語法／原生建置錯誤（`build_harness_repair_prompt`，先嘗試自動補 include 子目錄） | 1 |
  | `input_dependent_seed_generator.py` | seed 產生腳本執行錯誤（`build_generator_fix_prompt`） | 每輪 2 |

  沒有任何機制處理「建置設定」本身的錯誤：SymCC host 建置（`symcc_blocker_solver.build_binaries`）、coverage／replay binary、container 內的 `symcc_library`／`symcc_native` 建置、OSS-Fuzz `build_fuzzers` 失敗。

- **做法**：抽出一個共用元件（例如 `blocker_process/build_repair.py`），輸入為「建置命令、錯誤輸出、可修改的對象（原始碼、build context、flags）」，輸出為修正後的對象與理由；統一錯誤分類（缺 header、未定義符號、副檔名不支援、ABI 混用等）與重試上限。現有四處逐步改用它。
- **注意**：系統性的建置問題（clang、`.inl`）應修在程式裡，不該每次靠 LLM 修；這個元件主要處理專案各自的編譯差異。

### M3. SymCC 評估額度成為瓶頸

- **背景**：修正後 SymCC 能產生大量 input（416：418 個、494 新 harness：2737 個），但 `--symcc-max-candidate-evaluations 200` 只評估其中一部分，第 1 代就用完，沒有進入第 2 代。
- **做法**：在 H3 的批次重跑中比較 200 與 1000 的成功率；每次評估成本約數十毫秒到 1 秒。

### M4. 把 SymCC 的中間結果回饋給 LLM

- **背景**：SymCC 常產生「走到 branch 但沒進 blocked side」的 input（416：121 個），pipeline 是單向的，不會把這些資訊交回 LLM。
- **做法**：⑤ 失敗時，把走到 branch 的 input 與條件判斷原始碼交給 LLM，請它改寫成能走進 blocked side 的版本（類似 GT POC 的做法）。先排除 GT 判定為不可達的案例。

### M5. Seed generator 不理解 FDP 的 byte 排列

- **背景**：416 的 seed generator 把長度放在最前面的 8 bytes，但 harness 用 `ConsumeIntegralInRange` 從尾端讀；即使附上參考 seed 的格式提示，兩輪都猜錯（`format_mismatch_seed`）。
- **做法**：提供 harness 的 FDP 讀取順序摘要給 LLM，或提供一個 seed builder 輔助函式（類似 GT 416 `verify_poc.cc` 的 `SeedBuilder`），讓 LLM 只需描述欄位值。

### M6. Blocker 去重

- **背景**：
  - C++ template 實例化：`toml.hpp:8635` 以 4 個 mangled name 出現，佔用同一輪前 4 名。
  - 單一 header 與 `.inl`：`stop_recording` 在 `toml.hpp:13757` 與 `parser.inl:1174` 各被試一次（兩次共約 53 分鐘）；`at_path` 在 `path.inl:494` 與 `toml.hpp:11760` 分類結果甚至不同。
- **做法**：`canonical_blocker_key` 正規化 demangled 名稱與 template 參數；以原始碼內容（branch 條件文字 + 函式名）辨識同一段程式碼在不同檔案的副本。

### M7. GT 資料整理

- `pending_cases` 的 66 個「Dependent 失敗」案例來自 SymCC 無法執行的時期，停在 SymCC 階段的失敗需先確認是否為環境問題，不能直接當成分類器 FP 的證據。
- `extract_dependent_failed.py` 的專案名稱 bug（`*_run_all_fuzzer` 目錄會取到 `run`）。
- 3 個 libvpx 案例的 `meta.json` 缺少 label。

### M8. 單一 pipeline 耗時過長

- `utf8_byte_stream:12705` 一次 5761 秒、`parser.inl:1174` 2435 秒、`parser.inl:701` 1982 秒。可考慮每個 blocker 的 wall-clock 上限，或依 `branch_kind`／歷史失敗次數調整預算。

---

## 低優先

### L1. README 與文件更新

- 主機工具加入 `clang`；第 9 步驗證加入 `command -v clang`；常見問題補上 `Required tool not found: clang`。
- 第 7 步與 `docs/setup_symcc*.md`：說明 `regular` 模式在 QSYM runtime 下可能無限遞迴，以及 `select_cxx_stdlib_mode()` 的判斷規則。
- `backlog/building/1018/summary.md` 補上 10/19 的 `.inl` 修正與 494 驗證結果。

### L2. 小瑕疵

- build 失敗後仍印出 `Successfully completed fuzzing`。
- 實驗被 kill 後，Introspector webapp（`external/fuzz-introspector/.../app/main.py`）留在背景。
- `--blocker-top-k` 的 help 寫「每個 target」，實際是全域排序後取前 k 個。
- 已嘗試過的 blocker（`attempted_blocker_keys`）只存在記憶體，重啟後會重複嘗試；也沒有 resume 功能。

### L3. 工具整理

- 把分析腳本（實驗比較、`branch_kind` × Dependent 統計、離線重排、從 `run.log` 還原 pipeline 參數並重跑）整理到 `tools/`。

---

## 立即的整理工作（不屬於功能）

- 依規劃完成三次 commit；`.inl` 修正與相關測試併入第三次。
- `git status` 中 11 個 `llm_fuzzgen_*_0806*.cc` 的刪除不要 commit（檔案在 `backup_artifacts/`）。
- `external/oss-fuzz/projects/tomlplusplus/` 仍有 1018 實驗留下的 5 個 `llm_fuzzgen_reference_guided_1019*.cc`，下次乾淨實驗前需移走；`backup_artifacts/` 已累積約 19 GB。
