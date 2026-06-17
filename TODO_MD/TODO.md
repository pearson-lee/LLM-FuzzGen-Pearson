# LLM-FuzzGen — Input Dependent Pipeline 現況（2026-05-31）

---

## 系統背景

**LLM-FuzzGen** 是一個結合 LLM 與覆蓋率導向 fuzzing 的研究系統，目標是自動突破 OSS-Fuzz 專案長期無法覆蓋的 branch（"blocker"）。

**Blocker** = fuzz-introspector 偵測到的「某 branch 的一側 hit count 永遠為 0」的位置。  
分類器將 blocker 分為：
- **Input Independent**：條件不由輸入決定 → `input_independent_solver`
- **Input Dependent**：需要特定輸入才能觸發 → 本 pipeline

**Dependent Pipeline 執行順序**：
```
Stage 1 (LLM seed gen) → Stage 3a (SymCC on original) → Stage 2 (LLM harness gen) → Stage 3b (libFuzzer) → Stage 3c (SymCC on harness)
```

---

## Blocker 解決狀態（libpcap）

| Blocker | 位置 | 狀態 | 解法 |
|---|---|---|---|
| `and_pullup` | `optimize.c:2018→2021` | ✅ SOLVED | Stage 1，5/30，target=`llm_fuzzgen_symcc_and_pullup_0529022325` |
| `or_pullup` | `optimize.c:1939→1940` | ✅ SOLVED | Stage 1 iter 2，5/30，snaplen=0→65535，blocked_side=186 |
| `pcap_parse` | `grammar.c:2056→2057` | ❌ Dead code | Bison `yyerrstatus--`，BPF filter 路徑不可達，放棄 |
| `gen_proto` | `optimize.c` | ⏳ 未測試 | 等系統選出 |

**重要**：and_pullup / or_pullup 都在 **Stage 1** 解出，Stage 3（SymCC 路徑）從未被真實案例端對端執行。

---

## Fix 實作狀態

| Fix | 狀態 | 位置 |
|---|---|---|
| **B1-1** SymCC harness template include 指引 | ✅ 已修正 | `prompts/templates/symcc_harness_generator_template` Req.10 + CRITICAL |
| **B1-2** include normalizer | ✅ 正常 | `symcc_blocker_solver.py:393` |
| **B1-3** static path check（regex 攔截絕對路徑） | ✅ 正常 | `input_dependent_harness_generator.py:664` |
| **C1** size-diverse sampling（`max_candidates 16→32`） | ✅ 已修正 | `symcc_blocker_solver.py:1046` |
| **C2** format_mismatch_seed hint | ✅ 正常 | `input_dependent_seed_generator.py` |
| **E1** cjson replay driver（symcc_replay build 支援） | ✅ 已加入 5/31 | `projects/cjson/build.sh` |
| **E2** libvpx replay driver（symcc_replay build 支援） | ✅ 已加入 5/31 | `projects/libvpx/build.sh` |

> **B1-1 未端對端驗證**：template 已修正，但 Stage 2 harness gen 從未在真實 case 中跑過。

---

## 進行中實驗（5/31 深夜啟動）

### libvpx 12hr Dependent-Only Run

**目的**：驗證 Stage 3 SymCC 路徑可用、E2 replay driver 建置正確

```bash
python main.py run libvpx \
  --run-fuzzers 3600 \
  --use-blocker \
  --blocker-pipeline-mode dependent \
  --blocker-session-size 3 \
  --blocker-max-iterations 3 \
  --blocker-fuzz-seconds 15 \
  --llm vertexai --model gemini-2.5-flash \
  2>&1 | tee logs/$(date +%m%d_%H%M%S)_libvpx_12hr_dependent.log
```
> ⚠️ 確認 iteration-loop 參數（0528 log 顯示 `Iteration loop: 8`，12hr 需調整）

---

## 起床後檢查清單

### 1. Replay binary 建置
```bash
ls external/oss-fuzz/build/out/libvpx/symcc_replay/
```
✅ 有 `{target}_replay` → E2 有效；❌ 空 → `BUILD_FLAVOR=symcc_replay` 未觸發

### 2. 是否有 blocker 走 dependent pipeline
```bash
grep -E "blocker_pipeline_started|blocker_kind|Input Dependent" logs/*libvpx*.log | head -20
```

### 3. Stage 1 結果
```bash
grep -E "solved_by_generator|not_solved_by_generator|final_status" logs/*libvpx*.log | tail -10
```
- `solved_by_generator` → Stage 1 解出
- `not_solved_by_generator` → 進入 Stage 3a

### 4. Stage 3a（SymCC on original）是否執行
```bash
grep -E "symcc_probe_original_target|coverage_binary_kind|explore_with_symcc" logs/*libvpx*.log | head -20
```
確認 `coverage_binary_kind: replay`（用 `_replay` binary）或 `libfuzzer_target`（fallback）

### 5. Stage 2 harness include 路徑（B1-1 驗證）
```bash
find blocker_process/dependent/generated_targets/libvpx_* -name "parsed.json" 2>/dev/null \
  | xargs grep -l "harness_code" | head -3 \
  | xargs python3 -c "import sys,json; [print(json.load(open(f)).get('harness_code','')[:500]) for f in sys.argv[1:]]"
```
確認 `<vpx/vpx_decoder.h>` 而非 `/src/libvpx/vpx/vpx_decoder.h`

### 6. Stage 3c C++ libc++ 問題（D4）
```bash
grep -E "SYMCC_REGULAR_LIBCXX|libcxx|error.*c\+\+" logs/*libvpx*.log | head -10
```
若有 C++ 錯誤 → 需修 `symcc_blocker_solver.py:617`（`SYMCC_REGULAR_LIBCXX` → `SYMCC_LIBCXX_PATH`）

### 7. Coverage 進度
```bash
ls -lt external/oss-fuzz/build/out/libvpx/textcov_reports/*.covreport | head -5
```

---

## 待辦事項

### P1（論文相關）

- [ ] **Stage 3 端對端驗證**（D2）：libvpx overnight run 是否走到 Stage 3a/3c
- [ ] **B1-1 Stage 2 驗證**：確認 LLM 生成的 harness 用 angle-bracket include
- [ ] **D1 實作**：Stage 1 解出後立即觸發 coverage pass 寫入 `textcov_reports/`，防止 blocker 重複出現
  - 位置：`input_dependent_solver.py` 成功 return 前
  - 參考：`evaluate_iteration_with_coverage` 流程，但需寫入正式 covreport 路徑

### P2

- [ ] **D3**：已解 blocker 防重複選取保護（`solved_blockers.json` 暫存，或依賴 D1）
- [ ] **D4**：`symcc_blocker_solver.py:617` 改 `SYMCC_REGULAR_LIBCXX=yes` → `SYMCC_LIBCXX_PATH=libcxx_symcc_install`（C++ target 用）

### P3

- [ ] **D5**：Stage 3b/3c seeds 自動 merge 回 `build/corpus/{project}/{best_target}/`
- [ ] **input_independent_solver `#include <algorithm>`**：C 專案 LLM 生成 C++ include，本地 syntax check 失敗（Docker 成功，不影響主流程）

---

## 關鍵數據（論文用）

### and_pullup 覆蓋率

| 時機 | `optimize.c:2018`（branch） | `optimize.c:2021`（blocked side） |
|---|---|---|
| 加入 LLM 種子前（5130 seeds） | 1590 次 | **0 次** |
| 加入 9 個 LLM 種子後 | 1600 次 | **1 次（首次）** |

### or_pullup 解決過程

- Iter 1：snaplen=0 → `pcap_compile` 立即返回，`bpf_optimize` 不被呼叫，branch_hit=0
- Iter 2：snaplen=65535 + nested OR → branch_hit=1630，**blocked_side_hit=186**

---

## 系統架構快速參考

### Blocker 解析流程
```
Coverage Run → textcov_reports/{target}.covreport
Introspector Refresh → branch-blockers.json
Global Blocker Selector
  → blocked_hits_sum > 0（任一 target）→ resolved
  → best_target = 最高 sides_hitcount_diff
Live Revalidation → 只跑 best_target corpus 即時確認
```

**時序陷阱**：`evaluate_iteration_with_coverage`（solver 內）不寫入 `textcov_reports/`；主 loop coverage pass 才寫。Seeds 放進 corpus 後若 coverage pass 未及時跑，introspector 仍看到 blocked = 0 → blocker 重新出現。

### Replay Driver（SymCC 必需）

| Project | 狀態 | library 連結 |
|---|---|---|
| libpcap | ✅ 已設定 | `libpcap.a` + `symcc_native` export |
| cjson | ✅ 已設定（5/31） | `libcjson.a` |
| libvpx | ✅ 已設定（5/31） | `libvpx.a`，`-std=c++11` |

`run_symcc_blocker.py:135` 的 native archive 仍 hardcode `libpcap` only。其他 project 走 fallback（libFuzzer binary）。
