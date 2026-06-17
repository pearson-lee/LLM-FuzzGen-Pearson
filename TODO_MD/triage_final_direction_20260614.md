# Triage 最終方向（給 Codex review）— 2026-06-14

## Context（為什麼這樣決定）

Triage offline rerun（`triage_decisions_label_routing.jsonl`，跑三次）得到 **4–5/9** first-layer
agreement。經討論後，釐清兩個關鍵事實，據此**否決**了原本「Tree-sitter evidence verifier」大改
方案，改採最小、可防守的方向：

1. **目前所有 triage 錯誤都是 false positive（該 skip 卻 run_solver）**，沒有任何 false negative。
   也就是說 triage 不會害我們漏掉可解的 blocker，只會在不可解的 blocker 上多花時間。系統現況是
   「正確但偏慢」，不是「會漏解」。

2. **Defensibility 的不對稱**：把 triage 定位成需要證明「不誤跳可解 blocker」的 hard gate，
   用 9 個 case 根本證明不了；但定位成 **fail-open routing layer**（uncertain 一律 run_solver），
   它的核心保證是 *by construction* 的程式性質，不需要 ground truth 就能防守。Full verifier
   反而需要更多 ground truth 去證明沒誤跳，而且對 `pcap_parse_3594` / `compute_local_ud`
   這兩個跨函式/語意 case 仍然抓不到（原提案第 7 節自承），結果與 fail-open 相同。

**已定方向**：
- fail-open 定位 + 極小 `convert_code_r` 確定性檢查（**不引入 Tree-sitter**）。
- 實驗模式：正常 hard gate（skip_solver 真的擋下）。

---

## 設計原則（論文可直接引用）

> Triage 是 conservative fail-open routing layer。對「可用本地確定性分析驗證的 lexical 事實」
> 做硬性否決；對「需要跨函式或語意知識」的 case 一律 fail-open 進 solver。確定性檢查**只能把
> 判斷推向 run_solver / 重新分析，永遠不會獨自把 blocker 推向 skip**，因此不可能因為這個檢查
> 而誤跳可解 blocker。

`convert_code_r_2715` 是三個穩定錯誤裡**唯一**能靠純 lexical（大括號巢狀）分析處理的；另外兩個
（`pcap_parse_3594` parser state、`compute_local_ud_641` IR value domain）本地分析做不到，
維持 fail-open 並寫成 documented limitation。

### 三個穩定 false positive 的根因（背景）

| Case | LLM 判定 | 正確答案 | 根因 | 本地確定性可解？ |
|------|---------|---------|------|----------------|
| convert_code_r_2715 | Actionable Target Gap | Resource-Exhaustion Guard | 認為 `slen==0` 能到達 blocked side，但該行在 `if (slen)` block 內，slen==0 整塊被跳過 | ✅ 純 lexical 巢狀 |
| pcap_parse_3594 | Actionable Target Gap | Generated Parser State | 把 branch-line hit count 誤讀成 condition 為 true；parser state transition 跨函式 | ❌ 需跨函式/coverage 語意 |
| compute_local_ud_641 | Bounded Extreme Value | Internal Invariant Guard | 把 input 影響 internal IR field 擴張成可任意控制 atom 值 | ❌ 需 IR value domain 知識 |

---

## 實作計畫（最小範圍，不引入新依賴）

### 1. 確定性 enclosing-guard 抽取 — `blocker_process/blocker_triage.py`

新增 helper `extract_enclosing_guards(project_name, source_file, blocked_side_line_number)`：
- 重用現有 `resolve_source_path`（line 270）讀原始檔。
- 從 blocked-side line 往回做大括號配對（brace matching），找出每一層包住該行的 `{`，
  以及其控制條件 `if/for/while/switch (...)`。
- 回傳結構化清單，例如 convert_code_r：`[(2713, "slen"), (2715, "!offset")]`。
- 純 lexical，不處理 macro 展開、跨函式、function pointer（這些維持 fail-open）。
- 約 40–50 行，無外部依賴（不需 Tree-sitter / clang.cindex）。

### 2. 把 guard chain 當權威事實注入 prompt — `prompts/templates/blocker_triage_template`

在 Source Evidence 區段（現有 line 57–81 附近）新增 authoritative block：

```
### Enclosing Guard Chain (computed deterministically — treat as ground truth)
To reach blocked-side line {blocked_side_line_number}, EVERY guard below must be
entered (its condition must be true). A path that does not satisfy all of these
guards does NOT reach the blocked-side line.
{enclosing_guard_chain}
```

並在 Output JSON schema 增加結構化欄位，要求 LLM 明確列出可達路徑「依賴哪些 enclosing guard
為真」：

```json
"blocked_side_reach_requires": ["<echo each enclosing guard condition that your path makes true>"]
```

### 3. 確定性 post-check + 一次 re-analysis — `blocker_process/blocker_triage.py`

在 `run_triage_prompt`（line 743）拿到 parsed 結果後：
- 重新 derive computed guard chain（步驟 1）。
- **觸發條件（三者皆成立才動作，範圍很窄）**：
  1. label routing 為 Generation-solvable（Actionable Target Gap / Bounded Extreme Value）；
  2. blocked-side line 至少被一層 enclosing guard 包住；
  3. LLM 的 `blocked_side_reach_requires` **遺漏或牴觸**某個 computed guard
     （例：computed 有 `slen`，但 LLM 的路徑是 slen==0，未把 `slen` 列為需為真）。
- **動作（refute-and-reprompt，最多一次）**：把確定性反證回饋給 LLM 重跑一次：
  「Line N 在 `if (slen)` 內，slen==0 無法到達；請在『所有 enclosing guard 為真』的前提下
  重新判斷，若唯一剩餘路徑是 allocator 失敗，套用 Rule 6。」
  - 重跑後若 LLM 改判 Resource-Exhaustion Guard → **正確 skip**（convert_code_r 達成）。
  - 重跑後若仍無法自洽 → **fail-open 降為 Inconclusive → run_solver**，記錄確定性理由。
- 這條 override **永遠不會獨自產生 skip**：skip 只會由 LLM 在被反證後、套用既有 Rule 6 得出；
  系統無法解的情況一律 run_solver。fail-open 保證不變。

新增記錄欄位（供論文稽核）：`enclosing_guard_chain`、`deterministic_refutation_applied`、
`refuted_guard`、`reanalysis_triggered`。

---

## 不做的事（明確排除）

- 不引入 Tree-sitter / clang.cindex / 任何新依賴。
- 不對 `pcap_parse_3594`、`compute_local_ud`、`yy_get_next_buffer`、`newchunk` 做專屬硬規則
  — 維持 fail-open，列為 documented limitation。
- 不降低 per-blocker 預算當主要手段（事前無法分辨哪個不可解，降預算是鈍器，可能餓死可解 blocker）。

---

## 驗證步驟

1. 單元測試 `extract_enclosing_guards`：用 convert_code_r 的 source 驗證能正確抽出
   `[(2713,"slen"),(2715,"!offset")]`；用一個無巢狀的 case 驗證回傳空清單（不誤觸發）。
2. py_compile + 既有 triage 測試全綠。
3. Offline rerun（先只跑 convert_code_r 驗證 refute-and-reprompt 真的把它導向 skip）：

```bash
.venv/bin/python blocker_process/blocker_triage.py \
  --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl \
  --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json \
  --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv \
  --project-name libpcap --backend vertexai --model gemini-2.5-flash \
  --output-jsonl TODO_MD/triage_decisions_guardcheck.jsonl \
  --save-prompts-dir TODO_MD/triage_prompts_guardcheck
```

4. 確認 fail-open：在沒有 enclosing guard 的 case 上，override **不觸發**，結果與現況一致。

---

## 之後：跑完整實驗（hard gate 模式）

確定性檢查驗過後，用 `--enable-blocker-triage` 跑完整實驗（重點放在 lcms 等新 project 的泛化
資料）。skip_solver 真的擋下不可解 case，省下的時間留給其他 blocker 與 fuzzing。

---

## 論文措辭

- **不能說**：accuracy = 7/9（7/9 是局部 rerun + normalization 推導，非獨立 9-case rerun）。
- **應說**：triage 是 conservative fail-open routing layer；9 cases 為 development case study，
  報 first-layer routing agreement 與「fail-open 結構保證不誤跳可解 blocker」這個 *by construction*
  性質，不報 independent accuracy。確定性 enclosing-guard 檢查作為「可驗證 lexical 事實硬性否決」
  的方法貢獻，其餘 case 為 documented limitation（future work：跨函式 producer-path 驗證）。

---

## 想請 Codex 評估的點

1. enclosing-guard brace-matching 在「macro 展開、單行 `if` 無大括號、`do/while`」等邊界上，
   是否有會誤判的 lexical 陷阱？誤判時是否都安全地落在 fail-open 方向？
2. refute-and-reprompt 只重跑一次是否足夠？是否該對「重跑後仍 Generation-solvable 但仍牴觸
   guard」再做一次硬性 fail-open？
3. `blocked_side_reach_requires` 由 LLM echo，是否可靠到足以當 post-check 依據？或應改成
   完全由程式比對 computed guard 與 LLM 的 `required_condition` 文字（較 fragile）？
4. 這個方向是否同意：不值得為了 9-case dev set 從 5/9 擠到 7/9 而引入 Tree-sitter？
