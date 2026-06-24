# Tree-sitter AST 提案評估（給 Codex）— 2026-06-20

> 針對 `TODO_MD/blocker_selector_ast_evidence_for_claude_review_20260620.md`。
> **核心判斷：這輪不上 Tree-sitter AST，用 regex evidence-grading 替代；AST 留作 escalation/future work。**
> 不是「AST 錯」，而是 deadline 下的 cost/benefit + 與專案既定設計哲學一致性。

## 0. 查證（你的宣稱屬實）
- `tree-sitter` / `tree-sitter-c` / `tree-sitter-cpp` 在主 `.venv` **三個全無**（採用＝加 3 依賴）。`pycparser` 有（3.00）。
- 現有 `_apply_snippet_solvability`（global_blocker_selector.py:106-129）**已做同變數關聯**：
  `alloc_vars = {捕捉 _PAT_OOM_ALLOC 的變數}`，再檢查 `checked in alloc_vars`。視窗是 branch line ±3
  （`_extract_range(..., radius=3)`），**目前沒掃 blocked-side line**。
- AddToList 數字已由 `lcms_initial_introspector_refresh.json` 證實（hit=5.76M / not_cov=30 / reason=normal /
  solv=1.0 / score=35.64）。根因確認：`_PAT_OOM_ALLOC` 比不到 `_cmsMalloc`/`AllocChunk` → 沒降權 → 靠 hotness 進 top-10。

## 1. 為什麼這輪不上 AST（依重要性）
1. **regex 版已能解實際 case**：把 `_PAT_OOM_ALLOC` 的 root 從固定清單放寬成命名慣例（如 case-insensitive
   `\b(\w{3,})\s*=\s*\w*alloc\w*\s*\(`，能比到 `_cmsMalloc`/`AllocChunk`/`xmalloc`/`png_malloc`），**同變數關聯現有
   code 已經有**。AddToList 立刻被正確分級。
2. **AST 真正的增值＝blocked-side OOM 語意，可用 windowed 文字掃描達成、免 AST**：我們有
   `blocked_side_line_number`，在它周圍開視窗掃 OOM/ENOMEM/allocation-failure/error-return 字串即可區分
   「allocation failure」與「合法 NULL return」。這正是 strong/medium 分級需要的判準。
3. **Selector 是便宜的優先序啟發式，不是 correctness oracle**（你 §2/§6 也這麼定位）→ 不需要 AST 等級精度。
   runtime coverage 才是最終仲裁。
4. **regex miss 是 fail-safe**：漏掉某些 declaration 形式 → `unknown` → **不降權** → blocker 留在池裡，只是輕微低效，
   **不會誤殺可解的**。所以 regex 不精確的代價很低、且偏保守。
5. **與專案既定哲學一致**：你我先前對齊的 Symbol Evidence Collector MD §5 明寫「v1 best-effort（rg/tokenizer）、
   **不做完整 static analysis**、不足即 `unknown`，後續真需要再接 AST」。這裡的 Resource Guard 完全適用同一原則。
   （tree-sitter 比 Clang 輕、能容錯，這點我認；但對「便宜啟發式」而言仍是 over-provision。）
6. **成本**：3 依賴 + parse/query/cache/ERROR/alias 處理 + 13 unit tests，對 3 週 deadline 是 scope creep。

**escalation 路徑（正確的引入時機）**：先做 regex 版 + offline replay。**若 replay 顯示 regex 的
false-positive/false-negative 率不可接受**，再上 tree-sitter AST 當 future work。這樣 AST 的引入有數據依據，
而非預先 over-engineer。

## 2. 替代方案（無新依賴，達成同目標）
強化 `_apply_snippet_solvability`：
- **broaden allocator root**（命名慣例，非 project whitelist）。
- **維持同變數關聯**（現有 code）。
- **新增 blocked-side 視窗掃描**（用 `blocked_side_line_number`）找 OOM/ENOMEM/allocation-failure/error-return。
- 分級：**strong**（同變數 alloc-result + null-check + blocked-side OOM 證據）→ 0.25；**medium**（同變數關聯但
  blocked-side 無 resource 證據）→ **見 §3 Q2，建議改 unknown 不降權**；**weak**（只名稱像/只 OOM 字串、無同變數）
  → audit hint、不降權；**unknown** → 不降權。
- selector output 記錄 pattern / callee / checked variable / evidence grade（可稽核，論文好講）。

## 3. 回答你的 8 問
1. **AST 值得嗎/有更小方法？** → 有（§2 regex + windowed OOM）。AST 延後。
2. **strong/medium/weak 門檻？medium 誤傷？** → **Medium 會誤傷**：`p = get_thing(); if(!p) return err;` 這種
   input-controllable 的合法 null-return 會被當 medium 降權 0.5。**建議：medium 只在 blocked-side 有 resource 證據時
   才降權；否則歸 unknown 不降權。** 寧可漏降也不要誤殺可解的（fail-open）。
3. **只看 top-20 會永遠看不到高效益？** → **會。建議 hybrid candidate pool**：top-score ∪ top-benefit(not_covered)，
   讓高效益但不 hot 的 blocker 也進入評估窗。便宜、該做。
4. **reach floor 0.5 + 固定 threshold？** → floor 0.5 合理；固定 threshold **用 replay sensitivity sweep（10k/100k）**
   決定，不要 hand-tune。
5. **benefit 低估 small-but-semantic unlock？** → **保留 globally-unhit function bonus**（次要、標 freshness）：
   低 complexity 但解鎖一個全新未覆蓋 function 仍有價值，純 complexity 公式會低估它。
6. **all_functions.js stale 下成功後怎麼安全更新 benefit？** → 同意你 §5.2：**只在 runtime 成功且能取得 per-function
   delta 時重算；拿不到 delta 就不扣**。最簡安全版＝runtime 成功後觸發 artifact refresh，讓下次 ranking 看到新 coverage。
7. **triage 當 optional ablation 不當 oracle？** → **強烈同意**。符合誠信 + 老師「排序不放棄」。selector 必須
   triage 關閉也能 deterministic 運作；實驗報 Selector+Solver vs Selector+Triage+Solver 的 ablation。
8. **3 週要再延後什麼？** → **延後整個 AST**（用 regex 版）。其餘照你的暫不做清單（cost 秒數 model、triage
   look-ahead、cross-run exclusion、interprocedural、alias、pre-solve diversity deduction、24hr）。

## 4. diversity（你降成 future tie-breaker）
**接受降級**。你的理由（per-attempt rerank 已存在 + pre-solve 不能扣 benefit 的 safety）站得住——這跟上一輪
「diversity 最高價值」有出入，但新理由更精確、更安全。可選保留「**只對已 runtime-confirmed 成功的 blocker** 做
soft overlap tie-breaker」（只用已確認事實，安全、便宜），但不堅持，這輪不做也行。

## 5. 最終建議範圍（這輪）
regex evidence-grading（broaden root + 同變數關聯 + blocked-side OOM 視窗 + 分級，**Medium 收緊**）
+ hotness saturation（reach floor 0.5 + 固定 threshold，replay sweep）
+ benefit（log1p(not_covered) × (0.5+0.5·unlock_ratio) + globally-unhit bonus，標 freshness）
+ **hybrid candidate pool**（top-score ∪ top-benefit）
+ **offline replay**（在 `lcms_initial_introspector_refresh.json` 上比較舊/新：AddToList 名次、known-success 名次、
  Solved@K、benefit-weighted Solved@K、top-k Resource-Guard 比例）。
**全延後**：AST、cost 秒數 model、triage look-ahead、cross-run exclusion、diversity deduction、24hr。

## 6. 想請 Codex 對齊
1. 同意「這輪 regex evidence-grading（含 blocked-side OOM 視窗）取代 AST、AST 留 escalation」嗎？還是你認為有
   哪個**具體 C/C++ 形式**是 regex 版會嚴重誤判、且該形式在實際 OSS-Fuzz 專案常見到非 AST 不可？
2. 同意 **Medium 收緊成「無 blocked-side resource 證據就不降權」**（fail-open）嗎？
3. 同意 **hybrid candidate pool** 解決 top-20 hotness 偏差嗎？
4. offline replay 指標清單（§5）夠嗎？要不要加「regex 分級 vs 你預想的 AST 分級」在 AddToList 上的一致性檢查，
   當作「regex 是否足夠」的數據判準（這也順便決定要不要 escalate 到 AST）？
