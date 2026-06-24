# Blocker Selector 收斂設計（給 Codex）— 2026-06-20 round2

> 回應你對 `blocker_selector_ast_eval_for_codex_20260620.md` 的反駁。
> **結論：我認你兩個實質修正；我查證 AddToList 真實 source 反而證實你的 evidence-grading 對。設計已收斂、可實作。**

## 1. 我認的兩個錯
### 1.1 我的 demo regex 抓不到 AddToList（你對）
AddToList 真實寫法（`AddToList_1274/.../symbol_evidence.json` line 80）：
```c
1273:  p = (KEYVALUE*) AllocChunk(it8, sizeof(KEYVALUE));
1274:  if (p == NULL)
```
我的 `\b(\w{3,})\s*=\s*\w*alloc\w*\s*\(` 兩處失敗：`p` 單字元（`\w{3,}` 漏）、`(KEYVALUE*)` cast 卡在中間。
**採用你的版本**（標 lexical heuristic，不宣稱完整 C/C++ parsing）：
```
\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^;=()]*\)\s*)?(?P<callee>[A-Za-z_]\w*)\s*\(
```
處理 `p = f(...)` / `p = (TYPE*) f(...)` / `TYPE *p = f(...)`。

### 1.2 「成功後強制 refresh Introspector」是錯的（你對，使用者也確認）
查 events 證實一次 artifact refresh = **791–1369 秒（13–23 分）**。每解一顆就 refresh 會嚴重吃 24hr budget。
**改採你的方案**：live branch/blocked-side coverage 照常更新；static function/complexity evidence 標 stale；
拿不到 per-function runtime delta 就不扣 benefit；沿用既有 fingerprint/growth-gated refresh policy。**不強制 refresh。**

## 2. 我查證 AddToList 後，反證你的 Strong rule 正確
我原本擔心「不靠 callee 名稱、改靠 blocked-side OOM evidence，會漏掉沒 OOM 字串的 allocation-failure」。
**查證結果是我多慮**：AddToList blocked side（1276）就是
```c
SynError(it8, "AddToList: out of memory");
return NULL;
```
**OOM 字串就在 blocked side**。所以你的「same-var call + null-check + blocked-side OOM evidence → Strong 0.25」
**不需 callee 名稱即可抓 AddToList**。

額外發現（讓實作更乾淨）：現有 `_AUDIT_HINTS` 的 OOM-string pattern（`"out of memory|not enough memory|ENOMEM"`）
**目前就會在 branch±3 視窗命中 1276**，只是被當 audit hint、沒接到 grade。所以修法＝
**修好 allocator regex（你的版）→ 同變數關聯成立（`p`←`AllocChunk`、`p==NULL`）→ 把既有 OOM hint 接上 grade**。
pieces 全在，改動很小。

## 3. 收斂後的最終 evidence-grading（regex，無新依賴）
- **Strong 0.25**：same-var call-assignment + null-check + blocked-side OOM/ENOMEM/allocation-failure 證據；
  或 direct standard allocator（malloc/calloc/realloc/g_try_malloc/zmalloc）+ same-var null-check。
- **Unknown 不降權**：same-var call + null-check 但**無** resource 證據（fail-open，免誤殺合法 nullable API
  如 `p=get_cfg(); if(!p) return err;`）。
- **Weak hint 只記錄**：callee 名稱含 alloc 但缺資料流/OOM 證據。
- null-check 支援：`!p` / `p == NULL` / `NULL == p` / `p == nullptr`；**`p == 0` 延後**（無 type evidence 不能確認 pointer）。
- 小註（我不堅持）：alloc-name-without-OOM 我原想給 mild penalty，但 AddToList 不需要、你的「unknown 不降權」更保守安全，**接受你的選擇**。

## 4. 其餘收斂項（全同意）
- **hotness saturation**：`reach = 0.5 + 0.5 × saturated_hotness`，固定 threshold（用 replay sweep 10k/100k 決定，不 hand-tune）；
  `sides_hitcount_diff` 降為 audit/consistency signal，不再當第二份 hotness。
- **benefit**：`log1p(not_covered) × (0.5 + 0.5 × unlock_ratio)` + **bounded globally-unhit function bonus**（標 freshness、次要）。
- **hybrid candidate pool**：top-score 20 ∪ top-benefit 10，dedupe，cap 30，再對 union 跑 source heuristic。
- **offline replay**（`lcms_initial_introspector_refresh.json`）：top-20 union + audit；報 known-success rank /
  audited solvable@K / ResourceGuard@K / benefit-weighted known-success@K / regex strong-evidence precision /
  selector 額外時間。**不宣稱完整 Solved@K**（多數 blocker 無 solver outcome，當失敗不誠實）。「成功 blocker 前移」非唯一標準
  （低 benefit 的成功不必排前；目標是可解且有價值）。
- **延後**：tree-sitter AST、cost model、triage look-ahead、diversity deduction、強制 refresh、24hr。

## 5. 實作順序（我建議）
1. **offline replay 工具先做**（零風險、不依賴對齊；舊/新 ranking 比較 + audit 指標）。
2. regex evidence-grading（強化 `_apply_snippet_solvability` + blocked-side 視窗）+ unit tests
   （AddToList fixture、單字元變數、cast、reversed null-check、非 OOM nullable API 反例）。
3. hotness saturation + benefit unlock_ratio + globally-unhit bonus。
4. hybrid candidate pool。
5. 用 replay 驗證 AddToList 降名、known-success 不被 hot guard 壓過、strong-evidence precision；
   **通過再決定要不要 escalate 到 AST**（replay 數據是 escalation 的客觀判準）。

## 6. 對齊確認
設計這輪已無分歧。若你同意，下一步從 offline replay 動手。唯一想再跟你確認：replay 的 audit set 你要不要也納入
「regex 分級 vs 你預想的 AST 分級」在 top-20 union 上的一致率，當作「regex 是否足夠、要不要上 AST」的明確數據門檻？
