# Input Independent Solver：Symbol Evidence 問題與解法評估

## 1. 背景與目前進度

Input Independent solver 的目標，是在原始 fuzz target 無法建立 blocker 所需狀態時，自動生成新的 fuzz target/API sequence。

目前已加入 Strategy Contract，要求 generated target 明確保存：

- `required_state`：blocked side 所需的程式狀態。
- `state_constructor`：建立該狀態的 API 或輸入結構。
- `trigger_api`：實際走到 blocker 的 API。
- `preserved_invariants`：compile repair 不得破壞的條件。

Contract parser 現在不再使用 generic fallback；格式錯誤會先修一次，仍失敗則回傳 `contract_parse_error`。Compile repair 若刪除 Contract 中的核心 API anchor，會停止 repair 並回傳 `strategy_replan_required`。

這套機制已在 lcms v2 focused run 中正常運作：

- 所有 candidate 都有可解析的 explicit Contract。
- Reference iteration 2 與 Dedicated iteration 2 的 compile repair 刪除了核心 constructor/API，均被 guard 攔截。
- 因此先前「為了編譯成功而默默破壞策略」的問題已被修正。

相關結果：

- `experiments/20260615_lcms_target_contract_v2_403/independent_target/lcms_cmsDetectDestinationBlackPoint_20260615_174922/summary.json`

## 2. 目前真正的問題

v2 仍未到達 blocked side，但失敗原因已往前移到「LLM 一開始產生的策略就不正確」。Contract 可以保存一個策略，卻無法把錯誤策略變成正確策略。

具體現象包括：

- 把 sRGB matrix-shaper profile 誤認為 output CLUT profile。
- 使用不存在的 `cmsCreateDeviceLinkProfile`、`cmsCreateProfileTHR`。
- 使用 private/internal API，例如 `_cmsPipelineAlloc`。
- 建立的 profile class 或 tag direction 不符合 blocker 條件。
- Dedicated target 改讀 fuzz bytes 作為 ICC profile，但現有 triggering corpus 不符合新的 input contract，導致 blocker branch hit 降為 0。

這不是單純的 LLM reasoning 問題。現行 `collect_prompt_context()` 對 header/source 使用固定字元截斷：

```python
header_code = clip_text(..., max_chars=12000)
source_code = clip_text(..., max_chars=20000)
```

因此 prompt 收到的是「檔案開頭」，而不是「與 blocker 有關的 declaration、definition、setter 和 constructor」。lcms 真正相關的 public API declarations 位於 header 後段，沒有進入 prompt；LLM 只能依名稱與一般知識猜測 API，造成 hallucination 或選錯 route。

## 3. 問題的抽象化

目前流程是：

```text
截取大量局部 source/header
→ LLM 自行猜測哪些 API 能建立 required state
→ 生成 Strategy Contract 與 target
→ compile repair
→ runtime coverage
```

問題在於第一步沒有建立可靠的 evidence chain。LLM 同時被要求「找 API」與「組合解題策略」，但提供的 source 又不完整。

真正需要的流程應是：

```text
blocker predicate
→ 程式抽取相關 symbols
→ 搜尋 declaration/definition/assignment/callsite
→ 標示 visibility 與 build status
→ LLM 根據 evidence 組合策略
→ Contract 保存策略
→ compiler 與 runtime coverage 驗收
```

核心分工是：程式負責提供可追溯事實，LLM 負責做語意組合，runtime 負責最後判定。不能要求 LLM 從被截斷的 source 自行補完整個 project API。

## 4. 建議解法：Symbol Evidence Collector

新增一個泛用、best-effort 的 Symbol Evidence Collector。第一版不做完整 C/C++ static analysis，也不加入 lcms API 白名單。

### 4.1 Symbol seeds

從以下既有 evidence 抽取起始 symbols：

- blocker branch 與 blocked-side expression。
- blocker function 名稱。
- runtime blocker segment 與 CFG/callsite evidence。
- fuzz target 已使用的 project API。
- 後續 iteration 可加入前一版 Strategy Contract 中的 constructor/trigger symbols。

例如 predicate 為：

```c
cmsIsCLUT(hProfile, Intent, LCMS_USED_AS_OUTPUT)
```

至少應抽取 `cmsIsCLUT`、`hProfile`、`Intent`、`LCMS_USED_AS_OUTPUT`，再向外尋找 definition、來源、setter、enum/macro 與 public constructor。

### 4.2 Evidence kinds

每筆 evidence 使用統一結構：

```json
{
  "symbol": "cmsPipelineAlloc",
  "kind": "declaration",
  "location": "lcms2.h:1237",
  "visibility": "public",
  "build_status": "active",
  "relation": "candidate_state_constructor",
  "evidence": "...source window..."
}
```

建議欄位：

- `kind`：`declaration`、`definition`、`assignment`、`callsite`、`macro`、`enum`。
- `visibility`：`public`、`internal`、`unknown`。
- `build_status`：`active`、`inactive`、`unknown`。
- `relation`：此 evidence 與 blocker 的關係。
- `location`：可稽核的 `file:line`。
- `evidence`：有限長度的 source window。

`unknown` 必須保留。搜尋不到只能代表 evidence 不足，不能宣稱 symbol 不存在或 route 不可行。

### 4.3 搜尋與排序

第一版可以使用現有 source tree 加 `rg`/簡單 tokenizer：

1. 找 exact declaration/definition。
2. 找 predicate 變數的 assignment/setter。
3. 找 blocker function 的 callers。
4. 找 public header 中相同 type、prefix 或 parameter type 的 constructor/setter。
5. 根據 direct predicate relation、public visibility、active build status 排序。
6. 設定每個 symbol 與整體 evidence budget，避免 prompt 再度膨脹。

不能只做模糊名稱搜尋後全部塞入 prompt，否則只是把固定截斷換成另一種 noise。

### 4.4 與 Strategy Contract 的關係

Collector 不負責直接產生答案。它提供 source-supported candidates；LLM 仍負責選擇並組合 API sequence。

Contract 生成後再做基本驗證：

- `state_constructor`/`trigger_api` 是否能對應到已知 declaration 或 definition。
- 是否使用已確認的 internal/static API。
- 是否選到已確認 inactive 的 callsite。
- 若只有 `unknown` evidence，記錄 evidence 不足，但不要假裝已驗證。

明確不存在、internal-only 或 inactive 的核心 API 應觸發 `strategy_replan_required`，不應等 compile repair 幫忙改寫策略。

### 4.5 最終 Oracle

Source evidence 只能證明候選有依據，不能證明策略有效。最終仍由 runtime coverage 驗收：

- branch hit = 0：API route 或 input contract 錯誤。
- branch hit > 0、blocked side = 0：到達 blocker，但 required state 不成立。
- blocked side > 0：策略已由 runtime 證實。

因此應區分：

- `source_supported`：有 declaration/definition/callsite 支持。
- `runtime_confirmed`：實際到達 blocked side。

只有 `runtime_confirmed` 能算 solver 成功。

## 5. 泛用性邊界

這個方向對一般 C 與常見 C++ 程式碼可用，但第一版是 best-effort，不是完整 static analyzer。

可處理：

- 一般 C function、struct field、macro、enum。
- 一般 C++ free function 與明確 method 名稱。
- public header declaration、static/internal definition、文字可見 callsite。
- preprocessor/build status 已有證據的情況。

不保證完整處理：

- function pointer、callback、virtual dispatch。
- overload、template、namespace alias。
- 複雜 macro expansion。
- generated parser/scanner state。
- 缺少 `compile_commands.json` 的 build-dependent symbol resolution。

這些情況應標成 `unknown`。若後續確實需要，再接 Clang AST/compile database；不應在第一版直接擴張成完整 C/C++ analysis 工程。

## 6. 預期成本

### 開發成本

- 新增一個 Collector module。
- 修改 Input Independent solver 的 prompt context。
- Prompt template 增加 structured evidence 區段。
- Summary 記錄 evidence 與缺口。
- 新增 synthetic C/C++ tests 與 focused regression tests。

### 執行成本

每個 blocker 增加數次 local source search，預期遠低於 LLM、OSS-Fuzz build 與 fuzzing 成本。

### LLM 成本

預期下降。精簡且相關的 evidence 可減少 prompt token、空回應、API hallucination、compile retry 與無效 fuzzing。

### 主要風險

最大的風險是 false negative：文字搜尋沒找到複雜 C++ route，卻被錯誤解讀為不存在。因此所有 negative conclusion 都必須有明確 source/build 證據，否則保持 `unknown`。

## 7. 最小實作範圍

建議只做以下內容：

1. 新增 `blocker_process/blocker_source_evidence.py`。
2. 從 blocker windows 抽取 identifiers/function calls/macros。
3. 在指定 source/header tree 搜尋 exact symbol windows。
4. 判斷 basic public/internal 與 active/inactive/unknown。
5. 輸出 structured evidence，取代 header/source 從開頭固定截斷的主要角色。
6. 保留原始 branch/blocked windows 與 fuzz target context。
7. 不做 Clang AST、不做 domain-specific API whitelist。

## 8. 驗證方式

### Unit tests

- C public function declaration/definition。
- static/internal function。
- enum 與 macro definition。
- assignment/setter evidence。
- `#ifdef` active/inactive/unknown。
- C++ namespace/method 的基本案例。
- 搜尋不到時必須回傳 `unknown`，不能判不存在。

### Focused regression

1. 重跑 lcms `cmsDetectDestinationBlackPoint:403`。
2. 確認 prompt 包含相關 public API declarations 與 `cmsIsCLUT` 實作條件。
3. 確認不再生成不存在或 private API。
4. 檢查 branch hit 與 failure diagnosis 是否比 v2 更接近 required state。
5. 重跑 libpcap focused case，確認既有 seed solver/callsite evidence 沒有退化。

### 成功標準

第一階段不應把「lcms 一次解成功」當成唯一標準。至少要證明：

- evidence 可追溯到正確 `file:line`。
- prompt 不再依賴 header 開頭固定截斷。
- hallucinated/internal API 數量下降。
- Contract 使用的核心 API 有 source support。
- runtime diagnosis 能區分 route failure 與 predicate-state failure。

最終 blocked side > 0 才是 target-generation solver 的完整成功。

## 9. 請 Claude 評估的問題

1. 這個 minimal Symbol Evidence Collector 是否足以解決目前 evidence clipping 問題，而不會變成 lcms 特例？
2. Symbol seeds 是否還缺少必要來源？
3. `visibility/build_status/relation` 的資料模型是否足夠？
4. Contract API validation 應採 hard rejection，還是 evidence 不足時保留 `unknown` 並允許 runtime 驗證？
5. 第一版是否應完全避免 Clang AST，或有哪些 C++ 情況沒有 AST 就會造成不可接受的誤判？
6. 驗證標準是否足以支持論文中「source-grounded target generation」的主張？

## 10. 一句話總結

目前 Contract 已能防止 compile repair 破壞策略，但 solver 仍可能因 source/header evidence 被固定截斷而一開始選錯 API；下一步應由 deterministic Symbol Evidence Collector 提供可追溯的 declaration、definition、setter 與 callsite，再由 LLM 組合策略、Contract 保存策略、runtime coverage 最終驗收。
