# 論文方向與目標重訂（給 Codex review）— 2026-06-14

論文題目：**透過模糊測試目標與種子生成以解決模糊測試阻礙之方法**
*A Method for Resolving Fuzz Blockers through Fuzz Target and Seed Generation*

Deadline：< 1 個月（含實驗、benchmark、寫作）。

---

## 1. 實驗真實結果（三次完整 run 的硬事實）

從 `experiments/*/events.jsonl` 與 `blocker_attempts.jsonl` 抽出：

| 實驗 | 專案 | 預算 | blocker 嘗試 | **blocked side 到達** | 整體 branch 成長 |
|------|------|------|:---:|:---:|:---:|
| 20260612_020723 | libpcap | 10h | 9 | **0** | +40 branch（70.21→70.75%）|
| 20260613_025506 | libpcap | 12h | 2 | **0** | +76 branch（70.95→71.98%）|
| 20260613_172310 | lcms | 4h | 1 | **0** | +9 branch（58.68→58.78%）|

**關鍵事實：**

1. **20 次 blocker attempt，0 次打到 blocked side**（每筆 `blocked_side_newly_reached=False`、`pipeline_success=False`）。
   - 注意：`blocker_attempts.jsonl` 裡的 `success:True` 是 `branch_line_reached`（branch 本來就一定到得了），**不是**解開 blocker。真正結果欄位是 `blocked_side_line_reached=False`。
2. **整體覆蓋率成長全部來自 fuzzing，不是 blocker pipeline。** per-attempt 的 `branch_delta` 有正有負（+42, -37, +37, -34…），是 fuzzing noise / corpus churn，非 blocker 貢獻；0 個 blocked side 到達 → 邏輯上 blocker pipeline 淨貢獻 ≈ 0。
3. **libpcap 在 t≈3600（開跑 1 小時）就已 70%。** 整段 12 小時都在 70→72% 高原徘徊，blocker session 在高原後才啟動。

---

## 2. 核心問題診斷（兩個疊加問題，triage 都解決不了）

**P1 — 選到的 blocker 幾乎都是最難的。**
系統先 fuzz 到 71% 高原才挑 blocker，此時剩下的是最硬的 branch（allocator 失敗、internal invariant、infeasible overflow、generated parser state）。9 個 libpcap blocker 裡只有 `gen_prevlinkhdr_check` 一個是真正 actionable。等於在**最嚴苛的 regime** 測試方法。

**P2 — 連唯一可解的也沒解開。**
`gen_prevlinkhdr_check` 方向正確（generator 生成了 geneve seeds），但因缺 caller-path context 而失敗（詳見第 5 節，已用 source 追出精確原因）。

**結論：瓶頸是「一個 blocked side 都還沒打到」，不是 triage 不夠準。** triage 無論 shadow 或 enforce，都不會讓任何 blocked side 被打到。先前大量時間投在 triage，是在優化非瓶頸。

---

## 3. 目標重訂

### 3.1 指標修正（最重要）

在 71% 高原用「整體專案覆蓋率 delta」當成效指標是錯的——永遠是 fuzzing noise（±0.5%）。

**改用 per-blocker 指標：blocked-side 到達率。** 老師建議的 RQ「blocker 上的差異」正是這個層級。

### 3.2 主 RQ（務實、守得住）

> **RQ：對於 fuzzing 達到高原後仍無法到達的 blocked side，target/seed generation 能否到達它們？**
>
> 受控 per-blocker 比較：
> - Baseline arm：純 fuzzing 跑 budget T → 到不到 blocked side？
> - Method arm：target/seed generation 跑 budget T → 到不到 blocked side？
> - 「差異」= 方法到得了、baseline 到不了的 blocker 集合。

**只要有 1~2 個這樣的 blocker，就是正面結果。** 覆蓋率提升改成附帶的 per-blocker 數字（「打到此 blocked side 解鎖了 N 條下游 branch」），不再依賴整體覆蓋率大跳。

### 3.3 認知鏈校準

```
求解 blocker = 打到 blocked side       ← 乾淨訊號、RQ 錨在這
        ↓
解鎖下游 branch = 局部覆蓋率提升        ← 附帶報告，高原上小且 noisy
```

---

## 4. 行動優先序（< 1 個月）

| 優先 | 行動 | 產出 |
|:---:|------|------|
| **P0** | 拿到**至少一個** blocked-side 成功（首選 `gen_prevlinkhdr_check`，半手動亦可）| proof-of-concept 案例，答主 RQ |
| P1 | 把該案例的 fuzzing baseline 對照跑出來（證明 baseline 到不了）| 受控差異結果 |
| P2 | 其餘 8 個 blocker 用 triage 診斷 → 寫成「本來就非 input-generation 可解」+ failure analysis | 診斷貢獻 + 表格 |
| P3 | 完整實驗 triage 用 **shadow mode**（記錄但不擋 solver），收集泛化資料 | 不傷覆蓋率、可檢驗 |

### 不做

- 不再投時間把 triage 9-case agreement 從 5/9 擠高。
- 不引入 Tree-sitter / full evidence verifier。
- 不在新 project 直接 enforce 未驗證的 hard gate（有 false-skip 風險）。
- 不用整體覆蓋率 delta 當主要成效指標。

---

## 5. P0 目標案例：`gen_prevlinkhdr_check:3149`（已用 source 追出可達路徑）

source：`external/oss-fuzz/build/out/libpcap/source_code/gencode.c`

blocked side（line 3150）：
```c
static struct block *
gen_prevlinkhdr_check(compiler_state_t *cstate)
{
    if (cstate->is_geneve)
        return gen_geneve_ll_check(cstate);   // line 3150 = blocked side
    ...
```

**到達條件（兩者同時）：**

1. **`is_geneve = 1`** — 全檔唯一設定處在 line 9434，位於 `gen_geneve()` 內 → filter 必須含 `geneve`。
2. **`gen_prevlinkhdr_check` 在 is_geneve=1 後被呼叫** — 但最近的呼叫點 line 3208 **被 `if (!cstate->is_geneve)` 擋住**（is_geneve=1 時走 else、b0=NULL，不呼叫）。可用的是**未被 `!is_geneve` 擋住**的呼叫點：
   - line 5267（gateway / ether host，DLT_EN10MB）
   - line 7973 / 8059（ether broadcast / host，Q_LINK，DLT_EN10MB）
   這些都處理 **inner frame 的 ether-host 類操作**。

**為什麼 pipeline 失敗（caller-path context 缺口具體化）：**
generator 生成的是 geneve-only 或 geneve+ip 的 seeds，只設了 is_geneve，但**從未生成 inner ether-host 檢查**，所以那些 unconditional 呼叫點沒被觸發。它需要 `geneve` **配上** inner ether-host qualifier。

**候選 filter（待實測驗證）：**
```
geneve and ether host 00:11:22:33:44:55
geneve and ether broadcast
geneve and ether dst 00:11:22:33:44:55
```
語意：`geneve and ...` 對 geneve 封包的**內層** frame 做 ether-host 檢查——正是這段 code 的設計用途。

**尚需實測確認：** (a) 此版 libpcap 編得過此 filter；(b) codegen 順序讓 is_geneve 先於 ether-host 設定；(c) fuzzer harness 使用 DLT_EN10MB。需 compile + 看 line 3150 coverage。（此驗證正在進行。）

---

## 6. triage 的新定位

- **不是**論文主貢獻、**不是**覆蓋率過濾器。
- 是**診斷 / 失敗歸因層**：把「0/9 全 fail」翻譯成「N 個本來就非 input-generation 可解 + M 個 actionable 但 solver 有具體缺口」。
- 完整實驗用 shadow mode 產生「triage 判斷 vs 實際 solver outcome」配對資料。
- 論文措辭：development case study，報 first-layer agreement 與 stability，不報 independent accuracy；fail-open 只對 parse error / unknown label / insufficient evidence 成立，semantic misclassification 在 enforce mode 仍可能 suppress 可解 blocker（故主實驗採 shadow）。

---

## 7. 想請 Codex 評估

1. 把成效指標從「整體覆蓋率」改成「per-blocker blocked-side 到達率（受控對照 baseline）」是否合理且守得住？
2. 「至少 1~2 個 blocked-side 成功」作為論文最低正面結果門檻，是否足以支撐題目主張？
3. P0 集中在單一最 tractable blocker（gen_prevlinkhdr_check）半手動取得 proof-of-concept，是否為 deadline 下正確的賭注？還是應同時改 evaluation regime（較小 baseline corpus，讓更多 tractable blocker 浮出）？
4. 第 5 節的 source 級可達性分析是否有漏洞（特別是 BPF filter grammar 中 `geneve and ether host` 的 codegen 順序）？
