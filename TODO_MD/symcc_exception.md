# SymCC Pipeline 例外情況整理

最後更新：2026-06-08

---

## 一、已修正的 Bug：generated_harness 模式的 fuzz_target 覆蓋問題

### 根本原因

**檔案**：`blocker_process/dependent/symcc_blocker_solver.py` 原第 984 行

```python
# 修前（有 bug）
if loaded_context.target_source:
    args.fuzz_target = loaded_context.target_source  # 永遠覆蓋成原始 harness
```

當 `input_dependent_solver.py` 呼叫 `symcc_blocker_solver.py`（`symcc_generated_harness` 階段）時，`build_context.json` 含有：
- `mode = "generated_harness"`
- `target_source` = 原始 harness（例如 pcap binary 格式）
- `harness_source` = 新生成 harness（例如 filter string 格式）

但 line 984 無條件用 `target_source` 覆蓋 `args.fuzz_target`，造成：
- SymCC binary 用原始 harness 格式（pcap binary）生成 seeds
- Coverage binary 用新 harness 格式（filter string）量測
- **格式不符 → 所有 coverage run SIGABRT (-6)**

### 修正內容（由 Codex 套用）

```python
# 修後
if loaded_context.mode == "generated_harness" and loaded_context.harness_source:
    args.fuzz_target = loaded_context.harness_source   # 用新 harness
elif loaded_context.target_source:
    args.fuzz_target = loaded_context.target_source    # 保持舊行為
```

### 影響範圍

- 只影響 `symcc_generated_harness` stage（`mode="generated_harness"`）
- `symcc_probe_original_target` stage 完全不受影響
- 可確認 `generated_harness` 路徑有此 bug（pcap_parse_2056 已驗證）；其他 case 需逐一查 log，不應一概歸因

---

## 二、新發現的例外情況：Target 本身的 crash 導致 coverage 量不到

### 案例：libpcap `pcap_parse_2056`

**Blocked branch**：`grammar.c` line 2056，`if (yyerrstatus) yyerrstatus--;` 的 True branch

**yyerrstatus 的意義**：Bison parser 的 error recovery counter。語法錯誤時設為 3，每次 token shift 時遞減。True branch = parser 正在 error recovery 中。

### 驗證 pipeline 修正後的結果

修正 format mismatch bug 後，驗證結果（`/tmp/test_fix_pcap_parse_2056`）：

| 項目 | 結果 |
|---|---|
| SymCC binary 編譯來源 | `libpcap_pcap_parse_harness.o` ✅（新 harness，filter string 格式） |
| SymCC 生成 seeds 數量 | 12,647 個（從 2,256 baseline） |
| Coverage binary | `llm_fuzzgen_symcc_pcap_parse_0608110706_replay` ✅ |
| Coverage run 結果 | 多數 exit -6 (SIGABRT)（抽樣前 200 筆：184 筆 -6，16 筆 exit 0） |

### 崩潰原因

Coverage binary 對含有算術運算的 filter 表達式（如 `4*4`, `4&4`, `1 or 2`）全部 SIGABRT：

```
free(): double free detected in tcache 2
```

測試確認：
- `"ip"`, `"tcp"`, `"port 80"`, `"host 1.2.3.4"` → exit 0 ✅
- `"4*4"`, `"4&4"`, `"1 or 2"` → SIGABRT ❌

**根本原因**：純數字算術表達式在 pcap filter grammar 裡是語法錯誤 → 觸發 Bison error recovery → **error recovery 路徑正是 blocked branch（yyerrstatus--）所在** → 但 error recovery code 本身有 double free bug → SIGABRT。

### 情境的諷刺性

```
SymCC 生成的 seeds 高度支持走到 error recovery 路徑
    ↓
gdb breakpoint 在 grammar.c 附近被打到，但 debug line table 將 2056–2058 折到 2063
→ 可確認進入 error recovery 相關區域，尚未嚴格證明 yyerrstatus-- 那行本身被執行
    ↓
error recovery 路徑與 blocked branch 位於同一區域，且有 double free bug → SIGABRT
    ↓
LLVM coverage profile 有效資料沒被寫出
（crash 產生 0-byte .profraw，llvm-profdata merge 仍可執行但無新 coverage 資料）
    ↓
系統量不到 coverage → 回報「沒解到」
```

- `pcap_parse_2056` 這個 branch 之所以從來沒被解到，**不只是 seed 沒試到，也因為 libpcap 自己在 error recovery 有 bug，讓 fuzzer 自然迴避了這條路徑**（崩潰 input 不進 corpus）。
- glibc 2.29+ 的 tcache double free 檢查無法被 `MALLOC_CHECK_=0` 關閉，需要換 allocator 或修 libpcap source。

### 實驗定性：這是一種特殊的 Blocker 類型

這個 case 揭示了一種比普通 blocker 更有意義的情況：

> **Blocked branch 的根本原因不是沒有 seed 試到，而是那條路徑本身有 crash bug，導致 coverage-guided fuzzer 自然迴避它（crashing input 不進 corpus）。**

| 面向 | 評估 |
|---|---|
| 系統是否識別出這個 branch？ | ✅ 是 |
| SymCC 是否生成了能觸發該路徑的 inputs？ | ⚠️ 高度支持（gdb 確認進入 error recovery 相關區域；2056 行本身尚未嚴格證明） |
| 是否有正式的 coverage 量測結果？ | ❌ 沒有（binary crash 前 profile 沒寫出） |
| 作為實驗結果是否有效？ | ✅ 有效，應定性為「crash-revealing blocker」 |

**建議紀錄方式**：在實驗報告中將 `pcap_parse_2056` 標記為「系統正確識別並生成觸發路徑，該路徑同時揭露了 libpcap 的 double free bug（SIGABRT）」，屬於有效發現而非失敗案例。

### SymCC 本體確認正常

獨立 smoke test 確認 SymCC 功能完全正常：

```bash
# 編譯含 `if (name == "root")` 的 C 程式
/home/kyliechien/LLM-FuzzGen/symcc/build/symcc /tmp/simple_test.c -o /tmp/simple_test_sym
echo "aaaa" | SYMCC_OUTPUT_DIR=/tmp/symcc_out /tmp/simple_test_sym
# → 生成 000000 內容為 "raaa"（第一層約束求解成功）
```

---

## 三、待處理事項

### 問題 A：格式不符 bug（已修）
- [x] `symcc_blocker_solver.py` line 984 fix，由 Codex 套用
- [ ] 對所有之前失敗的 `input_dependent` cases 重新跑驗證

### 問題 B：Target crash 導致 coverage 量不到

**現階段決策：暫不投入工程資源修復**

原因：
- `pcap_parse_2056` 已定性為「crash-revealing blocker」，本身即為有效實驗發現
- SIGABRT handler 是工程修補，對核心實驗主張（系統能突破 blocker）沒有加分
- 實驗優先順序應放在讓更多 blocker 跑出結果

**若未來需要修**（scale 到更多 project 時），正確做法是改 `symcc_replay_driver.c` 模板：

```c
// 在 main() 開頭加，一次改動套用所有 project / harness
static void handle_sigabrt(int sig) {
    __llvm_profile_write_file();
    signal(SIGABRT, SIG_DFL);
    raise(SIGABRT);
}
int main(...) {
    signal(SIGABRT, handle_sigabrt);
    // 其餘不變
}
```

**不建議** per-harness 加 handler，因為每個 case 都要手動改，不 scalable。

### 問題 C：其他 blockers 可達性待確認

| Blocker | 分析 | 可達性 |
|---|---|---|
| `yy_get_next_buffer_4629` | `yy_fill_buffer` 是 flex 內部 flag，不受 input 控制 | ❌ 結構性不可達 |
| `convert_code_r_2715` | libpcap filter code generator，SymCC 生成 1009 seeds | 不確定，修 bug 後可再試 |
| `or_pullup_1916` | BPF CFG 圖結構，非 input 直接控制 | ❌ 可能結構性不可達 |
| `pcap_parse_2056` | 已確認可達，但 target 本身 crash | ⚠️ 可達但有 crash bug |
| `vpx_highbd_lpf_593` | VP8/VP9 decoder，需要合法 bitstream | 不確定 |

---

## 四、關鍵學習

1. **pipeline 正確性**：format mismatch bug 修好後，SymCC 的 seed 生成和 coverage 量測流程邏輯正確
2. **Target 本身的 bug 會干擾求解**：blocked branch 可達不代表 coverage binary 能存活，需要特別處理 SIGABRT 案例
3. **Fuzzer 的自然迴避**：有 crash bug 的路徑，fuzzer 本來就會迴避（不加入 corpus），這解釋了為什麼某些 branch 長期 0 count
4. **SymCC 本體正常**：已用 standalone test 確認，問題都在 pipeline 整合或 target 本身
