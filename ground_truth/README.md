# Ground Truth Blocker Classification Benchmark

## 1. 專案背景與目標

在 LLM-guided Fuzzing 與 Blocker 求解系統中，**Blocker Classifier（分支阻礙分類器）** 扮演關鍵的路由角色：
- **Input Dependent**：分支條件依賴於 Fuzzer 輸入或輸入衍生的語意狀態，系統會啟動種子生成（Seed Generation）或符號執行（SymCC）來嘗試翻轉分支。
- **Input Independent**：分支條件受限於程式碼內部不變量（Invariant）、環境配置、或現有 Harness 結構限制，純粹改變輸入位元組無法觸發，系統需轉向 Target-level 求解或進行排除。

### 現存問題：False Positive (FP) 的代價高昂
在歷史實驗中（例如 `experiments/20260912_204239_run_all_fuzzer`），LLM 分類器偶爾會出現 **False Positive**（將實際上是 `Input Independent` 的分支誤判為 `Input Dependent`）。
- **後果**：系統誤判後會耗費 20~30 分鐘（甚至數小時）於無效的符號執行、Preflight 驗證與 Fuzzing 循環中，最後因條件在數學上不可達而必定失敗（`success=False`），浪費大量運算資源與時間。

### 本階段核心任務
1. **建立 Ground Truth (GT) 基準測試集**：
   - 收集約 30 個高質量的 Blocker 案例（特別是歷史上容易引起 LLM 幻覺/誤判的失敗案例，以及已人工驗證的真實案例）。
   - 每個案例完整封裝執行時所需的全部上下文（Target Code、GDB Runtime Stack、GDB 函式原始碼、CFG 靜態呼叫鏈、CFG 函式原始碼、Header）。
2. **建立自動化評測工具（Benchmark Runner）**：
   - 提供離線重播評測機制，無須重新編譯或依賴龐大 Docker 容器環境，即可在數秒至數分鐘內評估不同提示詞（Prompt Template）或不同模型（Gemini 2.5 Flash / Pro）的分類表現。
3. **推動分類器準確性迭代**：
   - 針對常見錯誤模式（如錨定偏誤 Anchor Bias、因果鏈斷裂 Incomplete Causal Chain、FDP 限制誤判等）優化 Prompt 規則，杜絕 FP。

---

## 2. 資料夾架構

```text
ground_truth/
├── README.md                     # 本文件：研究目標、問題定義、測試框架說明
├── cases_summary.md              # 案例清單彙整（包含 Ground Truth 標籤、驗證理由與來源）
├── run_benchmark.py              # 基準評測執行腳本（支援 selected_cases / pending_cases）
├── extract_dependent_failed.py   # 從歷史記錄自動匯入 66 個 Dependent-failed 案例至 pending_cases/
├── benchmark_results.json        # 基準評測結果
└── cases/
    ├── selected_cases/           # 【已診斷／已審查確認的黃金標準 GT 案例】（目標收錄 30 個）
    │   └── cjson_update_offset_547/
    │       ├── meta.json                                # 案例元資料（標籤、來源、驗證理由）
    │       ├── fuzz_target.cc                           # Fuzz Target (Harness) 源碼
    │       ├── header.h                                 # 相關標頭檔定義
    │       ├── runtime_blocker_segment.txt              # GDB 執行期呼叫堆疊
    │       ├── runtime_blocker_segment_source_codes.txt # GDB 路徑上各函式的實作源碼
    │       ├── cfg_call_chain.txt                       # 靜態 CFG 呼叫關係
    │       ├── cfg_source_codes.txt                     # 靜態呼叫路徑上的函式源碼
    │       ├── verify_poc.c / verify_poc.cc             # 驗證程式（Dependent：重現 POC；Independent：反向實證）
    │       └── run_verify.sh                            # （選用）一鍵編譯＋產生 seed＋replay＋llvm-cov 量測 blocked side hit count
    └── pending_cases/            # 【待診斷的 66 個 Dependent-failed 候選池】
        ├── cjson_cJSON_Duplicate_rec_2772/
        ├── cjson_print_number_602/
        ├── zlib_deflate_958/
        ├── libtiff_OJPEGPreDecode_721/
        └── ... (共 66 個待審查候選案例，附帶 meta.json 與對應 Harness)
```

---

## 3. 案例收集與標註原則

參考 [`TODO_MD/minimal_ground_truth_protocol.md`](file:///home/peason/projects/LLM-FuzzGen-Pearson/TODO_MD/minimal_ground_truth_protocol.md)：
1. **Runtime Evidence**：確認該分支（Branch Line）在真實 Fuzzing 過程中有被頻繁執行（Branch Hit Count > 0），且目標側（Blocked Side）未曾被覆蓋（Hit Count = 0）。
2. **Producer & Dataflow Tracing**：追蹤分支條件中所有變數的生產者（Producer），分析其是否受輸入控制。
3. **Survival / Path Invariant Check**：檢查到達該分支的執行路徑上，是否存在防禦性檢查、提早退出（Early Return / Goto Fail）或常態鎖定，使得目標條件在該路徑上絕對不可滿足。
4. **Feasibility Check**：是否需要實體記憶體配置失敗（OOM）、系統級別錯誤（Environmental Failure）才能觸發。若需要，依照規則歸類為 `Input Independent`。

---

## 4. 評測指標

對 30 個 GT 案例進行測試時，關注以下指標：
- **Accuracy**：$\frac{TP + TN}{Total}$
- **False Positive Rate (FPR)**：$\frac{FP}{FP + TN}$（特別重要，目標將誤判為 Dependent 的機率降至最低）
- **Reason Fidelity**：LLM 所引用的 Rule（Rule 1 ~ Rule 6）與分析論證是否符合程式真實語意。

---

## 5. 評測工具與 Cache-on-Demand（隨選快取固化）機制

評測腳本 [`run_benchmark.py`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/run_benchmark.py) 具備 **隨選快取固化（Cache-on-Demand）** 機制：
1. **即插即用，離線優先**：當案例目錄內已存在上下文檔案（`runtime_blocker_segment.txt`, `cfg_call_chain.txt`, `header.h` 等）時，評測腳本會直接載入，無須依賴 Docker 或重跑 GDB，單個案例評測可在數秒內完成。
2. **動態自動補齊與固化**：若案例尚無上述檔案（如剛從歷史記錄匯入 `pending_cases/` 的新案例），評測工具會動態調用 GDB 與 Introspector 採集即時堆疊與 CFG，並在執行完成後**自動將結果解析並寫回該案例目錄固化為靜態文字檔**。之後再次執行即可享有 100% 離線快取加速。

### 常用評測指令

```bash
# 1. 評測單一確認案例（selected_cases）
python3 ground_truth/run_benchmark.py --case cjson_update_offset_547

# 2. 評測並動態補齊 pending_cases 中的某個候選案例
python3 ground_truth/run_benchmark.py --case cjson_cJSON_Duplicate_rec_2772

# 3. 評測所有已收錄的黃金案例（預設只跑 selected_cases/）
python3 ground_truth/run_benchmark.py

# 4. 批次評測待診斷案例池（pending_cases/）
python3 ground_truth/run_benchmark.py --pending
```

