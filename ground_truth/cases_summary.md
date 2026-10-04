# Ground Truth 案例清單與審查紀錄

本表彙整已人工檢驗及待審查的 Ground Truth 基準測試案例。目標收集約 30 個具代表性的 Blocker 案例。

---

## 一、 已驗證案例（Verified Cases）

### 案例 1: `cjson_update_offset_547`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `cjson_update_offset_547` |
| **專案名稱** | `cjson` |
| **目標函式** | `update_offset` (`/src/cjson/cJSON.c:547`) |
| **分支條件** | `if ((buffer == NULL) \|\| (buffer->buffer == NULL))` |
| **阻礙目標行** | `549` (`return;`) |
| **Harness** | `llm_fuzzgen0721221311` (及衍生之 `llm_fuzzgen_reference_guided_0725092654_414996`) |
| **執行期 Hit Count** | 1.67M 次（經常被執行，但 line 549 從未進入） |
| **Ground Truth 標籤** | **`Input Independent`** |
| **適用規則** | **`Rule 3: Observed-Path Invariants`** |
| **歷史紀錄來源** | - 驗證成功紀錄：[`experiments/20260724_025850_cjson`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260724_025850_cjson)<br>- 歷史誤判（FP）紀錄：[`experiments/20260912_204239_run_all_fuzzer`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260912_204239_run_all_fuzzer) |

#### 程式碼因果推導與證明：
1. **Producer 來源**：
   - 堆疊 frame 為 `LLVMFuzzerTestOneInput` -> `cJSON_PrintUnformatted` -> `print` -> `print_value` -> `print_object` -> `update_offset`。
   - `buffer` 是 `print()` 函式內部宣告於 stack 上的局部結構 `printbuffer buffer[1];`，其指標由呼叫鏈傳遞，**絕對不可能為 NULL**。
   - `buffer->buffer` 則是在 `print()` 中透過 `hooks->allocate(default_buffer_size)` 配置的記憶體指標。
2. **Path Invariant 防禦邏輯**：
   - 在 Harness 中，配置掛鉤受 `out_of_memory = fdp.ConsumeBool();` 控制。若 `out_of_memory == true`，`failing_malloc` 會回傳 `NULL`。
   - 然而在 `print()` 中，記憶體配置後緊接著檢查：
     ```c
     buffer->buffer = (unsigned char*) hooks->allocate(default_buffer_size);
     if (buffer->buffer == NULL) { goto fail; }
     ```
     如果配置失敗，函式立刻跳至 `fail:` 結束釋放，**完全不會呼叫下方的 `print_value()` 或 `update_offset()`**。
   - 若配置成功，後續在 `print_object()` 中雖然會透過 `ensure()` 嘗試擴展緩衝區，但若 `ensure()` 失敗返回 NULL，各層列印函式（如 `print_string_ptr`、`print_value`）都會立刻返回 `false` 並觸發呼叫端的中斷邏輯，絕不會在 `buffer->buffer` 毀損的情況下進入 `update_offset()`。
3. **結論**：
   在任何能執行到 `update_offset(buffer)` 的路徑上，`buffer->buffer` 恆不為 NULL。目標 line 549 在當前路徑語意下為不可達的防禦性死碼（Dead Code），因此為絕對的 **Input Independent**。


---

### 案例 2: `cjson_cJSON_Duplicate_rec_2772`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `cjson_cJSON_Duplicate_rec_2772` |
| **專案名稱** | `cjson` |
| **目標函式** | `cJSON_Duplicate_rec` (`/src/cjson/cJSON.c:2772`) |
| **分支條件** | `if (!newitem->valuestring)` |
| **阻礙目標行** | `2774` (`goto fail;`) |
| **Harness** | [`llm_fuzzgen_reference_guided_0724141917_518251.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/cjson/llm_fuzzgen_reference_guided_0724141917_518251.cc) |
| **執行期 Hit Count** | 17.4k 次（分支頻繁被執行，但 line 2774 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** |
| **適用規則** | **`Rule 3: Observed-Path Invariants` & `Rule 6: System Resource Failure`** |
| **Refined Triage Label** | **`Resource-Exhaustion Guard`** (`include_in_solver_evaluation = false`) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260724_025850_cjson`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260724_025850_cjson)（下游 5 個求解器耗時 11 分鐘皆失敗）<br>- 2026/09 評測重現：[`experiments/20260920_095432_run_all_fuzzer`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260920_095432_run_all_fuzzer) |

#### 程式碼因果推導與證明（Protocol 5 步審查）：
- **Step 1: Predicate & Target State**：
  進入目標行 2774 需要 `newitem->valuestring == NULL`。因第 2769 行已有防禦 `if (item->valuestring)`，在 `cJSON_strdup` 中唯一能回傳 NULL 的原因只有 `hooks->allocate` 失敗。
- **Step 2: Producer & Input Control**：
  記憶體配置掛鉤受 `failing_malloc` 攔截，由輸入 `out_of_memory = fdp.ConsumeBool()` 控制。若為 false，則走標準 libc `malloc(<=101)`。
- **Step 3: Survival & Path Invariants（雙重前置鎖死）**：
  1. 若 `out_of_memory == true`：在 Harness 端，`generate_random_json` 內部所有 7 種型態建立全部因 OOM 失敗回傳 NULL，`root == NULL` 導致第 96 行 `if (root)` 為假，跳過呼叫 `cJSON_Duplicate`。退一步即使進入函式，第 2760 行 `newitem = cJSON_New_Item` 先行配置失敗，在第 2763 行 `goto fail;` 提早退出，永遠無法執行到第 2771–2772 行。
  2. 若 `out_of_memory == false`：字串長度被限制在 100 bytes 內，常態 small allocation 絕不可能失敗。
- **Step 4: Alternative Path & Feasibility**：
  要觸發該分支，必須在同一個函式內使相隔 10 行的第 2760 行配置成功、第 2771 行配置失敗。這需要外部故障注入（Fault Injection）或系統實體 OOM，超出一般種子/目標生成的求解範圍。
- **Step 5: Final Adjudication**：
  在現行觀測路徑下純靠輸入無法觸發。裁定為 **`Input Independent`**，Refined Label 為 **`Resource-Exhaustion Guard`**，不納入 Solver 評測集。

---

### 案例 3: `cjson_print_number_602`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `cjson_print_number_602` |
| **專案名稱** | `cjson` |
| **目標函式** | `print_number` (`/src/cjson/cJSON.c:602`) |
| **分支條件** | `if ((length < 0) \|\| (length > (int)(sizeof(number_buffer) - 1)))` |
| **阻礙目標行** | `604` (`return false;`) |
| **Harness** | [`llm_fuzzgen_reference_guided_0724141917_518251.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/cjson/llm_fuzzgen_reference_guided_0724141917_518251.cc) |
| **執行期 Hit Count** | 38.9k 次（分支頻繁被執行，但 line 604 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** |
| **適用規則** | **`Rule 3: Observed-Path Invariants`（包含 C 語言標準與浮點數規格不變量）** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260724_025850_cjson`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260724_025850_cjson)（下游 SymCC / SeedGen 耗費 1,220 秒全數失敗） |

#### 程式碼因果推導與詳細數學規格證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  - 阻礙條件為 `(length < 0) || (length > (int)(sizeof(number_buffer) - 1))`。
  - 函式第 570 行宣告局部陣列 `unsigned char number_buffer[26] = {0};`，因此 `sizeof(number_buffer) - 1` 為固定常數 **`25`**。
  - 要進入第 604 行的 Blocked Side（`return false;`），必須使 `sprintf` 的回傳值滿足：
    $$\text{length} < 0 \quad \text{或} \quad \text{length} > 25 \quad (\text{即 } \text{length} \ge 26)$$

- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  - 變數 `length` 是標準函式庫 `sprintf` 的回傳值（代表實際寫入緩衝區的字元數，不含結尾的空字元 `\0`）。
  - 格式化的目標變數是 `d = item->valuedouble`。
  - 在 Fuzz Target（`fuzz_target.cc`）中，`d` 確實直接由 `fdp.ConsumeFloatingPoint<double>()` 所提供。Fuzzer 輸入可對該 64 位元 IEEE 754 雙精度浮點數的全部 64 個 bit 進行任意位元控制。

- **Step 3: Survival & Path Invariants（數學極限與 C99 規格不變量深度分析）**：
  這是本案例的核心：**Fuzzer 輸入所能提供的任何 64-bit 浮點數，是否能讓 `sprintf` 產出長度大於 25 的字串？**
  
  我們詳細檢驗函式內部設定 `length` 的所有 4 條賦值路徑：
  1. **路徑 A（特殊值：NaN 或 Infinity）**：
     `length = sprintf((char*)number_buffer, "null");` $\implies$ `length` 固定為 **4**。
  2. **路徑 B（數值等於整數：$d == \text{(double)}item->valueint$）**：
     `length = sprintf((char*)number_buffer, "%d", item->valueint);`  
     32 位元有號整數 `INT_MIN` 為 `-2147483648`（11 字元），因此 `length` 最大為 **11**。
  3. **路徑 C（一般浮點數嘗試 15 位精度）**：
     `length = sprintf((char*)number_buffer, "%1.15g", d);`  
     有效位數最多 15 位，長度最大不超過 **22**。
  4. **路徑 D（當 15 位精度無法無損還原時，使用 17 位極限精度）**：
     `length = sprintf((char*)number_buffer, "%1.17g", d);`  
     依據 **ISO/IEC C99 標準（Section 7.19.6.1）** 以及 **IEEE 754 雙精度浮點數** 規範，在科學記號模式（style `e`）下，格式化字串的字元組成上限具有嚴格的結構公式：
     - **符號位**：最多 **1** 字元（負號 `-`）
     - **小數點前第一位有效數字**：固定 **1** 字元（`1`–`9`）
     - **小數點**：**1** 字元（`.`）
     - **小數點後剩餘有效數字**：精度設定為 17，扣除整數位後小數點後最多 **16** 字元
     - **指數識別符號**：**1** 字元（`e`）
     - **指數符號位**：**1** 字元（`+` 或 `-`）
     - **指數數值**：雙精度浮點數的極值範圍約為 $10^{+308}$ 至 $10^{-324}$，指數最多 **3** 位數字（如 `308` 或 `324`）
     
     $$\text{最長字元數} = 1\text{ (負號)} + 1\text{ (首位)} + 1\text{ (點)} + 16\text{ (小數)} + 1\text{ (e)} + 1\text{ (符號)} + 3\text{ (指數)} = \mathbf{24 \text{ 字元}}$$
     
     例如極限雙精度數值：
     - 極小次常態數：`-4.9406564584124654e-324`（正好 24 字元）
     - 極大數值：`-1.7976931348623157e+308`（正好 24 字元）
     
     而在定點小數模式（style `f`）下，最大長度亦僅為 23 字元。  
     此外，`sprintf` 在輸出至記憶體緩衝區且格式字串為標準純 ASCII 時，絕無可能發生編碼錯誤而回傳負數（$\text{length} \ge 0$）。
     
     **數學結論**：在全域所有 $2^{64}$ 個浮點數取值空間中，`sprintf` 的回傳值嚴格滿足：
     $$0 \le \text{length} \le 24 \le 25$$
     因此，條件 `(length < 0) || (length > 25)` 在 C 語言標準規範與數學邏輯上**恆為 FALSE**。

- **Step 4: Alternative Path & Feasibility（替代 API 與設計意圖檢驗）**：
  - cJSON 中所有公開的 JSON 列印與字串化 API（`cJSON_Print`、`cJSON_PrintUnformatted`、`cJSON_PrintBuffered`），在處理數值時全數收斂進入此靜態函式 `print_number`。
  - 緩衝區 `number_buffer[26]` 是宣告在 Stack 上的固定陣列，外部呼叫端無從干預。
  - 檢視該行上方的原廠註解：`/* sprintf failed or buffer overrun occurred */`。此註解證實了作者當初寫下此檢查，純粹是出於防禦性程式設計習慣，防範「理論上絕不可能發生的緩衝區溢位」。該分支屬於標準的**內部防禦性死碼（Internal Defensive Dead Code）**。

- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  - **歷史誤判根源**：歷史上 LLM 分類器產生了**語意關聯性偏誤（Semantic Association Bias）**——LLM 看到輸入能控制浮點數，就主觀認定「只要輸入一個很極端的浮點數，字串長度就能超過 25」，完全無視了浮點數格式化的數學物理極限。這導致下游的符號執行（SymCC）與 LLM 種子生成器耗費了 1,220 秒（逾 20 分鐘）反覆嘗試求解，最終全數失敗。
  - **Ground Truth 標籤**：**`Input Independent`**
  - **適用規則**：**`Rule 3: Observed-Path Invariants`（包含語言規範與數學邊界）**
  - **Refined Triage Label**：**`Internal Invariant Guard`**
  - **求解評測納入**：**`include_in_solver_evaluation: false`**（該分支在數學上不可達，求解失敗是預期行為，不應列入求解器成功率計算）。

---

### 案例 4: `lcms_cmsCreateExtendedTransform_1239`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `lcms_cmsCreateExtendedTransform_1239` |
| **專案名稱** | `lcms` |
| **目標函式** | `cmsCreateExtendedTransform` (`/src/lcms/src/cmsxform.c:1239`) |
| **分支條件** | `if (cmsIsTag(hProfiles[nProfiles-1], cmsSigColorantTableOutTag))` |
| **阻礙目標行** | `1242` (`xform ->OutputColorant = cmsDupNamedColorList(...);`) |
| **Harness** | [`llm_fuzzgen0625160001.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/lcms/llm_fuzzgen0625160001.c) |
| **執行期 Hit Count** | 57 次（分支被執行，但 Line 1242 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** |
| **適用規則** | **`Rule 3: Observed-Path Invariants` & `Rule 5: Fuzz Target Hardcoded Logic & Incomplete Scope`** |
| **Refined Triage Label** | **`Structurally Unreachable API Path`** (`include_in_solver_evaluation = false`) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260707_000202_run_all_fuzzer`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260707_000202_run_all_fuzzer)（下游 SymCC / SeedGen 5 種求解方法全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  進入第 1242 行必須同時滿足：
  1. 外層守衛（Line 1236）：`cmsGetDeviceClass(hProfiles[nProfiles-1]) == cmsSigLinkClass`（必須為 DeviceLink Profile）；
  2. 目標條件（Line 1239）：`cmsIsTag(hProfiles[nProfiles-1], cmsSigColorantTableOutTag)` 評定為 TRUE（包含 `'clot'` 標籤）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  在 Harness 中，唯一能進入該分支的呼叫點在第 240 行 `cmsCreateTransform(hIT8Profile, TYPE_RGB_8, NULL, ...)`。物件 `hIT8Profile` 由第 228 行呼叫 `cmsCreateDeviceLinkFromCubeFileTHR(ctx, filename)` 建立，其檔案內容來自 Fuzzer 寫入之原始位元組。
- **Step 3: Survival & Path Invariants（函式庫規格與硬編碼不變量）**：
  查驗 `cmscgats.c:3206` 的 `cmsCreateDeviceLinkFromCubeFileTHR` 實作：
  1. 該函式專門解析 Adobe .cube（3D LUT）格式，其格式規範純屬 LUT 數據表，根本無任何 ICC Tag 概念；
  2. 解析完成後，函式庫硬編碼（Hardcoded）僅使用 `cmsWriteTag` 寫入兩個標籤：`cmsSigProfileDescriptionTag` 與 `cmsSigAToB0Tag`。函式庫絕無掛載 `cmsSigColorantTableOutTag` 的邏輯。
  3. 因此在該生成路徑上，標籤集合恆為 `{Description, AToB0}`，`cmsIsTag(..., cmsSigColorantTableOutTag)` 恆為 False，屬於確定性不可打破之路徑不變量。
- **Step 4: Alternative Path & Feasibility（替代路徑與歷史誤判根因）**：
  歷史 LLM 產生模式匹配幻覺（誤以為只要是由輸入檔案建立的 Profile 即可隨意構造任意 Tag），導致 False Positive。若要觸發該分支，必須在 Target 修改（L2/L3）層面改用 `cmsOpenProfileFromFile` 載入真實 ICC DeviceLink 檔案或呼叫 `cmsWriteTag` 寫入 clot 標籤，屬於典型 Target 範疇不全（Target Gap）。在現有 Target 下，任意輸入皆不可能觸發。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**（Rule 3 & Rule 5），Refined Triage Label 為 **`Structurally Unreachable API Path`**，`include_in_solver_evaluation = false`。

---

### 案例 5: `lcms_cmsDetectDestinationBlackPoint_442`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `lcms_cmsDetectDestinationBlackPoint_442` |
| **專案名稱** | `lcms` |
| **目標函式** | `cmsDetectDestinationBlackPoint` (`/src/lcms/src/cmssamp.c:442`) |
| **分支條件** | `if (hRoundTrip == NULL)` |
| **阻礙目標行** | `446` (`for (l=0; l < 256; l++)`) |
| **Harness** | [`llm_fuzzgen0625183111.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/lcms/llm_fuzzgen0625183111.c) |
| **執行期 Hit Count** | 228 次（分支被執行，但 Line 446 恆為 0） |
| **Ground Truth 標籤** | **`Input Dependent`** *(本基準庫首例 True Positive！)* |
| **適用規則** | **`Rule 1: Direct Data Flow` & `Rule 2: Implicit Flow & Semantic Properties`** |
| **Refined Triage Label** | **`Bounded Extreme Value`** (`include_in_solver_evaluation = true`) |
| **歷史紀錄來源** | - 歷史判定紀錄：[`experiments/20260707_000202_run_all_fuzzer`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260707_000202_run_all_fuzzer)（LLM 判定 Dependent 正確，但下游 5 種求解器因 ICC 二進位複雜度未解出） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  進入第 446 行（for 迴圈計算黑點斜坡取樣）需滿足條件式 `hRoundTrip == NULL` 評定為 **`FALSE`**（即 `hRoundTrip != NULL`）。這要求 `CreateRoundtripXForm(hProfile, Intent)` 必須成功回傳有效的轉換控制代碼。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  在 Harness（第 126–143 行）中，Fuzzer 原始輸入 bytes（Data, Size）直接經由 `cmsOpenIOhandlerFromMem` 建立記憶體 IO 串流，並由 `cmsOpenProfileFromIOhandlerTHR` 解析生成 ICC Profile 實體物件 `hProfile`，隨後傳入 `cmsDetectDestinationBlackPoint`。此處無任何人工篩選或阻斷，資料流為直接輸入資料流（Direct Data Flow）。
- **Step 3: Survival & Feasibility Analysis（存活與實體編譯實證）**：
  當傳入之 `hProfile` 為輸出設備（如 OutputClass/DisplayClass）、色彩空間為 Gray/RGB/CMYK 且包含輸出 CLUT 標籤（`cmsIsCLUT` 為真）時，程式進入 Step 2 呼叫 `CreateRoundtripXForm`。該函式建立 `Lab -> Device -> Lab` 之雙向閉環轉換。
  **實測證明**：我們在環境中直接撰寫驗證程式，將 LittleCMS 官方測試庫標準 CMYK 配置檔 `test1.icc`（557KB 具完整雙向 CLUT）作為輸入餵入：`CreateRoundtripXForm` 成功回傳非空 Handle，條件 `hRoundTrip == NULL` 順利為 FALSE，程式 100% 存活並進入第 446 行執行完整的 256 階梯取樣迴圈並回傳成功（`res = 1`）。
- **Step 4: Alternative Path & Solver 失敗分析（求解器能力邊界）**：
  此分支為 Adobe BPC 演算法主幹，非死碼或環境缺陷。歷史求解器失敗係因 ICC 二進位標籤結構約束極高（128-byte Header、Tag Table 偏移索引、多維度 CLUT 矩陣等），純隨機變異或純符號執行極難從零合成合法雙向 CLUT 檔案。這屬於典型的『求解複雜度高、但本質完全相依於輸入』之 True Positive 案例。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在不修改目前 Fuzz Target 程式碼的前提下，Fuzzer 輸入 bytes 完全可讓程式存活並抵達第 446 行未覆蓋分支。裁決為 **`Input Dependent`**（Rule 1 & Rule 2），Refined Triage Label 為 **`Bounded Extreme Value`**，`include_in_solver_evaluation = true`。

---

### 案例 6: `lcms_cmsIT8GetData_2865`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `lcms_cmsIT8GetData_2865` |
| **專案名稱** | `lcms` |
| **目標函式** | `cmsIT8GetData` (`/src/lcms/src/cmscgats.c:2865`) |
| **分支條件** | `if (iField < 0)` |
| **阻礙目標行** | `2869` (`iSet = LocatePatch(it8, cPatch);`) |
| **Harness** | [`llm_fuzzgen0625040504.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/lcms/llm_fuzzgen0625040504.c) |
| **執行期 Hit Count** | 1.00k 次（分支被執行，但 Line 2869 恆為 0） |
| **Ground Truth 標籤** | **`Input Dependent`** |
| **適用規則** | **`Rule 1: Direct Data Flow` & `Rule 2: Implicit Flow & Semantic Properties`** |
| **Refined Triage Label** | **`Bounded Extreme Value`** (`include_in_solver_evaluation = true`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/lcms_cmsIT8GetData_2865/verify_poc.c) (已實體驗證抵達目標行) |
| **歷史紀錄來源** | - 歷史判定紀錄：[`experiments/20260707_000202_run_all_fuzzer`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260707_000202_run_all_fuzzer)（下游 5 種求解器因跨切片語意約束未解出） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `cmscgats.c:2865`：`if (iField < 0)`。要進入第 2869 行未覆蓋目標程式碼（`iSet = LocatePatch(it8, cPatch);`），條件式必須 evaluate 為 **`FALSE`**，亦即 `LocateSample(it8, cSample)` 在 IT8 表格中必須成功找到欄位索引（`iField >= 0`）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  在 Fuzz Target（`llm_fuzzgen0625040504.c`）中，整個 Fuzzer 輸入緩衝區 `data[0..size-1]` 先傳入 `cmsIT8LoadFromMem(context, data, size)` 建立 IT8 物件；隨後 Target 透過 offset 手動切片方式，將前 255 位元組拷貝至 `str1`，將第 255 位元組起的剩餘位元組拷貝至 `str2`。隨後在第 75 行執行 `cmsIT8GetData(hIT8, str1, str2)`，將 `str2` 作為 `cSample` 傳入。資料流完全由 Fuzzer 輸入直接切片控制（Direct Data Flow）。
- **Step 3: Survival & Feasibility Analysis（存活與實體驗證實證）**：
  深入追查 `cmscgats.c` 內部欄位匹配機制：要使 `LocateSample(it8, str2)` 成功回傳非負索引，輸入必須具備跨切片語意一致性（Dual Semantic Consistency）——前段 `data[0..254]` 內解析出的 IT8 格式必須宣告某個欄位名稱（如 `MYCOL`），而後段 `data[255..]` 切片出來的字串必須正好等於該欄位名稱，且整體輸入還需符合 IT8 語法。  
  我們在案例目錄下附帶了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/lcms_cmsIT8GetData_2865/verify_poc.c)，構造了一組 260 位元組的輸入：前段宣告含 `MYCOL` 欄位並以 `#` 註解行填滿至第 252 位元組，第 253-254 位元組換行開啟新註解 `# `，第 255-259 位元組填入 `MYCOL`。  
  **實測結果**：`cmsIT8LoadFromMem` 順利將尾段視為合法註解完成解析，`str2` 成功切出 `"MYCOL"`，`LocateSample` 回傳 `iField = 1 >= 0`，程式 100% 存活並成功執行第 2869 行！
- **Step 4: Alternative Path & Solver 失敗分析（求解器能力邊界）**：
  此分支為 IT8 查表運算的主幹邏輯，非死碼或環境缺陷。歷史求解器失敗係因傳統 Fuzzer 或純符號執行極難無中生有拼出跨越 255 位元組 offset 相互呼應的語法與字串一致性結構。這屬於典型的『求解複雜度高、但本質完全相依於輸入』之 True Positive 案例。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在不修改目前 Fuzz Target 程式碼的前提下，Fuzzer 輸入 bytes 完全可讓程式存活並抵達第 2869 行未覆蓋分支。歷史 LLM 分類器在此處判斷為 Input Dependent 屬正確判定。裁決為 **`Input Dependent`**（Rule 1 & Rule 2），Refined Triage Label 為 **`Bounded Extreme Value`**，`include_in_solver_evaluation = true`。

---

### 案例 7: `libpcap_gen_ncode_7517`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libpcap_gen_ncode_7517` |
| **專案名稱** | `libpcap` |
| **目標函式** | `gen_ncode` (`/src/libpcap/gencode.c:7517`) |
| **分支條件** | `} else if (proto == Q_DECNET) {` |
| **阻礙目標行** | `7523` (`vlen = pcapint_atodn(s, &v);`) |
| **Harness** | [`llm_fuzzgen_reference_guided_0721050508_042323.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libpcap/llm_fuzzgen_reference_guided_0721050508_042323.c) |
| **執行期 Hit Count** | 949 次（分支被執行，但 Line 7523 恆為 0） |
| **Ground Truth 標籤** | **`Input Dependent`** |
| **適用規則** | **`Rule 1: Direct Data Flow` & `Rule 2: Implicit Flow & Semantic Properties`** |
| **Refined Triage Label** | **`Bounded Extreme Value`** (`include_in_solver_evaluation = true`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_gen_ncode_7517/verify_poc.c) (已實體驗證抵達目標行並驗證生成之 BPF 機器碼) |
| **歷史紀錄來源** | - 歷史判定紀錄：[`experiments/20260720_232522_libpcap`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260720_232522_libpcap)（歷史 LLM 判斷 Dependent 正確；下游因派送階段種子缺失報錯中斷） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `gencode.c:7517`：`} else if (proto == Q_DECNET) {`。要進入第 7523 行未覆蓋目標程式碼（`vlen = pcapint_atodn(s, &v);`），條件式必須 evaluate 為 **`TRUE`**，且必須滿足 `s != NULL` 以避開第 7503 行的純數字分支。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  在 Fuzz Target（`llm_fuzzgen_reference_guided_0721050508_042323.c`）中，輸入緩衝區前半段直接切片為 `source_str`（第 59-68 行），並傳入第 378 行的 `pcap_compile(p, &fp, source_str, 1, PCAP_NETMASK_UNKNOWN)`。libpcap 語法解析器中，詞法 `scanner.l` 將字串 `'decnet'` 識別為 `DECNET` token、將 `'1.2'` 識別為點分位址 `HID` token；語法 `grammar.y.in` 將 `DECNET` 轉化為修飾詞屬性 `q.proto = Q_DECNET`，並以 `HID` 作為字串指標傳入 `gen_ncode(cstate, $1, 0, $$.q)`。資料流與語意狀態完全由 Fuzzer 輸入直接控制（Direct Data Flow）。
- **Step 3: Survival & Feasibility Analysis（存活與實體驗證實證）**：
  當輸入提供合法 DECnet 過濾表示式（如 `'decnet host 1.2'`）時，`s = "1.2" != NULL`，第 7503 行 `if (s == NULL)` 為假，程式順利抵達第 7517 行且 `proto == Q_DECNET` 必然為真，100% 執行第 7523 行 `vlen = pcapint_atodn(s, &v)`。  
  我們在案例目錄下附帶了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_gen_ncode_7517/verify_poc.c)：構造 32 位元組輸入（前半段設置 `'decnet host 1.2'`），以 Target 相同之 `DLT_LINUX_SLL` 呼叫 `pcap_compile` 編譯成功，解析生成的 BPF 機器碼精確捕捉到 DECnet EtherType (`0x6003`) 與位址常數 (`0x204`)，實體證實程式完全存活並穿透目標分支！
- **Step 4: Alternative Path & Solver 失敗分析（求解器能力邊界）**：
  查閱歷史評測記錄，執行期 `branch_hit_count` 高達 949 次，證實該呼叫點高度活躍。歷史求解器失敗係因 LLM-FuzzGen 在派送階段（`solver_dispatch`）因初始種子庫中缺乏觸碰該分支的種子而報錯中斷，根本尚未進入求解生成，非程式邏輯或環境缺陷。此分支屬標準語意協定過濾主幹。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在不修改目前 Fuzz Target 程式碼的前提下，Fuzzer 輸入 bytes 完全可讓程式存活並抵達第 7523 行未覆蓋分支。歷史 LLM 分類器在此處判斷為 Input Dependent 屬正確判定。裁決為 **`Input Dependent`**（Rule 1 & Rule 2），Refined Triage Label 為 **`Bounded Extreme Value`**（語法與協定關鍵字結構約束），`include_in_solver_evaluation: true`。

---

### 案例 8: `libpcap_gen_scode_7226`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libpcap_gen_scode_7226` |
| **專案名稱** | `libpcap` |
| **目標函式** | `gen_scode` (`/src/libpcap/gencode.c:7226`) |
| **分支條件** | `if (eaddr == NULL)` |
| **阻礙目標行** | `7229` (`b = gen_ipfchostop(cstate, eaddr, dir);`) |
| **Harness** | [`llm_fuzzgen0710214309.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libpcap/llm_fuzzgen0710214309.c) |
| **執行期 Hit Count** | 1 次（分支被執行，但 Line 7229 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 嚴重誤判案例)* |
| **適用規則** | **`Rule 6: System Resource Failure / External Environment Dependency`** & **`Rule 3: Observed-Path Invariants`** |
| **Refined Triage Label** | **`External Resource Failure`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_gen_scode_7226/verify_poc.c) (反向實體驗證因缺失 `/etc/ethers` 恆觸發 `bpf_error`) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260720_232522_libpcap`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260720_232522_libpcap)（LLM 誤判為 Dependent，導致下游 5 種求解器耗費大量算力反覆 replan 全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `gencode.c:7226`：`if (eaddr == NULL)`。要進入第 7229 行未覆蓋目標程式碼（`b = gen_ipfchostop(cstate, eaddr, dir);`），條件式必須 evaluate 為 **`FALSE`**（亦即指標 `eaddr != NULL`），以避開第 7227 行呼叫 `bpf_error` 執行 longjmp 中斷編譯。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  指標 `eaddr` 於第 7225 行被賦值：`eaddr = pcap_ether_hostton(name);`。在 Fuzz Target（`llm_fuzzgen0710214309.c`）中，`data[0]` 被用於指定 linktype（`DLT_IP_OVER_FC = 122`），過濾字串由 `data+2` 拷貝為 `filter_string` 傳入 `pcap_compile`。當輸入為 `ether host <name>` 時，Parser 將主機名稱字串傳入 `gen_scode`。
- **Step 3: Survival & Path Invariants（環境依賴與雙重語法分流證明）**：
  深入追查 `nametoaddr.c:859-910` 之 `pcap_ether_hostton` 實作：該函式完全依賴系統靜態檔案 `PCAP_ETHERS_FILE`（即 `/etc/ethers`）。但在標準 Linux 系統與 OSS-Fuzz Docker 容器環境中，`/etc/ethers` 檔案預設根本不存在。當該檔案缺失時，`fopen` 恆回傳 NULL（glibc `ether_hostton` 亦回傳 -1），導致 `pcap_ether_hostton` 對於全域任何輸入字串恆回傳 NULL。  
  此外，若輸入為實體 MAC 位址（如 `00:11:22:33:44:55`），Lexer 會將其識別為 `EID` 並由 Bison 語法規則路由至 `gen_ecode`（`gencode.c:7731`），完全不會進入 `gen_scode`。因此在任何能進入 `gen_scode` 的路徑上，`eaddr` 恆為 NULL，第 7226 行恆為 TRUE，目標行 7229 在現行環境下為絕對死碼。  
  我們附帶了反向實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_gen_scode_7226/verify_poc.c)，實測證明無論提供一般主機名稱或常見名稱，`pcap_compile` 皆必定因缺失 `/etc/ethers` 噴出 `unknown Fibre Channel host` 錯誤中止；而給定 MAC 數值時則直接繞道至 `gen_ecode`，實體證明 Line 7229 恆不可達！
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史 LLM 產生模式匹配偏誤（誤以為只要輸入猜中主機名稱即可解鎖），將其誤判為 Input Dependent。這導致下游的 LLM 種子生成器、SymCC 探針與多輪 replan 耗費大量算力反覆嘗試求解，最終全數失敗。該阻擋點本質係因缺失外部環境資料庫，非種子生成或目標變異能力所能解決。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在現行執行環境下，任何 Fuzzer 輸入皆不可能使 `pcap_ether_hostton` 回傳非空指標。裁決為 **`Input Independent`**（Rule 6: System Resource Failure & Rule 3: Observed-Path Invariants），Refined Triage Label 為 **`External Resource Failure`**（缺失外部環境檔案 `/etc/ethers`），`include_in_solver_evaluation = false`。

---

### 案例 9: `libpcap_iface_dsa_get_proto_info_5730`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libpcap_iface_dsa_get_proto_info_5730` |
| **專案名稱** | `libpcap` |
| **目標函式** | `iface_dsa_get_proto_info` (`/src/libpcap/pcap-linux.c:5730`) |
| **分支條件** | `if (fd < 0)` |
| **阻礙目標行** | `5733` (`r = read(fd, buf, sizeof(buf) - 1);`) |
| **Harness** | [`llm_fuzzgen0710010837.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libpcap/llm_fuzzgen0710010837.c) |
| **執行期 Hit Count** | 464 次（分支被執行，但 Line 5733 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 嚴重誤判案例)* |
| **適用規則** | **`Rule 6: System Resource Failure / External Environment Dependency`** & **`Rule 3: Observed-Path Invariants`** |
| **Refined Triage Label** | **`External Resource Failure`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_iface_dsa_get_proto_info_5730/verify_poc.c) (反向實體驗證因缺失核心硬體 DSA 節點恆回傳 -1) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260720_232522_libpcap`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260720_232522_libpcap)（LLM 誤判為 Dependent，導致下游 5 種求解器耗費大量算力反覆求解全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `pcap-linux.c:5730`：`if (fd < 0)`。要進入第 5733 行未覆蓋目標程式碼（`r = read(fd, buf, sizeof(buf) - 1);`），條件式必須 evaluate 為 **`FALSE`**（亦即檔案描述符 `fd >= 0`）。這要求對 `/sys/class/net/%s/dsa/tagging` 執行 `open(..., O_RDONLY)` 必須成功打開有效檔案。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  變數 `fd` 是系統呼叫 `open("/sys/class/net/%s/dsa/tagging", O_RDONLY)` 的回傳值。在 Fuzz Target（`llm_fuzzgen0710010837.c`）中，呼叫點一（第 89 行）使用 `pcap_findalldevs` 列舉的現有主機介面名稱（如 `'eth0'`）呼叫 `pcap_create` 與 `pcap_activate`；呼叫點二（第 312 行）使用輸入字串 `filter_str` 作為裝置名稱。但在 `pcap_activate_linux`（第 1249 行）中，任何不存在於主機核心的裝置名稱皆會在 `setup_socket` 的 `ioctl(SIOCGIFHWADDR)` 驗證時直接回傳 ENODEV 錯誤並中止，完全無法抵達 `iface_dsa_get_proto_info`。唯有主機上真實存在的 Ethernet 介面（第 89 行）才能進入此函式。
- **Step 3: Survival & Path Invariants（核心硬體子系統缺失證明）**：
  DSA（Distributed Switch Architecture）是 Linux 核心專為外接實體硬體交換機晶片（如 Marvell、Broadcom switch IC）設計的核心子系統。核心唯有在物理主機板上偵測到實體 DSA 交換機硬體驅動時，才會在 sysfs 建立 `/sys/class/net/<dev>/dsa/tagging` 節點。在標準 Linux 伺服器、虛擬機以及 OSS-Fuzz Docker 容器中，網路介面純屬常規網卡（如 eth0, lo, veth），根本沒有 DSA 硬體晶片。  
  我們附帶了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libpcap_iface_dsa_get_proto_info_5730/verify_poc.c)：掃描系統所有網路介面（eth0, lo, any 等），證實所有介面的 `dsa/tagging` 節點均物理不存在（`open` 恆回傳 -1，`fd < 0` 恆為真）；且 sysfs 為唯讀核心偽檔案系統，使用者空間 Fuzzer 絕不可能寫入建立。因此第 5730 行恆 evaluate 為 TRUE 並返回 0，目標行 5733 為絕對死碼！
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史 LLM 產生嚴重的模式匹配幻覺（誤以為只要 Fuzzer 輸入猜中有效介面名稱的 Magic String 即可打開檔案），誤判為 Input Dependent。這導致下游的 LLM 種子生成器、SymCC 探針及多輪 replan 耗費大量算力反覆求解，最終全數失敗。該阻擋點本質係因缺失核心硬體 DSA 交換機子系統，非輸入變異或求解器能力所能解決。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在現有系統與容器環境下，任何 Fuzzer 輸入皆不可能使 `open()` 回傳非負描述符。裁決為 **`Input Independent`**（Rule 6: System Resource Failure & Rule 3: Observed-Path Invariants），Refined Triage Label 為 **`External Resource Failure`**（缺失核心硬體 DSA 交換機 sysfs 節點），`include_in_solver_evaluation = false`。

---

### 案例 10: `libtiff_JPEGPreDecode_1303`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libtiff_JPEGPreDecode_1303` |
| **專案名稱** | `libtiff` |
| **目標函式** | `JPEGPreDecode` (`/src/libtiff/libtiff/tif_jpeg.c:1303`) |
| **分支條件** | `if (TIFFjpeg_has_multiple_scans(sp))` |
| **阻礙目標行** | `1311` (`toff_t nRequiredMemory = 1024 * 1024;`) |
| **Harness** | [`llm_fuzzgen0717154312.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libtiff/llm_fuzzgen0717154312.cc) |
| **執行期 Hit Count** | 10,100 次（分支被執行，但 Line 1311 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 經典語意幻覺誤判案例)* |
| **適用規則** | **`Rule 5: Structurally Unreachable API Path / Harness Architectural Limitation`** & **`Rule 3: Observed-Path Invariants`** |
| **Refined Triage Label** | **`Structurally Unreachable API Path`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_JPEGPreDecode_1303/verify_poc.c) (實體驗證在 Harness 寫入後讀取架構下編碼器硬性輸出單一掃描 Baseline JPEG) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260717_180129_libtiff`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260717_180129_libtiff)（LLM 誤判為 Dependent，導致下游 5 種求解策略耗時 1,460 秒反覆求解全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `tif_jpeg.c:1303`：`if (TIFFjpeg_has_multiple_scans(sp))`。要進入第 1311 行未覆蓋目標程式碼（`toff_t nRequiredMemory = 1024 * 1024;`），條件式必須 evaluate 為 **`TRUE`**（非 0）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  `TIFFjpeg_has_multiple_scans(sp)` 呼叫 `libjpeg-turbo` 的 `jpeg_has_multiple_scans(&sp->cinfo.d)`，該函式依據 `jdinput.c:153-156` 的 `(cinfo->comps_in_scan < cinfo->num_components || cinfo->progressive_mode)` 決定。唯有解碼到漸進式 JPEG（帶有 `SOF2` Marker）或多重掃描 `SOS` 時才會回傳 TRUE。
- **Step 3: Survival & Path Invariants（規格不變量與 Harness 架構限制證明）**：
  Harness（`llm_fuzzgen0717154312.cc`）採用自產自銷的「寫入後讀取」架構。Fuzzer 輸入經由 `fdp.ConsumeData` 傳遞給 `TIFFWriteScanline`，此 buffer 乃未壓縮的光柵像素矩陣（RGB/YCbCr 數值），而非壓縮後的 JPEG 位元流！`TIFFWriteScanline` 會呼叫 libtiff 內建的 `JPEGEncode` 與 libjpeg 編碼器。  
  依據 TIFF 6.0 與 Tech Note 2 規範，漸進式 JPEG 在 TIFF 檔案中是非法的（Illegal in JPEG-in-TIFF）；libtiff 在 `tif_jpeg.c:1975-1992`（`JPEGSetupEncode`）中硬性寫死：
  ```c
  /* mozjpeg by default enables progressive JPEG, which is illegal in JPEG-in-TIFF */
  /* So explicitly disable it. */
  sp->cinfo.c.num_scans = 0;
  sp->cinfo.c.scan_info = NULL;
  ```
  強制禁止 Progressive JPEG 編碼。因此 libtiff 寫入的 JPEG strip 恆為 Baseline 單一掃描（`SOF0`），在讀取端 `TIFFReadScanline` 解析時 `TIFFjpeg_has_multiple_scans(sp)` 恆為 0（`FALSE`）。我們實作了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_JPEGPreDecode_1303/verify_poc.c)，並以 GDB 在 Line 1303 下斷點，實證多種像素變異下產出的均為 `SOF0=1, SOF2=0`，條件式恆 evaluate 為 FALSE！
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史 LLM 產生嚴重語意幻覺（誤以為 `scanline` 像素資料即為 JPEG 封包位元流），誤判為 Input Dependent。下游 SymCC 探針與種子生成器耗時 1,460 秒、進行 5 輪求解全數失敗（10,100 次分支命中，目標行 0 次命中）。編碼器程式碼路徑根本不存在生成 `SOF2` 或多重掃描的分支，路徑約束無解。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在該 Harness 的生命週期與調用拓撲下，第 1311 行為結構性不可達死碼。裁決為 **`Input Independent`**（Rule 5: Structurally Unreachable API Path / Harness Architectural Limitation & Rule 3: Observed-Path Invariants），Refined Triage Label 為 **`Structurally Unreachable API Path`**，不納入下游求解器評測（`include_in_solver_evaluation = false`）。

---

### 案例 11: `libtiff_LZMADecode_211`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libtiff_LZMADecode_211` |
| **專案名稱** | `libtiff` |
| **目標函式** | `LZMADecode` (`/src/libtiff/libtiff/tif_lzma.c:211`) |
| **分支條件** | `if (ret == LZMA_STREAM_END)` (須為 FALSE) 及 `if (ret == LZMA_MEMLIMIT_ERROR)` (須為 TRUE) |
| **阻礙目標行** | `213` ~ `229` (`lzma_ret r = lzma_stream_decoder(&sp->stream, lzma_memusage(&sp->stream), 0);`) |
| **Harness** | [`llm_fuzzgen0717111847.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libtiff/llm_fuzzgen0717111847.cc) |
| **執行期 Hit Count** | 166 次（分支被執行，但 Line 213 內部恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 忽略呼叫端不變量誤判案例)* |
| **適用規則** | **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** & **`Rule 3: Observed-Path Invariants`** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_LZMADecode_211/verify_poc.c) (實體驗證在 memlimit 為 UINT64_MAX 下 lzma_code 絕不回傳 LZMA_MEMLIMIT_ERROR) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260717_180129_libtiff`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260717_180129_libtiff)（LLM 誤判為 Dependent，導致下游 5 種求解策略耗時 1,794 秒反覆求解全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  目標函式為 `LZMADecode`（`tif_lzma.c:210-230`）。分支條件為第 211 行 `if (ret == LZMA_STREAM_END)`（須為 `FALSE`）以及第 213 行 `if (ret == LZMA_MEMLIMIT_ERROR)`（未覆蓋目標區塊，須為 `TRUE`）。要進入第 213 行內部的未覆蓋處理邏輯，變數 `ret`（型別為 `lzma_ret`）必須等於 `LZMA_MEMLIMIT_ERROR`（數值為 6）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  變數 `ret` 是底層庫 `liblzma`（XZ Utils）函式 `lzma_code(&sp->stream, LZMA_RUN)` 於第 210 行的回傳值。歷史 LLM 僅憑 API 手冊直覺推斷「若輸入流包含超大字典大小，就會因記憶體超出限制返回 `LZMA_MEMLIMIT_ERROR`」，因此錯誤認定為 `Input Dependent`。
- **Step 3: Survival & Path Invariants（函式庫不變量與防禦性死碼證明）**：
  在呼叫 `LZMADecode` 之前，解碼器狀態必須由 `LZMAPreDecode` 初始化。在 `tif_lzma.c:150-160` 中，libtiff 開發者留下了關鍵硬性設定：
  ```c
  /*
   * Disable memory limit when decoding. UINT64_MAX is a flag to disable
   * the limit, we are passing (uint64_t)-1 which should be the same.
   */
  ret = lzma_stream_decoder(&sp->stream, (uint64_t)-1, 0);
  ```
  `memlimit` 被設定為 `(uint64_t)-1`（即 `UINT64_MAX` = $18,446,744,073,709,551,615$ 位元組）。  
  深入查驗 `liblzma` 底層判定邏輯（`stream_decoder.c:220-234`），唯有 `memusage > coder->memlimit` 時才會回傳 `LZMA_MEMLIMIT_ERROR`。然而 `coder->memlimit == UINT64_MAX`，對於任何 64 位元無號整數，`memusage > UINT64_MAX` 在數學與邏輯上恆為 FALSE！若 Filter 異常，liblzma 回傳的是 `LZMA_OPTIONS_ERROR` 或 `LZMA_DATA_ERROR`，絕對不可能回傳 `LZMA_MEMLIMIT_ERROR`。我們實作了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_LZMADecode_211/verify_poc.c)，並以 GDB 追蹤 Line 154 與 Line 210，實證在 `UINT64_MAX` 限制下無論傳入何種正常或極端畸變串流，皆不可能觸發 `LZMA_MEMLIMIT_ERROR`，第 213 行為標準的防禦性死碼！
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史實驗中 LLM 產生嚴重語意幻覺（只看錯誤碼定義，忽視 PreDecode 的 limit 賦值），誤判為 Input Dependent。下游求解器（SymCC 符號執行、種子生成器）耗費 1,794 秒進行 5 輪求解全數宣告失敗（分支執行 166 次，目標行 0 次命中）。SymCC 建立 `memusage > UINT64_MAX` 約束時，底層 SMT 求解器（Z3）判定恆 UNSAT，算力完全浪費。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 4 (Internal Invariant Guard) 與 Rule 3 (Observed-Path Invariants)。Refined Triage Label 為 **`Internal Invariant Guard`**，不納入下游求解器評測（`include_in_solver_evaluation = false`）。

---

### 案例 12: `libtiff_TIFFjpeg_progress_monitor_281`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libtiff_TIFFjpeg_progress_monitor_281` |
| **專案名稱** | `libtiff` |
| **目標函式** | `TIFFjpeg_progress_monitor` (`/src/libtiff/libtiff/tif_jpeg.c:281`) |
| **分支條件** | `if (scan_no >= sp->otherSettings.max_allowed_scan_number)` |
| **阻礙目標行** | `284` ~ `293` (`TIFFErrorExtR(..., "Scan number %d exceeds maximum scans (%d)..."); jpeg_abort(cinfo); LONGJMP(...);`) |
| **Harness** | [`llm_fuzzgen0717154312.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/external/oss-fuzz/projects/libtiff/llm_fuzzgen0717154312.cc) |
| **執行期 Hit Count** | 152,000 次（分支被執行，但 Line 284 恆為 0） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 忽略 Harness 架構誤判案例)* |
| **適用規則** | **`Rule 5: Structurally Unreachable API Path / Harness Architectural Limitation`** & **`Rule 3: Observed-Path Invariants`** & **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** |
| **Refined Triage Label** | **`Structurally Unreachable API Path`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_TIFFjpeg_progress_monitor_281/verify_poc.c) (實體驗證在 Harness 寫入後讀取架構下 scan_no 恆為 1 且遠小於 100) |
| **歷史紀錄來源** | - 歷史誤判（FP）紀錄：[`experiments/20260717_180129_libtiff`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260717_180129_libtiff)（LLM 誤判為 Dependent，導致下游 5 種求解策略耗時 1,468 秒反覆求解全數失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙條件位於 `tif_jpeg.c:281` 的 `if (scan_no >= sp->otherSettings.max_allowed_scan_number)`。要進入第 284 行未覆蓋之 DoS 防護中斷處理區塊，條件式必須 evaluate 為 **`TRUE`**。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  `scan_no` 取自 `((j_decompress_ptr)cinfo)->input_scan_number`，代表當前解碼的 Scan 次數。`max_allowed_scan_number` 在 `tif_jpeg.c:413` 初始化為預設值 **`100`**（防範 Progressive JPEG 掃描炸彈引發 CPU DoS 的安全上限）。歷史 LLM 誤以為 Fuzzer 可提供超過 100 次掃描的 Progressive JPEG，因而判定為 `Input Dependent`。
- **Step 3: Survival & Path Invariants（規格不變量與 Harness 架構限制證明）**：
  Harness（`llm_fuzzgen0717154312.cc`）採用自產自銷的寫入後讀取架構。Fuzzer 輸入僅為未壓縮光柵像素，經由 `TIFFWriteScanline` 傳入 libtiff 編碼器。依據 TIFF 6.0 規範，漸進式 JPEG 在 TIFF 檔案中是非法的；libtiff 編碼器在 `tif_jpeg.c:1975-1992`（`JPEGSetupEncode`）中硬性寫死：
  ```c
  sp->cinfo.c.num_scans = 0;
  sp->cinfo.c.scan_info = NULL;
  ```
  強制禁止 Progressive JPEG 編碼。因此 libtiff 產出的 JPEG 串流永遠只有 1 次掃描（Baseline 單一掃描，`scan_no == 1`）。在讀取端 `TIFFReadScanline` 解析時，`scan_no` 恆等於 1，而 `max_allowed_scan_number` 為 100。條件式 $1 \ge 100$ 恆為 FALSE！我們實作了實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libtiff_TIFFjpeg_progress_monitor_281/verify_poc.c)，並以 GDB 實體追蹤 Line 280，實證在不同像素輸入下生成的串流僅有 1 個 SOS 標記，`scan_no == 1`，條件式恆 evaluate 為 FALSE！在歷史覆蓋率統計中該分支被執行了 **152,000 次**，Line 284 命中次數恆為 0。
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史實驗耗時 1,468 秒，歷經 5 種求解器策略全數失敗。根因在於 Harness 的寫入端根本沒有生成漸進式多重掃描的程式碼路徑，符號執行引擎面對 $1 \ge 100$ 的約束恆 UNSAT，算力完全浪費。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 5 (Structurally Unreachable API Path)、Rule 3 (Observed-Path Invariants) 與 Rule 4 (Internal Invariant Guard / Resource-Exhaustion Guard)。Refined Triage Label 為 **`Structurally Unreachable API Path`**，不納入下游求解器評測（`include_in_solver_evaluation = false`）。

---

### 案例 13: `libvpx_dec_build_inter_predictors_sb_738`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libvpx_dec_build_inter_predictors_sb_738` |
| **專案名稱** | `libvpx` |
| **目標函式** | `dec_build_inter_predictors_sb` (`/src/libvpx/vp9/decoder/vp9_decodeframe.c:738`) |
| **分支條件** | `if (!vp9_is_valid_scale(sf))` |
| **阻礙目標行** | `739` (`vpx_internal_error(xd->error_info, VPX_CODEC_UNSUP_BITSTREAM, "Reference frame has invalid dimensions");`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_dec_build_inter_predictors_sb_738/fuzz_target.cc) (原 `external/oss-fuzz/projects/libvpx/llm_fuzzgen_reference_guided_0727011112_353286.cc`) |
| **執行期 Hit Count** | 14,500,000 次（分支被頻繁執行 14.5M 次，但 Line 739 命中 0 次） |
| **Ground Truth 標籤** | **`Input Dependent`** *(歷史 LLM 分類 True Positive / 下游求解器邊界案例)* |
| **適用規則** | **`Rule 2: Semantic / Dataflow Dependent Branch`** |
| **Refined Triage Label** | **`Semantic Depth / Solver Bound`** (`include_in_solver_evaluation = true`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_dec_build_inter_predictors_sb_738/verify_poc.c) (實體驗證在尺寸倍率超過 16x 且指定非相容參照影格時直接命中 Line 739 拋出錯誤) |
| **歷史紀錄來源** | [`experiments/20260726_231453_run_all_fuzzer/blockers/dec_build_inter_predictors_sb_738/symbolic_run/libvpx_dec_build_inter_predictors_sb_20260727_142621`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260726_231453_run_all_fuzzer)（符號執行 Harness 階段超時失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `vp9_decodeframe.c:738` 的 `if (!vp9_is_valid_scale(sf))`。要進入 Line 739 執行 `vpx_internal_error(..., "Reference frame has invalid dimensions")`，述詞必須 evaluate 為 **`TRUE`**（即 `vp9_is_valid_scale(sf)` 回傳 0 / FALSE）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  條件變數 `sf` 是參照影格的縮放比例指標（`&ref_buf->sf`），其數值是在解碼 Inter 影格標頭時（`vp9_decodeframe.c:2758`），由 `vp9_setup_scale_factors_for_frame` 依據當前影格與參照影格的寬高尺寸計算而得。當前影格與參照影格的尺寸完全直接來自 Fuzzer 輸入的 IVF 位元流（Uncompressed Frame Header）。
- **Step 3: Survival & Path Invariants（規格縮放限制與標頭守衛放行推導）**：
  1. 依據 VP9 規格與 `vp9_scale.c:53` 的 `valid_ref_frame_size`，參照縮放倍率必須滿足：$2 \times W_{this} \ge W_{ref}$ 且 $W_{this} \le 16 \times W_{ref}$。若縮放比例超過 16 倍或縮小超過 2 倍，函式將 `sf->x_scale_fp` 設為 `REF_INVALID_SCALE`（-1），此時 `vp9_is_valid_scale(sf)` 回傳 0。
  2. 在影格標頭檢查（`setup_frame_size_with_refs`，Line 1586）中，解碼器檢查 `has_valid_ref_frame |= (valid_ref_frame_size(...));`。VP9 規格明確允許 Inter 影格所參照的 3 個影格中「只要有至少一個尺寸有效」即可放行通過標頭驗證。
  3. 當輸入位元流包含多個尺寸懸殊的影格（例如 Frame 0 為 32x32，Frame 1 為 128x128，Frame 2 為 600x600），Frame 2 標頭可藉由 Frame 1 滿足守衛檢查，但同時將 Frame 0（GOLDEN）標記為 `REF_INVALID_SCALE`。
  4. 隨後在巨區塊（Macroblock）預測階段，只要位元流指定參照 GOLDEN_FRAME，解碼器即進入 Line 738 並命中 Line 739 拋出錯誤。
- **Step 4: Alternative Path & Solver 失敗分析（歷史 14.5M 次未命中原因）**：
  隨機 Fuzzer 執行 14.5M 次未能命中，根因在於此分支存在 **5 重深度耦合約束**（多影格合法 IVF 序列、跨影格狀態緩存、倍率超過 16x、混合參照標頭守衛通過、巨區塊布林熵解碼模式選擇）。隨機突變器在天文數字級的搜尋空間下機率趨近於 0；下游符號執行（SymCC）在處理跨多影格與布林熵解碼狀態求解時超出了求解能力邊界。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Dependent`**，適用 Rule 2 (Semantic / Dataflow Dependent Branch)。歷史 LLM 分類器的判定為 **True Positive**。已在案例目錄建立實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_dec_build_inter_predictors_sb_738/verify_poc.c)，實測證明直接進入 Line 738/739 並捕獲 `VPX_CODEC_UNSUP_BITSTREAM`（"Reference frame has invalid dimensions"）。

---

### 案例 14: `libvpx_read_uncompressed_header_2717`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libvpx_read_uncompressed_header_2717` |
| **專案名稱** | `libvpx` |
| **目標函式** | `read_uncompressed_header` (`/src/libvpx/vp9/decoder/vp9_decodeframe.c:2717`) |
| **分支條件** | `if (cm->profile > PROFILE_0)` |
| **阻礙目標行** | `2718` (`read_bitdepth_colorspace_sampling(cm, rb);`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_read_uncompressed_header_2717/fuzz_target.cc) (原 `external/oss-fuzz/projects/libvpx/llm_fuzzgen_dedicated_generation_0727001606_033744.cc`) |
| **執行期 Hit Count** | 115 次（分支僅被評估 115 次且全為 FALSE，Line 2718 命中 0 次） |
| **Ground Truth 標籤** | **`Input Dependent`** *(歷史 LLM 分類 True Positive / 直接資料流控制)* |
| **適用規則** | **`Rule 1: Direct Data Flow`** / **`Rule 2: Semantic / Dataflow Dependent Branch`** |
| **Refined Triage Label** | **`Semantic Depth / Solver Bound`** (`include_in_solver_evaluation = true`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_read_uncompressed_header_2717/verify_poc.c) (實體驗證直接透過 `vpx_codec_decode` 餵入 Profile 1 構造位元流，100% 進入 Line 2718) |
| **歷史紀錄來源** | [`experiments/20260726_231453_run_all_fuzzer/blockers/read_uncompressed_header_2717/symbolic_run/libvpx_read_uncompressed_header_20260728_062518`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260726_231453_run_all_fuzzer)（符號執行 Harness Fidelity 階段失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `vp9_decodeframe.c:2717` 的 `if (cm->profile > PROFILE_0)`。要進入 Line 2718 執行 `read_bitdepth_colorspace_sampling(cm, rb)`，述詞必須 evaluate 為 **`TRUE`**（即 `cm->profile` 設定為 `PROFILE_1`, `PROFILE_2`, 或 `PROFILE_3`）。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  條件變數 `cm->profile` 是在 `read_uncompressed_header` 第 2655 行呼叫 `vp9_read_profile(rb)` 直接由輸入位元流開頭第 2、3 個 bit 解碼所得。Fuzzer 傳入之 raw buffer 經由 `vpx_codec_decode` 傳遞，資料直接映射至此變數，屬於最純粹的 Rule 1 直接資料流（Direct Data Flow）。
- **Step 3: Survival & Path Invariants（路徑可行性推導）**：
  要到達 Line 2717 並使條件成立，輸入位元流僅需依序具備以下欄位：
  1. Frame Marker（2 bits: `0b10`）；
  2. Profile（2 bits: 設定為 `1`，即 `PROFILE_1`，滿足 `1 > 0`）；
  3. Show Existing Frame（1 bit: `0`）；
  4. Frame Type（1 bit: `1`，非 Keyframe）；
  5. Show Frame（1 bit: `0`，不可見影格，使第 2708 行解析出 `cm->intra_only = 1`）；
  6. Intra-only Flag（1 bit: `1`）；
  7. Reset Frame Context（2 bits: `0b00`）；
  8. Sync Code（24 bits: `0x49 0x83 0x42`，通過第 2714 行檢查）。
  上述標頭總計僅需不到 5 個位元組，在解碼器規格中完全合法。到達 Line 2717 後，`cm->profile > PROFILE_0` 必然為 TRUE，直接執行 Line 2718 的 `read_bitdepth_colorspace_sampling(cm, rb)`。
- **Step 4: Alternative Path & Solver 失敗分析（歷史未命中原因）**：
  歷史 Fuzzing 中該分支僅被命中 115 次且全為 FALSE，根因在於標準測試語料與隨機生成資料 99.9% 均為 Profile 0（YUV 4:2:0），隨機突變器極難自然拼湊出 Profile 1 與不可見 Intra-only 影格的特殊複合標頭。歷史 LLM 的 Input Dependent 分類為 **True Positive**，下游符號執行未能突破屬於語意引導與求解器探索能力邊界（Solver Capability Limit）。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Dependent`**，適用 Rule 1 (Direct Data Flow) 與 Rule 2 (Semantic / Dataflow Dependent Branch)。已在案例目錄建立實體驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_read_uncompressed_header_2717/verify_poc.c)，透過呼叫 `vpx_codec_decode` 實測證明直接進入 Line 2718 並觸發 `read_bitdepth_colorspace_sampling` 內部邏輯。

---

### 案例 15: `libvpx_vpx_free_frame_buffer_138`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `libvpx_vpx_free_frame_buffer_138` |
| **專案名稱** | `libvpx` |
| **目標函式** | `vpx_free_frame_buffer` (`/src/libvpx/vpx_scale/generic/yv12config.c:138`) |
| **分支條件** | `if (ybf->buffer_alloc_sz > 0)` |
| **阻礙目標行** | `139` (`vpx_free(ybf->buffer_alloc);`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_vpx_free_frame_buffer_138/fuzz_target.cc) (原 `external/oss-fuzz/projects/libvpx/llm_fuzzgen_reference_guided_0727011112_353286.cc`) |
| **執行期 Hit Count** | 77.0k 次（分支頻繁被評估 77,000 次且全為 FALSE，Line 139 命中 0 次） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 分類誤判 False Positive / 內部架構不變量)* |
| **適用規則** | **`Rule 3: Observed-Path Invariants`** / **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_vpx_free_frame_buffer_138/verify_poc.c) (實體驗證即使成功解碼多影格，BufferPool 全部 12 個 frame buffers 的 `buffer_alloc_sz` 亦全部恆為 0) |
| **歷史紀錄來源** | [`experiments/20260726_231453_run_all_fuzzer/blockers/vpx_free_frame_buffer_138/symbolic_run/libvpx_vpx_free_frame_buffer_20260727_065341`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260726_231453_run_all_fuzzer)（符號執行 Harness Generation 階段失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `yv12config.c:138` 的 `if (ybf->buffer_alloc_sz > 0)`。要進入 Line 139 執行 `vpx_free(ybf->buffer_alloc)`，述詞必須 evaluate 為 **`TRUE`**（即 `ybf->buffer_alloc_sz > 0`）。
- **Step 2: Producer & Input Control（歷史 LLM 誤判根因）**：
  歷史 LLM 認為：只要解碼器成功解析並解碼有效的視訊影格，系統就會配置 frame buffer 並設定 `buffer_alloc_sz > 0`。然而，這完全忽略了 VP9 解碼器的底層 Frame Buffer Callbacks 架構機制。
- **Step 3: Survival & Path Invariants（內部架構不變量證明）**：
  1. 通用緩衝區函式 `yv12config.c:34` 白紙黑字明確註釋：
     `// If libvpx is using frame buffer callbacks then buffer_alloc_sz must not be set.`
  2. 在 VP9 解碼器工作流程中（`vp9_dx_iface.c:216`），解碼器初始化時強制啟用回調機制（`pool->get_fb_cb = vp9_get_frame_buffer; pool->release_fb_cb = vp9_release_frame_buffer;`，即 `cb != NULL`）。
  3. 在動態配置影格緩衝區時（`yv12config.c:211-224` 的 `vpx_realloc_frame_buffer`），當 `cb != NULL` 時，記憶體完全由回調函式配置於 `raw_frame_buffer`，`ybf->buffer_alloc` 僅指向外部對齊地址，而 `ybf->buffer_alloc_sz` 嚴格保持為 0，絕不設置。
  4. 在解碼器銷毀時（`vp9_alloccommon.c:82-88` 的 `vp9_free_ref_buffers`），緩衝區記憶體由 `pool->release_fb_cb` 統一回收，隨後調用 `vpx_free_frame_buffer(&pool->frame_bufs[i].buf)`。
  5. 此時 `ybf->buffer_alloc_sz` 恆等於 0，Line 138 的條件恆為 FALSE。若在此處執行 Line 139 呼叫 `vpx_free(ybf->buffer_alloc)` 反而會觸發 Double Free 毀損 Heap。因此 Line 138 是標準的內部不變量保護守衛，Line 139 在 VP9 解碼器路徑下恆不可達。
- **Step 4: Alternative Path & Feasibility Check**：
  在當前 Harness（調用 `vpx_codec_dec_init` 與 `vpx_codec_decode` 的 VP9 解碼架構）下，Frame Buffer Callbacks 是強制啟用的內部核心機制，外部輸入資料流無法改變解碼器的架構配置流程。因此該分支在現行呼叫路徑下不可能被觸發。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 3 (Observed-Path Invariants) 與 Rule 4 (Internal Invariant Guard / Redundant Defensive Code)。歷史 LLM 分類器的判定為 **False Positive**。已在案例目錄建立驗證程式 [`verify_poc.c`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/libvpx_vpx_free_frame_buffer_138/verify_poc.c)，實測解碼多個合法 64x64 VP9 影格，檢查 BufferPool 中全部 12 個緩衝區，證實 `buffer_alloc_sz` 全部恆為 0。歷史執行統計中 77,000 次評估中 Line 139 命中次數為 0，確證為絕對的 Input Independent。

---

### 案例 16: `tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176` |
| **專案名稱** | `tinyxml2` |
| **目標函式** | `tinyxml2::XMLNode::ParseDeep` (`/src/tinyxml2/tinyxml2.cpp:1176`) |
| **分支條件** | `if ( ele->ClosingType() != XMLElement::OPEN )` |
| **阻礙目標行** | `1177` (`mismatch = true;`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176/fuzz_target.cc) (原 `external/oss-fuzz/projects/tinyxml2/llm_fuzzgen0726233106.cc`) |
| **執行期 Hit Count** | 108.0k 次（分支頻繁被評估 108,000 次且全為 FALSE，Line 1177 命中 0 次） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 分類誤判 False Positive / 變數作用域幻覺)* |
| **適用規則** | **`Rule 3: Observed-Path Invariants`** & **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176/verify_poc.cc) (實體驗證在各類合法、畸變與不匹配 XML 結構下，若 `!endTag.Empty()` 則 `ele->ClosingType()` 恆為 `OPEN`，Line 1177 確證為防禦性死碼) |
| **歷史紀錄來源** | [`experiments/20260804_034935_run_all_fuzzer/blockers/tinyxml2::XMLNode::ParseDeep(char*, tinyxml2::StrPair*, int*)_1176/symbolic_run/tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_20260804_045703`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260804_034935_tinyxml2)（符號執行 Harness Generation 階段失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `tinyxml2.cpp:1176` 的 `if ( ele->ClosingType() != XMLElement::OPEN )`。要進入 Line 1177 執行 `mismatch = true;`，必須滿足外層 `else` 條件（即 `!endTag.Empty()` 為 TRUE），且當前元素 `ele->ClosingType() != XMLElement::OPEN` 為 TRUE。
- **Step 2: Producer & Input Control（歷史 LLM 誤判根因）**：
  歷史 LLM 產生嚴重的變數作用域幻覺（Variable Scope Hallucination），認為輸入 `<root><child></child><sibling/></root>` 時，子元素 child 返回的 endTag 會殘留並污染下一個 sibling 元素。然而，`StrPair endTag;` 是宣告於 `while(p && *p)` 迴圈內部的區域變數，每輪迴圈重新構造為 empty，跨節點污染在語意上完全不可能發生。
- **Step 3: Survival & Path Invariants（狀態機與解析不變量證明）**：
  1. `parentEndTag` 唯一被寫入的時機為 `ele->ClosingType() == XMLElement::CLOSING`（`tinyxml2.cpp:1158`），此時直接 `return p;`，不進入 Line 1167 以下的任何檢查。
  2. 若元素為自閉合標籤 `CLOSED`（`<tag/>`），`XMLElement::ParseDeep` 在 Line 2100 檢查 `_closingType != OPEN` 後立即 return，根本不調用下層遞迴，`endTag` 恆為 empty，只走 Line 1170 的 `if`，絕不進入 Line 1175 的 `else` 區塊。
  3. 唯有當前元素為 `OPEN` 時，才會將 `endTag` 傳遞給子層；若子層閉合返回非空標籤名（`!endTag.Empty()`），當前元素的 `_closingType` 必然為 `OPEN`。
  4. 因此在 Line 1175 的 `else` 區塊中，`ele->ClosingType() != XMLElement::OPEN` 恆為 FALSE，Line 1177 為標準的內部對稱防禦性死碼。
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史實驗中 Line 1176 評估 108,000 次，Line 1177 命中 0 次。下游符號執行（SymCC）耗時 778 秒全滅失敗。實測插樁與多組極端 XML 解析驗證，證實各類不匹配標籤僅會進入 Line 1180（名稱不符），Line 1177 恆不可達。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 3 (Observed-Path Invariants) 與 Rule 4 (Internal Invariant Guard / Redundant Defensive Code)。歷史 LLM 分類器的判定為 **False Positive**。已在案例目錄建立驗證程式 [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176/verify_poc.cc)，實測證明 Line 1177 確證為防禦性死碼。

---

### 案例 17: `tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494` |
| **專案名稱** | `tomlplusplus` |
| **目標函式** | `toml::v3::at_path(toml::v3::node&, toml::v3::path const&)` (`/src/tomlplusplus/include/toml++/impl/path.inl:494`，對應單標頭檔 `toml.hpp:11760`) |
| **分支條件** | `else if (type == path_component_type::key)` |
| **阻礙目標行** | `505` (`return {};`，位於 `else` 分支) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494/fuzz_target.cc) (原 `external/oss-fuzz/projects/tomlplusplus/llm_fuzzgen0727210908.cc`) |
| **執行期 Hit Count** | 4.96k 次（分支頻繁被評估 4,960 次且全為 FALSE，Line 505 命中 0 次） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 分類誤判 False Positive / 型別解析幻覺)* |
| **適用規則** | **`Rule 3: Observed-Path Invariants`** & **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494/verify_poc.cc) (實體驗證在各類正常、畸變與語法錯誤路徑下，組件型別嚴格為 `key` 或 `array_index`，語法錯誤直接回滾組件數為 0，Line 505 確證為防禦性死碼) |
| **歷史紀錄來源** | [`experiments/20260806_154151_run_all_fuzzer/blockers/blocker_494_fa7e286141ef/symbolic_run/tomlplusplus_blocker_494_fa7e286141ef_symbolic_run_20260806_214902`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260806_154151_tomlplusplus)（符號執行 Harness Generation 階段失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `path.inl:494`（單標頭檔 `toml.hpp:11760`）的 `else if (type == path_component_type::key)`。要進入 Line 505 / 11771 執行 `return {};`，必須使 `type == path_component_type::array_index` 與 `type == path_component_type::key` 兩者皆為 FALSE，即 `component.type()` 既非 `array_index` 也非 `key`。
- **Step 2: Producer & Input Control（歷史 LLM 誤判根因）**：
  歷史 LLM 產生型別解析幻覺（Enum Extensibility Hallucination），誤以為提供語法錯誤的路徑字串時，解析器會建立型別未知的非法組件。然而，toml++ 採用 C++ 封閉列舉（`TOML_CLOSED_ENUM`），且解析器在語法錯誤時直接回滾返回 `false`，組件數歸零，根本不生成任何無效型別組件。
- **Step 3: Survival & Path Invariants（型別系統與解析不變量證明）**：
  1. `enum class path_component_type : uint8_t` 嚴格僅定義 `key = 0x1` 與 `array_index = 0x2` 兩種值。
  2. `path_component` 的所有建構子保證 `type_` 只能為此二者之一，全庫無任何 API 可賦予第三種數值。
  3. 解析器 `impl::parse_path` 在遭遇語法錯誤時直接返回 `false` 並清除已解析組件，絕不建立未知型別組件。
  4. 因此進入 `at_path` 迴圈的任何組件，其型別必命中 `array_index` 或 `key`。Line 505 的 `else` 區塊純屬作者為防範未知型別所寫下的防禦性死碼。
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史實驗中 Line 494 評估 4,960 次，Line 505 命中 0 次。下游符號執行（SymCC）耗費 1,175 秒歷經 5 輪全滅失敗。實測驗證覆蓋 12 種各類正常、畸變與極端路徑字串，證實組件型別嚴格為 `key` 或 `array_index`，Line 505 恆不可達。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 3 (Observed-Path Invariants) 與 Rule 4 (Internal Invariant Guard / Redundant Defensive Code)。歷史 LLM 分類器的判定為 **False Positive**。已在案例目錄建立驗證程式 [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494/verify_poc.cc)，實測證明 Line 505 確證為防禦性死碼。

---

### 案例 18: `tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567` |
| **專案名稱** | `tomlplusplus` |
| **目標函式** | `void toml::v3::impl::print_floating_point_to_stream<double>` (`/src/tomlplusplus/include/toml++/impl/print_to_stream.inl:209`，對應單標頭檔 `toml.hpp:10567`) |
| **分支條件** | `if (!!(format & value_flags::format_as_hexadecimal))` |
| **阻礙目標行** | `10568` (`ss << std::hexfloat;`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567/fuzz_target.cc) (原 `external/oss-fuzz/projects/tomlplusplus/llm_fuzzgen0728070146.cc`) |
| **執行期 Hit Count** | 3.16k 次（分支頻繁被評估 3,160 次且全為 FALSE，Line 10568 命中 0 次） |
| **Ground Truth 標籤** | **`Input Independent`** *(歷史 LLM 分類誤判 False Positive / 三重語意幻覺)* |
| **適用規則** | **`Rule 3: Observed-Path Invariants`** & **`Rule 4: Internal Invariant Guard / Redundant Defensive Code`** & **`Rule 5: Fuzz Target Hardcoded Logic & Incomplete Scope`** |
| **Refined Triage Label** | **`Internal Invariant Guard`** (`include_in_solver_evaluation = false`) |
| **驗證程式** | [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567/verify_poc.cc) (實體驗證 TOML 1.0.0 標準禁止 hex float，且 `yaml_formatter` 在呼叫 `print_to_stream` 時硬編碼 `value_flags::none`，Line 10568 確證為防禦性死碼) |
| **歷史紀錄來源** | [`experiments/20260806_154151_run_all_fuzzer/blockers/blocker_10567_75f87f208b7d/symbolic_run/tomlplusplus_blocker_10567_75f87f208b7d_symbolic_run_20260806_201030`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260806_154151_tomlplusplus)（符號執行 Harness Generation 階段失敗） |

#### 程式碼因果推導與證明（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  阻礙述詞位於 `print_to_stream.inl:209`（單標頭檔 `toml.hpp:10567`）的 `if (!!(format & value_flags::format_as_hexadecimal))`。要進入 Line 10568 執行 `ss << std::hexfloat;`，傳入之 `format` 參數必須含有 `format_as_hexadecimal` (0x3) 旗標，條件式必須評估為 TRUE。
- **Step 2: Producer & Input Control（歷史 LLM 誤判根因）**：
  歷史 LLM 產生嚴重語意幻覺，誤以為 TOML 標準支援十六進位浮點數（如 `0x1.2p-3`），且誤以為解析器會為 `value<double>` 設定該旗標並由 `yaml_formatter` 透傳。然而 TOML 1.0.0 官方規範禁止十六進位浮點數，且格式化器內部硬編碼 `value_flags::none`，旗標完全無法抵達述詞。
- **Step 3: Survival & Path Invariants（規格與程式碼三重鎖死證明）**：
  1. 第一重鎖（TOML 規範禁止）：TOML 1.0.0 規範禁止十六進位浮點數，`toml::parse` 遭遇 `0x1.2p-3` 會直接拋出解析錯誤中斷。
  2. 第二重鎖（解析器內部賦值）：解析器 `parser.inl` 僅對整數 `int64_t` 設定 `format_as_hexadecimal`，全代碼庫從未對任何浮點數節點設定該旗標。
  3. 第三重鎖（格式化器硬編碼）：在 Fuzz Target 觸發的 `yaml_formatter` 流程中，基底類別 `formatter::print(const value<double>&)` 在調用 `print_to_stream` 時硬編碼傳遞常數 `value_flags::none` (0)。因此在當前路徑下 `format` 恆為 0，條件式恆為 FALSE，Line 10568 確證為防禦性死碼。
- **Step 4: Alternative Path & Solver 失敗分析（歷史求解器全滅根因）**：
  歷史實驗中 Line 10567 被評估 3,160 次，Line 10568 命中 0 次。下游符號執行（SymCC）生成 Harness 全滅失敗。實測驗證證實 hex float 無法通過解析器，且手動強制注入旗標亦會被 `yaml_formatter` 硬編碼常數阻斷，Line 10568 在該路徑下恆不可達。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  裁決為 **`Input Independent`**，適用 Rule 3 (Observed-Path Invariants)、Rule 4 (Internal Invariant Guard / Redundant Defensive Code) 與 Rule 5 (Fuzz Target Hardcoded Logic & Incomplete Scope)。歷史 LLM 分類器的判定為 **False Positive**。已在案例目錄建立驗證程式 [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567/verify_poc.cc)，實測證明 Line 10568 確證為防禦性死碼。

---

### 案例 19: `tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416`

| 欄位 | 內容 |
| :--- | :--- |
| **案例 ID** | `tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416` |
| **專案名稱** | `tomlplusplus` |
| **目標函式** | `toml::v3::stdopt::operator<(const date_time&, const date_time&)` (`/src/tomlplusplus/include/toml++/impl/date_time.hpp:416`) |
| **分支條件** | `if (lhs.time != rhs.time)` |
| **阻礙目標行** | `417` (`return lhs.time < rhs.time;`) |
| **Harness** | [`fuzz_target.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416/fuzz_target.cc) (原 `external/oss-fuzz/projects/tomlplusplus/llm_fuzzgen0727161637.cc`，已比對逐字相同) |
| **執行期 Hit Count** | 153 次（Line 416 每次皆為 FALSE，Line 417 命中 0 次） |
| **Ground Truth 標籤** | **`Input Dependent`** *(歷史 LLM 判定正確，True Positive)* |
| **適用規則** | **`Rule 1: Direct Data Flow`** |
| **Refined Triage Label** | **`Bounded Extreme Value`** (`include_in_solver_evaluation = true`，evidence `A`) |
| **驗證程式** | [`verify_poc.cc`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416/verify_poc.cc) + [`run_verify.sh`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/selected_cases/tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416/run_verify.sh)（原封不動 include harness，依 FDP 消耗語意構造 seed，以 clang source-based coverage 實測 Line 417 命中） |
| **歷史紀錄來源** | [`experiments/20260806_154151_run_all_fuzzer/blockers/blocker_416_63778a5501ad/symbolic_run/tomlplusplus_blocker_416_63778a5501ad_symbolic_run_20260806_233034`](file:///home/peason/projects/LLM-FuzzGen-Pearson/experiments/20260806_154151_tomlplusplus)（共兩次 pipeline：原 target 於 `symcc_harness_generation` 以 `llm_error` 中止，耗時 1,506 秒；reference-guided target `llm_fuzzgen_reference_guided_0806230505_691376` 於 `symcc_harness_fidelity_preflight_replan_02` 失敗，耗時 1,450 秒） |

#### 程式碼因果推導與 POC 實證（Protocol 5 步審查）：

- **Step 1: Predicate & Target State（目標條件與分支方向）**：
  `operator<` 的實作為：
  ```cpp
  if (lhs.date != rhs.date)   // 414
      return lhs.date < rhs.date;
  if (lhs.time != rhs.time)   // 416 ← 阻礙述詞
      return lhs.time < rhs.time;  // 417 ← 阻礙目標行
  return lhs.offset < rhs.offset;  // 418
  ```
  要執行 Line 417，必須讓兩個 `date_time` **日期相同（通過 414）且時間不同（416 為 TRUE）**。
- **Step 2: Producer & Input Control（生產者與資料流追蹤）**：
  harness 第 343–349 行對每個 date_time 節點執行 `*dt < *first_date_time` 與 `*dt >= *first_date_time`（`>=` 內部呼叫 `operator<`）。兩個運算元皆來自 `toml::parse(toml_string)`，而 `toml_string` 由第 18 行 `fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024))` 取得，fuzzer 可完整控制其內容（**Direct Data Flow**）。另外第 50 / 54 行可用 `ConsumeBool` 開關硬編碼的 `ldt1/ldt2`、`odt1/odt2` 片段。
- **Step 3: Survival & Path Invariants（歷史狀態成因分析）**：
  解析出的 date/time 欄位直接存入 `value<date_time>`，比較前沒有任何改寫，**不存在路徑不變量**。歷史上 416 被評估 153 次、417 恆為 0 的原因如下：harness 硬編碼片段中，**同日期的配對時間也恰好相同**。
  | 硬編碼值 | 日期 | 時間 | offset |
  | :--- | :--- | :--- | :--- |
  | `ldt2` | 1981-02-10 | 10:00:00 | 無 |
  | `odt2` | 1981-02-10 | 10:00:00 | -05:00 |
  | `ldt1` | 1979-05-27 | 07:32:00 | 無 |
  | `odt1` | 1979-05-27 | 07:32:00 | -07:00 |

  `toml::table` 是有序 map，走訪時以 stack 反序彈出，所以 `odt2` 成為 `first_date_time`。`ldt2` 與它比較時日期、時間都相同，416 為 FALSE，落到 418 的 offset 比較。這是 harness 硬編碼資料造成的巧合，不是程式語意上的限制；fuzzer 只要在 random string 中多提供一個同日期、不同時間的 date_time，就能打破。
- **Step 4: Alternative Path & Feasibility（POC 實證與求解器失敗分析）**：
  - **可行性**：不需要修改 harness，也不需要 OOM 或環境失敗；所需值是合法、有限的 TOML local date-time（RFC 3339）。
  - **POC 設計**：`verify_poc.cc` 直接 `#include "fuzz_target.cc"`。harness 中的絕對路徑 `/src/tomlplusplus/...` 由 `run_verify.sh` 以 `clang -ivfsoverlay` 導向本機 source，**harness 原始碼零修改**。`SeedBuilder` 依 FuzzedDataProvider 的消耗語意精確構造 byte stream：字串從前端取，整數與 bool 從尾端取，多位元組整數中先取出的位元組為高位。編碼順序逐行對應 harness 第 18–352 行的控制流程。產生 seed 後，再用真正的 `FuzzedDataProvider` 重建 TOML 文字並自我檢查。
  - **Coverage 實測**（LLVM 18.1.8，編譯參數與 OSS-Fuzz `build.sh` 相同，皆為 `-std=c++17 -DNDEBUG`）：
    | Seed | 輸入內容 | L414 | L416 | **L417** | L418 |
    | :--- | :--- | ---: | ---: | ---: | ---: |
    | `seed0_negative_control`（114 B） | 空 random string，只開啟硬編碼 ldt/odt | 6 | 2 | **0** | 2 |
    | `seed1_minimal`（120 B） | `a = 2024-01-01T10:00:00` / `b = 2024-01-01T12:00:00` | 2 | 2 | **2** | 0 |
    | `seed2_with_hardcoded`（117 B） | random string 只有 `x = 1979-05-27T08:00:00`，另開啟硬編碼 ldt | 4 | 2 | **2** | 0 |

    對照組精確重現了歷史的「416 有 hit、417 = 0」；兩顆正向 seed 都實際執行到 Line 417。
  - **求解器失敗原因（推論）**：這個 harness 的 FDP 編碼要求 TOML 文字放在 buffer 前端，同時約 70 個控制 bool 必須從尾端精確對齊，才能讓走訪迴圈跑到比較運算，並打開 `<` / `>=` 的 `ConsumeBool`。只會寫 TOML 文字的 LLM seed generator，難以同時滿足 byte 層級的佈局。第一次 pipeline 另外在 harness generation 階段以 `llm_error` 中止，未真正進入 SymCC 求解。
- **Step 5: Final Adjudication & Triage Decision（最終裁決與評測判定）**：
  在不修改目前 fuzz target 的前提下，fuzzer 輸入 bytes 可以讓程式執行到 Line 417，已由 coverage 實測證實。歷史 LLM 分類器判為 `Input Dependent` 是正確判定（**True Positive**），它在 reason 裡舉的例子（兩個同日期不同時間的 date_time）就是可行解。裁決為 **`Input Dependent`**（Rule 1），Refined Triage Label 為 **`Bounded Extreme Value`**，`include_in_solver_evaluation = true`。**這是求解器能力不足的失敗，不是分類器 FP。**

---

## 二、 待診斷案例庫（Pending Cases）

已透過 [`ground_truth/extract_dependent_failed.py`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/extract_dependent_failed.py) 匯入候選池，排除已驗證之案例後，剩餘 **49 個獨立 Blocker 案例** 位於 [`ground_truth/cases/pending_cases/`](file:///home/peason/projects/LLM-FuzzGen-Pearson/ground_truth/cases/pending_cases/)。

---

## 三、 案例收集進度表

- **Selected Cases（已選入基準集）**：**19 例**
  - [x] **Case 01**: `cjson_update_offset_547` (已確立為 `Input Independent` / Internal Invariant Guard)
  - [x] **Case 02**: `cjson_cJSON_Duplicate_rec_2772` (已確立為 `Input Independent` / Resource-Exhaustion Guard)
  - [x] **Case 03**: `cjson_print_number_602` (已確立為 `Input Independent` / Internal Invariant Guard)
  - [x] **Case 04**: `lcms_cmsCreateExtendedTransform_1239` (已確立為 `Input Independent` / Structurally Unreachable API Path)
  - [x] **Case 05**: `lcms_cmsDetectDestinationBlackPoint_442` (已確立為 `Input Dependent` / Bounded Extreme Value)
  - [x] **Case 06**: `lcms_cmsIT8GetData_2865` (已確立為 `Input Dependent` / Bounded Extreme Value，附驗證程式)
  - [x] **Case 07**: `libpcap_gen_ncode_7517` (已確立為 `Input Dependent` / Bounded Extreme Value，附驗證程式)
  - [x] **Case 08**: `libpcap_gen_scode_7226` (已確立為 `Input Independent` / External Resource Failure，附反向實證 PoC)
  - [x] **Case 09**: `libpcap_iface_dsa_get_proto_info_5730` (已確立為 `Input Independent` / External Resource Failure，附反向實證 PoC)
  - [x] **Case 10**: `libtiff_JPEGPreDecode_1303` (已確立為 `Input Independent` / Structurally Unreachable API Path，附反向實證 PoC)
  - [x] **Case 11**: `libtiff_LZMADecode_211` (已確立為 `Input Independent` / Internal Invariant Guard，附反向實證 PoC)
  - [x] **Case 12**: `libtiff_TIFFjpeg_progress_monitor_281` (已確立為 `Input Independent` / Structurally Unreachable API Path，附反向實證 PoC)
  - [x] **Case 13**: `libvpx_dec_build_inter_predictors_sb_738` (已確立為 `Input Dependent` / Semantic Depth / Solver Bound，附驗證程式)
  - [x] **Case 14**: `libvpx_read_uncompressed_header_2717` (已確立為 `Input Dependent` / Direct Data Flow / Solver Bound，附驗證程式)
  - [x] **Case 15**: `libvpx_vpx_free_frame_buffer_138` (已確立為 `Input Independent` / Internal Invariant Guard，附驗證程式)
  - [x] **Case 16**: `tinyxml2_tinyxml2_XMLNode_ParseDeep_char_tinyxml2_StrPair_int_1176` (已確立為 `Input Independent` / Internal Invariant Guard，附驗證程式)
  - [x] **Case 17**: `tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494` (已確立為 `Input Independent` / Internal Invariant Guard，附驗證程式)
  - [x] **Case 18**: `tomlplusplus_void_toml_v3_impl_print_floating_point_to_stream_double_std_1_basic_ostream_char_10567` (已確立為 `Input Independent` / Internal Invariant Guard，附驗證程式)
  - [x] **Case 19**: `tomlplusplus_toml_v3_stdopt_operator_toml_v3_stdopt_date_time_const_toml_v3_stdopt_date_time__416` (已確立為 `Input Dependent` / Bounded Extreme Value，附 coverage 實測 POC)
- **Pending Cases（待診斷審查）**：
  - [ ] 49 個候選案例位於 `ground_truth/cases/pending_cases/`，待逐一審查並移入 `selected_cases/`。



