# LLM Seed Generator — 系統設計、運作邏輯與討論

> **用途**：此文件供跨 session 溝通用。完整描述 LLM seed generator 子系統的架構、迭代流程、評估機制、與 SeedMind 論文的差異，以及尚未解決的設計疑慮。

---

## 一、系統定位

LLM seed generator 是 LLM-FuzzGen 的 Stage 1（種子生成），目標是透過 LLM 生成針對特定「blocker branch」設計的種子，讓 fuzzer 能進入原本從未到達的 code path。

整個 dependent pipeline 的流程：

```
Stage 1: LLM seed generator
  → 生成針對特定 blocker 的 Python generator，執行後產生種子
  → 如果種子直接解決了 blocker → done
  → 否則（stalled_at_branch 等） → 進入 Stage 3

Stage 3a: SymCC probe on original target
  → 用 SymCC 符號執行原始 fuzz target + blocker source
  → 如果 SymCC 直接解 blocker → done

Stage 2: LLM harness generator
  → 生成更適合 SymCC 的 harness（比原始 fuzz target 更簡潔，減少符號噪音）

Stage 3b: libFuzzer focused pass（可選）
  → 用 libFuzzer 在 harness 上跑一段時間，豐富起始種子

Stage 3c: SymCC on generated harness
  → 用 SymCC 符號執行生成的 harness
  → 期望產生能越過 blocked side 條件的輸入
```

---

## 二、Generator 的核心設計原則

### 為什麼不直接輸出種子？

| 面向 | 直接輸出 seeds | Python generator |
|---|---|---|
| Binary 格式 | LLM 必須輸出 hex/base64，100 個種子 × 1KB ≈ 100KB token 浪費 | `struct.pack()` 在執行時生成 binary，LLM 只輸出程式邏輯 |
| 種子數量 | 每次 LLM call ~5-10 個 | generator 一跑可產 100-1000 個（for-loop/range） |
| Family tracking | 無結構，不知哪類輸入有效 | filename 帶穩定 tag（`F01_xxx_01.bin`），可按 family 統計 |
| 跨 iteration 精煉 | 每次都重新生成所有種子，丟掉所有歷史資訊 | 每個 family 獨立 keep/refine/discard，保留有效假設 |
| 假設空間覆蓋 | 接近單點猜測 | range enumeration / 笛卡兒積，系統性掃描假設空間 |
| 可維護性 | 一堆不知意義的二進位檔案 | 程式碼明確記載「為何這組種子能觸發 blocker」 |

### Generator 的標準介面

```python
def build_seeds() -> list[tuple[str, bytes]]:
    """
    Returns: list of (filename, payload)
    filename 必須帶穩定 family tag，如 F01_structured_base_01.bpf
    """
    seeds = []
    # F01: 假設 A
    seeds.append(("F01_hypothesis_a_01.ext", b"..."))
    # F02: 假設 B
    for val in range(0, 256, 16):  # range enumeration
        seeds.append((f"F02_range_{val:03d}.ext", struct.pack(">B", val) + b"..."))
    return seeds

# 必須支援
# python generator.py --output-dir DIR
```

---

## 三、迭代流程（3 次迭代上限）

### 每次迭代的步驟

```
迭代 N:
  1. LLM 生成（或修改）generator.py
     - 第一次迭代：從 blocker 分析出發，設計初始 families
     - 後續迭代：收到上一輪的 feedback（哪些 family 有效/無效），更新策略

  2. 驗證 generator（語法、能否跑通）

  3. 執行 generator → 產生種子（materialize seeds）

  4. 把新種子加入 corpus（去重後）

  5. Coverage 評估（Docker 內跑 coverage binary）
     - 每個 family 取前 N 個代表種子（預設每新 family 2 個，最多 12 個總共）
     - 每個代表種子：在 Docker 裡跑 `coverage_binary -runs=1 seed_path`
     - 從 llvm-cov 輸出取得 branch_hit_count 和 blocked_side_hit_count

  6. 評估迭代結果 → 分類 iteration_status（見下節）

  7. 生成 Family summary（keep/refine/discard）→ 作為下一輪的 LLM prompt context
```

### 迭代狀態（iteration_status）

| 狀態 | 意義 | 下一步 |
|---|---|---|
| `solved` | 新種子直接到達 blocked_side → blocker 解決 | 結束，`terminal_reason = blocked_side_reached` |
| `already_covered_in_baseline` | baseline corpus 已能覆蓋 blocked_side（在加入新種子前就到了） | 結束，blocker 已解 |
| `coverage_progress` | blocked_side hit 增加，或 branch hit 增加 | 繼續下一輪（`coverage_progress_iteration_count++`） |
| `family_progress` | family signal score 上升（更多種子到達 branch），但 coverage 數字沒變 | 繼續下一輪（`family_progress_iteration_count++`） |
| `stalled_at_branch` | 種子能到 branch，但條件始終不滿足（`blocked_side_hit = 0`） | 繼續（或結束後交給 SymCC） |
| `no_branch_signal` | 種子連 branch 都到不了 | 繼續（LLM 改假設） |
| `invalid_generator` | generator 語法錯誤或執行失敗 | 有 repair 機制（最多 2 次修復嘗試） |
| `evaluation_failed` | Docker coverage 評估失敗 | 記錄錯誤，繼續 |

### 最終 terminal_reason（所有迭代結束後）

優先序（由高到低）：

```python
if success:
    terminal_reason = "blocked_side_reached"
elif already_covered_count > 0:
    terminal_reason = "already_covered_in_baseline"
elif coverage_progress_iteration_count > 0:
    terminal_reason = "coverage_progress_observed_but_not_solved"
elif family_progress_iteration_count > 0:
    terminal_reason = "family_progress_observed_but_not_solved"
elif stalled_iteration_count > 0:
    terminal_reason = "stalled_at_branch"
elif no_branch_signal_count == len(iterations):
    terminal_reason = "no_branch_signal"
elif invalid_iteration_count == len(iterations):
    terminal_reason = "invalid_generator"
else:
    terminal_reason = "no_useful_signal"
```

`stalled_at_branch` 是最常見的結果（Branch 可到但條件難解），之後移交 SymCC。

---

## 四、Family 評估機制

### 代表種子選取（`choose_representative_seed_records`）

```
每個 family（按 filename tag 分組）：
  - 新 family（本輪新增）：取前 2 個種子
  - 已知 family（前一輪已有）：取前 1 個種子
  - 全部總共：最多 12 個

「前 N 個」= sorted 後的前 N 個 = deterministic enumeration 的邊界值
（這是刻意設計：range 枚舉的前 2 個 = 最小值 + 次小值，邊界覆蓋最可靠）
```

### Family 分類（`build_family_summary`）

```python
# 每個 family 的統計：
branch_reach_ratio = branch_reached_count / total_evaluated  # 到達 branch 的比例

keep_families = [
    item for item in ranked_families
    if blocked_side_reached_count > 0      # 有任何種子解了 blocked side
    or branch_reach_ratio >= 0.5           # 超過一半種子能到 branch
]
refine_families = [
    item for item in ranked_families
    if branch_reached_count > 0            # 有種子能到 branch
    and blocked_side_reached_count == 0    # 但沒有解開 blocked side
]
discard_families = [
    item for item in ranked_families
    if branch_reached_count == 0           # 完全到不了 branch
]
```

### Family signal score（判斷是否有進步）

```
score = sum(blocked_side_reached_count * 100 + round(branch_reach_ratio * 100)
            for each keep/refine family)
```
若 score 上升 → `family_progress`（即使 coverage 沒有改變）。

---

## 五、SymCC 種子交接機制

Stage 1 結束後，根據 `terminal_reason` 決定是否把種子交給 SymCC（Stage 3c）：

```python
# 會交接的情況：
if terminal_reason in {"blocked_side_reached", "already_covered_in_baseline"}:
    # 已解，不需要 SymCC
    skip

if terminal_reason in {"invalid_generator", "no_branch_signal"}:
    # generator 失敗或完全無訊號，SymCC 無法從好的起點出發
    # 仍然交接，但用 triggering_input（原本就能到 branch 的種子）作為 fallback
```

SymCC 需要「能到達 branch 的種子」作為起點，才能從 branch 開始符號執行，探索 blocked condition 的解。

**交接的種子選取邏輯**：
- 優先選 `blocked_side_hit_count = 0`（還沒解開）但 `branch_hit_count` 最高的種子（接近 blocker 但還差一步）
- stalled_at_branch：從所有 keep/refine families 各選代表種子，提供多樣的 SymCC 起點
- 其他情況（coverage progress 等）：只選最佳 family 的代表種子

---

## 六、Template 改動（2026-05-31）

**檔案**：`prompts/templates/blocker_seed_generator_template` line 180

### 改動前
```
Prefer explicit boundary values over probabilistic logic.
```

### 改動後
```
Prefer deterministic systematic variants over probabilistic sampling:
use range enumeration, interesting-value lists, bitflip variants, and
Cartesian combinations instead of random.randint(). Each family should
explore a meaningful range of the hypothesis space, not a single hardcoded
point. For example, if a field controls a branch, enumerate all semantically
distinct values for that field rather than picking one guess.
```

### 改動動機
- LLM 過去常用 `random.randint()` 產生種子，導致每次跑 generator 結果不同
- Coverage 評估取「前 2 個代表種子」→ random 的前 2 個不穩定
- range enumeration 的前 2 個 = 邊界值（最小值、次小值），更有意義
- 論文中的 or_pullup case 驗證無效（見下節），尚未找到合適的驗證 case

---

## 七、與 SeedMind 論文（arXiv:2411.18143）的差異

### SeedMind 的設計（論文做法）

| 元素 | SeedMind 做法 |
|---|---|
| C1 格式屏障 | LLM 生成 Python generator，執行時生成 binary（與我們相同） |
| C2 多樣性屏障 | Generator 內含 random 邏輯（`random.randint`、`random.choice`），每次跑 generator 得到不同種子，執行多輪 fuzzing |
| 種子評估 | 把大量隨機種子餵給 fuzzer，靠 coverage feedback 更新 generator |
| 迭代策略 | 保留 high-coverage families，對低效的 families 重新設計 |

### 我們的設計差異

| 元素 | 我們的做法 | 差異說明 |
|---|---|---|
| C1 格式屏障 | 同 SeedMind | ✅ 已解決 |
| C2 多樣性屏障 | **range enumeration**（確定性）取代 random | ⚠️ 主動選擇不用 random |
| 評估對象 | 每個 family 取前 2 個代表種子做 Docker coverage | SeedMind 是大量跑 fuzzer，我們是精準評估少數代表種子 |
| 評估工具 | Docker `coverage binary -runs=1` | 單次執行，非 fuzzing（無變異） |
| 迭代目標 | 找到能越過 blocked branch condition 的輸入 | SeedMind 是整體 coverage，我們是針對單一 blocker |

### 為什麼選 range enumeration 而非 random？

**論點**：
- Blocker condition 通常是 `field == VALUE` 或 `field > THRESHOLD`，解法是找「剛好滿足條件」的值
- range enumeration 系統性掃描 `[0, 1, 2, ..., 255]` 或 `[0, 128, 256, ...]` → 邊界值一定被覆蓋
- random：即使跑 1000 個種子，也可能多次採樣到 0-127 而從未採樣到 128（如果條件是 `field >= 128`）
- 我們評估時只取前 2 個代表種子 → random 的「前 2 個」完全靠運氣

**反論（SeedMind 的立場）**：
- 有些 blocker condition 不是簡單的邊界值，而是複雜的組合（多個欄位同時滿足）
- range enumeration 在高維度組合空間中爆炸（N個欄位 × M個值 = N^M 種組合）
- random sampling 在這種情況下反而更有機會命中
- SeedMind 的 random + 大量種子策略是為了探索更廣的組合空間

**目前狀態**：
- 我們選 range enumeration 的主要原因是「評估成本低」（只取前 2 個），而非「range enumeration 一定更好」
- 還沒有對 range enumeration vs random 做實際 ablation study
- template 改動後，需要找到一個合適的 case 驗證效果（or_pullup 不適合，見下節）

---

## 八、已知問題與驗證困難

### or_pullup 為何不是好的驗證 case

**or_pullup 的 blocker 條件**：`(*samep)->val[A_ATOM] == val`

這個條件不是由某個輸入欄位直接控制的，而是 BPF optimizer 的 **內部 value numbering 狀態**。optimizer 在分析整個 BPF 濾波器表達式後，對每個 CFG block 計算 accumulator 的 value number。兩個 value number 相等是 optimizer 「碰巧」找到最佳化機會的結果，不是輸入的某個欄位直接控制的數值。

結論：**range enumeration 對這類 case 無效**。這是語義層面的問題，不是數值邊界問題。

### 迭代品質驗證的困難

- 先前 libpcap 跑過多次，corpus 是累積結果，無法分辨成長是系統能力還是累積跑的結果
- 需要一個「乾淨起點」的 12 小時實驗，從零計算覆蓋率成長

### stalled_at_branch 是最常見的結果（libvpx）

對 libvpx 來說，blocker 通常是 VP9 bitstream 裡深層的解碼邏輯：
- Branch 能到（seed 是合法的 VP9 IVF → `vpx_codec_decode` 能執行到 blocker 附近）
- Blocked side 不能到（需要精確的 frame color/bitdepth 組合或特定 ref frame 狀態）

LLM 能生成「看起來合理」的 VP9 IVF 結構，但要精確控制解碼器的內部狀態，往往超出 LLM 知識範圍。這是 SymCC 的強項（符號追蹤 + constraint solver 自動找到滿足條件的 byte 值）。

---

## 九、Stage 1 → Stage 3 的整體設計意圖

```
Stage 1（LLM generator）的角色：
  - 快速、低成本地嘗試「LLM 能不能直接想到解法」
  - 如果 blocker condition 是語義上可理解的（如：特定的 flag 組合），LLM 有機會直接解
  - 如果 blocker condition 是數值精確型（如：specific hash value, checksum），LLM 解不了

SymCC 的角色（Stage 3）：
  - 不需要理解語義，靠符號追蹤自動找到滿足條件的輸入
  - 但需要「能到達 branch 的起點種子」才能開始工作
  - Stage 1 的 stalled_at_branch 結果正好提供這個起點

兩者互補：
  - Stage 1 負責「從零到 branch」（LLM 生成結構合法的種子）
  - Stage 3c 負責「從 branch 到 blocked side」（SymCC 解條件方程）
```

---

## 十、關鍵程式位置

| 功能 | 檔案 | 關鍵函數 |
|---|---|---|
| Generator 迭代主循環 | `blocker_process/dependent/input_dependent_seed_generator.py` | `run_generation_loop()` (約 line 1700) |
| 迭代狀態分類 | 同上 | `classify_iteration_status()` (line 1461) |
| Family 評估 | 同上 | `build_family_summary()` (約 line 1100) |
| 代表種子選取 | 同上 | `choose_representative_seed_records()` (line 911) |
| SymCC 種子交接 | 同上 | `select_recommended_symcc_generator_seeds()` (約 line 1334) |
| 最終 terminal_reason | 同上 | 約 line 2148-2163 |
| Generator template | `prompts/templates/blocker_seed_generator_template` | line 180 為 range enumeration 指引 |
| 單次種子 coverage 評估 | `blocker_process/dependent/input_dependent_seed_generator.py` | `evaluate_seed_with_coverage_in_ossfuzz()` (line 932) |

---

## 十一、尚未解決的問題

1. **Range enumeration vs random 的實際效果**：需要 ablation study，目前只有理論論點，沒有實驗數據
2. **Template 改動驗證**：需要找一個「整數欄位直接控制 branch、未曾解過、非 complex binary protocol」的 case
3. **Generator 對複雜 blocker 的根本限制**：libvpx 的 VP9 bitstream 太複雜，LLM 無法構造足夠精確的 frame，Stage 1 對此類 blocker 幾乎必然 `stalled_at_branch`
4. **Family 數量的上限設計**：目前 max 12 個代表種子，是否足夠？太少可能錯過關鍵的 family signal
5. **迭代次數 3 的選擇依據**：預設 max 3 iterations，是否太少（LLM 可能需要更多輪才能收斂）？
