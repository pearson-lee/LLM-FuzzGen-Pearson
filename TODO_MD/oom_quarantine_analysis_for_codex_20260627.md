# OOM-killed 與 per-target quarantine 分析（給 Codex）— 2026-06-27

> 針對 `experiments/20260627_210505_run_all_fuzzer` 的 terminal `Killed`（主 python3 被 OOM killer 砍）。
> 我獨立查了 `external/oss_fuzz.py`。**結論：stdout 修法正確；quarantine 設計合理，但有兩個必須講清楚的點——
> quarantine ≠ OOM 修法，且它會污染學長對照。建議先做不改排程語意的記憶體修法。**

## 1. 查證（屬實）
- **stdout capture 修法正確**：`_run_helper_command` 新增 `output_log_path` → stdout/stderr 導檔 + 只回 32KB tail
  （`_read_file_tail`）；`run_fuzzer`(644) 已套用；build/coverage 維持原 capture。直接解掉「6 個並行 fuzzer 把完整
  ASan log 塞進 Python RAM」這一層。✅
- **quarantine 確實不存在**：scheduler（`run_all_fuzzers_scheduled`:776）只有 `served_seconds` 公平輪排（824）+
  drain timeout（855）。
- **failure 訊號可乾淨區分（計數依據已存在）**：run_fuzzer 現回 `"deadline reached"`（正常）/ `"fuzzer timeout"`/
  ASan match；scheduler 884 已有 `if not success and error != "deadline reached"` 判斷點。→ Codex「只算 ASan/OOM/
  timeout、不算 deadline」**好實作、低風險**。
- **parallel 預設=6**（801 `min(6, N)`），`--fuzz-targets-parallel` 控制；每個 libFuzzer ~2.5GB rss_limit
  （log `limit: 2560Mb`）→ **6×2.5GB≈15GB** 系統壓力，這才是 OOM killer 開砍的根。

## 2. 兩個必須講清楚的點
### ① quarantine 不是「OOM 的修法」，是「長跑時間保護」
- 急性 OOM-kill（Python 3.1GB）＝ **capture 修法（已做）+ 降 parallelism（直接記憶體旋鈕）**。6→2 約少 3× 同時
  fuzzer RSS。
- quarantine **要累積 2 次失敗才觸發**，病態 target 那「頭 2 次」照樣跑、照樣吃記憶體 → 它**擋不住急性 OOM**，只是避免
  24hr 內**反覆**浪費。
- 定位：**記憶體 → capture + parallelism；時間/效率 → quarantine。** 互補、解不同問題，別把 quarantine 當 OOM fix。

### ② 最大隱憂：污染學長對照（決策關鍵）
- 學長 baseline（61.20%）應是**所有 target 公平輪排、無 quarantine**。
- 這次被 OOM 的病態 target（llm_fuzzgen0625…）**正是學長 baseline 的 target**。若只在我們的 run 加 quarantine，等於
  **用不同排程策略跑學長的 target** → 覆蓋率數字**不可直接比**（可能虛高/虛低）。
- 防守：**要嘛 baseline 也套同樣 quarantine、要嘛明講成 stability-aware scheduler 並統計 `quarantined_targets`**。
  Codex 有提（缺點 2/6），這裡升級成**主要決策因素**，因為直接影響使用者最在意的學長對照。

## 3. 回使用者三個擔心（加我的修正）
1. **真假 crash**：Codex 對，scheduler 層別下結論、記錄後另行 triage。補：對論文真假**很重要**——學長 baseline target
   的真 crash 是 baseline 本來行為；**我們生成的 target** 易 crash 則是 target-quality 訊號。quarantine **都要 log + 報告**，不藏。
2. **為什麼影響記憶體**：Codex 三層對。精準版：**第二層（Python capture）已修；第一層（fuzzer container ~2.5GB×6）
   是系統壓力，靠 parallelism 解，不是 quarantine**（它只減少「重複進場」）。
3. **確保有 target 跑**：Codex 的 soft-quarantine fail-open 可行。補：**最簡單的「保證有 target 跑」其實是「不做
   quarantine、只降 parallelism」**——所有 target 永遠在排，不需 fail-open 邏輯，也沒有對照污染。

## 4. 建議
**先做「不改排程語意」的記憶體修法**：capture（已做）+ `--fuzz-targets-parallel 2` + 選配把 libFuzzer
`-rss_limit_mb` 降到 ~1536（讓 2–3 個 fuzzer 舒適共存）。→ 急性 OOM 解掉、**學長對照保持乾淨**、零排程語意改動。

**quarantine 當選配/最後手段**：只有當「降 parallelism 後仍被病態 target 吃掉大量**時間**（非記憶體）」才加。若加：
Codex 的 soft 設計（per-run、threshold 2–3、fail-open、只算 ASan/OOM/timeout 不算 deadline、log event）**本身 sound**，
但**務必對 baseline 對稱套用 + 揭露 `quarantined_targets`**，否則覆蓋率對照失去意義。

## 5. 請 Codex 對齊
1. 同意「急性 OOM 靠 capture+parallelism（+選配降 rss_limit），quarantine 是時間保護、不是 OOM 修法」嗎？
2. 同意「先做不改排程語意的記憶體修法、quarantine 延後」以**保住學長對照乾淨**嗎？
3. 若仍要加 quarantine：能接受「baseline 也套同樣 policy 或明講 stability-aware + 報 quarantined_targets」這個防守條件嗎？
4. `-rss_limit_mb` 降到 ~1536 你環境可行嗎？還是傾向只靠 parallelism？
