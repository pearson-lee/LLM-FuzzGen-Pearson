# SymCC 現況總整理

最後更新：2026-06-02

---

## 一、工具鏈狀態

| 項目 | 路徑 | 狀態 |
|---|---|---|
| C compiler (`symcc`) | `symcc/build/symcc` | ✅ 存在 |
| C++ compiler (`sym++`) | `symcc/build/sym++` | ✅ 存在 |
| 插樁版 libc++ | `libcxx_symcc_install/lib/libc++.a`, `libc++.so` 等 | ✅ 存在 |
| SymCC runtime | `symcc/build/libsymcc.so` | ✅ 存在 |

---

## 二、已實作的修正

### T3：C++ harness 的 SYMCC_LIBCXX_PATH 修正
**檔案**：`blocker_process/dependent/symcc_blocker_solver.py`（line 617-621, 744-749）

**問題**：原本設 `SYMCC_REGULAR_LIBCXX=yes`，導致 SymCC 在符號執行 C++ harness 時使用系統未插樁的 libc++，所有通過 `std::string`、`FuzzedDataProvider` 等的 symbolic data 都失去追蹤。

**現在的邏輯**：
```python
if use_cxx:
    libcxx_install = REPO_ROOT / "libcxx_symcc_install"
    if libcxx_install.is_dir():
        symcc_env["SYMCC_LIBCXX_PATH"] = str(libcxx_install)  # ✅ 使用插樁版 libc++
    else:
        symcc_env.setdefault("SYMCC_REGULAR_LIBCXX", "yes")   # fallback（防禦性）
```

**影響範圍**：只在 Stage 3c（SymCC harness）且 harness 是 `.cpp` 時生效。libpcap/libtiff/cjson 全是 C，不受影響。libvpx 的 Stage 3c harness 是 `.cpp`，是唯一影響到的 project。

**驗證狀態**：`libcxx_symcc_install` 確認存在。但 Stage 3c 尚未成功編譯過（先被 T8 問題卡住），T3 實際效果未實測。

---

### T8：Stage 3c build context 修正
**檔案**：`blocker_process/dependent/run_symcc_blocker.py`（line 327-330）

**問題**：`run_symcc_blocker.py` 原本對所有 fuzz_target 都呼叫 `reconstruct_build_context(mode="original_target", target_source=harness.cpp)`，但 harness 在 `generated_harnesses/` 目錄，不在原始 source tree，導致重建的 include_dirs 只有 10 個，缺少 `work/build/`（`vpx_config.h` 在這裡），Stage 3c 編譯失敗。

**現在的邏輯**：
```python
harness_build_ctx_path = Path(args.fuzz_target).parent / "build_context.json"
if harness_build_ctx_path.is_file():
    # harness 目錄下有正確的 build_context.json（由 harness generator 建立）
    symcc_build_context = BuildContext.from_json_file(harness_build_ctx_path)
    print(f"[info] using pre-built harness build context: {harness_build_ctx_path}")
else:
    # Stage 3a 的 fuzz target（在 auto_context/ 下），走原本的重建邏輯
    symcc_build_context = reconstruct_build_context(...)
```

**harness 的 build_context.json 內容驗證**（最新 `libvpx_setup_frame_size_with_refs_symcc_20260601_000427`）：
```
include_dirs: 12  ← 正確，含 work/build
  .../src/libvpx
  .../src
  .../googletest/include
  .../libyuv/include
  .../vpx_mem/include
  .../auto_context/libvpx/library_sources
  .../auto_context/libvpx
  .../auto_context/libvpx/fuzz_targets
  .../generated_harnesses/libvpx_setup_frame_size_with_refs_symcc_20260601_000427  ← harness 自身目錄
  .../generated_harnesses
  .../vpx_mem
  .../work/build  ← vpx_config.h 在這裡 ✅
```

**驗證狀態**：build_context.json 內容正確確認。但 setup_frame_size_with_refs 尚未重新跑過，`[info] using pre-built harness build context` log 訊號未出現過。**T8 的實際效果待下次 libvpx run 驗證。**

---

### T9：native archive 設定檔驅動
**檔案**：`blocker_process/dependent/run_symcc_blocker.py`（load_project_config + resolve_native_archive_inputs）
**新增**：`external/oss-fuzz/projects/libpcap/symcc_config.json`

**問題**：原本 `if args.project_name == "libpcap":` 硬碼，不可擴充。

**現在的邏輯**：每個 project 可放 `symcc_config.json`，程式從中讀取 `native_archive` flag：
```json
// libpcap/symcc_config.json
{
  "native_archive": true,
  "native_archive_build_flavor": "symcc_native",
  "native_archive_subdir": "symcc_native",
  "native_archive_filename": "libpcap.a",
  "native_archive_include_dirs": ["source_code", "source_code/pcap"]
}
```

**驗證狀態**：✅ 2026-06-01 pcap_parse run 確認 T9 有效（`native_prepare.success: true`，`libpcap.a` 成功 build 並使用）。

---

## 三、各 Project 的 SymCC 執行能力

| Project | Stage 3a（probe on original） | Stage 3c（SymCC harness） | 備註 |
|---|---|---|---|
| libpcap | ✅ 可執行（native archive 模式） | ⏳ 待驗 | T9 確認有效；Stage 3c 因 handoff 種子問題未執行 |
| libvpx | ❌ Stage 3a 無法編譯（`-DDECODER=vp9` missing） | ⏳ 待驗（T8 修後） | Stage 3a 是已知限制，不阻斷 Stage 3c |
| libtiff | 未測 | 未測 | 純 C，無 native archive 需求 |
| cjson | 未測 | 未測 | 純 C，無 native archive 需求 |

---

## 四、最新 SymCC 執行結果分析（2026-06-01 pcap_parse）

**指令**：
```bash
python3 blocker_process/blocker_classifier.py \
  --project-name libpcap \
  --function-name "pcap_parse" \
  --branch-line-number 2056 \
  --target-name llm_fuzzgen0625182131 \
  --seed external/oss-fuzz/build/corpus/libpcap/llm_fuzzgen0625182131/0001118fc3f072c60054c5b8f2e647fa8842d5c2 \
  --backend vertexai --model gemini-2.5-flash
```

**結果摘要**：

| 階段 | 狀態 | 說明 |
|---|---|---|
| Stage 1 LLM seed gen | `stalled_at_branch`（但有問題）| 3 個 family（F01/F02/F03）全部 branch_hit=0 |
| Stage 3a symcc probe | 執行成功，未解 | 使用 baseline corpus seed（branch_hit=3240000），SymCC 探索後仍 blocked_side=0 |
| Stage 3c harness gen | 未啟動 | 無 branch-reaching 種子可交接給 SymCC harness |

**Stage 3a 的詳細表現**（T9 驗證）：
```
[info] loaded shared build context: required=2 optional=1 include_dirs=5
[info] using prebuilt native archives: .../symcc_probe/native_archives/libpcap.a
[info] reusing prebuilt coverage binary: .../symcc_replay/llm_fuzzgen0625182131_replay
[info] SymCC generation 1: 1 seed(s)
[info] total corpus after SymCC: 1  ← SymCC 探索後沒有生成新 input
Status: No seed reached the blocked-side line.
```

→ SymCC 工具鏈本身運行正常，libpcap.a native archive 成功建立和使用（T9 ✅）。但 SymCC 無法從這個 seed 解出 blocked_side 條件。

**Stage 1 的問題（待調查）**：

Generator 生成了 pcap header + BPF expression 的種子（如 `tcp port`、`host`、`src and`、`foo`），但所有種子的 `branch_hit_count = 0`。這意味著 generator 的種子根本沒有到達 `pcap_parse` 的第 2056 行。

但是，基線 corpus seed 有 `branch_hit_count = 3240000`，表示這個 branch 被跑了 3.24M 次，說明現有 corpus 裡有會到達這個 branch 的種子。

**可能原因**：generator 生成的 BPF expression 格式本身可能能觸發 branch，但 pcap 封包部分（header）格式不正確，導致 fuzz target 在到達 `pcap_parse` 之前就因格式錯誤退出，或 snaplen=0 導致 `pcap_compile()` 失敗。

**解決方向**：
- 讓 generator 使用現有 corpus 中已知可到達 branch 的種子結構（改 pcap header 部分）
- 或調整 generator template，強調要從現有 corpus 截取有效 header 格式

---

## 五、尚待驗證的項目

### T3 驗證（SYMCC_LIBCXX_PATH 是否生效）
**條件**：需要 Stage 3c（libvpx SymCC harness）成功編譯並執行。
**阻礙**：Stage 3c 尚未在 T8 修後執行過。
**驗證方式**：在 symcc_blocker_solver.py 的 compile 階段加 print 確認 env var；或在 Stage 3c 執行時直接觀察 SymCC 的 output（有無 `libcxx` 相關訊息）。

### T8 驗證（pre-built build context 使用）
**條件**：重新跑 `setup_frame_size_with_refs` 或 `end` blocker。
**驗證訊號**：log 中出現 `[info] using pre-built harness build context: .../build_context.json`
**後續效果**：若 T8 有效，Stage 3c 應不再出現 `vpx_config.h file not found`，而是成功編譯出 `replay_symcc` binary。

### Stage 3c C++ SymCC 完整流程驗證
T8 解決 build context → T3 確保 libc++ 正確載入 → Stage 3c 執行 → SymCC 對 libvpx harness 進行符號執行 → 是否能解 `setup_frame_size_with_refs` blocker。

**執行指令**：
```bash
python3 blocker_process/blocker_classifier.py \
  --project-name libvpx \
  --function-name "setup_frame_size_with_refs" \
  --branch-line-number 1594 \
  --blocked-side-line-number 1599 \
  --source-api-file /src/libvpx/vp9/decoder/vp9_decodeframe.c \
  --target-name vpx_dec_fuzzer_vp9 \
  --seed external/oss-fuzz/build/corpus/libvpx/vpx_dec_fuzzer_vp9/038e85dcb082a20c85f2d41394006547171769db \
  --backend vertexai --model gemini-2.5-flash
```

---

## 六、已知限制

| 限制 | 說明 | 影響 |
|---|---|---|
| SSE2/SIMD source 不支援 | SymCC LLVM 14 的 `visitBitCastInst` 對 vector type abort（exit 134） | libvpx `vpx_highbd_lpf_horizontal_8_sse2.c`、其他 SIMD 函數無法用 SymCC |
| Stage 3a `-DDECODER=vp9` missing | libvpx `vpx_dec_fuzzer_vp9.cc` 需要 build system 傳 `-DDECODER=vp9`，未被捕捉 | Stage 3a 對 `vpx_dec_fuzzer_vp9` 永遠 compile fail，但不影響 Stage 3c |
| SymCC 探索能力有限 | pcap_parse 的 `push_and_jump_if` 邏輯依賴 yacc 狀態機，SymCC 單一 seed 探索深度有限，3.24M 次 branch hit 但未能解 | 需要更好的起點種子（能到達 branch 但離 blocked_side 近的） |
| Generator 種子不到 branch | pcap_parse case：generator 生成的種子 branch_hit=0，無法作為 SymCC 的好起點 | Stage 3c 的 SymCC harness 永遠等不到 handoff 種子 |

---

## 七、下一步行動

1. **重跑 libvpx setup_frame_size_with_refs**：驗證 T8 + T3 是否讓 Stage 3c 成功編譯
2. **調查 libpcap generator 種子不到 branch 的原因**：確認 pcap header 格式或 fuzz target 讀取邏輯
3. **libpcap clean run（待啟動）**：`build/out/libpcap` 已刪除，需要啟動 12 小時實驗觀察整體 pipeline 效能
4. **如果 Stage 3c 成功**：確認 `SYMCC_LIBCXX_PATH` 環境變數有被 SymCC 使用（T3 驗證）
