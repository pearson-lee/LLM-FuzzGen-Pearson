# SYMCC Dependent Pipeline 驗證進度

**日期**：2026-06-06  
**目標**：驗證 LLM-FuzzGen dependent blocker 系統（SYMCC 求解路徑）能否實際解決 input-dependent blockers

---

## 第一輪實驗：5 個 Case 結果

| Case | 函式 | Pipeline | 結果 | 根本原因 |
|------|------|----------|------|---------|
| 1 | libpcap `compute_local_ud:641→646` | input_dependent | ❌ | blocked side 是 `abort()` — 內部 invariant，合法輸入永遠不觸發 |
| 2 | libpcap `gen_proto:6416→6417` | input_independent（誤分類） | ❌ | `bpf_error("direction applied to 'proto'")` — 語法層面拒絕，LLM 也解不了 |
| 3 | libpcap `or_pullup:1916→1917` | input_dependent | ❌ | `*samep == 0` 需要 BPF CFG NULL pointer，無法從 filter 字串控制 |
| 4 | libvpx `vpx_highbd_lpf_horizontal_8_sse2:593→594` | input_dependent | ❌ | `bd == 8` 在 highbd function 中設計上不可達（該 function 只被 bd=10/12 呼叫） |
| 5 | libvpx `vp9_parse_superframe_index:570→571` | input_independent（誤分類） | ✅ | **LLM dedicated_generation 直接生成針對性 harness 成功** |

SYMCC 有在跑（Case 4 產生 165 個新種子），但全部無法到達 blocked side。

### 失敗根因分類

| 類型 | 案例 | 說明 |
|------|------|------|
| Invariant / assert | compute_local_ud:646 | `abort()` = 程式邏輯不變式，非輸入格式限制 |
| 架構設計不可達 | vpx_highbd:594 | highbd 路徑只給 10/12-bit，8-bit 走標準 loopfilter |
| 內部圖結構 | or_pullup:1917 | CFG graph 的指標結構，非輸入直接控制 |
| 誤分類 | gen_proto:6417 | 應為 input_dependent，但條件需語法層面無效輸入 |
| 成功（非 SYMCC） | superframe_index:571 | LLM 理解格式規格後直接生成 harness |

---

## 關鍵架構發現：Native Archive 限制

### 問題

查看 `external/oss-fuzz/projects/libpcap/build.sh` 和 `symcc_config.json`：

```json
// symcc_config.json（libpcap, libvpx 皆同）
{
  "native_archive": true,
  "native_archive_build_flavor": "symcc_native",
  "native_archive_filename": "libpcap.a"
}
```

SYMCC 的 build flow：
- `BUILD_FLAVOR=symcc_native` → 用普通 clang 編譯庫，匯出 native `libpcap.a`
- `BUILD_FLAVOR=symcc_replay` → 用 SYMCC 編譯 **harness** replay binary
- **庫本身永遠是 native 編譯，SYMCC 無法追蹤庫內部的符號狀態**

```
[輸入 bytes] → harness (SYMCC instrumented)
                        ↓
               pcap_compile() / vpx_codec_decode()  ← 符號追蹤在此斷裂
                        ↓
               optimizer, codegen, loopfilter... (SYMCC 完全看不到)
```

SYMCC 的 165 個新種子是探索 harness 層的 size check 和長度限制，而非追蹤庫內格式條件。

### 真正適合 SYMCC 的條件類型

| 條件類型 | 例子 | 適合 SYMCC？ |
|---------|------|------------|
| 直接 input byte 比較 | VP8 `bytes_left < 0`（partition size 欄位） | ✅ |
| Bitstream field check | VP9 superframe marker byte | ✅（但被 LLM 先解了） |
| 內部狀態機 | `yyerrstatus`, `break_loop`, `ready_for_new_data` | ❌ |
| 圖結構 invariant | `*samep == 0`, `ref_frame->idx == INVALID_IDX` | ❌ |
| 架構不可達 | `bd == 8` in highbd function | ❌ |
| `abort()` / assert | compute_local_ud:646 | ❌ |

---

## 改善方向：Library SYMCC Instrumentation

### 現有基礎設施（已有）

- `symcc/build/symcc` 和 `sym++` — 已編譯好的 SYMCC compiler binary
- `blocker_process/dependent/symcc_blocker_solver.py` — 已支援 `--prebuilt-archive` 參數
- `run_symcc_blocker.py` — 已有 `native_archive` 的 build + link 邏輯

### 需要新增的（3 個地方）

**1. `build.sh`（libpcap + libvpx）新增 `symcc_library` build flavor**

```bash
if [ "$BUILD_FLAVOR" = "symcc_library" ]; then
  SYMCC_HOME="/home/kyliechien/LLM-FuzzGen/symcc"
  export CC="$SYMCC_HOME/build/symcc"
  export CXX="$SYMCC_HOME/build/sym++"
  # 用 SYMCC 重新 build 庫
  mkdir build_symcc && cd build_symcc
  cmake .. -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  make
  mkdir -p "$OUT/symcc_library"
  cp libpcap.a "$OUT/symcc_library/libpcap.a"
  exit 0
fi
```

**2. `symcc_config.json` 新增 key**

```json
{
  "symcc_library": true,
  "symcc_library_build_flavor": "symcc_library",
  "symcc_library_subdir": "symcc_library",
  "symcc_library_filename": "libpcap.a"
}
```

**3. `run_symcc_blocker.py` 仿照 `native_archive` 邏輯新增分支**

```python
if project_config.get("symcc_library", False):
    oss_fuzz.build(project_name, env={"LLM_FUZZGEN_BUILD_FLAVOR": "symcc_library"}, ...)
    symcc_archive = resolve_symcc_library_archive(...)
    prebuilt_archives.append(symcc_archive)
    # symcc_blocker_solver 的 prebuilt_archives 機制已支援，不需改動
```

### 優缺點評估

| 面向 | 說明 |
|------|------|
| ✅ libpcap 效益 | 純 C，全庫可 instrument，PCAP 格式讀取、BPF lexer/parser 條件均可追蹤 |
| ✅ libvpx 部分效益 | VP8/VP9 bitstream header parsing 層可追蹤（bytes_left、frame_type 等） |
| ❌ libvpx SSE2 無效 | SSE2 / intrinsics 程式碼 SYMCC 無法 instrument，highbd 類仍是 native |
| 📦 Build 成本 | 每次 SYMCC run 前多一次 OSS-Fuzz build（SYMCC 編譯比 native 慢 3-5x） |
| ⚡ 執行成本 | SYMCC 探索因符號狀態擴大而變慢，大庫有 constraint explosion 風險 |
| 🛡️ 建議先試 | 先在 libpcap 試（小庫、純 C、風險低），libvpx 設較短的 SYMCC timeout |

### 最佳驗證 Case（一旦 library SYMCC 啟用後）

**VP8 `read_available_partition_size:687`**（最接近直接格式限制的案例）

```c
// VP8 bitstream bytes 3-5 是 partition size（24-bit LE）
bytes_left = data_end - data - first_part_size;
if (bytes_left < 0)   // ← 直接格式限制：partition_size 欄位值 > 剩餘資料量
    vpx_internal_error("Truncated packet or corrupt partition...");
```

Branch hits: 32,500，blocked side: 0。一旦 libvpx 以 SYMCC 編譯，這個條件對 SYMCC 是直接可解的。

---

---

## SymCC 官方文件確認的根本問題

SymCC FAQ 明確說明：

> **Incomplete symbolic handling of functions, systems interactions.**
> When an unsupported libc function is called SymCC can't trace the computations that happen in the function.
>
> 解法：
> 1. Add wrappers
> 2. **Build a fully instrumented libc** ← 核心解法
> 3. Cherry-pick individual functions

這直接解釋了我們所有 SYMCC case 失敗的原因：library 是 native，符號追蹤在 library 邊界斷掉，無論 blocker 條件多麼「格式直接」都無濟於事。

---

## 系統現有分工（釐清）

```
[host]   symcc/build/symcc          ← 編譯 harness replay binary
[host]   symcc_blocker_solver.py    ← 跑 SymCC 符號執行、產生 seeds
[docker] OSS-Fuzz build             ← 編譯 libpcap.a / libvpx.a（native，無 SymCC）
[host]   link                       ← harness + native library
```

Harness 在 host 上編（小、依賴少），library 在 Docker 裡編（依賴複雜：cmake, flex, bison, yasm...）。現在缺的是：**library 也需要用 SymCC 重編一份**。

---

## Library SymCC Instrumentation 的兩條路

| 方式 | 通用性 | 優點 | 缺點 |
|------|--------|------|------|
| **Host 上重編 library** | 限 libpcap（純 C）| 快速驗證、不改 Docker | host 要有 cmake+flex+bison；libvpx 需要 yasm 不適用 |
| **Docker 裡加 `symcc_library` build flavor** | 所有 project | 教授方向、依賴齊全、通用 | 需要讓 SymCC 進入 Docker container |

**教授的直覺（架在 Docker 裡）是對的**。Docker 環境有所有 build 依賴，include 路徑不用手動轉換，libvpx 的 yasm 等複雜依賴也有。

---

## 讓 SymCC 進入 OSS-Fuzz Docker 的方式

SymCC 官方提供現成 Docker image：

```bash
docker pull eurecoms3/symcc
```

或用 `symcc/Dockerfile` 自己 build。

**目標架構（Docker 全流程）**：

```
OSS-Fuzz Docker container（含 SymCC）
  ├── BUILD_FLAVOR=symcc_native   → 編 native libpcap.a（現有，供 harness link 普通用）
  ├── BUILD_FLAVOR=symcc_replay   → 編 harness replay binary（現有）
  └── BUILD_FLAVOR=symcc_library  → 用 symcc/sym++ 重編 libpcap.a（新增）
                                    → 匯出到 $OUT/symcc_library/libpcap.a
```

solver 改用 `symcc_library/libpcap.a` 與 harness link → SymCC 可以追蹤 `pcap_compile()` 內部。

---

## Case 評估修正（根據用戶回饋）

| Case | 原本描述 | 修正 |
|------|---------|------|
| `gen_proto:6416→6417` | 「LLM 也解不了」 | 過度絕對。這是 input-dependent，filter 可以帶 direction + proto；但這條 error path 需要「語法可 parse、語義上非法」的輸入，目前 pipeline 不適合，不代表永遠解不了 |
| `or_pullup:1916→1917` | 「無法從 filter string 控制」 | 太強。filter string 間接影響 BPF CFG；只是在 native archive 模式下 SymCC 看不到 optimizer 內部，並非這個條件在格式上不可達 |
| `vp9_parse_superframe_index:570→571` | 分類成 input_independent 荒謬 | 更精確：這個 branch 主要取決於 harness 是否傳 non-NULL `decrypt_cb`，而非 input bytes 本身；分類成 input_independent 並不荒謬，它比較像 API-state / harness-dependent |

---

---

## 實作方案定案：Docker Volume Mount（不複製進 image）

### 問題確認

`oss_fuzz.build_fuzzers()` 只支援 `extra_env`（-e flags），不支援額外 volume mount。
SYMCC binary（含 LLVM pass）約 10-50 MB，**不應複製進 Docker image**（每次 build 帶著這個負擔、重建 layer 浪費空間）。

### 解決方案：新增 `LLM_FUZZGEN_EXTRA_VOLUMES` 支援

在 `extra_env` 傳入一個特殊 key，helper.py 解析後加入 `-v` flag：

```
run_symcc_blocker.py
  → oss_fuzz.build_fuzzers(extra_volumes=["symcc/build:/symcc-bin:ro"])
    → extra_env["LLM_FUZZGEN_EXTRA_VOLUMES"] = "symcc/build:/symcc-bin:ro"
      → helper.py docker run -v .../symcc/build:/symcc-bin:ro
        → build.sh 用 /symcc-bin/symcc 作為 CC/CXX
```

**優點**：SYMCC 完全不進 Docker image；bind mount 只在 container 執行期間存在。

---

### 需要修改的檔案（定案）

**1. `external/oss-fuzz/infra/helper.py`（最小改動）**

**正確位置（Codex 修正）**：修改 `build_fuzzers_impl()` 函式（約 line 820 開始），**不動**通用 `docker_run()`，否則所有 helper command 都會吃這個特殊 env。

`_env_to_docker_args(env_list)` 把 `KEY=VALUE` string list 轉成 `-e` 參數，env 是 list 不是 dict，需要掃描找出 `LLM_FUZZGEN_EXTRA_VOLUMES=` 開頭的項目。

在 `env += env_to_add`（line 874）之後抽取 extra volumes，在 `-v /out -v /work` 之後、image name 之前插入：

```python
# 在 line 874 (env += env_to_add) 之後，line 876 (command = _env_to_docker_args) 之前：
_extra_vols_str = ''
for _item in env:
    if _item.startswith('LLM_FUZZGEN_EXTRA_VOLUMES='):
        _extra_vols_str = _item[len('LLM_FUZZGEN_EXTRA_VOLUMES='):]
        break

# 改寫 line 894-897（原本一行 command += [..., image_name]）：
command += ['-v', f'{project_out}:/out', '-v', f'{project.work}:/work']
if _extra_vols_str:
    for _vol_spec in _extra_vols_str.split('|'):
        _vol_spec = _vol_spec.strip()
        if _vol_spec:
            command.extend(['-v', _vol_spec])
command.append(f'gcr.io/oss-fuzz/{project.name}')   # image name 必須在最後
```

**2. `external/oss_fuzz.py`**

在 `build_fuzzers()` 加入 `extra_volumes` 參數：

```python
def build_fuzzers(self, ..., extra_volumes=None):
    env = extra_env.copy() if extra_env else {}
    if extra_volumes:
        env["LLM_FUZZGEN_EXTRA_VOLUMES"] = "|".join(extra_volumes)
    ...
```

**3. `external/oss-fuzz/projects/libpcap/Dockerfile`**：**不需修改**

**4. `external/oss-fuzz/projects/libpcap/build.sh`**

新增 `symcc_library` build flavor：

```bash
SYMCC_LIBRARY_ENABLED="${LLM_FUZZGEN_BUILD_SYMCC_LIBRARY:-0}"
if [ "$BUILD_FLAVOR" = "symcc_library" ]; then SYMCC_LIBRARY_ENABLED=1; fi

# 同 symcc_native 一樣 strip sanitizer/fuzzer flags
if [ "$BUILD_FLAVOR" = "symcc_native" ] || [ "$BUILD_FLAVOR" = "symcc_library" ]; then
  export CFLAGS="$(strip_instrumentation_flags "$CFLAGS")"
  ...
fi

# cmake 前注入 SYMCC 為 CC/CXX（/symcc-bin 是 volume mount 進來的）
# Codex 修正：symcc wrapper 的 default paths 是 host 絕對路徑，Docker 內不存在，必須覆蓋
if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  export CC="/symcc-bin/symcc"
  export CXX="/symcc-bin/sym++"
  export SYMCC_PASS_DIR="/symcc-bin"                           # wrapper 讀 $SYMCC_PASS_DIR/libsymcc.so
  export SYMCC_RUNTIME_DIR="/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build"
  # Pre-flight checks（Codex 建議加 build-time assert，比 runtime 靜默失敗好）
  test -x "/symcc-bin/symcc"    || { echo "[llm-fuzzgen] ERROR: /symcc-bin/symcc not found (volume mount missing?)" >&2; exit 1; }
  test -x "/symcc-bin/sym++"    || { echo "[llm-fuzzgen] ERROR: /symcc-bin/sym++ not found" >&2; exit 1; }
  test -f "/symcc-bin/libsymcc.so" || { echo "[llm-fuzzgen] ERROR: /symcc-bin/libsymcc.so not found" >&2; exit 1; }
  test -f "/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a" \
    || test -f "/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so" \
    || { echo "[llm-fuzzgen] ERROR: libsymcc-rt not found in volume" >&2; exit 1; }
  test -x "/usr/lib/llvm-14/bin/clang" || { echo "[llm-fuzzgen] ERROR: /usr/lib/llvm-14/bin/clang not in Docker image" >&2; exit 1; }

  # SymCC 的 libsymcc.so pass 是 LLVM-14 plugin，必須由 LLVM-14 clang 載入，版本不符直接 fail
  # host 的 symcc wrapper default 也是 /usr/lib/llvm-14/bin/clang
  # OSS-Fuzz base-builder 有相同路徑；若路徑不存在，上面的 test 已保護
  export SYMCC_CLANG="/usr/lib/llvm-14/bin/clang"
  export SYMCC_CLANGPP="/usr/lib/llvm-14/bin/clang++"
  export SYMCC_REGULAR_LIBCXX="yes"    # libpcap 是純 C，OK；libvpx C++ 需改用 SYMCC_LIBCXX_PATH
  export SYMCC_ENABLE_LINEARIZATION="1"
fi
```

匯出區段（含修正後的 artifact validation）：

```bash
if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  mkdir -p "$OUT/symcc_library"
  cp "$SRC/libpcap/build/libpcap.a" "$OUT/symcc_library/libpcap.a"
  # 確認 archive 有 undefined reference 到 _sym_* → object 真的呼叫了 SymCC runtime API
  # nm -A archive 格式：archive:object:                 U _sym_something（多空格縮排）
  # SymCC runtime 的 public API prefix 是 _sym_（單底線），如 _sym_build_add、_sym_make_symbolic
  # 用 [[:space:]]U[[:space:]] 比 '^ *U' 更準確（nm -A 前有 archive:object: prefix）
  if ! nm -A "$OUT/symcc_library/libpcap.a" | grep -qE '[[:space:]]U[[:space:]]+_sym_'; then
    echo "[llm-fuzzgen] ERROR: symcc_library archive missing SymCC runtime refs (_sym_*)!" >&2
    exit 1
  fi
  # 確認沒有 sanitizer coverage 污染
  if nm -A "$OUT/symcc_library/libpcap.a" | grep -qE '__sanitizer_cov_|__sancov_'; then
    echo "[llm-fuzzgen] ERROR: symcc_library archive has sanitizer coverage symbols!" >&2
    exit 1
  fi
  echo "[llm-fuzzgen] symcc_library archive exported OK" >&2
  exit 0   # library-only build，不需 build harness targets
fi
```

**5. `external/oss-fuzz/projects/libpcap/symcc_config.json`**

新增：
```json
{
  "symcc_library": true,
  "symcc_library_build_flavor": "symcc_library",
  "symcc_library_subdir": "symcc_library",
  "symcc_library_filename": "libpcap.a"
}
```

**6. `blocker_process/dependent/run_symcc_blocker.py`**

在 native_archive 區塊之後：

```python
symcc_lib_archive: Path | None = None
if project_config.get("symcc_library", False):
    symcc_lib_build = oss_fuzz.build_fuzzers(
        args.project_name,
        sanitizer="none",
        extra_env={"LLM_FUZZGEN_BUILD_FLAVOR": "symcc_library",
                   "LLM_FUZZGEN_BUILD_SYMCC_LIBRARY": "1"},
        extra_volumes=[f"{REPO_ROOT}/symcc/build:/symcc-bin:ro"],
        variant="symcc_library",
    )
    if symcc_lib_build.success:
        lib_path = oss_fuzz.build_out_dir / args.project_name / "symcc_library" / "libpcap.a"
        if lib_path.is_file():
            prebuilt_archives = [lib_path]   # 取代 native archive
            symcc_lib_archive = lib_path
```

---

### Artifact Validation 分層順序（Codex 建議，修正版）

1. **build 內部**（build.sh 已加，build 失敗即停）：
   - `nm -A | grep -qE '[[:space:]]U[[:space:]]+_sym_'` → archive objects 有 undefined ref 到 `_sym_*` SymCC runtime API（單底線）
   - `nm -A | grep -qE '__sanitizer_cov_|__sancov_'` 應無結果 → 無 sanitizer 污染
2. **執行前 smoke test**：最小 C byte-compare case（`data[0] == 'A'`），確認 SymCC 能產生新 seed
3. **Library field check**：用 libpcap parsing-layer blocker，確認 SymCC 追進庫內部
4. **才測複雜路徑**：BPF optimizer 層

**注意**：`SYMCC_REGULAR_LIBCXX=yes` 對純 C project（libpcap）沒問題；之後若擴展到 libvpx（C++ harness），需改用 `SYMCC_LIBCXX_PATH` 指向 instrumented libc++。

---

## Codex 補充要點（第二輪，含評估結論）

### 1. LLVM 版本相容性（最大風險）

`symcc/build/libsymcc.so` 是 LLVM-14 pass plugin，**必須由 LLVM-14 clang 載入**；版本不符 → plugin load fail 或行為不穩。

確認事實：
- host `clang --version` → Ubuntu clang 14.0.0，位於 `/usr/lib/llvm-14/bin/clang`
- OSS-Fuzz base-builder image 也使用 LLVM-14，此路徑應存在

在 build.sh 裡明確設定（不用模糊的 `"clang"`）：
```bash
export SYMCC_CLANG="/usr/lib/llvm-14/bin/clang"
export SYMCC_CLANGPP="/usr/lib/llvm-14/bin/clang++"
```
若路徑不存在就 build fail，比靜默用錯版本安全。

---

### 2. Artifact Cache 可能復用舊 symcc_library（Codex 修正）

**問題確認**：`_get_project_target_fingerprint()` 只 hash `build.sh`、`Dockerfile`、`llm_fuzzgen*` 檔案，SymCC binary（`libsymcc.so`、`libsymcc-rt.a`）不在 fingerprint 內。Cache key = `proj/sanitizer/variant/fingerprint`。若 SymCC binary 更新但 project 檔案沒變 → fingerprint 不變 → `_restore_build_artifacts_from_cache()` 復用舊 archive。

**解法：SymCC binary digest 納入 variant name（含 Codex 補強）**

在 `run_symcc_blocker.py` 計算 variant 時，hash **全部 5 個** SymCC 相關檔案（wrapper script 也可能影響行為）：

```python
def _symcc_variant_name(symcc_bin_host: Path, length: int = 8) -> str:
    """SymCC binary hash 納入 variant，讓 cache key 跟 SymCC 版本綁定。
    
    包含 wrapper script（symcc, sym++）、LLVM pass（libsymcc.so）、
    和 runtime（libsymcc-rt.a + libsymcc-rt.so，兩個都 hash）。
    任一檔案更新 → hash 變 → cache key 變 → 自動 rebuild。
    """
    h = hashlib.sha256()
    for fname in (
        "symcc",                                                           # wrapper script
        "sym++",                                                           # wrapper script
        "libsymcc.so",                                                     # LLVM pass plugin
        "SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a",      # runtime static
        "SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so",     # runtime shared
    ):
        fpath = symcc_bin_host / fname
        try:
            h.update(fpath.read_bytes())
        except OSError:
            h.update(fname.encode())    # 缺檔也貢獻 hash，讓缺檔和有檔的 key 不同
    return f"symcc_library_{h.hexdigest()[:length]}"
```

傳給 `build_fuzzers(variant=symcc_variant_name(...))` 即可，不需加 `force_rebuild` flag。

---

### 3. symcc_library early exit 後 source_code 遺失（比 Codex 說的更嚴重）

**Codex 的觀察**：symcc_library build 的 `exit 0` 讓 source_code 沒被匯出。

**實際確認更嚴重**：`build_fuzzers()` 永遠傳 `--clean` 給 helper.py，而 helper.py 的 clean 邏輯清掉整個 `/out/`。所以：
1. native_archive build → 匯出 `/out/source_code/` + `/out/symcc_native/libpcap.a` → 存 cache
2. **symcc_library build 啟動 → `--clean` 清掉整個 `/out/`** → source_code 消失
3. symcc_library 早退 → `/out/` 只有 `symcc_library/libpcap.a`
4. run_symcc_blocker.py 後續需要 `source_code/` 做 harness include → 不存在！

**解法：symcc_library build.sh 也匯出 source_code**

在 build.sh 的 symcc_library 匯出區段，`exit 0` 前也做 rsync（複用已有的 source_code 匯出邏輯）：

```bash
if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  # ... nm validation + archive export ...
  
  # source_code 也需要匯出：--clean 會清掉前一個 build flavor 留下的 /out/
  OUT_PROJECT_DIR="$OUT/source_code"
  mkdir -p "$OUT_PROJECT_DIR"
  rsync -a --delete --no-perms \
    --exclude='.git' --exclude='.github' --exclude='.gitignore' \
    --exclude='build' --exclude='CMakeFiles' \
    --exclude='*.o' --exclude='*.a' --exclude='*.so' --exclude='*.dll' \
    "$SRC/libpcap/" "$OUT_PROJECT_DIR/"

  exit 0
fi
```

這讓 symcc_library build flavor 自給自足：cache 存的內容同時包含 symcc_library/libpcap.a 和 source_code/，不依賴前一個 build 的殘留。

---

### 負面 Cache（fail-fast，Codex 補強）

**問題**：run_symcc_blocker.py 是 one-shot script（每個 blocker 獨立 process）→ 若 Docker 無 LLVM-14 或 volume mount 壞掉，每個 blocker 都白跑一次 build 再失敗。

**解法：file-based failure marker**（module-level 變數在不同 process 間無效）

Marker 路徑：`oss_fuzz.build_cache_dir / proj_name / "none" / symcc_variant / ".build_failed"`

在 `run_symcc_blocker.py` 的 symcc_library 區段：

```python
symcc_fail_marker = (
    oss_fuzz.build_cache_dir / args.project_name / "none" / symcc_variant / ".build_failed"
)

if symcc_fail_marker.exists():
    print(f"[warn] symcc_library build previously failed (marker: {symcc_fail_marker}), skipping", flush=True)
    # fall through to native_archive flow
else:
    symcc_lib_build = oss_fuzz.build_fuzzers(...)
    if not symcc_lib_build.success:
        symcc_fail_marker.parent.mkdir(parents=True, exist_ok=True)
        symcc_fail_marker.touch()
        print(f"[warn] symcc_library build failed, marker written; fallback to native_archive", flush=True)
```

Marker 與 variant name 綁定：SymCC 更新 → variant 變 → 舊 marker 不再匹配 → 自動重試。

---

### 啟用條件保護（Enabling Conditions，Codex 補強）

**問題**：並非所有 blocker 都值得跑 symcc_library（成本：一次額外 Docker build + 慢 3-5x 的 SymCC 探索）。

**Phase 1 保護（簡單版，blocker payload 目前沒有 `blocker_type` 欄位）**：

```python
SYMCC_LIBRARY_PROJECTS = {"libpcap"}   # Phase 1 allowlist，libvpx 之後再評估

def _should_use_symcc_library(project_name: str, project_config: dict,
                               blocker_payload: dict) -> bool:
    """決定是否要跑 symcc_library build。"""
    # 1. Project allowlist
    if project_name not in SYMCC_LIBRARY_PROJECTS:
        return False
    # 2. Config 開關
    if not project_config.get("symcc_library", False):
        return False
    # 3. 需要至少 1 個能到達 branch 的 seed（沒有 reaching seed，SYMCC 也探索不到）
    seeds = blocker_payload.get("seeds", [])
    if not seeds:
        print("[info] symcc_library skip: no branch-reaching seeds", flush=True)
        return False
    return True
```

**Phase 2 進一步過濾**（blocker 分類欄位需要 upstream pipeline 提供）：
- skip `blocker_type` in (`abort`, `assert`, `invariant`, `api_state`, `simd`)
- 目前 payload 欄位無此資訊，Phase 2 再補

**Fallback 策略**：symcc_library build/archive 失敗時，`prebuilt_archives` 保持用 native_archive，不影響 existing flow。

---

### 5. run_symcc_blocker.py archive 命名區分

`prebuilt_archives = [lib_path]` 可以工作，但名稱語意混淆（跟 native_archive 共用同一變數）。實作時應使用獨立變數：

```python
symcc_library_archives: list[Path] = []
if _should_use_symcc_library(args.project_name, project_config, blocker_payload):
    # ... build + marker logic ...
    if symcc_lib_archive.is_file():
        symcc_library_archives = [symcc_lib_archive]
        prebuilt_archives = symcc_library_archives   # 明確取代 native archive 用於 link

# Summary dict（Codex 要求的 4 個欄位）
summary["linked_archive_kind"] = "symcc_library" if symcc_library_archives else "native_archive"
summary["symcc_library_archive"] = str(symcc_library_archives[0]) if symcc_library_archives else None
summary["native_archive_path"] = str(native_archive_path) if native_archive_path else None
summary["symcc_library_prepare"] = {
    "build_success": symcc_lib_build.success if symcc_lib_build else None,
    "variant": symcc_variant if symcc_variant else None,
    "archive_found": bool(symcc_library_archives),
    "fail_marker_existed": symcc_fail_marker.exists() if symcc_fail_marker else None,
}
```

`linked_archive_kind` 是最重要的欄位：事後分析時可以直接知道這個 blocker 有沒有真的用到 SYMCC-instrumented archive。

---

### 5. Include 問題的範圍說明

Docker 內 build `symcc_library/libpcap.a` 解決的是 **library 自身的 build context**（include path、generated headers、build tools）。

但 host 端 `symcc_blocker_solver.py` 仍然要編譯 harness/replay driver，如果 harness include 了 project internal headers，host 的 include heuristic 還是可能出問題。

**短期（Phase 1）**：libpcap C harness 的 include 需求少，`-I source_code -I source_code/pcap` 足夠，沒問題。

**長期**：應從 Docker build 匯出 compile_commands.json 或 include manifest，取代 `build_context.py` 的 heuristic 掃目錄。

---

### 6. 兩階段計畫（Codex 建議）

**Phase 1（當前目標）：libpcap only**
- 實作 volume mount + symcc_library build
- 成功標準：**SymCC 對 library 內部條件產生新 seed**（不只是「build pass」）
- 驗證 case：libpcap parsing-layer blocker（`pcap_compile()` 內部格式條件）

**Phase 2（之後穩定化）**
- 匯出 compile/include manifest（Docker → host）
- summary 明確區分 native/symcc archive
- 補 C++ libc++ mount（`SYMCC_LIBCXX_PATH`）
- 再評估 libvpx（SIMD、C++、constraint explosion 等複合風險）

---

---

## LLVM 版本不相容問題（2026-06-06 確認）

### 問題

Phase 1 實作完成後跑 smoke test，`symcc_library` build 失敗：

```
[llm-fuzzgen] ERROR: /usr/lib/llvm-14/bin/clang not in Docker image (LLVM-14 required)
```

調查後確認根本原因：
- `symcc/build/` 裡的 SymCC binary 是用 **host LLVM-14** 編譯的（`libsymcc.so` 是 LLVM-14 pass plugin）
- Docker 容器 `gcr.io/oss-fuzz/libpcap` 使用 **LLVM-18**（`clang 18.1.8` 在 `/usr/local/bin/clang`）
- LLVM pass plugins 有嚴格版本相容性，LLVM-14 的 pass 無法被 LLVM-18 的 clang 載入

### Option B 死路確認

嘗試把 host 的 LLVM-14 相關 shared libraries 掛入 Docker — **失敗**：

```
/usr/lib/llvm-14/bin/clang: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found
```

Host 的 clang-14 binary 需要 `GLIBC_2.32/2.33/2.34`，Docker 容器的 glibc 是舊版（2.31）。無法用 volume mount 把 host 的 LLVM-14 帶進 Docker，這條路確認死路。

### LLVM-14 使用範圍調查結果

LLVM-14 hardcode 僅在兩個地方：

| 位置 | 內容 | 影響 |
|------|------|------|
| `external/oss-fuzz/projects/libpcap/build.sh`（line 98, 105-106） | pre-flight check + `SYMCC_CLANG` 路徑 | Step 1 要改的目標 |
| `symcc/build/CMakeCache.txt` | 原有 LLVM-14 SymCC build 的 cache | 保留不動 |
| `libcxx_symcc_build/CMakeCache.txt` | libcxx LLVM-14 build cache | Phase 1 不影響（libpcap 是純 C） |

**Python 程式碼、OSS-Fuzz builds、Introspector：完全沒有 LLVM-14 hardcode，不受影響。**

`symcc/CMakeLists.txt` 官方支援 LLVM 8–18（line 94），在 Docker 裡用 LLVM-18 build SymCC 有官方支援。

**架構**：`symcc/build/`（LLVM-14，host 用）與 `symcc/build_llvm18/`（LLVM-18，Docker 用）**兩套並存**，互不影響。`build_llvm18/` 是一份共用目錄，所有 project 的 Docker container 都 mount 同一份，不是每個 project 一份。

### Codex 補充（最終版）：三個保護，缺一不可

**保護 1：build.sh + run_symcc_blocker.py 切到 build_llvm18（必須，現在就失敗）**
- `build.sh` line 98 還在檢查 `/usr/lib/llvm-14/bin/clang` → Docker 容器沒有 → exit 1
- `run_symcc_blocker.py` line 477 還在 mount `symcc/build`（LLVM-14 pass）→ 即使 mount 進去也因 LLVM 版本不符無法使用
- **修正**：Step 1 改 build.sh SYMCC_CLANG 路徑；Step 2 改 run_symcc_blocker.py symcc_bin_host

**保護 2：oss_fuzz.py 修 symcc_library cache restore（必須，否則每次重建）**
- `_has_built_llm_targets()`（line 181-185）只找 `llm_fuzzgen*` binary，`symcc_library` build 沒有這類檔案
- `_restore_build_artifacts_from_cache()` line 270 永遠 False → cache 永遠 miss → 每次重建，成本浪費
- **修正**：Step 3 新增 `_has_built_symcc_library_artifact()`，修改 line 270 加 `or` 條件

**保護 3：run_symcc_blocker.py 變數初始化移到 if 外（防禦性）**
- `symcc_library_archives`、`symcc_variant`、`symcc_fail_marker` 等在 if block（line 413-569）內初始化（line 469-473）
- summary dict（line 570-595）在 if 外使用這些變數
- 若 explicit-source 模式不進 if block → NameError
- 正常 classifier 入口有 project/target 不會觸發，但這是潛在 bug
- **修正**：Step 2 中，把 line 469-473 的初始化移到 if block 之前（line 413 之前）

**Runtime 不一致（已知混合狀態，記錄即可，不強制修正）**
- `libpcap.a`：Docker 內 **LLVM-18 SymCC pass** 插樁
- Harness 編譯 + link：host **LLVM-14 symcc wrapper** + LLVM-14 `libsymcc-rt.a`
- `_sym_*` ABI：兩個 build 來自同一份 source，大概率一致，**但不能說「保證安全」**，需 smoke test 驗證
- **Phase 1 策略**：記錄到 summary `runtime_note`，smoke test 後若無異常繼續；Phase 2 評估 host final link 是否也切到 `build_llvm18/` runtime

### 解決方案（Option A）：在 Docker 容器內重建 SymCC for LLVM-18

**Step 0（一次性手動）**：在 Docker 容器內用 LLVM-18 重建 SymCC，輸出到 `symcc/build_llvm18/`

```bash
docker run --rm \
  -v /home/kyliechien/LLM-FuzzGen/symcc:/symcc-src \
  gcr.io/oss-fuzz/libpcap bash -c "
    apt-get update -q &&
    apt-get install -y cmake ninja-build z3 libz3-dev &&
    mkdir -p /symcc-src/build_llvm18 && cd /symcc-src/build_llvm18 &&
    cmake /symcc-src \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DZ3_TRUST_SYSTEM_VERSION=ON &&
    ninja -j\$(nproc)
  "
```

輸出：`symcc/build_llvm18/symcc`, `sym++`, `libsymcc.so`, `SymCCRuntime-prefix/...`

**Step 1**：修改 `external/oss-fuzz/projects/libpcap/build.sh`
- 移除 `test -x "/usr/lib/llvm-14/bin/clang"` 的 pre-flight 檢查
- 把 `SYMCC_CLANG="/usr/lib/llvm-14/bin/clang"` 改為 `SYMCC_CLANG="/usr/local/bin/clang"`（Docker 的 LLVM-18）
- 把 `SYMCC_CLANGPP="/usr/lib/llvm-14/bin/clang++"` 改為 `SYMCC_CLANGPP="/usr/local/bin/clang++"`

**Step 2**：修改 `blocker_process/dependent/run_symcc_blocker.py`
- 把 `symcc_bin_host = REPO_ROOT / "symcc" / "build"` 改為 `REPO_ROOT / "symcc" / "build_llvm18"`
- `_symcc_variant_name()` 會自動算出新 hash → variant name 不同 → cache 不會復用舊 archive

---

## 待辦

- [x] 確認 Docker volume mount 方案（不複製 binary 進 image）
- [x] 確認 LLVM-14 版本相容性策略（明確用 `/usr/lib/llvm-14/bin/clang`）← **此策略已作廢，改為 LLVM-18**
- [x] 確認 nm validation 正確 pattern（`[[:space:]]U[[:space:]]+_sym_`，單底線）
- [x] 確認 artifact cache 問題 → variant name 帶 SymCC digest
- [x] 確認 --clean 問題 → symcc_library build.sh 也匯出 source_code
- [x] 確認 negative cache 方案：file-based marker
- [x] 確認 enabling conditions：Phase 1 project allowlist + `len(seeds) > 0`
- [x] 確認 summary 欄位：4 個欄位
- [x] **Phase 1：libpcap symcc_library 實作（5 個檔案已修改）**
  - [x] `external/oss-fuzz/infra/helper.py`
  - [x] `external/oss_fuzz.py`
  - [x] `external/oss-fuzz/projects/libpcap/build.sh`
  - [x] `external/oss-fuzz/projects/libpcap/symcc_config.json`
  - [x] `blocker_process/dependent/run_symcc_blocker.py`
- [ ] **LLVM-18 修正（當前 blocker）**
  - [ ] Step 0：在 Docker 容器內重建 SymCC → `symcc/build_llvm18/`（一次性手動）
    ```bash
    # 前置確認 Docker 容器有 LLVMConfig.cmake
    docker run --rm gcr.io/oss-fuzz/libpcap bash -c "
      find /usr -name 'LLVMConfig.cmake' 2>/dev/null | head -5
      which llvm-config-18 2>/dev/null || which llvm-config 2>/dev/null
    "
    # 重建 SymCC（mount source，output 到 build_llvm18/）
    docker run --rm \
      -v /home/kyliechien/LLM-FuzzGen/symcc:/symcc-src \
      gcr.io/oss-fuzz/libpcap bash -c "
        apt-get update -q &&
        apt-get install -y cmake ninja-build z3 libz3-dev &&
        mkdir -p /symcc-src/build_llvm18 && cd /symcc-src/build_llvm18 &&
        cmake /symcc-src -GNinja -DCMAKE_BUILD_TYPE=Release -DZ3_TRUST_SYSTEM_VERSION=ON &&
        ninja -j\$(nproc)
      "
    ```
    最小驗證（build 完之後先跑）：
    ```bash
    # 驗證 binary 可執行
    /home/kyliechien/LLM-FuzzGen/symcc/build_llvm18/symcc --version
    # 驗證能 instrument 最小 C 檔案（要有 _sym_* 符號）
    echo 'int main(){return 0;}' > /tmp/test_symcc.c
    SYMCC_NO_SYMBOLIC_INPUT=1 \
      SYMCC_PASS_DIR=/home/kyliechien/LLM-FuzzGen/symcc/build_llvm18 \
      SYMCC_RUNTIME_DIR=/home/kyliechien/LLM-FuzzGen/symcc/build_llvm18/SymCCRuntime-prefix/src/SymCCRuntime-build \
      /home/kyliechien/LLM-FuzzGen/symcc/build_llvm18/symcc /tmp/test_symcc.c -o /tmp/test_out
    nm /tmp/test_out | grep _sym_ | head -5
    ```
  - [ ] Step 1：修改 `build.sh`（保護 1，2 處）：移除 LLVM-14 pre-flight check（line 98），`SYMCC_CLANG`/`SYMCC_CLANGPP` 改為 `/usr/local/bin/clang[++]`（line 105-106）
  - [ ] Step 2：修改 `run_symcc_blocker.py`（保護 1 + 保護 3，3 處）：
    - `symcc_bin_host` 改為 `REPO_ROOT / "symcc" / "build_llvm18"`
    - 把 line 469-473 的 symcc_library 變數初始化（`symcc_library_archives=[]`、`symcc_variant=None`、`symcc_fail_marker=None`、`symcc_lib_build_result=None`、`symcc_lib_archive=None`）移到 `if args.project_name and args.target_name:` block（line 413）**之前**
    - summary dict 加 `runtime_note`（記錄混合 runtime 狀態，標注「大概率一致但需 smoke test」）
  - [ ] Step 3：修改 `external/oss_fuzz.py`（保護 2：cache 修正）：新增 `_has_built_symcc_library_artifact()` method，修改 `_restore_build_artifacts_from_cache()` line 270 加 or 條件
    ```python
    def _has_built_symcc_library_artifact(self, proj_name: str, variant: str) -> bool:
        if not variant.startswith("symcc_library"):
            return False
        lib_dir = self.build_out_dir / proj_name / "symcc_library"
        if not lib_dir.exists():
            return False
        return any(f.suffix == ".a" and f.is_file() for f in lib_dir.iterdir())
    # line 270 改為：
    return (self._has_built_llm_targets(proj_name)
            or self._has_built_symcc_library_artifact(proj_name, variant))
    ```
  - [ ] Step 4：smoke test 確認 `symcc_library` build 成功，nm 有 `_sym_*` symbols，summary 的 `linked_archive_kind`/`runtime_note` 正確
- [ ] **驗證（build 成功後）**：libpcap parsing-layer blocker，**成功標準：SymCC 對 library 內部條件產生新 seed**
- [ ] **Phase 2（之後）**：blocker_type 細粒度過濾、include manifest 匯出、libvpx 評估、C++ libc++ mount
