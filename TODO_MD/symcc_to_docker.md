# SymCC 掛入 Docker 的完整處理紀錄

## 問題根源

`symcc/build/` 是在 host 用 **LLVM-14** 編譯的。
OSS-Fuzz libpcap Docker 容器使用 **LLVM-18**（`/usr/local/bin/clang`）。
LLVM pass plugin（`libsymcc.so`）有嚴格的 ABI 相容性要求，版本不符直接 load 失敗。

---

## 解法：在 Docker 容器內重建 SymCC → `symcc/build_llvm18/`

**不動** `symcc/build/`（host 側繼續用 LLVM-14 做 harness compile）。

### Step 0：一次性手動重建（用戶手動執行）

```bash
sudo rm -rf /home/kyliechien/LLM-FuzzGen/symcc/build_llvm18

docker run --rm \
  -v /home/kyliechien/LLM-FuzzGen/symcc:/symcc-src \
  gcr.io/oss-fuzz/libpcap bash -c "
    set -e &&
    apt-get update -q &&
    apt-get install -y cmake ninja-build z3 libz3-dev zlib1g-dev libncurses5-dev libtinfo-dev llvm-18-dev &&
    LLVM_CMAKE=\$(llvm-config-18 --cmakedir) &&
    echo \"[info] LLVM cmake: \$LLVM_CMAKE\" &&
    mkdir -p /symcc-src/build_llvm18 && cd /symcc-src/build_llvm18 &&
    env CFLAGS='' CXXFLAGS='' LDFLAGS='' cmake /symcc-src \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DZ3_TRUST_SYSTEM_VERSION=ON \
      -DSYMCC_RT_BACKEND=simple \
      -DCMAKE_CXX_FLAGS='-fno-rtti' \
      -DLLVM_DIR=\"\$LLVM_CMAKE\" &&
    ninja -j\$(nproc) &&
    echo '[step] build_llvm18 done'
  "
```

### 為什麼這些 cmake flags？

| Flag | 原因 |
|------|------|
| `llvm-18-dev` from Ubuntu apt | 容器的 clang-18 是從 Ubuntu focal apt 裝的，cmake 檔案必須用同一份才能 ABI 相容；掛 host 的 LLVM-18（libc++ build）會 ABI 不符 |
| `-DSYMCC_RT_BACKEND=simple` | qsym backend 需要 `std::filesystem` cmake target + 二次 `find_package(LLVM)`，simple backend 都不需要 |
| `-DCMAKE_CXX_FLAGS='-fno-rtti'` | OSS-Fuzz 自訂 clang-18 是 RTTI OFF 編的（`libsymcc.so` 若用 RTTI 會找不到 `typeinfo for llvm::CallbackVH`） |
| `libncurses5-dev libtinfo-dev` | Ubuntu apt 的 `llvm-18-dev` cmake 設定依賴 `Terminfo::terminfo`，需要安裝 ncurses |
| `env CFLAGS='' CXXFLAGS=''` | 避免 OSS-Fuzz 環境的 sanitizer flags 汙染 SymCC pass 的編譯 |

### 驗證 build 結果

```bash
ls -la symcc/build_llvm18/symcc
ls -la symcc/build_llvm18/libsymcc.so
ls -la symcc/build_llvm18/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a
```

---

## 程式碼改動（Agent 負責）

### 1. `external/oss-fuzz/projects/libpcap/build.sh`

**移除** LLVM-14 pre-flight 檢查：
```bash
# 已刪除：
# test -x "/usr/lib/llvm-14/bin/clang" || { echo "[llm-fuzzgen] ERROR..." >&2; exit 1; }
```

**改 SYMCC_CLANG 路徑**（LLVM-14 → LLVM-18）：
```bash
export SYMCC_CLANG="/usr/local/bin/clang"
export SYMCC_CLANGPP="/usr/local/bin/clang++"
```

**symcc_library cmake 前安裝 libz3-4**：
```bash
if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  # libsymcc-rt.so (simple backend) 依賴 Z3；裝 shared library 讓 cmake
  # compiler/feature test 的 link 步驟可以成功
  apt-get install -y libz3-4 -q 2>/dev/null || true
fi
cmake ..
```

> 為什麼要裝 libz3-4？
> symcc wrapper 對每次 compiler invocation 都加 `-lsymcc-rt`。
> cmake 的 compiler test 嘗試 link 時，`libsymcc-rt.so` 需要 `libz3.so`，
> 但 libpcap 容器沒裝 Z3 → link 失敗。
> 安裝 `libz3-4`（runtime library only）解決這個問題。

---

### 2. `blocker_process/dependent/run_symcc_blocker.py`

**改 symcc_bin_host 路徑**：
```python
# 改前：symcc_bin_host = REPO_ROOT / "symcc" / "build"
symcc_bin_host = REPO_ROOT / "symcc" / "build_llvm18"
```

**變數初始化移到 if block 外**（防止 explicit-source mode 下 NameError）：
```python
# 移到 if args.project_name and args.target_name: 之前
symcc_library_archives: list[Path] = []
symcc_lib_archive: Path | None = None
symcc_lib_build_result = None
symcc_variant: str | None = None
symcc_fail_marker: Path | None = None
```

**summary dict 加 runtime_note**（記錄混合 ABI 狀態）：
```python
"runtime_note": (
    "library: LLVM-18 pass (Docker build_llvm18), "
    "harness+link: LLVM-14 runtime (host symcc/build/); "
    "same source → _sym_* API compatible"
),
```

---

### 3. `external/oss_fuzz.py`

**新增 `_has_built_symcc_library_artifact()` method**：
```python
def _has_built_symcc_library_artifact(self, proj_name: str, variant: str) -> bool:
    if not variant.startswith("symcc_library"):
        return False
    lib_dir = self.build_out_dir / proj_name / "symcc_library"
    if not lib_dir.exists():
        return False
    return any(f.suffix == ".a" and f.is_file() for f in lib_dir.iterdir())
```

**修改 `_restore_build_artifacts_from_cache()` 第 270 行**：
```python
# 改前：return self._has_built_llm_targets(proj_name)
return (self._has_built_llm_targets(proj_name)
        or self._has_built_symcc_library_artifact(proj_name, variant))
```

> 為什麼需要這個？
> `symcc_library` build 只產生 `symcc_library/libpcap.a`，沒有 `llm_fuzzgen*` 執行檔。
> 舊的 `_has_built_llm_targets()` 永遠回傳 False → cache 永遠 miss → 每次重建。

---

## Docker Image 重建

每次修改 `build.sh` 後，需要重建 Docker image：

```bash
echo n | python external/oss-fuzz/infra/helper.py build_image libpcap
```

> 選 `n` 不拉新 base image，只用本地已有的 base 重打 libpcap image。

---

## End-to-End 測試指令範例

```bash
python blocker_process/dependent/run_symcc_blocker.py \
  --project-name libpcap \
  --target-name fuzz_pcap \
  --blocker-json-file /path/to/blocker.json \
  --seed /path/to/seed.pcap \
  --max-generations 5 \
  --timeout-sec 30 \
  --json-output \
  --symcc symcc/build/symcc \
  --sympp symcc/build/sym++
```

> `--symcc` / `--sympp` 仍指向 host 的 `symcc/build/`（LLVM-14, qsym backend）。
> `symcc_library` 部分（Docker 內的 instrumentation）是由 `run_symcc_blocker.py` 的
> `symcc_bin_host = REPO_ROOT / "symcc" / "build_llvm18"` 控制，不是這個參數。

---

## 已知混合 ABI 狀態（可接受）

| 元件 | 版本 | 位置 |
|------|------|------|
| SymCC LLVM pass（Docker 內插樁用） | LLVM-18, simple backend, RTTI OFF | `symcc/build_llvm18/libsymcc.so` |
| SymCC runtime（host harness link 用） | LLVM-14, qsym backend | `symcc/build/SymCCRuntime-prefix/.../libsymcc-rt.a` |

兩者來自相同的 SymCC source，`_sym_*` API 完全相同，功能上相容。
LLVM pass 和 runtime 版本不一致是已知狀態，記錄在 summary dict 的 `runtime_note`。

---

## Smoke Test 驗證指令

```bash
# 1. 建 image
echo n | python external/oss-fuzz/infra/helper.py build_image libpcap

# 2. 跑 symcc_library build
PROJ_OUT="/tmp/symcc_smoke_out"
PROJ_WORK="/tmp/symcc_smoke_work"
rm -rf "$PROJ_OUT" "$PROJ_WORK" && mkdir -p "$PROJ_OUT" "$PROJ_WORK"

docker run --rm \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=none \
  -e ARCHITECTURE=x86_64 -e FUZZING_LANGUAGE=c \
  -e LLM_FUZZGEN_BUILD_FLAVOR=symcc_library \
  -e LLM_FUZZGEN_BUILD_SYMCC_LIBRARY=1 \
  -v /home/kyliechien/LLM-FuzzGen/symcc/build_llvm18:/symcc-bin:ro \
  -v "$PROJ_OUT":/out -v "$PROJ_WORK":/work \
  gcr.io/oss-fuzz/libpcap 2>&1 | grep -E 'validated|ERROR|error'

# 3. 驗證 SymCC 插樁符號
nm -A "$PROJ_OUT/symcc_library/libpcap.a" | \
  grep -E '[[:space:]]U[[:space:]]+_sym_' | head -10
```

預期看到：`[llm-fuzzgen] symcc_library archive validated OK` 和大量 `U _sym_*` undefined refs。
