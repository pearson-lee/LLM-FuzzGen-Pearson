# SymCC build_llvm18 (symcc_library) GLIBC 不相容問題與修復紀錄 (2026-09-16)

## 1. 問題概述

在依據專案步驟執行 SymCC target 建置測試時：
```bash
./scripts/test_symcc_builds.sh --projects 'cjson' --flavor all
```
`symcc_native` 與 `symcc_replay` 建置成功，但 `symcc_library` 失敗：

```text
Building cjson           / symcc_native       ... PASS  libcjson.a (84K)
Building cjson           / symcc_library      ... FAIL
Building cjson           / symcc_replay       ... PASS  (build ok)

================================================================
 SymCC Build Test Summary
================================================================
Project             Flavor              Result
----------------------------------------------------------------
cjson               symcc_native        PASS  libcjson.a (84K)
cjson               symcc_library       FAIL  build error (see logs/symcc_test/cjson_symcc_library.log)
cjson               symcc_replay        PASS  build ok
```

---

## 2. 原始錯誤日誌

查閱原始失敗日誌（已歸檔於 `logs/cjson_symcc_library_failed.log`）第 301-314 行：

```text
-- The C compiler identification is unknown
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - failed
-- Check for working C compiler: /symcc-bin/symcc
-- Check for working C compiler: /symcc-bin/symcc - broken
CMake Error at /usr/local/share/cmake-3.29/Modules/CMakeTestCCompiler.cmake:67 (message):
  The C compiler

    "/symcc-bin/symcc"

  is not able to compile a simple test program.

  It fails with the following output:

    Change Dir: '/src/cjson/build/CMakeFiles/CMakeScratch/TryCompile-uiCipq'
    
    Run Build Command(s): /usr/local/bin/cmake -E env VERBOSE=1 /usr/bin/make -f Makefile cmTC_2453c/fast
    /usr/bin/make  -f CMakeFiles/cmTC_2453c.dir/build.make CMakeFiles/cmTC_2453c.dir/build
    make[1]: Entering directory '/src/cjson/build/CMakeFiles/CMakeScratch/TryCompile-uiCipq'
    Building C object CMakeFiles/cmTC_2453c.dir/testCCompiler.c.o
    /symcc-bin/symcc   -O1 -fno-omit-frame-pointer -gline-tables-only ... -c testCCompiler.c
    error: unable to load plugin '/symcc-bin/libsymcc.so': 'Could not load library '/symcc-bin/libsymcc.so': /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /symcc-bin/libsymcc.so)'
    1 error generated.
    make[1]: *** [CMakeFiles/cmTC_2453c.dir/build.make:78: CMakeFiles/cmTC_2453c.dir/testCCompiler.c.o] Error 1
    make[1]: Leaving directory '/src/cjson/build/CMakeFiles/CMakeScratch/TryCompile-uiCipq'
    make: *** [Makefile:127: cmTC_2453c/fast] Error 2
```

---

## 3. Root Cause（根本原因分析）

1. **掛載機制**：
   - 專案在編譯 `symcc_library` 時，會透過 Docker volume mount 將 Host 端的 `symcc/build_llvm18/` 目錄掛載至 OSS-Fuzz 容器內的 `/symcc-bin`。
   - 容器內編譯器 `/usr/local/bin/clang` 在編譯程式碼時，會由 `/symcc-bin/symcc` 自動傳入 `-Xclang -load -Xclang /symcc-bin/libsymcc.so`，載入 `libsymcc.so` 作為 LLVM pass plugin 來進行符號執行插樁。

2. **GLIBC 與系統版本不相容**：
   - **Host 環境**：系統為 **Ubuntu 22.04 LTS (Jammy)**，內建 **glibc 2.35**。在 Host 端直接編譯出來的 `symcc/build_llvm18/libsymcc.so`，動態連結了 Host 系統的 `GLIBC_2.32`（經 `readelf -s` 檢驗為 `__libc_single_threaded@GLIBC_2.32` 符號）。
   - **Docker 容器環境**：OSS-Fuzz 的基礎映像檔（`gcr.io/oss-fuzz-base/base-builder` / `gcr.io/oss-fuzz/cjson`）為 **Ubuntu 20.04 LTS (Focal)**，容器內的動態函式庫僅提供到 **glibc 2.31**。

3. **導致結果**：
   容器內的 Clang 在執行 plugin dlopen 時，容器內的 `/lib/x86_64-linux-gnu/libc.so.6` 無法滿足 `GLIBC_2.32` 要求，導致動態載入失敗，CMake 在檢查編譯器（`CMakeTestCCompiler.cmake`）時直接噴錯中止。

---

## 4. 修復方式（Fix Method）

如文檔 `TODO_MD/symcc_to_docker.md` 所述，**`symcc/build_llvm18` 不能在 Host 端編譯，必須直接在 OSS-Fuzz `base-builder` Docker 容器內建置**，以保證生成的二進位檔使用容器的 Ubuntu 20.04 (glibc 2.31) 環境。

### 重建指令

```bash
docker run --rm \
  -v "$PWD/symcc":/symcc-src \
  gcr.io/oss-fuzz-base/base-builder bash -c "
    set -e &&
    apt-get update -q &&
    apt-get install -y cmake ninja-build z3 libz3-dev zlib1g-dev libncurses5-dev libtinfo-dev llvm-18-dev &&
    LLVM_CMAKE=\$(llvm-config-18 --cmakedir) &&
    rm -rf /symcc-src/build_llvm18/* &&
    mkdir -p /symcc-src/build_llvm18 && cd /symcc-src/build_llvm18 &&
    env CFLAGS='' CXXFLAGS='' LDFLAGS='' cmake /symcc-src \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DZ3_TRUST_SYSTEM_VERSION=ON \
      -DSYMCC_RT_BACKEND=simple \
      -DCMAKE_CXX_FLAGS='-fno-rtti' \
      -DLLVM_DIR=\"\$LLVM_CMAKE\" \
      -DCLANG_BINARY=/usr/local/bin/clang \
      -DCLANGPP_BINARY=/usr/local/bin/clang++ &&
    ninja -j\$(nproc) &&
    chown -R $(id -u):$(id -g) /symcc-src/build_llvm18
  "
```

### 關鍵參數說明
- `llvm-18-dev`：容器自帶 Focal 的 LLVM 18 套件，提供符合容器環境的 CMake 設定。
- `-DCMAKE_CXX_FLAGS='-fno-rtti'`：OSS-Fuzz 自訂 clang-18 是以 RTTI OFF 編譯，避免 `libsymcc.so` 因 RTTI 找不到 `typeinfo for llvm::CallbackVH`。
- `env CFLAGS='' CXXFLAGS=''`：避免 OSS-Fuzz 環境預設的 sanitizer flags 污染 pass 編譯。
- `chown -R $(id -u):$(id -g)`：確保容器內產生的檔案由目前使用者擁有，避免權限問題。

---

## 5. 驗證結果

重新執行建置測試：
```bash
./scripts/test_symcc_builds.sh --projects 'cjson' --flavor all
```

測試全數通過（PASS）：
```text
SymCC build test — 2026-09-16 20:28:45
SYMCC_BIN: /home/peason/projects/LLM-FuzzGen-Pearson/symcc/build_llvm18

Building cjson           / symcc_native       ... PASS  libcjson.a (84K)
Building cjson           / symcc_library      ... PASS  libcjson.a (612K)
  [ok]   symcc_library/libcjson.a: 52 _sym_* refs found (SymCC instrumented)
Building cjson           / symcc_replay       ... PASS  (build ok)

================================================================
 SymCC Build Test Summary
================================================================
Project             Flavor              Result
----------------------------------------------------------------
cjson               symcc_native        PASS  libcjson.a (84K)
cjson               symcc_library       PASS  libcjson.a (612K)
cjson               symcc_replay        PASS  build ok

All tested builds passed.
```

---

## 6. 歸檔檔案清單

本資料夾內檔案結構如下：
- `summary.md`：本總結紀錄。
- `logs/cjson_symcc_library_failed.log`：原始遭遇 `GLIBC_2.32 not found` 的失敗日誌。
- `logs/cjson_symcc_library_success.log`：修復後成功編譯出插樁版 `libcjson.a` 的日誌。
- `logs/cjson_symcc_native.log`：原生 native flavor 的建置日誌。
- `logs/cjson_symcc_replay.log`：replay coverage flavor 的建置日誌。
