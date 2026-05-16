# SymCC Setup

## 目的

記錄這個 repo 在 blocker-solving pipeline 會用到的基本 SymCC 安裝方式，避免之後系統整合時每個人各自重建一套不一樣的環境。

這份文件只處理「一般 SymCC」。  
如果 target 的 branch 會穿過 STL 內部邏輯，請另外看 `docs/setup_symcc_stl.md`。

## 使用情境

適用於：

- 一般 C target
- 一般 C++ target
- branch 條件主要不依賴 STL 內部操作

不適用於：

- `std::string`
- `std::vector`
- `std::map`
- `std::unordered_map`

這類 STL 元件內部運算需要保留 symbolic trace 的情況。

## 需求

- Ubuntu 22.04
- `cmake`
- `ninja-build`
- `clang-14`
- `llvm-14`
- `llvm-14-dev`
- `libz3-dev`
- `zlib1g-dev`
- `libxml2-dev`
- `git`
- `build-essential`

安裝範例：

```bash
sudo apt update
sudo apt install -y \
  git cmake ninja-build clang-14 llvm-14 llvm-14-dev \
  libz3-dev zlib1g-dev libxml2-dev build-essential
```

## 建置方式

在 repo 內保留一份獨立的 SymCC build 目錄，不要把之後 STL 用的 `build_simple` 跟這份混在一起。

```bash
cd /home/kyliechien/LLM-FuzzGen/symcc
mkdir -p build
cd build

cmake -G Ninja .. \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZ3_TRUST_SYSTEM_VERSION=on

ninja
```

如果要順便跑檢查：

```bash
ninja check
```

## 驗證

確認產物存在：

```bash
ls /home/kyliechien/LLM-FuzzGen/symcc/build/symcc
ls /home/kyliechien/LLM-FuzzGen/symcc/build/sym++
```

最小 smoke test：

```bash
cat <<'EOF' > /tmp/symcc_smoke.c
#include <stdio.h>
int main(void) { puts("ok"); return 0; }
EOF

/home/kyliechien/LLM-FuzzGen/symcc/build/symcc -o /tmp/symcc_smoke /tmp/symcc_smoke.c
/tmp/symcc_smoke
```

## 環境變數

- `SYMCC_REGULAR_LIBCXX=yes`
  - 讓 `sym++` 使用系統 C++ standard library。
  - 這種模式下 STL 內部邏輯通常會被 concretize。
- `SYMCC_LIBCXX_PATH=/path/to/libcxx`
  - 指向 instrumented `libc++`。
  - 只有在需要 STL tracing 時才設定。
- `SYMCC_NO_SYMBOLIC_INPUT=yes`
  - 建置 helper program 時避免把輸入當 symbolic source。

## 規則

- 不要把 SymCC build 目錄 commit 進 Git。
- 不要全域 export `SYMCC_LIBCXX_PATH`，避免污染 blocker pipeline。
- 如果 target 的 branch 會經過 STL 內部操作，改用 `docs/setup_symcc_stl.md` 的流程。
