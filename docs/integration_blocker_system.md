# SymCC Integration with Blocker System

## 目的

記錄 SymCC 之後要怎麼掛進 blocker-solving pipeline，避免未來討論系統層時把環境假設、模式切換條件、與風險散落在聊天記錄裡。

## 模式

目前先定義兩種模式：

1. Regular SymCC
   - 用一般 SymCC 環境跑 target
   - 不追 STL 內部 symbolic computation
2. SymCC + instrumented libc++
   - 用額外 build 的 `libc++` 讓 symbolic trace 可以穿過 STL

## 決策規則

以下情況優先使用 Regular SymCC：

- C target
- branch 條件主要在 plain C / low-level logic
- C++ target 但 branch 判斷不依賴 STL 內部操作

以下情況切到 STL 模式：

- symbolic input 經過 `std::string` 再做比較
- symbolic input 經過 `std::vector` 再做比較
- branch 條件依賴 `std::map` / `std::unordered_map`
- target 的深層 branch 主要藏在 STL 轉換流程

## 路徑與隔離原則

建議保留以下分工：

- `symcc/build`
  - 原本一般用途的 SymCC build
- `symcc/build_simple`
  - 專門拿來建 instrumented `libc++`
- `llvm-project-14`
  - STL build 專用 source tree
- `libcxx_symcc_install`
  - instrumented `libc++` install 位置

不要覆蓋這些目錄的角色。

## 環境變數規則

- `SYMCC_REGULAR_LIBCXX=yes`
  - 使用系統 C++ standard library
- `SYMCC_NO_SYMBOLIC_INPUT=yes`
  - 建置 helper program 時停用 symbolic input
- `SYMCC_LIBCXX_PATH=/path/to/libcxx_symcc_install`
  - 指定 instrumented `libc++`

重要規則：

- 不要在 shell profile 或全域環境長期 export `SYMCC_LIBCXX_PATH`
- 只在需要 STL 模式的單次 command 上指定

範例：

```bash
SYMCC_LIBCXX_PATH=/home/kyliechien/LLM-FuzzGen/libcxx_symcc_install \
/home/kyliechien/LLM-FuzzGen/symcc/build_simple/sym++ \
  -O0 -g -o target target.cpp
```

## 建議整合方式

如果未來 blocker system 要依 target 特性切換模式，建議 decision point 放在「編譯 target」之前，而不是已經編完 binary 後才補救。

建議最小邏輯：

1. 判斷 target 是否為 C++
2. 判斷 branch 條件是否可能經過 STL
3. 若否，走 Regular SymCC
4. 若是，走 STL 模式並在編譯 command 上加 `SYMCC_LIBCXX_PATH`

## 不要做的事

- 不要把 LLVM source tree commit 進 repo
- 不要把 `libcxx_symcc_build/` 或 `libcxx_symcc_install/` commit 進 repo
- 不要把 `symcc/build_simple/` commit 進 repo
- 不要讓 blocker pipeline 預設永遠開 STL 模式

## 目前已知版本假設

- LLVM source for STL mode: `llvmorg-14.0.6`
- `libc++` build backend: SymCC simple backend

如果未來升級 LLVM，請把：

- 新版本號
- 成功 build 指令
- 相容性修正

一起補回 `docs/setup_symcc_stl.md`。
