# SymCC STL Setup

## 目的

讓 SymCC 在 C++ target 上不只「能編譯」，而是能繼續追蹤 STL 內部的 symbolic computation。

一般 `sym++` 直接搭配系統標準庫時，資料一旦進入 `std::string`、`std::vector` 之類的 STL 容器，常會被 concretize，導致 branch 條件追不到。

要解這個問題，需要另外建一份被 SymCC instrument 過的 `libc++`。

## 目前固定版本

目前先記錄已知較穩的版本組合：

- SymCC: repo 內 `symcc/`
- LLVM source: `llvmorg-14.0.6`
- build instrumented `libc++` 時使用 SymCC `simple backend`

這個版本選擇的原因很直接：

- 新版 LLVM 在 `libc++` / `libc++abi` 的 CMake target 與 distribution component 上變動較大
- `llvmorg-14.0.6` 跟現有 SymCC 文件相容性較好

## 什麼情況要用

以下情況應該切到 STL 版 SymCC：

- branch 判斷經過 `std::string`
- branch 判斷經過 `std::vector`
- branch 判斷經過 `std::map`
- branch 判斷經過 `std::unordered_map`
- symbolic input 進入 STL 容器後才做轉換或比較

## 目錄規劃

建議使用以下隔離目錄：

- `/home/kyliechien/LLM-FuzzGen/llvm-project-14`
- `/home/kyliechien/LLM-FuzzGen/symcc/build_simple`
- `/home/kyliechien/LLM-FuzzGen/libcxx_symcc_build`
- `/home/kyliechien/LLM-FuzzGen/libcxx_symcc_install`

不要覆蓋原本 `symcc/build`。

## 需求

```bash
sudo apt update
sudo apt install -y \
  git cmake ninja-build clang-14 llvm-14 llvm-14-dev \
  libz3-dev zlib1g-dev libxml2-dev build-essential
```

## Step 1: 下載 LLVM 14 source

```bash
cd /home/kyliechien/LLM-FuzzGen
git clone -b llvmorg-14.0.6 --depth 1 \
  https://github.com/llvm/llvm-project.git llvm-project-14
```

## Step 2: 建 SymCC simple backend

這份 build 只用來建 instrumented `libc++`。

```bash
cd /home/kyliechien/LLM-FuzzGen/symcc
mkdir -p build_simple
cd build_simple

cmake -G Ninja .. \
  -DSYMCC_RT_BACKEND=simple \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZ3_TRUST_SYSTEM_VERSION=on

ninja
```

確認：

```bash
ls /home/kyliechien/LLM-FuzzGen/symcc/build_simple/symcc
ls /home/kyliechien/LLM-FuzzGen/symcc/build_simple/sym++
```

## Step 3: 建 instrumented libc++

```bash
cd /home/kyliechien/LLM-FuzzGen
rm -rf libcxx_symcc_build libcxx_symcc_install
mkdir libcxx_symcc_build
cd libcxx_symcc_build

export SYMCC_REGULAR_LIBCXX=yes
export SYMCC_NO_SYMBOLIC_INPUT=yes

cmake -G Ninja /home/kyliechien/LLM-FuzzGen/llvm-project-14/llvm \
  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/home/kyliechien/LLM-FuzzGen/libcxx_symcc_install \
  -DCMAKE_C_COMPILER=/home/kyliechien/LLM-FuzzGen/symcc/build_simple/symcc \
  -DCMAKE_CXX_COMPILER=/home/kyliechien/LLM-FuzzGen/symcc/build_simple/sym++

ninja distribution
ninja install-distribution

unset SYMCC_REGULAR_LIBCXX
unset SYMCC_NO_SYMBOLIC_INPUT
```

## Step 4: 使用 instrumented libc++

編譯 STL target 時，單次指定 `SYMCC_LIBCXX_PATH`：

```bash
SYMCC_LIBCXX_PATH=/home/kyliechien/LLM-FuzzGen/libcxx_symcc_install \
/home/kyliechien/LLM-FuzzGen/symcc/build_simple/sym++ \
  -O0 -g -o testSymccSTL_sym /home/kyliechien/LLM-FuzzGen/testSymccSTL.cpp
```

## 驗證

先確認 install 結果存在：

```bash
ls /home/kyliechien/LLM-FuzzGen/libcxx_symcc_install/include/c++/v1
ls /home/kyliechien/LLM-FuzzGen/libcxx_symcc_install/lib
```

再試跑：

```bash
printf 'hello' | /home/kyliechien/LLM-FuzzGen/testSymccSTL_sym
printf 'abc' | /home/kyliechien/LLM-FuzzGen/testSymccSTL_sym
```

`testSymccSTL.cpp` 的成功輸入是 `hello`。  
不要手動輸入後按 Enter，不然 `read()` 會把 `\n` 一起吃進去，結果會失真。

## `testSymccSTL.cpp` 觀察重點

這個測試檔用來確認 symbolic input 是否能穿過 STL：

- `read()` 提供 symbolic-friendly input source
- `std::string input(buf, len)` 把輸入帶進 C++ string
- `build_secret()` 透過 `std::vector<char>` 與 `std::string` 做轉換
- `check()` 針對 `sym_hello` 做 branch 判斷

## integration 規則

- build instrumented `libc++` 時固定用 `simple backend`
- 不要覆蓋原本 `symcc/build`
- 不要全域 export `SYMCC_LIBCXX_PATH`
- 只在需要 STL tracing 的單一 command 上指定 `SYMCC_LIBCXX_PATH`
- 不要混用系統 STL 與 instrumented `libc++` 產生的 object file

## 已知風險

- 手動互動輸入會把等待時間算進整體執行時間
- 新版 LLVM 可能需要調整 runtime / distribution target
- 若 target 混用兩套 C++ standard library，可能出現 linker error 或 runtime crash
