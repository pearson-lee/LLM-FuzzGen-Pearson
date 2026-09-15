# LLM-FuzzGen

## 正常安裝（建議路徑）

本節只寫目前已實際驗證的標準安裝方式：Windows + WSL2 Ubuntu 22.04 x86_64、Docker Desktop、`main` branch、Vertex AI `gemini-2.5-pro`，並完整啟用 blocker、SymCC、STL tracing 與 GDB runtime call-chain。若環境或需求不同，請直接看後面的「例外狀況與替代方案」。

開始前建議準備至少 8 CPU cores、16 GB RAM 與 120 GB 可用空間；首次安裝必須能連線到 GitHub、GCR、Ubuntu package repositories、Google Storage、各 target source repository 與 Vertex AI。標準流程只需要依序完成本節 1–9，再執行後面的「正常執行」。

### 1. Clone 主專案

`external/oss-fuzz/` 與 `external/fuzz-introspector/` 已直接收進主 repo，不要再用最新版 upstream 覆蓋它們。

```bash
git clone --branch main \
  https://github.com/pei-lun-chien/LLM_FuzzGen_Seed.git LLM-FuzzGen
cd LLM-FuzzGen
```

### 2. 安裝主機工具

以下只列目前主程式、OSS-Fuzz orchestration、Fuzz Introspector 與 blocker/SymCC pipeline 實際需要的 Host 套件。各 fuzzing project 的編譯依賴由自己的 Dockerfile 安裝，不需要重複裝在 Host。

```bash
sudo apt update
sudo apt install -y \
  software-properties-common ca-certificates curl gnupg lsb-release \
  git build-essential cmake ninja-build xz-utils \
  clang-14 llvm-14 llvm-14-dev llvm-14-tools \
  libz3-dev zlib1g-dev gdb

sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv
```

blocker 需要 GDB runtime call-chain，因此 `kernel.yama.ptrace_scope=0` 是必要設定。以下指令會立即套用，並在 Ubuntu／WSL 重啟後保留：

```bash
echo 'kernel.yama.ptrace_scope=0' \
  | sudo tee /etc/sysctl.d/99-llm-fuzzgen-ptrace.conf >/dev/null
sudo sysctl --load=/etc/sysctl.d/99-llm-fuzzgen-ptrace.conf
test "$(cat /proc/sys/kernel/yama/ptrace_scope)" = "0"
```

### 3. 啟用 Docker Desktop

1. 在 Windows 安裝並啟動 [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)，使用 WSL 2 based engine 與 Linux containers。
2. 到 Docker Desktop 的 `Settings > Resources > WSL Integration`，啟用目前的 Ubuntu 22.04 distribution，然後按 `Apply`。
3. 不要在同一個 WSL distribution 另外安裝 `docker-ce`，也不需要 `usermod -aG docker`；Docker daemon 由 Docker Desktop 的 Linux VM 提供。
4. Repo 與 `external/oss-fuzz/build` 應放在 WSL 的 Linux filesystem（例如 `/home/<user>/LLM-FuzzGen`），不要放在 `/mnt/c`，否則大量 bind mount I/O 會明顯變慢。

在 WSL shell 確認 Docker 可用：

```bash
docker version
docker info
docker run --rm hello-world
```

### 4. 建 Python 3.11 環境與 OSS-Fuzz images

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python --version
./setup.sh
```

`setup.sh` 會安裝：

- `requirements.txt` 的主程式依賴。
- Fuzz Introspector local web API 依賴。
- repo 內 `external/fuzz-introspector/src` 的 editable package。
- OSS-Fuzz base images。

`setup.sh` 詢問是否使用 Taiwan apt repository 時，正常安裝請輸入 `n`。

測試與 SymCC 的 `ninja check` 另需：

```bash
python -m pip install pytest==9.0.3 lit==18.1.8
python -m pip check
```

### 5. 安裝固定版本 SymCC

fresh clone 不包含 `symcc/`；請固定 commit 並初始化 runtime submodule：

```bash
git clone https://github.com/eurecom-s3/symcc.git symcc
git -C symcc checkout 3b8acabf06c83b92facccde7f6dfb191b1a163b3
git -C symcc submodule update --init --recursive

test "$(git -C symcc rev-parse HEAD)" = \
  "3b8acabf06c83b92facccde7f6dfb191b1a163b3"
test "$(git -C symcc/runtime rev-parse HEAD)" = \
  "892f817f38f5abfa083dd0c1caa7ced821566bf5"
```

建立主機使用的 LLVM 14 + QSYM build：

```bash
cmake -S symcc -B symcc/build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DSYMCC_RT_BACKEND=qsym \
  -DZ3_TRUST_SYSTEM_VERSION=on \
  -DLLVM_DIR=/usr/lib/llvm-14/cmake
ninja -C symcc/build
ninja -C symcc/build check
```

`symcc/build/symcc` 與 `symcc/build/sym++` 是 blocker pipeline 的預設路徑。

本專案沒有使用 SymCC upstream 的 AFL 協作流程或 `symcc_fuzzing_helper`，因此 Host 不需要安裝 Rust/Cargo，也不需要建立 `symcc/Dockerfile` 定義的 standalone AFL image。

### 6. 安裝 LLVM 14 source 與 LLVM 18.1.8 tools

LLVM 14 source 對 blocker mode 是必要項目，不只是 STL 的選配項目：

```bash
git clone --depth 1 --branch llvmorg-14.0.6 \
  https://github.com/llvm/llvm-project.git llvm-project-14
test "$(git -C llvm-project-14 rev-parse HEAD)" = \
  "f28c006a5895fc0e329fe15fead81e37457cb1d1"
```

blocker coverage replay 預設從 `$HOME/tools/llvm-18.1.8/bin` 找 `llvm-cov` 與 `llvm-profdata`。安裝官方 LLVM 18.1.8 binary release：

```bash
LLVM18_NAME='clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04'
LLVM18_ARCHIVE="/tmp/${LLVM18_NAME}.tar.xz"
curl -L \
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/${LLVM18_NAME}.tar.xz" \
  -o "$LLVM18_ARCHIVE"
mkdir -p "$HOME/tools"
tar -xJf "$LLVM18_ARCHIVE" -C "$HOME/tools"
mv "$HOME/tools/$LLVM18_NAME" "$HOME/tools/llvm-18.1.8"

"$HOME/tools/llvm-18.1.8/bin/llvm-cov" --version
"$HOME/tools/llvm-18.1.8/bin/llvm-profdata" --version
```

建立 OSS-Fuzz container 專用的 LLVM 18 simple-backend SymCC。以下兩個 `/usr/local/bin/clang` 是 container 內的固定路徑，請照原值保留：

```bash
LLVM18_ROOT="$HOME/tools/llvm-18.1.8"
cmake -S symcc -B symcc/build_llvm18 -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DSYMCC_RT_BACKEND=simple \
  -DZ3_TRUST_SYSTEM_VERSION=on \
  -DLLVM_DIR="$LLVM18_ROOT/lib/cmake/llvm" \
  -DCMAKE_C_COMPILER="$LLVM18_ROOT/bin/clang" \
  -DCMAKE_CXX_COMPILER="$LLVM18_ROOT/bin/clang++" \
  -DCLANG_BINARY=/usr/local/bin/clang \
  -DCLANGPP_BINARY=/usr/local/bin/clang++
ninja -C symcc/build_llvm18
```

先確認必要輸出存在：

```bash
test -x symcc/build_llvm18/symcc
test -x symcc/build_llvm18/sym++
test -f symcc/build_llvm18/libsymcc.so
test -e symcc/build_llvm18/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so \
  || test -e symcc/build_llvm18/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a
```

正常情況下，project `build.sh` 會在 container 內安裝 `libz3-4`，這裡不需要再執行其他 Z3 指令。

### 7. 安裝 STL symbolic tracing 支援

本專案有許多 C++ target 的 branch 條件會經過 `std::string`、`std::vector`、`std::map` 或 `std::unordered_map` 等 STL 內部邏輯，因此還原完整實驗環境時必須預先建立 instrumented libc++。前面工具裝妥後執行：

```bash
ROOT_DIR="$PWD" ./scripts/setup_symcc_stl.sh
```

這會建立 `symcc/build_simple`、`libcxx_symcc_build` 與 `libcxx_symcc_install`，並覆寫既有的後兩個目錄。安裝是必要步驟，但執行時不應全域強制啟用：只有 target 的 symbolic input 會穿過 STL 內部運算時，才對該次編譯設定 `SYMCC_LIBCXX_PATH`。完整原理與單獨驗證方式見 [`docs/setup_symcc_stl.md`](docs/setup_symcc_stl.md)；一般 SymCC 說明見 [`docs/setup_symcc.md`](docs/setup_symcc.md)。

### 8. 設定 Vertex AI

正式實驗使用 Vertex AI `gemini-2.5-pro`。先安裝 Google Cloud CLI 並建立 Application Default Credentials：

```bash
# 只在使用預設 Vertex AI backend 時安裝 Google Cloud CLI。
sudo install -m 0755 -d /usr/share/keyrings
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
  | sudo gpg --dearmor --yes -o /usr/share/keyrings/cloud.google.gpg
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
  | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list >/dev/null
sudo apt update
sudo apt install -y google-cloud-cli

gcloud init
gcloud auth application-default login
export VERTEXAI_PROJECT_ID='YOUR_GCP_PROJECT_ID'
export VERTEXAI_LOCATION='us-central1'
```

執行時仍要明確傳入 `--llm vertexai --model gemini-2.5-pro`；省略 `--model` 會使用程式預設的 `gemini-2.5-flash`，不是正式實驗設定。不要把 credential 或 API key commit 到 repo。

### 9. 驗證正常安裝

先做不需長時間 fuzzing 的基本檢查：

```bash
source .venv/bin/activate
python --version
python -m pip check
python -c 'import yaml, requests, langchain, langgraph, fuzz_introspector'
python main.py --help
test "$(cat /proc/sys/kernel/yama/ptrace_scope)" = "0"

docker info >/dev/null
docker image inspect \
  gcr.io/oss-fuzz-base/base-image:latest \
  gcr.io/oss-fuzz-base/base-clang:latest \
  gcr.io/oss-fuzz-base/base-builder:latest \
  gcr.io/oss-fuzz-base/base-builder-ruby:latest \
  gcr.io/oss-fuzz-base/base-runner:latest >/dev/null

test -x symcc/build/symcc
test -x symcc/build/sym++
test -x symcc/build_simple/sym++
test -f libcxx_symcc_install/include/c++/v1/__config
test -f libcxx_symcc_install/lib/libc++.a
test -x symcc/build_llvm18/symcc
test -f symcc/build_llvm18/libsymcc.so
test -f llvm-project-14/compiler-rt/include/fuzzer/FuzzedDataProvider.h
```

執行 unit tests：

```bash
python -m pytest -q unitest
```

執行一個最小 OSS-Fuzz build；這一步會下載 target source：

```bash
python external/oss-fuzz/infra/helper.py build_image cjson
python external/oss-fuzz/infra/helper.py build_fuzzers cjson
```

驗證 SymCC 三種 project build flavor：

```bash
./scripts/test_symcc_builds.sh \
  --projects 'cjson' \
  --flavor all
```

完整 Fuzz Introspector report smoke test：

```bash
python external/oss-fuzz/infra/helper.py introspector cjson --seconds 30 --clean
```

## 正常執行
啟用 blocker pipeline：

```bash
python3 main.py run_all_fuzzer cjson \
  --budget-mode fuzzing-cpu \
  --run-fuzzers 86400 \
  --coverage-interval 3600 \
  --fuzz-targets-parallel 4 \
  --print-coverage \
  --use-blocker \
  --coverage-stagnation-window 1 \
  --coverage-stagnation-threshold 0.05 \
  --target-exposure-min-seconds 30 \
  --generated-target-priority-seconds 300 \
  --blocker-session-size 5 \
  --blocker-top-k 10 \
  --blocker-max-iterations 2 \
  --blocker-fuzz-seconds 15 \
  --blocker-artifact-report-seconds 30 \
  --blocker-refresh-branch-growth-threshold 0.05 \
  --blocker-refresh-branch-growth-floor 50 \
  --llm vertexai \
  --model gemini-2.5-pro
```

這個流程不會下載 OSS-Fuzz 公開 corpus。`run_fuzzer` 會建立或沿用 `external/oss-fuzz/build/corpus/cjson/<fuzzer>/` 的本地 corpus；coverage 固定使用 `--no-corpus-download`；blocker 觸發的 Introspector report 也會使用本地 fuzzing corpus，不會傳入 `--public-corpora`。

上面的新版 `run_all_fuzzer --use-blocker` 流程會在正常 fuzzing 階段直接偵測 libFuzzer 產生的 crash、OOM、timeout、leak 與 slow-unit artifacts，並嘗試把 seed、對應執行 log 與 metadata 保存到 `experiments/<timestamp>_run_all_fuzzer/crash_seeds/<project>/<fuzzer>/`。因此碰到 crash 時，標準流程已會直接收集，不需要再固定 replay corpus。

每次執行的 log、coverage、blocker 與 crash artifacts 會寫入 `experiments/<timestamp>_<command-or-project>/`。OSS-Fuzz build/corpus 在 `external/oss-fuzz/build/`，兩者都會快速占用大量空間。

## 版本與工具說明

以下內容用來解釋前面為什麼需要那些工具，並記錄可還原實驗環境的固定版本；正常安裝時不需要另外執行本節指令。

### 已確認的版本基準

以下版本依目前 `main` branch 與已驗證環境整理。OSS-Fuzz 沒有一般套件式的 release version，因此以 upstream Git commit 表示。

| 元件 | 版本 / commit | 用途與來源 |
| --- | --- | --- |
| LLM-FuzzGen | `b8c05899ad82c369ae1f3e8b68b95dc3b1a4e732` | `main` branch 基準；實際安裝時使用包含本 README 的最新 `main` commit |
| Host OS | Ubuntu 22.04 x86_64 on WSL2 | `setup.sh` 會檢查 Ubuntu 22.04；完整流程目前只在此環境驗證 |
| Host Python | Python 3.11.x；驗證環境為 3.11.13 | 主程式與 local Introspector API |
| Docker | Docker Desktop with WSL2 Linux containers；驗證環境 client/server 為 28.4.0 | 提供 OSS-Fuzz builder、runner 與 project containers |
| 實驗用 LLM | Vertex AI `gemini-2.5-pro` | 正式實驗執行參數；不是程式內預設的 `gemini-2.5-flash` |
| OSS-Fuzz snapshot | [`9f58c388aa52b9641260211a546ceb42b23f9fcf`](https://github.com/google/oss-fuzz/commit/9f58c388aa52b9641260211a546ceb42b23f9fcf) | `external/oss-fuzz/` 是此 upstream snapshot 加上本專案修改，不是 submodule；差異見 `external/patches/oss-fuzz.patch` |
| Fuzz Introspector | package `0.1.10`；[`8944d0b001754f60a602c95a816880f885f1e38d`](https://github.com/ossf/fuzz-introspector/commit/8944d0b001754f60a602c95a816880f885f1e38d) | `external/fuzz-introspector/` 與 OSS-Fuzz `base-clang` 固定此 commit；差異見 `external/patches/fuzz-introspector.patch` |
| OSS-Fuzz LLVM | `llvmorg-18.1.8` | fuzzing、coverage 與 Introspector build |
| SymCC | `v1.0-158-g3b8acab`；[`3b8acabf06c83b92facccde7f6dfb191b1a163b3`](https://github.com/eurecom-s3/symcc/commit/3b8acabf06c83b92facccde7f6dfb191b1a163b3) | `symcc/` 必須另外 clone，不在主 repo 追蹤內 |
| SymCC runtime | [`892f817f38f5abfa083dd0c1caa7ced821566bf5`](https://github.com/eurecom-s3/symcc-rt/commit/892f817f38f5abfa083dd0c1caa7ced821566bf5) | SymCC 的 `runtime` submodule，必須 recursive init |
| Host LLVM / Clang | Ubuntu LLVM/Clang 14.0.0 | `symcc/build` 的 QSYM backend 與一般 blocker harness |
| LLVM 14 source | `llvmorg-14.0.6`；`f28c006a5895fc0e329fe15fead81e37457cb1d1` | blocker 使用其 `FuzzedDataProvider.h`，STL 模式也用它建立 instrumented libc++ |

SymCC 在本專案有三份 build，路徑與用途不同，不能互相覆蓋：

| 路徑 | LLVM | Backend | 實際用途 |
| --- | --- | --- | --- |
| `symcc/build` | 14 | QSYM | Host 執行 blocker harness 與 concolic exploration |
| `symcc/build_simple` | 14 | simple | 建立 instrumented libc++，供 STL symbolic tracing 使用 |
| `symcc/build_llvm18` | 18.1.8 | simple | 掛進 OSS-Fuzz builder container，把 project library 編成 SymCC-instrumented archive |

### Host 套件用途

- `software-properties-common` 提供 `add-apt-repository`，用來加入 Python 3.11 的 deadsnakes PPA。
- `ca-certificates`、`curl`、`gnupg`、`lsb-release` 負責 HTTPS 下載、套件簽章與 Ubuntu release 判斷。
- `git` 用來取得主 repo、SymCC、LLVM source 與各 fuzzing project source。
- `build-essential`、`cmake`、`ninja-build` 是建立 SymCC、runtime 與 libc++ 的基本 C/C++ build tools。
- `xz-utils` 用來解開 LLVM 18.1.8 的 `.tar.xz` release archive。
- `clang-14`、`llvm-14`、`llvm-14-dev`、`llvm-14-tools` 提供 Host SymCC plugin 所需的 compiler、LLVM CMake package 與工具。
- `libz3-dev` 是 QSYM backend 的 constraint solver dependency；`zlib1g-dev` 是 LLVM/SymCC build dependency。
- `gdb` 讓 blocker 在 runtime 取得實際 call-chain；若沒有 ptrace 權限，即使安裝 GDB 也抓不到動態路徑。
- `python3.11` 與 `python3.11-venv` 提供主程式要求的 Python runtime 和隔離環境。

各 fuzzing project 自己的 library headers 與 build dependencies 應由 `external/oss-fuzz/projects/<project>/Dockerfile` 安裝，不要因為某個 target 需要，就全部塞進 Host 套件清單。

### `symcc/build_llvm18` 的兩組 Clang 路徑

這份 build 是在 Host 建立、拿到 OSS-Fuzz container 內使用，所以 CMake command 同時出現兩組 compiler：

- `CMAKE_C_COMPILER` 與 `CMAKE_CXX_COMPILER` 指向 Host 的 `$HOME/tools/llvm-18.1.8/bin/clang{,++}`，只負責「現在把 SymCC wrapper 和 pass 編出來」。
- `CLANG_BINARY` 與 `CLANGPP_BINARY` 固定為 `/usr/local/bin/clang{,++}`，這兩個路徑會寫進產出的 wrapper；wrapper 之後進入 OSS-Fuzz container 才會執行，而 container 的 LLVM 18 compiler 正好位於該路徑。

實際流程是：Host 建立 `symcc/build_llvm18`，solver 將它 read-only mount 成 container 的 `/symcc-bin`，project `build.sh` 再使用 `/symcc-bin/symcc` 或 `/symcc-bin/sym++` 編出 `$OUT/symcc_library/` archive。這份 wrapper 不應直接當 Host compiler；Host blocker 使用的是 `symcc/build`。

### Docker image 基準

`setup.sh` 選 `n` 時會拉取以下兩個固定 image，再以 repo 內 Dockerfile 建立 `base-builder`、`base-builder-ruby` 與 `base-runner`：

| Image | 固定 digest |
| --- | --- |
| `gcr.io/oss-fuzz-base/base-image` | `sha256:a1fd7287efaefa39df54216edaa7b732d33eb54c06155fa9ebc7dbdc2e1d9286` |
| `gcr.io/oss-fuzz-base/base-clang` | `sha256:fd173151d9281639f85eff98e998a1601189bc93665b6d9a18a2ecbe24682d76` |

`base-builder`、`base-builder-ruby` 與 `base-runner` 是 local build，不能只靠某台實驗機上的 image ID 還原；可重建基準是上表兩個 digest、目前 repo 的 Dockerfile 與已固定的 external source commits。

## 例外狀況與替代方案

以下都不是正常安裝的必要步驟。只有符合標題描述的情況才使用，否則維持前面的標準流程。

### 原生 Ubuntu 22.04，不使用 Docker Desktop

本專案的 container 操作可使用原生 Docker Engine，但這不是目前完整實驗的主要驗證環境。原生 Ubuntu 22.04 應依 [Docker 官方 Ubuntu repository](https://docs.docker.com/engine/install/ubuntu/) 安裝，不要在前面的 WSL + Docker Desktop 流程重複執行，也不要只裝 Ubuntu 提供的 `docker.io`：

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```

重新登入讓 `docker` group 生效，再用 `docker info` 與 `docker run --rm hello-world` 驗證目前使用者不需 `sudo` 即可操作 daemon。`docker` group 等同提供 root-level 權限，只能加入可信任的帳號；細節見 [Docker 官方 Linux post-install 說明](https://docs.docker.com/engine/install/linux-postinstall/)。

### 需要使用 Taiwan apt repository

`setup.sh` 詢問 Taiwan apt repository 時，輸入 `y` 會執行 OSS-Fuzz `infra/base-images/all.sh`，從 repo 內 Dockerfile 完整重建 base images，且 `base-image` 會將 Ubuntu apt source 改為 `free.nchc.org.tw`。這條路徑會重新建立 LLVM 與多個 base images，耗時和磁碟用量都明顯較高，只適合預設 mirror 下載不穩定、且所在網路確實適合 NCHC mirror 的環境。一般安裝維持輸入 `n`。

### Container 無法安裝 `libz3-4`

正常情況下，各支援 `symcc_library` 的 project `build.sh` 會在 container 內執行 `apt-get install libz3-4`。只有該安裝失敗，並出現找不到 `libz3.so.4` 的 link/runtime error 時，才在 Host 建立 fallback：

```bash
mkdir -p symcc/lib
cp -L /lib/x86_64-linux-gnu/libz3.so.4 symcc/lib/libz3.so.4
```

solver 與 `scripts/test_symcc_builds.sh` 偵測到這個檔案後，會自動將 `symcc/lib` read-only mount 為 container 的 `/symcc-libs`；project `build.sh` 已把該路徑放進 `LD_LIBRARY_PATH`。這不是另一套 SymCC 安裝方式，也不需要把檔案複製進 `symcc/build_llvm18`。

### CI／遠端機器使用 Vertex AI

無法執行 `gcloud auth application-default login` 的非互動式環境，可以改用具有 Vertex AI 權限的 service-account JSON：

```bash
export GOOGLE_APPLICATION_CREDENTIALS='/absolute/path/to/service-account.json'
export VERTEXAI_PROJECT_ID='YOUR_GCP_PROJECT_ID'
export VERTEXAI_LOCATION='us-central1'
```

credential 檔不可放進 repo 或 commit。正式實驗參數仍使用 `--llm vertexai --model gemini-2.5-pro`。

### 改用其他 LLM backend

這些 backend 是功能上的替代方案，不是目前正式實驗設定：

```bash
export GOOGLE_API_KEY='YOUR_GOOGLE_API_KEY'       # --llm gemini
export OPENROUTER_API_KEY='YOUR_OPENROUTER_KEY'   # --llm openrouter
# --llm ollama 需要先啟動 localhost:11434，並 pull config/config.yaml 指定的 model。
```

LangSmith tracing 也是選配；只有需要追蹤 LLM requests 時才設定：

```bash
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY='YOUR_LANGSMITH_API_KEY'
```

model 與 token budget 等設定可查看 [`config/config.yaml`](config/config.yaml)，但 API key 不應寫進該檔。

### 補跑既有 corpus 的 crash

`replay_corpus_crashes` 是舊實驗資料的補救工具：之前部分專案的 fuzzing 流程沒有保存 crash artifact，所以可以把現有 corpus 逐一重跑，檢查其中是否已包含會 crash 的 input。它不會呼叫 LLM，也不會修改原始 corpus：

```bash
python3 main.py replay_corpus_crashes cjson \
  --fuzz-targets-parallel 4 \
  --timeout-per-target 3600
```

過去使用這個替代方案時沒有補找到明顯有用的 crash；現在標準 `run_all_fuzzer --use-blocker` 已會在 fuzzing 當下收集 crash artifact，因此新實驗不需要固定執行 replay。

### 手動下載 OSS-Fuzz 公開 corpus

標準 `run_all_fuzzer`、coverage 與 blocker 流程只使用本地 corpus，不會下載 OSS-Fuzz 公開 corpus。只有自行呼叫 OSS-Fuzz helper 並明確使用 `--public-corpora` 時，Host 才需要額外安裝：

```bash
sudo apt install -y wget unzip
```

這兩個套件不應放回正常安裝清單，因為正式實驗指令不走這條路徑。

### GDB ptrace 的安全限制

`kernel.yama.ptrace_scope=0` 會放寬同一台機器上不同 process 間的 ptrace 限制。本專案需要它取得 runtime call-chain，但應只用在專用實驗環境，不要直接套用到多人共用或 production 主機。若不需要執行 blocker，可恢復為 `1`；恢復後 GDB 動態路徑功能會無法使用。

## Project Dockerfile 版本狀態

目前主 repo 內直接提供 11 個 project definition。主要實驗 targets 的 source pin 如下：

| Project | Source pin |
| --- | --- |
| `c-ares` | tag/branch `cares-1_20_0` |
| `cjson` | `12c4bf1986c288950a3d06da757109a6aa1ece38` |
| `lcms` | `04ace9c100fc6850f09223dd6c7ad8fa634acd06` |
| `libpcap` | `2559282f3db683e03cd29d30ab5947d6e14a6500` |
| `libtiff` | `fcd4c86c4907d859c3124c8ad786868ba3f0b713` |
| `libvpx` | `9514ab684d3680e5180404894809328611179ad1` |
| `tinyxml2` | `8224e427b655b83dae5e2298f1e6919523a78737` |
| `tomlplusplus` | `1e8829b793b66ad17011732a146b8077d379b011` |
| `zlib` | `5a82f71ed1dfc0bec044d9702463dbdf84ea3b71` |



blocker 的 `symcc_library` 已設定並驗證的 allowlist 是：`libpcap`、`libvpx`、`cjson`、`tinyxml2`、`lcms`、`zlib`、`libtiff`；`tomlplusplus` 是 header-only，不產生獨立 library archive。

## 新增專案的 SymCC 支援

新增一個 project 時，通常只需要處理版本 pin、該 project 的 `build.sh`、`symcc_config.json`、測試腳本登記與實際 smoke test。不要預設修改 `external/oss_fuzz.py`、SymCC compiler/pass 或其他共用程式碼。

### 1. 固定 project 版本

在 `external/oss-fuzz/projects/<project>/Dockerfile` 使用完整 commit hash，checkout 後立即驗證實際 HEAD：

```dockerfile
ARG PROJECT_COMMIT=<full-commit-hash>
RUN git fetch --depth 1 origin "$PROJECT_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$PROJECT_COMMIT"
```

同一目錄的 `project.yaml` 也要記錄完全相同的版本：

```yaml
commit_hash: '<full-commit-hash>'
```

Dockerfile 與 `project.yaml` 不一致時，實驗 metadata 和真正編進 image 的 source 會不同，因此不能只更新其中一個。

### 2. 在 project `build.sh` 支援三種 flavor

一般 library project 必須處理以下三種 `LLM_FUZZGEN_BUILD_FLAVOR`：

| Flavor | 責任 | 預期輸出 |
| --- | --- | --- |
| `symcc_native` | 以一般 compiler 建立沒有 sanitizer／SymCC instrumentation 的 native archive | `$OUT/symcc_native/<library>.a` |
| `symcc_library` | 使用 `/symcc-bin/symcc` 或 `/symcc-bin/sym++` 重新編譯 project library | `$OUT/symcc_library/<library>.a` |
| `symcc_replay` | 使用 coverage sanitizer 建立不含 libFuzzer main 的 replay binary，供 solver 判斷 branch 與 blocked side | `$OUT/symcc_replay/<target>_replay` |

`symcc_native` 和 `symcc_library` 開始編譯前，要從 `CFLAGS`、`CXXFLAGS` 與 `LDFLAGS` 清除 `-fsanitize=fuzzer`、`-fsanitize=fuzzer-no-link`、`-fsanitize-coverage`、`-mllvm ...sanitizer-coverage...` 等 instrumentation flags，避免 archive 混入 libFuzzer 或 sanitizer coverage symbols。

`symcc_library` 至少要設定：

```bash
export CC=/symcc-bin/symcc
export CXX=/symcc-bin/sym++
export SYMCC_PASS_DIR=/symcc-bin
export SYMCC_RUNTIME_DIR=/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build
export SYMCC_CLANG=/usr/local/bin/clang
export SYMCC_CLANGPP=/usr/local/bin/clang++
export SYMCC_ENABLE_LINEARIZATION=1
export SYMCC_REGULAR_LIBCXX=yes  # C++ project
```

`SYMCC_REGULAR_LIBCXX=yes` 是 project library build 的 C++ ABI 設定；前面必要安裝的 instrumented libc++ 則供需要追蹤 STL 內部 symbolic computation 的特定 harness 使用，兩者用途不同。

`symcc_replay` 必須重用與正式 fuzz target 相同的 `LLVMFuzzerTestOneInput`，但改由獨立 `main` 從 stdin 或 seed file 讀資料。replay binary 的 source、include、define 與 link libraries 必須和原 target 一致，否則 coverage 結果不能代表原 target。

### 3. 新增 `symcc_config.json`

一般 library project 在 `external/oss-fuzz/projects/<project>/symcc_config.json` 設定 archive 名稱和 source export 路徑：

```json
{
  "native_archive": true,
  "native_archive_build_flavor": "symcc_native",
  "native_archive_subdir": "symcc_native",
  "native_archive_filename": "libproject.a",
  "native_archive_include_dirs": ["source_code"],
  "symcc_library": true,
  "symcc_library_build_flavor": "symcc_library",
  "symcc_library_subdir": "symcc_library",
  "symcc_library_filename": "libproject.a"
}
```

專案額外的 compile／link 設定應優先留在 config，不要寫進 solver 的全域預設。路徑可以使用 `{repo_root}`、`{build_out}` 與 `{project}` placeholders：

```json
{
  "extra_cxxflags": ["-std=c++17"],
  "extra_ldflags": ["-lm"],
  "extra_include_dirs": ["{build_out}/{project}/work/include"]
}
```

若 include 或 generated header 需要從 build container 帶回 Host，`build.sh` 也要把它們輸出到 `$OUT`；只在 config 填一個 container 內路徑無法讓 Host solver 讀到檔案。

### 4. Header-only project

Header-only project 不建立 native 或 SymCC archive。template/header code 會直接進入 `sym++` 編譯的 harness object；例如目前的 `tomlplusplus/symcc_config.json`：

```json
{
  "header_only": true,
  "native_archive": false,
  "symcc_library": false,
  "extra_cxxflags": [
    "-std=c++17",
    "-DNDEBUG",
    "-DTOML_ENABLE_SIMD=0"
  ]
}
```

Header-only project 仍需提供 `symcc_replay`，並確保 replay 與 SymCC harness 使用相同 headers、defines 和語言標準。

### 5. 登記 build test 與自動化 solver allowlist（必要）

在 [`scripts/test_symcc_builds.sh`](scripts/test_symcc_builds.sh) 的預設 `PROJECTS` 加入 project，並登記預期 artifact：

```bash
NATIVE_ARTIFACT[project]="symcc_native/libproject.a"
LIBRARY_ARTIFACT[project]="symcc_library/libproject.a"
```

Header-only project 兩者都留空，測試腳本會略過不適用的 native/library flavors：

```bash
NATIVE_ARTIFACT[project]=""
LIBRARY_ARTIFACT[project]=""
```

對一般 library project 而言，把 project 加入 [`blocker_process/dependent/run_symcc_blocker.py`](blocker_process/dependent/run_symcc_blocker.py) 的 `_SYMCC_LIBRARY_PROJECTS`，是讓自動化 blocker solver 使用 `symcc_library` 的必要步驟，不是選配：

```python
_SYMCC_LIBRARY_PROJECTS = {
    # Existing validated projects...
    "project",
}
```

程式的 `_should_use_symcc_library()` 會同時檢查以下三個條件，缺少任何一個都會略過 SymCC-instrumented library，改走 native archive：

- project 已加入 `_SYMCC_LIBRARY_PROJECTS`。
- `symcc_config.json` 設定 `"symcc_library": true`。
- 本次 blocker 有可到達該 branch 的 seeds。

正確導入順序是：先完成 `symcc_library` build 與 `_sym_*`／sanitizer symbols 檢查，再把 project 加入 allowlist，接著執行 input-dependent smoke test，確認自動化流程實際回報 `linked_archive_kind=symcc_library`。smoke test 失敗時要移除 allowlist；build 和完整 smoke test 都通過後，才能把這筆 allowlist 視為 validated。只有「可以 build」仍不夠。

Header-only project 是例外：它沒有獨立 library archive，因此不加入 `_SYMCC_LIBRARY_PROJECTS`；由 `sym++` 直接編譯 harness 與 headers。

### 6. 驗證流程

先重建 project image，避免沿用舊 Docker layer：

```bash
python3 external/oss-fuzz/infra/helper.py build_image --no-pull <project>
```

確認 image 內實際 source commit；`<source-dir>` 要換成 Dockerfile clone 使用的目錄名稱：

```bash
docker run --rm gcr.io/oss-fuzz/<project> \
  git -C /src/<source-dir> rev-parse HEAD
```

分別驗證三種 build flavor：

```bash
./scripts/test_symcc_builds.sh --flavor symcc_native --projects '<project>'
./scripts/test_symcc_builds.sh --flavor symcc_library --projects '<project>'
./scripts/test_symcc_builds.sh --flavor symcc_replay --projects '<project>'
```

檢查 SymCC archive。第一個 command 必須找得到 `_sym_*` undefined references；第二個 command 必須沒有輸出並回傳成功：

```bash
nm -A external/oss-fuzz/build/out/<project>/symcc_library/lib{project}.a \
  | rg '[[:space:]]U[[:space:]]+_sym_'

! nm -A external/oss-fuzz/build/out/<project>/symcc_library/lib{project}.a \
  | rg '__sanitizer_cov_|__sancov_'
```

最後執行 input-dependent smoke test。此時一般 library project 必須已加入 `_SYMCC_LIBRARY_PROJECTS`，`symcc_config.json` 必須啟用 `symcc_library`，corpus 也必須包含能到達待解 branch 的 seed，否則 solver 會略過 library instrumentation。使用暫時 harness 和 corpus，初始 seed 可設為 `AAAA`，branch 條件要求另一組固定 bytes（例如 `MAGC`），而且 blocked side 內必須實際呼叫該 project API，不能只測一個與 library 無關的 `if`。成功條件如下：

- summary 的 `success=true`、`used_symcc=true`。
- library project 的 `linked_archive_kind=symcc_library`。
- SymCC exploration 的 `outputs_discovered > 0`、`stop_reason=blocked_side_reached`。
- solved seed bytes 符合 branch 條件。
- coverage replay 確實命中 blocked-side source line。

測試通過後，移除暫時 harness、seed、corpus，以及只屬於 smoke test 的 out/cache artifacts，再重建一次乾淨 image。最後清空該 project 的 `external/oss-fuzz/build/out/<project>` 後重跑三種 flavor，確認系統能只靠 Dockerfile、`build.sh` 與 `symcc_config.json` 自動重建，而不是意外沿用手動產物。

### 修改邊界

一般新增 project 不應修改：

- `external/oss_fuzz.py`
- SymCC compiler、pass 或 runtime 原始碼
- 全域 compiler 預設
- 其他 project 的設定

只有確認問題出在共用流程本身，而且能在多個 project 重現並加上對應 regression test 時，才修改共用檔案。

## 常見還原問題

- `setup.sh` 顯示 Python 不是 3.11：先 `source .venv/bin/activate`，再執行腳本；Ubuntu 22.04 系統預設 `python3` 通常是 3.10。
- WSL 內找不到 Docker daemon：先啟動 Docker Desktop，再到 `Settings > Resources > WSL Integration` 啟用目前的 distribution，並確認使用 Linux containers。
- 原生 Docker Engine 出現 socket permission denied：重新登入讓 `docker` group 生效，並用 `docker info` 驗證；Docker Desktop/WSL 不使用這個處理方式。
- `llvm-cov` 找不到：確認 `$HOME/tools/llvm-18.1.8/bin/llvm-cov` 存在；blocker scripts 預設使用這個固定路徑。
- `FuzzedDataProvider.h` 找不到：`llvm-project-14` 尚未 clone，或不是 `llvmorg-14.0.6`。
- `symcc_library` 找不到 `/usr/local/bin/clang`：`symcc/build_llvm18` 的 wrapper 建錯用途；重跑 LLVM 18 CMake command，保留 `-DCLANG_BINARY=/usr/local/bin/clang`。
- GDB 沒有產生 runtime call-chain，或出現 `ptrace: Operation not permitted`：確認 `cat /proc/sys/kernel/yama/ptrace_scope` 是 `0`；不是 `0` 代表必要的 Host 設定尚未套用。
- Introspector API 連不上：確認 port 8080 沒被占用；程式會由 `external/introspector.py` 啟動 local web API。
- Docker build 因 Taiwan mirror 連線失敗：重新執行 `setup.sh` 並選 `n`。
- 不要全域 export `SYMCC_LIBCXX_PATH`；只在確定需要 instrumented libc++ 的單一 command 設定，避免污染一般 C++ build。

更多 blocker 元件責任與流程見 [`docs/integration_blocker_system.md`](docs/integration_blocker_system.md)。

## 其他
- 實驗時，Ubuntu開24GB RAM，但偶有process kill問題，印象中fuzzing的log(build/out/log)我只擷取片段，碰到大量crash或是fuzz target有print的內容，就很容易kill
- 如果要做LLM-FuzzGen baseline(112 林祐清 學長，請使用那邊的專案，不要用這版的做，oss-fuzz和introspector程式碼皆有改動，若使用將無法還原那邊的行為)

## 選配且未完成：DFSan classifier ground truth

DFSan 原本規劃用來建立 classifier 的 data-flow taint ground truth，但這套驗證流程尚未完成，也沒有接進 `main.py`、`setup.sh` 或 blocker pipeline。它不是還原正式實驗環境的必要項目；只有要繼續開發或人工檢查 ground truth 時才需要以下工具：

```bash
sudo apt install -y clang rsync
```

- `dfsan_tool/compile_with_dfsan_cjson_tinyxml2.sh` 使用 Host `clang`/`clang++` 建立簡單的 DFSan target。
- `dfsan_tool/compile_with_dfsan_freetype2.sh` 額外使用 `rsync`，而且需要事先準備對應的 FreeType testing/work tree。
- `dfsan_tool/replay_corpus_dfsan.py` replay 已 instrument 的 binary；目前不是正式 classifier 流程的一部分。
