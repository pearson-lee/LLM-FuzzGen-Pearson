#!/usr/bin/env bash
# 以 clang source-based coverage 驗證 date_time.hpp:416 -> 417 是否可由 fuzzer 輸入觸發。
# 用法：./run_verify.sh            （產物放在 BUILD_DIR，預設為 mktemp -d）
set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$CASE_DIR/../../../.." && pwd)"
TOML_SRC="$REPO_ROOT/external/tomlplusplus"
LLVM_BIN="${LLVM_BIN:-$HOME/tools/llvm-18.1.8/bin}"
BUILD_DIR="${BUILD_DIR:-$(mktemp -d)}"
mkdir -p "$BUILD_DIR/seeds"

# harness 使用絕對路徑 /src/tomlplusplus/...，以 VFS overlay 導向本機 source，harness 不做任何修改
cat > "$BUILD_DIR/vfs.yaml" <<EOF
{ 'version': 0, 'case-sensitive': 'true',
  'roots': [ { 'name': '/src/tomlplusplus', 'type': 'directory-remap',
               'external-contents': '$TOML_SRC' } ] }
EOF

# 與 OSS-Fuzz build.sh 相同的 -std=c++17 -DNDEBUG -D_FUZZ_TARGET_NAME；另加 coverage instrumentation
"$LLVM_BIN/clang++" -std=c++17 -DNDEBUG -D_FUZZ_TARGET_NAME='"llm_fuzzgen0727161637"' -O0 -g \
  -fprofile-instr-generate -fcoverage-mapping \
  -ivfsoverlay "$BUILD_DIR/vfs.yaml" -I"$TOML_SRC/include" \
  "$CASE_DIR/verify_poc.cc" -o "$BUILD_DIR/verify_poc"

LLVM_PROFILE_FILE="$BUILD_DIR/emit.profraw" "$BUILD_DIR/verify_poc" emit "$BUILD_DIR/seeds"

DT_HPP="$TOML_SRC/include/toml++/impl/date_time.hpp"
for seed in "$BUILD_DIR"/seeds/*.bin; do
  name="$(basename "$seed" .bin)"
  LLVM_PROFILE_FILE="$BUILD_DIR/$name.profraw" "$BUILD_DIR/verify_poc" "$seed"
  "$LLVM_BIN/llvm-profdata" merge -o "$BUILD_DIR/$name.profdata" "$BUILD_DIR/$name.profraw"
  echo
  echo "================ $name ================"
  "$LLVM_BIN/llvm-cov" show "$BUILD_DIR/verify_poc" -instr-profile="$BUILD_DIR/$name.profdata" \
    -show-instantiations=false -path-equivalence="/src/tomlplusplus,$TOML_SRC" "$DT_HPP" \
    | sed -n '/^  *41[2-9]|/p'
done
echo
echo "產物目錄：$BUILD_DIR"
