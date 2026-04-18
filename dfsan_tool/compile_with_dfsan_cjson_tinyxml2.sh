#!/bin/bash
set -euo pipefail

SOURCE_FILE="${1:?請提供 source file}"
FUZZ_TARGET="${2:?請提供 fuzz target file}"
shift 2
EXTRA_FLAGS=("$@")

OUTPUT_DIR="./dfsan_build"
mkdir -p "$OUTPUT_DIR"

pick_compiler() {
    case "${1##*.}" in
        c)   echo "clang" ;;
        cpp|cc|cxx) echo "clang++" ;;
        *)   echo "clang++" ;;
    esac
}

SRC_COMPILER=$(pick_compiler "$SOURCE_FILE")
FUZZ_COMPILER=$(pick_compiler "$FUZZ_TARGET")
SRC_OBJ="$OUTPUT_DIR/$(basename "${SOURCE_FILE%.*}").o"
FUZZ_OBJ="$OUTPUT_DIR/$(basename "${FUZZ_TARGET%.*}").o"

cat > dfsan_abi_list.txt << 'EOF'
# Memory allocators
fun:malloc=uninstrumented
fun:free=uninstrumented
fun:calloc=uninstrumented
fun:realloc=uninstrumented

# LibFuzzer entry point - 必須保留原始符號名稱讓 LibFuzzer main 能找到
fun:LLVMFuzzerTestOneInput=uninstrumented

# C++ new/delete
fun:_Znwm=uninstrumented
fun:_Znam=uninstrumented
fun:_ZdlPv=uninstrumented
fun:_ZdaPv=uninstrumented

# C++ stdlib - LLVM 14 使用 .dfsan clone 機制
# 系統 libstdc++/libc++ 沒有這些 clone，必須排除否則 linker error
fun:_ZSt*=uninstrumented
fun:_ZNSt*=uninstrumented
fun:_ZNKSt*=uninstrumented
fun:_ZTISt*=uninstrumented

# Exception handling
fun:__gxx_personality_v0=uninstrumented
fun:__cxa_allocate_exception=uninstrumented
fun:__cxa_throw=uninstrumented
fun:__cxa_begin_catch=uninstrumented
fun:__cxa_end_catch=uninstrumented
fun:__cxa_rethrow=uninstrumented
fun:__cxa_pure_virtual=uninstrumented
fun:__clang_call_terminate=uninstrumented

# I/O
fun:printf=uninstrumented
fun:fprintf=uninstrumented
fun:puts=uninstrumented
fun:fwrite=uninstrumented
EOF

DFSAN_FLAGS=(
    -fsanitize=dataflow
    -fsanitize-ignorelist=dfsan_abi_list.txt
    -g -O1
    -DDFSAN_ENABLED
)

echo "[1/3] Compiling source: $SOURCE_FILE ($SRC_COMPILER)..."
$SRC_COMPILER "${DFSAN_FLAGS[@]}" "${EXTRA_FLAGS[@]}" \
    -c "$SOURCE_FILE" -o "$SRC_OBJ"

echo "[2/3] Compiling fuzz target: $FUZZ_TARGET ($FUZZ_COMPILER)..."
$FUZZ_COMPILER "${DFSAN_FLAGS[@]}" "${EXTRA_FLAGS[@]}" \
    -c "$FUZZ_TARGET" -o "$FUZZ_OBJ"

echo "[3/3] Linking..."
clang++ -fsanitize=dataflow,fuzzer \
    -fsanitize-ignorelist=dfsan_abi_list.txt \
    "$SRC_OBJ" "$FUZZ_OBJ" \
    -o "$OUTPUT_DIR/fuzzer_dfsan"

echo "Build Done → $OUTPUT_DIR/fuzzer_dfsan"