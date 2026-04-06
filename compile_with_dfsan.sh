#!/bin/bash

TARGET_DIR="."
OUTPUT_DIR="./dfsan_build"
mkdir -p $OUTPUT_DIR

cat > dfsan_abi_list.txt << 'EOF'
fun:malloc=uninstrumented
fun:free=uninstrumented
fun:realloc=uninstrumented
fun:printf=uninstrumented
fun:fprintf=uninstrumented
fun:sprintf=uninstrumented
fun:snprintf=uninstrumented
fun:LLVMFuzzerTestOneInput=uninstrumented
fun:_Znw*=uninstrumented
fun:_Zna*=uninstrumented
fun:_Zdl*=uninstrumented
fun:_Zda*=uninstrumented
fun:_ZSt*=uninstrumented
fun:_ZNSt*=uninstrumented
fun:_ZNKSt*=uninstrumented
fun:__gxx_personality_v0=uninstrumented
fun:__cxa_*=uninstrumented
fun:__clang_call_terminate=uninstrumented
EOF

echo "[1/3] Compiling tinyxml2.cpp with DFSan..."
clang -fsanitize=dataflow \
    -fsanitize-ignorelist=dfsan_abi_list.txt \
    -DDFSAN_ENABLED \
    -g -O1 \
    -c $TARGET_DIR/tinyxml2.cpp \
    -o $OUTPUT_DIR/tinyxml2.o

echo "[2/3] Compiling fuzz target (llm_fuzzgen0627183713.cc) with DFSan..."
clang++ -fsanitize=dataflow \
    -fsanitize-ignorelist=dfsan_abi_list.txt \
    -DDFSAN_ENABLED \
    -g -O1 \
    -c $TARGET_DIR/llm_fuzzgen0627183713.cc \
    -o $OUTPUT_DIR/llm_fuzzgen0627183713.o

echo "[3/3] Linking with LibFuzzer..."
clang++ -fsanitize=dataflow,fuzzer \
    -fsanitize-ignorelist=dfsan_abi_list.txt \
    $OUTPUT_DIR/tinyxml2.o \
    $OUTPUT_DIR/llm_fuzzgen0627183713.o \
    -o $OUTPUT_DIR/fuzzer_with_dfsan

echo "Build Done."