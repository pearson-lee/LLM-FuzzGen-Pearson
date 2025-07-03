#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
##### LLM-FuzzGen #####
export PATH="/ccache/bin:$PATH" # Use ccache for faster builds, from oss-fuzz/infra/base-images/base-builder/Dockerfile
export CCACHE_DIR="$WORK/ccache"
export CFLAGS="$CFLAGS -w -fno-color-diagnostics -fdiagnostics-fixit-info" # Suppress warnings, color diagnostics and fixit info
export CXXFLAGS="$CXXFLAGS -w -fno-color-diagnostics -fdiagnostics-fixit-info" # Suppress warnings, color diagnostics and fixit info
#https://github.com/google/oss-fuzz/pull/10891
#if [ "$SANITIZER" == "introspector" ]; then
#  export CFLAGS="${CFLAGS} -fsanitize=address"
#  export CXXFLAGS="${CXXFLAGS} -fsanitize=address"
#fi
#https://github.com/google/oss-fuzz/pull/12356
if [ "$SANITIZER" == "introspector" ]; then
  export CFLAGS=$(echo "$CFLAGS" | sed 's/gold/lld/g')
  export CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/gold/lld/g')
fi
#######################
# Build the project.
./buildconf
./configure --enable-debug --disable-tests
make clean
make -j$(nproc) V=1 all

# Build the fuzzers.
$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz.c -o $WORK/ares-test-fuzz.o
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz.o \
    -o $OUT/ares_parse_reply_fuzzer \
    $LIB_FUZZING_ENGINE -Wl,--whole-archive $SRC/c-ares/src/lib/.libs/libcares.a -Wl,--no-whole-archive

$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz-name.c \
    -o $WORK/ares-test-fuzz-name.o
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz-name.o \
    -o $OUT/ares_create_query_fuzzer \
    $LIB_FUZZING_ENGINE -Wl,--whole-archive $SRC/c-ares/src/lib/.libs/libcares.a -Wl,--no-whole-archive

# Archive and copy to $OUT seed corpus if the build succeeded.
zip -j $OUT/ares_parse_reply_fuzzer_seed_corpus.zip $SRC/c-ares/test/fuzzinput/*
zip -j $OUT/ares_create_query_fuzzer_seed_corpus.zip \
    $SRC/c-ares/test/fuzznames/*

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  #### compile the fuzz target
  $CC $CFLAGS -Iinclude -Isrc/lib -c "$target" -o "$WORK/${target_basename}.o"

  $CXX $CXXFLAGS -std=c++11 "$WORK/${target_basename}.o" \
    -o "$OUT/$target_basename" $LIB_FUZZING_ENGINE -Wl,--whole-archive $SRC/c-ares/src/lib/.libs/libcares.a -Wl,--no-whole-archive
  ####

  if [ -f "$SRC/llm_fuzzgen.dict" ] && [ ! -f "$SRC/${target_basename}.options" ]; then
    echo "[libfuzzer]" > "$SRC/${target_basename}.options"
    echo "dict = llm_fuzzgen.dict" >> "$SRC/${target_basename}.options"
  fi
done
cp $SRC/llm_fuzzgen.dict $OUT/ || true
cp $SRC/llm_fuzzgen*.options $OUT/ || true
cp $SRC/llm_fuzzgen*_seed_corpus.zip $OUT/ || true
#######################