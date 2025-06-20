# !/bin/bash -eu
# Copyright 2020 Google Inc.
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
export CC="ccache ${CC}"
export CXX="ccache ${CXX}"
export CCACHE_DIR="$WORK/ccache"
# build project and project-hosted fuzzers
echo "#pragma once" > astcenccli_version.h
echo "#define VERSION_STRING \"0.0.0\"" >> astcenccli_version.h
echo "#define YEAR_STRING \"2021\"" >> astcenccli_version.h

# Build the core project for fuzz tests to link against
for source in ./*.cpp; do
  BASE="${source##*/}"
  BASE="${BASE%.cpp}"
  echo ${BASE}

  $CXX $CXXFLAGS \
      -c \
      -DASTCENC_SSE=0 \
      -DASTCENC_AVX=0 \
      -DASTCENC_POPCNT=0 \
      -I. -std=c++14 -mfpmath=sse -msse2 -fno-strict-aliasing -O0 -g \
      $source \
      -o ${BASE}.o
done

ar -qc libastcenc.a *.o

# Build project local fuzzers
for fuzzer in ./Fuzzers/fuzz_*.cpp; do
  $CXX $CXXFLAGS \
      -DASTCENC_SSE=0 \
      -DASTCENC_AVX=0 \
      -DASTCENC_POPCNT=0 \
      -I. -std=c++14 $fuzzer $LIB_FUZZING_ENGINE ./libastcenc.a \
      -o $OUT/$(basename -s .cpp $fuzzer)
done



# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" | while read -r target; do
  target_basename=$(basename "${target%.*}")

    $CXX $CXXFLAGS \
        -DASTCENC_SSE=0 \
        -DASTCENC_AVX=0 \
        -DASTCENC_POPCNT=0 \
        -I. -std=c++14 "$target" $LIB_FUZZING_ENGINE ./libastcenc.a \
        -o "$OUT/$target_basename"

  if [ -f "$SRC/llm_fuzzgen.dict" ] && [ ! -f "$SRC/${target_basename}.options" ]; then
    echo "[libfuzzer]" > "$SRC/${target_basename}.options"
    echo "dict = llm_fuzzgen.dict" >> "$SRC/${target_basename}.options"
  fi
done
cp $SRC/llm_fuzzgen.dict $OUT/ || true
cp $SRC/llm_fuzzgen*.options $OUT/ || true
cp $SRC/llm_fuzzgen*_seed_corpus.zip $OUT/ || true
