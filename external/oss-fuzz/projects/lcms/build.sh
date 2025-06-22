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
# build the target.
./configure --enable-shared=no
make -j$(nproc) all

# build your fuzzer(s)
FUZZERS="cmsIT8_load_fuzzer            \
        cms_transform_fuzzer           \
        cms_overwrite_transform_fuzzer \
        cms_transform_all_fuzzer       \
        cms_profile_fuzzer             \
        cms_universal_transform_fuzzer \
        cms_transform_extended_fuzzer  \
        cms_md5_fuzzer                 \
        cms_dict_fuzzer                \
        cms_postscript_fuzzer          \
        cms_cie_cam02_fuzzer           \
        cms_gdb_fuzzer                 \
        cms_cgats_fuzzer               \
        cms_virtual_profile_fuzzer     \
        cms_devicelink_fuzzer" 


for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude \
        $SRC/$F.c -o $SRC/$F.o
    $CXX $CXXFLAGS \
        $SRC/$F.o -o $OUT/$F \
        $LIB_FUZZING_ENGINE src/.libs/liblcms2.a
done

cp $SRC/*.dict $SRC/*.options $OUT/
cp $SRC/icc.dict $OUT/cms_transform_all_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_transform_extended_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_universal_transform_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_profile_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_postscript_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_virtual_profile_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_md5_fuzzer.dict
cp $SRC/seed_corpus.zip $OUT/cms_postscript_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_profile_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_universal_transform_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_transform_all_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_transform_extended_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_transform_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_virtual_profile_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cmsIT8_load_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_md5_fuzzer_seed_corpus.zip
cp $SRC/seed_corpus.zip $OUT/cms_overwrite_transform_fuzzer_seed_corpus.zip

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  #### compile the fuzz target
  $CC $CFLAGS -c -Iinclude \
      "$target" -o "$OUT/${target_basename}.o"
  $CXX $CXXFLAGS \
      "$OUT/${target_basename}.o" -o "$OUT/${target_basename}" \
      $LIB_FUZZING_ENGINE -Wl,--whole-archive src/.libs/liblcms2.a -Wl,--no-whole-archive
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