#!/bin/bash -eu
#
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

./autogen.sh --without-cython --enable-debug --without-tests
make -j$(nproc) clean
make -j$(nproc) all

#https://github.com/google/oss-fuzz/commit/ecff0de4a3094e77804061b0b6dc5a57ef3d10d7
if [ "$SANITIZER" == "introspector" ]; then
  export CFLAGS="${CFLAGS} -fsanitize=address"
  export CXXFLAGS="${CXXFLAGS} -fsanitize=address"
fi

for fuzzer in bplist_fuzzer xplist_fuzzer jplist_fuzzer oplist_fuzzer; do
  $CXX $CXXFLAGS -std=c++11 -Iinclude/ \
      fuzz/$fuzzer.cc -o $OUT/$fuzzer \
      $LIB_FUZZING_ENGINE src/.libs/libplist-2.0.a
done

# Compile custom fuzzers (fuzz_*_fuzzer.cc or fuzz_*_fuzzer.cpp files)
find $SRC/libplist/fuzz/ -name "fuzz_*_fuzzer.cc" -o -name "fuzz_*_fuzzer.cpp" | while read -r fuzz_src; do
  fuzzer=$(basename "$fuzz_src" | sed -e 's/\.[^.]*$//')
  echo "Compiling custom fuzzer: $fuzzer"
  $CXX $CXXFLAGS -v -std=c++11 -Iinclude/ \
      "$fuzz_src" -o $OUT/$fuzzer \
      $LIB_FUZZING_ENGINE src/.libs/libplist-2.0.a
done

zip -j $OUT/bplist_fuzzer_seed_corpus.zip test/data/*.bplist
zip -j $OUT/xplist_fuzzer_seed_corpus.zip test/data/*.plist
zip -j $OUT/jplist_fuzzer_seed_corpus.zip test/data/*.json
zip -j $OUT/oplist_fuzzer_seed_corpus.zip test/data/*.ostep

cp fuzz/*.dict fuzz/*.options $OUT/
cp $SRC/*.dict $SRC/*.options $SRC/*corpus.zip $OUT/ || true
