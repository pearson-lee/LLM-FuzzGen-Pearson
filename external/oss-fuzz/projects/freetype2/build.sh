#!/bin/bash -eux
export CMAKE_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"

if [ "${SANITIZER:-}" = "dataflow" ]; then
  echo "[dataflow] skipping external lib builds for clean DFSan tracking"
  sed -i 's|bash "build/zlib.sh"|echo "[skip] zlib"|g'             "fuzzing/scripts/build-fuzzers.sh"
  sed -i 's|bash "build/bzip2.sh"|echo "[skip] bzip2"|g'           "fuzzing/scripts/build-fuzzers.sh"
  sed -i 's|bash "build/brotli.sh"|echo "[skip] brotli"|g'         "fuzzing/scripts/build-fuzzers.sh"
  sed -i 's|bash "build/libpng.sh"|echo "[skip] libpng"|g'         "fuzzing/scripts/build-fuzzers.sh"
  sed -i 's|bash "build/libarchive.sh"|echo "[skip] libarchive"|g' "fuzzing/scripts/build-fuzzers.sh"
fi

bash "fuzzing/scripts/build-fuzzers.sh"

if [ "${SANITIZER:-}" = "introspector" ]; then
  echo "[introspector] pruning llvm-project after build"
  rm -rf external/llvm-project || true
fi

bash "fuzzing/scripts/prepare-oss-fuzz.sh"

for f in "${OUT}/legacy"*; do
    mv "${f}" "${f/legacy/ftfuzzer}"
done

zip -ju "${OUT}/ftfuzzer_seed_corpus.zip" "${SRC}/font-corpus/"*