#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

BUILD_FLAVOR="${LLM_FUZZGEN_BUILD_FLAVOR:-default}"
SYMCC_NATIVE_EXPORT_ENABLED="${LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS:-0}"

if [ "$BUILD_FLAVOR" = "symcc_native" ]; then
  SYMCC_NATIVE_EXPORT_ENABLED=1
fi

strip_instrumentation_flags() {
  local raw_flags="$1"
  local filtered_flags=()
  local skip_next=0
  local token

  for token in $raw_flags; do
    if [ "$skip_next" -eq 1 ]; then
      skip_next=0
      case "$token" in
        *sanitizer-coverage*|*sancov*|*libfuzzer*|*fuzzer-no-link*)
          continue
          ;;
      esac
      filtered_flags+=("$token")
      continue
    fi

    case "$token" in
      -fsanitize-coverage=*|-fsanitize=fuzzer|-fsanitize=fuzzer-no-link|-fsanitize=fuzzer-no-link,*|-fsanitize=*fuzzer*)
        continue
        ;;
      -mllvm)
        skip_next=1
        continue
        ;;
      *sanitizer-coverage*|*sancov*)
        continue
        ;;
    esac
    filtered_flags+=("$token")
  done

  printf '%s ' "${filtered_flags[@]}"
}

if [ "$BUILD_FLAVOR" = "symcc_native" ]; then
  export CFLAGS="$(strip_instrumentation_flags "$CFLAGS")"
  export CXXFLAGS="$(strip_instrumentation_flags "$CXXFLAGS")"
  export LDFLAGS="$(strip_instrumentation_flags "${LDFLAGS:-}")"
fi

echo "[llm-fuzzgen] SANITIZER=$SANITIZER BUILD_FLAVOR=$BUILD_FLAVOR" >&2
#######################
. contrib/oss-fuzz/build.sh
##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  #### compile the fuzz target
    $CXX $CXXFLAGS -D_FUZZ_TARGET_NAME="\"$target_basename\"" -std=c++11 -I$WORK/include \
    "$target" -o "$OUT/$target_basename" \
    $LIB_FUZZING_ENGINE  $WORK/lib/libtiffxx.a -Wl,--whole-archive $WORK/lib/libtiff.a -Wl,--no-whole-archive $WORK/lib/libz.a $WORK/lib/libjpeg.a \
    $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
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

# Export CLEAN Source Tree
OUT_PROJECT_DIR="$OUT/source_code"

if [ -e "$OUT_PROJECT_DIR" ] && [ ! -d "$OUT_PROJECT_DIR" ]; then
  rm -f "$OUT_PROJECT_DIR"
fi
mkdir -p "$OUT_PROJECT_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --no-perms \
    --exclude='.git' --exclude='.github' --exclude='.gitignore' \
    --exclude='build' --exclude='CMakeFiles' \
    --exclude='*.o' --exclude='*.a' --exclude='*.so' --exclude='*.dll' \
    "$SRC/libtiff/" "$OUT_PROJECT_DIR/"
else
  find "$SRC/libtiff" -maxdepth 1 -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) \
    -exec cp {} "$OUT_PROJECT_DIR/" \;
fi

if [ "$SYMCC_NATIVE_EXPORT_ENABLED" = "1" ]; then
  SYMCC_NATIVE_DIR="$OUT/symcc_native"
  mkdir -p "$SYMCC_NATIVE_DIR/include"
  # Copy installed headers
  cp -r "$WORK/include/." "$SYMCC_NATIVE_DIR/include/"
  # Bundle libtiff + its non-system static dependencies into one combined archive
  BUNDLE_TMPDIR=$(mktemp -d)
  (
    cd "$BUNDLE_TMPDIR"
    for lib in libtiff.a libtiffxx.a libz.a libjpeg.a libjbig.a libjbig85.a; do
      [ -f "$WORK/lib/$lib" ] && ar x "$WORK/lib/$lib"
    done
    ar crs "$SYMCC_NATIVE_DIR/libtiff_combined.a" *.o
  )
  rm -rf "$BUNDLE_TMPDIR"
  if nm -A "$SYMCC_NATIVE_DIR/libtiff_combined.a" | grep -qE '__sanitizer_cov_|__sancov_'; then
    echo "[llm-fuzzgen] symcc_native archive still contains sanitizer coverage symbols" >&2
    exit 1
  fi
fi
