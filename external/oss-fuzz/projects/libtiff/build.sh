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
SYMCC_REPLAY_ENABLED="${LLM_FUZZGEN_BUILD_SYMCC_REPLAY:-0}"
SYMCC_NATIVE_EXPORT_ENABLED="${LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS:-0}"
SYMCC_LIBRARY_ENABLED="${LLM_FUZZGEN_BUILD_SYMCC_LIBRARY:-0}"

if [ "$BUILD_FLAVOR" = "symcc_replay" ]; then
  SYMCC_REPLAY_ENABLED=1
fi
if [ "$BUILD_FLAVOR" = "symcc_native" ]; then
  SYMCC_NATIVE_EXPORT_ENABLED=1
fi
if [ "$BUILD_FLAVOR" = "symcc_library" ]; then
  SYMCC_LIBRARY_ENABLED=1
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

if [ "$BUILD_FLAVOR" = "symcc_native" ] || [ "$BUILD_FLAVOR" = "symcc_library" ]; then
  export CFLAGS="$(strip_instrumentation_flags "$CFLAGS")"
  export CXXFLAGS="$(strip_instrumentation_flags "$CXXFLAGS")"
  export LDFLAGS="$(strip_instrumentation_flags "${LDFLAGS:-}")"
fi

if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  test -x "/symcc-bin/symcc"    || { echo "[llm-fuzzgen] ERROR: /symcc-bin/symcc not found (volume mount missing?)" >&2; exit 1; }
  test -x "/symcc-bin/sym++"    || { echo "[llm-fuzzgen] ERROR: /symcc-bin/sym++ not found" >&2; exit 1; }
  test -f "/symcc-bin/libsymcc.so" || { echo "[llm-fuzzgen] ERROR: /symcc-bin/libsymcc.so not found" >&2; exit 1; }
  test -f "/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.a" \
    || test -f "/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build/libsymcc-rt.so" \
    || { echo "[llm-fuzzgen] ERROR: libsymcc-rt not found in /symcc-bin volume" >&2; exit 1; }
  export CC="/symcc-bin/symcc"
  export CXX="/symcc-bin/sym++"
  export SYMCC_PASS_DIR="/symcc-bin"
  export SYMCC_RUNTIME_DIR="/symcc-bin/SymCCRuntime-prefix/src/SymCCRuntime-build"
  export SYMCC_CLANG="/usr/local/bin/clang"
  export SYMCC_CLANGPP="/usr/local/bin/clang++"
  export SYMCC_REGULAR_LIBCXX="yes"
  export SYMCC_ENABLE_LINEARIZATION="1"
  apt-get install -y libz3-4 -q 2>/dev/null || true
  export LD_LIBRARY_PATH="/symcc-bin:/symcc-libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

echo "[llm-fuzzgen] SANITIZER=$SANITIZER BUILD_FLAVOR=$BUILD_FLAVOR" >&2
#######################
. contrib/oss-fuzz/build.sh
SYMCC_REPLAY_DIR="$OUT/symcc_replay"

REPLAY_DRIVER_SOURCE="$SRC/libtiff_build_replay_driver.cc"
cat > "$REPLAY_DRIVER_SOURCE" <<'EOF'
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static bool ReadAllBytes(FILE* input, std::vector<uint8_t>* data) {
  if (!input || !data) {
    return false;
  }

  constexpr size_t kChunkSize = 4096;
  std::vector<uint8_t> buffer;
  uint8_t chunk[kChunkSize];

  for (;;) {
    size_t count = fread(chunk, 1, sizeof(chunk), input);
    if (count > 0) {
      buffer.insert(buffer.end(), chunk, chunk + count);
    }
    if (count < sizeof(chunk)) {
      if (feof(input)) {
        break;
      }
      return false;
    }
  }

  data->swap(buffer);
  return true;
}

int main(int argc, char** argv) {
  FILE* input = stdin;
  std::vector<uint8_t> data;

  if (argc > 2) {
    fprintf(stderr, "usage: %s [seed-file]\n", argv[0]);
    return 1;
  }

  if (argc == 2) {
    input = fopen(argv[1], "rb");
    if (!input) {
      perror("fopen");
      return 1;
    }
  }

  if (!ReadAllBytes(input, &data)) {
    fprintf(stderr, "failed to read input\n");
    if (argc == 2) {
      fclose(input);
    }
    return 1;
  }

  if (argc == 2) {
    fclose(input);
  }

  return LLVMFuzzerTestOneInput(data.data(), data.size());
}
EOF

compile_llm_target() {
  local target="$1"
  local target_basename="$2"
  local target_obj="${target_basename}.o"
  local replay_obj="${target_basename}_replay_driver.o"

  $CXX $CXXFLAGS -D_FUZZ_TARGET_NAME="\"$target_basename\"" -std=c++11 -I$WORK/include \
    -c "$target" -o "$target_obj"
  $CXX $CXXFLAGS "$target_obj" -o "$OUT/$target_basename" \
    $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a -Wl,--whole-archive $WORK/lib/libtiff.a -Wl,--no-whole-archive \
    $WORK/lib/libz.a $WORK/lib/libjpeg.a $WORK/lib/libjbig.a $WORK/lib/libjbig85.a \
    -Wl,-Bstatic -llzma -Wl,-Bdynamic

  if [ "$SYMCC_REPLAY_ENABLED" = "1" ]; then
    mkdir -p "$SYMCC_REPLAY_DIR"
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include -c "$REPLAY_DRIVER_SOURCE" -o "$replay_obj"
    $CXX $CXXFLAGS "$replay_obj" "$target_obj" \
      -o "$SYMCC_REPLAY_DIR/${target_basename}_replay" \
      $WORK/lib/libtiffxx.a -Wl,--whole-archive $WORK/lib/libtiff.a -Wl,--no-whole-archive \
      $WORK/lib/libz.a $WORK/lib/libjpeg.a $WORK/lib/libjbig.a $WORK/lib/libjbig85.a \
      -Wl,-Bstatic -llzma -Wl,-Bdynamic
  fi
}

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  compile_llm_target "$target" "$target_basename"
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

if [ "$SYMCC_LIBRARY_ENABLED" = "1" ]; then
  SYMCC_LIBRARY_DIR="$OUT/symcc_library"
  mkdir -p "$SYMCC_LIBRARY_DIR/include"
  cp -r "$WORK/include/." "$SYMCC_LIBRARY_DIR/include/"
  BUNDLE_TMPDIR=$(mktemp -d)
  (
    cd "$BUNDLE_TMPDIR"
    for lib in libtiff.a libtiffxx.a libz.a libjpeg.a libjbig.a libjbig85.a; do
      [ -f "$WORK/lib/$lib" ] && ar x "$WORK/lib/$lib"
    done
    ar crs "$SYMCC_LIBRARY_DIR/libtiff_combined.a" *.o
  )
  rm -rf "$BUNDLE_TMPDIR"
  if ! nm -A "$SYMCC_LIBRARY_DIR/libtiff_combined.a" | grep -qE '[[:space:]]U[[:space:]]+_sym_'; then
    echo "[llm-fuzzgen] ERROR: symcc_library archive missing SymCC runtime refs (_sym_*)" >&2
    exit 1
  fi
  if nm -A "$SYMCC_LIBRARY_DIR/libtiff_combined.a" | grep -qE '__sanitizer_cov_|__sancov_'; then
    echo "[llm-fuzzgen] ERROR: symcc_library archive contains sanitizer coverage symbols" >&2
    exit 1
  fi
  echo "[llm-fuzzgen] symcc_library archive validated OK: $SYMCC_LIBRARY_DIR/libtiff_combined.a" >&2

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

  exit 0
fi
